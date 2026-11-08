/**
 * TrustLens Centralized Fetch API Client
 * Manages authorization headers, request correlation IDs, automatic JWT token rotation,
 * and unified error extraction matching the TrustLens backend specification.
 */

import { generateUUID } from '../lib/utils';

export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

// Token storage keys
const ACCESS_TOKEN_KEY = 'trustlens_access_token';
const REFRESH_TOKEN_KEY = 'trustlens_refresh_token';
const USER_KEY = 'trustlens_user';

export const tokenStorage = {
  getAccessToken: () => localStorage.getItem(ACCESS_TOKEN_KEY),
  setAccessToken: (token) =>
    token ? localStorage.setItem(ACCESS_TOKEN_KEY, token) : localStorage.removeItem(ACCESS_TOKEN_KEY),
  getRefreshToken: () => localStorage.getItem(REFRESH_TOKEN_KEY),
  setRefreshToken: (token) =>
    token ? localStorage.setItem(REFRESH_TOKEN_KEY, token) : localStorage.removeItem(REFRESH_TOKEN_KEY),
  getUser: () => {
    try {
      const u = localStorage.getItem(USER_KEY);
      return u ? JSON.parse(u) : null;
    } catch {
      return null;
    }
  },
  setUser: (user) =>
    user ? localStorage.setItem(USER_KEY, JSON.stringify(user)) : localStorage.removeItem(USER_KEY),
  clear: () => {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  },
};

let isRefreshing = false;
let refreshSubscribers = [];

function onRefreshed(newAccessToken) {
  refreshSubscribers.forEach((callback) => callback(newAccessToken));
  refreshSubscribers = [];
}

function addRefreshSubscriber(callback) {
  refreshSubscribers.push(callback);
}

/**
 * Perform an authenticated request against the TrustLens API.
 * @param {string} endpoint - API endpoint (e.g. '/scans' or 'http://...')
 * @param {RequestInit & { _retry?: boolean }} [options={}] - Fetch options
 * @returns {Promise<any>}
 */
export async function apiClient(endpoint, options = {}) {
  const url = endpoint.startsWith('http')
    ? endpoint
    : `${API_BASE_URL}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;
  const method = (options.method || 'GET').toUpperCase();
  const headers = new Headers(options.headers || {});

  // Add correlation request ID
  if (!headers.has('X-Request-ID')) {
    headers.set('X-Request-ID', generateUUID());
  }

  // Add JSON Content-Type if payload exists and not form data
  if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  // Attach access token if present
  const accessToken = tokenStorage.getAccessToken();
  if (accessToken && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${accessToken}`);
  }

  let response;
  try {
    response = await fetch(url, { ...options, method, headers });
  } catch (netErr) {
    throw {
      error: {
        code: 'NETWORK_ERROR',
        message: 'Unable to reach the TrustLens backend service. Please verify that the API server is online.',
        request_id: headers.get('X-Request-ID') || generateUUID(),
        details: [{ field: 'network', issue: netErr.message }],
      },
    };
  }

  // Handle 401 Unauthorized with token refresh attempt
  if (
    response.status === 401 &&
    !options._retry &&
    !endpoint.includes('/auth/login') &&
    !endpoint.includes('/auth/refresh') &&
    !endpoint.includes('/auth/register')
  ) {
    const refreshToken = tokenStorage.getRefreshToken();
    if (refreshToken) {
      if (!isRefreshing) {
        isRefreshing = true;
        try {
          const refreshRes = await fetch(`${API_BASE_URL}/auth/refresh`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-Request-ID': generateUUID(),
            },
            body: JSON.stringify({ refresh_token: refreshToken }),
          });

          if (refreshRes.ok) {
            const data = await refreshRes.json();
            const tokens = data.tokens || data;
            tokenStorage.setAccessToken(tokens.access_token);
            if (tokens.refresh_token) tokenStorage.setRefreshToken(tokens.refresh_token);
            if (data.user) tokenStorage.setUser(data.user);
            isRefreshing = false;
            onRefreshed(tokens.access_token);
          } else {
            isRefreshing = false;
            tokenStorage.clear();
            window.dispatchEvent(new CustomEvent('trustlens:auth-expired'));
          }
        } catch {
          isRefreshing = false;
          tokenStorage.clear();
          window.dispatchEvent(new CustomEvent('trustlens:auth-expired'));
        }
      }

      return new Promise((resolve, reject) => {
        addRefreshSubscriber((newToken) => {
          if (newToken) {
            headers.set('Authorization', `Bearer ${newToken}`);
            resolve(apiClient(endpoint, { ...options, headers, _retry: true }));
          } else {
            reject({
              error: {
                code: 'AUTHENTICATION_REQUIRED',
                message: 'Your session has expired. Please log in again.',
                request_id: headers.get('X-Request-ID'),
                details: [],
              },
            });
          }
        });
      });
    } else {
      tokenStorage.clear();
      window.dispatchEvent(new CustomEvent('trustlens:auth-expired'));
    }
  }

  // Handle HTTP 204 No Content
  if (response.status === 204) {
    return null;
  }

  // Parse JSON or text response
  let data;
  const contentType = response.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    try {
      data = await response.json();
    } catch {
      data = null;
    }
  } else {
    data = await response.text();
  }

  if (!response.ok) {
    // If backend provided standardized error envelope
    if (data && data.error) {
      throw data;
    }

    throw {
      error: {
        code:
          response.status === 429
            ? 'RATE_LIMIT_EXCEEDED'
            : response.status >= 500
              ? 'INTERNAL_ERROR'
              : 'HTTP_ERROR',
        message:
          typeof data === 'string'
            ? data
            : response.statusText || 'An unexpected error occurred during request processing.',
        request_id:
          response.headers.get('X-Request-ID') || headers.get('X-Request-ID') || generateUUID(),
        details: [{ field: 'status', issue: `HTTP status code ${response.status}` }],
      },
    };
  }

  return data;
}

