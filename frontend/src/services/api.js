/**
 * TrustLens Centralized Fetch API Client
 * Manages authorization headers, CSRF tokens, request IDs, automatic token rotation,
 * and unified error extraction matching the backend specification.
 */

import { generateUUID } from '../lib/utils';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';
export const USE_MOCK_API = import.meta.env.VITE_USE_MOCK_API === 'true';

// Token storage keys
const ACCESS_TOKEN_KEY = 'trustlens_access_token';
const REFRESH_TOKEN_KEY = 'trustlens_refresh_token';
const CSRF_TOKEN_KEY = 'trustlens_csrf_token';
const USER_KEY = 'trustlens_user';

export const tokenStorage = {
  getAccessToken: () => localStorage.getItem(ACCESS_TOKEN_KEY),
  setAccessToken: (token) => token ? localStorage.setItem(ACCESS_TOKEN_KEY, token) : localStorage.removeItem(ACCESS_TOKEN_KEY),
  getRefreshToken: () => localStorage.getItem(REFRESH_TOKEN_KEY),
  setRefreshToken: (token) => token ? localStorage.setItem(REFRESH_TOKEN_KEY, token) : localStorage.removeItem(REFRESH_TOKEN_KEY),
  getCsrfToken: () => localStorage.getItem(CSRF_TOKEN_KEY),
  setCsrfToken: (token) => token ? localStorage.setItem(CSRF_TOKEN_KEY, token) : localStorage.removeItem(CSRF_TOKEN_KEY),
  getUser: () => {
    try {
      const u = localStorage.getItem(USER_KEY);
      return u ? JSON.parse(u) : null;
    } catch {
      return null;
    }
  },
  setUser: (user) => user ? localStorage.setItem(USER_KEY, JSON.stringify(user)) : localStorage.removeItem(USER_KEY),
  clear: () => {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
    localStorage.removeItem(CSRF_TOKEN_KEY);
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
 * Perform an authenticated request against TrustLens API
 * @param {string} endpoint 
 * @param {RequestInit} [options={}] 
 * @returns {Promise<any>}
 */
export async function apiClient(endpoint, options = {}) {
  const url = endpoint.startsWith('http') ? endpoint : `${API_BASE_URL}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;
  const method = (options.method || 'GET').toUpperCase();
  const headers = new Headers(options.headers || {});

  // Add Request ID
  if (!headers.has('X-Request-ID')) {
    headers.set('X-Request-ID', generateUUID());
  }

  // Add JSON Content-Type if payload exists and not set
  if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  // Attach access token
  const accessToken = tokenStorage.getAccessToken();
  if (accessToken && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${accessToken}`);
  }

  // Attach CSRF token on state-changing methods
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const csrfToken = tokenStorage.getCsrfToken();
    if (csrfToken && !headers.has('X-CSRF-Token')) {
      headers.set('X-CSRF-Token', csrfToken);
    }
  }

  let response;
  try {
    response = await fetch(url, { ...options, method, headers });
  } catch (netErr) {
    throw {
      error: {
        code: 'NETWORK_ERROR',
        message: 'Unable to reach the TrustLens backend service. Please check your network connection.',
        request_id: headers.get('X-Request-ID') || generateUUID(),
        details: { originalError: netErr.message },
      },
    };
  }

  // Handle 401 Unauthorized with token refresh attempt
  if (response.status === 401 && !options._retry && !endpoint.includes('/auth/login') && !endpoint.includes('/auth/refresh')) {
    const refreshToken = tokenStorage.getRefreshToken();
    if (refreshToken) {
      if (!isRefreshing) {
        isRefreshing = true;
        try {
          const refreshRes = await fetch(`${API_BASE_URL}/auth/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ refresh_token: refreshToken }),
          });

          if (refreshRes.ok) {
            const data = await refreshRes.json();
            // Backend refresh returns AuthResponse: { user, tokens } or flat tokens
            const tokens = data.tokens || data;
            tokenStorage.setAccessToken(tokens.access_token);
            if (tokens.refresh_token) tokenStorage.setRefreshToken(tokens.refresh_token);
            if (tokens.csrf_token) tokenStorage.setCsrfToken(tokens.csrf_token);
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

      // Wait for active refresh
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

  // Parse JSON response
  let data;
  const contentType = response.headers.get('content-type');
  if (contentType && contentType.includes('application/json')) {
    try {
      data = await response.json();
    } catch {
      data = null;
    }
  } else {
    data = await response.text();
  }

  if (!response.ok) {
    // Standardized error envelope from backend or fallback
    if (data && data.error) {
      throw data;
    }

    throw {
      error: {
        code: response.status === 429 ? 'RATE_LIMIT_EXCEEDED' : (response.status >= 500 ? 'INTERNAL_ERROR' : 'HTTP_ERROR'),
        message: typeof data === 'string' ? data : (response.statusText || 'An error occurred during request execution.'),
        request_id: response.headers.get('X-Request-ID') || headers.get('X-Request-ID') || generateUUID(),
        details: { status: response.status },
      },
    };
  }

  return data;
}
