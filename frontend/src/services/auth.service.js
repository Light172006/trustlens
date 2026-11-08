/**
 * TrustLens Authentication Service
 * Interacts with /api/v1/auth endpoints or mock authentication when in mock mode.
 */

import { apiClient, USE_MOCK_API, tokenStorage } from './api';
import { mockLogin, mockRegister, mockRefreshToken, MOCK_USER } from '../mocks/mock-auth';

export const authService = {
  /**
   * Log in user
   * @param {string} email 
   * @param {string} password 
   */
  async login(email, password) {
    if (USE_MOCK_API) {
      const res = await mockLogin(email, password);
      tokenStorage.setAccessToken(res.tokens.access_token);
      tokenStorage.setRefreshToken(res.tokens.refresh_token);
      tokenStorage.setCsrfToken(res.tokens.csrf_token);
      tokenStorage.setUser(res.user);
      return res;
    }

    const data = await apiClient('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });

    tokenStorage.setAccessToken(data.tokens.access_token);
    tokenStorage.setRefreshToken(data.tokens.refresh_token);
    tokenStorage.setCsrfToken(data.tokens.csrf_token);
    tokenStorage.setUser(data.user);
    return data;
  },

  /**
   * Register new user
   * @param {string} email 
   * @param {string} password 
   * @param {string} displayName 
   */
  async register(email, password, displayName) {
    if (USE_MOCK_API) {
      const res = await mockRegister(email, password, displayName);
      tokenStorage.setAccessToken(res.tokens.access_token);
      tokenStorage.setRefreshToken(res.tokens.refresh_token);
      tokenStorage.setCsrfToken(res.tokens.csrf_token);
      tokenStorage.setUser(res.user);
      return res;
    }

    const data = await apiClient('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, display_name: displayName }),
    });

    tokenStorage.setAccessToken(data.tokens.access_token);
    tokenStorage.setRefreshToken(data.tokens.refresh_token);
    tokenStorage.setCsrfToken(data.tokens.csrf_token);
    tokenStorage.setUser(data.user);
    return data;
  },

  /**
   * Log out active session
   */
  async logout() {
    try {
      if (!USE_MOCK_API) {
        await apiClient('/auth/logout', { method: 'POST' });
      }
    } catch {
      // Ignore network errors on logout
    } finally {
      tokenStorage.clear();
    }
    return { success: true };
  },

  /**
   * Fetch current user profile
   */
  async getProfile() {
    if (USE_MOCK_API) {
      const stored = tokenStorage.getUser();
      return stored || MOCK_USER;
    }

    return await apiClient('/auth/me');
  },

  /**
   * Rotate access/refresh tokens
   */
  async refresh() {
    if (USE_MOCK_API) {
      const res = await mockRefreshToken();
      tokenStorage.setAccessToken(res.access_token);
      tokenStorage.setRefreshToken(res.refresh_token);
      tokenStorage.setCsrfToken(res.csrf_token);
      return res;
    }

    const refreshToken = tokenStorage.getRefreshToken();
    const data = await apiClient('/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    // Backend returns AuthResponse: { user, tokens }
    const tokens = data.tokens || data;
    tokenStorage.setAccessToken(tokens.access_token);
    tokenStorage.setRefreshToken(tokens.refresh_token);
    if (tokens.csrf_token) tokenStorage.setCsrfToken(tokens.csrf_token);
    if (data.user) tokenStorage.setUser(data.user);
    return tokens;
  },
};
