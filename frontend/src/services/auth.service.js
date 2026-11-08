/**
 * TrustLens Authentication Service
 * Communicates with backend /api/v1/auth endpoints.
 */

import { apiClient, tokenStorage } from './api';

export const authService = {
  /**
   * Authenticate user with email and password
   * @param {string} email 
   * @param {string} password 
   */
  async login(email, password) {
    const data = await apiClient('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: email.trim(), password }),
    });

    tokenStorage.setAccessToken(data.tokens.access_token);
    tokenStorage.setRefreshToken(data.tokens.refresh_token);
    tokenStorage.setUser(data.user);
    return data;
  },

  /**
   * Register a new user account
   * @param {string} email 
   * @param {string} password 
   * @param {string} displayName 
   */
  async register(email, password, displayName) {
    const data = await apiClient('/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        email: email.trim(),
        password,
        display_name: displayName.trim(),
      }),
    });

    tokenStorage.setAccessToken(data.tokens.access_token);
    tokenStorage.setRefreshToken(data.tokens.refresh_token);
    tokenStorage.setUser(data.user);
    return data;
  },

  /**
   * Terminate active user session
   */
  async logout() {
    try {
      await apiClient('/auth/logout', { method: 'POST' });
    } catch {
      // Ignore network errors on logout to allow local session clearance
    } finally {
      tokenStorage.clear();
    }
    return { success: true };
  },

  /**
   * Fetch current authenticated user profile
   */
  async getProfile() {
    return await apiClient('/auth/me');
  },

  /**
   * Manually rotate access and refresh tokens
   */
  async refresh() {
    const refreshToken = tokenStorage.getRefreshToken();
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }
    const data = await apiClient('/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    const tokens = data.tokens || data;
    tokenStorage.setAccessToken(tokens.access_token);
    if (tokens.refresh_token) tokenStorage.setRefreshToken(tokens.refresh_token);
    if (data.user) tokenStorage.setUser(data.user);
    return data;
  },
};

