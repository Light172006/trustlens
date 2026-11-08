/**
 * TrustLens Authentication Context & Provider
 * Manages reactive authentication state, login, registration, and session invalidation.
 */

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { authService } from '../services/auth.service';
import { tokenStorage, USE_MOCK_API } from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => tokenStorage.getUser());
  const [isLoading, setIsLoading] = useState(true);

  // Sync state and handle global session expiration
  useEffect(() => {
    async function initializeSession() {
      const token = tokenStorage.getAccessToken();
      if (!token) {
        setIsLoading(false);
        return;
      }

      try {
        const profile = await authService.getProfile();
        setUser(profile);
        tokenStorage.setUser(profile);
      } catch {
        // If profile fetch fails on boot with 401, purge invalid token
        tokenStorage.clear();
        setUser(null);
      } finally {
        setIsLoading(false);
      }
    }

    initializeSession();

    // Listen for 401 auth-expired custom events emitted by apiClient
    const handleAuthExpired = () => {
      setUser(null);
    };

    window.addEventListener('trustlens:auth-expired', handleAuthExpired);
    return () => {
      window.removeEventListener('trustlens:auth-expired', handleAuthExpired);
    };
  }, []);

  const login = useCallback(async (email, password) => {
    const res = await authService.login(email, password);
    setUser(res.user);
    return res;
  }, []);

  const register = useCallback(async (email, password, displayName) => {
    const res = await authService.register(email, password, displayName);
    setUser(res.user);
    return res;
  }, []);

  const logout = useCallback(async () => {
    await authService.logout();
    setUser(null);
  }, []);

  const value = {
    user,
    isAuthenticated: Boolean(user && tokenStorage.getAccessToken()),
    isLoading,
    isMockMode: USE_MOCK_API,
    login,
    register,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
