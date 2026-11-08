/**
 * TrustLens Authentication Context
 * Manages user authentication lifecycle, role verification, and token expiration events.
 */

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { authService } from '../services/auth.service';
import { tokenStorage } from '../services/api';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => tokenStorage.getUser());
  const [isLoading, setIsLoading] = useState(true);

  const initAuth = useCallback(async () => {
    const token = tokenStorage.getAccessToken();
    if (!token) {
      setUser(null);
      setIsLoading(false);
      return;
    }

    try {
      const userProfile = await authService.getProfile();
      setUser(userProfile);
      tokenStorage.setUser(userProfile);
    } catch {
      // If profile fails and refresh fails, tokenStorage is cleared by api client
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    initAuth();

    const handleAuthExpired = () => {
      setUser(null);
    };

    window.addEventListener('trustlens:auth-expired', handleAuthExpired);
    return () => {
      window.removeEventListener('trustlens:auth-expired', handleAuthExpired);
    };
  }, [initAuth]);

  const login = async (email, password) => {
    const res = await authService.login(email, password);
    setUser(res.user);
    return res;
  };

  const register = async (email, password, displayName) => {
    const res = await authService.register(email, password, displayName);
    setUser(res.user);
    return res;
  };

  const logout = async () => {
    await authService.logout();
    setUser(null);
  };

  const refreshUser = async () => {
    try {
      const updated = await authService.getProfile();
      setUser(updated);
      tokenStorage.setUser(updated);
      return updated;
    } catch {
      return null;
    }
  };

  const value = {
    user,
    isAuthenticated: Boolean(user && tokenStorage.getAccessToken()),
    isLoading,
    isAdmin: user?.role === 'admin',
    isModerator: user?.role === 'moderator' || user?.role === 'admin',
    login,
    register,
    logout,
    refreshUser,
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

