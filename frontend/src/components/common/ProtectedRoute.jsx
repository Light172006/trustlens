/**
 * ProtectedRoute Component
 * Guards private routes, requiring active user authentication and optional role authorization.
 */

import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { Spin } from 'antd';
import { ShieldX } from 'lucide-react';

export function ProtectedRoute({ children, requiredRole = null }) {
  const { isAuthenticated, isLoading, user } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div
        style={{
          display: 'flex',
          height: '100vh',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: 'var(--bg-app)',
        }}
      >
        <Spin size="large" />
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <Navigate
        to={`/login?returnUrl=${encodeURIComponent(location.pathname + location.search)}`}
        replace
      />
    );
  }

  if (requiredRole) {
    const userRole = user?.role || 'user';
    const hasRole =
      requiredRole === 'admin'
        ? userRole === 'admin'
        : requiredRole === 'moderator'
          ? userRole === 'moderator' || userRole === 'admin'
          : true;

    if (!hasRole) {
      return (
        <div
          style={{
            padding: '3rem 1.5rem',
            textAlign: 'center',
            maxWidth: '540px',
            margin: '4rem auto',
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border-color)',
            borderRadius: 'var(--radius-lg)',
          }}
        >
          <div
            style={{
              width: '56px',
              height: '56px',
              borderRadius: '50%',
              backgroundColor: 'rgba(239, 68, 68, 0.1)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 1.25rem',
              color: 'var(--severity-critical)',
            }}
          >
            <ShieldX size={28} />
          </div>
          <h2 style={{ fontSize: '1.25rem', fontWeight: 600, marginBottom: '0.5rem' }}>
            Access Denied
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.875rem', marginBottom: '1.5rem' }}>
            This section requires {requiredRole === 'admin' ? 'Administrator' : 'Moderator'} privileges.
            Your current account role is <strong style={{ color: 'var(--text-primary)' }}>{userRole}</strong>.
          </p>
          <a
            href="/dashboard"
            style={{
              display: 'inline-block',
              padding: '0.5rem 1.25rem',
              backgroundColor: 'var(--bg-surface-secondary)',
              border: '1px solid var(--border-color)',
              borderRadius: 'var(--radius-md)',
              fontSize: '0.85rem',
              fontWeight: 500,
              color: 'var(--text-primary)',
            }}
          >
            Return to Dashboard
          </a>
        </div>
      );
    }
  }

  return children;
}
