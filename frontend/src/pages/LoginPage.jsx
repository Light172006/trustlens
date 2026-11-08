/**
 * TrustLens LoginPage Component
 * Minimal dark cybersecurity login console with password visibility toggle,
 * credential validation, and clear error extraction from backend response envelopes.
 */

import React, { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { Shield, Lock, Mail, Eye, EyeOff } from 'lucide-react';
import { Input, Button, Alert } from 'antd';
import { useAuth } from '../context/AuthContext';

export function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const query = new URLSearchParams(location.search);
  const returnUrl = query.get('returnUrl') || '/dashboard';

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMessage('');

    if (!email || !password) {
      setErrorMessage('Please enter both your email address and password.');
      return;
    }

    setIsLoading(true);
    try {
      await login(email.trim(), password);
      navigate(returnUrl, { replace: true });
    } catch (err) {
      const payload = err.error || err;
      setErrorMessage(payload.message || 'Invalid email or password.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        backgroundColor: 'var(--bg-app)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '1.5rem',
      }}
    >
      <div style={{ maxWidth: '400px', width: '100%' }}>
        {/* Brand Header */}
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <div
            style={{
              width: '40px',
              height: '40px',
              borderRadius: '8px',
              backgroundColor: 'var(--bg-surface-secondary)',
              border: '1px solid var(--border-color-strong)',
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--color-accent)',
              marginBottom: '0.75rem',
            }}
          >
            <Shield size={22} />
          </div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
            TrustLens Console
          </h2>
          <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            Sign in to access digital trust intelligence & investigation telemetry
          </p>
        </div>

        {/* Login Card */}
        <div
          className="tl-card"
          style={{
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border-color)',
            borderRadius: 'var(--radius-lg)',
            padding: '2rem',
          }}
        >
          {errorMessage && (
            <div style={{ marginBottom: '1.25rem' }}>
              <Alert
                message={errorMessage}
                type="error"
                showIcon
                style={{
                  backgroundColor: 'var(--color-malicious-bg)',
                  borderColor: 'var(--color-malicious-border)',
                  color: 'var(--color-malicious-text)',
                  fontSize: '0.8rem',
                }}
              />
            </div>
          )}

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div>
              <label
                style={{
                  display: 'block',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  color: 'var(--text-secondary)',
                  marginBottom: '0.4rem',
                  letterSpacing: '0.04em',
                }}
              >
                Email Address
              </label>
              <Input
                size="large"
                type="email"
                placeholder="analyst@trustlens.internal"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                prefix={<Mail size={16} style={{ color: 'var(--text-muted)' }} />}
                disabled={isLoading}
                required
                style={{
                  backgroundColor: 'var(--bg-app)',
                  borderColor: 'var(--border-color)',
                  color: 'var(--text-primary)',
                }}
              />
            </div>

            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                <label
                  style={{
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    textTransform: 'uppercase',
                    color: 'var(--text-secondary)',
                    letterSpacing: '0.04em',
                  }}
                >
                  Password
                </label>
              </div>
              <Input
                size="large"
                type={showPassword ? 'text' : 'password'}
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                prefix={<Lock size={16} style={{ color: 'var(--text-muted)' }} />}
                suffix={
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    style={{ color: 'var(--text-muted)', display: 'flex' }}
                  >
                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                }
                disabled={isLoading}
                required
                style={{
                  backgroundColor: 'var(--bg-app)',
                  borderColor: 'var(--border-color)',
                  color: 'var(--text-primary)',
                }}
              />
            </div>

            <Button
              type="primary"
              size="large"
              htmlType="submit"
              loading={isLoading}
              style={{
                backgroundColor: 'var(--color-accent)',
                borderColor: 'var(--color-accent)',
                color: '#101112',
                fontWeight: 600,
                marginTop: '0.5rem',
                height: '42px',
              }}
            >
              Sign In
            </Button>
          </form>

          <div
            style={{
              marginTop: '1.5rem',
              paddingTop: '1rem',
              borderTop: '1px solid var(--border-color-subtle)',
              textAlign: 'center',
              fontSize: '0.8rem',
              color: 'var(--text-secondary)',
            }}
          >
            Don't have an analyst account?{' '}
            <Link to="/register" style={{ color: 'var(--color-accent)', fontWeight: 600 }}>
              Register here
            </Link>
          </div>
        </div>

        <div style={{ textAlign: 'center', marginTop: '1.5rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          TrustLens Security Intelligence Platform • Port 8000
        </div>
      </div>
    </div>
  );
}
