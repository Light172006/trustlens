/**
 * LoginPage Component
 * Minimal dark login interface with password visibility toggle,
 * demo credentials fill button, and clear authentication error states.
 */

import React, { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { Shield, Lock, Mail, Eye, EyeOff, AlertCircle, ArrowRight, Zap } from 'lucide-react';
import { Input, Button, Alert } from 'antd';
import { useAuth } from '../context/AuthContext';

export function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const { login, isMockMode } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  // Extract returnUrl from query params if available
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

  const handleDemoFill = () => {
    setEmail('analyst@trustlens.dev');
    setPassword('SecurePassword123!');
    setErrorMessage('');
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
            Sign in to access web threat intelligence & scan reports
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
              <label style={{ display: 'block', fontSize: '0.775rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.4rem' }}>
                EMAIL ADDRESS
              </label>
              <Input
                size="large"
                type="email"
                placeholder="analyst@trustlens.dev"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                prefix={<Mail size={16} style={{ color: 'var(--text-muted)', marginRight: '6px' }} />}
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
                <label style={{ fontSize: '0.775rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
                  PASSWORD
                </label>
              </div>
              <Input
                size="large"
                type={showPassword ? 'text' : 'password'}
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                prefix={<Lock size={16} style={{ color: 'var(--text-muted)', marginRight: '6px' }} />}
                suffix={
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    style={{ color: 'var(--text-muted)', display: 'flex', alignItems: 'center' }}
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
                fontWeight: 600,
                color: '#101112',
                marginTop: '0.5rem',
              }}
            >
              Sign In to Console
            </Button>

            {/* Quick Demo Credentials Autofill */}
            <div style={{ paddingTop: '0.75rem', borderTop: '1px solid var(--border-color-subtle)' }}>
              <Button
                type="dashed"
                block
                size="middle"
                icon={<Zap size={14} color="var(--color-accent)" />}
                onClick={handleDemoFill}
                style={{
                  borderColor: 'var(--border-color-strong)',
                  color: 'var(--text-secondary)',
                  fontSize: '0.8rem',
                }}
              >
                Autofill Demo Credentials
              </Button>
            </div>
          </form>

          <div style={{ marginTop: '1.5rem', textAlign: 'center', fontSize: '0.825rem', color: 'var(--text-muted)' }}>
            Don't have an account?{' '}
            <Link to="/register" style={{ color: 'var(--color-accent)', fontWeight: 600 }}>
              Create Account
            </Link>
          </div>
        </div>

        <div style={{ textAlign: 'center', marginTop: '1.5rem' }}>
          <Link to="/" style={{ fontSize: '0.775rem', color: 'var(--text-muted)' }}>
            ← Back to public homepage
          </Link>
        </div>
      </div>
    </div>
  );
}
