/**
 * TrustLens RegisterPage Component
 * New user registration matching backend requirements:
 * - Minimum 12 character password policy
 * - Display name (2-80 chars)
 * - Conflict detection (409)
 */

import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Lock, Mail, User, Eye, EyeOff, Check, X } from 'lucide-react';
import { Input, Button, Alert } from 'antd';
import { useAuth } from '../context/AuthContext';

export function RegisterPage() {
  const [email, setEmail] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const { register } = useAuth();
  const navigate = useNavigate();

  const isPasswordLongEnough = password.length >= 12;
  const doPasswordsMatch = password && password === confirmPassword;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMessage('');

    if (!displayName || displayName.trim().length < 2) {
      setErrorMessage('Display name must be at least 2 characters.');
      return;
    }

    if (!email || !email.includes('@')) {
      setErrorMessage('Please enter a valid email address.');
      return;
    }

    if (!isPasswordLongEnough) {
      setErrorMessage('Password must be at least 12 characters long per platform security policy.');
      return;
    }

    if (!doPasswordsMatch) {
      setErrorMessage('Passwords do not match.');
      return;
    }

    setIsLoading(true);
    try {
      await register(email.trim(), password, displayName.trim());
      navigate('/dashboard', { replace: true });
    } catch (err) {
      const payload = err.error || err;
      setErrorMessage(payload.message || 'Registration failed. Please verify your details.');
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
      <div style={{ maxWidth: '440px', width: '100%' }}>
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
            Create Analyst Account
          </h2>
          <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            Register to conduct digital trust investigations and collaborate on threat feeds
          </p>
        </div>

        {/* Card */}
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

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.1rem' }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                Full Name / Display Name *
              </label>
              <Input
                size="large"
                placeholder="Jane Analyst"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                prefix={<User size={16} style={{ color: 'var(--text-muted)' }} />}
                disabled={isLoading}
                required
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                Corporate Email Address *
              </label>
              <Input
                size="large"
                type="email"
                placeholder="analyst@domain.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                prefix={<Mail size={16} style={{ color: 'var(--text-muted)' }} />}
                disabled={isLoading}
                required
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                Password * (minimum 12 characters)
              </label>
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
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                Confirm Password *
              </label>
              <Input
                size="large"
                type={showPassword ? 'text' : 'password'}
                placeholder="••••••••••••"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                prefix={<Lock size={16} style={{ color: 'var(--text-muted)' }} />}
                disabled={isLoading}
                required
              />
            </div>

            {/* Password Validation Hints */}
            <div style={{ fontSize: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.25rem', marginTop: '0.2rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: isPasswordLongEnough ? 'var(--color-safe-text)' : 'var(--text-muted)' }}>
                {isPasswordLongEnough ? <Check size={12} /> : <X size={12} />}
                <span>At least 12 characters long</span>
              </div>
              {confirmPassword && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: doPasswordsMatch ? 'var(--color-safe-text)' : 'var(--color-malicious-text)' }}>
                  {doPasswordsMatch ? <Check size={12} /> : <X size={12} />}
                  <span>Passwords match</span>
                </div>
              )}
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
              Register Account
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
            Already registered?{' '}
            <Link to="/login" style={{ color: 'var(--color-accent)', fontWeight: 600 }}>
              Sign in here
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

