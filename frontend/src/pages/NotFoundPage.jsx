/**
 * NotFoundPage Component
 * 404 Route handler with quick return navigation.
 */

import React from 'react';
import { useNavigate } from 'react-router-dom';
import { HelpCircle, ArrowLeft, Shield } from 'lucide-react';
import { Button } from 'antd';

export function NotFoundPage() {
  const navigate = useNavigate();

  return (
    <div
      style={{
        minHeight: '80vh',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        textAlign: 'center',
        padding: '2rem',
      }}
    >
      <div
        style={{
          width: '56px',
          height: '56px',
          borderRadius: '50%',
          backgroundColor: 'var(--bg-surface-secondary)',
          border: '1px solid var(--border-color)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'var(--color-accent)',
          marginBottom: '1.25rem',
        }}
      >
        <HelpCircle size={28} />
      </div>

      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--color-accent)', marginBottom: '0.5rem' }}>
        404 • ROUTE_NOT_FOUND
      </div>

      <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
        Page Not Found
      </h1>

      <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', maxWidth: '420px', lineHeight: 1.5, marginBottom: '1.75rem' }}>
        The requested console endpoint or investigation view does not exist or has been relocated.
      </p>

      <Button
        type="primary"
        icon={<ArrowLeft size={14} />}
        onClick={() => navigate('/dashboard')}
        style={{
          backgroundColor: 'var(--color-accent)',
          borderColor: 'var(--color-accent)',
          color: '#101112',
          fontWeight: 600,
        }}
      >
        Return to Console Overview
      </Button>
    </div>
  );
}
