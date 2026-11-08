/**
 * ErrorState Component
 * Displays structured backend errors with Request ID and actionable remedies.
 */

import React from 'react';
import { AlertOctagon, RotateCcw } from 'lucide-react';
import { Button } from 'antd';
import { ERROR_MESSAGES } from '../../lib/utils';

export function ErrorState({ error, onRetry, title = 'Investigation Error' }) {
  const errPayload = error?.error || error || {};
  const code = errPayload.code || 'UNKNOWN_ERROR';
  const customMessage = ERROR_MESSAGES[code] || errPayload.message || 'An unexpected error occurred.';
  const requestId = errPayload.request_id;
  const details = errPayload.details;

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '3rem 1.5rem',
        textAlign: 'center',
        backgroundColor: 'var(--bg-surface)',
        border: '1px solid var(--border-color)',
        borderRadius: 'var(--radius-lg)',
      }}
    >
      <div
        style={{
          width: '46px',
          height: '46px',
          borderRadius: '50%',
          backgroundColor: 'var(--color-malicious-bg)',
          color: 'var(--color-malicious-text)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          marginBottom: '1rem',
        }}
      >
        <AlertOctagon size={24} />
      </div>

      <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.4rem' }}>
        {title}
      </h3>

      <div
        style={{
          display: 'inline-block',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.75rem',
          color: 'var(--color-malicious-text)',
          backgroundColor: 'var(--bg-surface-secondary)',
          padding: '0.2rem 0.5rem',
          borderRadius: '3px',
          marginBottom: '0.75rem',
        }}
      >
        CODE: {code}
      </div>

      <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '480px', lineHeight: 1.5, marginBottom: '1.25rem' }}>
        {customMessage}
      </p>

      {requestId && (
        <div
          style={{
            fontSize: '0.725rem',
            fontFamily: 'var(--font-mono)',
            color: 'var(--text-muted)',
            marginBottom: '1.5rem',
          }}
        >
          Request ID: {requestId}
        </div>
      )}

      {details && Object.keys(details).length > 0 && (
        <div
          style={{
            maxWidth: '500px',
            width: '100%',
            backgroundColor: 'var(--bg-app)',
            border: '1px solid var(--border-color)',
            borderRadius: 'var(--radius-sm)',
            padding: '0.75rem',
            textAlign: 'left',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.72rem',
            color: 'var(--text-secondary)',
            marginBottom: '1.5rem',
            overflowX: 'auto',
          }}
        >
          {JSON.stringify(details, null, 2)}
        </div>
      )}

      {onRetry && (
        <Button icon={<RotateCcw size={14} />} onClick={onRetry}>
          Try Again
        </Button>
      )}
    </div>
  );
}
