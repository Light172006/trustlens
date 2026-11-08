/**
 * StatusBadge Component
 * Renders scan status state indicators (queued, running, succeeded, partial, failed).
 */

import React from 'react';
import { Clock, Loader2, CheckCircle2, AlertCircle, XCircle } from 'lucide-react';

const STATUS_CONFIG = {
  queued: {
    label: 'Queued',
    icon: Clock,
    color: 'var(--text-muted)',
    bg: 'rgba(100, 104, 112, 0.15)',
    border: 'rgba(100, 104, 112, 0.3)',
  },
  running: {
    label: 'Running',
    icon: Loader2,
    color: 'var(--color-accent)',
    bg: 'var(--color-accent-subtle)',
    border: 'rgba(214, 164, 91, 0.35)',
    spin: true,
  },
  succeeded: {
    label: 'Completed',
    icon: CheckCircle2,
    color: 'var(--color-safe-text)',
    bg: 'var(--color-safe-bg)',
    border: 'var(--color-safe-border)',
  },
  partial: {
    label: 'Partial',
    icon: AlertCircle,
    color: 'var(--color-suspicious-text)',
    bg: 'var(--color-suspicious-bg)',
    border: 'var(--color-suspicious-border)',
  },
  failed: {
    label: 'Failed',
    icon: XCircle,
    color: 'var(--color-malicious-text)',
    bg: 'var(--color-malicious-bg)',
    border: 'var(--color-malicious-border)',
  },
};

export function StatusBadge({ status }) {
  const normStatus = (status || 'queued').toLowerCase();
  const cfg = STATUS_CONFIG[normStatus] || STATUS_CONFIG.queued;
  const Icon = cfg.icon;

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.35rem',
        padding: '0.2rem 0.5rem',
        borderRadius: '4px',
        fontSize: '0.725rem',
        fontWeight: 600,
        fontFamily: 'var(--font-mono)',
        backgroundColor: cfg.bg,
        color: cfg.color,
        border: `1px solid ${cfg.border}`,
      }}
    >
      <Icon size={12} className={cfg.spin ? 'animate-spin' : ''} />
      <span>{cfg.label}</span>
    </span>
  );
}
