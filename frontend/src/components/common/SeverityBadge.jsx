/**
 * SeverityBadge Component
 * Displays finding severities with distinct color tokens.
 */

import React from 'react';
import { SEVERITY_CONFIG } from '../../lib/utils';

export function SeverityBadge({ severity }) {
  const norm = (severity || 'info').toLowerCase();
  const cfg = SEVERITY_CONFIG[norm] || SEVERITY_CONFIG.info;

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: '0.15rem 0.45rem',
        borderRadius: '3px',
        fontSize: '0.7rem',
        fontWeight: 700,
        fontFamily: 'var(--font-mono)',
        letterSpacing: '0.04em',
        textTransform: 'uppercase',
        backgroundColor: cfg.bg,
        color: cfg.color,
        border: `1px solid ${cfg.color}33`,
      }}
    >
      {cfg.label}
    </span>
  );
}
