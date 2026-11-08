/**
 * RiskScoreGauge Component
 * Clean, compact visual indicator of the 0-100 risk score.
 */

import React from 'react';

export function RiskScoreGauge({ score, size = 'default' }) {
  if (score === null || score === undefined) {
    return (
      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}>
        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: size === 'large' ? '1.5rem' : '0.9rem',
            color: 'var(--text-muted)',
            fontWeight: 600,
          }}
        >
          N/A
        </span>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>(Insufficient telemetry)</span>
      </div>
    );
  }

  const numScore = Math.min(100, Math.max(0, Number(score)));
  
  // Determine color based on threshold
  let color = 'var(--color-safe-text)';
  let label = 'Low Risk';
  if (numScore >= 75) {
    color = 'var(--color-malicious-text)';
    label = 'Critical Risk';
  } else if (numScore >= 40) {
    color = 'var(--color-suspicious-text)';
    label = 'Elevated Risk';
  } else if (numScore > 15) {
    color = 'var(--severity-medium)';
    label = 'Moderate Risk';
  }

  if (size === 'large') {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', minWidth: '160px' }}>
        <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.3rem' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '2.25rem', fontWeight: 700, color }}>
              {numScore}
            </span>
            <span style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>/ 100</span>
          </div>
          <span style={{ fontSize: '0.75rem', fontWeight: 600, color, fontFamily: 'var(--font-mono)' }}>
            {label}
          </span>
        </div>
        <div
          style={{
            width: '100%',
            height: '6px',
            backgroundColor: 'var(--border-color)',
            borderRadius: '999px',
            overflow: 'hidden',
          }}
        >
          <div
            style={{
              width: `${numScore}%`,
              height: '100%',
              backgroundColor: color,
              borderRadius: '999px',
              transition: 'width 0.4s ease',
            }}
          />
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.6rem' }}>
      <div
        style={{
          width: '48px',
          height: '4px',
          backgroundColor: 'var(--border-color)',
          borderRadius: '999px',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            width: `${numScore}%`,
            height: '100%',
            backgroundColor: color,
            borderRadius: '999px',
          }}
        />
      </div>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', fontWeight: 600, color }}>
        {numScore}
      </span>
    </div>
  );
}
