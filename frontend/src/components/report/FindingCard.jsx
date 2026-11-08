/**
 * FindingCard Component
 * Displays heuristic security findings with risk points, severity, evidence inspector,
 * remediation advice, and origin source tag.
 */

import React, { useState } from 'react';
import {
  ChevronDown,
  ChevronUp,
  Code,
  Wrench,
} from 'lucide-react';
import { SeverityBadge } from '../common/SeverityBadge';
import { Button } from 'antd';

export function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false);

  const {
    code = 'FINDING',
    title = 'Security Finding',
    description = '',
    severity = 'info',
    category = 'web_security',
    points = 0,
    evidence = {},
    remediation = '',
    source = 'scanner',
  } = finding;

  return (
    <div
      style={{
        backgroundColor: 'var(--bg-surface)',
        border: '1px solid var(--border-color)',
        borderRadius: 'var(--radius-md)',
        marginBottom: '0.75rem',
        overflow: 'hidden',
        transition: 'border-color 0.15s ease',
      }}
    >
      {/* Finding Summary Bar */}
      <div
        onClick={() => setExpanded(!expanded)}
        style={{
          padding: '1rem 1.25rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          cursor: 'pointer',
          userSelect: 'none',
          gap: '1rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flex: 1, minWidth: 0 }}>
          <SeverityBadge severity={severity} />
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                {title}
              </span>
              <span
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.7rem',
                  color: 'var(--text-muted)',
                  backgroundColor: 'var(--bg-app)',
                  padding: '0.1rem 0.35rem',
                  borderRadius: '3px',
                }}
              >
                {code}
              </span>
            </div>
            <p
              style={{
                fontSize: '0.8rem',
                color: 'var(--text-secondary)',
                marginTop: '0.2rem',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}
            >
              {description}
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexShrink: 0 }}>
          {points > 0 && (
            <span
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '0.8rem',
                fontWeight: 600,
                color: severity === 'critical' || severity === 'high' ? 'var(--color-malicious-text)' : 'var(--color-suspicious-text)',
                backgroundColor: 'var(--bg-surface-secondary)',
                padding: '0.2rem 0.5rem',
                borderRadius: 'var(--radius-sm)',
              }}
            >
              +{points} pts
            </span>
          )}

          <Button
            type="text"
            size="small"
            icon={expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
            style={{ color: 'var(--text-secondary)' }}
          />
        </div>
      </div>

      {/* Expanded Details Section */}
      {expanded && (
        <div
          style={{
            padding: '1.25rem',
            backgroundColor: 'var(--bg-surface-secondary)',
            borderTop: '1px solid var(--border-color)',
            display: 'flex',
            flexDirection: 'column',
            gap: '1rem',
          }}
        >
          {/* Full description */}
          <div>
            <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '0.25rem' }}>
              ANALYSIS EXPLANATION
            </div>
            <p style={{ fontSize: '0.825rem', color: 'var(--text-primary)', lineHeight: 1.5 }}>
              {description}
            </p>
          </div>

          {/* Remediation */}
          {remediation && (
            <div
              style={{
                padding: '0.75rem 1rem',
                backgroundColor: 'var(--bg-app)',
                borderRadius: 'var(--radius-sm)',
                borderLeft: '3px solid var(--color-accent)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.75rem', fontWeight: 600, color: 'var(--color-accent)', marginBottom: '0.25rem' }}>
                <Wrench size={13} />
                RECOMMENDED REMEDIATION
              </div>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                {remediation}
              </p>
            </div>
          )}

          {/* Technical Evidence */}
          {evidence && Object.keys(evidence).length > 0 && (
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.725rem', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '0.35rem' }}>
                <Code size={13} />
                TECHNICAL EVIDENCE
              </div>
              <pre
                style={{
                  backgroundColor: 'var(--bg-app)',
                  border: '1px solid var(--border-color)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '0.75rem',
                  fontSize: '0.75rem',
                  fontFamily: 'var(--font-mono)',
                  color: 'var(--text-secondary)',
                  overflowX: 'auto',
                }}
              >
                {JSON.stringify(evidence, null, 2)}
              </pre>
            </div>
          )}

          {/* Metadata Footer */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.725rem', color: 'var(--text-muted)', paddingTop: '0.5rem', borderTop: '1px solid var(--border-color-subtle)' }}>
            <span>Category: <strong style={{ color: 'var(--text-secondary)' }}>{category}</strong></span>
            <span>Source Engine: <strong style={{ color: 'var(--text-secondary)' }}>{source}</strong></span>
          </div>
        </div>
      )}
    </div>
  );
}
