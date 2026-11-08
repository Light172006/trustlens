/**
 * VerdictBadge Component
 * Renders one of four security verdicts (SAFE, SUSPICIOUS, MALICIOUS, INCONCLUSIVE)
 * with strict adherence to cybersecurity disclaimers (e.g. no green padlock).
 */

import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert, HelpCircle } from 'lucide-react';
import { VERDICT_CONFIG, VERDICT_DESCRIPTIONS } from '../../lib/utils';
import { Tooltip } from 'antd';

export function VerdictBadge({ verdict, showDescription = false, size = 'default' }) {
  const normVerdict = (verdict || 'INCONCLUSIVE').toUpperCase();
  const config = VERDICT_CONFIG[normVerdict] || VERDICT_CONFIG.INCONCLUSIVE;
  const description = VERDICT_DESCRIPTIONS[normVerdict] || VERDICT_DESCRIPTIONS.INCONCLUSIVE;

  const getIcon = () => {
    switch (normVerdict) {
      case 'SAFE':
        return <ShieldCheck size={size === 'large' ? 18 : 14} />;
      case 'SUSPICIOUS':
        return <AlertTriangle size={size === 'large' ? 18 : 14} />;
      case 'MALICIOUS':
        return <ShieldAlert size={size === 'large' ? 18 : 14} />;
      case 'INCONCLUSIVE':
      default:
        return <HelpCircle size={size === 'large' ? 18 : 14} />;
    }
  };

  const badgeContent = (
    <span
      className={`badge-tag ${normVerdict}`}
      style={{
        padding: size === 'large' ? '0.35rem 0.75rem' : '0.2rem 0.55rem',
        fontSize: size === 'large' ? '0.85rem' : '0.725rem',
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.4rem',
        borderRadius: '4px',
      }}
    >
      {getIcon()}
      <span>{config.label}</span>
    </span>
  );

  return (
    <div style={{ display: 'inline-flex', flexDirection: 'column', gap: '0.25rem' }}>
      <Tooltip title={description} placement="top">
        {badgeContent}
      </Tooltip>
      {showDescription && (
        <span style={{ fontSize: '0.775rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
          {description}
        </span>
      )}
    </div>
  );
}
