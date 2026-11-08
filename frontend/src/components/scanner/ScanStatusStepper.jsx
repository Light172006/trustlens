/**
 * ScanStatusStepper Component
 * Real-time investigation stepper reflecting authentic backend pipeline stages.
 * Strictly avoids fake percentages (e.g. "45% complete").
 */

import React from 'react';
import { Clock, Globe, Shield, CheckCircle2, AlertOctagon, Loader2 } from 'lucide-react';

const STEPS = [
  { id: 1, key: 'queued', label: 'Queued', icon: Clock },
  { id: 2, key: 'network', label: 'Inspecting Network & DNS', icon: Globe },
  { id: 3, key: 'threat_intel', label: 'Running Threat Intelligence', icon: Shield },
  { id: 4, key: 'completed', label: 'Completed', icon: CheckCircle2 },
];

export function ScanStatusStepper({ status = 'queued', checksCompleted = 0, failureMessage = null }) {
  const normStatus = (status || 'queued').toLowerCase();

  // Determine active step index (0-based)
  let activeStep = 0;
  if (normStatus === 'queued') {
    activeStep = 0;
  } else if (normStatus === 'running') {
    if (checksCompleted >= 3) {
      activeStep = 2;
    } else {
      activeStep = 1;
    }
  } else if (normStatus === 'succeeded' || normStatus === 'partial') {
    activeStep = 3;
  } else if (normStatus === 'failed') {
    activeStep = checksCompleted > 0 ? 1 : 0;
  }

  const isFailed = normStatus === 'failed';

  return (
    <div
      style={{
        padding: '1.5rem',
        backgroundColor: 'var(--bg-surface)',
        borderRadius: 'var(--radius-lg)',
        border: '1px solid var(--border-color)',
        marginBottom: '1.5rem',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          {normStatus === 'running' || normStatus === 'queued' ? (
            <Loader2 size={16} className="animate-spin" color="var(--color-accent)" />
          ) : isFailed ? (
            <AlertOctagon size={16} color="var(--color-malicious-text)" />
          ) : (
            <CheckCircle2 size={16} color="var(--color-safe-text)" />
          )}
          <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            Investigation Pipeline Status
          </span>
        </div>
        <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
          {normStatus.toUpperCase()} ({checksCompleted}/4 stages verified)
        </span>
      </div>

      <div className="stepper-container">
        <div className="stepper-line" />
        {STEPS.map((step, idx) => {
          const Icon = step.icon;
          const isDone = !isFailed && (idx < activeStep || activeStep === 3);
          const isCurrent = idx === activeStep;
          const isErrorStep = isFailed && idx === activeStep;

          let stepClass = 'stepper-step';
          if (isDone) stepClass += ' completed';
          else if (isCurrent) stepClass += ' active';

          return (
            <div key={step.id} className={stepClass}>
              <div
                className="stepper-circle"
                style={{
                  borderColor: isErrorStep
                    ? 'var(--color-malicious)'
                    : isDone
                    ? 'var(--color-safe)'
                    : isCurrent
                    ? 'var(--color-accent)'
                    : 'var(--border-color)',
                  backgroundColor: isErrorStep
                    ? 'var(--color-malicious-bg)'
                    : isDone
                    ? 'var(--color-safe-bg)'
                    : 'var(--bg-surface)',
                  color: isErrorStep
                    ? 'var(--color-malicious-text)'
                    : isDone
                    ? 'var(--color-safe-text)'
                    : isCurrent
                    ? 'var(--color-accent)'
                    : 'var(--text-muted)',
                }}
              >
                {isDone ? (
                  <CheckCircle2 size={18} />
                ) : isCurrent && (normStatus === 'running' || normStatus === 'queued') ? (
                  <Loader2 size={18} className="animate-spin" />
                ) : (
                  <Icon size={16} />
                )}
              </div>
              <div className="stepper-label">{step.label}</div>
            </div>
          );
        })}
      </div>

      {failureMessage && (
        <div
          style={{
            marginTop: '1.25rem',
            padding: '0.75rem 1rem',
            borderRadius: 'var(--radius-sm)',
            backgroundColor: 'var(--color-malicious-bg)',
            border: '1px solid var(--color-malicious-border)',
            color: 'var(--color-malicious-text)',
            fontSize: '0.8rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <AlertOctagon size={16} style={{ flexShrink: 0 }} />
          <span>Pipeline halted: {failureMessage}</span>
        </div>
      )}
    </div>
  );
}
