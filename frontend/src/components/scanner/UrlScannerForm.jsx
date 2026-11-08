/**
 * UrlScannerForm Component
 * Core target URL input with scheme validation, sensitive URL privacy toggle,
 * deduplication handling, and quick demo presets.
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, ShieldAlert, Lock, Info, ArrowRight, Loader2 } from 'lucide-react';
import { Input, Button, Checkbox, message, Alert } from 'antd';
import { validateUrl } from '../../lib/utils';
import { scanService } from '../../services/scan.service';

export function UrlScannerForm({ onScanSubmitted, compact = false }) {
  const [url, setUrl] = useState('');
  const [treatAsSensitive, setTreatAsSensitive] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [inlineError, setInlineError] = useState('');
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    if (e) e.preventDefault();
    setInlineError('');

    // Pre-flight client validation
    const validation = validateUrl(url);
    if (!validation.valid) {
      setInlineError(validation.error);
      return;
    }

    setIsLoading(true);

    try {
      const res = await scanService.submitScan(url.trim(), treatAsSensitive);
      const scanId = res.scan?.id || res.id;

      if (res.deduplicated) {
        message.info('Identical recent scan found. Navigating to existing assessment.');
      } else {
        message.success('Target queued for security investigation.');
      }

      if (onScanSubmitted) {
        onScanSubmitted(res);
      } else if (scanId) {
        navigate(`/scans/${scanId}`);
      }
    } catch (err) {
      const payload = err.error || err;
      setInlineError(payload.message || 'Unable to submit URL for scanning.');
    } finally {
      setIsLoading(false);
    }
  };

  const handlePresetSelect = (presetUrl, sensitive = false) => {
    setUrl(presetUrl);
    setTreatAsSensitive(sensitive);
    setInlineError('');
  };

  return (
    <div className="tl-card" style={{ padding: compact ? '1rem' : '1.5rem' }}>
      <form onSubmit={handleSubmit}>
        <div style={{ display: 'flex', gap: '0.75rem', flexDirection: compact ? 'column' : 'row' }}>
          <div style={{ flex: 1, position: 'relative' }}>
            <Input
              size="large"
              placeholder="Enter target URL (e.g. https://example.com/login)"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                if (inlineError) setInlineError('');
              }}
              prefix={<Search size={16} style={{ color: 'var(--text-muted)', marginRight: '4px' }} />}
              disabled={isLoading}
              status={inlineError ? 'error' : ''}
              allowClear
              style={{
                backgroundColor: 'var(--bg-app)',
                borderColor: inlineError ? 'var(--color-malicious)' : 'var(--border-color)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.875rem',
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
              minWidth: '140px',
              color: '#101112',
            }}
          >
            {isLoading ? 'Submitting...' : 'Analyze Target'}
          </Button>
        </div>

        {inlineError && (
          <div style={{ marginTop: '0.75rem' }}>
            <Alert
              message={inlineError}
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

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '0.75rem',
            marginTop: '1rem',
            paddingTop: '0.75rem',
            borderTop: '1px solid var(--border-color-subtle)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Checkbox
              checked={treatAsSensitive}
              onChange={(e) => setTreatAsSensitive(e.target.checked)}
              disabled={isLoading}
            >
              <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                Treat as sensitive URL
              </span>
            </Checkbox>
            <span
              style={{
                fontSize: '0.725rem',
                color: 'var(--text-muted)',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '0.2rem',
              }}
              title="Protects privacy by skipping third-party URLhaus telemetry queries. The SAFE verdict is disabled for sensitive submissions."
            >
              <Info size={12} />
              (Skips external threat share)
            </span>
          </div>

          {/* Quick presets for demonstration */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>Demo Presets:</span>
            <Button
              type="text"
              size="small"
              onClick={() => handlePresetSelect('https://example.com/login', false)}
              style={{ fontSize: '0.725rem', color: 'var(--color-safe-text)', padding: '0 4px', height: '22px' }}
            >
              Safe
            </Button>
            <span style={{ color: 'var(--border-color)' }}>•</span>
            <Button
              type="text"
              size="small"
              onClick={() => handlePresetSelect('http://account-verify-login.xyz', false)}
              style={{ fontSize: '0.725rem', color: 'var(--color-suspicious-text)', padding: '0 4px', height: '22px' }}
            >
              Suspicious
            </Button>
            <span style={{ color: 'var(--border-color)' }}>•</span>
            <Button
              type="text"
              size="small"
              onClick={() => handlePresetSelect('http://update-secure-banking-portal.net/login.php', false)}
              style={{ fontSize: '0.725rem', color: 'var(--color-malicious-text)', padding: '0 4px', height: '22px' }}
            >
              Malicious
            </Button>
            <span style={{ color: 'var(--border-color)' }}>•</span>
            <Button
              type="text"
              size="small"
              onClick={() => handlePresetSelect('https://internal-dev-cluster-99.net', true)}
              style={{ fontSize: '0.725rem', color: 'var(--color-inconclusive-text)', padding: '0 4px', height: '22px' }}
            >
              Inconclusive
            </Button>
          </div>
        </div>
      </form>
    </div>
  );
}
