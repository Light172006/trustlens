/**
 * TrustLens ScanPage Component
 * Dedicated page for submitting targets to the asynchronous Celery pipeline
 * and monitoring progress.
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, Shield, Zap, Lock, Info } from 'lucide-react';
import { UrlScannerForm } from '../components/scanner/UrlScannerForm';
import { ScanStatusStepper } from '../components/scanner/ScanStatusStepper';

export function ScanPage() {
  const [activeScan, setActiveScan] = useState(null);
  const navigate = useNavigate();

  const handleScanSubmitted = (res) => {
    const scan = res.scan || res;
    setActiveScan(scan);
    if (scan.id) {
      setTimeout(() => {
        navigate(`/scans/${scan.id}`);
      }, 1500);
    }
  };

  return (
    <div style={{ maxWidth: '960px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
          Asynchronous Website Security Investigation
        </h1>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
          Executes multi-stage safe network telemetry, DNS validation, TLS handshake inspection,
          feed correlation (OpenPhish, URLhaus), and multiclass machine learning threat assessment.
        </p>
      </div>

      {activeScan && (
        <ScanStatusStepper
          status={activeScan.status || 'queued'}
          checksCompleted={activeScan.checks_completed || 0}
        />
      )}

      <UrlScannerForm onScanSubmitted={handleScanSubmitted} />

      {/* Pipeline Information Card */}
      <div className="tl-card" style={{ padding: '1.5rem' }}>
        <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.75rem' }}>
          Investigation Verification Stages
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
          <div style={{ padding: '0.75rem', backgroundColor: 'var(--bg-app)', borderRadius: 'var(--radius-md)' }}>
            <div style={{ fontWeight: 600, fontSize: '0.8rem', color: 'var(--color-accent)', marginBottom: '0.25rem' }}>
              1. Strict SSRF Defense
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
              Resolves destination IPs, blocking loopback, RFC 1918 private subnets, cloud metadata (169.254.169.254), and carrier-grade NAT.
            </p>
          </div>

          <div style={{ padding: '0.75rem', backgroundColor: 'var(--bg-app)', borderRadius: 'var(--radius-md)' }}>
            <div style={{ fontWeight: 600, fontSize: '0.8rem', color: 'var(--color-accent)', marginBottom: '0.25rem' }}>
              2. DNS & HTTP Telemetry
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
              Safe passive inspection of security headers (HSTS, CSP), cookies, redirect chains (up to 5 hops), and server banners.
            </p>
          </div>

          <div style={{ padding: '0.75rem', backgroundColor: 'var(--bg-app)', borderRadius: 'var(--radius-md)' }}>
            <div style={{ fontWeight: 600, fontSize: '0.8rem', color: 'var(--color-accent)', marginBottom: '0.25rem' }}>
              3. TLS & PKI Intelligence
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
              Evaluates X.509 certification paths against Mozilla Root Store, CA/B Forum baseline rules, and RFC 9525 identity validation.
            </p>
          </div>

          <div style={{ padding: '0.75rem', backgroundColor: 'var(--bg-app)', borderRadius: 'var(--radius-md)' }}>
            <div style={{ fontWeight: 600, fontSize: '0.8rem', color: 'var(--color-accent)', marginBottom: '0.25rem' }}>
              4. ML & Threat Feeds
            </div>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
              Correlates live indicators with OpenPhish and URLhaus feeds, yielding a calibrated Risk Score (0-100) and explainable verdict.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

