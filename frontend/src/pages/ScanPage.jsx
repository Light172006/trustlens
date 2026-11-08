/**
 * ScanPage Component
 * Dedicated page for launching a new web threat investigation.
 */

import React from 'react';
import { Shield, Info, CheckCircle2, AlertOctagon } from 'lucide-react';
import { UrlScannerForm } from '../components/scanner/UrlScannerForm';

export function ScanPage() {
  return (
    <div style={{ maxWidth: '900px', margin: '0 auto' }}>
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '1.4rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
          New Web Threat Investigation
        </h1>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
          Submit a website URL to evaluate reputation, redirect hops, transport layer security, and threat indicators.
        </p>
      </div>

      <div style={{ marginBottom: '2rem' }}>
        <UrlScannerForm />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem' }}>
        <div className="tl-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem', color: 'var(--color-accent)' }}>
            <Info size={18} />
            <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>Investigation Methodology</span>
          </div>
          <ul style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', paddingLeft: '1.2rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
            <li>SSRF defenses prevent scanning loopback, metadata, or private IP networks.</li>
            <li>HTTP & HTTPS protocols on ports 80 and 443 are fully probed.</li>
            <li>Threat intelligence caches match real-time feeds from OpenPhish and URLhaus.</li>
            <li>HTTP redirection chains are traced to uncover masked landing pages.</li>
          </ul>
        </div>

        <div className="tl-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem', color: 'var(--color-accent)' }}>
            <Shield size={18} />
            <span style={{ fontWeight: 600, fontSize: '0.9rem' }}>Sensitive Target Mode</span>
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            When <strong>Treat as sensitive URL</strong> is enabled, external lookup queries to URLhaus are intentionally omitted to preserve organization confidentiality. As a result, the target cannot receive a <code>SAFE</code> verdict and will resolve to <code>INCONCLUSIVE</code> or <code>SUSPICIOUS</code>.
          </p>
        </div>
      </div>
    </div>
  );
}
