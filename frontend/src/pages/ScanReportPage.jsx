/**
 * ScanReportPage Component
 * Comprehensive security investigation report page with real-time polling,
 * exact canonical verdict copy, findings filter, threat provider coverage,
 * and the signature Redirect Investigation Explorer.
 */

import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  HelpCircle,
  Clock,
  ExternalLink,
  Globe,
  Radio,
  FileText,
  Key,
  GitFork,
  AlertCircle,
  Copy,
  Check,
  RotateCw,
  ArrowLeft,
  Lock,
} from 'lucide-react';
import { Tabs, Tag, Button, Alert, message } from 'antd';
import { scanService } from '../services/scan.service';
import { certificateService } from '../services/certificate.service';
import { ScanStatusStepper } from '../components/scanner/ScanStatusStepper';
import { FindingCard } from '../components/report/FindingCard';
import { RedirectExplorer } from '../components/report/RedirectExplorer';
import { StatusBadge } from '../components/common/StatusBadge';
import { RiskScoreGauge } from '../components/common/RiskScoreGauge';
import { ErrorState } from '../components/common/ErrorState';
import { EmptyState } from '../components/common/EmptyState';
import { VERDICT_DESCRIPTIONS, formatDate, formatRelativeTime } from '../lib/utils';

export function ScanReportPage() {
  const { scanId } = useParams();
  const navigate = useNavigate();

  const [scanData, setScanData] = useState(null);
  const [findings, setFindings] = useState([]);
  const [certInfo, setCertInfo] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [copiedUrl, setCopiedUrl] = useState(false);
  const [selectedSeverityFilter, setSelectedSeverityFilter] = useState('all');

  const pollingTimerRef = useRef(null);
  const pollStartTimeRef = useRef(0);
  const isDocumentVisibleRef = useRef(true);

  // Fetch report data
  const fetchReport = useCallback(async (isInitial = false) => {
    if (isInitial) setIsLoading(true);
    try {
      const reportRes = await scanService.getScan(scanId);
      setScanData(reportRes);
      setError(null);

      // If finished, load findings and certificate assessment
      const status = reportRes?.scan?.status;
      if (['succeeded', 'partial', 'failed'].includes(status)) {
        try {
          const findingsRes = await scanService.getFindings(scanId);
          setFindings(findingsRes?.items || []);
        } catch {
          setFindings([]);
        }

        try {
          const certRes = await certificateService.getCertificate(scanId);
          setCertInfo(certRes);
        } catch {
          setCertInfo(null);
        }
      }
      return reportRes?.scan?.status;
    } catch (err) {
      setError(err);
      return 'error';
    } finally {
      if (isInitial) setIsLoading(false);
    }
  }, [scanId]);

  // Polling loop adhering strictly to section 5.2 of FRONTEND_REQUIREMENTS.md:
  // - Poll every 2s for first 30s
  // - Back off to 5s afterward
  // - Cancel on terminal states (succeeded, partial, failed)
  // - Pause when document is hidden, resume when visible
  useEffect(() => {
    pollStartTimeRef.current = Date.now();
    let isMounted = true;

    const executePoll = async () => {
      if (!isMounted) return;

      // Only poll if document is visible
      if (isDocumentVisibleRef.current) {
        const currentStatus = await fetchReport(false);
        if (['succeeded', 'partial', 'failed', 'error'].includes(currentStatus)) {
          // Terminal state reached: cancel polling
          return;
        }
      }

      // Calculate backoff interval
      const elapsedMs = Date.now() - pollStartTimeRef.current;
      const intervalMs = elapsedMs < 30000 ? 2000 : 5000;

      pollingTimerRef.current = setTimeout(executePoll, intervalMs);
    };

    // Initial load
    fetchReport(true).then((initialStatus) => {
      if (initialStatus === 'queued' || initialStatus === 'running') {
        pollingTimerRef.current = setTimeout(executePoll, 2000);
      }
    });

    // Handle visibility changes
    const handleVisibilityChange = () => {
      isDocumentVisibleRef.current = !document.hidden;
      if (!document.hidden && scanData?.scan?.status && ['queued', 'running'].includes(scanData.scan.status)) {
        // Immediate poll upon returning to tab
        if (pollingTimerRef.current) clearTimeout(pollingTimerRef.current);
        executePoll();
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      isMounted = false;
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      if (pollingTimerRef.current) clearTimeout(pollingTimerRef.current);
    };
  }, [scanId, fetchReport]);

  const handleCopyUrl = (urlToCopy) => {
    if (!urlToCopy) return;
    navigator.clipboard.writeText(urlToCopy);
    setCopiedUrl(true);
    message.success('Target URL copied to clipboard');
    setTimeout(() => setCopiedUrl(false), 2000);
  };

  if (isLoading) {
    return (
      <div style={{ padding: '3rem 1.5rem', textAlign: 'center' }}>
        <RotateCw size={28} className="animate-spin" style={{ color: 'var(--color-accent)', margin: '0 auto 1rem' }} />
        <h3 style={{ fontSize: '1rem', color: 'var(--text-primary)' }}>Loading Threat Intelligence Report...</h3>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Querying scan assessment repository</p>
      </div>
    );
  }

  if (error) {
    return <ErrorState error={error} onRetry={() => fetchReport(true)} />;
  }

  if (!scanData?.scan) {
    return (
      <EmptyState
        title="Assessment Not Found"
        description={`No scan record matching ID '${scanId}' could be located.`}
        actionLabel="Return to Console"
        onAction={() => navigate('/dashboard')}
      />
    );
  }

  const { scan, coverage, provider_checks = [], redirects = [] } = scanData;
  const isTerminal = ['succeeded', 'partial', 'failed'].includes(scan.status);
  const isSensitive = scan.is_sensitive;
  const canonicalVerdict = scan.verdict || 'INCONCLUSIVE';
  const verdictCopy = VERDICT_DESCRIPTIONS[canonicalVerdict] || VERDICT_DESCRIPTIONS.INCONCLUSIVE;

  // Filter findings
  const filteredFindings = selectedSeverityFilter === 'all'
    ? findings
    : findings.filter((f) => f.severity === selectedSeverityFilter);

  // Tab definitions
  const tabItems = [
    {
      key: 'findings',
      label: (
        <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <FileText size={14} />
          <span>Security Findings ({findings.length})</span>
        </span>
      ),
      children: (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Heuristic evaluations and vulnerability observations
            </div>

            {/* Severity Filter Pills */}
            <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
              {['all', 'critical', 'high', 'medium', 'low', 'info'].map((sev) => {
                const count = sev === 'all' ? findings.length : findings.filter((f) => f.severity === sev).length;
                if (sev !== 'all' && count === 0) return null;
                const isSelected = selectedSeverityFilter === sev;
                return (
                  <button
                    key={sev}
                    onClick={() => setSelectedSeverityFilter(sev)}
                    style={{
                      padding: '0.2rem 0.5rem',
                      borderRadius: '3px',
                      fontSize: '0.725rem',
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 600,
                      textTransform: 'uppercase',
                      cursor: 'pointer',
                      border: `1px solid ${isSelected ? 'var(--color-accent)' : 'var(--border-color)'}`,
                      backgroundColor: isSelected ? 'var(--color-accent-subtle)' : 'var(--bg-surface)',
                      color: isSelected ? 'var(--color-accent)' : 'var(--text-secondary)',
                    }}
                  >
                    {sev} ({count})
                  </button>
                );
              })}
            </div>
          </div>

          {filteredFindings.length === 0 ? (
            <div
              style={{
                padding: '2.5rem 1.5rem',
                textAlign: 'center',
                backgroundColor: 'var(--bg-surface)',
                borderRadius: 'var(--radius-md)',
                border: '1px solid var(--border-color)',
              }}
            >
              <Check size={24} color="var(--color-safe-text)" style={{ margin: '0 auto 0.5rem' }} />
              <div style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                No findings in this category
              </div>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                Perimeter heuristic scans observed no flagged anomalies matching the selected filter.
              </p>
            </div>
          ) : (
            filteredFindings.map((finding, idx) => (
              <FindingCard key={idx} finding={finding} />
            ))
          )}
        </div>
      ),
    },
    {
      key: 'redirects',
      label: (
        <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <GitFork size={14} />
          <span>Redirect Chain ({redirects.length})</span>
        </span>
      ),
      children: (
        <RedirectExplorer
          redirects={redirects}
          originalUrl={scan.original_url}
          canonicalUrl={scan.canonical_url}
        />
      ),
    },
    {
      key: 'providers',
      label: (
        <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <Radio size={14} />
          <span>Threat Feeds ({provider_checks.length})</span>
        </span>
      ),
      children: (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Real-time feed telemetry matching against global threat databases
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
            {provider_checks.map((p, idx) => {
              const isMatch = p.matched;
              const isClean = p.result_status === 'no_match';
              const isSkipped = p.result_status === 'skipped_sensitive_url';
              const isUnavailable = ['unavailable', 'not_configured', 'stale_cache'].includes(p.result_status);

              return (
                <div key={idx} className="tl-card" style={{ padding: '1rem 1.25rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <Radio size={16} color="var(--color-accent)" />
                      <span style={{ fontWeight: 600, fontSize: '0.9rem', textTransform: 'capitalize' }}>
                        {p.provider}
                      </span>
                    </div>

                    {isMatch && (
                      <span className="badge-tag MALICIOUS">MATCH (MALICIOUS)</span>
                    )}
                    {isClean && (
                      <span className="badge-tag SAFE">CLEAN (NO MATCH)</span>
                    )}
                    {isSkipped && (
                      <span className="badge-tag INCONCLUSIVE">SKIPPED (PRIVACY)</span>
                    )}
                    {isUnavailable && (
                      <span className="badge-tag SUSPICIOUS">FEED UNAVAILABLE</span>
                    )}
                  </div>

                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>
                    {isMatch
                      ? 'Target URL matches a confirmed phishing/malware signature in this intelligence feed.'
                      : isClean
                      ? 'No malicious matches registered for this host in active feed snapshots.'
                      : isSkipped
                      ? 'External feed check was skipped because target was flagged as sensitive.'
                      : 'This source could not be checked. It is not a clean result.'}
                  </p>

                  <div style={{ fontSize: '0.725rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', borderTop: '1px solid var(--border-color-subtle)', paddingTop: '0.5rem', display: 'flex', justifyContent: 'space-between' }}>
                    <span>Checked: {formatRelativeTime(p.checked_at)}</span>
                    <span>Status: {p.result_status}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ),
    },
    {
      key: 'certificate',
      label: (
        <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <Key size={14} />
          <span>Certificate Preview</span>
        </span>
      ),
      children: (
        <div className="tl-card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
            <div>
              <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                X.509 Cryptographic Identity
              </h4>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                Inspect TLS certificates, authority validity, and expiration parameters
              </p>
            </div>
            <Button
              type="primary"
              size="small"
              onClick={() => navigate(`/scans/${scanId}/certificate`)}
              style={{ backgroundColor: 'var(--color-accent)', borderColor: 'var(--color-accent)', color: '#101112', fontWeight: 600 }}
            >
              Full Certificate Intelligence →
            </Button>
          </div>

          <div
            style={{
              padding: '0.85rem 1rem',
              borderRadius: 'var(--radius-sm)',
              backgroundColor: 'var(--bg-app)',
              border: '1px solid var(--border-color)',
              fontSize: '0.8rem',
              color: 'var(--text-secondary)',
              lineHeight: 1.5,
              marginBottom: '1rem',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--color-accent)', fontWeight: 600, marginBottom: '0.25rem' }}>
              <AlertTriangle size={14} />
              CRITICAL SECURITY DISTINCTION
            </div>
            A valid TLS certificate guarantees only encryption in transit between client and server. <strong>A valid certificate is NOT proof that a website is trustworthy, legitimate, or benign.</strong> Phishing sites frequently employ valid Let's Encrypt certificates.
          </div>

          {/* Live Certificate Analyzer Assessment Summary if available */}
          {certInfo && (certInfo.assessment || certInfo.certificate) && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0.85rem 1rem',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--bg-surface-secondary)',
                border: '1px solid var(--border-color)',
                marginBottom: '1rem',
                flexWrap: 'wrap',
                gap: '0.75rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <div
                  style={{
                    fontSize: '1.25rem',
                    fontWeight: 800,
                    color: (certInfo.assessment?.trust_score ?? certInfo.certificate?.trust_score ?? 80) >= 80 ? 'var(--color-safe-text)' : 'var(--color-suspicious-text)',
                  }}
                >
                  {certInfo.assessment?.trust_score ?? certInfo.certificate?.trust_score ?? '—'}/100
                </div>
                <div>
                  <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                    Certificate Trust Score: {certInfo.assessment?.verdict || certInfo.certificate?.verdict || (certInfo.certificate?.chain_valid ? 'TRUSTED' : 'DISTRUSTED')}
                  </div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                    CA/B Forum BR v2.3.1 Evaluated • {certInfo.assessment?.confidence ? `${Math.round(certInfo.assessment.confidence * 100)}% Confidence` : 'Verified Evidence'}
                  </div>
                </div>
              </div>

              <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                Issuer: {certInfo.certificate?.issuer_o || certInfo.certificate?.issuer || '—'}
              </div>
            </div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
            <div>
              <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>TARGET HOST</div>
              <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.2rem' }}>
                {scan.host}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>TRANSPORT SCHEME</div>
              <div style={{ fontSize: '0.85rem', fontFamily: 'var(--font-mono)', color: scan.scheme === 'https' ? 'var(--color-safe-text)' : 'var(--color-malicious-text)', marginTop: '0.2rem', textTransform: 'uppercase' }}>
                {scan.scheme}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>LAYER COVERAGE</div>
              <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.2rem', textTransform: 'capitalize' }}>
                {coverage?.certificate || 'Complete'}
              </div>
            </div>
          </div>
        </div>
      ),
    },
  ];

  return (
    <div>
      {/* Back button and quick actions */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.75rem' }}>
        <button
          onClick={() => navigate('/dashboard')}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.4rem',
            color: 'var(--text-secondary)',
            fontSize: '0.825rem',
            cursor: 'pointer',
          }}
        >
          <ArrowLeft size={14} />
          Back to Overview
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Button
            size="small"
            icon={<RotateCw size={13} />}
            onClick={() => fetchReport(false)}
            style={{ color: 'var(--text-secondary)' }}
          >
            Refresh Report
          </Button>
          <Button
            size="small"
            icon={<Key size={13} />}
            onClick={() => navigate(`/scans/${scanId}/certificate`)}
            style={{ color: 'var(--text-primary)' }}
          >
            Inspect Certificate
          </Button>
        </div>
      </div>

      {/* Target Header Card */}
      <div className="tl-card" style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div style={{ flex: 1, minWidth: '280px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.4rem' }}>
              <span style={{ fontSize: '0.725rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                TARGET HOST
              </span>
              <StatusBadge status={scan.status} />
              {isSensitive && (
                <span className="badge-tag INCONCLUSIVE" title="Sensitive target mode enabled">
                  SENSITIVE
                </span>
              )}
            </div>

            <h1 style={{ fontSize: '1.4rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)', wordBreak: 'break-all' }}>
              {scan.host}
            </h1>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                marginTop: '0.5rem',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.775rem',
                color: 'var(--text-secondary)',
                wordBreak: 'break-all',
              }}
            >
              <span>{scan.canonical_url}</span>
              <button
                onClick={() => handleCopyUrl(scan.canonical_url)}
                style={{ color: 'var(--text-muted)', display: 'inline-flex', alignItems: 'center' }}
                title="Copy URL"
              >
                {copiedUrl ? <Check size={14} color="var(--color-safe-text)" /> : <Copy size={14} />}
              </button>
            </div>
          </div>

          {/* Quick Risk Score View */}
          <div style={{ textAlign: 'right', display: 'flex', flexDirection: 'column', alignItems: 'flex-end' }}>
            <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>AGGREGATE RISK SCORE</span>
            <RiskScoreGauge score={scan.risk_score} size="large" />
          </div>
        </div>

        {/* Scan Metadata Row */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '1.5rem',
            flexWrap: 'wrap',
            marginTop: '1.25rem',
            paddingTop: '0.85rem',
            borderTop: '1px solid var(--border-color-subtle)',
            fontSize: '0.75rem',
            color: 'var(--text-muted)',
          }}
        >
          <span>Scan ID: <strong style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{scan.id}</strong></span>
          <span>Initiated: <strong style={{ color: 'var(--text-secondary)' }}>{formatDate(scan.created_at)}</strong></span>
          {scan.completed_at && (
            <span>Completed: <strong style={{ color: 'var(--text-secondary)' }}>{formatDate(scan.completed_at)}</strong></span>
          )}
          <span>Engine: <strong style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{scan.scoring_version}</strong></span>
        </div>
      </div>

      {/* Sensitive URL Warning Banner if applicable */}
      {isSensitive && (
        <Alert
          message="Sensitive URL Analysis Mode"
          description="URLhaus external threat intelligence lookup was skipped to protect privacy. The SAFE verdict is disabled for sensitive URL submissions."
          type="info"
          showIcon
          style={{
            marginBottom: '1.5rem',
            backgroundColor: 'var(--bg-surface-secondary)',
            borderColor: 'var(--border-color)',
            color: 'var(--text-primary)',
          }}
        />
      )}

      {/* Investigation Pipeline Stepper */}
      {!isTerminal && (
        <ScanStatusStepper
          status={scan.status}
          checksCompleted={scan.checks_completed}
          failureMessage={scan.failure_message}
        />
      )}

      {/* Mandatory Verdict Banner */}
      <div className={`verdict-banner ${canonicalVerdict}`}>
        <div className="verdict-icon-container">
          {canonicalVerdict === 'SAFE' && <ShieldCheck size={26} />}
          {canonicalVerdict === 'SUSPICIOUS' && <AlertTriangle size={26} />}
          {canonicalVerdict === 'MALICIOUS' && <ShieldAlert size={26} />}
          {canonicalVerdict === 'INCONCLUSIVE' && <HelpCircle size={26} />}
        </div>

        <div style={{ flex: 1 }}>
          <div className="verdict-header-title">
            <span className="verdict-title-text">
              VERDICT: {canonicalVerdict}
            </span>
          </div>

          <p className="verdict-canonical-copy">
            {verdictCopy}
          </p>

          <div className="verdict-subnote">
            Assessed according to TrustLens scoring criteria ({scan.scoring_version}). Zero-tolerance verification rules applied.
          </div>
        </div>
      </div>

      {/* Tabs Container */}
      <div className="tl-card" style={{ padding: '1rem 1.25rem' }}>
        <Tabs defaultActiveKey="findings" items={tabItems} />
      </div>
    </div>
  );
}
