/**
 * CertificatePage Component
 * Full X.509 Cryptographic Certificate Intelligence inspector.
 * Implements CA/Browser Forum BR v2.3.1 compliance, RFC 9525 identity validation,
 * RFC 5280 path validation, trust scoring (0-100), and auxiliary ML Advisory.
 */

import React, { useState, useEffect } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
import {
  Key,
  ShieldCheck,
  ShieldAlert,
  ArrowLeft,
  Calendar,
  AlertTriangle,
  RotateCw,
  Copy,
  Check,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Layers,
  Sparkles,
  Search,
  FileCode,
  Globe,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Cpu,
  Info,
} from 'lucide-react';
import { Button, Tag, Tooltip, message, Alert, Tabs, Input, InputNumber, Switch } from 'antd';
import { certificateService } from '../services/certificate.service';
import { scanService } from '../services/scan.service';
import { formatDate, parseDate } from '../lib/utils';
import { ErrorState } from '../components/common/ErrorState';

// Sample self-signed certificate for one-click testing
const SAMPLE_TEST_PEM = `-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQDC7pX8d9zT1TANBgkqhkiG9w0BAQsFADANMQswCQYDVQQDDAJj
YTAeFw0yNjAxMDEwMDAwMDBaFw0yNjEyMzEyMzU5NTlaMBExDzANBgNVBAMMBlRl
c3RJRzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL0Fm2T5x5K0b2M3
t7aB+K6fTzY5qL8u9V0p2N+9oYqYm3lQ0vL4gJ1q2s3t4u5v6w7x8y9z0A1B2C3D
4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6a7b8c9d0e1f2g3h4i5j
6k7l8m9n0o1p2q3r4s5t6u7v8w9x0y1z2A3B4C5D6E7F8G9H0I1J2K3L4M5N6O7P
8Q9R0S1T2U==
-----END CERTIFICATE-----`;

const VERDICT_CONFIG = {
  TRUSTED: {
    label: 'TRUSTED',
    color: 'var(--color-safe-text)',
    bg: 'var(--color-safe-bg)',
    border: 'var(--color-safe-border)',
    icon: ShieldCheck,
    description: 'Certificate is structurally valid, signed by a trusted root, unrevoked, unexpired, and matches target domain.',
  },
  WARNING: {
    label: 'WARNING',
    color: 'var(--color-suspicious-text)',
    bg: 'var(--color-suspicious-bg)',
    border: 'var(--color-suspicious-border)',
    icon: AlertTriangle,
    description: 'Certificate is functional but has policy deviations (e.g. expiring soon, weak cipher negotiation, or long validity).',
  },
  DISTRUSTED: {
    label: 'DISTRUSTED',
    color: 'var(--color-malicious-text)',
    bg: 'var(--color-malicious-bg)',
    border: 'var(--color-malicious-border)',
    icon: ShieldAlert,
    description: 'Certificate possesses critical security flaws: expired, revoked, untrusted root, self-signed, or hostname mismatch.',
  },
  INCONCLUSIVE: {
    label: 'INCONCLUSIVE',
    color: 'var(--color-inconclusive-text)',
    bg: 'var(--color-inconclusive-bg)',
    border: 'var(--color-inconclusive-border)',
    icon: HelpCircle,
    description: 'Input was malformed, corrupted, exceeded limits, or had ambiguous leaf certificates.',
  },
};

const SEVERITY_COLORS = {
  CRITICAL: { color: 'var(--severity-critical)', bg: 'var(--severity-critical-bg)' },
  HIGH: { color: 'var(--severity-high)', bg: 'var(--severity-high-bg)' },
  MEDIUM: { color: 'var(--severity-medium)', bg: 'var(--severity-medium-bg)' },
  LOW: { color: 'var(--severity-low)', bg: 'var(--severity-low-bg)' },
  INFO: { color: 'var(--severity-info)', bg: 'var(--severity-info-bg)' },
};

export function CertificatePage() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();

  const [certData, setCertData] = useState(null);
  const [scan, setScan] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [copiedFingerprint, setCopiedFingerprint] = useState(false);
  const [showDirectConsole, setShowDirectConsole] = useState(!scanId);
  const [expandedFindings, setExpandedFindings] = useState({});

  // Direct Analyzer state
  const [consoleTab, setConsoleTab] = useState('host');
  const [targetHostname, setTargetHostname] = useState('api.trustlens.io');
  const [targetPort, setTargetPort] = useState(443);
  const [pemContent, setPemContent] = useState('');
  const [pemHostname, setPemHostname] = useState('');
  const [includeMlAdvisory, setIncludeMlAdvisory] = useState(true);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisError, setAnalysisError] = useState(null);

  // Load scan data if scanId is present
  useEffect(() => {
    if (!scanId) {
      setShowDirectConsole(true);
      return;
    }

    async function loadData() {
      setIsLoading(true);
      setError(null);
      try {
        const [loadedCert, scanData] = await Promise.all([
          certificateService.getCertificate(scanId),
          scanService.getScan(scanId).catch(() => null),
        ]);
        setCertData(loadedCert);
        if (scanData?.scan) setScan(scanData.scan);
      } catch (err) {
        setError(err);
      } finally {
        setIsLoading(false);
      }
    }

    loadData();
  }, [scanId]);

  // Execute direct analysis
  const handleDirectAnalyze = async (overrideParams = {}) => {
    setIsAnalyzing(true);
    setAnalysisError(null);

    const isHostMode = (overrideParams.mode || consoleTab) === 'host';
    const reqPayload = {
      include_ml_advisory: includeMlAdvisory,
    };

    if (isHostMode) {
      const host = overrideParams.hostname !== undefined ? overrideParams.hostname : targetHostname;
      if (!host || !host.trim()) {
        setAnalysisError({ message: 'Target hostname is required for endpoint TLS analysis.' });
        setIsAnalyzing(false);
        return;
      }
      reqPayload.hostname = host.trim();
      reqPayload.port = overrideParams.port || targetPort || 443;
    } else {
      const pem = overrideParams.pem !== undefined ? overrideParams.pem : pemContent;
      if (!pem || !pem.trim()) {
        setAnalysisError({ message: 'Raw PEM certificate text is required.' });
        setIsAnalyzing(false);
        return;
      }
      reqPayload.pem = pem.trim();
      if (pemHostname && pemHostname.trim()) {
        reqPayload.hostname = pemHostname.trim();
      }
    }

    try {
      const result = await certificateService.analyzeCertificate(reqPayload);
      setCertData(result);
      message.success('Certificate analysis complete');
    } catch (err) {
      const errObj = err?.error || err;
      setAnalysisError(errObj);
      message.error(errObj.message || 'Certificate analysis failed.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleCopy = (text) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedFingerprint(true);
    message.success('SHA-256 fingerprint copied to clipboard');
    setTimeout(() => setCopiedFingerprint(false), 2000);
  };

  const toggleFindingDetails = (index) => {
    setExpandedFindings((prev) => ({
      ...prev,
      [index]: !prev[index],
    }));
  };

  // Extract normalized data model from certData
  const assessment = certData?.assessment_payload || certData?.assessment || (certData?.trust_score !== undefined ? certData : null);
  const rawCert = certData?.certificate || certData || {};
  const features = assessment?.features || {};
  const policyEval = assessment?.policy_evaluation || rawCert?.policy_evaluation;
  const mlAdvisory = assessment?.ml_advisory || rawCert?.ml_advisory;
  const findings = assessment?.findings || rawCert?.findings || [];
  const recommendations = assessment?.recommendations || rawCert?.recommendations || [];

  const host = rawCert.host || certData?.host || scan?.host || targetHostname || 'Target Endpoint';
  const verdictKey = assessment?.verdict || rawCert?.verdict || (rawCert?.chain_valid === false ? 'DISTRUSTED' : 'TRUSTED');
  const verdictConfig = VERDICT_CONFIG[verdictKey] || VERDICT_CONFIG.INCONCLUSIVE;
  const VerdictIcon = verdictConfig.icon;

  const trustScore = assessment?.trust_score ?? rawCert?.trust_score ?? (rawCert?.chain_valid ? 85 : 0);
  const confidence = assessment?.confidence ?? rawCert?.confidence ?? 1.0;
  const confidencePercent = Math.round(confidence * 100);

  const subject = rawCert.subject_cn || rawCert.subject || assessment?.subject_dn || '—';
  const issuer = rawCert.issuer_o || rawCert.issuer || assessment?.issuer_dn || '—';
  const sans = rawCert.sans || rawCert.san_dns || [];
  const fingerprint = assessment?.certificate_sha256 || rawCert.sha256_fingerprint || rawCert.leaf_fingerprint_sha256 || '—';
  const signatureAlgorithm = rawCert.signature_algorithm || features.signature_algorithm || '—';
  const keyAlgorithm = rawCert.key_algorithm || (features.public_key_algorithm ? `${features.public_key_algorithm} (${features.key_size_bits || ''} bit)` : (rawCert.public_key_algorithm ? `${rawCert.public_key_algorithm} (${rawCert.public_key_bits || ''} bit)` : '—'));

  const validFrom = rawCert.valid_from || rawCert.not_before;
  const validTo = rawCert.valid_to || rawCert.not_after;

  let daysUntilExp = rawCert.days_until_expiration;
  if (daysUntilExp === undefined && features.days_until_expiry !== undefined) {
    daysUntilExp = Math.round(features.days_until_expiry);
  } else if (daysUntilExp === undefined && validTo) {
    try {
      const parsedTo = parseDate(validTo);
      if (parsedTo) {
        const diffMs = parsedTo.getTime() - Date.now();
        daysUntilExp = Math.floor(diffMs / (1000 * 60 * 60 * 24));
      } else {
        daysUntilExp = null;
      }
    } catch {
      daysUntilExp = null;
    }
  }

  const isChainValid = features.is_chain_complete ?? rawCert.chain_valid ?? false;
  const hasTrustedAnchor = features.has_trusted_anchor ?? (rawCert.chain_valid === true);
  const isHostnameMatch = features.matches_tested_hostname ?? rawCert.hostname_match ?? true;
  const sctPresent = features.has_scts ?? rawCert.sct_present ?? false;
  const sctCount = features.sct_count ?? (rawCert.sct_present ? 1 : 0);
  const revocationStatus = rawCert.revocation_status || 'not_checked';

  const isExpired = daysUntilExp !== null && daysUntilExp < 0;
  const isExpiringSoon = daysUntilExp !== null && daysUntilExp <= 14 && daysUntilExp >= 0;

  if (isLoading) {
    return (
      <div style={{ padding: '3.5rem 1.5rem', textAlign: 'center' }}>
        <RotateCw size={32} className="animate-spin" style={{ color: 'var(--color-accent)', margin: '0 auto 1.25rem' }} />
        <h3 style={{ fontSize: '1.1rem', color: 'var(--text-primary)', fontWeight: 600 }}>
          Inspecting X.509 Cryptographic Identity...
        </h3>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: '0.35rem' }}>
          Performing RFC 5280 path validation, CA/B Forum v2.3.1 compliance check, and ML advisory assessment.
        </p>
      </div>
    );
  }

  if (error && !certData) {
    return <ErrorState error={error} onRetry={() => window.location.reload()} />;
  }

  return (
    <div style={{ maxWidth: '1080px', margin: '0 auto', paddingBottom: '3rem' }}>
      {/* Top Navigation & Direct Analyzer Toggle */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.75rem' }}>
        {scanId ? (
          <button
            onClick={() => navigate(`/scans/${scanId}`)}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.4rem',
              color: 'var(--text-secondary)',
              fontSize: '0.825rem',
              cursor: 'pointer',
              background: 'none',
              border: 'none',
              padding: 0,
            }}
          >
            <ArrowLeft size={14} />
            Back to Scan Report
          </button>
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Key size={16} color="var(--color-accent)" />
            <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Interactive Certificate Intelligence Console
            </span>
          </div>
        )}

        <Button
          size="small"
          icon={<Search size={13} />}
          onClick={() => setShowDirectConsole(!showDirectConsole)}
          style={{ color: 'var(--text-secondary)' }}
        >
          {showDirectConsole ? 'Hide Analyzer Console' : 'Analyze Another Endpoint / PEM'}
        </Button>
      </div>

      {/* Direct Analysis Console Drawer / Form */}
      {showDirectConsole && (
        <div
          className="tl-card"
          style={{
            marginBottom: '1.75rem',
            border: '1px solid var(--border-color-strong)',
            backgroundColor: 'var(--bg-surface-secondary)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div>
              <h3 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <Cpu size={16} color="var(--color-accent)" />
                Direct Certificate Analyzer
              </h3>
              <p style={{ fontSize: '0.775rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
                Query any live public TLS endpoint or paste PEM-encoded X.509 certificate chains for cryptographic evaluation.
              </p>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Include ML Advisory:</span>
              <Switch checked={includeMlAdvisory} onChange={setIncludeMlAdvisory} size="small" />
            </div>
          </div>

          <Tabs
            activeKey={consoleTab}
            onChange={setConsoleTab}
            items={[
              {
                key: 'host',
                label: (
                  <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <Globe size={13} />
                    <span>Live Endpoint TLS Handshake</span>
                  </span>
                ),
                children: (
                  <div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(200px, 1fr) 110px auto', gap: '0.75rem', alignItems: 'end' }}>
                      <div>
                        <label style={{ display: 'block', fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                          Target Hostname or FQDN
                        </label>
                        <Input
                          placeholder="e.g. api.trustlens.io"
                          value={targetHostname}
                          onChange={(e) => setTargetHostname(e.target.value)}
                          disabled={isAnalyzing}
                          onPressEnter={() => handleDirectAnalyze()}
                        />
                      </div>
                      <div>
                        <label style={{ display: 'block', fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                          TLS Port
                        </label>
                        <InputNumber
                          min={1}
                          max={65535}
                          value={targetPort}
                          onChange={setTargetPort}
                          disabled={isAnalyzing}
                          style={{ width: '100%' }}
                        />
                      </div>
                      <Button
                        type="primary"
                        icon={isAnalyzing ? <RotateCw size={13} className="animate-spin" /> : <Search size={13} />}
                        loading={isAnalyzing}
                        onClick={() => handleDirectAnalyze()}
                        style={{ backgroundColor: 'var(--color-accent)', borderColor: 'var(--color-accent)', color: '#101112', fontWeight: 600 }}
                      >
                        Analyze Endpoint
                      </Button>
                    </div>

                    {/* Quick test presets */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginTop: '0.75rem', flexWrap: 'wrap' }}>
                      <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>Quick Presets:</span>
                      <button
                        onClick={() => {
                          setTargetHostname('github.com');
                          setTargetPort(443);
                          handleDirectAnalyze({ mode: 'host', hostname: 'github.com', port: 443 });
                        }}
                        style={{
                          fontSize: '0.725rem',
                          padding: '0.15rem 0.5rem',
                          background: 'var(--bg-surface)',
                          border: '1px solid var(--border-color)',
                          color: 'var(--text-secondary)',
                          borderRadius: '3px',
                          cursor: 'pointer',
                        }}
                      >
                        github.com
                      </button>
                      <button
                        onClick={() => {
                          setTargetHostname('cloudflare.com');
                          setTargetPort(443);
                          handleDirectAnalyze({ mode: 'host', hostname: 'cloudflare.com', port: 443 });
                        }}
                        style={{
                          fontSize: '0.725rem',
                          padding: '0.15rem 0.5rem',
                          background: 'var(--bg-surface)',
                          border: '1px solid var(--border-color)',
                          color: 'var(--text-secondary)',
                          borderRadius: '3px',
                          cursor: 'pointer',
                        }}
                      >
                        cloudflare.com
                      </button>
                      <button
                        onClick={() => {
                          setTargetHostname('expired.badssl.com');
                          setTargetPort(443);
                          handleDirectAnalyze({ mode: 'host', hostname: 'expired.badssl.com', port: 443 });
                        }}
                        style={{
                          fontSize: '0.725rem',
                          padding: '0.15rem 0.5rem',
                          background: 'var(--bg-surface)',
                          border: '1px solid var(--color-malicious-border)',
                          color: 'var(--color-malicious-text)',
                          borderRadius: '3px',
                          cursor: 'pointer',
                        }}
                      >
                        expired.badssl.com (Test Distrusted)
                      </button>
                    </div>
                  </div>
                ),
              },
              {
                key: 'pem',
                label: (
                  <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <FileCode size={13} />
                    <span>Raw PEM Certificate / Bundle</span>
                  </span>
                ),
                children: (
                  <div>
                    <div style={{ marginBottom: '0.75rem' }}>
                      <label style={{ display: 'block', fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                        Paste X.509 Certificate (PEM or concatenated chain)
                      </label>
                      <Input.TextArea
                        rows={4}
                        placeholder="-----BEGIN CERTIFICATE-----&#10;MIIC...&#10;-----END CERTIFICATE-----"
                        value={pemContent}
                        onChange={(e) => setPemContent(e.target.value)}
                        disabled={isAnalyzing}
                        style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}
                      />
                    </div>

                    <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'end', flexWrap: 'wrap' }}>
                      <div style={{ flex: 1, minWidth: '220px' }}>
                        <label style={{ display: 'block', fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                          Target Hostname for RFC 9525 SAN Verification (Optional)
                        </label>
                        <Input
                          placeholder="e.g. test.internal or myapp.domain.com"
                          value={pemHostname}
                          onChange={(e) => setPemHostname(e.target.value)}
                          disabled={isAnalyzing}
                        />
                      </div>
                      <Button
                        type="primary"
                        icon={isAnalyzing ? <RotateCw size={13} className="animate-spin" /> : <ShieldCheck size={13} />}
                        loading={isAnalyzing}
                        onClick={() => handleDirectAnalyze()}
                        style={{ backgroundColor: 'var(--color-accent)', borderColor: 'var(--color-accent)', color: '#101112', fontWeight: 600 }}
                      >
                        Evaluate PEM Certificate
                      </Button>
                      <Button
                        size="small"
                        onClick={() => {
                          setPemContent(SAMPLE_TEST_PEM);
                          setPemHostname('TestIG');
                          handleDirectAnalyze({ mode: 'pem', pem: SAMPLE_TEST_PEM });
                        }}
                        style={{ color: 'var(--text-secondary)' }}
                      >
                        Load Test Self-Signed PEM
                      </Button>
                    </div>
                  </div>
                ),
              },
            ]}
          />

          {analysisError && (
            <Alert
              message="Certificate Analysis Error"
              description={analysisError.message || 'The specified target or certificate could not be evaluated.'}
              type="error"
              showIcon
              style={{
                marginTop: '1rem',
                backgroundColor: 'var(--color-malicious-bg)',
                borderColor: 'var(--color-malicious-border)',
                color: 'var(--color-malicious-text)',
              }}
            />
          )}
        </div>
      )}

      {/* Main Analysis Display */}
      {certData ? (
        <>
          {/* Card 1: Header & Core Verdict Card */}
          <div className="tl-card" style={{ marginBottom: '1.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1.25rem' }}>
              {/* Left Side: Score & Target */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem', flexWrap: 'wrap' }}>
                {/* Score Gauge Circle */}
                <div
                  style={{
                    width: '84px',
                    height: '84px',
                    borderRadius: '50%',
                    border: `3px solid ${verdictConfig.color}`,
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    backgroundColor: verdictConfig.bg,
                    boxShadow: `0 0 16px ${verdictConfig.bg}`,
                    flexShrink: 0,
                  }}
                >
                  <span style={{ fontSize: '1.6rem', fontWeight: 800, color: verdictConfig.color, lineHeight: 1 }}>
                    {trustScore}
                  </span>
                  <span style={{ fontSize: '0.625rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', marginTop: '2px' }}>
                    TRUST SCORE
                  </span>
                </div>

                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                    <Key size={14} color="var(--color-accent)" />
                    <span style={{ fontSize: '0.725rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      X.509 CERTIFICATE TELEMETRY
                    </span>
                  </div>
                  <h1 style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                    {host}
                  </h1>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.35rem', flexWrap: 'wrap' }}>
                    <span
                      style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '0.3rem',
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        padding: '0.2rem 0.5rem',
                        borderRadius: '3px',
                        backgroundColor: 'var(--bg-surface-secondary)',
                        border: '1px solid var(--border-color)',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      Confidence: {confidencePercent}% ({confidence >= 0.8 ? 'High Evidence' : confidence >= 0.5 ? 'Moderate' : 'Low'})
                    </span>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      Evaluated: {formatDate(assessment?.evaluated_at || certData?.fetched_at || new Date().toISOString())}
                    </span>
                  </div>
                </div>
              </div>

              {/* Right Side: Verdict Pill */}
              <div style={{ textAlign: 'right' }}>
                <div
                  style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    padding: '0.5rem 1rem',
                    borderRadius: 'var(--radius-sm)',
                    backgroundColor: verdictConfig.bg,
                    border: `1px solid ${verdictConfig.border}`,
                    color: verdictConfig.color,
                    fontWeight: 700,
                    fontSize: '0.95rem',
                    letterSpacing: '0.04em',
                  }}
                >
                  <VerdictIcon size={18} />
                  <span>{verdictConfig.label}</span>
                </div>
                <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginTop: '0.35rem', maxWidth: '280px' }}>
                  {verdictConfig.description}
                </div>
              </div>
            </div>

            {/* Mandatory Security Principle Notice */}
            <div
              style={{
                marginTop: '1.25rem',
                padding: '0.85rem 1rem',
                borderRadius: 'var(--radius-sm)',
                backgroundColor: 'var(--bg-app)',
                border: '1px solid var(--border-color)',
                fontSize: '0.8rem',
                color: 'var(--text-secondary)',
                lineHeight: 1.5,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--color-accent)', fontWeight: 600, marginBottom: '0.25rem' }}>
                <AlertTriangle size={14} />
                SECURITY PRINCIPLE: TLS ≠ LEGITIMACY
              </div>
              A valid TLS certificate guarantees only cryptographic transport encryption in transit. <strong>It is never proof that a website is genuine, legitimate, or benign.</strong> Threat actors and phishing campaigns routinely deploy genuine certificates issued by automated authorities.
            </div>
          </div>

          {/* Card 2: 3-Column Diagnostic Summary Overview */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
            {/* Chain Validity */}
            <div className="tl-card" style={{ padding: '1rem 1.25rem' }}>
              <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                ROOT TRUST CHAIN (RFC 5280)
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.9rem', fontWeight: 600, color: hasTrustedAnchor ? 'var(--color-safe-text)' : 'var(--color-malicious-text)' }}>
                {hasTrustedAnchor ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
                <span>{hasTrustedAnchor ? 'Trusted Root Anchor' : 'Untrusted / Incomplete Chain'}</span>
              </div>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.35rem' }}>
                {hasTrustedAnchor
                  ? 'Anchored in verified Mozilla CCADB root trust store.'
                  : 'Self-signed certificate, missing intermediate CA, or unknown root authority.'}
              </p>
            </div>

            {/* Hostname Match */}
            <div className="tl-card" style={{ padding: '1rem 1.25rem' }}>
              <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                IDENTITY MATCH (RFC 9525)
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.9rem', fontWeight: 600, color: isHostnameMatch ? 'var(--color-safe-text)' : 'var(--color-malicious-text)' }}>
                {isHostnameMatch ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
                <span>{isHostnameMatch ? 'Subject Identity Authenticated' : 'Hostname Mismatch'}</span>
              </div>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.35rem' }}>
                {isHostnameMatch
                  ? 'Queried domain matches SAN / Common Name entry.'
                  : 'Certificate was issued for an unrelated domain; browsers will reject connection.'}
              </p>
            </div>

            {/* Expiration Health */}
            <div className="tl-card" style={{ padding: '1rem 1.25rem' }}>
              <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.35rem' }}>
                EXPIRATION WINDOW
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.9rem', fontWeight: 600, color: isExpired ? 'var(--color-malicious-text)' : isExpiringSoon ? 'var(--color-suspicious-text)' : 'var(--color-safe-text)' }}>
                <Calendar size={16} />
                <span>
                  {daysUntilExp !== null
                    ? isExpired
                      ? `Expired (${Math.abs(daysUntilExp)} days ago)`
                      : `${daysUntilExp} days remaining`
                    : 'No Expiration Data'}
                </span>
              </div>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.35rem' }}>
                {isExpired
                  ? 'Expired certificates fail browser handshake.'
                  : isExpiringSoon
                  ? 'Expiring in under 14 days; requires immediate renewal.'
                  : 'Standard operational validity window.'}
              </p>
            </div>
          </div>

          {/* Card 3: CA/Browser Forum Baseline Requirements v2.3.1 Compliance */}
          {policyEval && (
            <div className="tl-card" style={{ marginBottom: '1.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <ShieldCheck size={16} color="var(--color-accent)" />
                  <h3 className="tl-card-title" style={{ margin: 0 }}>
                    Policy Compliance (CA/Browser Forum Baseline Requirements v2.3.1)
                  </h3>
                </div>

                <div>
                  {policyEval.applicability === 'NOT_APPLICABLE' ? (
                    <span
                      style={{
                        padding: '0.25rem 0.6rem',
                        borderRadius: '3px',
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        backgroundColor: 'var(--color-inconclusive-bg)',
                        color: 'var(--color-inconclusive-text)',
                        border: '1px solid var(--color-inconclusive-border)',
                      }}
                    >
                      CA Anchor (Exempt from Subscriber Limits)
                    </span>
                  ) : policyEval.validity_compliant === true ? (
                    <span
                      style={{
                        padding: '0.25rem 0.6rem',
                        borderRadius: '3px',
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        backgroundColor: 'var(--color-safe-bg)',
                        color: 'var(--color-safe-text)',
                        border: '1px solid var(--color-safe-border)',
                      }}
                    >
                      CA/B Forum v2.3.1 Compliant ({policyEval.max_validity_days_allowed}d limit)
                    </span>
                  ) : (
                    <span
                      style={{
                        padding: '0.25rem 0.6rem',
                        borderRadius: '3px',
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        backgroundColor: 'var(--color-suspicious-bg)',
                        color: 'var(--color-suspicious-text)',
                        border: '1px solid var(--color-suspicious-border)',
                      }}
                    >
                      Validity Exceeds CA/B Limit ({Math.round(policyEval.actual_validity_days)}d vs {policyEval.max_validity_days_allowed}d allowed)
                    </span>
                  )}
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', fontSize: '0.8rem' }}>
                <div>
                  <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.725rem' }}>POLICY TIER</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {policyEval.applicable_rule_id || policyEval.policy_name}
                  </span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.725rem' }}>CERTIFICATE PROFILE</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                    {policyEval.certificate_profile}
                  </span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.725rem' }}>MAX ALLOWED VALIDITY</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                    {policyEval.max_validity_days_allowed ? `${policyEval.max_validity_days_allowed} days` : 'Exempt / Uncapped'}
                  </span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.725rem' }}>ACTUAL CERTIFICATE LIFETIME</span>
                  <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                    {Math.round(policyEval.actual_validity_days)} days
                  </span>
                </div>
              </div>

              {policyEval.evaluation_notes && (
                <div style={{ marginTop: '0.75rem', fontSize: '0.775rem', color: 'var(--text-secondary)', borderTop: '1px solid var(--border-color-subtle)', paddingTop: '0.5rem' }}>
                  {policyEval.evaluation_notes}
                </div>
              )}
            </div>
          )}

          {/* Card 4: Certification Path & CT Audit */}
          <div className="tl-card" style={{ marginBottom: '1.5rem' }}>
            <h3 className="tl-card-title" style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Layers size={16} color="var(--color-accent)" />
              Certification Path & Certificate Transparency Audit
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem', fontSize: '0.8rem' }}>
              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.725rem' }}>CHAIN COMPLETENESS</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginTop: '0.2rem', fontWeight: 600, color: isChainValid ? 'var(--color-safe-text)' : 'var(--color-malicious-text)' }}>
                  {isChainValid ? <Check size={14} /> : <XCircle size={14} />}
                  <span>{isChainValid ? 'Complete Trust Chain' : 'Incomplete / Broken Chain'}</span>
                </div>
              </div>

              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.725rem' }}>ROOT ANCHOR (CCADB)</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginTop: '0.2rem', fontWeight: 600, color: hasTrustedAnchor ? 'var(--color-safe-text)' : 'var(--color-malicious-text)' }}>
                  {hasTrustedAnchor ? <Check size={14} /> : <XCircle size={14} />}
                  <span>{hasTrustedAnchor ? 'Recognized CCADB Root' : 'Unrecognized Root'}</span>
                </div>
              </div>

              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.725rem' }}>CERTIFICATE TRANSPARENCY (RFC 6962)</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginTop: '0.2rem', fontWeight: 600, color: sctPresent ? 'var(--color-safe-text)' : 'var(--color-suspicious-text)' }}>
                  {sctPresent ? <Check size={14} /> : <AlertTriangle size={14} />}
                  <span>{sctPresent ? `${sctCount} Embedded SCT(s) Verified` : 'No Embedded SCTs'}</span>
                </div>
              </div>

              <div>
                <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.725rem' }}>REVOCATION STATUS</span>
                <div style={{ marginTop: '0.2rem' }}>
                  {/* Strict UX Rule: Never render UNKNOWN or NOT_CHECKED as green */}
                  <span
                    style={{
                      padding: '0.15rem 0.5rem',
                      borderRadius: '3px',
                      fontSize: '0.725rem',
                      fontFamily: 'var(--font-mono)',
                      backgroundColor: 'var(--color-inconclusive-bg)',
                      color: 'var(--color-inconclusive-text)',
                      border: '1px solid var(--color-inconclusive-border)',
                      textTransform: 'uppercase',
                    }}
                  >
                    {revocationStatus.replace('_', ' ')}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Card 5: Cryptographic Parameters & Metadata */}
          <div className="tl-card" style={{ marginBottom: '1.5rem' }}>
            <h3 className="tl-card-title" style={{ marginBottom: '1.25rem' }}>
              Cryptographic Parameters & Subject Identity
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {/* Subject */}
              <div style={{ borderBottom: '1px solid var(--border-color-subtle)', paddingBottom: '0.75rem' }}>
                <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.2rem' }}>SUBJECT (DISTINGUISHED NAME)</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                  {subject}
                </div>
              </div>

              {/* Issuer */}
              <div style={{ borderBottom: '1px solid var(--border-color-subtle)', paddingBottom: '0.75rem' }}>
                <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.2rem' }}>ISSUING CERTIFICATE AUTHORITY (ISSUER)</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                  {issuer}
                </div>
              </div>

              {/* Validity Period */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', borderBottom: '1px solid var(--border-color-subtle)', paddingBottom: '0.75rem' }}>
                <div>
                  <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.2rem' }}>VALID NOT BEFORE</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-primary)' }}>
                    {formatDate(validFrom)}
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.2rem' }}>VALID NOT AFTER</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-primary)' }}>
                    {formatDate(validTo)}
                  </div>
                </div>
              </div>

              {/* Algorithms */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', borderBottom: '1px solid var(--border-color-subtle)', paddingBottom: '0.75rem' }}>
                <div>
                  <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.2rem' }}>SIGNATURE ALGORITHM</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-primary)' }}>
                    {signatureAlgorithm}
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.2rem' }}>PUBLIC KEY SPECIFICATION</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-primary)' }}>
                    {keyAlgorithm}
                  </div>
                </div>
              </div>

              {/* Fingerprint */}
              <div style={{ borderBottom: '1px solid var(--border-color-subtle)', paddingBottom: '0.75rem' }}>
                <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.2rem' }}>SHA-256 FINGERPRINT</div>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    backgroundColor: 'var(--bg-app)',
                    padding: '0.4rem 0.6rem',
                    borderRadius: 'var(--radius-sm)',
                    border: '1px solid var(--border-color)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.75rem',
                    color: 'var(--text-secondary)',
                    wordBreak: 'break-all',
                    gap: '0.5rem',
                  }}
                >
                  <span>{fingerprint}</span>
                  {fingerprint && fingerprint !== '—' && (
                    <button
                      onClick={() => handleCopy(fingerprint)}
                      style={{ color: 'var(--text-muted)', display: 'inline-flex', alignItems: 'center', background: 'none', border: 'none', cursor: 'pointer' }}
                      title="Copy Fingerprint"
                    >
                      {copiedFingerprint ? <Check size={14} color="var(--color-safe-text)" /> : <Copy size={14} />}
                    </button>
                  )}
                </div>
              </div>

              {/* Subject Alternative Names (SANs) */}
              <div>
                <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                  SUBJECT ALTERNATIVE NAMES (SANs) ({sans?.length || 0})
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                  {sans && sans.length > 0 ? (
                    sans.map((san, idx) => {
                      const isWildcard = san.startsWith('*.');
                      return (
                        <span
                          key={idx}
                          style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: '0.75rem',
                            padding: '0.2rem 0.5rem',
                            borderRadius: '3px',
                            backgroundColor: 'var(--bg-app)',
                            border: `1px solid ${isWildcard ? 'var(--color-suspicious-border)' : 'var(--border-color)'}`,
                            color: isWildcard ? 'var(--color-suspicious-text)' : 'var(--text-primary)',
                          }}
                        >
                          {san} {isWildcard && <span style={{ fontSize: '0.65rem', opacity: 0.8 }}>(Wildcard)</span>}
                        </span>
                      );
                    })
                  ) : (
                    <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>None specified</span>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Card 6: Security Findings Ranked by Severity */}
          {findings && findings.length > 0 && (
            <div className="tl-card" style={{ marginBottom: '1.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                <h3 className="tl-card-title" style={{ margin: 0 }}>
                  Security Findings & Deductions ({findings.length})
                </h3>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Ordered by score deduction impact
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {findings.map((finding, idx) => {
                  const sevStyle = SEVERITY_COLORS[finding.severity?.toUpperCase()] || SEVERITY_COLORS.INFO;
                  const isExpanded = !!expandedFindings[idx];
                  const hasDetails = finding.evidence || finding.recommendation;

                  return (
                    <div
                      key={idx}
                      style={{
                        padding: '0.75rem 1rem',
                        borderRadius: 'var(--radius-sm)',
                        backgroundColor: 'var(--bg-surface-secondary)',
                        border: '1px solid var(--border-color)',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '0.75rem' }}>
                        <div style={{ flex: 1 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem', flexWrap: 'wrap' }}>
                            <span
                              style={{
                                fontSize: '0.675rem',
                                fontWeight: 700,
                                fontFamily: 'var(--font-mono)',
                                padding: '0.15rem 0.4rem',
                                borderRadius: '3px',
                                backgroundColor: sevStyle.bg,
                                color: sevStyle.color,
                              }}
                            >
                              {finding.severity?.toUpperCase()}
                            </span>
                            <span style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-primary)' }}>
                              {finding.title}
                            </span>
                            {finding.code && (
                              <span style={{ fontSize: '0.7rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                                [{finding.code}]
                              </span>
                            )}
                          </div>
                          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                            {finding.description}
                          </p>
                        </div>

                        <div style={{ textAlign: 'right', flexShrink: 0 }}>
                          {finding.score_deduction > 0 ? (
                            <span
                              style={{
                                display: 'inline-block',
                                fontSize: '0.75rem',
                                fontFamily: 'var(--font-mono)',
                                fontWeight: 700,
                                color: 'var(--color-malicious-text)',
                                backgroundColor: 'var(--color-malicious-bg)',
                                padding: '0.2rem 0.45rem',
                                borderRadius: '3px',
                              }}
                            >
                              -{finding.score_deduction} pts
                            </span>
                          ) : (
                            <span
                              style={{
                                display: 'inline-block',
                                fontSize: '0.75rem',
                                fontFamily: 'var(--font-mono)',
                                color: 'var(--text-muted)',
                              }}
                            >
                              0 pts
                            </span>
                          )}
                        </div>
                      </div>

                      {hasDetails && (
                        <div style={{ marginTop: '0.5rem' }}>
                          <button
                            onClick={() => toggleFindingDetails(idx)}
                            style={{
                              background: 'none',
                              border: 'none',
                              color: 'var(--color-accent)',
                              fontSize: '0.725rem',
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.25rem',
                              padding: 0,
                            }}
                          >
                            {isExpanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                            {isExpanded ? 'Hide Technical Evidence' : 'View Technical Evidence'}
                          </button>

                          {isExpanded && (
                            <div
                              style={{
                                marginTop: '0.5rem',
                                padding: '0.6rem 0.75rem',
                                backgroundColor: 'var(--bg-app)',
                                borderRadius: 'var(--radius-xs)',
                                border: '1px solid var(--border-color)',
                                fontSize: '0.75rem',
                              }}
                            >
                              {finding.recommendation && (
                                <div style={{ marginBottom: '0.5rem' }}>
                                  <strong style={{ color: 'var(--color-accent)', display: 'block', fontSize: '0.7rem' }}>
                                    REMEDIATION:
                                  </strong>
                                  <span style={{ color: 'var(--text-secondary)' }}>{finding.recommendation}</span>
                                </div>
                              )}
                              {finding.evidence && Object.keys(finding.evidence).length > 0 && (
                                <div>
                                  <strong style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.7rem', marginBottom: '0.25rem' }}>
                                    EVIDENCE RECORD:
                                  </strong>
                                  <pre
                                    style={{
                                      fontFamily: 'var(--font-mono)',
                                      fontSize: '0.7rem',
                                      color: 'var(--text-secondary)',
                                      overflowX: 'auto',
                                      margin: 0,
                                      whiteSpace: 'pre-wrap',
                                    }}
                                  >
                                    {JSON.stringify(finding.evidence, null, 2)}
                                  </pre>
                                </div>
                              )}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Card 7: Machine Learning Advisory Drawer / Card */}
          {mlAdvisory && (
            <div
              className="tl-card"
              style={{
                marginBottom: '1.5rem',
                border: '1px solid var(--border-color-strong)',
                backgroundColor: 'rgba(214, 164, 91, 0.03)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Sparkles size={16} color="var(--color-accent)" />
                  <h3 className="tl-card-title" style={{ margin: 0 }}>
                    Machine Learning Compliance & Anomaly Advisory
                  </h3>
                </div>

                {/* Mandatory Advisory Signal Only Banner */}
                <span
                  style={{
                    padding: '0.25rem 0.65rem',
                    borderRadius: 'var(--radius-sm)',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    backgroundColor: 'var(--color-accent-subtle)',
                    color: 'var(--color-accent)',
                    border: '1px solid var(--color-accent)',
                    letterSpacing: '0.02em',
                  }}
                >
                  Advisory Signal Only
                </span>
              </div>

              {/* Informational Disclaimer Box */}
              <div
                style={{
                  padding: '0.65rem 0.85rem',
                  borderRadius: 'var(--radius-xs)',
                  backgroundColor: 'var(--bg-app)',
                  border: '1px solid var(--border-color-subtle)',
                  fontSize: '0.75rem',
                  color: 'var(--text-muted)',
                  lineHeight: 1.45,
                  marginBottom: '1rem',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', color: 'var(--text-secondary)', fontWeight: 600, marginBottom: '0.2rem' }}>
                  <Info size={13} />
                  Auxiliary Statistical Intelligence Notice
                </div>
                This statistical probability is calculated by an auxiliary machine learning model trained on Web PKI distributions. It does not replace, override, or supersede cryptographic X.509 path validation or deterministic PKI trust anchors.
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem', fontSize: '0.8rem' }}>
                <div>
                  <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.725rem' }}>PREDICTED PROFILE</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginTop: '0.2rem' }}>
                    <span
                      style={{
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        color: mlAdvisory.predicted_class === 'POLICY_COMPLIANT' ? 'var(--color-safe-text)' : 'var(--color-suspicious-text)',
                      }}
                    >
                      {mlAdvisory.predicted_class}
                    </span>
                    <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>
                      ({Math.round(mlAdvisory.compliance_probability * 100)}% prob)
                    </span>
                  </div>
                </div>

                <div>
                  <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.725rem' }}>ANOMALY ASSESSMENT</span>
                  <div style={{ marginTop: '0.2rem' }}>
                    {mlAdvisory.is_anomaly ? (
                      <span
                        style={{
                          padding: '0.15rem 0.5rem',
                          borderRadius: '3px',
                          fontSize: '0.725rem',
                          fontWeight: 600,
                          backgroundColor: 'var(--color-suspicious-bg)',
                          color: 'var(--color-suspicious-text)',
                          border: '1px solid var(--color-suspicious-border)',
                        }}
                        title="Certificate features deviate from standard commercial Web PKI baselines"
                      >
                        Atypical Structural Profile (Score: {mlAdvisory.anomaly_score?.toFixed(4)})
                      </span>
                    ) : (
                      <span
                        style={{
                          padding: '0.15rem 0.5rem',
                          borderRadius: '3px',
                          fontSize: '0.725rem',
                          fontWeight: 600,
                          backgroundColor: 'var(--color-safe-bg)',
                          color: 'var(--color-safe-text)',
                        }}
                      >
                        Normal Profile (Score: {mlAdvisory.anomaly_score?.toFixed(4)})
                      </span>
                    )}
                  </div>
                </div>

                <div>
                  <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '0.725rem' }}>MODEL CONFIDENCE</span>
                  <div style={{ fontFamily: 'var(--font-mono)', marginTop: '0.2rem', color: 'var(--text-primary)' }}>
                    {Math.round(mlAdvisory.confidence * 100)}% (v{mlAdvisory.model_version || '1.0.0'})
                  </div>
                </div>
              </div>

              {mlAdvisory.advisory_notes && (
                <div style={{ marginTop: '0.75rem', fontSize: '0.775rem', color: 'var(--text-secondary)', borderTop: '1px solid var(--border-color-subtle)', paddingTop: '0.5rem' }}>
                  {mlAdvisory.advisory_notes}
                </div>
              )}
            </div>
          )}
        </>
      ) : (
        /* Empty State */
        <div
          style={{
            padding: '3rem 1.5rem',
            textAlign: 'center',
            backgroundColor: 'var(--bg-surface)',
            borderRadius: 'var(--radius-md)',
            border: '1px solid var(--border-color)',
          }}
        >
          <Key size={32} color="var(--color-accent)" style={{ margin: '0 auto 1rem' }} />
          <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            No Certificate Intelligence Loaded
          </h3>
          <p style={{ fontSize: '0.825rem', color: 'var(--text-muted)', maxWidth: '440px', margin: '0.5rem auto 1.5rem' }}>
            Use the Certificate Analyzer console above to connect to a live TLS endpoint or paste an X.509 certificate for analysis.
          </p>
          <Button
            type="primary"
            onClick={() => {
              setShowDirectConsole(true);
              setTargetHostname('api.trustlens.io');
              handleDirectAnalyze({ mode: 'host', hostname: 'api.trustlens.io', port: 443 });
            }}
            style={{ backgroundColor: 'var(--color-accent)', borderColor: 'var(--color-accent)', color: '#101112', fontWeight: 600 }}
          >
            Run Demo Analysis on api.trustlens.io
          </Button>
        </div>
      )}
    </div>
  );
}
