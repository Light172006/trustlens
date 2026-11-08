/**
 * TrustLens WebSecurityPage Component
 * Passive website technical security posture analysis interface.
 * Evaluates 22 deterministic security rules, calibrated HistGradientBoosting ML classification,
 * rule-vs-model consensus, and prioritized remediation roadmap.
 */

import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Globe,
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  RotateCw,
  Search,
  CheckCircle2,
  XCircle,
  Cpu,
  Layers,
  ArrowRight,
  ExternalLink,
  Info,
  Copy,
  Check,
} from 'lucide-react';
import { Input, Button, Tag, Alert, Checkbox, Tabs, Progress, Tooltip, message } from 'antd';
import { webSecurityService } from '../services/webSecurity.service';
import { validateUrl, formatDate, formatRelativeTime } from '../lib/utils';
import { ErrorState } from '../components/common/ErrorState';

export function WebSecurityPage() {
  const { id: scanId } = useParams();
  const navigate = useNavigate();

  const [url, setUrl] = useState('');
  const [forceFresh, setForceFresh] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [assessment, setAssessment] = useState(null);
  const [error, setError] = useState(null);
  const [copiedKey, setCopiedKey] = useState(null);
  const [activeSeverityTab, setActiveSeverityTab] = useState('ALL');

  useEffect(() => {
    if (scanId) {
      const loadScan = async () => {
        setIsLoading(true);
        setError(null);
        try {
          const res = await webSecurityService.getWebSecurityScan(scanId);
          setAssessment(res);
          setUrl(res.target_url || '');
        } catch (err) {
          setError(err.error || err);
        } finally {
          setIsLoading(false);
        }
      };
      loadScan();
    }
  }, [scanId]);

  const handleAnalyze = async (e) => {
    if (e) e.preventDefault();
    const validation = validateUrl(url);
    if (!validation.valid) {
      message.error(validation.error);
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const res = await webSecurityService.analyzeWebSecurity({
        url: url.trim(),
        force_fresh: forceFresh,
      });
      setAssessment(res);
      if (res.id && res.id !== scanId) {
        navigate(`/web-security/${res.id}`, { replace: true });
      }
    } catch (err) {
      setError(err.error || err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const getPostureColor = (posture) => {
    switch ((posture || '').toUpperCase()) {
      case 'GOOD':
        return 'var(--color-safe-text)';
      case 'MODERATE':
        return 'var(--color-suspicious-text)';
      case 'POOR':
        return 'var(--color-malicious-text)';
      default:
        return 'var(--text-secondary)';
    }
  };

  const findings = assessment?.findings || [];
  const filteredFindings = findings.filter((f) => {
    if (activeSeverityTab === 'ALL') return true;
    return (f.severity || '').toUpperCase() === activeSeverityTab;
  });

  return (
    <div style={{ maxWidth: '1280px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
          Web Security Posture Analysis
        </h1>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
          Real-time passive telemetry inspection evaluating 22 deterministic security controls,
          calibrated gradient-boosted ML classification with abstention, and evidence-backed remediation.
        </p>
      </div>

      {/* Target Input Card */}
      <div className="tl-card" style={{ padding: '1.5rem' }}>
        <form onSubmit={handleAnalyze}>
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <div style={{ flex: 1, minWidth: '280px' }}>
              <Input
                size="large"
                placeholder="Enter URL to analyze (e.g. https://example.com)"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                prefix={<Globe size={16} style={{ color: 'var(--text-muted)' }} />}
                disabled={isLoading}
                allowClear
                style={{ fontFamily: 'var(--font-mono)' }}
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
                color: '#101112',
                fontWeight: 600,
                minWidth: '150px',
              }}
            >
              Analyze Posture
            </Button>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginTop: '0.75rem' }}>
            <Checkbox
              checked={forceFresh}
              onChange={(e) => setForceFresh(e.target.checked)}
              disabled={isLoading}
            >
              <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                Force fresh network extraction (bypass cache)
              </span>
            </Checkbox>
          </div>
        </form>
      </div>

      {error && <ErrorState error={error} onRetry={handleAnalyze} title="Analysis Error" />}

      {/* Assessment Results */}
      {assessment && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Top Posture Banner */}
          <div
            className="tl-card"
            style={{
              padding: '1.75rem',
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
              gap: '1.5rem',
              alignItems: 'center',
            }}
          >
            {/* Score & Posture */}
            <div>
              <span style={{ fontSize: '0.75rem', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                Aggregate Security Posture
              </span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginTop: '0.5rem' }}>
                <span
                  style={{
                    fontSize: '2.5rem',
                    fontWeight: 800,
                    fontFamily: 'var(--font-mono)',
                    color: getPostureColor(assessment.posture),
                  }}
                >
                  {assessment.posture}
                </span>
                <Tag
                  color={assessment.posture === 'GOOD' ? 'green' : assessment.posture === 'MODERATE' ? 'gold' : 'red'}
                  style={{ fontSize: '0.85rem', padding: '4px 10px', fontWeight: 700, fontFamily: 'var(--font-mono)' }}
                >
                  SCORE: {assessment.security_score?.toFixed(1)}/100
                </Tag>
              </div>
              <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
                {assessment.summary_text || `Evaluated ${assessment.target_url} against authoritative security rubrics.`}
              </p>
            </div>

            {/* Deterministic vs ML Consensus Card */}
            <div
              style={{
                padding: '1.25rem',
                backgroundColor: 'var(--bg-app)',
                borderRadius: 'var(--radius-md)',
                border: '1px solid var(--border-color)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <Cpu size={14} color="var(--color-accent)" /> Model & Consensus
                </span>
                <Tag color={assessment.consensus?.status === 'CONSENSUS' ? 'blue' : 'warning'}>
                  {assessment.consensus?.status || 'CONSENSUS'}
                </Tag>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.75rem' }}>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Rule Engine:</span>{' '}
                  <strong style={{ color: getPostureColor(assessment.deterministic_posture) }}>
                    {assessment.deterministic_posture}
                  </strong>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>ML Classifier:</span>{' '}
                  <strong style={{ color: getPostureColor(assessment.ml_prediction?.predicted_posture) }}>
                    {assessment.ml_prediction?.predicted_posture || 'N/A'}
                  </strong>
                </div>
              </div>

              {assessment.ml_prediction?.available && (
                <div style={{ marginTop: '0.75rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border-color-subtle)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.725rem', color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>
                    <span>Prediction Confidence:</span>
                    <span style={{ fontFamily: 'var(--font-mono)' }}>
                      {(assessment.ml_prediction.confidence * 100).toFixed(1)}%
                    </span>
                  </div>
                  <Progress
                    percent={Math.round(assessment.ml_prediction.confidence * 100)}
                    size="small"
                    showInfo={false}
                    strokeColor="var(--color-accent)"
                  />
                  {assessment.ml_prediction.abstained && (
                    <div style={{ fontSize: '0.7rem', color: 'var(--color-suspicious-text)', marginTop: '0.4rem' }}>
                      Abstention active: {assessment.ml_prediction.abstention_reason}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Findings Summary Strip */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
              gap: '1rem',
            }}
          >
            <div className="tl-card" style={{ padding: '1rem', textAlign: 'center' }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Total Checks</span>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                {assessment.findings_summary?.total_findings || findings.length}
              </div>
            </div>
            <div className="tl-card" style={{ padding: '1rem', textAlign: 'center', borderBottom: '2px solid var(--severity-critical)' }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--severity-critical)', textTransform: 'uppercase' }}>Critical</span>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--severity-critical)' }}>
                {assessment.findings_summary?.critical_count || 0}
              </div>
            </div>
            <div className="tl-card" style={{ padding: '1rem', textAlign: 'center', borderBottom: '2px solid var(--severity-high)' }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--severity-high)', textTransform: 'uppercase' }}>High</span>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--severity-high)' }}>
                {assessment.findings_summary?.high_count || 0}
              </div>
            </div>
            <div className="tl-card" style={{ padding: '1rem', textAlign: 'center', borderBottom: '2px solid var(--severity-medium)' }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--severity-medium)', textTransform: 'uppercase' }}>Medium</span>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--severity-medium)' }}>
                {assessment.findings_summary?.medium_count || 0}
              </div>
            </div>
            <div className="tl-card" style={{ padding: '1rem', textAlign: 'center', borderBottom: '2px solid var(--severity-low)' }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--severity-low)', textTransform: 'uppercase' }}>Low</span>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--severity-low)' }}>
                {assessment.findings_summary?.low_count || 0}
              </div>
            </div>
            <div className="tl-card" style={{ padding: '1rem', textAlign: 'center', borderBottom: '2px solid var(--color-safe)' }}>
              <span style={{ fontSize: '0.7rem', color: 'var(--color-safe-text)', textTransform: 'uppercase' }}>Compliant</span>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--color-safe-text)' }}>
                {assessment.findings_summary?.pass_count || 0}
              </div>
            </div>
          </div>

          {/* Detailed Tabs: Findings, Remediations, Telemetry */}
          <div className="tl-card" style={{ padding: '1.5rem' }}>
            <Tabs
              defaultActiveKey="findings"
              items={[
                {
                  key: 'findings',
                  label: `Rule Findings (${findings.length})`,
                  children: (
                    <div>
                      {/* Severity Filter Pills */}
                      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.25rem', flexWrap: 'wrap' }}>
                        {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'PASS'].map((sev) => (
                          <button
                            key={sev}
                            type="button"
                            onClick={() => setActiveSeverityTab(sev)}
                            style={{
                              padding: '0.3rem 0.75rem',
                              fontSize: '0.75rem',
                              borderRadius: 'var(--radius-full)',
                              backgroundColor:
                                activeSeverityTab === sev
                                  ? 'var(--color-accent)'
                                  : 'var(--bg-app)',
                              color:
                                activeSeverityTab === sev
                                  ? '#101112'
                                  : 'var(--text-secondary)',
                              fontWeight: activeSeverityTab === sev ? 700 : 500,
                              border: '1px solid var(--border-color)',
                            }}
                          >
                            {sev}
                          </button>
                        ))}
                      </div>

                      {/* Findings List */}
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                        {filteredFindings.map((finding) => (
                          <div
                            key={finding.finding_id}
                            style={{
                              padding: '1rem',
                              backgroundColor: 'var(--bg-app)',
                              borderRadius: 'var(--radius-md)',
                              border: '1px solid var(--border-color-subtle)',
                            }}
                          >
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                <Tag
                                  color={
                                    finding.severity === 'CRITICAL'
                                      ? 'red'
                                      : finding.severity === 'HIGH'
                                        ? 'orange'
                                        : finding.severity === 'MEDIUM'
                                          ? 'gold'
                                          : finding.severity === 'PASS'
                                            ? 'green'
                                            : 'default'
                                  }
                                  style={{ fontWeight: 700, fontFamily: 'var(--font-mono)' }}
                                >
                                  {finding.severity}
                                </Tag>
                                <span style={{ fontWeight: 600, fontSize: '0.875rem', color: 'var(--text-primary)' }}>
                                  {finding.name}
                                </span>
                              </div>
                              <span style={{ fontSize: '0.7rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                                {finding.finding_id}
                              </span>
                            </div>

                            {finding.evidence && (
                              <div
                                style={{
                                  fontSize: '0.775rem',
                                  fontFamily: 'var(--font-mono)',
                                  backgroundColor: 'var(--bg-surface)',
                                  padding: '0.5rem 0.75rem',
                                  borderRadius: 'var(--radius-sm)',
                                  color: 'var(--text-secondary)',
                                  marginBottom: '0.5rem',
                                  wordBreak: 'break-all',
                                }}
                              >
                                {finding.evidence}
                              </div>
                            )}

                            {finding.recommendation && (
                              <div style={{ fontSize: '0.8rem', color: 'var(--color-accent)', display: 'flex', gap: '0.3rem' }}>
                                <strong>Remediation:</strong>
                                <span>{finding.recommendation}</span>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  ),
                },
                {
                  key: 'remediations',
                  label: `Remediation Guidance (${assessment.remediations?.length || 0})`,
                  children: (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                      {(assessment.remediations || []).map((rem, idx) => (
                        <div
                          key={idx}
                          style={{
                            padding: '1rem',
                            backgroundColor: 'var(--bg-app)',
                            borderRadius: 'var(--radius-md)',
                            border: '1px solid var(--border-color)',
                            display: 'flex',
                            gap: '0.75rem',
                            alignItems: 'flex-start',
                          }}
                        >
                          <Tag
                            color={rem.severity === 'CRITICAL' ? 'red' : rem.severity === 'HIGH' ? 'orange' : 'gold'}
                            style={{ fontWeight: 700 }}
                          >
                            {rem.severity}
                          </Tag>
                          <div style={{ flex: 1 }}>
                            <div style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--text-primary)', marginBottom: '0.25rem' }}>
                              {rem.category}: {rem.finding_id}
                            </div>
                            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                              {rem.recommendation}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ),
                },
                {
                  key: 'telemetry',
                  label: 'Extracted Telemetry',
                  children: (
                    <pre
                      style={{
                        padding: '1rem',
                        backgroundColor: 'var(--bg-app)',
                        borderRadius: 'var(--radius-md)',
                        fontSize: '0.75rem',
                        color: 'var(--text-secondary)',
                        overflowX: 'auto',
                      }}
                    >
                      {JSON.stringify(assessment.telemetry, null, 2)}
                    </pre>
                  ),
                },
              ]}
            />
          </div>
        </div>
      )}
    </div>
  );
}

