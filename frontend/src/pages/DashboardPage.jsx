/**
 * TrustLens DashboardPage Component
 * Security investigation console displaying real user metrics from /api/v1/dashboard/summary,
 * verdict distributions, target submission form, and recent scan logs.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  HelpCircle,
  Clock,
  ArrowRight,
  RotateCw,
  Search,
  Activity,
  Layers,
  Users,
} from 'lucide-react';
import { Table, Button, Tooltip, Tag } from 'antd';
import { UrlScannerForm } from '../components/scanner/UrlScannerForm';
import { VerdictBadge } from '../components/common/VerdictBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { RiskScoreGauge } from '../components/common/RiskScoreGauge';
import { EmptyState } from '../components/common/EmptyState';
import { ErrorState } from '../components/common/ErrorState';
import { dashboardService } from '../services/dashboard.service';
import { formatDate, formatRelativeTime } from '../lib/utils';
import { useAuth } from '../context/AuthContext';

export function DashboardPage() {
  const { user } = useAuth();
  const [data, setData] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  const fetchDashboardData = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const res = await dashboardService.getSummary();
      setData(res);
    } catch (err) {
      setError(err.error || err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDashboardData();
  }, [fetchDashboardData]);

  const summary = data?.summary || {
    total_scans: 0,
    scans_last_30_days: 0,
    verdict_counts: { SAFE: 0, SUSPICIOUS: 0, MALICIOUS: 0, INCONCLUSIVE: 0 },
    active_scans: 0,
    pending_community_reports: 0,
  };
  const recentScans = data?.recent_scans || [];

  const columns = [
    {
      title: 'TARGET DOMAIN / URL',
      dataIndex: 'canonical_url',
      key: 'canonical_url',
      render: (text, record) => (
        <div>
          <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.85rem' }}>
            {record.host || text}
          </div>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '0.725rem',
              color: 'var(--text-muted)',
              maxWidth: '300px',
              whiteSpace: 'nowrap',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}
          >
            {text}
          </div>
        </div>
      ),
    },
    {
      title: 'SECURITY VERDICT',
      dataIndex: 'verdict',
      key: 'verdict',
      render: (verdict) => <VerdictBadge verdict={verdict} />,
    },
    {
      title: 'STATUS',
      dataIndex: 'status',
      key: 'status',
      render: (status) => <StatusBadge status={status} />,
    },
    {
      title: 'RISK SCORE',
      dataIndex: 'risk_score',
      key: 'risk_score',
      render: (score) => (
        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontWeight: 700,
            fontSize: '0.85rem',
            color:
              score === null || score === undefined
                ? 'var(--text-muted)'
                : score > 70
                  ? 'var(--color-malicious-text)'
                  : score > 35
                    ? 'var(--color-suspicious-text)'
                    : 'var(--color-safe-text)',
          }}
        >
          {score !== null && score !== undefined ? `${score}/100` : '—'}
        </span>
      ),
    },
    {
      title: 'DISCOVERED',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date) => (
        <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          {formatRelativeTime(date)}
        </span>
      ),
    },
    {
      title: 'ACTIONS',
      key: 'actions',
      align: 'right',
      render: (_, record) => (
        <Button
          type="text"
          size="small"
          onClick={() => navigate(`/scans/${record.id}`)}
          style={{
            fontSize: '0.75rem',
            color: 'var(--color-accent)',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.2rem',
          }}
        >
          <span>View Report</span>
          <ArrowRight size={12} />
        </Button>
      ),
    },
  ];

  return (
    <div style={{ maxWidth: '1280px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Console Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
            Security Threat Overview
          </h1>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            Aggregated digital trust posture and scan telemetry scoped to account{' '}
            <strong style={{ color: 'var(--text-primary)' }}>{user?.email}</strong>.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Button
            icon={<RotateCw size={13} className={isLoading ? 'animate-spin' : ''} />}
            onClick={fetchDashboardData}
            loading={isLoading}
            style={{
              backgroundColor: 'var(--bg-surface)',
              borderColor: 'var(--border-color)',
              color: 'var(--text-primary)',
              fontSize: '0.8rem',
            }}
          >
            Refresh Metrics
          </Button>
        </div>
      </div>

      {error && (
        <ErrorState
          error={error}
          onRetry={fetchDashboardData}
          title="Failed to Load Dashboard Telemetry"
        />
      )}

      {/* Target Scanner Card */}
      <section>
        <UrlScannerForm
          onScanSubmitted={(res) => {
            const scanId = res.scan?.id || res.id;
            if (scanId) navigate(`/scans/${scanId}`);
          }}
        />
      </section>

      {/* Security Metrics Strip */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1rem',
        }}
      >
        {/* Total Scans Card */}
        <div className="tl-card" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
              Total Scans
            </span>
            <Layers size={16} color="var(--text-muted)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
            {summary.total_scans}
          </div>
          <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            {summary.scans_last_30_days} in the last 30 days
          </div>
        </div>

        {/* Safe Verdicts */}
        <div className="tl-card" style={{ padding: '1.25rem', borderLeft: '3px solid var(--color-safe)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--color-safe-text)', textTransform: 'uppercase' }}>
              Safe Targets
            </span>
            <ShieldCheck size={16} color="var(--color-safe-text)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--color-safe-text)' }}>
            {summary.verdict_counts?.SAFE || 0}
          </div>
          <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            Verified low risk
          </div>
        </div>

        {/* Suspicious Verdicts */}
        <div className="tl-card" style={{ padding: '1.25rem', borderLeft: '3px solid var(--color-suspicious)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--color-suspicious-text)', textTransform: 'uppercase' }}>
              Suspicious
            </span>
            <AlertTriangle size={16} color="var(--color-suspicious-text)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--color-suspicious-text)' }}>
            {summary.verdict_counts?.SUSPICIOUS || 0}
          </div>
          <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            Caution warranted
          </div>
        </div>

        {/* Malicious Verdicts */}
        <div className="tl-card" style={{ padding: '1.25rem', borderLeft: '3px solid var(--color-malicious)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--color-malicious-text)', textTransform: 'uppercase' }}>
              Malicious
            </span>
            <ShieldAlert size={16} color="var(--color-malicious-text)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--color-malicious-text)' }}>
            {summary.verdict_counts?.MALICIOUS || 0}
          </div>
          <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            Active threat indicators
          </div>
        </div>

        {/* Inconclusive / Active */}
        <div className="tl-card" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
              Active / Inconclusive
            </span>
            <HelpCircle size={16} color="var(--text-muted)" />
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
            {summary.active_scans} / {summary.verdict_counts?.INCONCLUSIVE || 0}
          </div>
          <div style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            {summary.pending_community_reports} pending community reports
          </div>
        </div>
      </div>

      {/* Recent Investigations Table */}
      <div className="tl-card" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Clock size={16} color="var(--color-accent)" />
            <h2 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
              Recent Security Scans
            </h2>
          </div>
          <Button
            type="text"
            size="small"
            onClick={() => navigate('/history')}
            style={{ fontSize: '0.75rem', color: 'var(--color-accent)' }}
          >
            View Complete History →
          </Button>
        </div>

        {recentScans.length === 0 && !isLoading ? (
          <EmptyState
            title="No Recent Investigations Found"
            description="Submit your first URL above to trigger asynchronous DNS, HTTP, TLS, and threat intelligence analysis."
            actionText="Run Website Scan"
            onAction={() => navigate('/scan')}
          />
        ) : (
          <Table
            columns={columns}
            dataSource={recentScans}
            rowKey="id"
            loading={isLoading}
            pagination={false}
            size="small"
            style={{ backgroundColor: 'transparent' }}
          />
        )}
      </div>
    </div>
  );
}
