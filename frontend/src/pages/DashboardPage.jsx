/**
 * DashboardPage Component
 * Main security investigation console displaying threat posture stats,
 * immediate URL scanner, and recent target scan history.
 */

import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  HelpCircle,
  Clock,
  ArrowRight,
  ExternalLink,
  RotateCw,
  Search,
  Filter,
} from 'lucide-react';
import { Table, Button, Tooltip, Tag } from 'antd';
import { UrlScannerForm } from '../components/scanner/UrlScannerForm';
import { VerdictBadge } from '../components/common/VerdictBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { RiskScoreGauge } from '../components/common/RiskScoreGauge';
import { scanService } from '../services/scan.service';
import { formatDate, formatRelativeTime } from '../lib/utils';
import { useAuth } from '../context/AuthContext';

export function DashboardPage() {
  const { user, isMockMode } = useAuth();
  const [scans, setScans] = useState([]);
  const [stats, setStats] = useState({ total: 0, safe: 0, suspicious: 0, malicious: 0, inconclusive: 0 });
  const [isLoading, setIsLoading] = useState(true);
  const navigate = useNavigate();

  const fetchDashboardData = async () => {
    setIsLoading(true);
    try {
      const res = await scanService.listScans({ page: 1, pageSize: 20 });
      const items = res.items || [];
      setScans(items);

      // Compute statistics directly from loaded data
      const computed = {
        total: res.total || items.length,
        safe: items.filter((s) => s.verdict === 'SAFE').length,
        suspicious: items.filter((s) => s.verdict === 'SUSPICIOUS').length,
        malicious: items.filter((s) => s.verdict === 'MALICIOUS').length,
        inconclusive: items.filter((s) => s.verdict === 'INCONCLUSIVE').length,
      };
      setStats(computed);
    } catch {
      setScans([]);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

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
      render: (score) => <RiskScoreGauge score={score} />,
    },
    {
      title: 'ANALYSIS TIME',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (date) => (
        <Tooltip title={formatDate(date)}>
          <span style={{ fontSize: '0.775rem', color: 'var(--text-secondary)' }}>
            {formatRelativeTime(date)}
          </span>
        </Tooltip>
      ),
    },
    {
      title: 'ACTION',
      key: 'action',
      align: 'right',
      render: (_, record) => (
        <Button
          type="text"
          size="small"
          onClick={() => navigate(`/scans/${record.id}`)}
          style={{ color: 'var(--color-accent)', fontSize: '0.775rem', fontWeight: 600 }}
        >
          View Report →
        </Button>
      ),
    },
  ];

  return (
    <div>
      {/* Top Welcome Section */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
            Welcome back, {user?.display_name || 'Security Analyst'}
          </h1>
          <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
            Threat Intelligence Console • Live perimeter monitoring
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Button
            icon={<RotateCw size={13} />}
            onClick={fetchDashboardData}
            loading={isLoading}
            size="small"
            style={{ color: 'var(--text-secondary)' }}
          >
            Refresh Data
          </Button>
        </div>
      </div>

      {/* Target URL Scanner Card */}
      <div style={{ marginBottom: '1.5rem' }}>
        <UrlScannerForm />
      </div>

      {/* Demonstration Notice if Mock Mode */}
      {isMockMode && (
        <div
          style={{
            padding: '0.6rem 1rem',
            backgroundColor: 'var(--color-accent-subtle)',
            border: '1px solid rgba(214, 164, 91, 0.25)',
            borderRadius: 'var(--radius-md)',
            fontSize: '0.775rem',
            color: 'var(--color-accent)',
            marginBottom: '1.5rem',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <span>
            <strong>Demonstration Mode:</strong> The metrics below reflect simulated telemetry data for verification and hackathon evaluation.
          </span>
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}>MOCK_API: ACTIVE</span>
        </div>
      )}

      {/* Metric Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1.75rem' }}>
        {/* Total */}
        <div className="tl-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-secondary)' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, letterSpacing: '0.05em' }}>TOTAL SCANS</span>
            <Search size={16} />
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '1.8rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.4rem' }}>
            {stats.total}
          </div>
          <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>Assessed targets</span>
        </div>

        {/* Safe */}
        <div className="tl-card" style={{ borderLeft: '3px solid var(--color-safe)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--color-safe-text)' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, letterSpacing: '0.05em' }}>SAFE</span>
            <ShieldCheck size={16} />
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '1.8rem', fontWeight: 700, color: 'var(--color-safe-text)', marginTop: '0.4rem' }}>
            {stats.safe}
          </div>
          <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>Bounded clean results</span>
        </div>

        {/* Suspicious */}
        <div className="tl-card" style={{ borderLeft: '3px solid var(--color-suspicious)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--color-suspicious-text)' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, letterSpacing: '0.05em' }}>SUSPICIOUS</span>
            <AlertTriangle size={16} />
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '1.8rem', fontWeight: 700, color: 'var(--color-suspicious-text)', marginTop: '0.4rem' }}>
            {stats.suspicious}
          </div>
          <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>Caution indicators</span>
        </div>

        {/* Malicious */}
        <div className="tl-card" style={{ borderLeft: '3px solid var(--color-malicious)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--color-malicious-text)' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, letterSpacing: '0.05em' }}>MALICIOUS</span>
            <ShieldAlert size={16} />
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '1.8rem', fontWeight: 700, color: 'var(--color-malicious-text)', marginTop: '0.4rem' }}>
            {stats.malicious}
          </div>
          <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>Confirmed threats</span>
        </div>

        {/* Inconclusive */}
        <div className="tl-card" style={{ borderLeft: '3px solid var(--color-inconclusive)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--color-inconclusive-text)' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, letterSpacing: '0.05em' }}>INCONCLUSIVE</span>
            <HelpCircle size={16} />
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '1.8rem', fontWeight: 700, color: 'var(--color-inconclusive-text)', marginTop: '0.4rem' }}>
            {stats.inconclusive}
          </div>
          <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)' }}>Incomplete evidence</span>
        </div>
      </div>

      {/* Recent Investigations Table */}
      <div className="tl-card">
        <div className="tl-card-header">
          <div>
            <h3 className="tl-card-title">Recent Target Assessments</h3>
            <p className="tl-card-subtitle">Detailed security records analyzed by TrustLens</p>
          </div>
          <Button
            type="link"
            size="small"
            onClick={() => navigate('/history')}
            style={{ color: 'var(--color-accent)' }}
          >
            Full History →
          </Button>
        </div>

        <Table
          dataSource={scans}
          columns={columns}
          rowKey="id"
          loading={isLoading}
          pagination={false}
          size="middle"
          scroll={{ x: 800 }}
        />
      </div>
    </div>
  );
}
