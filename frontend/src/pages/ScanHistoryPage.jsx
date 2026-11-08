/**
 * TrustLens ScanHistoryPage Component
 * Multi-module historical investigation directory:
 * - Asynchronous Website Scans (/api/v1/scans)
 * - Web Security Posture Scans (/api/v1/web-security)
 * - Certificate Assessments (/api/v1/certificates)
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  History,
  Search,
  Filter,
  Trash2,
  ExternalLink,
  RotateCw,
  AlertOctagon,
  Globe,
  ShieldCheck,
  ArrowRight,
} from 'lucide-react';
import { Table, Input, Select, Button, Modal, message, Tooltip, Tabs, Tag } from 'antd';
import { scanService } from '../services/scan.service';
import { webSecurityService } from '../services/webSecurity.service';
import { certificateService } from '../services/certificate.service';
import { VerdictBadge } from '../components/common/VerdictBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { RiskScoreGauge } from '../components/common/RiskScoreGauge';
import { formatDate, formatRelativeTime } from '../lib/utils';
import { EmptyState } from '../components/common/EmptyState';

const { Option } = Select;

export function ScanHistoryPage() {
  const [activeTab, setActiveTab] = useState('scans');
  const navigate = useNavigate();

  // Asynchronous Scans state
  const [scans, setScans] = useState([]);
  const [scansTotal, setScansTotal] = useState(0);
  const [scansPage, setScansPage] = useState(1);
  const [scansPageSize, setScansPageSize] = useState(10);
  const [statusFilter, setStatusFilter] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [isScansLoading, setIsScansLoading] = useState(true);

  // Web Security Scans state
  const [webScans, setWebScans] = useState([]);
  const [webScansTotal, setWebScansTotal] = useState(0);
  const [webScansPage, setWebScansPage] = useState(1);
  const [webScansLimit, setWebScansLimit] = useState(10);
  const [webPostureFilter, setWebPostureFilter] = useState('');
  const [isWebLoading, setIsWebLoading] = useState(false);

  // Certificate Assessments state
  const [certScans, setCertScans] = useState([]);
  const [certTotal, setCertTotal] = useState(0);
  const [certLimit, setCertLimit] = useState(10);
  const [certOffset, setCertOffset] = useState(0);
  const [isCertLoading, setIsCertLoading] = useState(false);

  // 1. Fetch Asynchronous Scans
  const fetchScans = useCallback(async () => {
    setIsScansLoading(true);
    try {
      const res = await scanService.listScans({
        page: scansPage,
        pageSize: scansPageSize,
        status: statusFilter,
        verdict: verdictFilter,
      });
      setScans(res.items || []);
      setScansTotal(res.total || 0);
    } catch {
      setScans([]);
      setScansTotal(0);
    } finally {
      setIsScansLoading(false);
    }
  }, [scansPage, scansPageSize, statusFilter, verdictFilter]);

  // 2. Fetch Web Security Scans
  const fetchWebScans = useCallback(async () => {
    setIsWebLoading(true);
    try {
      const res = await webSecurityService.listWebSecurityScans({
        page: webScansPage,
        limit: webScansLimit,
        posture: webPostureFilter,
      });
      setWebScans(res.items || []);
      setWebScansTotal(res.total || 0);
    } catch {
      setWebScans([]);
      setWebScansTotal(0);
    } finally {
      setIsWebLoading(false);
    }
  }, [webScansPage, webScansLimit, webPostureFilter]);

  // 3. Fetch Certificate Assessments
  const fetchCertScans = useCallback(async () => {
    setIsCertLoading(true);
    try {
      const res = await certificateService.listCertificateAssessments({
        limit: certLimit,
        offset: certOffset,
      });
      setCertScans(res.items || []);
      setCertTotal(res.total || 0);
    } catch {
      setCertScans([]);
      setCertTotal(0);
    } finally {
      setIsCertLoading(false);
    }
  }, [certLimit, certOffset]);

  useEffect(() => {
    if (activeTab === 'scans') fetchScans();
    else if (activeTab === 'web-security') fetchWebScans();
    else if (activeTab === 'certificates') fetchCertScans();
  }, [activeTab, fetchScans, fetchWebScans, fetchCertScans]);

  const handleDeleteScan = (record) => {
    Modal.confirm({
      title: 'Delete Investigation Record?',
      icon: <AlertOctagon size={22} color="var(--color-malicious-text)" />,
      content: `Are you sure you want to permanently delete the scan record for '${record.canonical_url}'? This will cascade deletion to findings, redirects, and certificates.`,
      okText: 'Delete Record',
      okType: 'danger',
      cancelText: 'Cancel',
      async onOk() {
        try {
          await scanService.deleteScan(record.id);
          message.success('Scan record deleted.');
          fetchScans();
        } catch {
          message.error('Failed to delete scan record.');
        }
      },
    });
  };

  const filteredScans = scans.filter((item) => {
    if (!searchTerm.trim()) return true;
    const term = searchTerm.toLowerCase();
    return (
      (item.host && item.host.toLowerCase().includes(term)) ||
      (item.canonical_url && item.canonical_url.toLowerCase().includes(term))
    );
  });

  const scanColumns = [
    {
      title: 'DOMAIN / TARGET URL',
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
              maxWidth: '320px',
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
      width: 150,
      render: (verdict) => <VerdictBadge verdict={verdict} />,
    },
    {
      title: 'STATUS',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      render: (status) => <StatusBadge status={status} />,
    },
    {
      title: 'RISK SCORE',
      dataIndex: 'risk_score',
      key: 'risk_score',
      width: 110,
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
      title: 'SUBMITTED',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 140,
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
      width: 170,
      render: (_, record) => (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '0.4rem' }}>
          <Button
            type="text"
            size="small"
            onClick={() => navigate(`/scans/${record.id}`)}
            style={{ fontSize: '0.75rem', color: 'var(--color-accent)' }}
          >
            Report
          </Button>
          <Tooltip title="Delete scan record">
            <Button
              type="text"
              size="small"
              icon={<Trash2 size={13} />}
              onClick={() => handleDeleteScan(record)}
              style={{ color: 'var(--text-muted)' }}
            />
          </Tooltip>
        </div>
      ),
    },
  ];

  const webScanColumns = [
    {
      title: 'TARGET URL',
      dataIndex: 'target_url',
      key: 'target_url',
      render: (url, record) => (
        <div>
          <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.85rem' }}>
            {record.normalized_domain}
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.725rem', color: 'var(--text-muted)' }}>
            {url}
          </div>
        </div>
      ),
    },
    {
      title: 'POSTURE',
      dataIndex: 'posture',
      key: 'posture',
      width: 140,
      render: (posture) => (
        <Tag
          color={posture === 'GOOD' ? 'green' : posture === 'MODERATE' ? 'gold' : 'red'}
          style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}
        >
          {posture}
        </Tag>
      ),
    },
    {
      title: 'SCORE',
      dataIndex: 'security_score',
      key: 'security_score',
      width: 100,
      render: (score) => (
        <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
          {score !== null ? `${score}/100` : '—'}
        </span>
      ),
    },
    {
      title: 'FINDINGS',
      dataIndex: 'total_findings',
      key: 'total_findings',
      width: 120,
      render: (total, record) => (
        <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          {total} total ({record.critical_count} crit, {record.high_count} high)
        </span>
      ),
    },
    {
      title: 'SCANNED AT',
      dataIndex: 'scanned_at',
      key: 'scanned_at',
      width: 140,
      render: (date) => (
        <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          {formatRelativeTime(date)}
        </span>
      ),
    },
    {
      title: 'ACTION',
      key: 'action',
      align: 'right',
      width: 120,
      render: (_, record) => (
        <Button
          type="text"
          size="small"
          onClick={() => navigate(`/web-security/${record.id}`)}
          style={{ fontSize: '0.75rem', color: 'var(--color-accent)' }}
        >
          View Posture →
        </Button>
      ),
    },
  ];

  const certColumns = [
    {
      title: 'HOSTNAME / SHA-256',
      dataIndex: 'target_hostname',
      key: 'target_hostname',
      render: (host, record) => (
        <div>
          <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.85rem' }}>
            {host || 'Direct PEM Payload'}
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
            SHA-256: {record.certificate_sha256 ? `${record.certificate_sha256.substring(0, 16)}...` : '—'}
          </div>
        </div>
      ),
    },
    {
      title: 'VERDICT',
      dataIndex: 'verdict',
      key: 'verdict',
      width: 140,
      render: (verdict) => (
        <Tag
          color={verdict === 'TRUSTED' ? 'green' : verdict === 'WARNING' ? 'gold' : 'red'}
          style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}
        >
          {verdict}
        </Tag>
      ),
    },
    {
      title: 'TRUST SCORE',
      dataIndex: 'trust_score',
      key: 'trust_score',
      width: 120,
      render: (score) => (
        <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
          {score !== null ? `${score}/100` : '—'}
        </span>
      ),
    },
    {
      title: 'CHECKS',
      dataIndex: 'checks_completed',
      key: 'checks_completed',
      width: 100,
      render: (checks) => (
        <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          {checks} checks
        </span>
      ),
    },
    {
      title: 'SCANNED',
      dataIndex: 'scanned_at',
      key: 'scanned_at',
      width: 140,
      render: (date) => (
        <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          {formatRelativeTime(date)}
        </span>
      ),
    },
    {
      title: 'ACTION',
      key: 'action',
      align: 'right',
      width: 120,
      render: (_, record) => (
        <Button
          type="text"
          size="small"
          onClick={() => navigate(`/certificates/${record.id}`)}
          style={{ fontSize: '0.75rem', color: 'var(--color-accent)' }}
        >
          Inspect Cert →
        </Button>
      ),
    },
  ];

  return (
    <div style={{ maxWidth: '1280px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
          Historical Security Investigations
        </h1>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
          Explore, filter, and audit past website scans, passive web security posture evaluations, and cryptographic certificate analyses.
        </p>
      </div>

      <div className="tl-card" style={{ padding: '1.25rem' }}>
        <Tabs
          activeKey={activeTab}
          onChange={(key) => setActiveTab(key)}
          items={[
            {
              key: 'scans',
              label: (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
                  <History size={14} /> Full Website Scans
                </span>
              ),
              children: (
                <div>
                  {/* Filters Bar */}
                  <div
                    style={{
                      display: 'flex',
                      gap: '0.75rem',
                      marginBottom: '1rem',
                      flexWrap: 'wrap',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                    }}
                  >
                    <div style={{ display: 'flex', gap: '0.75rem', flex: 1, minWidth: '280px', flexWrap: 'wrap' }}>
                      <Input
                        placeholder="Search by target host or URL..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        prefix={<Search size={14} style={{ color: 'var(--text-muted)' }} />}
                        allowClear
                        style={{ maxWidth: '300px', backgroundColor: 'var(--bg-app)' }}
                      />

                      <Select
                        placeholder="Filter by Status"
                        value={statusFilter || undefined}
                        onChange={(v) => {
                          setStatusFilter(v || '');
                          setScansPage(1);
                        }}
                        allowClear
                        style={{ width: '150px' }}
                      >
                        <Option value="succeeded">Succeeded</Option>
                        <Option value="running">Running</Option>
                        <Option value="queued">Queued</Option>
                        <Option value="partial">Partial</Option>
                        <Option value="failed">Failed</Option>
                      </Select>

                      <Select
                        placeholder="Filter by Verdict"
                        value={verdictFilter || undefined}
                        onChange={(v) => {
                          setVerdictFilter(v || '');
                          setScansPage(1);
                        }}
                        allowClear
                        style={{ width: '160px' }}
                      >
                        <Option value="SAFE">SAFE</Option>
                        <Option value="SUSPICIOUS">SUSPICIOUS</Option>
                        <Option value="MALICIOUS">MALICIOUS</Option>
                        <Option value="INCONCLUSIVE">INCONCLUSIVE</Option>
                      </Select>
                    </div>

                    <Button
                      icon={<RotateCw size={13} className={isScansLoading ? 'animate-spin' : ''} />}
                      onClick={fetchScans}
                      loading={isScansLoading}
                      size="small"
                      style={{ backgroundColor: 'var(--bg-app)' }}
                    >
                      Refresh
                    </Button>
                  </div>

                  {filteredScans.length === 0 && !isScansLoading ? (
                    <EmptyState
                      title="No Matching Scans Found"
                      description="No asynchronous investigations match your query criteria."
                      actionText="Run New Scan"
                      onAction={() => navigate('/scan')}
                    />
                  ) : (
                    <Table
                      columns={scanColumns}
                      dataSource={filteredScans}
                      rowKey="id"
                      loading={isScansLoading}
                      pagination={{
                        current: scansPage,
                        pageSize: scansPageSize,
                        total: scansTotal,
                        onChange: (p, ps) => {
                          setScansPage(p);
                          setScansPageSize(ps);
                        },
                        showSizeChanger: true,
                        pageSizeOptions: ['10', '20', '50'],
                      }}
                      size="small"
                    />
                  )}
                </div>
              ),
            },
            {
              key: 'web-security',
              label: (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
                  <Globe size={14} /> Web Security Posture
                </span>
              ),
              children: (
                <div>
                  <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem', alignItems: 'center', justifyContent: 'space-between' }}>
                    <Select
                      placeholder="Filter by Posture"
                      value={webPostureFilter || undefined}
                      onChange={(v) => {
                        setWebPostureFilter(v || '');
                        setWebScansPage(1);
                      }}
                      allowClear
                      style={{ width: '180px' }}
                    >
                      <Option value="GOOD">GOOD</Option>
                      <Option value="MODERATE">MODERATE</Option>
                      <Option value="POOR">POOR</Option>
                    </Select>

                    <Button
                      icon={<RotateCw size={13} className={isWebLoading ? 'animate-spin' : ''} />}
                      onClick={fetchWebScans}
                      loading={isWebLoading}
                      size="small"
                    >
                      Refresh
                    </Button>
                  </div>

                  {webScans.length === 0 && !isWebLoading ? (
                    <EmptyState
                      title="No Web Security Posture Scans Found"
                      description="Analyze a website's passive security posture to evaluate headers, cookies, and TLS configuration."
                      actionText="Analyze Web Posture"
                      onAction={() => navigate('/web-security')}
                    />
                  ) : (
                    <Table
                      columns={webScanColumns}
                      dataSource={webScans}
                      rowKey="id"
                      loading={isWebLoading}
                      pagination={{
                        current: webScansPage,
                        pageSize: webScansLimit,
                        total: webScansTotal,
                        onChange: (p, l) => {
                          setWebScansPage(p);
                          setWebScansLimit(l);
                        },
                        showSizeChanger: true,
                      }}
                      size="small"
                    />
                  )}
                </div>
              ),
            },
            {
              key: 'certificates',
              label: (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
                  <ShieldCheck size={14} /> Certificate Analyses
                </span>
              ),
              children: (
                <div>
                  <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '1rem' }}>
                    <Button
                      icon={<RotateCw size={13} className={isCertLoading ? 'animate-spin' : ''} />}
                      onClick={fetchCertScans}
                      loading={isCertLoading}
                      size="small"
                    >
                      Refresh
                    </Button>
                  </div>

                  {certScans.length === 0 && !isCertLoading ? (
                    <EmptyState
                      title="No Certificate Evaluations Stored"
                      description="Submit a live TLS host or paste an X.509 PEM bundle to evaluate cryptographic integrity."
                      actionText="Analyze Certificate"
                      onAction={() => navigate('/certificates')}
                    />
                  ) : (
                    <Table
                      columns={certColumns}
                      dataSource={certScans}
                      rowKey="id"
                      loading={isCertLoading}
                      pagination={{
                        current: Math.floor(certOffset / certLimit) + 1,
                        pageSize: certLimit,
                        total: certTotal,
                        onChange: (p, l) => {
                          setCertOffset((p - 1) * l);
                          setCertLimit(l);
                        },
                        showSizeChanger: true,
                      }}
                      size="small"
                    />
                  )}
                </div>
              ),
            },
          ]}
        />
      </div>
    </div>
  );
}

