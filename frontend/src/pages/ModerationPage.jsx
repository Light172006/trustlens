/**
 * TrustLens ModerationPage Component
 * Restricted console for moderators and administrators:
 * - Community report triage queue (/api/v1/admin/reports)
 * - Auditable decision recording (/api/v1/admin/reports/{id}/moderation)
 * - External threat intelligence feed provider telemetry (/api/v1/admin/providers)
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  CheckCircle2,
  XCircle,
  Copy,
  RotateCw,
  Activity,
  Radio,
  FileCheck,
  AlertTriangle,
  Clock,
} from 'lucide-react';
import { Table, Button, Tag, Modal, Input, Select, message, Alert, Card, Progress } from 'antd';
import { adminService } from '../services/admin.service';
import { formatRelativeTime } from '../lib/utils';
import { EmptyState } from '../components/common/EmptyState';

const { TextArea } = Input;
const { Option } = Select;

export function ModerationPage() {
  const [reports, setReports] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState('pending');
  const [isLoading, setIsLoading] = useState(true);

  // Provider Health
  const [providers, setProviders] = useState([]);
  const [isHealthLoading, setIsHealthLoading] = useState(false);

  // Decision Modal State
  const [selectedReport, setSelectedReport] = useState(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [decision, setDecision] = useState('confirmed');
  const [reason, setReason] = useState('');
  const [isDeciding, setIsDeciding] = useState(false);

  // 1. Fetch Moderation Reports
  const fetchReports = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await adminService.listAdminReports({
        status: statusFilter,
        page,
        pageSize: 15,
      });
      setReports(res.items || []);
      setTotal(res.total || 0);
    } catch {
      setReports([]);
      setTotal(0);
    } finally {
      setIsLoading(false);
    }
  }, [statusFilter, page]);

  // 2. Fetch Provider Health
  const fetchProviderHealth = useCallback(async () => {
    setIsHealthLoading(true);
    try {
      const res = await adminService.getProviderHealth();
      setProviders(res.providers || []);
    } catch {
      setProviders([]);
    } finally {
      setIsHealthLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchReports();
    fetchProviderHealth();
  }, [fetchReports, fetchProviderHealth]);

  const handleOpenModal = (report) => {
    setSelectedReport(report);
    setDecision('confirmed');
    setReason('');
    setModalOpen(true);
  };

  const handleSubmitDecision = async () => {
    if (!reason || reason.trim().length < 10) {
      message.error('Please provide an auditable justification (minimum 10 characters).');
      return;
    }

    setIsDeciding(true);
    try {
      await adminService.moderateReport(selectedReport.id, decision, reason.trim());
      message.success(`Report status committed as ${decision.toUpperCase()}.`);
      setModalOpen(false);
      fetchReports();
    } catch (err) {
      const p = err.error || err;
      message.error(p.message || 'Failed to record moderation decision.');
    } finally {
      setIsDeciding(false);
    }
  };

  const columns = [
    {
      title: 'TARGET URL / HOST',
      dataIndex: 'canonical_url',
      key: 'canonical_url',
      render: (url, record) => (
        <div>
          <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.85rem' }}>
            {record.host || url}
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.725rem', color: 'var(--text-muted)' }}>
            {url}
          </div>
          <div style={{ fontSize: '0.775rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            <strong>Evidence:</strong> {record.evidence_text}
          </div>
        </div>
      ),
    },
    {
      title: 'CATEGORY',
      dataIndex: 'category',
      key: 'category',
      width: 140,
      render: (cat) => <Tag color="volcano" style={{ textTransform: 'uppercase' }}>{cat}</Tag>,
    },
    {
      title: 'CLAIMED',
      dataIndex: 'claimed_verdict',
      key: 'claimed_verdict',
      width: 120,
      render: (v) => (
        <Tag color={v === 'MALICIOUS' ? 'red' : 'gold'} style={{ fontWeight: 700 }}>
          {v}
        </Tag>
      ),
    },
    {
      title: 'COMMUNITY FEEDBACK',
      key: 'feedback',
      width: 170,
      render: (_, record) => (
        <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          <div>Confirmed: <strong>{record.confirmation_count || 0}</strong></div>
          <div>False Positives: <strong>{record.false_positive_count || 0}</strong></div>
        </div>
      ),
    },
    {
      title: 'SUBMITTED',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 130,
      render: (d) => (
        <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          {formatRelativeTime(d)}
        </span>
      ),
    },
    {
      title: 'ACTION',
      key: 'action',
      align: 'right',
      width: 130,
      render: (_, record) => (
        <Button
          type="primary"
          size="small"
          onClick={() => handleOpenModal(record)}
          style={{
            backgroundColor: 'var(--color-accent)',
            borderColor: 'var(--color-accent)',
            color: '#101112',
            fontWeight: 600,
            fontSize: '0.75rem',
          }}
        >
          Triage Decision
        </Button>
      ),
    },
  ];

  return (
    <div style={{ maxWidth: '1280px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
          Moderation Operations & Threat Feed Telemetry
        </h1>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
          Triage submitted community threat indicators, commit auditable determinations, and observe provider feed ingestion health.
        </p>
      </div>

      {/* Threat Feed Ingestion Status Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem' }}>
        {providers.map((p) => (
          <div key={p.provider} className="tl-card" style={{ padding: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)', textTransform: 'uppercase' }}>
                {p.provider} Feed Telemetry
              </span>
              <Tag color={p.status === 'healthy' ? 'green' : 'orange'}>
                {p.status?.toUpperCase()}
              </Tag>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              <div>Freshness: <strong style={{ color: 'var(--text-primary)' }}>{p.freshness_seconds !== null ? `${p.freshness_seconds}s` : 'Real-time'}</strong></div>
              <div>Active Records: <strong style={{ color: 'var(--text-primary)' }}>{p.records_active ? p.records_active.toLocaleString() : 'Live Query'}</strong></div>
            </div>
          </div>
        ))}
      </div>

      {/* Moderation Queue Table */}
      <div className="tl-card" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
              Queue Status:
            </span>
            <Select
              value={statusFilter}
              onChange={(v) => {
                setStatusFilter(v);
                setPage(1);
              }}
              style={{ width: '160px' }}
            >
              <Option value="pending">Pending Review</Option>
              <Option value="confirmed">Confirmed</Option>
              <Option value="rejected">Rejected</Option>
              <Option value="duplicate">Duplicate</Option>
            </Select>
          </div>

          <Button
            icon={<RotateCw size={13} className={isLoading ? 'animate-spin' : ''} />}
            onClick={() => {
              fetchReports();
              fetchProviderHealth();
            }}
            loading={isLoading}
            size="small"
          >
            Refresh Queue
          </Button>
        </div>

        {reports.length === 0 && !isLoading ? (
          <EmptyState
            title="Moderation Queue Clear"
            description={`No community submissions currently hold status '${statusFilter}'.`}
          />
        ) : (
          <Table
            columns={columns}
            dataSource={reports}
            rowKey="id"
            loading={isLoading}
            pagination={{
              current: page,
              pageSize: 15,
              total: total,
              onChange: (p) => setPage(p),
            }}
            size="small"
          />
        )}
      </div>

      {/* Decision Modal */}
      <Modal
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <ShieldAlert size={18} color="var(--color-accent)" />
            <span>Record Auditable Moderation Decision</span>
          </div>
        }
        open={modalOpen}
        onCancel={() => setModalOpen(false)}
        footer={null}
        destroyOnClose
      >
        {selectedReport && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginTop: '1rem' }}>
            <div style={{ backgroundColor: 'var(--bg-app)', padding: '0.75rem', borderRadius: 'var(--radius-md)', fontSize: '0.8rem' }}>
              <div><strong>Target:</strong> {selectedReport.canonical_url}</div>
              <div><strong>Category:</strong> {selectedReport.category}</div>
              <div style={{ marginTop: '0.25rem' }}><strong>Evidence:</strong> {selectedReport.evidence_text}</div>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                OUTCOME DETERMINATION *
              </label>
              <Select
                value={decision}
                onChange={(v) => setDecision(v)}
                style={{ width: '100%' }}
              >
                <Option value="confirmed">Confirm Malicious Indicator</Option>
                <Option value="rejected">Reject Report (Benign / Insufficient Evidence)</Option>
                <Option value="duplicate">Mark as Duplicate Submission</Option>
              </Select>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                AUDITABLE JUSTIFICATION REASON * (10 to 1000 characters)
              </label>
              <TextArea
                rows={3}
                placeholder="Document observed evidence, brand validation checks, or rationale for this determination..."
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                maxLength={1000}
                showCount
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
              <Button onClick={() => setModalOpen(false)}>Cancel</Button>
              <Button
                type="primary"
                onClick={handleSubmitDecision}
                loading={isDeciding}
                style={{
                  backgroundColor: 'var(--color-accent)',
                  borderColor: 'var(--color-accent)',
                  color: '#101112',
                  fontWeight: 600,
                }}
              >
                Commit Decision
              </Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}

