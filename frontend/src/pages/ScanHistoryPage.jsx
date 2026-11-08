/**
 * ScanHistoryPage Component
 * Paginated historical scan directory with status filters, verdict filters,
 * local search filter across loaded results, and scan deletion confirmation.
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
} from 'lucide-react';
import { Table, Input, Select, Button, Modal, message, Tooltip } from 'antd';
import { scanService } from '../services/scan.service';
import { VerdictBadge } from '../components/common/VerdictBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { RiskScoreGauge } from '../components/common/RiskScoreGauge';
import { formatDate, formatRelativeTime } from '../lib/utils';
import { EmptyState } from '../components/common/EmptyState';

const { Option } = Select;

export function ScanHistoryPage() {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [statusFilter, setStatusFilter] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [deletingId, setDeletingId] = useState(null);

  const navigate = useNavigate();

  const fetchScans = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await scanService.listScans({
        page,
        pageSize,
        status: statusFilter,
        verdict: verdictFilter,
      });
      setItems(res.items || []);
      setTotal(res.total || 0);
    } catch {
      setItems([]);
      setTotal(0);
    } finally {
      setIsLoading(false);
    }
  }, [page, pageSize, statusFilter, verdictFilter]);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  const handleDeleteScan = (record) => {
    Modal.confirm({
      title: 'Delete Investigation Record?',
      icon: <AlertOctagon size={22} color="var(--color-malicious-text)" />,
      content: `Are you sure you want to permanently delete the scan record for '${record.canonical_url}'? This will cascade deletion to its findings, redirects, and certificate records.`,
      okText: 'Delete Record',
      okType: 'danger',
      cancelText: 'Cancel',
      async onOk() {
        setDeletingId(record.id);
        try {
          await scanService.deleteScan(record.id);
          message.success('Scan record deleted successfully.');
          fetchScans();
        } catch {
          message.error('Failed to delete scan record.');
        } finally {
          setDeletingId(null);
        }
      },
    });
  };

  // Client-side search filtering over loaded results
  const filteredItems = items.filter((item) => {
    if (!searchTerm.trim()) return true;
    const term = searchTerm.toLowerCase();
    return (
      (item.host && item.host.toLowerCase().includes(term)) ||
      (item.canonical_url && item.canonical_url.toLowerCase().includes(term)) ||
      (item.id && item.id.toLowerCase().includes(term))
    );
  });

  const columns = [
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
      title: 'SUBMITTED',
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
      title: 'COMPLETED',
      dataIndex: 'completed_at',
      key: 'completed_at',
      render: (date) => (
        <span style={{ fontSize: '0.775rem', color: 'var(--text-muted)' }}>
          {date ? formatRelativeTime(date) : '—'}
        </span>
      ),
    },
    {
      title: 'ACTIONS',
      key: 'actions',
      align: 'right',
      render: (_, record) => (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '0.5rem' }}>
          <Button
            type="primary"
            size="small"
            onClick={() => navigate(`/scans/${record.id}`)}
            style={{
              backgroundColor: 'var(--color-accent)',
              borderColor: 'var(--color-accent)',
              color: '#101112',
              fontWeight: 600,
              fontSize: '0.75rem',
            }}
          >
            View
          </Button>
          <Tooltip title="Delete record">
            <Button
              type="text"
              size="small"
              danger
              icon={<Trash2 size={14} />}
              loading={deletingId === record.id}
              onClick={() => handleDeleteScan(record)}
            />
          </Tooltip>
        </div>
      ),
    },
  ];

  return (
    <div>
      {/* Page Title */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '1.4rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
            Investigation History
          </h1>
          <p style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
            Archived security scans and forensic telemetry records
          </p>
        </div>

        <Button
          icon={<RotateCw size={13} />}
          onClick={fetchScans}
          loading={isLoading}
          size="small"
          style={{ color: 'var(--text-secondary)' }}
        >
          Refresh Directory
        </Button>
      </div>

      {/* Filter and Search Bar */}
      <div
        className="tl-card"
        style={{
          padding: '1rem 1.25rem',
          marginBottom: '1.5rem',
          display: 'flex',
          alignItems: 'center',
          gap: '1rem',
          flexWrap: 'wrap',
        }}
      >
        <div style={{ flex: 1, minWidth: '220px' }}>
          <Input
            placeholder="Search domain or URL in loaded records..."
            prefix={<Search size={15} style={{ color: 'var(--text-muted)', marginRight: 4 }} />}
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            allowClear
            style={{ backgroundColor: 'var(--bg-app)', borderColor: 'var(--border-color)' }}
          />
        </div>

        {/* Verdict Filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Verdict:</span>
          <Select
            value={verdictFilter}
            onChange={(val) => {
              setVerdictFilter(val);
              setPage(1);
            }}
            style={{ width: 140 }}
            size="middle"
          >
            <Option value="">All Verdicts</Option>
            <Option value="SAFE">Safe</Option>
            <Option value="SUSPICIOUS">Suspicious</Option>
            <Option value="MALICIOUS">Malicious</Option>
            <Option value="INCONCLUSIVE">Inconclusive</Option>
          </Select>
        </div>

        {/* Status Filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Status:</span>
          <Select
            value={statusFilter}
            onChange={(val) => {
              setStatusFilter(val);
              setPage(1);
            }}
            style={{ width: 130 }}
            size="middle"
          >
            <Option value="">All Statuses</Option>
            <Option value="succeeded">Completed</Option>
            <Option value="running">Running</Option>
            <Option value="queued">Queued</Option>
            <Option value="partial">Partial</Option>
            <Option value="failed">Failed</Option>
          </Select>
        </div>
      </div>

      {/* Scans Table */}
      <div className="tl-card" style={{ padding: '0.5rem' }}>
        <Table
          dataSource={filteredItems}
          columns={columns}
          rowKey="id"
          loading={isLoading}
          pagination={{
            current: page,
            pageSize,
            total,
            onChange: (p, ps) => {
              setPage(p);
              setPageSize(ps);
            },
            showSizeChanger: true,
            pageSizeOptions: ['10', '20', '50'],
            size: 'small',
          }}
          scroll={{ x: 900 }}
          locale={{
            emptyText: (
              <EmptyState
                title="No Scans Matched"
                description={
                  searchTerm || statusFilter || verdictFilter
                    ? 'No scan records matched your selected criteria or search term.'
                    : 'You have not submitted any URL targets for analysis yet.'
                }
                actionLabel={searchTerm || statusFilter || verdictFilter ? 'Reset Filters' : 'Submit Target Scan'}
                onAction={() => {
                  if (searchTerm || statusFilter || verdictFilter) {
                    setSearchTerm('');
                    setStatusFilter('');
                    setVerdictFilter('');
                  } else {
                    navigate('/scan');
                  }
                }}
              />
            ),
          }}
        />
      </div>
    </div>
  );
}
