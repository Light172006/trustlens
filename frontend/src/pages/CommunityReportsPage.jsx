/**
 * TrustLens CommunityReportsPage Component
 * Collaborative threat reporting, crowd-voting intelligence, and submission tracking.
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  Users,
  AlertTriangle,
  ShieldAlert,
  ThumbsUp,
  ThumbsDown,
  PlusCircle,
  RotateCw,
  Search,
  Filter,
  CheckCircle2,
  Clock,
  ExternalLink,
} from 'lucide-react';
import { Table, Tabs, Input, Select, Button, Tag, message, Alert, Modal } from 'antd';
import { communityService } from '../services/community.service';
import { formatDate, formatRelativeTime, validateUrl } from '../lib/utils';
import { EmptyState } from '../components/common/EmptyState';
import { useAuth } from '../context/AuthContext';

const { TextArea } = Input;
const { Option } = Select;

export function CommunityReportsPage() {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState('feed');

  // Feed State
  const [feedItems, setFeedItems] = useState([]);
  const [feedTotal, setFeedTotal] = useState(0);
  const [feedPage, setFeedPage] = useState(1);
  const [feedCategory, setFeedCategory] = useState('');
  const [feedHost, setFeedHost] = useState('');
  const [isFeedLoading, setIsFeedLoading] = useState(true);

  // My Reports State
  const [myReports, setMyReports] = useState([]);
  const [myTotal, setMyTotal] = useState(0);
  const [myPage, setMyPage] = useState(1);
  const [myStatus, setMyStatus] = useState('');
  const [isMyLoading, setIsMyLoading] = useState(false);

  // Submit Form State
  const [submitUrl, setSubmitUrl] = useState('');
  const [submitCategory, setSubmitCategory] = useState('phishing');
  const [submitVerdict, setSubmitVerdict] = useState('MALICIOUS');
  const [submitEvidence, setSubmitEvidence] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState('');

  // 1. Fetch Confirmed Threat Feed
  const fetchFeed = useCallback(async () => {
    setIsFeedLoading(true);
    try {
      const res = await communityService.listConfirmedReports({
        category: feedCategory,
        host: feedHost,
        page: feedPage,
        pageSize: 15,
      });
      setFeedItems(res.items || []);
      setFeedTotal(res.total || 0);
    } catch {
      setFeedItems([]);
      setFeedTotal(0);
    } finally {
      setIsFeedLoading(false);
    }
  }, [feedCategory, feedHost, feedPage]);

  // 2. Fetch My Submissions
  const fetchMyReports = useCallback(async () => {
    setIsMyLoading(true);
    try {
      const res = await communityService.listMyReports({
        status: myStatus,
        page: myPage,
        pageSize: 15,
      });
      setMyReports(res.items || []);
      setMyTotal(res.total || 0);
    } catch {
      setMyReports([]);
      setMyTotal(0);
    } finally {
      setIsMyLoading(false);
    }
  }, [myStatus, myPage]);

  useEffect(() => {
    if (activeTab === 'feed') fetchFeed();
    else if (activeTab === 'mine') fetchMyReports();
  }, [activeTab, fetchFeed, fetchMyReports]);

  // Handle Crowd Vote
  const handleVote = async (reportId, voteType) => {
    try {
      const res = await communityService.castVote(reportId, voteType);
      message.success(
        `Vote registered: ${voteType === 'confirm' ? 'Confirmed malicious' : 'Disputed / False positive'}`
      );
      // Update local counts in feed
      setFeedItems((prev) =>
        prev.map((item) => {
          if (item.id === reportId) {
            return {
              ...item,
              confirmation_count: res.counts.confirm,
              false_positive_count: res.counts.false_positive,
            };
          }
          return item;
        })
      );
    } catch (err) {
      const p = err.error || err;
      message.error(p.message || 'Failed to submit vote. You cannot vote on your own report.');
    }
  };

  // Handle Submit Report
  const handleSubmitReport = async (e) => {
    if (e) e.preventDefault();
    setSubmitError('');

    const val = validateUrl(submitUrl);
    if (!val.valid) {
      setSubmitError(val.error);
      return;
    }

    if (!submitEvidence || submitEvidence.trim().length < 20) {
      setSubmitError('Evidence text must be at least 20 characters in length.');
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await communityService.submitReport({
        url: submitUrl.trim(),
        category: submitCategory,
        claimed_verdict: submitVerdict,
        evidence_text: submitEvidence.trim(),
      });

      if (res.duplicate_submission) {
        message.warning('Deduplicated: An active report for this domain was submitted within the last 30 days.');
      } else {
        message.success('Threat report submitted for moderator triage.');
      }

      setSubmitUrl('');
      setSubmitEvidence('');
      setActiveTab('mine');
    } catch (err) {
      const p = err.error || err;
      setSubmitError(p.message || 'Unable to submit report.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const feedColumns = [
    {
      title: 'TARGET DOMAIN / URL',
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
          <div style={{ fontSize: '0.775rem', color: 'var(--text-secondary)', marginTop: '0.35rem' }}>
            {record.evidence_summary}
          </div>
        </div>
      ),
    },
    {
      title: 'CATEGORY',
      dataIndex: 'category',
      key: 'category',
      width: 140,
      render: (cat) => (
        <Tag color="volcano" style={{ textTransform: 'uppercase', fontWeight: 600, fontSize: '0.7rem' }}>
          {cat}
        </Tag>
      ),
    },
    {
      title: 'VERDICT',
      dataIndex: 'claimed_verdict',
      key: 'claimed_verdict',
      width: 120,
      render: (verdict) => (
        <Tag color={verdict === 'MALICIOUS' ? 'red' : 'gold'} style={{ fontWeight: 700 }}>
          {verdict}
        </Tag>
      ),
    },
    {
      title: 'CROWD VOTES',
      key: 'votes',
      width: 220,
      render: (_, record) => (
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Button
            size="small"
            icon={<ThumbsUp size={12} />}
            onClick={() => handleVote(record.id, 'confirm')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.25rem',
              color: 'var(--color-safe-text)',
              borderColor: 'var(--color-safe-border)',
              backgroundColor: 'var(--color-safe-bg)',
              fontSize: '0.75rem',
            }}
          >
            {record.confirmation_count || 0}
          </Button>

          <Button
            size="small"
            icon={<ThumbsDown size={12} />}
            onClick={() => handleVote(record.id, 'false_positive')}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.25rem',
              color: 'var(--color-suspicious-text)',
              borderColor: 'var(--color-suspicious-border)',
              backgroundColor: 'var(--color-suspicious-bg)',
              fontSize: '0.75rem',
            }}
          >
            {record.false_positive_count || 0}
          </Button>
        </div>
      ),
    },
    {
      title: 'MODERATED',
      dataIndex: 'moderated_at',
      key: 'moderated_at',
      width: 130,
      render: (date) => (
        <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          {formatRelativeTime(date)}
        </span>
      ),
    },
  ];

  const myColumns = [
    {
      title: 'TARGET URL',
      dataIndex: 'canonical_url',
      key: 'canonical_url',
      render: (url, record) => (
        <div>
          <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.85rem' }}>
            {url}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            {record.evidence_text}
          </div>
        </div>
      ),
    },
    {
      title: 'CATEGORY',
      dataIndex: 'category',
      key: 'category',
      width: 140,
      render: (cat) => <Tag style={{ textTransform: 'uppercase' }}>{cat}</Tag>,
    },
    {
      title: 'STATUS',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      render: (status) => (
        <Tag
          color={
            status === 'confirmed'
              ? 'green'
              : status === 'pending'
                ? 'gold'
                : status === 'rejected'
                  ? 'red'
                  : 'default'
          }
          style={{ textTransform: 'uppercase', fontWeight: 600 }}
        >
          {status}
        </Tag>
      ),
    },
    {
      title: 'MODERATION REASON',
      dataIndex: 'moderation_reason',
      key: 'moderation_reason',
      render: (reason) => (
        <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          {reason || 'Awaiting moderator review'}
        </span>
      ),
    },
    {
      title: 'SUBMITTED',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 130,
      render: (date) => (
        <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          {formatRelativeTime(date)}
        </span>
      ),
    },
  ];

  return (
    <div style={{ maxWidth: '1280px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
          Collaborative Community Threat Intelligence
        </h1>
        <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
          Peer-reviewed indicators of compromise, crowd-sourced threat triage, and community consensus voting.
        </p>
      </div>

      <div className="tl-card" style={{ padding: '1.25rem' }}>
        <Tabs
          activeKey={activeTab}
          onChange={(key) => setActiveTab(key)}
          items={[
            {
              key: 'feed',
              label: (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
                  <ShieldAlert size={14} /> Confirmed Threat Feed
                </span>
              ),
              children: (
                <div>
                  <div
                    style={{
                      display: 'flex',
                      gap: '0.75rem',
                      marginBottom: '1rem',
                      flexWrap: 'wrap',
                      justifyContent: 'space-between',
                    }}
                  >
                    <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
                      <Input
                        placeholder="Filter by hostname..."
                        value={feedHost}
                        onChange={(e) => setFeedHost(e.target.value)}
                        allowClear
                        prefix={<Search size={14} style={{ color: 'var(--text-muted)' }} />}
                        style={{ width: '220px', backgroundColor: 'var(--bg-app)' }}
                      />

                      <Select
                        placeholder="Category"
                        value={feedCategory || undefined}
                        onChange={(v) => setFeedCategory(v || '')}
                        allowClear
                        style={{ width: '180px' }}
                      >
                        <Option value="phishing">Phishing</Option>
                        <Option value="malware">Malware</Option>
                        <Option value="scam">Scam</Option>
                        <Option value="credential_harvesting">Credential Harvesting</Option>
                        <Option value="unsolicited_bulk">Unsolicited Bulk</Option>
                        <Option value="other">Other</Option>
                      </Select>
                    </div>

                    <Button
                      icon={<RotateCw size={13} className={isFeedLoading ? 'animate-spin' : ''} />}
                      onClick={fetchFeed}
                      loading={isFeedLoading}
                      size="small"
                    >
                      Refresh Feed
                    </Button>
                  </div>

                  {feedItems.length === 0 && !isFeedLoading ? (
                    <EmptyState
                      title="No Confirmed Threat Reports Found"
                      description="No confirmed malicious community reports match your filter criteria."
                      actionText="Submit Threat Report"
                      onAction={() => setActiveTab('submit')}
                    />
                  ) : (
                    <Table
                      columns={feedColumns}
                      dataSource={feedItems}
                      rowKey="id"
                      loading={isFeedLoading}
                      pagination={{
                        current: feedPage,
                        pageSize: 15,
                        total: feedTotal,
                        onChange: (p) => setFeedPage(p),
                      }}
                      size="small"
                    />
                  )}
                </div>
              ),
            },
            {
              key: 'mine',
              label: (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
                  <Clock size={14} /> My Submissions
                </span>
              ),
              children: (
                <div>
                  <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem', justifyContent: 'space-between' }}>
                    <Select
                      placeholder="Status Filter"
                      value={myStatus || undefined}
                      onChange={(v) => setMyStatus(v || '')}
                      allowClear
                      style={{ width: '180px' }}
                    >
                      <Option value="pending">Pending Review</Option>
                      <Option value="confirmed">Confirmed</Option>
                      <Option value="rejected">Rejected</Option>
                      <Option value="duplicate">Duplicate</Option>
                    </Select>

                    <Button
                      icon={<RotateCw size={13} className={isMyLoading ? 'animate-spin' : ''} />}
                      onClick={fetchMyReports}
                      loading={isMyLoading}
                      size="small"
                    >
                      Refresh
                    </Button>
                  </div>

                  {myReports.length === 0 && !isMyLoading ? (
                    <EmptyState
                      title="No Community Submissions Yet"
                      description="You have not submitted any suspicious websites for community review."
                      actionText="Submit New Report"
                      onAction={() => setActiveTab('submit')}
                    />
                  ) : (
                    <Table
                      columns={myColumns}
                      dataSource={myReports}
                      rowKey="id"
                      loading={isMyLoading}
                      pagination={{
                        current: myPage,
                        pageSize: 15,
                        total: myTotal,
                        onChange: (p) => setMyPage(p),
                      }}
                      size="small"
                    />
                  )}
                </div>
              ),
            },
            {
              key: 'submit',
              label: (
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
                  <PlusCircle size={14} /> Submit Threat Report
                </span>
              ),
              children: (
                <div style={{ maxWidth: '640px', padding: '1rem 0' }}>
                  <form onSubmit={handleSubmitReport} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    {submitError && <Alert message={submitError} type="error" showIcon />}

                    <div>
                      <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                        TARGET URL *
                      </label>
                      <Input
                        size="large"
                        placeholder="https://malicious-login-example.test/auth"
                        value={submitUrl}
                        onChange={(e) => setSubmitUrl(e.target.value)}
                        disabled={isSubmitting}
                        style={{ fontFamily: 'var(--font-mono)' }}
                      />
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                      <div>
                        <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                          THREAT CATEGORY *
                        </label>
                        <Select
                          size="large"
                          value={submitCategory}
                          onChange={(v) => setSubmitCategory(v)}
                          style={{ width: '100%' }}
                        >
                          <Option value="phishing">Phishing</Option>
                          <Option value="malware">Malware</Option>
                          <Option value="scam">Financial Scam</Option>
                          <Option value="credential_harvesting">Credential Harvesting</Option>
                          <Option value="unsolicited_bulk">Unsolicited Bulk / Spam</Option>
                          <Option value="other">Other Security Risk</Option>
                        </Select>
                      </div>

                      <div>
                        <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                          CLAIMED RISK VERDICT *
                        </label>
                        <Select
                          size="large"
                          value={submitVerdict}
                          onChange={(v) => setSubmitVerdict(v)}
                          style={{ width: '100%' }}
                        >
                          <Option value="MALICIOUS">MALICIOUS</Option>
                          <Option value="SUSPICIOUS">SUSPICIOUS</Option>
                          <Option value="SAFE">SAFE (False Positive)</Option>
                        </Select>
                      </div>
                    </div>

                    <div>
                      <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
                        TECHNICAL EVIDENCE & OBSERVATIONS * (20 - 2000 characters)
                      </label>
                      <TextArea
                        rows={4}
                        placeholder="Describe observed malicious indicators, brand impersonation, spoofed login forms, credential harvesting payloads, or TLS discrepancies..."
                        value={submitEvidence}
                        onChange={(e) => setSubmitEvidence(e.target.value)}
                        maxLength={2000}
                        showCount
                        disabled={isSubmitting}
                      />
                    </div>

                    <Button
                      type="primary"
                      size="large"
                      htmlType="submit"
                      loading={isSubmitting}
                      style={{
                        backgroundColor: 'var(--color-accent)',
                        borderColor: 'var(--color-accent)',
                        color: '#101112',
                        fontWeight: 600,
                        marginTop: '0.5rem',
                      }}
                    >
                      Submit for Moderation Review
                    </Button>
                  </form>
                </div>
              ),
            },
          ]}
        />
      </div>
    </div>
  );
}

