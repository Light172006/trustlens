/**
 * TrustLens Collaborative Community Threat Intelligence Service
 * Interacts with /api/v1/community/reports endpoints for report submission,
 * public confirmed feeds, personal tracking, and peer voting.
 */

import { apiClient } from './api';

export const communityService = {
  /**
   * Submit suspicious website with evidence for collaborative moderation
   * @param {object} payload 
   * @param {string} payload.url
   * @param {string} [payload.scan_id]
   * @param {string} payload.category - 'phishing'|'malware'|'scam'|'credential_harvesting'|'unsolicited_bulk'|'other'
   * @param {string} [payload.claimed_verdict='MALICIOUS']
   * @param {string} payload.evidence_text - 20 to 2000 characters
   * @returns {Promise<{ report: object, duplicate_submission: boolean }>}
   */
  async submitReport({ url, scan_id = null, category, claimed_verdict = 'MALICIOUS', evidence_text }) {
    return await apiClient('/community/reports', {
      method: 'POST',
      body: JSON.stringify({
        url: url.trim(),
        scan_id: scan_id || null,
        category,
        claimed_verdict,
        evidence_text: evidence_text.trim(),
      }),
    });
  },

  /**
   * Retrieve public verified community threat reports
   * @param {object} params
   * @param {string} [params.category]
   * @param {string} [params.host]
   * @param {number} [params.page=1]
   * @param {number} [params.pageSize=20]
   * @returns {Promise<{ items: Array, total: number, page: number, page_size: number, pages: number }>}
   */
  async listConfirmedReports({ category = '', host = '', page = 1, pageSize = 20 } = {}) {
    const query = new URLSearchParams();
    if (category) query.set('category', category);
    if (host) query.set('host', host);
    if (page) query.set('page', page);
    if (pageSize) query.set('page_size', pageSize);

    return await apiClient(`/community/reports?${query.toString()}`);
  },

  /**
   * Retrieve user-scoped community report submissions
   * @param {object} params
   * @param {string} [params.status] - 'pending'|'confirmed'|'rejected'|'duplicate'
   * @param {number} [params.page=1]
   * @param {number} [params.pageSize=20]
   * @returns {Promise<{ items: Array, total: number, page: number, page_size: number, pages: number }>}
   */
  async listMyReports({ status = '', page = 1, pageSize = 20 } = {}) {
    const query = new URLSearchParams();
    if (status) query.set('status', status);
    if (page) query.set('page', page);
    if (pageSize) query.set('page_size', pageSize);

    return await apiClient(`/community/reports/mine?${query.toString()}`);
  },

  /**
   * Get single report detail
   * @param {string} reportId 
   * @returns {Promise<{ report: object }>}
   */
  async getReportDetail(reportId) {
    return await apiClient(`/community/reports/${reportId}`);
  },

  /**
   * Endorse or dispute a confirmed report
   * @param {string} reportId 
   * @param {'confirm' | 'false_positive'} vote 
   * @returns {Promise<{ report_id: string, vote: string, updated: boolean, counts: { confirm: number, false_positive: number } }>}
   */
  async castVote(reportId, vote) {
    return await apiClient(`/community/reports/${reportId}/votes`, {
      method: 'POST',
      body: JSON.stringify({ vote }),
    });
  },
};

