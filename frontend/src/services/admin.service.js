/**
 * TrustLens Moderation & Administration Service
 * Restricted to users holding moderator or admin roles.
 * Interacts with /api/v1/admin endpoints.
 */

import { apiClient } from './api';

export const adminService = {
  /**
   * Retrieve community reports in the moderation triage queue
   * @param {object} params
   * @param {string} [params.status='pending']
   * @param {number} [params.page=1]
   * @param {number} [params.pageSize=20]
   * @returns {Promise<{ items: Array, total: number, page: number, page_size: number, pages: number }>}
   */
  async listAdminReports({ status = 'pending', page = 1, pageSize = 20 } = {}) {
    const query = new URLSearchParams();
    if (status) query.set('status', status);
    if (page) query.set('page', page);
    if (pageSize) query.set('page_size', pageSize);

    return await apiClient(`/admin/reports?${query.toString()}`);
  },

  /**
   * Submit an auditable moderation decision (confirmed, rejected, duplicate)
   * @param {string} reportId 
   * @param {'confirmed' | 'rejected' | 'duplicate'} decision 
   * @param {string} reason - 10 to 1000 characters
   * @returns {Promise<{ report: object, audit_event_id: string }>}
   */
  async moderateReport(reportId, decision, reason) {
    return await apiClient(`/admin/reports/${reportId}/moderation`, {
      method: 'POST',
      body: JSON.stringify({
        decision,
        reason: reason.trim(),
      }),
    });
  },

  /**
   * Fetch operational health and freshness of threat intelligence feeds (OpenPhish, URLhaus)
   * @returns {Promise<{ providers: Array }>}
   */
  async getProviderHealth() {
    return await apiClient('/admin/providers');
  },
};

