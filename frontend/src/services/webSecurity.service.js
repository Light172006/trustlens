/**
 * TrustLens Web Security Posture Analysis Service
 * Interacts with /api/v1/web-security endpoints for passive telemetry,
 * 22 deterministic security rules, and ML posture classification.
 */

import { apiClient } from './api';

export const webSecurityService = {
  /**
   * Execute passive web security posture analysis for a target URL
   * @param {object} params
   * @param {string} params.url
   * @param {boolean} [params.force_fresh=false]
   * @returns {Promise<object>}
   */
  async analyzeWebSecurity({ url, force_fresh = false }) {
    return await apiClient('/web-security/analyze', {
      method: 'POST',
      body: JSON.stringify({
        url: url.trim(),
        force_fresh: Boolean(force_fresh),
      }),
    });
  },

  /**
   * Retrieve a stored web security posture assessment by ID
   * @param {string} id
   * @returns {Promise<object>}
   */
  async getWebSecurityScan(id) {
    return await apiClient(`/web-security/${id}`);
  },

  /**
   * List paginated web security assessments with optional filters
   * @param {object} params
   * @param {string} [params.domain]
   * @param {string} [params.posture]
   * @param {number} [params.page=1]
   * @param {number} [params.limit=20]
   * @returns {Promise<{ items: Array, total: number, page: number, limit: number }>}
   */
  async listWebSecurityScans({ domain = '', posture = '', page = 1, limit = 20 } = {}) {
    const query = new URLSearchParams();
    if (domain) query.set('domain', domain);
    if (posture) query.set('posture', posture);
    if (page) query.set('page', page);
    if (limit) query.set('limit', limit);

    return await apiClient(`/web-security?${query.toString()}`);
  },
};

