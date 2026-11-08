/**
 * TrustLens Asynchronous Website Scan Service
 * Interacts with /api/v1/scans endpoints and findings.
 */

import { apiClient } from './api';

export const scanService = {
  /**
   * Submit a new website URL target for asynchronous security analysis
   * @param {string} url 
   * @param {boolean} [treatAsSensitive=false] 
   * @returns {Promise<{ scan: object, deduplicated: boolean }>}
   */
  async submitScan(url, treatAsSensitive = false) {
    return await apiClient('/scans', {
      method: 'POST',
      body: JSON.stringify({
        url: url.trim(),
        treat_as_sensitive: Boolean(treatAsSensitive),
      }),
    });
  },

  /**
   * List paginated scans scoped to the requesting user
   * @param {object} params 
   * @param {number} [params.page=1]
   * @param {number} [params.pageSize=20]
   * @param {string} [params.status]
   * @param {string} [params.verdict]
   * @returns {Promise<{ items: Array, total: number, page: number, page_size: number, pages: number }>}
   */
  async listScans({ page = 1, pageSize = 20, status = '', verdict = '' } = {}) {
    const query = new URLSearchParams();
    if (page) query.set('page', page);
    if (pageSize) query.set('page_size', pageSize);
    if (status) query.set('status', status);
    if (verdict) query.set('verdict', verdict);

    return await apiClient(`/scans?${query.toString()}`);
  },

  /**
   * Get detailed scan assessment report including layer coverage, provider checks, and redirects
   * @param {string} scanId 
   * @returns {Promise<{ scan: object, coverage: object, provider_checks: Array, redirects: Array }>}
   */
  async getScan(scanId) {
    return await apiClient(`/scans/${scanId}`);
  },

  /**
   * Get technical security findings discovered during the scan
   * @param {string} scanId 
   * @returns {Promise<{ scan_id: string, items: Array, total: number }>}
   */
  async getFindings(scanId) {
    return await apiClient(`/scans/${scanId}/findings`);
  },

  /**
   * Get leaf certificate analysis for HTTPS targets
   * @param {string} scanId 
   * @returns {Promise<{ scan_id: string, available: boolean, certificate: object | null, reason: string | null }>}
   */
  async getScanCertificate(scanId) {
    return await apiClient(`/scans/${scanId}/certificate`);
  },

  /**
   * Delete a scan record and cascade its child relations
   * @param {string} scanId 
   * @returns {Promise<void>}
   */
  async deleteScan(scanId) {
    await apiClient(`/scans/${scanId}`, { method: 'DELETE' });
  },
};

