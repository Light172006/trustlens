/**
 * TrustLens Website Scan Service
 * Interacts with /api/v1/scans endpoints and findings.
 */

import { apiClient, USE_MOCK_API } from './api';
import {
  mockSubmitScan,
  mockListScans,
  mockGetScan,
  mockDeleteScan,
} from '../mocks/mock-scans';
import { mockGetFindings } from '../mocks/mock-findings';

export const scanService = {
  /**
   * Submit a new URL target for security analysis
   * @param {string} url 
   * @param {boolean} [treatAsSensitive=false] 
   * @returns {Promise<{ scan: object, deduplicated: boolean }>}
   */
  async submitScan(url, treatAsSensitive = false) {
    if (USE_MOCK_API) {
      return await mockSubmitScan(url, treatAsSensitive);
    }

    return await apiClient('/scans', {
      method: 'POST',
      body: JSON.stringify({
        url,
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
    if (USE_MOCK_API) {
      return await mockListScans({ page, pageSize, status, verdict });
    }

    const query = new URLSearchParams();
    if (page) query.set('page', page);
    if (pageSize) query.set('page_size', pageSize);
    if (status) query.set('status', status);
    if (verdict) query.set('verdict', verdict);

    return await apiClient(`/scans?${query.toString()}`);
  },

  /**
   * Get detailed scan report including coverage, provider checks, and redirects
   * @param {string} scanId 
   * @returns {Promise<{ scan: object, coverage: object, provider_checks: Array, redirects: Array }>}
   */
  async getScan(scanId) {
    if (USE_MOCK_API) {
      return await mockGetScan(scanId);
    }

    return await apiClient(`/scans/${scanId}`);
  },

  /**
   * Get fine-grained heuristic findings that generated the risk score
   * @param {string} scanId 
   * @returns {Promise<{ items: Array, total: number }>}
   */
  async getFindings(scanId) {
    if (USE_MOCK_API) {
      return await mockGetFindings(scanId);
    }

    return await apiClient(`/scans/${scanId}/findings`);
  },

  /**
   * Delete a scan record and cascade its findings
   * @param {string} scanId 
   * @returns {Promise<boolean>}
   */
  async deleteScan(scanId) {
    if (USE_MOCK_API) {
      return await mockDeleteScan(scanId);
    }

    await apiClient(`/scans/${scanId}`, { method: 'DELETE' });
    return true;
  },
};
