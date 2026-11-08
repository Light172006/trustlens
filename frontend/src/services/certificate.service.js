/**
 * TrustLens Certificate Intelligence Service
 * Interacts with /api/v1/scans/{scan_id}/certificate and /api/v1/certificates/analyze endpoints.
 */

import { apiClient, USE_MOCK_API } from './api';
import { mockGetCertificate } from '../mocks/mock-certificates';

export const certificateService = {
  /**
   * Get parsed X.509 cryptographic parameters and trust assessment for a scan
   * @param {string} scanId 
   * @returns {Promise<object>}
   */
  async getCertificate(scanId) {
    if (USE_MOCK_API) {
      return await mockGetCertificate(scanId);
    }

    return await apiClient(`/scans/${scanId}/certificate`);
  },

  /**
   * Directly analyze a certificate via PEM payload or target hostname
   * @param {object} params
   * @param {string} [params.hostname]
   * @param {number} [params.port=443]
   * @param {string} [params.pem]
   * @param {boolean} [params.include_ml_advisory=true]
   * @returns {Promise<object>}
   */
  async analyzeCertificate({ hostname, port = 443, pem, include_ml_advisory = true }) {
    if (USE_MOCK_API) {
      return await mockGetCertificate('demo');
    }

    return await apiClient('/certificates/analyze', {
      method: 'POST',
      body: JSON.stringify({
        hostname: hostname || undefined,
        port: port ? Number(port) : 443,
        pem: pem || undefined,
        include_ml_advisory,
      }),
    });
  },
};
