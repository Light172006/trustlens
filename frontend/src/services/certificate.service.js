/**
 * TrustLens Certificate Intelligence Service
 * Interacts with /api/v1/certificates and direct analysis endpoints.
 */

import { apiClient } from './api';

export const certificateService = {
  /**
   * Directly analyze an X.509 certificate via target hostname or PEM payload
   * @param {object} params
   * @param {string} [params.target_hostname]
   * @param {number} [params.port=443]
   * @param {string} [params.tls_protocol_version="TLSv1.3"]
   * @param {string} [params.cipher_suite]
   * @param {string} [params.certificate_pem]
   * @param {string} [params.certificate_der_base64]
   * @param {boolean} [params.include_ml_advisory=true]
   * @returns {Promise<object>}
   */
  async analyzeCertificate({
    target_hostname,
    port = 443,
    tls_protocol_version = 'TLSv1.3',
    cipher_suite,
    certificate_pem,
    certificate_der_base64,
    include_ml_advisory = true,
  }) {
    const payload = {
      port: port ? Number(port) : 443,
      tls_protocol_version: tls_protocol_version || 'TLSv1.3',
      include_ml_advisory: Boolean(include_ml_advisory),
    };

    if (target_hostname && target_hostname.trim()) {
      payload.target_hostname = target_hostname.trim();
    }
    if (cipher_suite && cipher_suite.trim()) {
      payload.cipher_suite = cipher_suite.trim();
    }
    if (certificate_pem && certificate_pem.trim()) {
      payload.certificate_pem = certificate_pem.trim();
    }
    if (certificate_der_base64 && certificate_der_base64.trim()) {
      payload.certificate_der_base64 = certificate_der_base64.trim();
    }

    return await apiClient('/certificates/analyze', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  /**
   * Retrieve certificate details for a website scan target or standalone assessment
   * @param {string} id 
   * @returns {Promise<object>}
   */
  async getCertificate(id) {
    try {
      return await apiClient(`/scans/${id}/certificate`);
    } catch (err) {
      if (err?.error?.code === 'NOT_FOUND' || err?.status === 404) {
        return await apiClient(`/certificates/${id}`);
      }
      throw err;
    }
  },

  /**
   * Retrieve previous certificate assessment by its scan ID
   * @param {string} id 
   * @returns {Promise<object>}
   */
  async getCertificateAssessment(id) {
    return await apiClient(`/certificates/${id}`);
  },

  /**
   * List previous certificate evaluations performed by user
   * @param {object} params
   * @param {number} [params.limit=20]
   * @param {number} [params.offset=0]
   * @returns {Promise<{ items: Array, total: number, limit: number, offset: number }>}
   */
  async listCertificateAssessments({ limit = 20, offset = 0 } = {}) {
    const query = new URLSearchParams();
    if (limit) query.set('limit', limit);
    if (offset) query.set('offset', offset);
    return await apiClient(`/certificates?${query.toString()}`);
  },
};

