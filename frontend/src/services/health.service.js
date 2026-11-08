/**
 * TrustLens Platform Health & Connectivity Service
 * Probes root health endpoints for liveness, readiness, DB, and Redis status.
 */

import { apiClient } from './api';

export const healthService = {
  /**
   * Check base application health and API version
   */
  async getHealth() {
    return await apiClient('/health');
  },

  /**
   * Probe PostgreSQL database latency and connectivity
   */
  async getDatabaseHealth() {
    return await apiClient('/health/database');
  },

  /**
   * Probe Redis cache and task queue connectivity
   */
  async getRedisHealth() {
    return await apiClient('/health/redis');
  },

  /**
   * Composite readiness probe
   */
  async getReadiness() {
    return await apiClient('/health/ready');
  },
};

