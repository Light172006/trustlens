/**
 * TrustLens Dashboard Service
 * Interacts with /api/v1/dashboard/summary for real user-scoped metrics.
 */

import { apiClient } from './api';

export const dashboardService = {
  /**
   * Fetch aggregate scan statistics, verdict distribution, and 10 recent scans
   * @returns {Promise<{ summary: { total_scans: number, scans_last_30_days: number, verdict_counts: Record<string, number>, active_scans: number, pending_community_reports: number }, recent_scans: Array }>}
   */
  async getSummary() {
    return await apiClient('/dashboard/summary');
  },
};

