/**
 * Mock Scan Data & Repository
 * Stores initial demo scans covering all four verdicts (SAFE, SUSPICIOUS, MALICIOUS, INCONCLUSIVE)
 * and supports creating new live scans with realistic polling state transitions.
 */

export const INITIAL_MOCK_SCANS = [
  {
    scan: {
      id: 'c1f7b029-4556-41bf-bb44-ec853c8b4ad1',
      original_url: 'https://example.com/login',
      canonical_url: 'https://example.com/login',
      host: 'example.com',
      scheme: 'https',
      is_sensitive: false,
      status: 'succeeded',
      verdict: 'SAFE',
      risk_score: 12,
      scoring_version: 'trustlens-1.0',
      checks_completed: 4,
      created_at: '2026-11-07T13:32:00Z',
      started_at: '2026-11-07T13:32:01Z',
      completed_at: '2026-11-07T13:32:04Z',
      failure_code: null,
      failure_message: null,
    },
    coverage: {
      threat_intel: 'complete',
      web_security: 'complete',
      certificate: 'complete',
      community: 'complete',
    },
    provider_checks: [
      {
        provider: 'openphish',
        result_status: 'no_match',
        matched: false,
        checked_at: '2026-11-07T13:32:03Z',
        details: { feed_timestamp: '2026-11-07T10:00:00Z' },
      },
      {
        provider: 'urlhaus',
        result_status: 'no_match',
        matched: false,
        checked_at: '2026-11-07T13:32:03Z',
        details: { query_status: 'ok' },
      },
    ],
    redirects: [
      {
        hop: 1,
        source_url: 'http://example.com/login',
        destination_url: 'https://example.com/login',
        status_code: 301,
        host: 'example.com',
        ip: '93.184.216.34',
        tls_verified: true,
      },
    ],
  },
  {
    scan: {
      id: 's2a8c130-9112-48cd-aa55-fd964d9c5be2',
      original_url: 'http://account-verify-login.xyz',
      canonical_url: 'https://account-verify-login.xyz/secure',
      host: 'account-verify-login.xyz',
      scheme: 'https',
      is_sensitive: false,
      status: 'succeeded',
      verdict: 'SUSPICIOUS',
      risk_score: 58,
      scoring_version: 'trustlens-1.0',
      checks_completed: 4,
      created_at: '2026-11-07T14:10:00Z',
      started_at: '2026-11-07T14:10:01Z',
      completed_at: '2026-11-07T14:10:05Z',
      failure_code: null,
      failure_message: null,
    },
    coverage: {
      threat_intel: 'complete',
      web_security: 'complete',
      certificate: 'partial',
      community: 'complete',
    },
    provider_checks: [
      {
        provider: 'openphish',
        result_status: 'no_match',
        matched: false,
        checked_at: '2026-11-07T14:10:03Z',
        details: { feed_timestamp: '2026-11-07T14:00:00Z' },
      },
      {
        provider: 'urlhaus',
        result_status: 'no_match',
        matched: false,
        checked_at: '2026-11-07T14:10:03Z',
        details: { query_status: 'ok' },
      },
    ],
    redirects: [
      {
        hop: 1,
        source_url: 'http://account-verify-login.xyz',
        destination_url: 'http://account-verify-login.xyz/auth',
        status_code: 302,
        host: 'account-verify-login.xyz',
        ip: '185.220.101.5',
        tls_verified: false,
      },
      {
        hop: 2,
        source_url: 'http://account-verify-login.xyz/auth',
        destination_url: 'https://account-verify-login.xyz/secure',
        status_code: 301,
        host: 'account-verify-login.xyz',
        ip: '185.220.101.5',
        tls_verified: true,
      },
    ],
  },
  {
    scan: {
      id: 'm3d9e241-1234-49de-bb66-af075e0d6cf3',
      original_url: 'http://update-secure-banking-portal.net/login.php',
      canonical_url: 'http://update-secure-banking-portal.net/login.php',
      host: 'update-secure-banking-portal.net',
      scheme: 'http',
      is_sensitive: false,
      status: 'succeeded',
      verdict: 'MALICIOUS',
      risk_score: 95,
      scoring_version: 'trustlens-1.0',
      checks_completed: 4,
      created_at: '2026-11-07T14:45:00Z',
      started_at: '2026-11-07T14:45:01Z',
      completed_at: '2026-11-07T14:45:06Z',
      failure_code: null,
      failure_message: null,
    },
    coverage: {
      threat_intel: 'complete',
      web_security: 'complete',
      certificate: 'unavailable',
      community: 'complete',
    },
    provider_checks: [
      {
        provider: 'openphish',
        result_status: 'match',
        matched: true,
        checked_at: '2026-11-07T14:45:02Z',
        details: {
          feed_timestamp: '2026-11-07T14:30:00Z',
          target_brand: 'Financial Institution Phish',
        },
      },
      {
        provider: 'urlhaus',
        result_status: 'match',
        matched: true,
        checked_at: '2026-11-07T14:45:02Z',
        details: {
          threat: 'malicious_download_phish',
          reporter: 'community_analyst',
        },
      },
    ],
    redirects: [
      {
        hop: 1,
        source_url: 'http://update-secure-banking-portal.net/login.php',
        destination_url: 'http://update-secure-banking-portal.net/auth/harvest.php',
        status_code: 302,
        host: 'update-secure-banking-portal.net',
        ip: '194.87.139.12',
        tls_verified: false,
      },
    ],
  },
  {
    scan: {
      id: 'i4e0f352-5678-40ef-cc77-bf186f1e7d04',
      original_url: 'https://internal-dev-cluster-99.net',
      canonical_url: 'https://internal-dev-cluster-99.net',
      host: 'internal-dev-cluster-99.net',
      scheme: 'https',
      is_sensitive: true,
      status: 'partial',
      verdict: 'INCONCLUSIVE',
      risk_score: null,
      scoring_version: 'trustlens-1.0',
      checks_completed: 1,
      created_at: '2026-11-07T15:00:00Z',
      started_at: '2026-11-07T15:00:01Z',
      completed_at: '2026-11-07T15:00:15Z',
      failure_code: 'TARGET_TIMEOUT',
      failure_message: 'Target web service timed out before responding to probe requests.',
    },
    coverage: {
      threat_intel: 'partial',
      web_security: 'unavailable',
      certificate: 'unavailable',
      community: 'complete',
    },
    provider_checks: [
      {
        provider: 'openphish',
        result_status: 'no_match',
        matched: false,
        checked_at: '2026-11-07T15:00:02Z',
        details: { feed_timestamp: '2026-11-07T14:30:00Z' },
      },
      {
        provider: 'urlhaus',
        result_status: 'skipped_sensitive_url',
        matched: false,
        checked_at: '2026-11-07T15:00:02Z',
        details: { reason: 'External lookup disabled for sensitive submission.' },
      },
    ],
    redirects: [],
  },
];

// In-memory scans repository for current session
let mockScansStore = [...INITIAL_MOCK_SCANS];

/**
 * Reset mock store to default state
 */
export function resetMockScans() {
  mockScansStore = [...INITIAL_MOCK_SCANS];
}

/**
 * List paginated scans
 * @param {object} params
 */
export async function mockListScans({ page = 1, pageSize = 20, status, verdict }) {
  await new Promise((res) => setTimeout(res, 250));

  let filtered = mockScansStore.map((item) => ({
    id: item.scan.id,
    canonical_url: item.scan.canonical_url,
    host: item.scan.host,
    status: item.scan.status,
    verdict: item.scan.verdict,
    risk_score: item.scan.risk_score,
    created_at: item.scan.created_at,
    completed_at: item.scan.completed_at,
  }));

  if (status) {
    filtered = filtered.filter((s) => s.status.toLowerCase() === status.toLowerCase());
  }

  if (verdict) {
    filtered = filtered.filter((s) => s.verdict.toUpperCase() === verdict.toUpperCase());
  }

  // Sort newest first
  filtered.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

  const total = filtered.length;
  const pages = Math.ceil(total / pageSize) || 1;
  const start = (page - 1) * pageSize;
  const items = filtered.slice(start, start + pageSize);

  return {
    items,
    total,
    page: Number(page),
    page_size: Number(pageSize),
    pages,
  };
}

/**
 * Get single scan report by ID with realistic polling transitions
 * @param {string} scanId 
 */
export async function mockGetScan(scanId) {
  await new Promise((res) => setTimeout(res, 200));

  const item = mockScansStore.find((s) => s.scan.id === scanId);
  if (!item) {
    throw {
      error: {
        code: 'RESOURCE_NOT_FOUND',
        message: `Scan with ID '${scanId}' not found.`,
        request_id: 'mock-req-scan-notfound',
      },
    };
  }

  // If this scan is currently active (queued or running), simulate progression over time
  const now = Date.now();
  const createdTime = new Date(item.scan.created_at).getTime();
  const elapsedSec = (now - createdTime) / 1000;

  if (item.scan.status === 'queued' && elapsedSec >= 2) {
    item.scan.status = 'running';
    item.scan.started_at = new Date(createdTime + 2000).toISOString();
    item.scan.checks_completed = 1;
  } else if (item.scan.status === 'running') {
    if (elapsedSec >= 4 && item.scan.checks_completed < 2) {
      item.scan.checks_completed = 2;
    }
    if (elapsedSec >= 6 && item.scan.checks_completed < 3) {
      item.scan.checks_completed = 3;
    }
    if (elapsedSec >= 8) {
      // Complete the scan!
      item.scan.status = 'succeeded';
      item.scan.checks_completed = 4;
      item.scan.completed_at = new Date().toISOString();
      if (!item.scan.risk_score && item.scan.verdict === 'INCONCLUSIVE') {
        item.scan.verdict = 'SAFE';
        item.scan.risk_score = 15;
      }
    }
  }

  return JSON.parse(JSON.stringify(item));
}

/**
 * Submit target for scan (simulating deduplication window of 60 seconds)
 * @param {string} url 
 * @param {boolean} treatAsSensitive 
 */
export async function mockSubmitScan(url, treatAsSensitive = false) {
  await new Promise((res) => setTimeout(res, 350));

  // Check for invalid hosts / SSRF simulation
  if (url.includes('127.0.0.1') || url.includes('localhost') || url.includes('169.254')) {
    throw {
      error: {
        code: 'TARGET_NOT_PUBLIC',
        message: 'The target hostname or IP address resolves to a private, loopback, or non-public network address.',
        request_id: 'mock-req-ssrf-defense',
        details: { host: url, resolved_ips: ['127.0.0.1'] },
      },
    };
  }

  // Deduplication check: recent queued or running scan for identical URL within 60s
  const now = Date.now();
  const existingActive = mockScansStore.find((s) => {
    if (s.scan.original_url.toLowerCase() !== url.toLowerCase()) return false;
    const diff = (now - new Date(s.scan.created_at).getTime()) / 1000;
    return diff < 60 && (s.scan.status === 'queued' || s.scan.status === 'running');
  });

  if (existingActive) {
    return {
      scan: { ...existingActive.scan },
      deduplicated: true,
    };
  }

  // Determine host and scheme
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    parsed = { hostname: url.replace(/^https?:\/\//, '').split('/')[0], protocol: 'https:' };
  }

  const newId = 'scan-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6);
  
  // Choose simulated verdict based on URL patterns for easy demo/testing
  let simulatedVerdict = 'SAFE';
  let simulatedScore = 14;
  const lowerUrl = url.toLowerCase();

  if (lowerUrl.includes('malicious') || lowerUrl.includes('phish') || lowerUrl.includes('bank-update') || lowerUrl.includes('harvest')) {
    simulatedVerdict = 'MALICIOUS';
    simulatedScore = 92;
  } else if (lowerUrl.includes('suspicious') || lowerUrl.includes('verify') || lowerUrl.includes('login-xyz') || lowerUrl.includes('alert')) {
    simulatedVerdict = 'SUSPICIOUS';
    simulatedScore = 64;
  } else if (lowerUrl.includes('inconclusive') || lowerUrl.includes('timeout') || treatAsSensitive) {
    simulatedVerdict = 'INCONCLUSIVE';
    simulatedScore = null;
  }

  const newScanRecord = {
    scan: {
      id: newId,
      original_url: url,
      canonical_url: url,
      host: parsed.hostname || 'target.host',
      scheme: parsed.protocol ? parsed.protocol.replace(':', '') : 'https',
      is_sensitive: Boolean(treatAsSensitive),
      status: 'queued',
      verdict: simulatedVerdict,
      risk_score: simulatedScore,
      scoring_version: 'trustlens-1.0',
      checks_completed: 0,
      created_at: new Date().toISOString(),
      started_at: null,
      completed_at: null,
      failure_code: null,
      failure_message: null,
    },
    coverage: {
      threat_intel: 'complete',
      web_security: 'complete',
      certificate: 'complete',
      community: 'complete',
    },
    provider_checks: [
      {
        provider: 'openphish',
        result_status: simulatedVerdict === 'MALICIOUS' ? 'match' : 'no_match',
        matched: simulatedVerdict === 'MALICIOUS',
        checked_at: new Date().toISOString(),
        details: { feed_timestamp: new Date().toISOString() },
      },
      {
        provider: 'urlhaus',
        result_status: treatAsSensitive ? 'skipped_sensitive_url' : (simulatedVerdict === 'MALICIOUS' ? 'match' : 'no_match'),
        matched: !treatAsSensitive && simulatedVerdict === 'MALICIOUS',
        checked_at: new Date().toISOString(),
        details: { query_status: 'ok' },
      },
    ],
    redirects: [
      {
        hop: 1,
        source_url: url.replace('https://', 'http://'),
        destination_url: url,
        status_code: 301,
        host: parsed.hostname || 'target.host',
        ip: '104.21.55.19',
        tls_verified: true,
      },
    ],
  };

  mockScansStore.unshift(newScanRecord);

  return {
    scan: { ...newScanRecord.scan },
    deduplicated: false,
  };
}

/**
 * Delete a scan by ID
 * @param {string} scanId 
 */
export async function mockDeleteScan(scanId) {
  await new Promise((res) => setTimeout(res, 200));
  const idx = mockScansStore.findIndex((s) => s.scan.id === scanId);
  if (idx !== -1) {
    mockScansStore.splice(idx, 1);
  }
  return true;
}
