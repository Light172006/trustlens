/**
 * Mock Security Findings Repository
 * Fine-grained heuristic findings with severity, category, evidence, and remediation.
 */

export const MOCK_FINDINGS = {
  // Safe scan findings
  'c1f7b029-4556-41bf-bb44-ec853c8b4ad1': [
    {
      code: 'HSTS_MISSING',
      title: 'Strict-Transport-Security Header Missing',
      description: 'The web server does not advertise HSTS, leaving users vulnerable to SSL-stripping man-in-the-middle attacks.',
      severity: 'medium',
      category: 'web_security',
      points: 10,
      evidence: {
        header_evaluated: 'strict-transport-security',
        value: null,
      },
      remediation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to HTTP response headers.",
      source: 'backend_scanner',
    },
    {
      code: 'CSP_MISSING',
      title: 'Content-Security-Policy Missing',
      description: 'The site does not define a Content Security Policy to restrict origin execution of scripts.',
      severity: 'low',
      category: 'web_security',
      points: 5,
      evidence: {
        header_evaluated: 'content-security-policy',
        value: null,
      },
      remediation: 'Configure a Content-Security-Policy header restricting script execution to approved domains.',
      source: 'backend_scanner',
    },
  ],

  // Suspicious scan findings
  's2a8c130-9112-48cd-aa55-fd964d9c5be2': [
    {
      code: 'CERTIFICATE_SELF_SIGNED',
      title: 'Untrusted Self-Signed Certificate',
      description: 'The TLS certificate was issued by an untrusted authority or is self-signed, preventing cryptographic chain validation.',
      severity: 'high',
      category: 'certificate',
      points: 30,
      evidence: {
        issuer: 'CN=localhost,OU=DevTesting',
        subject: 'CN=account-verify-login.xyz',
        chain_valid: false,
      },
      remediation: 'Replace the self-signed certificate with one issued by a trusted Public Certificate Authority (e.g. Let\'s Encrypt, DigiCert).',
      source: 'certificate_evaluator',
    },
    {
      code: 'SUSPICIOUS_REGISTRATION_TLD',
      title: 'High-Risk TLD & Recent Domain Registration',
      description: 'The domain uses a TLD frequently associated with spam campaigns and was registered less than 7 days ago.',
      severity: 'medium',
      category: 'threat_intel',
      points: 18,
      evidence: {
        tld: '.xyz',
        domain_age_days: 3,
        registrar: 'NameCheap Public Proxy',
      },
      remediation: 'Monitor domain telemetry and avoid entering sensitive login credentials.',
      source: 'whois_intel',
    },
    {
      code: 'LOGIN_FORM_UNENCRYPTED_REDIRECT',
      title: 'Authentication Page Originates from Insecure HTTP Hop',
      description: 'The redirect chain began on an unencrypted HTTP link before transitioning to HTTPS.',
      severity: 'medium',
      category: 'web_security',
      points: 10,
      evidence: {
        initial_scheme: 'http',
        redirect_hops: 2,
      },
      remediation: 'Enforce immediate 301 redirection to HTTPS at the root domain or enable HSTS preloading.',
      source: 'redirect_analyzer',
    },
  ],

  // Malicious scan findings
  'm3d9e241-1234-49de-bb66-af075e0d6cf3': [
    {
      code: 'THREAT_FEED_MATCH_OPENPHISH',
      title: 'Known Phishing Site (OpenPhish Match)',
      description: 'The target URL matches a high-confidence credential harvesting signature in the OpenPhish global intelligence feed.',
      severity: 'critical',
      category: 'threat_intel',
      points: 50,
      evidence: {
        feed: 'OpenPhish Premium',
        indicator_id: 'OP-2026-9921',
        target_brand: 'Global Banking Portal',
        detected_at: '2026-11-07T14:30:00Z',
      },
      remediation: 'Immediately block user access via firewall/DNS sinkhole. Do not enter credentials or download files.',
      source: 'openphish_feed',
    },
    {
      code: 'URLHAUS_MALWARE_DISTRIBUTION',
      title: 'Active Malware Distribution Endpoint (URLhaus Match)',
      description: 'URLhaus community intelligence confirmed this URL is actively distributing malware payloads.',
      severity: 'critical',
      category: 'threat_intel',
      points: 40,
      evidence: {
        threat_type: 'trojan_dropper',
        file_sha256: '9f8e7d6c5b4a3928170e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c',
        status: 'online',
      },
      remediation: 'Report the hosting provider and submit domain takedown notice.',
      source: 'urlhaus_feed',
    },
    {
      code: 'TLS_ABSENT_ON_CREDENTIAL_FORM',
      title: 'Cleartext Form Submission on Phishing Endpoint',
      description: 'The webpage solicits user password credentials over unencrypted HTTP.',
      severity: 'high',
      category: 'web_security',
      points: 25,
      evidence: {
        scheme: 'http',
        form_action: 'http://update-secure-banking-portal.net/auth/harvest.php',
        form_fields: ['username', 'password', 'pin', 'ssn'],
      },
      remediation: 'Terminate host immediately.',
      source: 'dom_analyzer',
    },
  ],

  // Inconclusive scan findings
  'i4e0f352-5678-40ef-cc77-bf186f1e7d04': [
    {
      code: 'PROBE_TIMEOUT',
      title: 'Network Probe Request Timed Out',
      description: 'The automated scanner was unable to receive a timely HTTP response from the target server within the configured 15-second window.',
      severity: 'info',
      category: 'web_security',
      points: 0,
      evidence: {
        timeout_seconds: 15,
        protocol: 'https',
      },
      remediation: 'Check server availability, upstream firewall rules, or re-run the scan once the host is responsive.',
      source: 'backend_scanner',
    },
  ],
};

/**
 * Get findings for a scan ID
 * @param {string} scanId 
 */
export async function mockGetFindings(scanId) {
  await new Promise((res) => setTimeout(res, 200));
  const items = MOCK_FINDINGS[scanId] || [
    {
      code: 'BASELINE_CHECK_PASSED',
      title: 'Baseline Security Check Completed',
      description: 'Standard security perimeter checks finished without flagging critical anomalies.',
      severity: 'info',
      category: 'web_security',
      points: 0,
      evidence: { timestamp: new Date().toISOString() },
      remediation: 'Continue practicing proactive security hygiene and monitoring.',
      source: 'backend_scanner',
    },
  ];

  return {
    items,
    total: items.length,
  };
}
