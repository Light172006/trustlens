/**
 * TrustLens Utility Library
 * Core helper functions for formatting, validation, and verdict rendering.
 */

/**
 * Mandatory canonical descriptions for security verdicts as defined in FRONTEND_REQUIREMENTS.md
 */
export const VERDICT_DESCRIPTIONS = {
  SAFE: 'No material risk was found by the checks performed. This is not a guarantee that the website is safe.',
  SUSPICIOUS: 'Some signals require caution. Review the findings before sharing information.',
  MALICIOUS: 'This URL matched a trusted threat indicator or independently confirmed community intelligence. Do not visit or enter information.',
  INCONCLUSIVE: 'TrustLens could not collect enough reliable evidence. Do not interpret this result as safe.',
};

/**
 * Verdict styling definitions
 */
export const VERDICT_CONFIG = {
  SAFE: {
    label: 'SAFE',
    color: 'var(--color-safe-text)',
    bg: 'var(--color-safe-bg)',
    border: 'var(--color-safe-border)',
    badgeClass: 'verdict-safe',
  },
  SUSPICIOUS: {
    label: 'SUSPICIOUS',
    color: 'var(--color-suspicious-text)',
    bg: 'var(--color-suspicious-bg)',
    border: 'var(--color-suspicious-border)',
    badgeClass: 'verdict-suspicious',
  },
  MALICIOUS: {
    label: 'MALICIOUS',
    color: 'var(--color-malicious-text)',
    bg: 'var(--color-malicious-bg)',
    border: 'var(--color-malicious-border)',
    badgeClass: 'verdict-malicious',
  },
  INCONCLUSIVE: {
    label: 'INCONCLUSIVE',
    color: 'var(--color-inconclusive-text)',
    bg: 'var(--color-inconclusive-bg)',
    border: 'var(--color-inconclusive-border)',
    badgeClass: 'verdict-inconclusive',
  },
};

/**
 * Severity configuration for findings
 */
export const SEVERITY_CONFIG = {
  info: { label: 'INFO', color: 'var(--severity-info)', bg: 'var(--severity-info-bg)' },
  low: { label: 'LOW', color: 'var(--severity-low)', bg: 'var(--severity-low-bg)' },
  medium: { label: 'MEDIUM', color: 'var(--severity-medium)', bg: 'var(--severity-medium-bg)' },
  high: { label: 'HIGH', color: 'var(--severity-high)', bg: 'var(--severity-high-bg)' },
  critical: { label: 'CRITICAL', color: 'var(--severity-critical)', bg: 'var(--severity-critical-bg)' },
};

/**
 * Canonical error code guidance map
 */
export const ERROR_MESSAGES = {
  TARGET_NOT_PUBLIC: 'Private, loopback, and internal addresses cannot be scanned.',
  UNSUPPORTED_URL_SCHEME: 'Only HTTP and HTTPS URLs are supported.',
  CREDENTIALS_IN_URL_REJECTED: 'URLs containing credentials are not permitted.',
  PORT_NOT_ALLOWED: 'Only standard web ports (80 and 443) are supported.',
  REDIRECT_LOOP_DETECTED: 'Target has an infinite redirect loop.',
  AUTHENTICATION_REQUIRED: 'Your session has expired or is invalid. Please log in again.',
  FORBIDDEN: 'You do not have permission to view or manage this scan.',
  RESOURCE_NOT_FOUND: 'The requested resource could not be found.',
  RATE_LIMIT_EXCEEDED: 'Rate limit exceeded. Please wait a moment before trying again.',
  STATE_CONFLICT: 'A conflict occurred with an existing resource.',
  INTERNAL_ERROR: 'An internal server error occurred. Please reference your Request ID when contacting support.',
};

/**
 * Join CSS class names cleanly
 * @param  {...(string|boolean|undefined|null)} classes
 * @returns {string}
 */
export function cn(...classes) {
  return classes.filter(Boolean).join(' ');
}

/**
 * Safely parse date strings into Date objects, ensuring UTC strings without
 * explicit timezone offsets (e.g. from SQLite) are treated as UTC.
 * @param {string|Date|null|undefined} dateInput 
 * @returns {Date|null}
 */
export function parseDate(dateInput) {
  if (!dateInput) return null;
  if (dateInput instanceof Date) return isNaN(dateInput.getTime()) ? null : dateInput;
  let s = String(dateInput).trim();
  if (!s) return null;

  // Handle ISO / SQL timestamps like '2026-11-07T18:08:39' or '2026-11-07 18:08:39'
  if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}/.test(s)) {
    // If it doesn't end with Z or a timezone offset (+/-HH:MM or +/-HHMM)
    if (!/[Zz]$/.test(s) && !/[+-]\d{2}(:?\d{2})?$/.test(s)) {
      s = s.replace(' ', 'T') + 'Z';
    }
  }

  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

/**
 * Format an ISO date string into a readable timestamp
 * @param {string|Date|null} dateString 
 * @param {boolean} includeTime 
 * @returns {string}
 */
export function formatDate(dateString, includeTime = true) {
  const d = parseDate(dateString);
  if (!d) return '—';
  try {
    if (!includeTime) {
      return d.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      });
    }
    return d.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  } catch {
    return '—';
  }
}

/**
 * Format relative time (e.g. "2 minutes ago")
 * @param {string|Date|null} dateString 
 * @returns {string}
 */
export function formatRelativeTime(dateString) {
  const d = parseDate(dateString);
  if (!d) return '—';
  try {
    const now = new Date();
    const diffMs = now.getTime() - d.getTime();
    if (diffMs < 0 && diffMs > -5000) return 'just now';
    if (diffMs < 0) return formatDate(dateString, true);

    const diffSec = Math.floor(diffMs / 1000);
    if (diffSec < 45) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHours = Math.floor(diffMin / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    const diffDays = Math.floor(diffHours / 24);
    if (diffDays < 30) return `${diffDays}d ago`;
    return formatDate(dateString, false);
  } catch {
    return '—';
  }
}

/**
 * Validates whether a URL has a valid http/https scheme and hostname
 * @param {string} urlString 
 * @returns {{ valid: boolean, error?: string }}
 */
export function validateUrl(urlString) {
  if (!urlString || typeof urlString !== 'string') {
    return { valid: false, error: 'Please enter a target URL.' };
  }

  const trimmed = urlString.trim();
  if (!trimmed) {
    return { valid: false, error: 'URL cannot be empty.' };
  }

  // Scheme check
  if (!/^https?:\/\//i.test(trimmed)) {
    return { valid: false, error: 'Only HTTP and HTTPS URLs are supported (e.g. https://example.com).' };
  }

  try {
    const parsed = new URL(trimmed);
    if (parsed.username || parsed.password) {
      return { valid: false, error: 'URLs containing user credentials are not permitted.' };
    }
    if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
      return { valid: false, error: 'Only standard web ports (80 and 443) are supported.' };
    }
    if (!parsed.hostname || !parsed.hostname.includes('.')) {
      return { valid: false, error: 'Please enter a fully-qualified domain name.' };
    }
    return { valid: true };
  } catch {
    return { valid: false, error: 'Invalid URL format.' };
  }
}

/**
 * Generate a client-side UUID v4 for X-Request-ID
 * @returns {string}
 */
export function generateUUID() {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}
