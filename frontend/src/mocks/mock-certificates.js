/**
 * Mock Certificate Details Repository
 * Realistic X.509 cryptographic parameters, validity states, and chain diagnostics.
 */

export const MOCK_CERTIFICATES = {
  // Valid certificate for example.com
  'c1f7b029-4556-41bf-bb44-ec853c8b4ad1': {
    host: 'example.com',
    valid: true,
    subject: 'CN=example.com,O=Internet Corporation for Assigned Names and Numbers,L=Los Angeles,ST=California,C=US',
    issuer: 'CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US',
    valid_from: '2026-01-15T00:00:00Z',
    valid_to: '2027-01-15T23:59:59Z',
    days_until_expiration: 69,
    sans: ['example.com', 'www.example.com', 'm.example.com'],
    serial_number: '0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d',
    sha256_fingerprint: 'a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef0123',
    signature_algorithm: 'sha256WithRSAEncryption',
    key_algorithm: 'RSA (2048 bit)',
    chain_valid: true,
    hostname_match: true,
    reasons: [],
  },

  // Self-signed invalid certificate
  's2a8c130-9112-48cd-aa55-fd964d9c5be2': {
    host: 'account-verify-login.xyz',
    valid: false,
    subject: 'CN=account-verify-login.xyz,O=SelfSignedDev',
    issuer: 'CN=account-verify-login.xyz,O=SelfSignedDev',
    valid_from: '2026-10-01T00:00:00Z',
    valid_to: '2026-11-01T00:00:00Z',
    days_until_expiration: -6,
    sans: ['account-verify-login.xyz'],
    serial_number: '778899aabbccddeeff00112233445566',
    sha256_fingerprint: '3f4e5d6c7b8a9012345678abcdef0123456789abcdef0123456789abcdef9988',
    signature_algorithm: 'sha256WithRSAEncryption',
    key_algorithm: 'RSA (2048 bit)',
    chain_valid: false,
    hostname_match: true,
    reasons: ['UNTRUSTED_ROOT_AUTHORITY', 'CERTIFICATE_EXPIRED'],
  },

  // HTTP-only / No TLS
  'm3d9e241-1234-49de-bb66-af075e0d6cf3': {
    host: 'update-secure-banking-portal.net',
    valid: false,
    subject: 'None (Plaintext HTTP)',
    issuer: 'None',
    valid_from: null,
    valid_to: null,
    days_until_expiration: null,
    sans: [],
    serial_number: null,
    sha256_fingerprint: null,
    signature_algorithm: null,
    key_algorithm: null,
    chain_valid: false,
    hostname_match: false,
    reasons: ['PORT_443_CLOSED', 'NO_TLS_NEGOTIATED'],
  },

  // Inconclusive target
  'i4e0f352-5678-40ef-cc77-bf186f1e7d04': {
    host: 'internal-dev-cluster-99.net',
    valid: false,
    subject: 'None (Connection Timed Out)',
    issuer: 'None',
    valid_from: null,
    valid_to: null,
    days_until_expiration: null,
    sans: [],
    serial_number: null,
    sha256_fingerprint: null,
    signature_algorithm: null,
    key_algorithm: null,
    chain_valid: false,
    hostname_match: false,
    reasons: ['HANDSHAKE_TIMEOUT'],
  },
};

/**
 * Get certificate details for a scan ID
 * @param {string} scanId 
 */
export async function mockGetCertificate(scanId) {
  await new Promise((res) => setTimeout(res, 200));
  const cert = MOCK_CERTIFICATES[scanId] || {
    host: 'target.domain',
    valid: true,
    subject: 'CN=target.domain,O=Demonstration Domain',
    issuer: 'CN=Let\'s Encrypt Authority X3,O=Let\'s Encrypt,C=US',
    valid_from: '2026-06-01T00:00:00Z',
    valid_to: '2026-12-31T23:59:59Z',
    days_until_expiration: 54,
    sans: ['target.domain', 'www.target.domain'],
    serial_number: '1234567890abcdef1234567890abcdef',
    sha256_fingerprint: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    signature_algorithm: 'sha256WithRSAEncryption',
    key_algorithm: 'RSA (2048 bit)',
    chain_valid: true,
    hostname_match: true,
    reasons: [],
  };

  return JSON.parse(JSON.stringify(cert));
}
