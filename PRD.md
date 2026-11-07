# TrustLens — Product Requirements Document

**Document version:** 1.0  
**Product:** TrustLens  
**Product category:** AI-assisted web threat detection and digital trust intelligence  
**Primary interface:** Responsive web application  
**MVP posture:** Evidence-led, passive assessment; no exploit testing  

## 1. Product overview

TrustLens helps a person decide whether to interact with a website by combining four complementary signals in one report:

1. **Threat analysis:** Check the submitted URL against phishing and malware intelligence sources and TrustLens's curated indicator store.
2. **Web security assessment:** Inspect public HTTP response behaviour, security headers, cookie attributes, redirects, and negotiated TLS configuration using bounded, non-invasive requests.
3. **Certificate validation:** Verify the HTTPS certificate chain and hostname against the scanner's operating-system trust store; inspect validity dates, subject alternative names, key properties, and available certificate-transparency evidence.
4. **Collaborative threat intelligence:** Allow authenticated people to report suspicious URLs, add evidence, and vote on already-published reports; moderators review and curate community submissions.

TrustLens is a decision-support product, not a guarantee of safety, an antivirus product, a browser, or a penetration-testing platform. A `SAFE` result means that the defined checks completed without finding a material risk at the time of the scan. It does not mean the site is guaranteed harmless.

### 1.1 Product goals

- Give a user one explainable report instead of requiring several disconnected tools.
- Return a clear overall verdict plus the evidence behind it.
- Keep malicious-site detection distinct from weak-but-not-malicious website configuration.
- Make uncertainty and provider outages visible instead of silently treating missing evidence as a clean result.
- Create a moderated community signal that improves coverage without allowing unverified crowd reports to label a site malicious automatically.
- Run public URL checks without becoming a server-side request forgery (SSRF) proxy or an abuse tool.

### 1.2 Success metrics

| Metric | MVP target | Measurement |
|---|---:|---|
| Scan enqueue latency | p95 below 500 ms | API request duration, excluding scan execution |
| Typical scan completion | p50 below 12 s; p95 below 25 s | `completed_at - started_at` for successful/partial scans |
| Scan completion availability | At least 98% of accepted scans reach a terminal state | Completed, partial, or failed scans / accepted scans |
| Explainability | 100% of non-`SAFE` verdicts have at least one finding | Verdict-to-findings invariant |
| Feed freshness | OpenPhish community feed no older than 13 h; URLhaus direct lookups performed per scan | Provider check timestamps and sync logs |
| API reliability | 99.5% monthly availability for authenticated core API | `/health/ready` and request telemetry |
| False-positive governance | 100% of community reports remain non-authoritative until moderator review | Database state transition audit |
| SSRF prevention | Zero successful connections to prohibited IP ranges in security tests | Automated adversarial test suite and egress logs |

These are launch targets, not claims about achieved production performance.

## 2. Users, personas, and problem statement

### 2.1 Primary personas

**P1 — Everyday internet user**

- **Context:** Receives a banking, delivery, recruitment, university, payment, or government-service link through email, messaging, search, or social media.
- **Goal:** Decide whether to open the link or enter information.
- **Pain:** A convincing phishing page can use familiar logos, HTTPS, and a similar domain. A green padlock alone does not prove legitimacy.
- **Needs:** A short verdict, plain-language reasons, risk level, and immediate safety advice.
- **MVP permissions:** Register, scan public URLs, view own scan history, submit a community report, vote on published reports.

**P2 — Student, researcher, or security-aware user**

- **Context:** Checks links for coursework, research, personal projects, or responsible security awareness.
- **Goal:** Understand why the site was classified as safe, suspicious, malicious, or inconclusive.
- **Pain:** Single-purpose reputation checkers do not explain certificate quality or web-security configuration; raw TLS diagnostics are difficult to interpret.
- **Needs:** Evidence, timestamps, redirect chain, certificate facts, provider names, and remediation explanations.
- **MVP permissions:** Same as P1, with access to detailed findings and JSON report data in the UI.

**P3 — Community contributor**

- **Context:** Encounters a suspicious URL and wants to warn other users.
- **Goal:** Submit a report that can be assessed and shared responsibly.
- **Pain:** Public reporting mechanisms may be fragmented, hard to follow, or vulnerable to duplicate/noisy submissions.
- **Needs:** A guided report form, a visible moderation state, duplicate detection, and a way to add a confirmation or false-positive vote.
- **MVP permissions:** Submit reports, see own report status, vote once per report, view moderator-confirmed public reports.

**P4 — TrustLens moderator**

- **Context:** Reviews incoming community reports and handles false positives or abuse.
- **Goal:** Publish only credible community intelligence and preserve an auditable decision trail.
- **Pain:** Unverified claims can damage legitimate domains; brigading can distort votes.
- **Needs:** Evidence review, reporter history, duplicate detection, vote counts, reasoned decisions, and audit history.
- **MVP permissions:** Review, confirm, reject, or mark duplicate reports. Moderation actions are recorded in `audit_events`.

**P5 — Platform administrator**

- **Context:** Operates the application, integrations, workers, and service health.
- **Goal:** Maintain reliable scanning and protect the service from abuse.
- **Needs:** Health metrics, provider freshness, queue depth, error rates, controlled configuration, and role management through operational tooling.
- **MVP permissions:** Admin role; no unrestricted arbitrary URL fetch or command execution is exposed in the product UI.

### 2.2 Detailed problem statement

Internet users increasingly encounter phishing pages, fraudulent payment links, impersonated organisations, fake recruitment portals, deceptive redirects, and malware-distribution websites. A malicious site can closely resemble a legitimate banking portal, university website, government service, or corporate platform. People may disclose credentials, payment details, identity information, or authentication tokens before recognising the deception.

Existing controls are often fragmented. A URL reputation service may identify known phishing or malware infrastructure but say little about a site's TLS configuration. A certificate viewer may confirm that a certificate chains to a trusted root without determining whether the site is impersonating a brand. A header scanner may identify missing security headers but cannot establish that a domain is malicious. Community reporting systems may contain valuable observations but lack consistent verification and context.

TrustLens addresses this gap with one time-bounded assessment that keeps the four evidence classes separate, correlates them through a versioned scoring policy, and exposes both the verdict and its limitations. Certificate validity is never treated as proof of business identity. Missing security headers are never treated as proof of phishing. Community votes are not treated as authoritative threat intelligence until moderation.

## 3. Product principles and terminology

### 3.1 Verdict definitions

| Verdict | Definition | User-facing interpretation |
|---|---|---|
| `SAFE` | Required scan layers completed, threat-intelligence coverage was sufficiently fresh, and risk score is 0–24 with no decisive malicious indicator. | No material risk was found by the checks performed. Continue to verify the site's identity before sharing sensitive information. |
| `SUSPICIOUS` | Risk score is 25–74, or a material configuration/certificate issue exists without decisive threat-intelligence confirmation. | Use caution; review the findings and avoid entering sensitive information until independently verified. |
| `MALICIOUS` | An exact URL match exists in an enabled trusted threat feed, or at least two independent moderator-confirmed reports refer to the same canonical URL. | Do not visit, download, pay, or enter credentials on this URL. |
| `INCONCLUSIVE` | Mandatory evidence is missing, scanner access was blocked, the scan timed out, or threat-intelligence coverage is too stale/unavailable to justify a clean verdict. | TrustLens could not collect enough reliable evidence. Do not interpret this as safe. |

A completed scan can still be `INCONCLUSIVE`. A scan with a decisive threat-intelligence match can be `MALICIOUS` even when a later web-security check fails.

### 3.2 Scan state definitions

- `queued`: Accepted by the API and waiting for a worker.
- `running`: A worker has claimed the scan and is collecting evidence.
- `succeeded`: All required check groups reached a usable result.
- `partial`: Some checks completed but at least one required check could not complete; verdict is usually `INCONCLUSIVE` unless a decisive malicious match already exists.
- `failed`: The scanner could not produce a reliable report, for example because of an internal processing error. `verdict` is `INCONCLUSIVE` and `risk_score` is `null`.

### 3.3 Finding categories

- `threat_intel`: External feed or TrustLens curated-indicator match.
- `web_security`: HTTP response, headers, cookie flags, redirect, or TLS protocol observations.
- `certificate`: X.509 certificate and hostname-validation observations.
- `community`: Moderator-confirmed community intelligence associated with the target.

Finding severity is one of `info`, `low`, `medium`, `high`, or `critical`.

## 4. MVP scope

### 4.1 In scope

**Account and access**

- Email/password registration and login.
- Password hashing with Argon2id.
- Opaque, random, server-side sessions in secure HttpOnly cookies.
- CSRF token required on state-changing cookie-authenticated requests.
- Roles: `user`, `moderator`, `admin`.
- User can view and manage only their own scans and own report submissions; public community pages expose only moderator-confirmed reports.

**URL submission and scan orchestration**

- Accept one public HTTP or HTTPS URL per scan.
- Normalize scheme, hostname, IDNA representation, default port, path, and fragment handling.
- Reject malformed URLs, embedded credentials, non-HTTP schemes, IP-literal hosts, private/reserved destinations, unsupported ports, and URLs longer than 2,048 characters.
- Enqueue scans asynchronously and return a `scan_id` immediately.
- Display scan progress by polling the scan resource.
- Persist an immutable scan result with timestamps and `scoring_version`.

**Threat analysis**

- Exact URL checks against the current OpenPhish community feed, subject to its community-feed terms and attribution requirements.
- Exact URL lookup against URLhaus for malware-distribution indicators, using an Auth-Key; only an `online` result is decisive, while `offline` or `unknown` results are historical warnings.
- Match against TrustLens moderator-confirmed community indicators.
- Store source, match state, timestamps, and limited provider evidence.
- Show provider unavailability and feed freshness.
- Cache feed data and provider results with explicit freshness timestamps.

**Passive web security assessment**

- Resolve A and AAAA records and reject a target if any resolved address is non-public or prohibited.
- Perform bounded HTTP GET requests with automatic redirect following disabled.
- Manually validate every redirect destination before following it; maximum five redirect hops.
- Record status code, final URL, redirect chain, and selected response headers.
- Inspect HSTS, Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and frame-protection policy.
- Inspect `Set-Cookie` attributes for `Secure`, `HttpOnly`, and `SameSite`.
- Record whether an HTTP URL redirects to HTTPS.
- Inspect negotiated TLS version and cipher where HTTPS is available.
- Limit response body reads to 128 KiB; do not execute JavaScript, parse active content, download files, or inspect subresources.

**Certificate validation**

- Connect to TCP port 443 only after DNS/IP validation.
- Verify the TLS chain using the worker's configured system trust store.
- Enforce hostname verification with SNI set to the original hostname.
- Record leaf certificate subject, issuer, serial number, SHA-256 fingerprint, SAN DNS entries, validity window, public-key algorithm and size, signature algorithm, and validation outcome.
- Detect the presence of an embedded Signed Certificate Timestamp (SCT) extension when the parser supports it.
- Label revocation status `not_checked` in the MVP; do not imply that revocation was checked.
- Label SCT presence as evidence only; do not imply that a full Certificate Transparency inclusion proof was verified.

**Collaborative threat intelligence**

- Submit a report for a URL with a category, claimed verdict, and evidence text.
- View published moderator-confirmed reports and their public summaries.
- View the status of the current user's own reports.
- Vote once per report as `confirm` or `false_positive`.
- Moderator review: confirm, reject, or mark duplicate with a reason.
- Prevent a single user's report or votes from automatically making a site `MALICIOUS`.

**Dashboard and reporting**

- Dashboard summary of the current user's scan counts, verdict distribution, recent scans, and unresolved reports.
- Scan detail page with verdict, risk score, layer coverage, findings, redirects, certificate details, provider checks, and scan timestamps.
- Copyable canonical URL and report permalink within the authenticated application.
- Responsive layout and accessible loading, empty, error, and success states.

**Operations and observability**

- Liveness and readiness endpoints.
- Structured application logs with request IDs and sensitive-data redaction.
- Metrics for API latency, queue depth, scan duration, scan outcomes, provider freshness, and worker errors.
- Database migrations and repeatable local Docker Compose environment.

### 4.2 Out of scope for MVP

- Browser extension, mobile application, desktop client, or email/SMS link interception.
- Active vulnerability scanning, fuzzing, exploitation, brute force, authentication bypass, or crawling.
- Downloading, opening, emulating, or executing malware or other files.
- Form submission, credential testing, account creation, payment interaction, or login attempts on target sites.
- Browser JavaScript execution, third-party subresource crawling, DOM-based phishing detection, screenshot-based brand matching, or visual similarity models.
- Automatic domain-owner verification or a guarantee that a site belongs to a claimed brand.
- Full OCSP/CRL revocation verification or end-to-end Certificate Transparency log inclusion-proof verification.
- Deep TLS cipher-suite enumeration or denial-of-service/load testing.
- Arbitrary port scanning; the scanner uses standard HTTP/HTTPS ports only.
- User-configurable scan profiles, scheduled rescans, bulk CSV uploads, and API keys for external customers.
- Public raw feed dumps, public exposure of provider credentials, or public listing of unmoderated reports.
- Automated machine-learning verdict generation. The MVP uses deterministic, versioned rules; AI may later explain findings but must not override rules.
- Enterprise SSO, organisation workspaces, billing, subscriptions, multi-region failover, and contractual SLA reporting.
- Public webhook subscriptions and customer-configurable outbound callbacks.

## 5. Functional requirements

### FR-01 — Registration

- Accept `email`, `password`, and `display_name`.
- Normalize email by trimming whitespace and lowercasing the domain and local part for account uniqueness.
- Require a valid email address and a password of 12–128 characters.
- Reject passwords appearing in the application's configured common-password blocklist.
- Hash passwords with Argon2id; never store or log raw passwords.
- Create a user with role `user` and status `active`.
- Create a session and return `csrf_token`; set the session cookie.

### FR-02 — Login and logout

- Login validates credentials and account status.
- Failed login returns a generic message that does not reveal whether an email exists.
- Session tokens contain at least 256 bits of cryptographic randomness; only SHA-256 hashes are persisted.
- Rotate the session token on login and privilege changes.
- Session absolute lifetime is 7 days; idle lifetime is 24 hours.
- Logout revokes the current session and expires the cookie.

### FR-03 — URL validation and normalization

- Only `http` and `https` schemes are supported.
- Maximum raw URL size is 2,048 UTF-8 bytes.
- Reject username/password URL user-info, IP literal hosts, fragments as network inputs, unsupported schemes, empty hostnames, invalid IDNA labels, ports other than 80 and 443, and prohibited destination IPs.
- Remove fragments from canonical URL identity; preserve query parameters and path because they can distinguish phishing URLs.
- Normalize default ports away and normalize hostname to lower-case IDNA ASCII.
- Do not reorder or drop query parameters.
- Do not decode percent-encoded path delimiters before making network requests.
- Store the original input separately from the canonical URL.

### FR-04 — Scan creation

- Require authentication.
- Enforce per-user rate limit: 10 new scans per 10 minutes and 100 per day; return `429` when exceeded.
- Deduplicate only active identical scans for the same user if created within the previous 60 seconds; return the existing scan ID and `deduplicated: true`.
- Persist `queued` state before enqueueing a Celery task. If enqueue fails, mark the scan `failed` and return a server error.
- Return `202 Accepted` with `scan_id`, `status`, and `created_at`.

### FR-05 — Scan processing

A worker runs these stages in order, recording stage outcomes:

1. Canonical URL and hostname verification.
2. DNS resolution and destination-IP policy validation.
3. Threat-intelligence exact URL checks and local indicator lookup.
4. Bounded HTTP request and manual redirect evaluation.
5. HTTPS certificate and negotiated TLS inspection when applicable.
6. Security-header and cookie evaluation.
7. Community-confirmed indicator lookup.
8. Deterministic scoring and verdict computation.
9. Persist findings, provider checks, certificate evidence, redirect hops, and terminal scan state.

A worker must be idempotent: reprocessing the same scan cannot create duplicate findings or redirect rows. Use deterministic finding codes and unique constraints or delete-and-replace within one transaction.

### FR-06 — Threat-intelligence matching

- OpenPhish is the phishing URL feed; URLhaus is the malware-distribution URL source. They are separate providers and must be labelled separately in UI and API.
- Match canonicalized exact URLs; do not automatically mark every URL on a matching shared host as malicious.
- Match local indicators using type-specific normalized values.
- Store provider status as `match`, `no_match`, `unavailable`, or `not_configured`.
- Store each check's timestamp and provider error code, without storing secrets or full HTTP debug dumps.
- A stale or unavailable provider cannot count as a clean no-match.

### FR-07 — Passive HTTP inspection

- Use a dedicated scanner worker network identity and egress policy.
- Never send cookies, authorization headers, user-specific headers, or browser credentials to a target.
- Use a fixed TrustLens User-Agent string and an `Accept` header for basic HTML/text responses.
- Do not honour environment proxy variables for target fetches.
- Disable automatic redirects and inspect each `Location` header manually.
- Re-parse, resolve, and validate each redirect target before connecting.
- Maximum five redirects, 10 seconds total network timeout, 3 seconds connect timeout, and 128 KiB maximum response body read.
- No POST, PUT, PATCH, DELETE, WebSocket, FTP, file, gopher, or custom protocol access.
- Close connections when body cap, timeout, or policy limit is reached.

### FR-08 — Certificate checks

- Perform standard TLS certificate verification using the original hostname and SNI.
- The connection must be pinned to a previously validated public IP for the connection lifetime.
- Record `chain_valid` and `hostname_match` based on the actual verified TLS handshake.
- Record `not_before` and `not_after` in UTC.
- Calculate expiry state: `valid`, `expires_soon` (within 30 days), `expired`, or `not_yet_valid`.
- Capture certificate details even when certificate validation fails, when the peer provided a parseable leaf certificate.
- A certificate failure is a risk finding, not by itself proof of phishing.

### FR-09 — Deterministic score

`risk_score` is an integer from 0 to 100. The algorithm is versioned as `trustlens-1.0`.

**Decisive rules, applied before additive scoring:**

- Exact canonical URL match in the current OpenPhish community feed, or an exact URLhaus match with `url_status="online"`: verdict `MALICIOUS`, score 100.
- At least two moderator-confirmed reports from distinct reporter accounts for the same canonical URL: verdict `MALICIOUS`, score at least 90.

**Otherwise, additive findings:**

| Finding code | Points | Maximum contribution |
|---|---:|---:|
| `CERT_CHAIN_INVALID` | 25 | 25 |
| `CERT_HOSTNAME_MISMATCH` | 25 | 25 |
| `CERT_EXPIRED` | 20 | 20 |
| `TLS_LEGACY_PROTOCOL` | 10 | 10 |
| `HSTS_MISSING` | 5 | 5 |
| `CSP_MISSING` | 4 | 4 |
| `X_CONTENT_TYPE_OPTIONS_MISSING` | 2 | 2 |
| `REFERRER_POLICY_MISSING` | 1 | 1 |
| `PERMISSIONS_POLICY_MISSING` | 1 | 1 |
| `COOKIE_SECURE_MISSING` | 3 per affected cookie | 6 total |
| `COOKIE_HTTPONLY_MISSING` | 2 per affected cookie | 4 total |
| `COOKIE_SAMESITE_MISSING` | 2 per affected cookie | 4 total |
| `HTTP_NO_HTTPS_REDIRECT` | 5 | 5 |
| `URLHAUS_HISTORICAL_URL_MATCH` | 25 | 25 |

Rules:

- Sum contributions and cap at 100.
- Duplicate instances of the same header finding count once.
- Cookie point contributions are capped as shown.
- A URLhaus exact match with `url_status` equal to `offline` or `unknown` creates `URLHAUS_HISTORICAL_URL_MATCH` (25 points) and cannot by itself trigger `MALICIOUS`; it remains a warning that the URL was previously recorded as malware distribution.
- Missing headers never trigger `MALICIOUS` by themselves.
- A single community report or vote does not add score.
- `risk_score` is `null` for internal `failed` scans without a reliable assessment.

**Verdict mapping when no decisive malicious rule applies:**

- Score 25–74: `SUSPICIOUS`.
- Score 0–24 with a completed HTTP check, completed local/community indicator lookup, and fresh successful phishing and malware feed coverage: `SAFE`.
- Score 0–24 without all required coverage: `INCONCLUSIVE`.
- Score 75–100 without a decisive malicious rule: `SUSPICIOUS` (high score alone cannot prove malicious intent).

A system test must assert that unavailable providers never produce `SAFE`.

### FR-10 — Community reports

- Require an authenticated active user.
- Accept canonical URL, category, claimed verdict, and evidence text.
- Evidence text is 20–2,000 characters; HTML is escaped and rendered as plain text.
- Duplicate pending/confirmed reports for the same canonical URL and reporter within 30 days return the existing report with `duplicate_submission: true`.
- New reports begin in `pending` status.
- Only moderators/admins can set `confirmed`, `rejected`, or `duplicate`.
- Moderation must include a reason of 10–1,000 characters.
- Confirmed reports become visible in the public community listing; rejected and pending reports do not.

### FR-11 — Community votes

- Require an authenticated user.
- One vote per user per report; a repeated vote updates the existing vote.
- A user cannot vote on their own report.
- Votes are visible to moderators and aggregated publicly only for confirmed reports.
- Votes inform review but do not directly change scan verdicts or report moderation state.

### FR-12 — Dashboard and scan detail

- Dashboard data is scoped to the authenticated user.
- Recent scans default to the latest 10, ordered by `created_at DESC`.
- Scan detail shows all findings sorted by severity descending, then category, then creation time.
- Do not expose another user's scan by guessing a UUID; return `404` for non-owned resources.
- Public confirmed community reports are shown separately from the user's private scan history.

### FR-13 — Moderation

- Only `moderator` and `admin` can moderate.
- Every moderation action creates an `audit_events` record with actor, action, target report, reason, and timestamp.
- Moderation must be transactional: report status update and audit event either both commit or both roll back.

## 6. Core user journeys — Given / When / Then

### Journey A — Register and sign in

```gherkin
Feature: Account access
  Scenario: A new user creates an account
    Given an anonymous visitor is on the registration page
    And the email address is not already registered
    When the visitor submits a valid email, a password of at least 12 characters, and a display name
    Then TrustLens creates an active user with role "user"
    And TrustLens stores only an Argon2id password hash
    And TrustLens creates a server-side session
    And the browser receives a secure HttpOnly session cookie
    And the response contains a CSRF token
    And the visitor is redirected to the dashboard

  Scenario: Registration rejects an existing email
    Given an account already exists for "alex@example.com"
    When a visitor submits a registration request using "alex@example.com"
    Then TrustLens returns HTTP 400 with code "EMAIL_ALREADY_REGISTERED"
    And no second user is created

  Scenario: A user logs out
    Given an authenticated user has an active session
    When the user selects Log out
    Then the current session is revoked
    And the session cookie is expired
    And subsequent authenticated requests return HTTP 401
```

### Journey B — Scan a public website

```gherkin
Feature: Public website assessment
  Scenario: A valid URL is queued for scanning
    Given an authenticated user is on the scan page
    When the user submits "https://www.example.org/security"
    Then TrustLens validates and canonicalizes the URL
    And TrustLens creates a scan in state "queued"
    And TrustLens returns HTTP 202 with a scan ID
    And the scan appears at the top of the user's scan history

  Scenario: A scan reaches a completed result
    Given a scan is in state "queued"
    When a worker claims the scan and completes the configured checks
    Then the scan transitions through "running" to "succeeded" or "partial"
    And TrustLens persists provider checks, redirect hops, certificate evidence, and findings
    And TrustLens calculates a versioned risk score and verdict
    And the scan detail page displays the verdict and its evidence

  Scenario: A scan is inconclusive because a threat provider is unavailable
    Given the target website responds successfully
    And the phishing feed is stale or unavailable
    When the scan's other checks complete without findings
    Then the scan verdict is "INCONCLUSIVE"
    And the provider section shows the unavailable or stale provider
    And TrustLens does not label the website "SAFE"

  Scenario: The URL points to a private network destination
    Given an authenticated user is on the scan page
    When the user submits a URL whose hostname resolves to 127.0.0.1 or another prohibited address
    Then TrustLens rejects the request before any target connection is made
    And the API returns HTTP 400 with code "TARGET_NOT_PUBLIC"
    And no scan worker task is enqueued
```

### Journey C — Review an assessment

```gherkin
Feature: Scan report inspection
  Scenario: A user reviews a suspicious report
    Given a scan owned by the user has status "succeeded"
    And its verdict is "SUSPICIOUS"
    When the user opens the scan detail page
    Then TrustLens displays the score, verdict, and scan time
    And findings are grouped by Threat Intelligence, Web Security, Certificate, and Community
    And each finding includes severity, explanation, evidence, and remediation guidance
    And the redirect chain and provider coverage are visible

  Scenario: A user cannot read another user's scan
    Given a scan belongs to a different user
    When the current user requests that scan by ID
    Then TrustLens returns HTTP 404
    And no scan metadata is disclosed
```

### Journey D — Submit a community report

```gherkin
Feature: Community threat reporting
  Scenario: A user submits a new suspicious URL report
    Given an authenticated active user is on the community report form
    When the user submits a valid URL, category, claimed verdict, and evidence text
    Then TrustLens canonicalizes the URL
    And TrustLens creates a report with status "pending"
    And the report is visible in the reporter's private report history
    And the report is not visible in the public confirmed-report listing

  Scenario: A duplicate report is submitted
    Given the user has already submitted a pending report for the same canonical URL in the last 30 days
    When the user submits the same URL again
    Then TrustLens returns the existing report ID
    And the response sets "duplicate_submission" to true
    And no duplicate report row is created
```

### Journey E — Vote and moderate community intelligence

```gherkin
Feature: Community moderation
  Scenario: A user confirms a published report
    Given a community report has status "confirmed"
    And the current user did not create that report
    When the user submits a vote of "confirm"
    Then TrustLens creates or updates that user's vote
    And the report's confirmation count is updated
    And the vote alone does not change the report status or a scan verdict

  Scenario: A moderator confirms a pending report
    Given a moderator is authenticated
    And a report has status "pending"
    When the moderator confirms it with a reason of at least 10 characters
    Then the report status becomes "confirmed"
    And the moderator ID and reason are recorded in an audit event
    And the report becomes visible in the public community listing

  Scenario: A regular user attempts moderation
    Given a user with role "user" is authenticated
    When the user calls the moderation endpoint
    Then TrustLens returns HTTP 403
    And the report status remains unchanged
```

### Journey F — View the dashboard

```gherkin
Feature: User dashboard
  Scenario: A user views their security activity
    Given an authenticated user has completed scans and community reports
    When the user opens the dashboard
    Then TrustLens displays only that user's scan counts and verdict distribution
    And TrustLens displays the 10 most recent scans
    And TrustLens displays the user's pending community report count
    And no other user's private activity is returned

  Scenario: A new user has no activity
    Given an authenticated user has no scans and no reports
    When the user opens the dashboard
    Then TrustLens displays zero-valued summary metrics
    And the recent scans panel displays a helpful empty state
    And the scan action remains available
```

## 7. Non-functional requirements

### 7.1 Performance and capacity

| Area | Requirement |
|---|---|
| API read latency | p95 under 300 ms for dashboard, scan detail, and community reads at 100 concurrent active users |
| Scan enqueue | p95 under 500 ms, with no target HTTP fetch in the API request process |
| Scan network budget | 10 seconds total; 3 seconds per connection attempt; maximum 5 redirects |
| HTTP response body | Read no more than 128 KiB per target response |
| Certificate handshake | One standard TLS handshake to port 443; 5-second handshake timeout included in total scan budget |
| Feed synchronization | OpenPhish community feed at most once per 12 hours; URLhaus checks per submitted URL, subject to provider rate limits and fair-use rules |
| Pagination | Default 20, maximum 100 records per page |
| Database | All user-scoped queries use indexed owner columns and bounded pagination |
| Queue | Separate `scans`, `feeds`, and `maintenance` queues so feed sync cannot starve interactive scans |

### 7.2 Security requirements

- Target application security baseline: OWASP ASVS 5.0.0, prioritizing applicable Level 2 controls.
- Password storage: Argon2id with parameters meeting current OWASP Password Storage guidance; parameters are configurable and load-tested.
- Session cookie: `__Host-trustlens_session; Secure; HttpOnly; SameSite=Lax; Path=/`; no `Domain` attribute.
- Session secrets: cryptographically random, at least 32 bytes; store only a SHA-256 token hash.
- CSRF: per-session random token, required in `X-CSRF-Token` for state-changing cookie-authenticated requests; verify `Origin` against exact configured frontend origins.
- TLS: TLS 1.2 minimum for TrustLens itself; prefer TLS 1.3. Target website TLS is measured, not controlled by TrustLens.
- Transport security: HSTS for TrustLens production hostname with an approved max-age; no unsafe mixed content in the application.
- Input validation: Pydantic schemas, strict URL allowlist, output escaping, parameterized SQL, and server-side authorization for every resource.
- SSRF protection: validate all A/AAAA answers, reject any non-global or special-purpose IP, pin validated addresses at connection time, revalidate each redirect, disable environment proxies, and enforce egress firewall rules that block private, loopback, link-local, metadata, and internal networks.
- Network isolation: scanner workers run in a separate container/task role with no route to database administration networks, cloud metadata endpoints, or internal service subnets other than explicitly required dependencies.
- Abuse controls: per-user and per-IP rate limits, URL length limits, worker concurrency limits, request timeouts, response caps, and account suspension support.
- Secrets: provider keys and database credentials are injected through a secrets manager; never put them in source code, image layers, or client bundles.
- Logging: redact passwords, session tokens, CSRF tokens, provider keys, full query strings containing possible tokens, and raw form evidence where unnecessary.
- Data retention: scans and community reports retained for 12 months in the MVP; account deletion anonymizes reporter identity on community records and deletes private sessions/scans within 30 days, subject to an immutable minimal moderation audit policy.
- Dependency security: lockfiles, automated dependency updates, vulnerability scanning, signed production images, and container base-image updates.

### 7.3 Privacy and data handling

- A submitted URL may contain personal, confidential, or one-time token data. The UI must warn users not to submit private links, password-reset URLs, authenticated URLs, or URLs containing secrets.
- Do not send a full URL to an external lookup API if the query contains a detected secret/token pattern or the user sets `treat_as_sensitive=true` at scan creation. Persist this choice as `scans.is_sensitive`. The worker may still compare the URL against the already-ingested local OpenPhish feed and TrustLens community indicators because those checks do not transmit the URL. Skip the URLhaus per-URL request and record its provider status as `skipped_sensitive_url`; the missing malware-provider coverage prevents a `SAFE` verdict.
- OpenPhish and URLhaus requests must follow their provider terms. Provider credentials are never returned to the browser.
- Public community pages expose only canonical URL, category, claimed verdict, moderator decision, sanitized evidence summary, report timestamp, and aggregate vote counts. They do not expose reporter email, IP address, session information, or private notes.

### 7.4 Accessibility and usability

- Meet WCAG 2.2 AA for core flows.
- All actions are keyboard accessible and have visible focus styles.
- Status is communicated by text and icon as well as color.
- Use plain-language descriptions for certificate and header findings.
- Loading states announce progress to assistive technology without excessive repeated announcements.
- Mobile layout supports 360 px viewport width without horizontal page scrolling.

### 7.5 Reliability and observability

- API and worker processes are stateless; durable state lives in PostgreSQL.
- Celery tasks use explicit retry policies and idempotency keys.
- Retry transient provider failures at most twice with exponential backoff and jitter; do not retry policy rejections or invalid URLs.
- A periodic maintenance task marks scans stuck in `queued` or `running` for more than 5 minutes as `failed` with `WORKER_TIMEOUT`, unless a worker heartbeat proves active progress.
- Database backups are daily with point-in-time recovery enabled in production.
- Metrics and logs include `request_id`, `scan_id`, and task ID but never secrets.

## 8. Acceptance criteria

The MVP is accepted only when all statements below are demonstrably true:

1. A new user can register, log in, log out, and access only their own private scans.
2. A valid public HTTP or HTTPS URL is queued asynchronously and produces an explainable report.
3. Private, loopback, link-local, metadata, reserved, and DNS-rebinding targets are blocked before target connection.
4. Each redirect is independently parsed, resolved, and validated; more than five redirects stop the scan.
5. No target request uses credentials, cookies, POST, file download, or JavaScript execution.
6. OpenPhish, URLhaus, local community indicators, and provider failures are represented distinctly.
7. A provider outage or stale required feed cannot produce `SAFE`.
8. Certificate hostname and chain validation use the original hostname and trusted roots; the UI does not equate HTTPS with legitimacy.
9. Each finding has a stable code, category, severity, points, evidence, and remediation text.
10. The scoring algorithm is deterministic for identical inputs and records `trustlens-1.0`.
11. A user can submit a pending report and vote once on another user's report.
12. A single unmoderated report or vote cannot create a `MALICIOUS` verdict.
13. Only moderators/admins can change report moderation state, and every change is audited.
14. The dashboard and list APIs are paginated and user-scoped.
15. Core pages provide loading, error, empty, and success states and pass automated accessibility checks.
16. Unit, integration, API, worker, SSRF, and end-to-end test suites pass in CI.

## 9. Key risks and mitigations

| Risk | Mitigation |
|---|---|
| SSRF or DNS rebinding | Connection-time DNS pinning, redirect revalidation, no ambient proxies, egress firewall, adversarial tests |
| False-positive malicious classification | Exact indicator matching, source attribution, no host-wide URLhaus promotion, moderator review, deterministic rules |
| False confidence from a clean scan | Fresh-provider requirement for `SAFE`, visible coverage, `INCONCLUSIVE` state, clear non-guarantee language |
| Third-party feed licensing or availability | Provider adapters, terms tracking, feed freshness, graceful degradation, no implicit redistribution |
| Abuse through high-volume scanning | Rate limits, queue quotas, per-target cooldowns, WAF, worker concurrency and body/time caps |
| Malicious community submissions | Pending state, evidence requirements, one vote per user, moderator workflow, audit trail |
| Certificate limitations | Clearly label revocation and CT proof as not checked in MVP; never equate certificate validity with brand legitimacy |
| Sensitive URLs disclosed to providers | Secret-pattern detection, user warning, provider skip policy, query-string redaction |

## 10. External standards and provider documentation

- OWASP Application Security Verification Standard 5.0.0: <https://asvs.owasp.org/>.
- OWASP Server-Side Request Forgery Prevention Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>.
- URLhaus Community API: <https://urlhaus.abuse.ch/api/>.
- OpenPhish feed and terms: <https://www.openphish.com/phishing_feeds.html>.
- RFC 9162, Certificate Transparency Version 2.0: <https://www.rfc-editor.org/rfc/rfc9162.html>.
- Google Safe Browsing documentation notes that the Safe Browsing APIs are for non-commercial use; commercial URL detection should use Web Risk: <https://developers.google.com/safe-browsing/reference/rest>.
