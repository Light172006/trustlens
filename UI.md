# TrustLens — UI and Interaction Specification

**Document version:** 1.0  
**Product:** TrustLens  
**Frontend:** React 19, TypeScript strict mode, Vite, Tailwind CSS 4, Radix UI  
**Primary experience:** Responsive web dashboard for explainable website-risk reports  

## 1. UX direction

TrustLens should feel like a calm, credible security console rather than a frightening antivirus pop-up. It must present a clear verdict quickly while making the underlying evidence inspectable. Do not use fear-driven copy, unexplained numerical scores, or a green padlock as proof of legitimacy.

The primary hierarchy on a report page is:

1. Verdict and plain-language recommendation.
2. Target hostname and scan time.
3. Risk score and evidence coverage.
4. Four analysis layers: Threat Intelligence, Web Security, Certificate, Community.
5. Individual findings with observed evidence and remediation.
6. Redirect chain and provider status.

`SAFE` always includes a disclaimer that the checks are bounded and cannot guarantee future safety. `INCONCLUSIVE` must be visually distinct from `SAFE` and must never use a green success treatment.

## 2. Design tokens

### 2.1 Color palette

All values are exact CSS hex tokens. Use semantic tokens in components; do not hard-code hex values inside JSX.

**Brand and structure**

| Token | Hex | Usage |
|---|---|---|
| `--color-primary-950` | `#10223D` | Deep brand/nav background |
| `--color-primary-900` | `#17345A` | Dark primary surfaces |
| `--color-primary-700` | `#1D4ED8` | Primary action hover / active |
| `--color-primary-600` | `#2563EB` | Primary actions and links |
| `--color-primary-500` | `#3B82F6` | Focus accents and chart series |
| `--color-secondary-700` | `#0F766E` | Secondary action / teal accent |
| `--color-secondary-600` | `#0D9488` | Secondary action hover |
| `--color-accent-600` | `#6D28D9` | Intelligence / community accent |
| `--color-accent-500` | `#8B5CF6` | Secondary data visualization |

**Light theme surfaces and text**

| Token | Hex | Usage |
|---|---|---|
| `--color-bg` | `#F5F7FB` | Application background |
| `--color-surface` | `#FFFFFF` | Cards, panels, forms |
| `--color-surface-muted` | `#EEF2F7` | Secondary panels, selected row |
| `--color-surface-raised` | `#FFFFFF` | Modals and elevated cards |
| `--color-border` | `#D9E1EC` | Dividers and card borders |
| `--color-border-strong` | `#B8C5D6` | Input border and active outline |
| `--color-text` | `#142033` | Primary text |
| `--color-text-secondary` | `#4B5B72` | Body secondary text |
| `--color-text-muted` | `#68778D` | Helper text and metadata |
| `--color-text-inverse` | `#FFFFFF` | Text on dark brand surfaces |

**Dark theme surfaces and text**

| Token | Hex | Usage |
|---|---|---|
| `--color-dark-bg` | `#0B1220` | Application background |
| `--color-dark-surface` | `#111C2E` | Cards and panels |
| `--color-dark-surface-muted` | `#17263D` | Nested surfaces and table hover |
| `--color-dark-surface-raised` | `#1B2B43` | Modal and dropdown surface |
| `--color-dark-border` | `#2B3B53` | Dividers and borders |
| `--color-dark-border-strong` | `#40536D` | Input borders |
| `--color-dark-text` | `#E8EEF7` | Primary text |
| `--color-dark-text-secondary` | `#B6C3D5` | Secondary text |
| `--color-dark-text-muted` | `#8C9BB0` | Metadata |

**Semantic status colors**

| Semantic token | Light hex | Dark hex | Use |
|---|---|---|---|
| `--color-safe` | `#15803D` | `#4ADE80` | `SAFE` verdict only |
| `--color-safe-bg` | `#DCFCE7` | `#123522` | Safe status surface |
| `--color-suspicious` | `#B45309` | `#FBBF24` | `SUSPICIOUS` verdict |
| `--color-suspicious-bg` | `#FEF3C7` | `#3A2A0C` | Suspicious surface |
| `--color-malicious` | `#B91C1C` | `#F87171` | `MALICIOUS` verdict |
| `--color-malicious-bg` | `#FEE2E2` | `#451A1A` | Malicious surface |
| `--color-inconclusive` | `#475569` | `#CBD5E1` | `INCONCLUSIVE` verdict |
| `--color-inconclusive-bg` | `#E2E8F0` | `#263448` | Inconclusive surface |
| `--color-info` | `#0369A1` | `#38BDF8` | Informational notices |
| `--color-info-bg` | `#E0F2FE` | `#102F45` | Informational surface |
| `--color-success` | `#15803D` | `#4ADE80` | Non-verdict successful action |
| `--color-warning` | `#B45309` | `#FBBF24` | Operational warning |
| `--color-danger` | `#B91C1C` | `#F87171` | Destructive action/error |

Status must always include text (for example `SUSPICIOUS`) and an icon or textual label. Color is never the only status indicator.

### 2.2 Typography

Use **Inter** as the primary UI font, loaded from a self-hosted WOFF2 asset or a system fallback. Use `ui-monospace`, `SFMono-Regular`, `Consolas`, or `JetBrains Mono` for URLs, fingerprints, IDs, and technical evidence.

| Style token | Size | Line height | Weight | Typical use |
|---|---:|---:|---:|---|
| `display` | 32 px / 2rem | 40 px | 700 | Dashboard title on desktop only |
| `h1` | 28 px / 1.75rem | 36 px | 700 | Page title |
| `h2` | 22 px / 1.375rem | 30 px | 650 | Major panel title |
| `h3` | 18 px / 1.125rem | 26 px | 600 | Card title / finding title |
| `body-lg` | 16 px / 1rem | 24 px | 400 | Main reading text |
| `body` | 14 px / 0.875rem | 22 px | 400 | Default controls and content |
| `body-sm` | 13 px / 0.8125rem | 20 px | 400 | Secondary descriptions |
| `label` | 12 px / 0.75rem | 16 px | 600 | Form labels and table headers |
| `caption` | 11 px / 0.6875rem | 16 px | 500 | Timestamps, compact metadata |
| `mono` | 12 px / 0.75rem | 18 px | 500 | URL fragments, hashes, certificate fingerprints |

Use sentence case for headings and buttons. Avoid all-caps prose. Verdict labels may be uppercase for consistent machine-recognizable presentation.

### 2.3 Spacing, dimensions, and radii

- Base spacing unit: 4 px.
- Standard spacing scale: 4, 8, 12, 16, 20, 24, 32, 40, 48, 64 px.
- Page max width: 1,440 px; centered with 24 px desktop gutters and 16 px mobile gutters.
- Sidebar width: 256 px expanded, 72 px collapsed.
- Top bar height: 64 px desktop, 56 px mobile.
- Standard card padding: 20 px desktop, 16 px mobile.
- Input height: 44 px; compact control height: 36 px; primary button height: 44 px.
- Border radius: 6 px for compact controls, 10 px for inputs/buttons, 14 px for cards, 18 px for major panels/modals, 999 px for pills/avatars.
- Border thickness: 1 px standard; 2 px focus/selected state.
- Shadow: subtle only on raised panels and menus. Do not use large glowing shadows or neon effects.

## 3. Application shell and route map

### 3.1 Routes

| Route | Page | Access |
|---|---|---|
| `/login` | Sign in | Anonymous |
| `/register` | Create account | Anonymous |
| `/dashboard` | User dashboard | Authenticated |
| `/scans/new` | Scan a website | Authenticated |
| `/scans` | Scan history | Authenticated |
| `/scans/:scanId` | Scan report | Owner only |
| `/community` | Confirmed community reports | Public |
| `/community/report` | Submit report | Authenticated |
| `/community/reports/mine` | My submissions | Authenticated |
| `/community/reports/:reportId` | Community report detail | Public if confirmed; owner/moderator otherwise |
| `/moderation/reports` | Pending and reviewed reports | Moderator/admin |
| `/moderation/providers` | Provider freshness and operational status | Moderator/admin |
| `/account` | Account profile and session information | Authenticated |
| `*` | Not found | Public |

### 3.2 Desktop shell

- Left navigation sidebar is fixed to the viewport below the top bar; content area scrolls independently.
- Header includes TrustLens mark, page context/breadcrumb, theme toggle, and user menu.
- Sidebar entries: Dashboard, Scan a URL, Scan history, Community. Add Moderation and Provider health only for moderator/admin roles.
- The current route has a clear selected state using primary tint and a 3 px left accent line.
- Main content is centered and uses responsive grid columns; avoid full-width text paragraphs beyond 80 characters where possible.

### 3.3 Mobile shell

- At widths below 768 px, replace the expanded sidebar with a drawer opened by a menu button.
- Top bar contains menu, compact TrustLens wordmark, and account control.
- The primary scan action remains visible on Dashboard and Community pages.
- Two-column report cards collapse to one column; tables become stacked summary rows or horizontally scrollable only inside their own container.
- No page-level horizontal overflow is allowed at 360 px width.

## 4. Component directory and contracts

The component names below are normative. Props should be TypeScript interfaces, not untyped dictionaries. Shared primitives should not know backend authorization rules; feature components receive already-authorized data from route loaders/hooks.

### 4.1 Directory mapping

```text
src/components/
├── layout/
│   ├── AppShell.tsx
│   ├── AppHeader.tsx
│   ├── AppSidebar.tsx
│   ├── MobileNavigationDrawer.tsx
│   ├── PageContainer.tsx
│   └── Breadcrumbs.tsx
├── navigation/
│   ├── NavItem.tsx
│   ├── UserMenu.tsx
│   └── ThemeToggle.tsx
├── feedback/
│   ├── Alert.tsx
│   ├── ToastProvider.tsx
│   ├── LoadingSpinner.tsx
│   ├── Skeleton.tsx
│   ├── EmptyState.tsx
│   ├── ErrorState.tsx
│   ├── InlineStatus.tsx
│   └── ConfirmDialog.tsx
├── forms/
│   ├── TextField.tsx
│   ├── PasswordField.tsx
│   ├── UrlInput.tsx
│   ├── CheckboxField.tsx
│   ├── SelectField.tsx
│   ├── TextareaField.tsx
│   └── FormActions.tsx
├── data-display/
│   ├── Card.tsx
│   ├── StatCard.tsx
│   ├── DataTable.tsx
│   ├── Pagination.tsx
│   ├── CopyButton.tsx
│   ├── CodeValue.tsx
│   └── Timestamp.tsx
├── scan/
│   ├── VerdictBadge.tsx
│   ├── VerdictBanner.tsx
│   ├── RiskScoreGauge.tsx
│   ├── ScanStatusStepper.tsx
│   ├── LayerCoverageGrid.tsx
│   ├── AnalysisLayerCard.tsx
│   ├── FindingCard.tsx
│   ├── FindingList.tsx
│   ├── RedirectChain.tsx
│   ├── ProviderStatusList.tsx
│   ├── CertificatePanel.tsx
│   ├── CertificateField.tsx
│   └── ScanSummaryCard.tsx
└── community/
    ├── CommunityReportCard.tsx
    ├── CommunityReportForm.tsx
    ├── CommunityVoteControl.tsx
    ├── ModerationDecisionDialog.tsx
    └── ReportStatusBadge.tsx
```

### 4.2 Layout components

**`AppShell`**

- **Props:** `children: ReactNode`, `user: CurrentUser | null`, `activeRoute: string`.
- **Layout:** desktop sidebar + top header + main content; mobile header + drawer.
- **States:** loading shell while session bootstrap runs; authenticated shell; anonymous shell; session-expired redirect.

**`AppHeader`**

- **Props:** `user`, `onOpenNavigation`, `onLogout`, `theme`, `onThemeChange`.
- **Layout:** single horizontal row, brand left, user controls right.
- **States:** default, menu open, logout pending, logout error.

**`AppSidebar`**

- **Props:** `activeRoute`, `role`, `collapsed`, `onNavigate`.
- **Layout:** 256 px expanded / 72 px collapsed; icon and label when expanded; tooltip on collapsed item.
- **States:** active, hover, focus, disabled, role-hidden. Do not render admin links for regular users.

**`MobileNavigationDrawer`**

- **Props:** `open`, `onOpenChange`, `activeRoute`, `role`.
- **Layout:** full-height drawer up to 320 px wide, scrim, focus trap, Escape closes.
- **States:** closed, open, navigating; focus returns to trigger when closed.

**`PageContainer`**

- **Props:** `title`, `description?`, `actions?`, `children`.
- **Layout:** max-width 1,440 px; responsive page gutters; title/actions stack on mobile.
- **States:** default and optional route-level loading.

### 4.3 Feedback and action components

**`Alert`**

- **Props:** `tone: info | success | warning | danger`, `title?`, `children`, `dismissible?`, `onDismiss?`.
- **Layout:** icon, message, optional action; tinted surface and 1 px semantic border.
- **States:** visible, dismissing, dismissed; keyboard-accessible close control.

**`ToastProvider`**

- **Props:** provider-level configuration only; `toast()` utility receives `title`, `description?`, `tone`, `duration?`.
- **Layout:** top-right desktop, bottom center mobile; max 3 visible toasts.
- **States:** queued, visible, paused on hover/focus, dismissed. Important errors must also remain inline; toast is not the only feedback.

**`LoadingSpinner`**

- **Props:** `size: sm | md | lg`, `label?`.
- **Layout:** inline or centered; `aria-live="polite"` when used for an operation.
- **States:** spinning; reduced-motion mode uses a static progress indicator.

**`Skeleton`**

- **Props:** `variant: text | card | avatar | row`, `width?`, `height?`.
- **Layout:** matches the shape of the content being loaded.
- **States:** animated shimmer, static in reduced-motion mode; never display false placeholder text as real data.

**`EmptyState`**

- **Props:** `title`, `description`, `actionLabel?`, `onAction?`, `icon`.
- **Layout:** centered within the relevant card/table region, not the entire viewport unless the page itself is empty.
- **States:** default, action pending, action error.

**`ErrorState`**

- **Props:** `title`, `description`, `requestId?`, `retryLabel?`, `onRetry?`.
- **Layout:** neutral error panel with retry action and request ID when available.
- **States:** error, retrying, retry failed. Never show raw backend exception text.

**`InlineStatus`**

- **Props:** `label`, `tone`, `icon?`.
- **Layout:** compact icon + label; text always visible.
- **States:** default and disabled.

**`ConfirmDialog`**

- **Props:** `open`, `title`, `description`, `confirmLabel`, `cancelLabel`, `danger?`, `busy?`, `onConfirm`, `onCancel`.
- **Layout:** Radix Dialog, max width 480 px, focus trap, Escape cancel unless request is in irreversible commit stage.
- **States:** closed, open, confirming, success-close, error.

### 4.4 Form components

**`TextField`**

- **Props:** `id`, `label`, `value`, `onChange`, `type?`, `hint?`, `error?`, `required?`, `autoComplete?`.
- **Layout:** label above input; helper/error text below; full width by default.
- **States:** default, hover, focus, filled, invalid, disabled, read-only.

**`PasswordField`**

- **Props:** same as TextField, with `showToggle` and `autoComplete`.
- **Layout:** trailing visibility control inside field; button has an accessible name.
- **States:** hidden, visible, invalid, disabled. Password strength feedback is explanatory and never logs the value.

**`UrlInput`**

- **Props:** `value`, `onChange`, `error?`, `disabled?`, `maxLength=2048`, `onSubmit?`.
- **Layout:** URL icon leading, large single-line input, optional Scan button on desktop; Scan button moves below on narrow screens.
- **States:** idle, typing, validating, invalid, submitting, disabled.
- **Validation:** client checks obvious scheme/length issues; server is authoritative for URL normalization and destination policy.

**`CheckboxField`**

- **Props:** `checked`, `onChange`, `label`, `description?`, `error?`.
- **Layout:** checkbox + label + optional description aligned to top.
- **States:** unchecked, checked, focus, disabled, invalid.

**Sensitive-URL acknowledgement in `UrlInput` form**

- Label: “This URL may contain a private or one-time token. Do not send it to third-party threat providers.”
- Field maps to API `treat_as_sensitive` boolean and persisted `scans.is_sensitive`.
- This setting does not disable TrustLens's own bounded HTTP/security checks; it skips the URLhaus external lookup and makes `SAFE` unavailable because provider coverage is incomplete. The URLhaus provider row must display `skipped_sensitive_url`, never `no_match`; local OpenPhish and community lookups may still run without transmitting the URL.

**`SelectField`**

- **Props:** `value`, `options`, `onChange`, `label`, `error?`, `disabled?`.
- **Layout:** 44 px control; Radix Select; option labels are human-readable.
- **States:** closed, open, selected, focused, disabled, invalid.

**`TextareaField`**

- **Props:** `value`, `onChange`, `label`, `minLength`, `maxLength`, `error?`, `hint?`.
- **Layout:** minimum 112 px height; character count below for report evidence.
- **States:** idle, focus, invalid, limit reached, disabled.

**`FormActions`**

- **Props:** `primaryLabel`, `secondaryLabel?`, `busy`, `onCancel?`, `disabled?`.
- **Layout:** right aligned desktop; full-width stacked mobile.
- **States:** enabled, disabled, submitting, success, error.

### 4.5 Data-display components

**`Card`**

- **Props:** `title?`, `description?`, `actions?`, `children`, `padding?`, `interactive?`.
- **Layout:** white/dark surface, border, 14 px radius; nested cards use muted surface rather than extra shadow.
- **States:** default, hover only when interactive, focus-visible, loading, disabled.

**`StatCard`**

- **Props:** `label`, `value`, `trend?`, `icon`, `tone?`.
- **Layout:** label above large value, icon top-right; optional trend caption.
- **States:** skeleton, populated, empty/zero, error.

**`DataTable`**

- **Props:** `columns`, `rows`, `loading`, `emptyState`, `rowKey`, `onRowClick?`.
- **Layout:** fixed header, aligned numeric columns, truncation for long URLs with accessible full value, responsive card/list mode on mobile.
- **States:** loading skeleton, populated, empty, error, row hover/focus.

**`Pagination`**

- **Props:** `page`, `pageSize`, `total`, `onPageChange`, `onPageSizeChange?`.
- **Layout:** compact controls under list; disabled previous/next at boundaries.
- **States:** normal, first page, last page, loading, disabled.

**`CopyButton`**

- **Props:** `value`, `label?`, `successLabel?`.
- **Layout:** icon-only with tooltip or visible text button; accessible label includes copied content type.
- **States:** idle, copied, copy error.

**`CodeValue`**

- **Props:** `value`, `truncateAt?`, `copyable?`, `breakAnywhere?`.
- **Layout:** monospace font, wrap hashes/fingerprints where needed; URLs truncate visually but copy full value.
- **States:** default, hover/focus, copied.

**`Timestamp`**

- **Props:** `value`, `format: relative | absolute | both`.
- **Layout:** human-readable relative time with exact UTC timestamp in tooltip/title.
- **States:** valid, missing value; do not display a fake current time.

### 4.6 Scan-specific components

**`VerdictBadge`**

- **Props:** `verdict: SAFE | SUSPICIOUS | MALICIOUS | INCONCLUSIVE`, `size: sm | md | lg`.
- **Layout:** pill with icon + uppercase verdict label; semantic color token; minimum 4.5:1 text contrast.
- **States:** four verdict styles; never render unknown verdict as `SAFE` (fallback `INCONCLUSIVE`).

**`VerdictBanner`**

- **Props:** `verdict`, `riskScore: number | null`, `targetHost`, `recommendation`, `completedAt`.
- **Layout:** full-width panel at report top; verdict and recommendation left; score right on desktop, stacked on mobile.
- **States:** verdict variants, pending scan, failed/inconclusive. For SAFE, include “No material risk was found by the checks performed; this is not a guarantee.” For MALICIOUS, lead with “Do not visit or enter information.”

**`RiskScoreGauge`**

- **Props:** `score: number | null`, `verdict`.
- **Layout:** compact horizontal scale 0–100 with textual score; no circular speedometer that suggests scientific precision.
- **States:** populated, unknown/null, animated only after data load; reduced-motion disables animation.

**`ScanStatusStepper`**

- **Props:** `status`, `createdAt`, `startedAt?`, `completedAt?`.
- **Layout:** horizontal on desktop, vertical on mobile; step labels Queued, Running, Completed/Partial/Failed.
- **States:** queued, running, succeeded, partial, failed. Terminal status stops polling.

**`LayerCoverageGrid`**

- **Props:** `coverage` object with `threat_intel`, `web_security`, `certificate`, `community` values `complete | partial | unavailable | not_applicable`.
- **Layout:** four equal desktop cards; 2x2 tablet; one column mobile.
- **States:** complete, partial, unavailable, not applicable. Unavailable must be amber/neutral, never green.

**`AnalysisLayerCard`**

- **Props:** `layer`, `status`, `summary`, `findingCount`, `children?`.
- **Layout:** layer icon/title/coverage label; collapsible evidence area.
- **States:** loading, complete with/without findings, partial, unavailable, not applicable, error.

**`FindingCard`**

- **Props:** `code`, `title`, `description`, `severity`, `points`, `evidence`, `remediation`, `source`.
- **Layout:** title/severity on first row, short explanation, evidence accordion, remediation callout. Show stable finding code in a secondary technical-details area.
- **States:** info/low/medium/high/critical, expanded/collapsed, loading skeleton, malformed evidence fallback.
- **Safety:** render evidence strings as text; never inject untrusted HTML.

**`FindingList`**

- **Props:** `findings`, `loading`, `categoryFilter?`.
- **Layout:** group by category; order severity descending then title; show count in group header.
- **States:** loading, populated, no findings, error. No findings must say “No findings were detected by this check,” not “This site is perfectly safe.”

**`RedirectChain`**

- **Props:** `redirects` array of hop index, source URL, destination URL, HTTP status, resolved host, resolved IPs, TLS verified.
- **Layout:** vertical step chain; host prominent, URL in monospace; status and TLS verification adjacent.
- **States:** no redirects, one hop, multiple hops, blocked redirect, truncated at limit, loading.

**`ProviderStatusList`**

- **Props:** `providerChecks` with provider, result status, matched, checked time, limited details.
- **Layout:** one row per provider, provider name, source type, result, last checked, source link where allowed.
- **States:** match, no match, unavailable, not configured, skipped sensitive URL, stale cache.
- **Copy:** never call `unavailable`, `not_configured`, or `stale_cache` a clean result.

**`CertificatePanel`**

- **Props:** certificate object or `available=false` reason.
- **Layout:** validation state at top; identity, issuer, validity window, key/signature algorithms, SANs, SHA-256 fingerprint below; technical values copyable.
- **States:** verified, invalid chain, hostname mismatch, expired, expires soon, no certificate, loading, error.
- **Copy:** show “Revocation status: Not checked in MVP” and explain that SCT presence is not a complete CT inclusion-proof verification. Never equate a valid certificate with organisational legitimacy.

**`CertificateField`**

- **Props:** `label`, `value`, `copyable?`, `status?`.
- **Layout:** label above value; monospace for serial/fingerprint; long SAN values wrap.
- **States:** present, missing, warning, copy success.

**`ScanSummaryCard`**

- **Props:** `scan` summary with ID, canonical URL, host, status, verdict, score, created/completed time.
- **Layout:** clickable card with hostname as title, URL as secondary line, verdict badge and timestamp.
- **States:** queued, running, completed, partial, failed; keyboard focus and selected style.

### 4.7 Community components

**`CommunityReportCard`**

- **Props:** `report` public summary, `onOpen`.
- **Layout:** hostname, category, claimed verdict, moderator-confirmed status, evidence summary, vote counts, date.
- **States:** confirmed only in public view; skeleton, populated, empty, error.

**`CommunityReportForm`**

- **Props:** `initialUrl?`, `onSubmit`, `busy`, `serverError?`.
- **Fields:** URL, category, claimed verdict, evidence text; optional link to a scan ID is set only from a scan detail action and is never editable as arbitrary ownership data.
- **Layout:** single-column form; explanatory note that submissions are pending until moderator review.
- **States:** idle, validation error, submitting, created, duplicate, server error.

**`CommunityVoteControl`**

- **Props:** `reportId`, `currentVote: confirm | false_positive | null`, counts, `disabled`, `onVote`.
- **Layout:** two adjacent controls; count next to label; responsive stacked mobile.
- **States:** not voted, confirm selected, false-positive selected, submitting, success, error, own-report disabled, report-not-votable disabled.
- **Copy:** “Votes inform review; they do not automatically change a scan verdict.”

**`ModerationDecisionDialog`**

- **Props:** `reportId`, `decision`, `open`, `onOpenChange`, `onSubmit`, `busy`.
- **Fields:** reason text, required 10–1,000 characters.
- **Layout:** destructive warning treatment for reject/duplicate only; confirm is neutral/primary; all decisions require a reason.
- **States:** idle, reason invalid, submitting, success, conflict, server error.

**`ReportStatusBadge`**

- **Props:** `status: pending | confirmed | rejected | duplicate`.
- **Layout:** compact pill; pending amber, confirmed teal/green, rejected slate/red-muted, duplicate slate.
- **States:** four status labels plus unknown fallback `pending review`.

## 5. Page-level layouts and interactions

### 5.1 Login and registration

- Centered narrow panel (max-width 440 px) on a muted page background.
- TrustLens mark and a short purpose sentence above the form.
- Inline validation; no backend error text leakage.
- Login failure uses generic message “Email or password is incorrect.”
- Registration success redirects to `/dashboard` and displays one small success notice.
- Show password toggle; do not persist credentials in browser storage.

### 5.2 Dashboard

Desktop layout:

- Page title and “Scan a website” primary button.
- Four StatCards: Total scans, Safe, Suspicious, Malicious. Inconclusive count is shown in a small secondary statistic or distribution chart, not hidden from the data.
- Verdict distribution chart with text-accessible legend and exact counts.
- Recent scan list/table with hostname, verdict, status, score, and date.
- Community submissions panel showing pending count and latest statuses.

States:

- New account: zero metrics, simple explanation, primary scan CTA, no empty chart axes.
- Loading: skeleton cards and recent rows.
- Error: inline retry panel; preserve navigation.
- Populated: real counts from `/dashboard/summary`.

### 5.3 Scan a website page

- Page title: “Check a website”.
- URL input at the top with scan button.
- Warning copy: “Only scan public URLs. Do not submit private dashboards, password-reset links, authenticated links, or URLs containing confidential information.”
- Optional sensitive URL checkbox maps to `treat_as_sensitive`.
- Small explanation of the four layers beneath the form.
- On successful submit, navigate to `/scans/:scanId`; the first report state is `queued`.
- Invalid syntax is shown inline. A destination-policy rejection is shown as a clear safety error and does not imply a network request was made.

### 5.4 Scan report page

**Top region**

- Breadcrumb: Dashboard / Scan report.
- VerdictBanner, canonical URL, CopyButton, scan time, scan ID in expandable technical details.
- ScanStatusStepper while queued/running. Poll `/scans/:scanId` every 2 seconds while status is `queued` or `running`, back off to 5 seconds after 30 seconds, stop on terminal status. Stop polling when page is hidden and resume on visibility.

**Middle region**

- RiskScoreGauge and LayerCoverageGrid.
- Four AnalysisLayerCards in the exact PRD order: Threat Intelligence, Web Security, Certificate, Community.
- `INCONCLUSIVE` page prominently displays which evidence could not be collected.

**Lower region**

- FindingList, RedirectChain, ProviderStatusList, CertificatePanel.
- “Report this website” action pre-fills the URL and optionally attaches the scan ID.

**Error/partial behaviour**

- `partial` is not displayed as a normal completed success. Show “Some checks could not complete” and list missing layers.
- `failed` shows a failure summary and a Retry scan action that creates a new scan resource; it does not mutate the failed scan.
- If certificate is not available, show the reason from `/certificate`, not a blank card.

### 5.5 Scan history

- Filters: status and verdict.
- Table/list columns: Hostname, Verdict, Status, Risk score, Created.
- Page size 20; maximum 100.
- Empty state suggests checking a public URL.
- Use server pagination and query keys containing filters/page; changing filters resets page to 1.

### 5.6 Community directory

- Intro text explaining moderator-confirmed reports only.
- Search/filter by host and category.
- Cards show hostname, category, claimed verdict, evidence summary, confirmation/false-positive counts, and moderation date.
- No pending/rejected report is visible on the public route.
- Report CTA is shown to signed-in users; anonymous users see a login link.

### 5.7 My community reports

- Private list of own submissions and states.
- Pending state says “Awaiting moderator review.”
- Rejected state displays moderation reason when present.
- Confirmed state includes a link to its public report detail.

### 5.8 Moderation queue

- Moderator-only route, enforced by API.
- Tabs or filters for Pending, Confirmed, Rejected, Duplicate.
- Detail panel shows canonical URL, category, evidence text as escaped plain text, linked scan when allowed, existing votes, and reporter ID (not email).
- Decision actions open `ModerationDecisionDialog` and require a reason.
- On HTTP 409, refresh report and show “This report was already reviewed by another moderator.”
- Moderation action success invalidates queue and report query keys.

### 5.9 Provider health page

- Moderator/admin route.
- Show provider name, source category, enabled state, last successful time, freshness, current status, and active records where available.
- Never render credentials or raw provider response payloads.
- OpenPhish feed health uses the 13-hour maximum freshness target. URLhaus is a per-scan lookup and displays most recent successful check time, not a feed-age freshness claim.

## 6. Frontend state and API integration rules

### 6.1 API state management

- Use TanStack Query for all server state.
- Query keys: `['me']`, `['dashboard-summary']`, `['scans', filters]`, `['scan', scanId]`, `['scan-findings', scanId]`, `['scan-certificate', scanId]`, `['community-reports', filters]`, `['my-community-reports', filters]`, `['community-report', reportId]`, `['admin-reports', filters]`, `['admin-providers']`.
- Invalidate only affected keys after mutations.
- All list reads use server pagination; do not download all scans/reports to filter in the browser.
- API errors are normalized from `{error:{code,message,request_id,details}}` into a typed `ApiError`.
- On 401, clear user/session query state and route to login with a return path.
- On 403, display an access denied page; do not just hide server data in the client.

### 6.2 CSRF and cookies

- API client uses `credentials: 'include'`.
- After login/register, keep `csrf_token` in an in-memory auth context.
- Attach `X-CSRF-Token` to every authenticated POST/PUT/PATCH/DELETE request.
- Do not store session or CSRF tokens in localStorage/sessionStorage.
- Logout clears in-memory state and invalidates all authenticated query caches.

### 6.3 Loading and polling

- Use skeletons when initial data is loading.
- Use a small inline spinner for mutation buttons.
- Disable the submit action while request is in flight.
- Scan polling only occurs for `queued` and `running`, with stop conditions specified on the report page.
- Do not animate the verdict gauge continuously or present a fake progress percentage; worker stage progress is not exposed as a numeric percentage in the MVP.

### 6.4 Forms and validation

- React Hook Form controls form state.
- Zod validates client-side shape and required fields.
- FastAPI/Pydantic validation is authoritative.
- Display validation messages next to the field and move focus to the first invalid control on submit.
- Trim evidence text but do not silently rewrite submitted URL query strings.
- Report evidence is displayed as escaped text, never HTML.

## 7. CSS and Tailwind implementation guidelines

### 7.1 Global structural rules

- Mobile-first: start with one-column layout and add `md`, `lg`, and `xl` grid rules.
- Use CSS Grid for dashboards and analysis layer summaries; use Flexbox for nav rows, toolbars, card headers, and form actions.
- Avoid fixed heights for content cards; use min-height only for skeleton alignment.
- Main page uses a max-width container and consistent gutters.
- No component may set global `body` styles outside `styles/index.css`.
- Do not use arbitrary inline hex colors. Use theme variables and semantic utility classes.
- Use `min-width: 0` in grid/flex children containing URLs or long hashes to prevent overflow.
- Long URLs use break-all only in technical detail views; default display truncates visually with a copy action.

### 7.2 Tailwind CSS 4 token integration

Define CSS variables in `src/styles/tokens.css` and map them with Tailwind's `@theme` feature. Components use semantic classes such as `bg-surface`, `text-primary`, `border-default`, `text-verdict-malicious`; do not reference raw palette values in feature components.

Example token structure:

```css
:root {
  color-scheme: light;
  --color-bg: #F5F7FB;
  --color-surface: #FFFFFF;
  --color-surface-muted: #EEF2F7;
  --color-border: #D9E1EC;
  --color-text: #142033;
  --color-text-secondary: #4B5B72;
  --color-primary: #2563EB;
  --color-secondary: #0F766E;
  --color-safe: #15803D;
  --color-suspicious: #B45309;
  --color-malicious: #B91C1C;
  --color-inconclusive: #475569;
  --radius-control: 10px;
  --radius-card: 14px;
  --radius-panel: 18px;
}

[data-theme="dark"] {
  color-scheme: dark;
  --color-bg: #0B1220;
  --color-surface: #111C2E;
  --color-surface-muted: #17263D;
  --color-border: #2B3B53;
  --color-text: #E8EEF7;
  --color-text-secondary: #B6C3D5;
  --color-primary: #3B82F6;
  --color-secondary: #2DD4BF;
  --color-safe: #4ADE80;
  --color-suspicious: #FBBF24;
  --color-malicious: #F87171;
  --color-inconclusive: #CBD5E1;
}
```

### 7.3 Dark mode

- Support `light`, `dark`, and `system` preference.
- Default to system preference on first visit.
- Persist the selected preference in localStorage as a non-sensitive UI preference only.
- Apply theme using `data-theme` on the root element before React paints to avoid a flash of the wrong theme.
- Ensure charts, severity indicators, borders, code panels, and focus rings are readable in both themes.
- Theme changes must not alter verdict semantics or only rely on color.

### 7.4 Responsive breakpoints

| Breakpoint | Width | Layout rule |
|---|---:|---|
| Base | 0–639 px | Single column; mobile drawer; stacked cards |
| `sm` | 640 px | Wider form and compact 2-column statistics where space permits |
| `md` | 768 px | Tablet grid; drawer remains available; 2-column analysis cards |
| `lg` | 1024 px | Expanded sidebar; 2–3 column dashboard grid |
| `xl` | 1280 px | Full report layout with side-by-side panels |

### 7.5 Accessibility rules

- WCAG 2.2 AA contrast for body text, controls, and status pills.
- Use semantic landmarks: `header`, `nav`, `main`, `aside`, `footer` where appropriate.
- Every input has a visible label; placeholder text is not a label.
- All buttons and controls have accessible names.
- Focus ring: 2 px primary token with 2 px offset; never remove default focus without replacement.
- Modals use Radix focus trapping and return focus to trigger.
- Tables have header cells and meaningful caption/accessible label.
- Charts provide a text/table equivalent with exact values.
- Respect `prefers-reduced-motion`.
- Announce scan terminal state once through a polite live region.

### 7.6 Security and rendering rules

- Never use `dangerouslySetInnerHTML` for URLs, provider data, report evidence, certificate subjects, or external responses.
- Render all provider strings and community text as plain text.
- Sanitize links; only allow `https:` and `http:` for source references and `target="_blank"` links must include `rel="noopener noreferrer"`.
- Do not display query parameters by default if secret-pattern detection marks the URL sensitive; provide a masked display and copy only after explicit user action.
- Do not embed external scripts, widgets, fonts, or images from target websites.
- Do not fetch favicons, screenshots, or previews from submitted targets.

## 8. Copy and content rules

Use the following canonical language to keep product semantics consistent:

| State | Canonical copy |
|---|---|
| `SAFE` | “No material risk was found by the checks performed. This is not a guarantee that the website is safe.” |
| `SUSPICIOUS` | “Some signals require caution. Review the findings before sharing information.” |
| `MALICIOUS` | “This URL matched a trusted threat indicator or independently confirmed community intelligence. Do not visit or enter information.” |
| `INCONCLUSIVE` | “TrustLens could not collect enough reliable evidence. Do not interpret this result as safe.” |
| Provider unavailable | “This source could not be checked. It is not a clean result.” |
| Certificate valid | “The certificate chain and hostname passed the checks. This does not prove that the site represents the organisation it claims to be.” |
| Certificate not checked | “Certificate revocation status was not checked in this version.” |
| Community pending | “Your report is awaiting moderator review and is not included as confirmed threat intelligence.” |

Avoid labels such as “100% safe”, “virus-free”, “trusted company”, or “certified legitimate”.

## 9. UI acceptance checklist

- [ ] Every route in section 3 is implemented with the specified role protection.
- [ ] Every list supports loading, empty, error, and populated states.
- [ ] Every mutation supports idle, submitting, success, validation error, and server error states.
- [ ] Scan result rendering uses the exact status, verdict, coverage, provider, and finding enums from API.md.
- [ ] `SAFE`, `SUSPICIOUS`, `MALICIOUS`, and `INCONCLUSIVE` are visually distinguishable without depending solely on color.
- [ ] `partial` and `failed` scans are not presented as a normal successful assessment.
- [ ] Provider unavailability and stale cache cannot appear as a clean provider result.
- [ ] Sensitive URL mode sends `treat_as_sensitive: true`, masks query details by default, and shows skipped provider coverage.
- [ ] Certificate panel makes revocation and CT-proof limitations explicit.
- [ ] Pending community reports are private to the reporter and moderators.
- [ ] Votes never imply automatic confirmation or direct verdict modification.
- [ ] Moderator screens require role enforcement on the API and reason text for every decision.
- [ ] All text is escaped; no untrusted HTML or target-site assets are rendered.
- [ ] 360 px mobile viewport has no page-level horizontal overflow.
- [ ] Keyboard navigation, screen reader labels, contrast, and reduced-motion behaviour pass automated and manual accessibility checks.
- [ ] Both light and dark themes cover all pages and all four verdict styles.
