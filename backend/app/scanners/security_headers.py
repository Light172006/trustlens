"""Security header and cookie audit scanner."""

from pydantic import BaseModel, Field


class CookieObservation(BaseModel):
    """Observed Set-Cookie properties."""

    name: str
    secure: bool = False
    httponly: bool = False
    samesite: str | None = None


class HeaderObservation(BaseModel):
    """Observation for an individual security header."""

    header_name: str
    present: bool
    value: str | None = None
    is_adequate: bool = False
    finding_code: str | None = None
    finding_title: str | None = None
    description: str | None = None
    remediation: str | None = None
    points: int = 0


class SecurityHeadersResult(BaseModel):
    """Normalized security header and cookie findings."""

    headers: dict[str, HeaderObservation] = Field(default_factory=dict)
    cookies: list[CookieObservation] = Field(default_factory=list)
    raw_headers: dict[str, str] = Field(default_factory=dict)
    points_total: int = 0


class SecurityHeaderScanner:
    """Evaluates security headers and Set-Cookie flags from HTTP response."""

    def analyze(
        self,
        headers: dict[str, str],
        cookies: list[CookieObservation] | None = None,
        is_https: bool = True,
    ) -> SecurityHeadersResult:
        """Inspect HTTP response headers and extract findings."""
        norm_headers = {k.lower(): v for k, v in headers.items()}
        result = SecurityHeadersResult(raw_headers=norm_headers, cookies=cookies or [])
        total_points = 0

        # 1. Strict-Transport-Security (HSTS)
        hsts_val = norm_headers.get("strict-transport-security")
        if is_https:
            if not hsts_val:
                result.headers["strict-transport-security"] = HeaderObservation(
                    header_name="Strict-Transport-Security",
                    present=False,
                    finding_code="HSTS_MISSING",
                    finding_title="HTTP Strict Transport Security is not configured",
                    description="The HTTPS response did not include an HSTS header, allowing potential protocol downgrade attacks.",
                    remediation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains to enforce HTTPS.",
                    points=5,
                )
                total_points += 5
            else:
                result.headers["strict-transport-security"] = HeaderObservation(
                    header_name="Strict-Transport-Security",
                    present=True,
                    value=hsts_val,
                    is_adequate=True,
                )

        # 2. Content-Security-Policy (CSP)
        csp_val = norm_headers.get("content-security-policy")
        if not csp_val:
            result.headers["content-security-policy"] = HeaderObservation(
                header_name="Content-Security-Policy",
                present=False,
                finding_code="CSP_MISSING",
                finding_title="Content Security Policy is not configured",
                description="The response did not include a Content-Security-Policy header, reducing defense against cross-site scripting (XSS).",
                remediation="Define a strict Content Security Policy restricting script, style, and object origins.",
                points=4,
            )
            total_points += 4
        else:
            result.headers["content-security-policy"] = HeaderObservation(
                header_name="Content-Security-Policy",
                present=True,
                value=csp_val,
                is_adequate=True,
            )

        # 3. X-Content-Type-Options
        xcto_val = norm_headers.get("x-content-type-options")
        if not xcto_val or "nosniff" not in xcto_val.lower():
            result.headers["x-content-type-options"] = HeaderObservation(
                header_name="X-Content-Type-Options",
                present=bool(xcto_val),
                value=xcto_val,
                finding_code="X_CONTENT_TYPE_OPTIONS_MISSING",
                finding_title="MIME sniffing protection not enabled",
                description="The response is missing X-Content-Type-Options: nosniff header, which may allow MIME-type confusion attacks.",
                remediation="Set X-Content-Type-Options: nosniff on all HTTP responses.",
                points=2,
            )
            total_points += 2
        else:
            result.headers["x-content-type-options"] = HeaderObservation(
                header_name="X-Content-Type-Options",
                present=True,
                value=xcto_val,
                is_adequate=True,
            )

        # 4. X-Frame-Options
        xfo_val = norm_headers.get("x-frame-options")
        if not xfo_val and not (csp_val and "frame-ancestors" in csp_val.lower()):
            result.headers["x-frame-options"] = HeaderObservation(
                header_name="X-Frame-Options",
                present=False,
                finding_code="FRAME_PROTECTION_MISSING",
                finding_title="Clickjacking protection not configured",
                description="Neither X-Frame-Options nor CSP frame-ancestors was configured, leaving the site potentially vulnerable to clickjacking.",
                remediation="Configure X-Frame-Options: DENY (or SAMEORIGIN) or CSP frame-ancestors 'self'.",
                points=2,
            )
            total_points += 2
        else:
            result.headers["x-frame-options"] = HeaderObservation(
                header_name="X-Frame-Options",
                present=bool(xfo_val),
                value=xfo_val,
                is_adequate=True,
            )

        # 5. Referrer-Policy
        ref_val = norm_headers.get("referrer-policy")
        if not ref_val:
            result.headers["referrer-policy"] = HeaderObservation(
                header_name="Referrer-Policy",
                present=False,
                finding_code="REFERRER_POLICY_MISSING",
                finding_title="Referrer Policy is not configured",
                description="The response did not specify a Referrer-Policy header.",
                remediation="Configure Referrer-Policy: strict-origin-when-cross-origin to control URL referral leakage.",
                points=1,
            )
            total_points += 1
        else:
            result.headers["referrer-policy"] = HeaderObservation(
                header_name="Referrer-Policy",
                present=True,
                value=ref_val,
                is_adequate=True,
            )

        # 6. Permissions-Policy
        perm_val = norm_headers.get("permissions-policy")
        if not perm_val:
            result.headers["permissions-policy"] = HeaderObservation(
                header_name="Permissions-Policy",
                present=False,
                finding_code="PERMISSIONS_POLICY_MISSING",
                finding_title="Permissions Policy is not configured",
                description="The response did not include a Permissions-Policy header.",
                remediation="Configure Permissions-Policy to explicitly restrict browser device APIs (camera, microphone, geolocation).",
                points=1,
            )
            total_points += 1
        else:
            result.headers["permissions-policy"] = HeaderObservation(
                header_name="Permissions-Policy",
                present=True,
                value=perm_val,
                is_adequate=True,
            )

        # Cookie attribute checks
        cookie_points = 0
        for c in result.cookies:
            if is_https and not c.secure and cookie_points < 6:
                cookie_points += 3
            if not c.httponly and cookie_points < 10:
                cookie_points += 2
            if not c.samesite and cookie_points < 14:
                cookie_points += 2

        result.points_total = total_points + cookie_points
        return result


security_header_scanner = SecurityHeaderScanner()
