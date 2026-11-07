"""DNS resolution scanner collecting A, AAAA, CNAME, MX, and NS records."""

import time

import dns.resolver
from pydantic import BaseModel, Field


class DnsScanResult(BaseModel):
    """Normalized DNS scanner observations."""

    host: str
    a_records: list[str] = Field(default_factory=list)
    aaaa_records: list[str] = Field(default_factory=list)
    cname_records: list[str] = Field(default_factory=list)
    mx_records: list[str] = Field(default_factory=list)
    ns_records: list[str] = Field(default_factory=list)
    resolution_time_ms: float = 0.0
    error: str | None = None
    completed: bool = False


class DnsScanner:
    """Performs structured DNS inspection."""

    def __init__(self, timeout: float = 3.0) -> None:
        self.timeout = timeout

    def scan(self, host: str) -> DnsScanResult:
        """Collect DNS telemetry for target host."""
        start_time = time.monotonic()
        result = DnsScanResult(host=host)

        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        records_to_query = [
            ("A", result.a_records),
            ("AAAA", result.aaaa_records),
            ("CNAME", result.cname_records),
            ("MX", result.mx_records),
            ("NS", result.ns_records),
        ]

        errors: list[str] = []

        for rtype, target_list in records_to_query:
            try:
                answers = resolver.resolve(host, rtype)
                for rdata in answers:
                    if rtype == "MX":
                        target_list.append(f"{rdata.preference} {rdata.exchange}")
                    else:
                        target_list.append(str(rdata).rstrip("."))
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                errors.append(f"NXDOMAIN for {rtype}")
            except dns.resolver.LifetimeTimeout:
                errors.append(f"Timeout resolving {rtype}")
            except Exception as exc:
                errors.append(f"{rtype} error: {type(exc).__name__}")

        result.resolution_time_ms = round((time.monotonic() - start_time) * 1000, 2)
        if errors and not (result.a_records or result.aaaa_records):
            result.error = "; ".join(errors)
            result.completed = False
        else:
            result.completed = True

        return result


dns_scanner = DnsScanner()
