# TrustLens Collaborative Threat Intelligence Engine

Module-level implementation of the Collaborative Threat Intelligence Engine for the TrustLens cybersecurity platform.

## Architecture

This package provides an offline, deterministic, and abuse-resistant intelligence pipeline for community-submitted threat reports.

### Key Components

- **`normalization.py`**: RFC 3986 URL canonicalization, Punycode/IDNA domain decoding, default port stripping, userinfo isolation, query parameter deterministic sorting, and IPv4/IPv6 literal support.
- **`validation.py`**: Defensive input bounds, format validation, and DoS mitigation.
- **`deduplication.py`**: Canonical equivalence, path-variant detection, and host-variant clustering with indexed hash keys.
- **`evidence.py`**: Cryptographic evidence fingerprinting (SHA-256), stance analysis, diversity evaluation, and unverified source penalties.
- **`corroboration.py`**: Independent source clustering (resolving Sybil and copied evidence), exponential temporal decay, and confidence assessment.
- **`abuse_detection.py`**: Detection of report flooding, Sybil clusters, duplicate evidence reuse, and coordinated submission patterns.
- **`reporter_reliability.py`**: Anti-farming reporter reliability scoring and tier assignment.
- **`moderation.py`**: Transparent, explainable action recommendations for human moderation queues.
- **`indicators.py`**: Indicator lifecycle management (confirmation, dispute, expiration, revocation) and scoped matching (EXACT_URL, HOST, DOMAIN).
- **`service.py`**: High-level unified orchestrator (`CollaborativeIntelligenceEngine`).
- **`interfaces.py`**: Typed protocols for backend consumers.
- **`config.py`**: Module-local configurable policies and thresholds.

## Testing

Run tests with:
```bash
python -m pytest intelligence/collaborative_intelligence/tests/ -v
```

