# TrustLens — Unified Website Security Assessment Platform

TrustLens is a production-oriented cybersecurity SaaS platform that determines whether a website is **SAFE**, **SUSPICIOUS**, **MALICIOUS**, or **INCONCLUSIVE**.

The platform combines four capabilities:
1. **Threat Intelligence Analysis**: Live lookups against OpenPhish, URLhaus, and curated local threat indicators.
2. **Passive Web Security Assessment**: Strict HTTP inspection, security header audits, and redirect tracking.
3. **SSL/TLS Certificate Validation**: X.509 leaf certificate validation, SAN inspection, chain validity, and expiration checks.
4. **Collaborative Threat Intelligence**: Community threat reporting with strict moderator workflows and auditable decision trails.

---

## Technical Architecture & Core Principles

- **Modular Monolith**: Clean layer separation across API, Services, Models, Scanners, and Integrations.
- **SSRF Safeguards**: Pre-flight DNS resolution, global IPv4/IPv6 routability validation, loopback/private/link-local/metadata IP rejection, connection pinning, and manual redirect hop revalidation.
- **Strict Decoupling**: Integration boundary with the AI Intelligence Engine is mediated via typed Pydantic contracts and dependency injection.
- **Deterministic Risk Scoring**: Decisive threat feed rules take precedence over additive heuristics. Missing evidence yields `INCONCLUSIVE` instead of false `SAFE`.

---

## Technology Stack

| Technology | Responsibility |
|---|---|
| **Python 3.12** | Backend Language |
| **FastAPI** | High-performance REST API Framework |
| **Pydantic v2** | Strict validation & Data Transfer Objects |
| **SQLAlchemy 2.0** | Async ORM & Relational Data Access |
| **PostgreSQL 16+** | Primary Database |
| **Alembic** | Versioned Database Migrations |
| **Redis 7.4+** | In-memory message broker & cache |
| **Celery 5.4+** | Asynchronous task processing |
| **HTTPX & dnspython** | Safe HTTP scanning & DNS resolution |
| **cryptography** | X.509 Certificate parsing and validation |
| **PyJWT & Argon2id** | JWT auth, token rotation, and password hashing |
| **pytest & Ruff** | Automated test suite & linting/formatting |
| **Docker & Compose** | Containerization & local orchestration |

---

## Repository Structure

```text
trustlens/
├── backend/
│   ├── app/
│   │   ├── main.py                   # FastAPI Application Entrypoint
│   │   ├── config.py                 # Pydantic Settings & Environment Variables
│   │   ├── api/v1/                   # REST API v1 Routers & Endpoints
│   │   ├── core/                     # Logging, Security, Exceptions, Permissions
│   │   ├── database/                 # SQLAlchemy Base, Async Sessions, Init DB
│   │   ├── models/                   # SQLAlchemy 2.0 ORM Models
│   │   ├── schemas/                  # Pydantic v2 Request/Response DTOs
│   │   ├── services/                 # Domain Business Logic
│   │   ├── scanners/                 # URL, DNS, HTTP, TLS, Redirect, Headers
│   │   ├── integrations/             # AI Engine Integration & Test Double
│   │   ├── workers/                  # Celery Application & Tasks
│   │   └── tests/                    # Unit, Integration, & Security Tests
│   ├── migrations/                   # Alembic Database Migrations
│   ├── Dockerfile                    # Production Hardened Dockerfile
│   ├── requirements.txt              # Pinned Python Dependencies
│   ├── pyproject.toml                # Tooling Configuration (Ruff, Mypy, Pytest)
│   ├── alembic.ini                   # Alembic Configuration
│   └── .env.example                  # Environment Configuration Template
├── shared/
│   └── contracts/                    # Cross-Boundary Data Contracts
├── docker-compose.yml                # Docker Compose Orchestration
├── .gitignore                        # Git Ignore Rules
└── README.md                         # Documentation
```

---

## Quickstart & Local Development

### Prerequisites
- Python 3.11+ (or Python 3.12)
- Docker & Docker Compose (optional for containerized setup)

### 1. Local Environment Setup
```bash
# Clone and enter directory
cd trustlens/backend

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment variables
cp .env.example .env
```

### 2. Run with Docker Compose
```bash
# From the repository root:
docker compose up -d --build

# Verify services:
docker compose ps

# View API logs:
docker compose logs -f api
```

### 3. Verify Health Endpoints
- Base Health: `http://localhost:8000/health`
- Database Health: `http://localhost:8000/health/database`
- Redis Health: `http://localhost:8000/health/redis`
- Interactive OpenAPI Docs: `http://localhost:8000/docs`

### 4. Running Tests
```bash
cd backend
pytest -v
```

