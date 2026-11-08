# TrustLens Backend — Startup & Execution Guide

This guide provides step-by-step instructions for running, operating, and verifying the **TrustLens** backend services locally, via Docker Compose, and natively in Python.

---

## 1. Quick Start: Docker Compose (Recommended)

Docker Compose provides a complete, isolated local environment with all four required services:
1. **PostgreSQL 16**: Relational storage for scans, reports, findings, and authentication sessions.
2. **Redis 7.4**: In-memory broker for Celery queues and sliding-window rate limiting.
3. **FastAPI API Server**: Asynchronous REST API on port `8000`.
4. **Celery Worker**: Background task worker handling URL, DNS, HTTP, TLS, and Threat Intelligence pipelines.

### Step 1: Launch Services
From the repository root (`d:\trustlens`):

```bash
docker compose up -d --build
```

### Step 2: Verify Running Containers
```bash
docker compose ps
```
All four containers (`trustlens_postgres`, `trustlens_redis`, `trustlens_api`, `trustlens_worker`) should report state `Up (healthy)` or `Up`.

### Step 3: Stream Logs
- **API Server Logs:**
  ```bash
  docker compose logs -f api
  ```
- **Celery Worker Logs:**
  ```bash
  docker compose logs -f worker
  ```

### Step 4: Stop Services
```bash
# Stop containers (preserves database data in Docker volumes)
docker compose down

# Stop and wipe database/redis volumes (fresh reset)
docker compose down -v
```

---

## 2. Native Local Development (Without Docker)

If you prefer running services directly on your host machine or pairing with local/cloud PostgreSQL and Redis instances:

### Prerequisites
- **Python 3.11** or **Python 3.12**
- **PostgreSQL 16+** running on `localhost:5432` (or Docker container)
- **Redis 7+** running on `localhost:6379` (or Docker container)

*(Tip: You can run just the dependencies in Docker: `docker compose up -d postgres redis`)*

### Step 1: Activate Virtual Environment
Open a terminal in `d:\trustlens\backend`:

**On Windows (PowerShell):**
```powershell
.\.venv\Scripts\Activate.ps1
```

**On Windows (CMD):**
```cmd
.\.venv\Scripts\activate.bat
```

**On Linux / macOS:**
```bash
source .venv/bin/activate
```

*(If `.venv` is not yet created, run `python -m venv .venv` and `pip install -r requirements.txt`)*

### Step 2: Configure Environment File
Ensure a `.env` file exists in the `backend/` directory:

```bash
# Copy from template if not present
cp .env.example .env
```

Verify your database and broker connection strings in `backend/.env`:
```ini
ENVIRONMENT=development
DEBUG=true
DATABASE_URL=postgresql+asyncpg://trustlens_user:trustlens_password@localhost:5432/trustlens_db
DATABASE_SYNC_URL=postgresql+psycopg://trustlens_user:trustlens_password@localhost:5432/trustlens_db
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/1
CELERY_RESULT_BACKEND=redis://localhost:6379/2
SECRET_KEY=dev-secret-key-at-least-32-characters-long-trustlens
```

### Step 3: Initialize Database Tables
The application automatically creates tables on startup in `development` mode. To manually initialize or verify database tables:

```bash
python -m app.database.init_db
```

### Step 4: Start the FastAPI API Server
In Terminal 1 (from `backend/`):

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

The server will be available at: `http://localhost:8000`

### Step 5: Start the Celery Worker
In Terminal 2 (with `.venv` activated, from `backend/`):

> **IMPORTANT FOR WINDOWS USERS:**  
> Python multiprocessing on Windows does not support `fork()`. Celery workers must be started with the **`solo` pool (`-P solo`)** to prevent worker hangs or startup crashes:

**On Windows:**
```powershell
celery -A app.workers.celery_app.celery_app worker --loglevel=info -P solo -Q scans,celery
```

**On Linux / macOS:**
```bash
celery -A app.workers.celery_app.celery_app worker --loglevel=info -Q scans,celery
```

---

## 3. Verifying Health & Interactive Documentation

Once the server is running, verify the status through your browser or `curl`:

| Endpoint | Method | Purpose | Expected Status |
|---|---|---|---|
| `http://localhost:8000/health` | `GET` | Core application health probe | `200 OK` (`"status": "healthy"`) |
| `http://localhost:8000/health/database` | `GET` | PostgreSQL connectivity probe | `200 OK` (`"healthy": true`) |
| `http://localhost:8000/health/redis` | `GET` | Redis broker connectivity probe | `200 OK` (`"healthy": true`) |
| `http://localhost:8000/health/ready` | `GET` | Kubernetes readiness probe | `200 OK` |
| `http://localhost:8000/docs` | `GET` | Interactive Swagger OpenAPI UI | Web UI |
| `http://localhost:8000/redoc` | `GET` | Formatted ReDoc API Reference | Web UI |

---

## 4. Testing Core Workflows via CLI / Curl

### 1. Register a Test User
```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "analyst@example.com",
    "password": "SecurePassword123!",
    "display_name": "Security Analyst"
  }'
```

Save the `access_token` returned in `tokens.access_token`.

### 2. Submit a Website for Security Scan
```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>" \
  -d '{
    "url": "https://example.com",
    "treat_as_sensitive": false
  }'
```
*Response: HTTP `202 Accepted` with `"status": "queued"` and a `scan.id`.*

### 3. Check Scan Results
```bash
curl -X GET http://localhost:8000/api/v1/scans/<SCAN_ID> \
  -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>"
```

### 4. Query User Dashboard
```bash
curl -X GET http://localhost:8000/api/v1/dashboard/summary \
  -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>"
```

### 5. Submit a Community Threat Report
```bash
curl -X POST http://localhost:8000/api/v1/community/reports \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>" \
  -d '{
    "url": "https://suspicious-example.com/login",
    "category": "phishing",
    "claimed_verdict": "MALICIOUS",
    "evidence_text": "Observed credential harvesting form mimicking banking portal."
  }'
```

### 6. Analyze Standalone Certificate / Endpoint TLS
```bash
# Analyze a live endpoint TLS certificate
curl -X POST http://localhost:8000/api/v1/certificates/analyze \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>" \
  -d '{
    "target_hostname": "api.trustlens.io",
    "port": 443,
    "tls_protocol_version": "TLSv1.3"
  }'

# Or analyze PEM string directly
curl -X POST http://localhost:8000/api/v1/certificates/analyze \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <YOUR_ACCESS_TOKEN>" \
  -d '{
    "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIC...-----END CERTIFICATE-----",
    "target_hostname": "api.trustlens.io"
  }'
```

---

## 5. Running Automated Tests & Linting

### Run the Automated Test Suite (68 Tests)
From `backend/`:

```bash
python run_test.py
```
*(Or `pytest -v app/tests`)*

All 68 tests across Authentication, Scanning, Certificate Intelligence, Threat Intelligence, Dashboard, and Community Moderation will execute in isolated memory mode.

### Code Style & Formatting
```bash
# Run Ruff linting
ruff check app

# Auto-format codebase
ruff format app
```

---

## 6. Common Troubleshooting & FAQs

### Q1: Celery hangs on Windows when processing tasks
- **Cause:** Windows lacks POSIX `fork()` support, causing the default Celery prefork execution pool to stall.
- **Solution:** Always pass `-P solo` when starting Celery on Windows:  
  `celery -A app.workers.celery_app.celery_app worker -l info -P solo -Q scans,celery`

### Q2: `TargetNotPublicException` / HTTP 400 when submitting scans
- **Cause:** TrustLens incorporates strict Server-Side Request Forgery (SSRF) defense. The target hostname or IP resolved to loopback (`127.0.0.1`), private networks (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`), or cloud metadata endpoints (`169.254.169.254`).
- **Solution:** TrustLens only scans publicly routable internet targets on ports `80` and `443`.

### Q3: Port 5432 or 6379 already allocated
- **Cause:** An existing local PostgreSQL or Redis instance is already bound to default ports.
- **Solution:** Either stop local services, or edit `docker-compose.yml` and `.env` to map to alternative ports (e.g., `5433:5432` and `6380:6379`).

### Q4: CORS errors when connecting from React / Vite frontend
- **Cause:** Frontend port is not included in the CORS origin allowlist.
- **Solution:** Ensure your frontend URL (e.g. `http://localhost:5173` or `http://localhost:3000`) is listed in `ALLOWED_CORS_ORIGINS` inside `backend/.env`.

