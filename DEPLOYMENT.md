# TrustLens — Production Deployment Guide

This guide details how to deploy TrustLens in production using containerized Docker Compose or in standalone local mode.

---

## 1. Architecture Overview

TrustLens consists of five cohesive services:

| Service | Port | Container Name | Description |
|---|---|---|---|
| **Frontend** | `3000` / `5173` | `trustlens_frontend` | React 19 + Vite SPA served via Nginx reverse proxy |
| **Backend API** | `8000` | `trustlens_api` | FastAPI application serving REST endpoints (`/api/v1`) |
| **Celery Worker** | Internal | `trustlens_worker` | Background worker for asynchronous website scanning |
| **PostgreSQL** | `5432` | `trustlens_postgres` | Primary relational database (PostgreSQL 16) |
| **Redis** | `6379` | `trustlens_redis` | Distributed broker & result store for Celery |

---

## 2. Option A: Full Production Deployment (Docker Compose)

The entire platform can be brought up with a single command.

### Prerequisites
- Docker Engine 24+ & Docker Compose v2+

### Quick Start

1. **Clone & Navigate:**
   ```bash
   cd trustlens-main/trustlens-main
   ```

2. **Configure Environment Variables (Optional):**
   ```bash
   cp backend/.env .env
   ```
   *(Or accept production defaults defined in `docker-compose.yml`)*

3. **Build & Start Services:**
   ```bash
   docker compose up -d --build
   ```

4. **Verify Health:**
   ```bash
   docker compose ps
   ```

5. **Access Application:**
   - **Frontend UI:** `http://localhost:3000` (or `http://localhost:5173`)
   - **Backend API Docs (Swagger):** `http://localhost:8000/docs`
   - **API Healthcheck:** `http://localhost:8000/health`

### Stopping Services
```bash
docker compose down
# To also delete database volumes:
docker compose down -v
```

---

## 3. Option B: Standalone / Local Development Mode (Zero External Dependencies)

If Docker or PostgreSQL is not available on the host, TrustLens natively operates on SQLite with in-process background scanning:

### Backend Startup
```powershell
# From repository root:
python run_backend.py

# Or from backend/ directory:
cd trustlens-main/trustlens-main/backend
python run_backend.py
```
- The backend will bind to `http://localhost:8000`.
- SQLite database `trustlens.db` is auto-initialized on first launch.

### Frontend Startup
```powershell
cd trustlens-main/trustlens-main/frontend
npm install
npm run dev
```
- The Vite development server will bind to `http://localhost:5173`.

---

## 4. Production Security Checklist

Before exposing to a public network:

1. **SECRET_KEY:** Generate a cryptographically secure 32+ character key:
   ```bash
   openssl rand -hex 32
   ```
   Set this in `.env` as `SECRET_KEY`.
2. **PostgreSQL Password:** Replace `trustlens_password` with a strong database secret.
3. **CORS Origins:** Set `ALLOWED_CORS_ORIGINS` in `.env` to your exact production domain(s):
   ```json
   ALLOWED_CORS_ORIGINS=["https://trustlens.yourdomain.com"]
   ```
4. **Third-Party Threat Intelligence (Optional):**
   - Provide `URLHAUS_AUTH_KEY` in `.env` to enable live abuse.ch lookups.
   - Set `OPENPHISH_ENABLED=true` to enable phishing feed verification.

