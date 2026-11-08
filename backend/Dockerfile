# Multi-stage optimized production container for TrustLens Backend
FROM python:3.12-slim AS base

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/workspace:/workspace/backend

WORKDIR /workspace

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY backend/requirements.txt /workspace/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /workspace/requirements.txt

# Create a non-root user for security best practices
RUN groupadd -g 10001 trustlens && \
    useradd -u 10001 -g trustlens -s /bin/bash -m trustlens

# Copy full application tree (backend, shared, intelligence)
COPY backend /workspace/backend
COPY shared /workspace/shared
COPY intelligence /workspace/intelligence

# Ensure ownership for non-root user
RUN chown -R trustlens:trustlens /workspace

USER trustlens
WORKDIR /workspace/backend

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
