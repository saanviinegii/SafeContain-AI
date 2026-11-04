# ==============================================================================
# SafeContain AI — Production Multi-Stage Dockerfile (Render Cloud Optimized)
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Build React Frontend
# ------------------------------------------------------------------------------
FROM node:20-alpine AS frontend-builder
WORKDIR /build

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# ------------------------------------------------------------------------------
# Stage 2: Build Python Wheels & Dependencies
# ------------------------------------------------------------------------------
FROM python:3.11-slim AS python-builder
WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ------------------------------------------------------------------------------
# Stage 3: Production Runtime
# ------------------------------------------------------------------------------
FROM python:3.11-slim AS runner
WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ENVIRONMENT=production \
    GRAPH_BACKEND=dual \
    USE_SQLITE_FALLBACK=true \
    PORT=8000

# Non-root user for enterprise security threat compliance
RUN useradd -m -u 1000 safecontain && \
    apt-get update && apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Copy installed Python packages & binaries
COPY --from=python-builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=python-builder /usr/local/bin /usr/local/bin

# Copy backend codebase
COPY backend /app/backend
COPY pyproject.toml /app/

# Copy compiled frontend SPA from Stage 1 into /app/frontend/dist
COPY --from=frontend-builder /build/dist /app/frontend/dist

# Initialize audit data storage directory
RUN mkdir -p /app/data && \
    touch /app/data/audit_ledger.jsonl && \
    chown -R safecontain:safecontain /app

USER safecontain

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/api/v1/health || exit 1

# Render dynamically passes the PORT environment variable (defaulting to 8000 if not set)
CMD ["sh", "-c", "uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 2"]
