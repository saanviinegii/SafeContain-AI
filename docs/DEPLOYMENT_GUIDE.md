# SafeContain AI — Enterprise Deployment & DevOps Guide

## 1. Unified Single-Port Architecture

SafeContain AI uses a unified deployment model where the **FastAPI backend acts as both the REST API server and the static file server for the production-built React SPA**.

### Benefits:
- Single web service on cloud platforms (Render, AWS App Runner, Google Cloud Run).
- Zero CORS friction in production (frontend and API share the exact same host and port).
- Automatic single TLS certificate termination.
- Seamless fallback for SPA client-side routing.

---

## 2. Docker Container Deployment

The multi-stage `Dockerfile` handles the complete build and runtime process:

```dockerfile
# Stage 1: Build the React TypeScript frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Python FastAPI Runtime
FROM python:3.11-slim
WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application
COPY backend/ ./backend/

# Copy compiled frontend from Stage 1 into backend static directory
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Expose port
EXPOSE 8000

# Start Uvicorn web server
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## 3. Render Web Service Deployment

SafeContain AI is deployed live on Render Cloud:
- **Production URL**: `https://safecontain-ai.onrender.com`
- **Source Repository**: `https://github.com/saanviinegii/SafeContain-AI.git`
- **Branch**: `main`

### Deployment Configuration (`render.yaml`)

```yaml
services:
  - type: web
    name: safecontain-ai
    env: docker
    plan: free
    region: oregon
    dockerfilePath: Dockerfile
    healthCheckPath: /api/v1/health
    envVars:
      - key: PORT
        value: 10000
      - key: ENVIRONMENT
        value: production
      - key: GRAPH_BACKEND
        value: dual
      - key: NEO4J_URI
        sync: false
      - key: NEO4J_USER
        sync: false
      - key: NEO4J_PASSWORD
        sync: false
      - key: NEO4J_DATABASE
        sync: false
      - key: SECRET_KEY
        generateValue: true
```

> **Note on Neo4j Aura Database Name:**
> In Neo4j Aura, standard/free instances route to your tenant home database. The application dynamically auto-discovers your database via `CALL db.info()`. Set `NEO4J_DATABASE` to your Aura database name (e.g. `e5193897`) or leave it blank to use automatic home database discovery. Avoid setting it to `neo4j` unless your Aura database is explicitly named `neo4j`.

---

## 4. Local Quick Start & Development

To run the application locally without Docker:

```powershell
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Build the frontend
cd frontend
npm install
npm run build
cd ..

# 3. Launch the unified platform
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

Then open your browser at `http://127.0.0.1:8000/`.

---

## 5. Verification & Health Check

After deployment, verify the live deployment by probing the health endpoint:

```bash
curl -i https://safecontain-ai.onrender.com/api/v1/health
```

Expected output:
```http
HTTP/2 200
content-type: application/json
x-content-type-options: nosniff
x-frame-options: DENY
x-correlation-id: req-...

{
  "status": "HEALTHY",
  "service": "SafeContain AI Enterprise Backend",
  "version": "1.0.0",
  "graph_backend": "live_neo4j",
  "audit_chain_length": 4
}
```
