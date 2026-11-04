# 🚀 SafeContain AI — Render Cloud Deployment Guide

This guide provides end-to-end instructions for deploying **SafeContain AI** to [Render](https://render.com).

The application is configured to run as a **Unified Full-Stack Service** (FastAPI backend + React Web Console) inside a single container on Render's Free or Starter tier, with zero CORS configuration hurdles.

---

## 📋 Table of Contents
1. [Prerequisites](#-prerequisites)
2. [Method 1: 1-Click Render Blueprint (Recommended)](#-method-1-1-click-render-blueprint-recommended)
3. [Method 2: Manual Web Service Setup (Docker)](#-method-2-manual-web-service-setup-docker)
4. [Method 3: Native Python Runtime Setup](#-method-3-native-python-runtime-setup)
5. [Environment Variables Reference](#-environment-variables-reference)
6. [Post-Deployment Verification](#-post-deployment-verification)
7. [Optional: Connecting External Neo4j & PostgreSQL](#-optional-connecting-external-neo4j--postgresql)
8. [Troubleshooting & FAQs](#-troubleshooting--faqs)

---

## 📌 Prerequisites

1. A **GitHub account** with access to your repository:  
   `https://github.com/saanviinegii/SafeContain-AI`
2. A **[Render Account](https://render.com)** (free tier works perfectly).

---

## 🌟 Method 1: 1-Click Render Blueprint (Recommended)

Render Blueprints use the pre-configured [render.yaml](file:///c:/Users/saanv/Desktop/SafeContain%20AI/render.yaml) file to automatically provision your web service, health check, environment variables, and Docker settings.

1. **Push your latest changes to GitHub:**
   ```bash
   git add .
   git commit -m "feat: configure Render cloud deployment with Blueprint and Dockerfile"
   git push origin main
   ```

2. **Open Render Blueprints:**
   - Log into [dashboard.render.com](https://dashboard.render.com/).
   - Click the **New +** button in the top navigation bar.
   - Select **Blueprint**.

3. **Connect Your Repository:**
   - Choose `saanviinegii/SafeContain-AI`.
   - Render will detect `render.yaml` automatically.

4. **Review & Deploy:**
   - Enter a Service Group Name (e.g., `safecontain-ai-production`).
   - Click **Apply**.
   - Render will build the Docker container (compiling React and installing Python packages) and launch your instance!

---

## 🛠️ Method 2: Manual Web Service Setup (Docker)

If you prefer to configure the service manually via the Render UI:

1. In the [Render Dashboard](https://dashboard.render.com/), click **New +** ➔ **Web Service**.
2. Select **Build and deploy from a Git repository** and connect `SafeContain-AI`.
3. Configure the following fields:
   - **Name:** `safecontain-ai`
   - **Region:** `Oregon (US West)` or your closest region.
   - **Branch:** `main`
   - **Language / Runtime:** `Docker`
   - **Dockerfile Path:** `./Dockerfile`
   - **Instance Type:** `Free` (or `Starter` for 24/7 uptime without sleep)
4. Under **Advanced** ➔ **Health Check Path**, enter:
   ```
   /api/v1/health
   ```
5. Add the following **Environment Variables**:
   | Key | Value | Notes |
   |---|---|---|
   | `ENVIRONMENT` | `production` | Enables production security policies |
   | `GRAPH_BACKEND` | `dual` | Uses Neo4j if available, or NetworkX in-memory |
   | `USE_SQLITE_FALLBACK` | `true` | Embedded offline database |
   | `SECRET_KEY` | *(Click "Generate" or set 32+ characters)* | Used for cryptographic signatures |
   | `AUDIT_LEDGER_STORAGE_PATH` | `/app/data/audit_ledger.jsonl` | Chained cryptographic audit trail |
6. Click **Create Web Service**.

---

## 🐍 Method 3: Native Python Runtime Setup

If you wish to use Render's Native Python environment without Docker:

1. Click **New +** ➔ **Web Service** in Render.
2. Choose **Language:** `Python`.
3. Set:
   - **Build Command:** `./build.sh`
   - **Start Command:** `uvicorn backend.app.main:app --host 0.0.0.0 --port $PORT`
4. In **Environment Variables**:
   - `PYTHON_VERSION`: `3.11.9`
   - Plus the variables from Method 2 above.

---

## ⚙️ Environment Variables Reference

| Variable | Default Value | Description |
|---|---|---|
| `PORT` | Auto-assigned by Render (`10000`) | Network port uvicorn listens on |
| `ENVIRONMENT` | `production` | Deployment mode (`development`, `staging`, `production`) |
| `GRAPH_BACKEND` | `dual` | `dual` (Neo4j with auto NetworkX fallback) or `in_memory` |
| `USE_SQLITE_FALLBACK` | `true` | Automatically provisions SQLite relational store |
| `SECRET_KEY` | auto-generated | Enterprise JWT & token encryption key |
| `AUDIT_LEDGER_STORAGE_PATH` | `/app/data/audit_ledger.jsonl` | File storage path for cryptographic audit ledger |
| `ALLOWED_ORIGINS` | Comma-separated domains | Allowed frontend domains (all `*.onrender.com` domains are accepted by default) |
| `NEO4J_URI` | *(Optional)* `bolt://...` | Neo4j AuraDB or external cluster URI |
| `DATABASE_URL` | *(Optional)* `postgresql://...` | Managed PostgreSQL connection string |

---

## 🔍 Post-Deployment Verification

Once Render displays **"Live"**:

1. **Web Console UI:**
   Navigate to your service URL:
   ```
   https://safecontain-ai.onrender.com/
   ```
   You will see the 19-view SafeContain AI Enterprise Console loaded with the synthetic national gateway scenario.

2. **Health Check Probe:**
   ```
   https://safecontain-ai.onrender.com/api/v1/health
   ```
   Expected response:
   ```json
   {
     "status": "HEALTHY",
     "service": "SafeContain AI Enterprise Backend",
     "version": "1.0.0",
     "graph_backend": "in_memory_networkx",
     "audit_chain_length": 15
   }
   ```

3. **Interactive OpenAPI (Swagger) Documentation:**
   ```
   https://safecontain-ai.onrender.com/docs
   ```

---

## 🌐 Optional: Connecting External Neo4j & PostgreSQL

By default, SafeContain AI operates in zero-dependency **Dual Engine Fallback** mode (In-Memory NetworkX graph + embedded storage + automated scenario generation).

If you want persistent external databases:

### 1. Neo4j AuraDB (Free Cloud Graph):
1. Create a free graph instance at [neo4j.com/cloud/aura/](https://neo4j.com/cloud/aura/).
2. In your Render Dashboard ➔ Environment Variables, add:
   ```env
   NEO4J_URI=neo4j+s://<your-db-id>.databases.neo4j.io
   NEO4J_USER=neo4j
   NEO4J_PASSWORD=<your-db-password>
   ```

### 2. Render Managed PostgreSQL:
1. In Render Dashboard, click **New +** ➔ **PostgreSQL**.
2. Copy the **Internal Database URL**.
3. In your Web Service Environment Variables, set:
   ```env
   DATABASE_URL=<your-internal-postgres-url>
   USE_SQLITE_FALLBACK=false
   ```

---

## ❓ Troubleshooting & FAQs

- **Cold Starts on Free Tier:**
  Render's free tier spins down after 15 minutes of inactivity. The first request after sleep may take ~30–50 seconds to wake up. This is normal on the free tier. Upgrading to the *Starter* plan keeps the service warm 24/7.
- **Port Binding:**
  The Dockerfile and start command dynamically bind to `0.0.0.0:${PORT:-8000}`, satisfying Render's `$PORT` requirement.
- **CORS Issues:**
  The backend includes a regex policy matching `https://.*\.onrender\.com`, ensuring custom or preview Render domains work out of the box.
- **Automated Re-deploys:**
  `autoDeploy: true` is enabled in `render.yaml`. Every `git push` to your `main` branch will automatically build and deploy the updated application.
