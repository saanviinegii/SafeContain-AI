# SafeContain AI — Local Run & Demonstration Guide (Windows PowerShell)

This guide provides the exact commands to set up, test, build, and run **SafeContain AI** on Windows using PowerShell.

---

## 1. Prerequisites

- **OS**: Windows 10/11
- **Python**: Python 3.10, 3.11, or 3.14 (with `pip`)
- **Node.js**: Node.js v18+ or v20+ (with `npm`)
- **Git**: Installed and available in PATH

Verify installations in PowerShell:
```powershell
python --version
node --version
npm --version
```

---

## 2. Python Virtual Environment Setup & Backend Installation

From the repository root (`c:\Users\saanv\Desktop\SafeContain AI`):

```powershell
# 1. Create a Python virtual environment
python -m venv venv

# 2. Set PowerShell Execution Policy (if script execution is restricted)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 3. Activate the virtual environment
.\venv\Scripts\Activate.ps1

# 4. Upgrade pip
python -m pip install --upgrade pip

# 5. Install backend dependencies
pip install -r requirements.txt
```

---

## 3. Frontend Dependencies Installation & Production Build

```powershell
# 1. Navigate to the frontend directory
cd frontend

# 2. Install Node.js dependencies
npm install

# 3. Run TypeScript type checking and production build
npm run build

# 4. Return to the repository root
cd ..
```

---

## 4. Run All Automated Verification Tests

SafeContain AI includes a comprehensive test suite across unit, performance, security, and integration layers:

```powershell
# Run the CI test runner (executes all 4 suites: unit, performance, security, integration)
python run_ci_tests.py
```

Or run via pytest directly with detailed flags:
```powershell
pytest tests/unit tests/performance tests/security tests/integration -v --tb=short
```

Expected result:
```
======================== 42 passed, 1 skipped in 4.5s ========================
```
*(Note: `test_real_neo4j_aura_lifecycle` cleanly skips when live cloud Neo4j Aura credentials are not provided in your local `.env`, conforming to the offline resilience design.)*

---

## 5. Starting the Application

SafeContain AI supports two local run workflows:

### Option A: Unified Full-Stack Launcher (Recommended)

Runs the FastAPI backend and serves the compiled React single-page dashboard together on a single port (`8000`), automatically launching your default web browser:

```powershell
python run_app.py
```

Dashboard URL: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)  
Swagger API Docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)  
Health Endpoint: [http://127.0.0.1:8000/api/v1/health](http://127.0.0.1:8000/api/v1/health)

---

### Option B: Standalone Dual-Process Mode (For Frontend Hot-Reloading)

Open two separate Windows PowerShell windows:

#### Window 1: Backend API Server
```powershell
.\venv\Scripts\Activate.ps1
$env:PORT = "8000"
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

#### Window 2: Frontend Vite Dev Server
```powershell
cd frontend
npm run dev
```

The Vite dev server will start at: [http://localhost:5173/](http://localhost:5173/)  
API requests are automatically routed to the backend on `http://127.0.0.1:8000/api/v1` via Vite proxy and runtime detection.

---

## 6. Safe Neo4j AuraDB Connectivity Test

SafeContain AI uses a **Dual Engine**:
- If `NEO4J_URI` is reachable, it uses live Neo4j Aura.
- If unreachable or unconfigured, it seamlessly operates on the in-memory NetworkX engine.

To safely test real Neo4j Aura connectivity without mocks:

```powershell
# Supply your live Aura instance credentials in PowerShell:
$env:NEO4J_URI = "neo4j+s://your-instance.databases.neo4j.io"
$env:NEO4J_USER = "neo4j"
$env:NEO4J_PASSWORD = "YourSecurePassword"

# Run the dedicated non-mocked integration test
pytest tests/integration/test_neo4j_aura.py -v
```

---

## 7. Blockchain Audit Verification Workflow

SafeContain AI implements the R&D Blueprint Page 2 & 4 cryptographic audit anchor:
- **On-chain minimal tuple**: `(record_id, cryptographic_hash, timestamp, event_type, approval_reference)`
- **Off-chain canonical ledger**: `audit_ledger.jsonl`

In local demonstration mode, the system runs in **Deterministic Permissioned Anchor Mode** (simulating `SafeContainAuditLedger.sol` block heights and tx receipts).

To verify on-chain integrity from the UI:
1. Navigate to the **Audit Explorer** view (View 15).
2. Click **Verify On-Chain** next to any audit record.
3. The system recomputes the off-chain SHA-256 hash and verifies a 100% cryptographic match against the on-chain anchor.

