# SafeContain AI — Phase 6 Hackathon Judge & Evaluator Demonstration Guide

**Project:** SafeContain AI — Enterprise Cybersecurity Decision Support Platform  
**Target Audience:** Hackathon Judges, Technical Evaluators & System Auditors  
**Current State:** 100% Functioning, Authenticated, Persistent AuraDB Cloud Graph, Zero Regressions  

---

## 1. Quick Access Credentials

SafeContain AI is pre-configured with three role tiers designed to demonstrate strict separation of duties and privilege boundaries:

| Persona | Username | Password | Role Tier | Scope of Authority |
| :--- | :--- | :--- | :--- | :--- |
| **Platform Administrator** | `admin` | `Admin@SafeContain2026!` | `ADMIN` | Full control: CSV Ingestion, Neo4j Aura Sync, User Management, Scenario Resets. |
| **SOC Incident Analyst** | `analyst` | `Analyst@SafeContain2026!` | `ANALYST` | Tactical analysis: Attack Paths, Sensitivity, CP-SAT Optimization, Isolated Simulation. |
| **Executive / Auditor** | `viewer` | `Viewer@SafeContain2026!` | `VIEWER` | Read-only inspection: Graph Topology, Observability Metrics, Audit Ledger, Dossier Export. |

---

## 2. Five-Minute Live Judge Demonstration Walkthrough

Follow these steps in the interactive web interface (`http://localhost:5173`) to verify all Phase 6 security controls:

### Step 1: Open the Application & Inspect the Authentication Gate
1. Navigate to `http://localhost:5173`.
2. Notice the **SafeContain AI Authentication Modal** appears automatically if no valid token exists in the browser.
3. Observe the three **Hackathon Demo Persona Buttons**:
   - `[Admin: Full Control]`
   - `[Analyst: Planning/Sim]`
   - `[Viewer: Read-Only]`
4. Clicking any persona button automatically fills the username and password with secure test credentials.

---

### Step 2: Authenticate as Administrator & Verify Full Authority
1. Click **`[Admin]`** and press **Sign In**.
2. Notice the topbar updates immediately:
   - Green/Cyan Status: `Neo4j AuraDB Active (154 nodes)`
   - Identity Badge: `admin` with a red **`ADMIN`** badge.
   - Logout button.
3. In the sidebar, select **Governance Roles** (View 17):
   - Review the **Active Authenticated Security Session** card: verified caller identity, enforced RBAC tier, HS256 token signer, and account active state.
   - Review the **Platform User Accounts (Persistent SQLite Store)** table showing registered platform accounts.
4. Test Administrative Authority:
   - Go to **SOC Operations** (View 2) -> Click **CSV Ingestion**.
   - Admin has full permission to upload CSVs and sync topology to Neo4j Aura Cloud.

---

### Step 3: Switch to SOC Analyst & Verify Tactical Authorization
1. Go back to **Governance Roles** (View 17).
2. Click **`Analyst Persona (analyst)`** under the Persona Switcher:
   - The platform transparently authenticates with the backend (`POST /api/v1/auth/login`) and receives an `ANALYST` JWT.
   - The topbar badge updates to blue **`ANALYST`**.
3. Verify Permitted Operations:
   - Navigate to **Attack Paths** (View 4): 32 directed multi-hop attack paths render with zero errors.
   - Navigate to **Simulation Sandbox** (View 11): Click **Run What-If Simulation**. The CP-SAT solver executes in isolated memory.
4. Verify Enforced RBAC Restrictions:
   - In **SOC Operations** (View 2), attempting to upload a CSV will be rejected with an `API Error [403] Forbidden: Insufficient privileges. Required role: ADMIN, Caller role: ANALYST`.

---

### Step 4: Switch to Executive Viewer & Verify Read-Only Safeguards
1. In View 17, click **`Viewer Persona (viewer)`**.
2. Topbar updates to green **`VIEWER`**.
3. Verify Permitted Briefing Operations:
   - Navigate to **Executive Briefing** (View 1): Risk decomposition, business impact, and workflow continuity render smoothly.
   - Navigate to **Cryptographic Audit Ledger** (View 15): Cryptographic hash chain verification runs and displays `VALIDATED (100% Integrity)`.
   - Navigate to **Export Dossier** (View 19): Click **Export Complete JSON Dossier** to download compliance evidence.
4. Verify Enforced Prohibitions:
   - Attempting to run simulations or plan containment displays a clear permission error: **403 Forbidden**.

---

### Step 5: Test Role Self-Assertion Defense
1. In SafeContain AI, attackers cannot escalate privilege by tampering with request payloads.
2. Even if an analyst or viewer passes `actor_role="PLATFORM_ADMIN"` in request bodies (e.g. `/api/v1/governance/transition`), the backend **completely ignores** the body claim and binds the action strictly to the validated JWT role.
3. Unauthorized state transitions are rejected with HTTP 403 Forbidden.

---

## 3. Command-Line API Verification Script (For Technical Judges)

Run these quick curl or Python commands from any terminal to verify the security enforcement directly:

### 1. Verify Public Health Probe (No Auth Required)
```bash
curl -s http://127.0.0.1:8000/api/v1/health
```
*Expected Output:* Status `HEALTHY`, `graph_backend: "live_neo4j"`, `neo4j_connected: true`, `persistence_status: "PERSISTENT_AURA"`.

---

### 2. Verify 401 Unauthorized Without Token
```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/api/v1/graph/attack-paths
```
*Expected Output:* `401`

---

### 3. Authenticate as Analyst & Verify JWT Issuance
```bash
ANALYST_TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst","password":"Analyst@SafeContain2026!"}' \
  | python -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

echo "Analyst Token: ${ANALYST_TOKEN:0:35}..."
```

---

### 4. Verify Analyst Access to Tactical Endpoints (200 OK)
```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/api/v1/graph/attack-paths \
  -H "Authorization: Bearer $ANALYST_TOKEN"
```
*Expected Output:* `200`

---

### 5. Verify Analyst Denied from Admin Endpoints (403 Forbidden)
```bash
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/api/v1/auth/users \
  -H "Authorization: Bearer $ANALYST_TOKEN"
```
*Expected Output:* `403`

---

## 4. Automated Test Verification

Judges can run the complete automated security and regression test suite directly:

```bash
# Run Phase 6 Authentication & RBAC Test Suite (23 Tests)
pytest tests/security/test_phase6_authentication.py -v

# Run Full Combined Regression Suite (58 Tests: 100% Passing)
pytest tests/security/ tests/integration/ -v
```

*All 58 tests pass in ~60 seconds with live AuraDB cloud verification.*
