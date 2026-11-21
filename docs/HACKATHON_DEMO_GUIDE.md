# SafeContain AI — Hackathon Live Demonstration & Verification Guide

## 1. Value Proposition (30 Seconds Pitch)

> *"In enterprise cybersecurity, containment is a high-stakes balancing act. Over-containment shuts down revenue and citizen services, while under-containment leads to catastrophic ransomware extortion.*
>
> *SafeContain AI introduces **Uncertainty-Aware Cyber Threat Containment with Business Continuity and Tamper-Evident Dual Audit**.*
>
> *Unlike naive SOAR bots that blindly pull network cables, SafeContain AI models lateral attack paths, factors in forensic uncertainty, protects mission-critical business workflows via Google OR-Tools CP-SAT, simulates outcomes in an isolated digital twin, anchors all decisions to an immutable blockchain ledger, and strictly requires human authorization before execution."*

---

## 2. Dedicated Hackathon Demonstration Scenario (Section 9 Compliance)

SafeContain AI features a dedicated 1-click **Hackathon Demonstration Scenario** explicitly designed to illustrate the difference between crude infrastructure isolation and uncertainty-aware business continuity optimization.

### Scenario Architecture:
1. **Suspicious Compromised Identity**:
   - `user-contractor-guest` (Compromised External Contractor account)
   - `dev-contractor-laptop` (Compromised Workstation Terminal #CON-409)
2. **Two Distinct Directed Attack Routes to Critical Database (`db-citizen-identity-vault`)**:
   - **Route A**: `user-contractor-guest` $\to$ `jump-host-admin` $\to$ `db-citizen-identity-vault`
   - **Route B**: `user-contractor-guest` $\to$ `api-gateway-internal` $\to$ `app-service-auth` $\to$ `db-citizen-identity-vault`
3. **Mission-Critical Business Workflows**:
   - `wf-payment-processing` (Real-Time Payment & Treasury Clearing Switch): Directly supported by `api-gateway-internal` and `db-citizen-identity-vault` (\$300,000/hr downtime penalty, 0 allowable outage hours).
   - `wf-citizen-identity-portal` (National Citizen Identity Verification Portal): Directly supported by `app-service-auth` and `db-citizen-identity-vault` (\$200,000/hr downtime penalty).

---

## 3. Side-by-Side Candidate Action Comparison

| Metric / Attribute | Option A: Disruptive Action (`act-firewall-api-gateway-internal`) | Option B: Targeted Alternative (`act-revoke-user-contractor-guest`) |
| :--- | :--- | :--- |
| **Target Entity** | `api-gateway-internal` (Core API Ingress) | `user-contractor-guest` (Compromised Contractor) |
| **Intervention Type** | `APPLY_FIREWALL_RULE / ISOLATE` | `REVOKE_SESSION / DISABLE_ACCOUNT` |
| **Disruption Score** | **20.0 (High Disruption)** | **10.0 (Minimal Disruption)** |
| **Business Workflow Impact** | ❌ **Payment Clearing Outage (\$250,000 SLA Penalty)** | ✅ **0 Business Outages (\$0 Downtime, 100% SLA)** |
| **SLA Violations** | **VIOLATED (Tier-1 Citizen Service)** | **SATISFIED (Zero Outage Guarantee)** |
| **Residual Attack Paths** | ⚠️ **6 Residual Paths Remain OPEN via Route A (`jump-host-admin`)** | ✅ **0 Residual Paths (Both routes severed at root)** |
| **Containment Status** | **Partially Contained / Breach Risk Persists** | **100% Fully Contained** |
| **Recommended by SafeContain AI?** | ❌ **Rejected by CP-SAT Constraint Solver** | ✅ **Optimal Plan Selected by CP-SAT** |

---

## 4. Live Hackathon Demonstration Walkthrough (5-Minute Script)

### Step 1: Launch Hackathon Scenario (Top Operational Bar)
- Click the blue **"Launch Hackathon Demo"** button on the top right.
- The badge displays `Hackathon Demonstration Scenario`, initializing the compromised contractor account and both lateral attack routes.

### Step 2: Visual Topology & Attack Paths (Views 3 & 4)
- Navigate to **Topology Explorer (View 3)** or **Attack Paths (View 4)**.
- Cytoscape.js directed graph displays:
  - 👑 **Gold Diamonds**: Crown Jewel Database (`db-citizen-identity-vault`).
  - ⚠️ **Crimson Circles**: Compromised Contractor (`user-contractor-guest`) and laptop (`dev-contractor-laptop`).
  - 🖥️ **Blue Cylinders**: Intermediate Jump Host (`jump-host-admin`) and API Gateway (`api-gateway-internal`).
  - 💼 **Purple Hexagons**: Protected Workflows (`wf-payment-processing`).
- Click any attack path in the table to isolate and trace Route A vs Route B on the graph.

### Step 3: Tri-Level Strategy Comparison (View 10)
- Navigate to **Strategy Comparator (View 10)**.
- Review the comparison matrix:
  - **Strategy 1 (Baseline Severity)**: Isolates perimeter gateways, incurring massive disruption and failing the zero-outage SLA.
  - **Strategy 2 (Greedy Risk-Cost)**: Cuts low-cost nodes but fails to optimize cross-path bottlenecks.
  - **Strategy 3 (Google OR-Tools CP-SAT)**: Identifies the root identity choke point, strictly preserving business continuity.

### Step 4: What-If Simulation Sandbox (View 11)
- Navigate to **Simulation Sandbox (View 11)**.
- Locate the **"Hackathon Demo: Disruptive vs Targeted Containment Comparison"** panel:
  - Click **"Simulate Disruptive Action (API Gateway)"**:
    - Observe residual paths remain at 6.
    - Observe payment clearing workflow is disrupted (\$250,000 penalty).
    - Notice on the Simulated Topology Map that Route A via `jump-host-admin` is still active!
  - Click **"Simulate Targeted Action (Contractor Identity)"**:
    - Observe residual paths drop to **0**.
    - Observe disrupted workflows drop to **0**.
    - Threat status switches to **THREAT CONTAINED**.
    - Cryptographic SHA-256 simulation hash generated and anchored.

### Step 5: Human-in-the-Loop Governance (View 14)
- Navigate to **Human Approval Center (View 14)**:
  - Current role: `SECURITY_MANAGER`.
  - Click **"Submit For Manager Review"** ($\to$ `PENDING_APPROVAL`).
  - Click **"Approve Containment Plan"** ($\to$ `APPROVED`).
  - Note: Lower roles (such as `READ_ONLY_VIEWER` or `SOC_ANALYST`) are denied approval capability (HTTP 403 Forbidden).

### Step 6: Tamper-Evident Audit & Blockchain Verification (View 15)
- Navigate to **Cryptographic Audit Ledger (View 15)**:
  - Inspect the recent events: `LOAD_SYNTHETIC_SCENARIO`, `RECOMMENDATION_ANCHOR`, `SIMULATION_SANDBOX_EVALUATION`, and `GOVERNANCE_STATE_TRANSITION`.
  - Click **"Verify Cryptographic Integrity"**: full forward SHA-256 hash-chain verification confirms ledger is 100% intact.
  - Review on-chain anchoring status (`SafeContainAuditLedger.sol` on Ethereum Sepolia Testnet / local permissioned anchor).

### Step 7: Dossier Export (View 19)
- Navigate to **Export Dossier (View 19)**:
  - Download official incident dossier in JSON, CSV, or Executive Briefing Text format.

---

## 5. Live Production URLs & Local Run Commands

- **Deployed Live Application (Render Cloud)**: [https://safecontain-ai.onrender.com](https://safecontain-ai.onrender.com)
- **Live Health & Engine Diagnostics Probe**: [https://safecontain-ai.onrender.com/api/v1/health](https://safecontain-ai.onrender.com/api/v1/health)
- **Interactive OpenAPI Documentation**: [https://safecontain-ai.onrender.com/docs](https://safecontain-ai.onrender.com/docs)

### Local Launch (Windows PowerShell):
```powershell
# Run full test suite (36 tests)
pytest tests/unit tests/performance tests/security tests/integration/test_e2e_workflow.py -v

# Build frontend production bundle
npm --prefix frontend run build

# Start unified server on port 8000
python run_app.py
```
