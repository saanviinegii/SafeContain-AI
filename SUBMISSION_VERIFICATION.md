# SafeContain AI — Evaluator Quickstart & Verification Guide

Welcome to the **SafeContain AI** Evaluation Package. This guide provides step-by-step instructions for judges, evaluators, and academic reviewers to verify the complete platform end-to-end in under 2 minutes.

---

## 1. Submission Overview & Prototype Links

- **Author / Lead Architect:** Saanvi Negi
- **System Classification:** Government-Ready, Uncertainty-Aware Cybersecurity Containment Planning & Simulation Platform
- **Official Project Repository:** [https://github.com/saanviinegii/SafeContain-AI](https://github.com/saanviinegii/SafeContain-AI)
- **Verified CI/CD Pipeline:** [https://github.com/saanviinegii/SafeContain-AI/actions](https://github.com/saanviinegii/SafeContain-AI/actions)
- **Interactive Evaluation Prototype:**
  - **Frontend UI Prototype:** `http://localhost:5173` (via `start_evaluation.bat` / `start_evaluation.sh`)
  - **FastAPI OpenAPI / Swagger Endpoint:** `http://localhost:8000/docs`
  - **System Health API:** `http://localhost:8000/api/v1/health`
- **Test Suite Pass Rate:** 100% (37 of 37 passed)
- **CI/CD Pipeline Status:** Verified Green (`✔`) on GitHub Actions

---

## 2. Fast Verification (Under 2 Minutes)

### Option A: Automated One-Click Verification (Windows)
Double-click:
```cmd
start_evaluation.bat
```
This batch script will:
1. Verify Python 3.11+
2. Run the full 37-test automated verification suite
3. Launch the FastAPI Backend on `http://127.0.0.1:8000`
4. Serve the Production Frontend Dashboard on `http://localhost:5173`

---

### Option B: Manual Step-by-Step Verification

#### Step 1: Install Python Dependencies
```bash
pip install -r requirements.txt
pip install -e .
```

#### Step 2: Run the Automated Verification Suite
```bash
python run_ci_tests.py
```
*Expected Result: All 37 integration, security, performance, and unit tests will pass with 0 errors.*

#### Step 3: Launch the Backend Application Server
```bash
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```
- Interactive OpenAPI / Swagger Docs: `http://localhost:8000/docs`
- Redoc Documentation: `http://localhost:8000/redoc`
- System Health Endpoint: `http://localhost:8000/api/v1/health`

#### Step 4: Serve the Frontend Application
In a separate terminal:
```bash
python -m http.server 5173 --directory frontend/dist
```
Open your browser to: **`http://localhost:5173`**

---

## 3. Key Evaluator Verification Checkpoints

1. **Topological Graph & Attack Paths:**
   - Navigate to **Topology Explorer** or **Attack Paths** tab to view multi-hop Dijkstra attack trajectories.
2. **What-If Simulation Sandbox:**
   - Go to **Simulation Sandbox** and click **"Re-run What-If Simulation"** with candidate actions to evaluate residual risk scores, budget constraints, and workflow impacts in real-time.
3. **Tri-Level Optimization Comparison:**
   - Inspect **Strategy Comparator** to review CP-SAT exact constraint optimization vs Greedy heuristics vs Baseline severity planner.
4. **Business Continuity Digital Twin:**
   - Inspect **Business Continuity Twin** to see mission-critical SLAs (SWIFT Interbank, Core Banking, Gov Identity Gateway) preserved during containment.
5. **Cryptographic Audit Ledger:**
   - Verify sequential SHA-256 forward integrity at `GET /api/v1/audit/verify`.

---

## 4. Documentation Index

The following complete architectural specifications are included in this package:
- [SYSTEM_ARCHITECTURE.md](file:///c:/Users/saanv/Desktop/SafeContain%20AI/SYSTEM_ARCHITECTURE.md): End-to-end architecture and technology stack
- [TECHNICAL_DESIGN.md](file:///c:/Users/saanv/Desktop/SafeContain%20AI/TECHNICAL_DESIGN.md): Modular component contracts and data flow
- [OPTIMIZATION_METHODOLOGY.md](file:///c:/Users/saanv/Desktop/SafeContain%20AI/OPTIMIZATION_METHODOLOGY.md): OR-Tools CP-SAT formulation and SLA constraints
- [UNCERTAINTY_MODEL.md](file:///c:/Users/saanv/Desktop/SafeContain%20AI/UNCERTAINTY_MODEL.md): Bayesian evidence decay and sensitivity drift
- [PERFORMANCE_BENCHMARKS.md](file:///c:/Users/saanv/Desktop/SafeContain%20AI/PERFORMANCE_BENCHMARKS.md): Graph traversal & solver scaling metrics
- [SECURITY_THREAT_MODEL.md](file:///c:/Users/saanv/Desktop/SafeContain%20AI/SECURITY_THREAT_MODEL.md): STRIDE threat analysis and injection defenses
- [COMPLIANCE_MAPPING.md](file:///c:/Users/saanv/Desktop/SafeContain%20AI/COMPLIANCE_MAPPING.md): NIST CSF 2.0, ISO 27001, and SOC2 mapping

---

*Confidential & Proprietary Submission — Governed by [EVALUATION_LICENSE.md](file:///c:/Users/saanv/Desktop/SafeContain%20AI/EVALUATION_LICENSE.md)*
