# TESTING STRATEGY & QUALITY ASSURANCE SPECIFICATION
## SafeContain AI — Comprehensive Verification Architecture
**Document Version:** 1.0.0  

---

## 1. Test Suite Organization

SafeContain AI enforces automated verification across four distinct test layers:

1. **Unit Tests (`tests/unit/`):**
   - `test_domain_models.py`: Validates Pydantic domain models, enum constraints, and schema bounds.
   - `test_ingestion.py`: Validates SIEM/EDR connectors, deduplication fingerprints, and synthetic scenario generation.
   - `test_graph_engine.py`: Validates dual-engine graph store, directed traversal, and snapshot immutability.
   - `test_evidence_and_risk.py`: Validates freshness decay, sensitivity drift, and decomposed risk factors.
   - `test_business_twin.py`: Validates workflow dependency mapping and SLA outage checks.
   - `test_optimization.py`: Validates Baseline, Greedy, and Google OR-Tools CP-SAT solvers.
   - `test_simulation_and_explanation.py`: Validates snapshot what-if simulation, residual path re-traversal, and decision explainer.
   - `test_governance_and_audit.py`: Validates 7-role state machine and cryptographic SHA-256 tamper detection.

2. **Integration Tests (`tests/integration/`):**
   - `test_api_endpoints.py`: End-to-end FastAPI endpoint validation, security headers, and report exports.

3. **Security Penetration Tests (`tests/security/`):**
   - `test_security_controls.py`: Cypher injection sanitization, role escalation denial, and security header checks.

4. **Performance & Scalability Benchmarks (`tests/performance/`):**
   - `test_performance_benchmarks.py`: Evaluates traversal latency and CP-SAT solver runtimes on 50-node and 250-node network topologies.

---

## 2. Test Execution & Assertion Evidence

All 36 automated tests pass deterministically:

```bash
pytest -v --strict-markers
======================== 36 passed in 6.36s ========================
```
