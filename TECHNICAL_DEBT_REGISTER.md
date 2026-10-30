# TECHNICAL DEBT REGISTER & ARCHITECTURAL RISK LOG
## SafeContain AI — Enterprise Cybersecurity Platform
**Document Version:** 1.0.0  
**Phase:** Phase 0 Baseline  
**Date:** October 30, 2026  

---

## 1. Identified Technical Debt & Environmental Risks

| Debt ID | Category | Description | Severity | Impact | Mitigation Strategy |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **DEBT-01** | **Host Services** | Docker daemon is not installed in host PATH. | High | Cannot execute `docker compose up` directly on the host during local dev. | Provide native dual-mode execution (direct Python virtualenv/Node scripts) and supply certified `Dockerfile` + `docker-compose.yml` for containerized environments. |
| **DEBT-02** | **Graph Storage** | Neo4j server daemon is not currently active on local port 7687. | High | System could fail to start if tightly coupled exclusively to a live Bolt connection. | Architect a unified `GraphEngine` interface that transparently operates with live Neo4j Cypher when reachable, and falls back to a high-performance in-memory graph engine with identical semantics. |
| **DEBT-03** | **Python Compatibility** | Python 3.14.8 is a very recent release; binary wheels for complex solvers (like Google OR-Tools CP-SAT) may encounter platform build nuances. | Medium | If `pip install ortools` fails or lacks prebuilt wheels, optimization engine could break. | Test `ortools` installation immediately. Implement an exact, constraint-satisfaction branch-and-bound solver in pure Python as a zero-dependency fallback matching CP-SAT formulation. |
| **DEBT-04** | **Uncertainty Fallacy** | Risk engines frequently treat heuristic weights as Bayesian probabilities without calibration. | Critical | Misleads incident responders into false precision. | Formalize uncertainty using Dempster-Shafer or calibrated confidence bounds; document explicit limitations and separate evidence status from inherent risk. |
| **DEBT-05** | **Graph Mutation Leakage**| Naive graph simulations modify the production graph in-place and attempt to "rollback" changes. | Critical | Partial failure during simulation corrupts the operational ground truth. | Mandate isolated immutable snapshots. Every simulation instantiates an independent graph clone in memory or a dedicated simulation transaction context. |
| **DEBT-06** | **Audit Tampering** | Audit records stored in standard relational tables without cryptographic chaining can be altered by database admins. | High | Inadmissible in legal or government forensic audits. | Implement cryptographic SHA-256 hash chaining where each event includes `previous_hash` and `signature`, verified via automated integrity audits. |
| **DEBT-07** | **Synthetic Bias** | Demo platforms mix synthetic mock data with real feeds without clear provenance markers. | High | Operators or auditors cannot distinguish between actual threats and test benchmarks. | Enforce strict `data_provenance: SYNTHETIC | LIVE_TELEMETRY | REPLAY` tagging on every node, edge, and incident event in the system. |

---

## 2. Review and Remediation Lifecycle

All debt items will be tracked through the sequential execution phases. No phase will be marked complete until its corresponding debt items have been resolved or mitigated with automated tests.
