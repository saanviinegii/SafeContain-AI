# REQUIREMENT TRACEABILITY MATRIX (RTM)
## SafeContain AI — Enterprise Cybersecurity Platform
**Document Version:** 1.0.0  
**Phase:** Phase 0 Baseline  
**Date:** October 30, 2026  

---

## 1. Traceability Mapping

| Req ID | Requirement Description | Master Prompt Section | Target Module | Architecture / Component | Verification Method | Acceptance Criteria |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **REQ-ING-01** | Multi-source telemetry ingestion with schema validation | Section 6 (Module A) | `backend/ingestion` | `DataConnector`, `SchemaValidator` | Unit & Integration Test | Ingests SIEM, EDR, IAM, Cloud feeds; rejects malformed input with structured errors. |
| **REQ-ING-02** | Synthetic scenario data generation clearly labeled | Section 6 (Module A) | `backend/ingestion` | `SyntheticScenarioGenerator` | Deterministic Scenario Test | Generates reproducible enterprise incident scenarios without fabricated real labels. |
| **REQ-GRP-01** | Normalized Neo4j graph model with constraints & indexing | Section 7 (Module B) | `backend/graph` | `Neo4jGraphModel`, `GraphSchema` | Schema Constraint Verification | Enforces entity uniqueness, typed edges, and indexed lookups on critical keys. |
| **REQ-GRP-02** | Resilient dual-engine architecture (Neo4j + NetworkX) | Section 7 (Module B) | `backend/graph` | `GraphEngineAdapter` | Dual-Engine Equivalence Test | Identical path traversal results across live Neo4j driver and in-memory engine. |
| **REQ-ATK-01** | Explainable directed attack path discovery | Section 8 (Module C) | `backend/analysis` | `AttackPathEngine` | Synthetic Graph Traversal Test | Identifies all reachable routes from compromise nodes to target crown jewels. |
| **REQ-ATK-02** | Alternative path detection & bottleneck identification | Section 8 (Module C) | `backend/analysis` | `PathBottleneckAnalyzer` | Multi-Route Topology Test | Discovers secondary lateral paths and common node cut-sets (choke points). |
| **REQ-UNC-01** | Five-state evidence model with confidence attribution | Section 9 (Module D) | `backend/evidence` | `EvidenceModel`, `ConfidenceScorer` | State Transition & Scoring Test | Explicit handling of `CONFIRMED`, `SUSPECTED`, `UNKNOWN`, `DISPUTED`, `STALE`. |
| **REQ-UNC-02** | Evidence sensitivity analysis (Drift & Uncertainty impact) | Section 9 (Module D) | `backend/evidence` | `SensitivityAnalyzer` | Monte Carlo / Perturbation Test | Quantifies plan stability when suspected evidence is confirmed or invalidated. |
| **REQ-RSK-01** | Decomposed mathematical risk engine | Section 10 (Module E) | `backend/risk` | `DecomposedRiskEngine` | Mathematical Proof & Unit Tests | Separates Inherent, Observed, Residual, and Uncertainty-Adjusted risk metrics. |
| **REQ-BCN-01** | Business Continuity Digital Twin with workflow dependencies | Section 11 (Module F) | `backend/business` | `BusinessContinuityTwin` | Dependency Impact Matrix Test | Computes downtime, citizen service impact, and revenue loss per intervention. |
| **REQ-OPT-01** | Action catalog with cost, reversibility, & impact models | Section 12 (Module G) | `backend/planning` | `ActionCatalog` | Action Model Tests | 11 action types with formal preconditions, costs, and reversibility flags. |
| **REQ-OPT-02** | Tri-level optimization strategies (Baseline, Greedy, CP-SAT)| Section 12 (Module G) | `backend/optimization` | `BaselinePlanner`, `GreedyOptimizer`, `CPSATOptimizer` | Comparative Benchmark Test | Solves containment within budget and zero-downtime workflow constraints. |
| **REQ-SIM-01** | Isolated snapshot graph simulation | Section 13 (Module H) | `backend/simulation` | `IsolatedSimulationSandbox` | Graph Immutability Assertion | Proves zero mutations occur on the production/baseline graph instance. |
| **REQ-RES-01** | Residual path verification post-containment | Section 14 (Module I) | `backend/simulation` | `ResidualRiskVerifier` | Choke-Point Verification Test | Re-traverses graph to verify that blocking one path didn't leave open alternatives. |
| **REQ-EXP-01** | Grounded explainable decision & counterfactual analysis | Section 15 (Module J) | `backend/explanation`| `DecisionExplainer` | Counterfactual Difference Test | Explains mathematical trade-offs without hallucinated LLM scores. |
| **REQ-GOV-01** | Multi-tier RBAC & Human-in-the-Loop approval lifecycle | Section 16 (Module K) | `backend/governance` | `RBACManager`, `ApprovalWorkflow` | State Machine & Permission Test | Enforces DRAFT $\to$ SIMULATED $\to$ PENDING $\to$ APPROVED $\to$ AUTH. |
| **REQ-AUD-01** | Cryptographic SHA-256 chained tamper-evident audit ledger | Section 17 (Module L) | `backend/audit` | `ChainedAuditLedger` | Tamper Injection Verification | Detects modification of any historical record via broken hash chain. |
| **REQ-SEC-01** | Hardened security controls, sanitization, & tenant isolation| Section 18 (Module M) | `backend/security` | `SecurityMiddleware`, `AuthHandler` | Vulnerability & Injection Tests | Protects against injection, unauthorized tenant access, and timing attacks. |
| **REQ-UI-01**  | Enterprise operations console (19 specialized views) | Section 19 (Module N) | `frontend/src` | React + TypeScript + Cytoscape | Browser Test / Cypress / Jest | Comprehensive interactive views with rich dark mode and zero fake numbers. |
| **REQ-REP-01** | Structured reproducible reporting (PDF, CSV, JSON) | Section 20 (Module O) | `backend/reporting` | `ReportGenerator` | Export Verification Test | Generates verifiable incident, simulation, and audit export packages. |
| **REQ-OBS-01** | Production observability, metrics, & structured logging | Section 21 (Module P) | `backend/observability`| `MetricsCollector`, `StructuredLogger` | Telemetry Benchmark Test | Exposes Prometheus `/metrics` and structured JSON logs with trace IDs. |
| **REQ-TST-01** | Full test coverage (Unit, Integration, Security, Perf) | Section 22 (Module Q) | `tests/` | Pytest & Vitest Suites | Continuous Integration Execution | Comprehensive test suite covering all modules with deterministic assertions. |
