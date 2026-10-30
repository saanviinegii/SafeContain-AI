# KNOWN LIMITATIONS & OPERATIONAL BOUNDARIES
## SafeContain AI — Disclosure of System Constraints & Assumptions
**Document Version:** 1.0.0  

---

## 1. Disclosed Operational Constraints

In accordance with Non-Negotiable Principle #4, #18, and #20: SafeContain AI explicitly discloses all technical boundaries, assumptions, and unimplemented live integrations:

1. **Non-Destructive Simulation Boundaries:**  
   The platform operates in **simulation-only mode**. It generates, optimizes, simulates, and explains containment plans. It does **not** push direct active API mutations to external firewalls or cloud providers (e.g. AWS Security Groups, CrowdStrike quarantine APIs) without an external, authorized SOAR execution gateway.
2. **Neo4j Dual-Engine Behavior:**  
   If an external Neo4j Bolt daemon (`bolt://localhost:7687`) is offline or unreachable, the system transparently utilizes its in-memory NetworkX directed multigraph engine. While algorithmic outcomes (path discovery, choke points, isolated simulations) are identical, massive graph topologies exceeding $10^5$ nodes benefit significantly from persistent Neo4j indexing.
3. **Synthetic Telemetry Transparency:**  
   The pre-packaged "Operation Sovereign Gateway" scenario is calibrated synthetic data. Nodes and edges are strictly labeled with `DataProvenance.SYNTHETIC` to ensure analysts and evaluators never mistake demonstration scenarios for live government infrastructure.
4. **Epistemic Probability Calibration:**  
   Confidence scores represent sensor corroboration and evidence freshness. They should be calibrated against an organization's specific false-positive rates rather than treated as absolute Bayesian likelihoods.
