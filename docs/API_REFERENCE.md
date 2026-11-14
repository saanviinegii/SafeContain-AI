# SafeContain AI — REST API Reference Manual

The SafeContain AI backend provides a comprehensive, typed REST API conforming to OpenAPI 3.0 / Swagger specifications. All endpoints are mounted under the `/api/v1` namespace.

---

## 1. System & Observability

### `GET /api/v1/health`
Liveness and readiness health probe.
- **Response `200`**:
  ```json
  {
    "status": "HEALTHY",
    "service": "SafeContain AI Enterprise Backend",
    "version": "1.0.0",
    "graph_backend": "live_neo4j",
    "audit_chain_length": 18
  }
  ```

### `GET /api/v1/metrics`
Real-time operational, solver latency, and memory telemetry.
- **Response `200`**:
  ```json
  {
    "uptime_seconds": 342.1,
    "active_nodes_count": 14,
    "active_edges_count": 16,
    "cpsat_last_runtime_ms": 12.4,
    "total_simulations_executed": 3,
    "audit_chain_length": 18
  }
  ```

---

## 2. Ingestion & Synthetic Scenarios

### `GET /api/v1/ingestion/connectors`
Lists all registered enterprise security connectors and deduplication statistics.
- **Response `200`**: List of connector descriptors (`Splunk_SIEM`, `CrowdStrike_Falcon`, `ActiveDirectory_IAM`, `SyntheticScenarioGenerator`).

### `POST /api/v1/ingestion/siem`
Ingests raw SIEM security alerts with SHA-256 deduplication and schema validation.
- **Request Body**:
  ```json
  [
    {
      "alert_id": "siem-alert-101",
      "title": "Suspicious PowerShell Invocations",
      "severity": 0.85,
      "source_ip": "10.0.1.15",
      "target_ip": "10.0.3.50",
      "signature": "MITRE-T1059.001"
    }
  ]
  ```

### `POST /api/v1/ingestion/edr`
Ingests endpoint detection and response telemetry with host agent status.

### `POST /api/v1/ingestion/iam`
Ingests directory permissions, access entitlements, and identity roles.

### `POST /api/v1/scenario/load-synthetic?scenario_name=...`
Ingests the national gateway scenario with compromised identity, crown jewel databases, multi-route attack paths, and dual citizen workflows.

---

## 3. Graph Intelligence & Neo4j Service

### `GET /api/v1/graph/topology`
Returns normalized infrastructure graph topology (nodes, edges, node types, certainty tiers).

### `GET /api/v1/graph/attack-paths`
Discovers all viable paths from compromised sources to critical crown jewels with adjusted risk scores and choke-point nodes.

### `GET /api/v1/graph/neo4j/status`
Returns connectivity status to Neo4j AuraDB.

### `GET /api/v1/graph/neo4j/statistics`
Returns Neo4j database statistics, label counts, relationship counts, and constraint states.

### `POST /api/v1/graph/neo4j/sync`
Persists active in-memory topology to live Neo4j AuraDB.

### `POST /api/v1/graph/neo4j/load`
Imports persistent topology from Neo4j AuraDB into the traversal engine.

---

## 4. Evidence & Risk Intelligence

### `GET /api/v1/evidence/sensitivity`
Performs sensitivity analysis on lateral movement paths under hypothetical evidence state flips (`SUSPECTED` $\to$ `CONFIRMED` or `DISPUTED`).

### `GET /api/v1/risk/decompose`
Calculates transparent risk factor decomposition:
- `inherent_risk`
- `observed_risk`
- `potential_risk`
- `residual_risk`
- `uncertainty_penalty`
- `contributing_factors`

---

## 5. Business Continuity Digital Twin

### `GET /api/v1/business/workflows`
Returns all monitored business and citizen service workflows (`wf-national-identity-auth`, `wf-payment-clearing-switch`), dependencies, criticality tiers, and maximum allowable outages.

---

## 6. Planning & Optimization

### `GET /api/v1/planning/candidates`
Synthesizes valid candidate containment actions targeting active attack paths (`ISOLATE_HOST`, `REVOKE_USER_ACCESS`, `TERMINATE_PROCESS`, `APPLY_FIREWALL_RULE`).

### `POST /api/v1/planning/optimize`
Solves containment optimization and compares all 3 strategies on identical inputs.
- **Request Body**:
  ```json
  {
    "budget_limit": 10000.0,
    "strategy": "CONSTRAINT_CPSAT"
  }
  ```
- **Response `200`**: Strategy comparison metrics across Greedy baseline, Severity baseline, and CP-SAT exact solver.

---

## 7. Simulation & Decision Explanation

### `POST /api/v1/simulation/run`
Executes isolated snapshot simulation and verifies residual attack paths.
- **Request Body (Optional What-If Custom Simulation)**:
  ```json
  {
    "action_ids": ["act-001", "act-003"],
    "strategy": "CONSTRAINT_CPSAT",
    "budget_limit": 10000.0
  }
  ```
- **Response `200`**: Complete `SimulationResult` containing residual attack paths, workflow disruptions, and SHA-256 simulation audit hash.

### `GET /api/v1/explanation/recommendation`
Generates mathematically grounded decision justification, counterfactual analysis, model assumptions, verification steps, and rollback guidance.

---

## 8. Governance & Auditing

### `POST /api/v1/governance/transition`
Transitions containment plan approval state machine with role enforcement.
- **Request Body**:
  ```json
  {
    "target_status": "PENDING_APPROVAL",
    "actor_id": "soc-analyst-1",
    "actor_role": "SOC_ANALYST",
    "notes": "Containment verified via simulation."
  }
  ```

### `GET /api/v1/audit/ledger?limit=50`
Returns recent cryptographically chained audit records.

### `GET /api/v1/audit/verify`
Performs forward SHA-256 hash-chain verification and returns integrity report.

### `GET /api/v1/audit/blockchain/status`
Returns smart contract ledger status, block height, and on-chain record count.

### `POST /api/v1/audit/blockchain/verify?event_id=...`
Recomputes off-chain record hash and verifies against smart contract anchor.

---

## 9. Reporting & Export

### `GET /api/v1/reports/export?format=json|csv|text`
Exports canonical forensic incident dossier in JSON, CSV, or executive text briefing format.
