# SafeContain AI — Synthetic Enterprise Dataset Documentation

**Location:** `backend/data/synthetic_enterprise/`  
**Version:** 2.0.0  
**Data Provenance:** Strict Synthetic / Reserved Fictional (RFC 1918 Private Addressing)  
**Target Graph Architecture:** Dual Engine (Neo4j AuraDB persistent cloud + NetworkX in-memory fallback)

---

## 1. Dataset Purpose & Executive Context

The **SafeContain AI Synthetic Enterprise Dataset** is an interconnected benchmark cybersecurity dataset specifically engineered for graph-based decision intelligence, uncertainty-aware containment planning, and business continuity optimization.

It models a multi-tiered corporate and production cloud infrastructure subject to realistic lateral movement attack vectors, credential pivots, vulnerable services, and mission-critical payment workflows.

### Strict Safety & Synthetic Attribution Notice
- All entity identifiers (`node-*`, `usr-*`, `ast-*`, `alrt-*`) are synthetic and reserved exclusively for simulation.
- IP addresses use RFC 1918 private subnets (`10.100.0.0/16`, `10.200.0.0/16`, `192.168.1.0/24`).
- All employee names, hostnames, and credentials are fictional.
- Defensive containment actions are **simulation-only** and do not execute destructive operations against real infrastructure.

---

## 2. Catalog of the 12 Interconnected CSV Files

| File Name | Record Count | Description | Primary Key | Key Foreign Keys |
|---|---|---|---|---|
| **`nodes.csv`** | 120 | Infrastructure, identity, network, and application entities | `node_id` | N/A |
| **`relationships.csv`** | 285 | Directed topological edges, permissions, and dependencies | `relationship_id` | `source_id`, `target_id` $\to$ `nodes.csv` |
| **`assets.csv`** | 35 | Mission-critical enterprise assets & CIA classification | `asset_id` | `node_id` $\to$ `nodes.csv` |
| **`users.csv`** | 30 | Identity accounts, roles, privileges, and MFA statuses | `user_id` | `node_id` $\to$ `nodes.csv` |
| **`vulnerabilities.csv`** | 45 | CVEs and synthetic vulnerabilities affecting assets | `vulnerability_id` | `asset_id` $\to$ `assets.csv` |
| **`security_alerts.csv`** | 60 | Telemetry detections from EDR, SIEM, and CloudTrail | `alert_id` | `source_node_id`, `target_node_id` $\to$ `nodes.csv` |
| **`evidence.csv`** | 75 | Forensic artifacts with uncertainty confidence labels | `evidence_id` | `related_node_id` $\to$ `nodes.csv` |
| **`attack_paths.csv`** | 32 | Verified multi-hop traversal sequences to crown jewels | `attack_path_id` | `entry_node_id`, `target_node_id` $\to$ `nodes.csv` |
| **`interventions.csv`** | 45 | Candidate defensive interventions (isolation, revokes) | `intervention_id` | `target_node_id` $\to$ `nodes.csv` |
| **`asset_dependencies.csv`** | 60 | Cross-asset operational and data-flow dependencies | `dependency_id` | `source_asset_id`, `dependent_asset_id` $\to$ `assets.csv` |
| **`business_impact.csv`** | 35 | Financial loss ($/hr), RTO, RPO, and SLA impact tiers | `impact_id` | `asset_id` $\to$ `assets.csv` |
| **`threat_scenarios.csv`** | 10 | Complete end-to-end evaluation demonstration scenarios | `scenario_id` | `entry_node_id`, `target_node_id` $\to$ `nodes.csv` |

---

## 3. Schema & Identifier Conventions

- **Nodes:** `node-<type>-<descriptor>` (e.g., `node-user-marcus`, `node-srv-jumpbox01`, `node-db-customer-core`).
- **Relationships:** `rel-<number:04d>` (e.g., `rel-0001` through `rel-0285`).
- **Assets:** `ast-<number:03d>` (e.g., `ast-001` through `ast-035`).
- **Users:** `usr-<number:03d>` (e.g., `usr-001` through `usr-030`).
- **Vulnerabilities:** `vuln-<number:03d>` (e.g., `vuln-001` through `vuln-045`).
- **Alerts:** `alrt-<number:03d>` (e.g., `alrt-001` through `alrt-060`).
- **Evidence:** `ev-<number:03d>` (e.g., `ev-001` through `ev-075`).
- **Attack Paths:** `path-<number:03d>` (e.g., `path-001` through `path-032`).
- **Interventions:** `act-<number:03d>` (e.g., `act-001` through `act-045`).
- **Dependencies:** `dep-<number:03d>` (e.g., `dep-001` through `dep-060`).
- **Impacts:** `imp-<number:03d>` (e.g., `imp-001` through `imp-035`).
- **Scenarios:** `SCEN-<number:03d>` (e.g., `SCEN-001` through `SCEN-010`).

---

## 4. Primary Judge Demonstration Scenarios

### Scenario 1: Compromised Developer Account to Customer PII Database (`SCEN-001`)
- **Adversary Entry:** `node-user-marcus` (`node-ep-laptop-marcus`)
- **Compromise Vector:** Drive-by phishing payload extracts cached SSH private keys from memory.
- **Traversal Path:**
  $$\text{Marcus Laptop} \xrightarrow{\text{SSH Key}} \text{Jumpbox Bastion 01} \xrightarrow{\text{Admin Tunnel}} \text{Payment Gateway Microservice} \xrightarrow{\text{DB Pool}} \text{Customer Core PII DB}$$
- **The Optimization Dilemma:**
  - *Disruptive Action (`act-003`):* Sever Payment Gateway firewall. Eliminates attack path but causes **$120,000/hr downtime outage** on citizen payments!
  - *SafeContain AI Recommendation (`act-001` + `act-002`):* EDR isolate Marcus laptop + disable Okta user session. Achieves **95% risk reduction** at **$2,000 cost** and **$0 workflow disruption**.

### Scenario 2: Perimeter Web Exploit to Sovereign Identity Vault (`SCEN-002`)
- **Adversary Entry:** `node-net-fw-perimeter`
- **Traversal:** `Perimeter FW` $\to$ `Public Web Portal` $\to$ `API Gateway` $\to$ `SSO Engine` $\to$ `Identity Vault DB`.
- **Mitigation:** Deploy WAF rate limit rule + microsegmentation drop rule.

### Scenario 3: Cloud CI/CD Supply Chain to Payment Ledger (`SCEN-003`)
- **Adversary Entry:** `node-user-svc-cicd`
- **Traversal:** `GitLab SCM` $\to$ `K8s Master Node` $\to$ `AWS SuperAdmin Role` $\to$ `S3 Data Lake` $\to$ `Payment Ledger DB`.
- **Mitigation:** Cloud IAM boundary policy revocation without container downtime.

---

## 5. Execution Procedures

### 5.1 Validation
To run the automated data integrity validator:
```bash
python -m backend.app.ingestion.dataset_validator
```
Expected output: `Validation Status: PASSED` (Zero foreign key violations, zero orphan edges).

### 5.2 Importing into Active Graph Engine
To import the dataset and load Scenario 1:
```bash
python -m backend.scripts.import_synthetic_dataset SCEN-001
```

### 5.3 Resetting the Graph
To clear and restore the baseline scenario:
```bash
python -c "from backend.app.api.v1.router import platform_ctx; platform_ctx.engine.clear(); print('Graph reset.')"
```
Or via REST API:
```http
POST /api/v1/dataset/reset
```
