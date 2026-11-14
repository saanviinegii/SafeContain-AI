# SafeContain AI — System Architecture & Technical Specification

## 1. Executive Summary & Purpose

**SafeContain AI** is an enterprise-grade cybersecurity decision-support system designed to assist security operation centers (SOC), incident response teams, and chief information security officers (CISOs) in responding to multi-stage cyber threats.

Unlike traditional automated security orchestration tools that either blindly isolate critical assets (causing catastrophic citizen service or revenue outages) or delay action while waiting for manual forensics, SafeContain AI couples:
1. **Uncertainty-Aware Graph Reasoning**: Differentiating confirmed forensic telemetry from suspected and unknown lateral links with temporal confidence decay.
2. **Business Continuity Digital Twin**: Directly mapping IT assets and infrastructure dependencies to mission-critical business and citizen workflows.
3. **Rigorous Multiobjective Optimization**: Leveraging Google OR-Tools CP-SAT (Constraint Programming - Satisfiability) alongside Greedy and Severity-First baselines to minimize residual risk under strict budget and outage constraints.
4. **Isolated Simulation Sandbox**: Proving non-mutation of persistent topology while verifying residual attack routes before containment execution.
5. **Tamper-Evident Dual Audit Chaining**: Combining continuous SHA-256 hash-chained off-chain records with Solidity 0.8.20 EVM-compatible on-chain smart contract anchoring.
6. **Mandatory Human-in-the-Loop Governance**: Enforcing role-based access control (RBAC), separation of duties, and explicit human authorization before any defensive action can be executed.

---

## 2. Target Architecture Diagram

```
                              +---------------------------------------+
                              |      React 18 + TypeScript SPA        |
                              |   19 Operational Enterprise Views     |
                              |   Cytoscape.js Interactive Topology   |
                              +---------------------------------------+
                                                  |
                                                  | HTTPS / REST API
                                                  v
                              +---------------------------------------+
                              |          FastAPI Application          |
                              |   OWASP Security Headers Middleware   |
                              |   Pydantic Domain Validation          |
                              +---------------------------------------+
                                                  |
        +---------------------+-------------------+---------------------+---------------------+
        |                     |                   |                     |                     |
        v                     v                   v                     v                     v
+---------------+     +---------------+   +---------------+     +---------------+     +---------------+
| Neo4j AuraDB  |     |  NetworkX     |   | Google OR-    |     |  Business     |     | Dual Audit    |
| Dedicated     |     |  Simulation   |   | Tools CP-SAT  |     |  Continuity   |     | Chained Ledger|
| Graph Store   |     |  Sandbox      |   | Exact Solver  |     |  Digital Twin |     | & EVM Anchor  |
+---------------+     +---------------+   +---------------+     +---------------+     +---------------+
```

---

## 3. Core Graph Entity & Relationship Taxonomy

SafeContain AI normalizes heterogeneous enterprise telemetry into an enriched, directed property graph.

### 3.1 Node Entities

| Node Type | Description | Key Attributes |
| :--- | :--- | :--- |
| `USER` | Human operator, service account, or administrator | `id`, `name`, `department`, `privilege_level`, `is_compromised` |
| `DEVICE` | Physical or virtual endpoint running agent software | `id`, `name`, `ip_address`, `os`, `status`, `compromised` |
| `SERVER` | Workstation, application server, domain controller | `id`, `name`, `ip_address`, `criticality_tier`, `vulnerabilities` |
| `DATABASE` | Crown jewel data store (citizen DB, payment ledger) | `id`, `name`, `data_classification`, `criticality_tier` |
| `THREAT` | Identified adversary, malware campaign, or CVE exploit | `id`, `name`, `severity`, `threat_actor`, `technique_id` |
| `PERMISSION` | High-privilege access token or directory entitlement | `id`, `name`, `resource`, `action`, `risk_level` |
| `ALERT` | Security detection from SIEM, EDR, or IDS | `id`, `name`, `severity`, `signature`, `source_ip`, `target_ip` |
| `BUSINESS_WORKFLOW` | Mission-critical business or citizen service | `id`, `name`, `tier`, `max_allowable_outage_hours`, `hourly_cost` |

### 3.2 Directed Relationship Types

| Relationship | Source $\to$ Target | Meaning |
| :--- | :--- | :--- |
| `USES_DEVICE` | `User` $\to$ `Device` | Identity is authenticated and active on host |
| `HAS_ACCESS_TO` | `User` $\to$ `Server` / `Database` | Identity possesses active network or logical access |
| `CAN_ACCESS` | `Permission` $\to$ `Server` / `Database` | Directory permission grants execution or query rights |
| `CONNECTED_TO` | `Server` $\to$ `Server` / `Database` | Established network socket, route, or RPC channel |
| `GENERATED_ALERT` | `Server` / `Device` $\to$ `Alert` | Infrastructure node triggered a detection event |
| `SUPPORTS_WORKFLOW` | `Server` / `Database` $\to$ `BusinessWorkflow` | IT asset is an operational dependency of the workflow |

### 3.3 Evidence Certainty Tiers

Every graph relationship maintains forensic provenance:
- **`CONFIRMED`** ($c \in [0.85, 1.0]$): Directly substantiated by verifiable SIEM logs, EDR process trees, or Active Directory audit logs.
- **`SUSPECTED`** ($c \in [0.40, 0.84]$): Inferred from anomalous traffic patterns, heuristic heuristics, or unverified lateral attempts.
- **`UNKNOWN`** ($c \in [0.0, 0.39]$): Plausible lateral movement paths requiring verification.

---

## 4. Mathematical Risk & Optimization Formulation

### 4.1 Inherent Path Risk Formulation

For an attack path $P = (v_0, e_1, v_1, \dots, e_k, v_k)$ terminating at critical asset $v_k$:
$$\text{Risk}_{\text{inherent}}(P) = 100 \times \text{Impact}(v_k) \times \prod_{i=1}^k \text{Likelihood}(e_i)$$
Where:
- $\text{Impact}(v_k) \in [0.1, 1.0]$ is derived from the asset's criticality tier (Tier-1 Crown Jewel = 1.0).
- $\text{Likelihood}(e_i) \in [0.1, 1.0]$ represents edge traversability based on vulnerability severity and privileges.

### 4.2 Uncertainty Penalty & Temporal Decay

Evidence confidence decays over time according to:
$$c(t) = c_0 \cdot e^{-\lambda t}$$
Where $\lambda$ is the decay rate per day and $t$ is the age of the forensic telemetry in days.

For paths containing non-confirmed edges ($S \subset P$ where status $\neq$ `CONFIRMED`):
$$\text{UncertaintyPenalty}(P) = w_u \cdot \left(1.0 - \min_{e \in P} c(e)\right) \cdot \frac{|S|}{|P|} \cdot 100$$
$$\text{Risk}_{\text{adjusted}}(P) = \min(100.0, \text{Risk}_{\text{inherent}}(P) + \text{UncertaintyPenalty}(P))$$

### 4.3 Multiobjective CP-SAT Solver Formulation

Let $A = \{a_1, a_2, \dots, a_n\}$ be candidate containment actions. Let $x_j \in \{0, 1\}$ indicate selection of action $a_j$.

**Objective Function:**
$$\text{Maximize } Z = w_1 \sum_{j=1}^n \Delta R(a_j) x_j - w_2 \sum_{j=1}^n C(a_j) x_j - w_3 \sum_{j=1}^n D(a_j) x_j$$

**Subject to Constraints:**
1. **Budget Constraint**:
   $$\sum_{j=1}^n C(a_j) x_j \le B_{\text{max}}$$
2. **Tier-1 Zero Outage Invariance**:
   $$D(a_j) x_j = 0 \quad \forall j \text{ where } a_j \text{ impacts Tier-1 Workflow}$$
3. **Action Exclusivity / Conflicts**:
   $$x_j + x_k \le 1 \quad \forall (a_j, a_k) \in \text{Conflicts}$$

If no combination satisfies all constraints (e.g., $B_{\text{max}}$ is set below minimum feasible action cost), the solver returns a structured **Infeasible** explanation without crashing or fabricating greedy fallbacks.

---

## 5. Isolated Simulation & Verification Engine

Before proposing containment actions for human review:
1. An in-memory deep copy of the graph topology is created (`SimulationSandbox`).
2. Candidate containment actions are applied to the snapshot (nodes isolated, risky edges severed).
3. Attack path traversal algorithms re-execute on the snapshot.
4. Residual risk score and remaining uncontained paths are computed.
5. Impact on business workflows is verified.
6. A cryptographic SHA-256 fingerprint of the simulation state is anchored in the audit ledger.
7. **The persistent Neo4j graph remains 100% unaltered.**

---

## 6. Dual Cryptographic Audit & Blockchain Architecture

Conforming to R&D Blueprint Page 2 & 4:
- **Off-Chain Ledger**: High-throughput SHA-256 hash-chained JSONL records storing full execution context, user IDs, roles, timestamps, and full telemetry payloads.
- **On-Chain EVM Smart Contract (`SafeContainAuditLedger.sol`)**:
  - Stores only minimal immutable tuples:
    $$\text{Tuple} = (\text{Record ID}, \text{Cryptographic SHA-256 Hash}, \text{Timestamp}, \text{Event Type}, \text{Approval Reference})$$
  - Detailed telemetry and sensitive infrastructure topologies are never exposed on-chain.
- **Tamper Verification**:
  $$\text{Integrity}(E) = \begin{cases} \text{AUTHENTIC} & \text{if recomputed\_hash}(E) == \text{on\_chain\_hash}(E) \\ \text{TAMPER\_DETECTED} & \text{otherwise} \end{cases}$$
- **Foundational Limitation Notice**: Blockchain guarantees tamper evidence and ordering, not ground truth; false telemetry can still be recorded immutably.

---

## 7. Mandatory Human-in-the-Loop Governance

SafeContain AI does not automatically execute destructive containment actions in the physical environment.

### 7.1 Approval State Machine

```
[ DRAFT ] ---> [ ANALYZED ] ---> [ SIMULATED ] ---> [ PENDING_APPROVAL ]
                                                             |
                                         +-------------------+-------------------+
                                         |                                       |
                                         v                                       v
                                   [ APPROVED ]                            [ REJECTED ]
                                         |                                       |
                                         v                                       v
                             [ EXECUTION_AUTHORIZED ]                       [ DRAFT ]
```

### 7.2 Separation of Duties (RBAC Matrix)

| Role | Simulate | Submit for Review | Approve | Authorize Execution | View Audit |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `SOC_ANALYST` | Yes | Yes | No | No | Yes |
| `INCIDENT_RESPONDER` | Yes | Yes | No | No | Yes |
| `SECURITY_MANAGER` | Yes | Yes | Yes | Yes | Yes |
| `INCIDENT_COMMANDER` | Yes | Yes | Yes | Yes | Yes |
| `AUDITOR` | No | No | No | No | Yes |
| `READ_ONLY_VIEWER` | No | No | No | No | Yes |
