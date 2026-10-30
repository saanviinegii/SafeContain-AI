# TECHNICAL DESIGN DOCUMENT (TDD)
## SafeContain AI — Enterprise Cybersecurity Platform
**Document Version:** 1.0.0  
**Module:** Core Engine Design & Mathematical Formulations  

---

## 1. Mathematical Models & Formulations

### 1.1 Decomposed Risk Model
Systemic cyber risk is decomposed into transparent, un-hallucinated factors:

$$\text{Risk}_{\text{adjusted}} = \min\left(100.0, \, R_{\text{observed}} + 0.5 \cdot (R_{\text{potential}} - R_{\text{observed}}) + \Omega_{\text{uncertainty}}\right)$$

Where:
- $R_{\text{observed}}$ is the peak risk calculated exclusively across paths supported by confirmed telemetry ($C_e \ge 0.8$).
- $R_{\text{potential}}$ is the peak risk including suspected routes ($C_e < 0.8$).
- $\Omega_{\text{uncertainty}}$ is the uncertainty penalty:
  $$\Omega_{\text{uncertainty}} = \frac{1}{|P|} \sum_{p \in P} \left( k_{\text{uncertain\_edges}} \cdot w_{\text{penalty}} \cdot 10.0 \right)$$
- Path inherent risk is attenuated by hop distance to model lateral friction:
  $$\text{PathRisk}(p) = \text{Criticality}(\text{Target}) \times 100.0 \times \left(\frac{1}{1 + 0.1 \cdot (\text{Hops} - 1)}\right)$$

### 1.2 Temporal Evidence Confidence Decay
Confidence in un-refreshed telemetry decays exponentially over time:

$$C(t) = C_0 \cdot \exp(-\lambda \cdot t_{\text{days}})$$

Where $\lambda = 0.05$ (configurable in `Settings.CONFIDENCE_DECAY_RATE_PER_DAY`). When elapsed time exceeds 72 hours, the edge status transitions to `EvidenceStatus.STALE`.

### 1.3 Exact Constraint-Based Optimization (CP-SAT Formulation)
The response containment problem is formulated as a 0-1 Integer Linear Programming (ILP) problem:

$$\text{Maximize} \quad \sum_{i=1}^N \left( 100 \cdot \Delta R_i - 0.1 \cdot C_i - 20 \cdot D_i \right) \cdot x_i$$

Subject to:
1. **Containment Budget Constraint:**
   $$\sum_{i=1}^N C_i \cdot x_i \le B_{\text{max}}$$
2. **Critical Citizen Service SLA Constraint:**
   $$\forall i \in \{1 \dots N\}, \quad \text{if } \text{ViolatesSLA}(a_i) = \text{True} \implies x_i = 0$$
3. **Binary Integrality Constraint:**
   $$x_i \in \{0, 1\} \quad \forall i \in \{1 \dots N\}$$

---

## 2. Core Service Interfaces & Signatures

### GraphEngine (`backend.app.graph.engine.GraphEngine`)
- `add_node(node: GraphNode) -> None`
- `add_edge(edge: GraphEdge) -> None`
- `clone_isolated_snapshot() -> GraphEngine`
- `find_attack_paths(max_depth: int) -> List[AttackPath]`
- `remove_edge(edge_id: str) -> bool`

### BusinessContinuityTwin (`backend.app.business.twin.BusinessContinuityTwin`)
- `discover_dependencies_from_graph(engine: GraphEngine) -> None`
- `assess_action_disruption(action: ContainmentAction, engine: GraphEngine) -> List[WorkflowDisruptionAssessment]`
- `assess_plan_disruption(actions: List[ContainmentAction], engine: GraphEngine) -> List[WorkflowDisruptionAssessment]`

### SimulationSandbox (`backend.app.simulation.sandbox.SimulationSandbox`)
- `simulate_containment_plan(plan: ContainmentPlan, baseline_engine: GraphEngine, twin: BusinessContinuityTwin) -> SimulationResult`

### ChainedAuditLedger (`backend.app.audit.ledger.ChainedAuditLedger`)
- `record_event(actor_id: str, actor_role: UserRole, action: str, resource_type: str, resource_id: str, metadata: dict) -> AuditEvent`
- `verify_integrity() -> AuditIntegrityReport`
