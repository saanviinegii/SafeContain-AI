"""SafeContain AI Primary REST API Router (v1).

Exposes full functional endpoints for graph intelligence, attack paths, evidence uncertainty,
decomposed risk, business twin, tri-level optimization, isolated simulation,
counterfactual explanation, multi-tier governance, and cryptographic audit.
"""

import json
import uuid
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.app.audit.ledger import AuditIntegrityReport, ChainedAuditLedger
from backend.app.business.twin import BusinessContinuityTwin
from backend.app.evidence.engine import EvidenceEngine, SensitivityScenarioResult
from backend.app.explanation.engine import DecisionExplainer
from backend.app.graph.engine import GraphEngine
from backend.app.ingestion.connectors import SyntheticScenarioGenerator
from backend.app.models.domain import (
    ApprovalStatus,
    AttackPath,
    AuditEvent,
    BusinessWorkflow,
    ContainmentAction,
    ContainmentPlan,
    GraphEdge,
    GraphNode,
    OptimizationStrategy,
    RiskDecomposition,
    SimulationResult,
    UserRole,
)
from backend.app.observability.metrics import MetricsCollector, SystemMetrics
from backend.app.optimization.solver import (
    BaselinePlanner,
    CPSATOptimizer,
    GreedyOptimizer,
    StrategyComparator,
)
from backend.app.planning.catalog import ActionCatalog
from backend.app.reporting.exporter import ReportExporter
from backend.app.risk.engine import RiskEngine
from backend.app.governance.workflow import GovernanceWorkflow
from backend.app.simulation.sandbox import SimulationSandbox

api_router = APIRouter()

# Global In-Memory State Container for Session Context
class PlatformContext:
    def __init__(self):
        self.engine = GraphEngine()
        self.twin = BusinessContinuityTwin()
        self.evidence_eng = EvidenceEngine()
        self.ledger = ChainedAuditLedger()
        self.current_plan: Optional[ContainmentPlan] = None
        self.last_simulation: Optional[SimulationResult] = None
        self.active_scenario_name = "Uninitialized (Clean State)"

platform_ctx = PlatformContext()


# =====================================================================
# SYSTEM & OBSERVABILITY ENDPOINTS
# =====================================================================

@api_router.get("/health", tags=["System"])
def health_check() -> Dict[str, Any]:
    """Liveness & readiness probe."""
    return {
        "status": "HEALTHY",
        "service": "SafeContain AI Enterprise Backend",
        "version": "1.0.0",
        "graph_backend": "live_neo4j" if platform_ctx.engine.is_neo4j_live else "in_memory_networkx",
        "audit_chain_length": len(platform_ctx.ledger._events),
    }


@api_router.get("/metrics", response_model=SystemMetrics, tags=["System"])
def get_metrics() -> SystemMetrics:
    """Exposes real-time operational and solver telemetry."""
    return MetricsCollector.get_metrics(platform_ctx.engine, platform_ctx.ledger)


# =====================================================================
# SCENARIO & INGESTION ENDPOINTS
# =====================================================================

@api_router.post("/scenario/load-synthetic", tags=["Ingestion"])
def load_synthetic_scenario(scenario_name: str = "Operation Sovereign Gateway") -> Dict[str, Any]:
    """Ingests and initializes the calibrated synthetic scenario with strict provenance labeling."""
    result = SyntheticScenarioGenerator.generate_national_gateway_scenario()
    platform_ctx.engine.clear()

    for node in result.nodes:
        platform_ctx.engine.add_node(node)
    for edge in result.edges:
        platform_ctx.engine.add_edge(edge)

    platform_ctx.twin.discover_dependencies_from_graph(platform_ctx.engine)
    platform_ctx.active_scenario_name = scenario_name
    MetricsCollector.record_ingestion(len(result.nodes) + len(result.edges))

    if platform_ctx.engine.is_neo4j_live:
        platform_ctx.engine.sync_to_neo4j()

    # Audit the ingestion
    platform_ctx.ledger.record_event(
        actor_id="soc-operator",
        actor_role=UserRole.SOC_ANALYST,
        action="LOAD_SYNTHETIC_SCENARIO",
        resource_type="SyntheticScenario",
        resource_id=scenario_name,
        metadata={
            "nodes_loaded": len(result.nodes),
            "edges_loaded": len(result.edges),
            "provenance": "SYNTHETIC",
        },
    )

    return {
        "message": f"Successfully loaded scenario '{scenario_name}'",
        "nodes_count": len(result.nodes),
        "edges_count": len(result.edges),
        "provenance": "SYNTHETIC",
    }


# =====================================================================
# GRAPH & ATTACK PATH ENDPOINTS
# =====================================================================

@api_router.get("/graph/topology", tags=["Graph Intelligence"])
def get_graph_topology() -> Dict[str, Any]:
    """Returns normalized infrastructure graph topology."""
    return platform_ctx.engine.export_topology()


@api_router.get("/graph/attack-paths", response_model=List[AttackPath], tags=["Graph Intelligence"])
def get_attack_paths() -> List[AttackPath]:
    """Discovers all directed attack paths from compromised nodes to crown jewels."""
    return platform_ctx.engine.find_attack_paths()


@api_router.get("/graph/neo4j/status", tags=["Graph Intelligence"])
def get_neo4j_connection_status() -> Dict[str, Any]:
    """Returns real-time connection status and entity counts for live Neo4j."""
    return platform_ctx.engine.get_neo4j_status()


@api_router.post("/graph/neo4j/sync", tags=["Graph Intelligence"])
def sync_topology_to_neo4j() -> Dict[str, Any]:
    """Flushes and synchronizes active graph topology into live Neo4j instance."""
    result = platform_ctx.engine.sync_to_neo4j()
    platform_ctx.ledger.record_event(
        actor_id="soc-admin",
        actor_role=UserRole.INCIDENT_COMMANDER,
        action="NEO4J_TOPOLOGY_SYNC",
        resource_type="GraphTopology",
        resource_id=f"neo4j-{settings.NEO4J_DATABASE}",
        metadata=result,
    )
    return result


@api_router.post("/graph/neo4j/load", tags=["Graph Intelligence"])
def load_topology_from_neo4j() -> Dict[str, Any]:
    """Imports topology from live Neo4j into in-memory traversal engine."""
    result = platform_ctx.engine.load_from_neo4j()
    platform_ctx.twin.discover_dependencies_from_graph(platform_ctx.engine)
    platform_ctx.ledger.record_event(
        actor_id="soc-admin",
        actor_role=UserRole.INCIDENT_COMMANDER,
        action="NEO4J_TOPOLOGY_IMPORT",
        resource_type="GraphTopology",
        resource_id=f"neo4j-{settings.NEO4J_DATABASE}",
        metadata=result,
    )
    return result


# =====================================================================
# EVIDENCE & RISK INTELLIGENCE ENDPOINTS
# =====================================================================

@api_router.get("/evidence/sensitivity", response_model=List[SensitivityScenarioResult], tags=["Evidence & Risk"])
def get_evidence_sensitivity() -> List[SensitivityScenarioResult]:
    """Evaluates sensitivity analysis under evidence drift (suspected -> confirmed / disputed)."""
    paths = platform_ctx.engine.find_attack_paths()
    return platform_ctx.evidence_eng.run_sensitivity_analysis(paths, platform_ctx.engine)


@api_router.get("/risk/decompose", response_model=RiskDecomposition, tags=["Evidence & Risk"])
def get_decomposed_risk() -> RiskDecomposition:
    """Computes transparent, factor-contributed decomposed risk metrics."""
    paths = platform_ctx.engine.find_attack_paths()
    return RiskEngine.decompose_system_risk(paths, platform_ctx.engine.get_all_nodes())


# =====================================================================
# BUSINESS CONTINUITY TWIN ENDPOINTS
# =====================================================================

@api_router.get("/business/workflows", response_model=List[BusinessWorkflow], tags=["Business Continuity"])
def get_business_workflows() -> List[BusinessWorkflow]:
    """Returns all monitored business and citizen service workflows."""
    return platform_ctx.twin.get_all_workflows()


# =====================================================================
# PLANNING & OPTIMIZATION ENDPOINTS
# =====================================================================

@api_router.get("/planning/candidates", response_model=List[ContainmentAction], tags=["Response Planning"])
def get_candidate_actions() -> List[ContainmentAction]:
    """Synthesizes valid candidate containment actions targeting active attack paths."""
    paths = platform_ctx.engine.find_attack_paths()
    nodes = {n.id: n for n in platform_ctx.engine.get_all_nodes()}
    return ActionCatalog.generate_candidate_actions(paths, nodes)


class OptimizeRequest(BaseModel):
    budget_limit: float = Field(default=10000.0, ge=100.0)
    strategy: OptimizationStrategy = OptimizationStrategy.CONSTRAINT_CPSAT


@api_router.post("/planning/optimize", tags=["Response Planning"])
def optimize_containment(req: OptimizeRequest) -> Dict[str, Any]:
    """Solves containment optimization and compares all 3 strategies on identical inputs."""
    paths = platform_ctx.engine.find_attack_paths()
    nodes = {n.id: n for n in platform_ctx.engine.get_all_nodes()}
    candidates = ActionCatalog.generate_candidate_actions(paths, nodes)

    comparison = StrategyComparator.compare(
        candidates, platform_ctx.twin, platform_ctx.engine, req.budget_limit
    )

    # Store active recommended plan
    if req.strategy == OptimizationStrategy.CONSTRAINT_CPSAT:
        platform_ctx.current_plan = CPSATOptimizer.plan(
            candidates, platform_ctx.twin, platform_ctx.engine, req.budget_limit
        )
    elif req.strategy == OptimizationStrategy.GREEDY_RISK_COST:
        platform_ctx.current_plan = GreedyOptimizer.plan(candidates, req.budget_limit)
    else:
        platform_ctx.current_plan = BaselinePlanner.plan(candidates, req.budget_limit)

    return comparison


# =====================================================================
# SIMULATION & DECISION EXPLANATION ENDPOINTS
# =====================================================================

class SimulationRequest(BaseModel):
    action_ids: Optional[List[str]] = None
    strategy: Optional[OptimizationStrategy] = None
    budget_limit: Optional[float] = None


@api_router.post("/simulation/run", response_model=SimulationResult, tags=["Simulation"])
def run_isolated_simulation(req: Optional[SimulationRequest] = None) -> SimulationResult:
    """Executes isolated snapshot simulation and verifies residual attack paths."""
    paths = platform_ctx.engine.find_attack_paths()
    nodes = {n.id: n for n in platform_ctx.engine.get_all_nodes()}
    candidates = ActionCatalog.generate_candidate_actions(paths, nodes)
    candidate_map = {a.id: a for a in candidates}

    target_plan: Optional[ContainmentPlan] = None

    if req and req.action_ids is not None:
        # Build plan with specifically requested containment actions
        selected_actions = [candidate_map[aid] for aid in req.action_ids if aid in candidate_map]
        total_cost = sum(a.implementation_cost for a in selected_actions)
        total_disruption = sum(a.operational_disruption_score for a in selected_actions)
        strat = req.strategy or (
            platform_ctx.current_plan.strategy if platform_ctx.current_plan else OptimizationStrategy.CONSTRAINT_CPSAT
        )
        target_plan = ContainmentPlan(
            id=f"plan-whatif-{uuid.uuid4().hex[:8]}",
            strategy=strat,
            actions=selected_actions,
            total_cost=total_cost,
            total_disruption_score=total_disruption,
            predicted_risk_reduction=sum(a.estimated_risk_reduction for a in selected_actions),
            predicted_residual_risk=0.0,
            satisfies_all_constraints=True,
            objective_score=1.0,
            status=ApprovalStatus.DRAFT,
            explanation=f"What-If custom simulation applying {len(selected_actions)} selected containment actions.",
        )
    elif req and req.strategy is not None:
        budget = req.budget_limit or 10000.0
        if req.strategy == OptimizationStrategy.CONSTRAINT_CPSAT:
            target_plan = CPSATOptimizer.plan(candidates, platform_ctx.twin, platform_ctx.engine, budget)
        elif req.strategy == OptimizationStrategy.GREEDY_RISK_COST:
            target_plan = GreedyOptimizer.plan(candidates, budget)
        else:
            target_plan = BaselinePlanner.plan(candidates, budget)
    elif platform_ctx.current_plan:
        target_plan = platform_ctx.current_plan
    else:
        target_plan = CPSATOptimizer.plan(candidates, platform_ctx.twin, platform_ctx.engine, 10000.0)

    platform_ctx.current_plan = target_plan

    sim_result = SimulationSandbox.simulate_containment_plan(
        target_plan, platform_ctx.engine, platform_ctx.twin
    )
    platform_ctx.current_plan.status = ApprovalStatus.SIMULATED
    platform_ctx.last_simulation = sim_result
    MetricsCollector.record_simulation()

    # Record simulation in audit ledger
    platform_ctx.ledger.record_event(
        actor_id="soc-analyst",
        actor_role=UserRole.SOC_ANALYST,
        action="RUN_ISOLATED_SIMULATION",
        resource_type="Simulation",
        resource_id=sim_result.simulation_id,
        metadata={
            "initial_risk": sim_result.initial_risk_score,
            "residual_risk": sim_result.residual_risk_score,
            "residual_paths": sim_result.residual_attack_path_count,
            "applied_actions": sim_result.applied_action_ids,
            "audit_hash": sim_result.audit_hash,
        },
    )

    return sim_result


@api_router.get("/explanation/recommendation", tags=["Decision Intelligence"])
def get_decision_explanation() -> Dict[str, Any]:
    """Generates mathematically grounded decision justification and counterfactual analysis."""
    if not platform_ctx.current_plan or not platform_ctx.last_simulation:
        run_isolated_simulation()

    # Create dummy alternative plan for comparison
    paths = platform_ctx.engine.find_attack_paths()
    nodes = {n.id: n for n in platform_ctx.engine.get_all_nodes()}
    candidates = ActionCatalog.generate_candidate_actions(paths, nodes)
    alt_baseline = BaselinePlanner.plan(candidates, 10000.0)

    explanation = DecisionExplainer.explain_recommendation(
        platform_ctx.current_plan, [alt_baseline], platform_ctx.last_simulation
    )
    return explanation


# =====================================================================
# GOVERNANCE & APPROVAL WORKFLOW ENDPOINTS
# =====================================================================

class GovernanceTransitionRequest(BaseModel):
    target_status: ApprovalStatus
    actor_id: str = "sec-manager-raj"
    actor_role: UserRole = UserRole.SECURITY_MANAGER
    notes: str = "Authorized containment plan post-simulation."
    rejection_reason: Optional[str] = None


@api_router.post("/governance/transition", tags=["Governance"])
def transition_plan_status(req: GovernanceTransitionRequest) -> Dict[str, Any]:
    """Transitions containment plan approval state machine with role enforcement."""
    if not platform_ctx.current_plan:
        raise HTTPException(status_code=400, detail="No active containment plan to transition.")

    try:
        updated_plan, decision = GovernanceWorkflow.transition_plan(
            plan=platform_ctx.current_plan,
            target_status=req.target_status,
            actor_id=req.actor_id,
            actor_role=req.actor_role,
            notes=req.notes,
            rejection_reason=req.rejection_reason,
        )
        platform_ctx.current_plan = updated_plan

        # Record in cryptographic audit ledger
        platform_ctx.ledger.record_event(
            actor_id=req.actor_id,
            actor_role=req.actor_role,
            action=f"TRANSITION_TO_{req.target_status.value}",
            resource_type="ContainmentPlan",
            resource_id=updated_plan.id,
            metadata={"notes": req.notes, "status": req.target_status.value},
        )

        return {
            "plan_id": updated_plan.id,
            "status": updated_plan.status.value,
            "decision": decision.model_dump(mode="json"),
        }
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))


# =====================================================================
# AUDIT & VERIFICATION ENDPOINTS
# =====================================================================

@api_router.get("/audit/ledger", response_model=List[AuditEvent], tags=["Audit"])
def get_audit_ledger(limit: int = 50) -> List[AuditEvent]:
    """Returns recent cryptographically chained audit records."""
    return platform_ctx.ledger.get_events(limit=limit)


@api_router.get("/audit/verify", response_model=AuditIntegrityReport, tags=["Audit"])
def verify_audit_integrity() -> AuditIntegrityReport:
    """Performs full forward cryptographic SHA-256 hash-chain verification."""
    return platform_ctx.ledger.verify_integrity()


# =====================================================================
# REPORTING & EXPORT ENDPOINTS
# =====================================================================

@api_router.get("/reports/export", tags=["Reporting"])
def export_incident_report(format: str = Query("json")) -> Any:
    """Exports canonical incident report dossier in requested format."""
    if format not in ("json", "csv", "text"):
        raise HTTPException(status_code=400, detail="Invalid format. Supported: 'json', 'csv', 'text'.")
    if not platform_ctx.current_plan or not platform_ctx.last_simulation:
        run_isolated_simulation()

    events = platform_ctx.ledger.get_events(limit=20)

    if format == "csv":
        csv_data = ReportExporter.generate_actions_csv(platform_ctx.current_plan)
        return {"format": "csv", "data": csv_data}
    elif format == "text":
        text_data = ReportExporter.generate_executive_text_summary(
            platform_ctx.active_scenario_name, platform_ctx.last_simulation, platform_ctx.current_plan
        )
        return {"format": "text", "data": text_data}
    else:
        json_data = ReportExporter.generate_incident_json(
            platform_ctx.active_scenario_name, platform_ctx.last_simulation, platform_ctx.current_plan, events
        )
        return {"format": "json", "data": json.loads(json_data)}
