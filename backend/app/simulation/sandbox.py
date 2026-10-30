"""SafeContain AI Isolated Response Simulation Sandbox.

Guarantees strict isolation (Principle #9 & #10):
- Interventions are evaluated ONLY on an isolated graph copy.
- The original infrastructure graph is NEVER mutated.
- Residual attack paths are unconditionally re-verified post-containment (Principle #12).
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from backend.app.business.twin import BusinessContinuityTwin
from backend.app.graph.engine import GraphEngine
from backend.app.models.domain import (
    AttackPath,
    ContainmentAction,
    ContainmentPlan,
    RiskDecomposition,
    SecurityActionType,
    SimulationResult,
    WorkflowDisruptionAssessment,
)
from backend.app.risk.engine import RiskEngine


class SimulationSandbox:
    """Forensically isolated simulation sandbox."""

    @classmethod
    def simulate_containment_plan(
        cls,
        plan: ContainmentPlan,
        baseline_engine: GraphEngine,
        twin: BusinessContinuityTwin,
        scenario_id: str = "SCENARIO-CURRENT"
    ) -> SimulationResult:
        """Executes a what-if containment simulation on a cloned graph snapshot."""
        # Step 1: Capture pre-intervention baseline attack paths and risk
        initial_paths = baseline_engine.find_attack_paths()
        initial_risk_decomp = RiskEngine.decompose_system_risk(
            initial_paths, baseline_engine.get_all_nodes()
        )
        initial_risk = initial_risk_decomp.uncertainty_adjusted_risk

        # Step 2: Create isolated simulation snapshot (Deep Clone)
        sim_engine = baseline_engine.clone_isolated_snapshot()

        # Step 3: Apply containment interventions to snapshot ONLY
        applied_action_ids: List[str] = []
        for action in plan.actions:
            applied_action_ids.append(action.id)
            target_nid = action.target_node_id

            # Endpoint / Server isolation -> Sever all incident and outgoing edges
            if action.action_type in (
                SecurityActionType.ISOLATE_ENDPOINT,
                SecurityActionType.RESTRICT_NETWORK,
                SecurityActionType.DISABLE_ACCOUNT,
                SecurityActionType.REVOKE_SESSION,
            ):
                # Identify all incident edges to target node in snapshot
                edges_to_sever = [
                    e.id for e in sim_engine.get_all_edges()
                    if (e.source == target_nid or e.target == target_nid) and e.is_active
                ]
                for eid in edges_to_sever:
                    sim_engine.remove_edge(eid)

            # Targeted ACL / Resource restriction
            elif action.action_type in (
                SecurityActionType.APPLY_FIREWALL_RULE,
                SecurityActionType.RESTRICT_RESOURCE_ACCESS,
            ):
                edges_to_sever = [
                    e.id for e in sim_engine.get_all_edges()
                    if e.target == target_nid and e.is_active
                ]
                for eid in edges_to_sever:
                    sim_engine.remove_edge(eid)

        # Step 4: Re-discover attack paths on the simulated post-containment graph
        # This directly satisfies Core Module I (Residual Path Verification)
        residual_paths = sim_engine.find_attack_paths()
        for p in residual_paths:
            p.is_residual = True

        # Step 5: Recalculate residual risk
        residual_risk_decomp = RiskEngine.decompose_system_risk(
            residual_paths, sim_engine.get_all_nodes()
        )
        residual_risk = residual_risk_decomp.uncertainty_adjusted_risk
        risk_reduction = max(0.0, round(initial_risk - residual_risk, 2))

        # Step 6: Recalculate business workflow disruption
        disrupted_workflows = twin.assess_plan_disruption(plan.actions, baseline_engine)

        # Step 7: Identify unprotected crown jewels
        crown_jewels = [n.id for n in baseline_engine.get_all_nodes() if n.is_crown_jewel]
        unprotected_targets = set(p.target_id for p in residual_paths if p.target_id in crown_jewels)

        is_fully_contained = len(residual_paths) == 0

        # Step 8: Generate plain-language explanation
        explanation = (
            f"Simulation applied {len(applied_action_ids)} actions. "
            f"Initial paths: {len(initial_paths)}, Residual paths remaining: {len(residual_paths)}. "
            f"Risk reduced from {initial_risk:.1f} to {residual_risk:.1f} (-{risk_reduction:.1f}). "
            f"{'Threat is completely contained.' if is_fully_contained else f'WARNING: Threat is partially contained; {len(residual_paths)} residual paths remain.'}"
        )

        # Step 9: Compute deterministic cryptographic audit hash of simulation
        sim_id = f"sim-{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)
        audit_payload = {
            "simulation_id": sim_id,
            "scenario_id": scenario_id,
            "applied_actions": applied_action_ids,
            "initial_risk": initial_risk,
            "residual_risk": residual_risk,
            "residual_paths_count": len(residual_paths),
            "timestamp": now.isoformat(),
        }
        audit_hash = hashlib.sha256(json.dumps(audit_payload, sort_keys=True).encode()).hexdigest()

        return SimulationResult(
            simulation_id=sim_id,
            scenario_id=scenario_id,
            timestamp=now,
            applied_action_ids=applied_action_ids,
            initial_attack_path_count=len(initial_paths),
            residual_attack_path_count=len(residual_paths),
            initial_risk_score=initial_risk,
            residual_risk_score=residual_risk,
            risk_reduction_achieved=risk_reduction,
            disrupted_workflows=disrupted_workflows,
            residual_paths=residual_paths,
            unprotected_crown_jewels=list(unprotected_targets),
            is_fully_contained=is_fully_contained,
            explanation=explanation,
            audit_hash=audit_hash,
        )
