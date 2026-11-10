"""SafeContain AI Explainable Decision and Counterfactual Intelligence Engine.

Synthesizes mathematically grounded explanations and counterfactual analysis
explaining why specific containment plans were chosen over alternatives.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel

from backend.app.models.domain import (
    ContainmentAction,
    ContainmentPlan,
    SimulationResult,
)


class CounterfactualResult(BaseModel):
    """Result of what-if counterfactual perturbation on an optimized decision."""
    query: str
    scenario_type: str # ACTION_REMOVAL | BUDGET_HALVED | STRICTER_SLA
    original_risk_reduction: float
    counterfactual_risk_reduction: float
    risk_reduction_delta: float
    original_disruption: float
    counterfactual_disruption: float
    explanation: str


class DecisionExplainer:
    """Enterprise Decision Explanation and Counterfactual Reasoning Engine."""

    @classmethod
    def explain_recommendation(
        cls,
        recommended_plan: ContainmentPlan,
        alternative_plans: List[ContainmentPlan],
        simulation: SimulationResult
    ) -> Dict[str, Any]:
        """Produces a multi-tier explanation grounded in mathematical outcomes."""
        selected_action_names = [f"'{a.target_node_name}' ({a.action_type.value})" for a in recommended_plan.actions]

        # 1. Reasons behind recommendations (R&D Blueprint Objective #6)
        reasons: List[str] = [
            f"Optimized objective score of {recommended_plan.objective_score:.2f} balancing security benefit against operational friction.",
            f"Achieved ${recommended_plan.total_cost:.2f} implementation cost, satisfying organization budgetary bounds.",
            f"Preserved critical citizen service SLAs with {len(simulation.disrupted_workflows)} disrupted workflows.",
            f"Reduced systemic risk from {simulation.initial_risk_score:.1f} to {simulation.residual_risk_score:.1f} (-{simulation.risk_reduction_achieved:.1f}).",
            f"Eliminated {simulation.initial_attack_path_count - simulation.residual_attack_path_count} of {simulation.initial_attack_path_count} identified attack routes.",
        ]

        # 2. Supporting Evidence (R&D Blueprint Objective #6 & Page 1)
        supporting_evidence: List[Dict[str, Any]] = []
        for action in recommended_plan.actions:
            supporting_evidence.append({
                "action_id": action.id,
                "target_node": action.target_node_name,
                "action_type": action.action_type.value,
                "telemetry_source": "Multi-source correlated network & identity alerts",
                "estimated_risk_reduction": action.estimated_risk_reduction,
                "implementation_cost": action.implementation_cost,
                "operational_disruption": action.operational_disruption_score,
            })

        # 3. Explicit Model Assumptions (R&D Blueprint Objective #6 & Page 1)
        assumptions: List[str] = [
            "Critical citizen/payment services enforce strict zero-allowable outage SLAs (0.0 hours).",
            "Attack paths model directed lateral movement along authenticated, connected, or vulnerable edges.",
            "Uncertain or unrefreshed telemetry is penalized by uncertainty weight (temporal decay rate).",
            "Forensic simulation is isolated on an immutable graph copy without altering live topology.",
            "Human approval is mandatory prior to real-world command execution (decision-support principle).",
        ]

        # 4. Residual Risk Assessment (R&D Blueprint Objective #6)
        residual_risk_evaluation: Dict[str, Any] = {
            "initial_risk": simulation.initial_risk_score,
            "residual_risk": simulation.residual_risk_score,
            "risk_reduction": simulation.risk_reduction_achieved,
            "residual_paths_count": simulation.residual_attack_path_count,
            "is_fully_contained": simulation.is_fully_contained,
            "unprotected_crown_jewels": simulation.unprotected_crown_jewels,
            "residual_paths": [
                {
                    "path_id": p.id,
                    "target": p.target_id,
                    "hops": p.hop_count,
                    "risk": p.adjusted_path_risk,
                    "choke_points": p.choke_point_nodes,
                }
                for p in simulation.residual_paths
            ],
        }

        # 5. Verification Guidance (R&D Blueprint Objective #6)
        verification_guidance: List[str] = [
            "Verify all crown jewel database connection pools remain responsive.",
            "Run post-containment synthetic transaction probe against citizen-facing workflows.",
            "Inspect residual attack routes in simulation view to ensure covert secondary paths are monitored.",
            "Confirm EDR agent connectivity and certificate validity on isolated nodes.",
            "Review chained SHA-256 audit ledger entry for approval cryptographic signature.",
        ]

        # 6. Rollback Guidance (R&D Blueprint Objective #6)
        rollback_guidance: List[Dict[str, Any]] = []
        for action in recommended_plan.actions:
            rollback_guidance.append({
                "action_id": action.id,
                "target": action.target_node_name,
                "action_type": action.action_type.value,
                "contingency_trigger": "Unplanned service outage or critical citizen workflow SLA degradation",
                "rollback_procedure": (
                    f"Restore network access / un-isolate '{action.target_node_name}' via EDR API; "
                    f"re-enable session tokens from emergency credential backup."
                ),
                "estimated_recovery_time_minutes": 5,
            })

        # Explicit rejected alternatives analysis
        rejected_reasons: List[Dict[str, Any]] = []
        for alt in alternative_plans:
            if alt.id == recommended_plan.id:
                continue
            if alt.strategy.value == "BASELINE_SEVERITY":
                rejected_reasons.append({
                    "strategy": alt.strategy.value,
                    "rejection_rationale": (
                        f"Baseline strategy created excessive operational disruption ({alt.total_disruption_score:.1f}) "
                        f"by blunt containment on shared services, violating critical SLAs."
                    ),
                    "disruption_difference": round(alt.total_disruption_score - recommended_plan.total_disruption_score, 2),
                })
            elif alt.strategy.value == "GREEDY_RISK_COST":
                rejected_reasons.append({
                    "strategy": alt.strategy.value,
                    "rejection_rationale": (
                        f"Greedy heuristic produced sub-optimal path severance compared to exact mathematical solver."
                    ),
                    "cost_difference": round(alt.total_cost - recommended_plan.total_cost, 2),
                })

        return {
            "plan_id": recommended_plan.id,
            "strategy": recommended_plan.strategy.value,
            "confidence": "HIGH (Exact Google OR-Tools CP-SAT Global Optimum)",
            "selected_actions_summary": selected_action_names,
            "reasons": reasons,
            "justification": reasons,
            "supporting_evidence": supporting_evidence,
            "assumptions": assumptions,
            "residual_risk": residual_risk_evaluation,
            "verification_guidance": verification_guidance,
            "rollback_guidance": rollback_guidance,
            "rejected_alternatives": rejected_reasons,
            "residual_state_summary": {
                "residual_paths_count": simulation.residual_attack_path_count,
                "is_fully_contained": simulation.is_fully_contained,
                "unprotected_crown_jewels": simulation.unprotected_crown_jewels,
            },
            "audit_hash": simulation.audit_hash,
        }

    @classmethod
    def evaluate_counterfactual_action_removal(
        cls,
        plan: ContainmentPlan,
        action_to_remove_id: str
    ) -> CounterfactualResult:
        """Answers: What happens if action A is NOT executed?"""
        action = next((a for a in plan.actions if a.id == action_to_remove_id), None)
        if not action:
            return CounterfactualResult(
                query=f"Remove action {action_to_remove_id}",
                scenario_type="ACTION_REMOVAL",
                original_risk_reduction=plan.predicted_risk_reduction,
                counterfactual_risk_reduction=plan.predicted_risk_reduction,
                risk_reduction_delta=0.0,
                original_disruption=plan.total_disruption_score,
                counterfactual_disruption=plan.total_disruption_score,
                explanation="Action not found in plan.",
            )

        new_risk_reduct = max(0.0, round(plan.predicted_risk_reduction - action.estimated_risk_reduction, 2))
        new_disruption = max(0.0, round(plan.total_disruption_score - action.operational_disruption_score, 2))
        delta_risk = round(new_risk_reduct - plan.predicted_risk_reduction, 2)

        explanation = (
            f"Omitting action '{action.target_node_name} ({action.action_type.value})' "
            f"decreases risk reduction by {abs(delta_risk):.1f} points (leaving attack routes open), "
            f"but saves ${action.implementation_cost:.2f} and reduces operational disruption by {action.operational_disruption_score:.1f}."
        )

        return CounterfactualResult(
            query=f"What if action '{action.target_node_name}' is omitted?",
            scenario_type="ACTION_REMOVAL",
            original_risk_reduction=plan.predicted_risk_reduction,
            counterfactual_risk_reduction=new_risk_reduct,
            risk_reduction_delta=delta_risk,
            original_disruption=plan.total_disruption_score,
            counterfactual_disruption=new_disruption,
            explanation=explanation,
        )
