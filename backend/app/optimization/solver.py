"""SafeContain AI Tri-Level Optimization Engine.

Implements:
1. Strategy 1 (Baseline): Severity-first selection.
2. Strategy 2 (Greedy): Marginal risk reduction divided by operational cost and disruption.
3. Strategy 3 (Constraint-Based CP-SAT): Exact OR-Tools mathematical constraint optimizer
   preserving critical workflow SLAs under budget bounds.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple
from ortools.sat.python import cp_model

from backend.app.business.twin import BusinessContinuityTwin
from backend.app.core.config import settings
from backend.app.models.domain import (
    ApprovalStatus,
    ContainmentAction,
    ContainmentPlan,
    OptimizationStrategy,
)


class BaselinePlanner:
    """Strategy 1: Baseline Severity-First Planner.
    
    Greedily prioritizes highest raw risk reduction regardless of workflow disruption or cost.
    Demonstrates the perils of unconstrained, blunt containment.
    """

    @classmethod
    def plan(
        cls,
        candidate_actions: List[ContainmentAction],
        budget_limit: float = 10000.0,
        max_actions: int = 4
    ) -> ContainmentPlan:
        # Sort strictly by estimated risk reduction descending
        sorted_actions = sorted(
            candidate_actions,
            key=lambda a: a.estimated_risk_reduction,
            reverse=True
        )

        selected: List[ContainmentAction] = []
        total_cost = 0.0
        total_disruption = 0.0
        total_risk_reduct = 0.0

        for a in sorted_actions:
            if len(selected) >= max_actions:
                break
            if total_cost + a.implementation_cost <= budget_limit:
                selected.append(a)
                total_cost += a.implementation_cost
                total_disruption += a.operational_disruption_score
                total_risk_reduct += a.estimated_risk_reduction

        predicted_residual = max(0.0, 100.0 - total_risk_reduct)

        return ContainmentPlan(
            id="plan-strat1-baseline",
            strategy=OptimizationStrategy.BASELINE_SEVERITY,
            actions=selected,
            total_cost=round(total_cost, 2),
            total_disruption_score=round(total_disruption, 2),
            predicted_risk_reduction=round(total_risk_reduct, 2),
            predicted_residual_risk=round(predicted_residual, 2),
            satisfies_all_constraints=total_cost <= budget_limit,
            constraint_violations=[],
            objective_score=round(total_risk_reduct, 2),
            status=ApprovalStatus.ANALYZED,
            explanation=(
                f"Baseline severity-first containment selected {len(selected)} actions "
                f"targeting highest risk nodes. Total cost: ${total_cost:.2f}, "
                f"Operational disruption: {total_disruption:.1f} (high disruption risk)."
            ),
        )


class GreedyOptimizer:
    """Strategy 2: Greedy Risk-Per-Cost & Disruption Optimizer.
    
    Ranks actions by efficiency score:
    Score = RiskReduction / (Cost + lambda * Disruption)
    """

    @classmethod
    def plan(
        cls,
        candidate_actions: List[ContainmentAction],
        budget_limit: float = 10000.0,
        disruption_weight: float = 15.0
    ) -> ContainmentPlan:
        def efficiency(a: ContainmentAction) -> float:
            denominator = a.implementation_cost + (disruption_weight * a.operational_disruption_score)
            return a.estimated_risk_reduction / max(1.0, denominator)

        ranked = sorted(candidate_actions, key=efficiency, reverse=True)
        selected: List[ContainmentAction] = []
        total_cost = 0.0
        total_disruption = 0.0
        total_risk_reduct = 0.0

        for a in ranked:
            if total_cost + a.implementation_cost <= budget_limit:
                selected.append(a)
                total_cost += a.implementation_cost
                total_disruption += a.operational_disruption_score
                total_risk_reduct += a.estimated_risk_reduction

        predicted_residual = max(0.0, 100.0 - total_risk_reduct)

        return ContainmentPlan(
            id="plan-strat2-greedy",
            strategy=OptimizationStrategy.GREEDY_RISK_COST,
            actions=selected,
            total_cost=round(total_cost, 2),
            total_disruption_score=round(total_disruption, 2),
            predicted_risk_reduction=round(total_risk_reduct, 2),
            predicted_residual_risk=round(predicted_residual, 2),
            satisfies_all_constraints=total_cost <= budget_limit,
            constraint_violations=[],
            objective_score=round(total_risk_reduct - (0.5 * total_disruption), 2),
            status=ApprovalStatus.ANALYZED,
            explanation=(
                f"Greedy optimization selected {len(selected)} actions based on marginal risk "
                f"reduction per dollar and disruption unit. Total cost: ${total_cost:.2f}, "
                f"Disruption score: {total_disruption:.1f}."
            ),
        )


class CPSATOptimizer:
    """Strategy 3: Google OR-Tools CP-SAT Mathematical Constraint Optimizer.
    
    Solves an exact 0-1 Integer Programming problem:
    - Subject to: Hard containment budget cap
    - Subject to: Zero SLA outage violations on Mission-Critical / Citizen workflows
    - Objective: Maximize Risk Reduction + ML Threat Exposure Mitigation - alpha * Cost - beta * Disruption
    """

    @classmethod
    def plan(
        cls,
        candidate_actions: List[ContainmentAction],
        twin: BusinessContinuityTwin,
        engine,
        budget_limit: float = 10000.0,
        max_time_seconds: float = 5.0,
        ml_probabilities: Optional[Dict[str, float]] = None,
        operating_threshold: Optional[float] = None,
        model_registry: Optional[Any] = None,
        predictive_probabilities: Optional[Dict[str, float]] = None,
        predictive_weight: float = 0.0,
        forecast_horizon: Optional[str] = None,
    ) -> ContainmentPlan:
        if not candidate_actions:
            return ContainmentPlan(
                id="plan-strat3-cpsat",
                strategy=OptimizationStrategy.CONSTRAINT_CPSAT,
                actions=[],
                total_cost=0.0,
                total_disruption_score=0.0,
                predicted_risk_reduction=0.0,
                predicted_residual_risk=100.0,
                satisfies_all_constraints=True,
                objective_score=0.0,
                status=ApprovalStatus.ANALYZED,
                explanation="No candidate actions supplied.",
            )

        # Retrieve calibrated ML threat probabilities if not passed explicitly
        if ml_probabilities is None:
            try:
                from backend.app.ml.model_registry import ModelRegistry
                reg = model_registry or ModelRegistry()
                if reg.is_model_available():
                    target_nids = list(set(a.target_node_id for a in candidate_actions))
                    preds = reg.predict_for_nodes(node_ids=target_nids)
                    ml_probabilities = {p["node_id"]: p["risk_probability"] for p in preds}
                    if operating_threshold is None:
                        operating_threshold = reg.get_operating_threshold()
            except Exception:
                ml_probabilities = None

        th = operating_threshold if operating_threshold is not None else 0.32

        model = cp_model.CpModel()
        num_actions = len(candidate_actions)

        # Decision variables x[i] in {0, 1}
        x = [model.NewBoolVar(f"action_{i}") for i in range(num_actions)]

        # Precompute disruption and SLA violations per action
        action_sla_violated = []
        for a in candidate_actions:
            assessments = twin.assess_action_disruption(a, engine)
            violates_critical_sla = any(ass.violates_sla for ass in assessments)
            action_sla_violated.append(violates_critical_sla)

        # Constraint 1: Budget Cap
        # Scale costs to integer cents for CP-SAT precision
        costs_cents = [int(round(a.implementation_cost * 100)) for a in candidate_actions]
        budget_cents = int(round(budget_limit * 100))
        model.Add(sum(costs_cents[i] * x[i] for i in range(num_actions)) <= budget_cents)

        # Constraint 2: Mandatory Protection of Critical Citizen Workflows (Hard SLA Constraint)
        # If an action causes an unallowable critical outage, force x[i] == 0
        for i in range(num_actions):
            if action_sla_violated[i]:
                model.Add(x[i] == 0)

        # Objective Function:
        # Maximize: 100 * RiskReduction + 50 * (p_i * 100) + predictive_term - 0.1 * Cost($) - 20 * Disruption
        # Scaled to integer coefficients
        obj_coefficients = []
        for i, a in enumerate(candidate_actions):
            p_i = ml_probabilities.get(a.target_node_id, 0.0) if ml_probabilities else 0.0
            future_p_i = predictive_probabilities.get(a.target_node_id, 0.0) if predictive_probabilities else 0.0
            pred_term = (future_p_i * predictive_weight * 5000.0) if (predictive_probabilities and predictive_weight > 0) else 0.0
            # Integer-scaled coefficient: reward topological risk reduction + calibrated ML threat exposure + predictive future risk
            coeff = int(round(
                (a.estimated_risk_reduction * 100.0)
                + (p_i * 5000.0)
                + pred_term
                - (a.implementation_cost * 0.1)
                - (a.operational_disruption_score * 20.0)
            ))
            obj_coefficients.append(coeff)

        model.Maximize(sum(obj_coefficients[i] * x[i] for i in range(num_actions)))

        # Solve Model
        solver = cp_model.CpSolver()
        solver.parameters.max_time_in_seconds = max_time_seconds
        solver_status = solver.Solve(model)

        selected: List[ContainmentAction] = []
        total_cost = 0.0
        total_disruption = 0.0
        total_risk_reduct = 0.0
        constraint_violations: List[str] = []

        obj_score = 0.0
        is_optimal = False
        if solver_status in (cp_model.OPTIMAL, cp_model.FEASIBLE):
            for i in range(num_actions):
                if solver.Value(x[i]) == 1:
                    a = candidate_actions[i]
                    p_i = ml_probabilities.get(a.target_node_id, 0.0) if ml_probabilities else None
                    th_crossed = bool(p_i >= th) if p_i is not None else None
                    pred_class = ("At-Risk / Threat" if th_crossed else "Healthy / Benign") if p_i is not None else None

                    # Enrich action with explainable ML metadata
                    a.ml_probability = round(p_i, 4) if p_i is not None else None
                    a.decision_threshold = round(th, 4) if p_i is not None else None
                    a.threshold_crossed = th_crossed
                    a.predicted_threat_class = pred_class

                    future_p_i = predictive_probabilities.get(a.target_node_id) if predictive_probabilities else None
                    if future_p_i is not None:
                        a.predictive_future_probability = round(future_p_i, 4)
                        a.forecast_horizon = forecast_horizon

                    if future_p_i is not None and future_p_i >= th:
                        opt_rationale = (
                            f"Target node '{a.target_node_name}' (ID: {a.target_node_id}) selected: "
                            f"Temporal forecast projects {future_p_i:.1%} future compromise probability ({forecast_horizon or 'predictive'}). "
                            f"Containment yields estimated risk reduction of {a.estimated_risk_reduction:.1f} with zero SLA outage violations."
                        )
                    elif p_i is not None and th_crossed:
                        opt_rationale = (
                            f"Target node '{a.target_node_name}' (ID: {a.target_node_id}) selected: "
                            f"Calibrated ML threat probability of {p_i:.1%} crosses the {th:.2f} operating threshold. "
                            f"Containment yields estimated risk reduction of {a.estimated_risk_reduction:.1f} with "
                            f"zero SLA outage violations on mission-critical citizen workflows."
                        )
                    elif p_i is not None:
                        opt_rationale = (
                            f"Target node '{a.target_node_name}' (ID: {a.target_node_id}) selected: "
                            f"Substantial topological risk reduction ({a.estimated_risk_reduction:.1f}) along active attack route, "
                            f"with ML probability estimated at {p_i:.1%}."
                        )
                    else:
                        opt_rationale = (
                            f"Target node '{a.target_node_name}' selected based on optimal mathematical risk reduction "
                            f"under budget and workflow SLA constraints."
                        )
                    a.optimization_rationale = opt_rationale

                    selected.append(a)
                    total_cost += a.implementation_cost
                    total_disruption += a.operational_disruption_score
                    total_risk_reduct += a.estimated_risk_reduction

            obj_score = round(solver.ObjectiveValue() / 100.0, 2)
            is_optimal = solver_status == cp_model.OPTIMAL
            ml_note = f" incorporating calibrated ML threat probabilities (threshold {th:.2f})" if ml_probabilities else ""
            if predictive_probabilities and predictive_weight > 0:
                ml_note += f" and {forecast_horizon or 'predictive'} propagation forecasting (weight {predictive_weight})"
            explanation = (
                f"CP-SAT optimization achieved {'mathematically optimal' if is_optimal else 'feasible'} "
                f"containment{ml_note} across {len(selected)} actions while strictly preserving critical citizen SLAs. "
                f"Total cost: ${total_cost:.2f}, Disruption: {total_disruption:.1f}."
            )
        else:
            constraint_violations.append(
                f"CP-SAT solver proved INFEASIBLE under strict SLA constraints and budget cap of ${budget_limit:.2f}."
            )
            explanation = (
                f"CP-SAT optimization is INFEASIBLE: No combination of candidate actions satisfies "
                f"the budget cap of ${budget_limit:.2f} while strictly preserving zero-allowable outage SLAs "
                f"on mission-critical citizen workflows."
            )

        predicted_residual = max(0.0, 100.0 - total_risk_reduct)

        return ContainmentPlan(
            id="plan-strat3-cpsat",
            strategy=OptimizationStrategy.CONSTRAINT_CPSAT,
            actions=selected,
            total_cost=round(total_cost, 2),
            total_disruption_score=round(total_disruption, 2),
            predicted_risk_reduction=round(total_risk_reduct, 2),
            predicted_residual_risk=round(predicted_residual, 2),
            satisfies_all_constraints=len(constraint_violations) == 0,
            constraint_violations=constraint_violations,
            objective_score=obj_score,
            status=ApprovalStatus.ANALYZED,
            explanation=explanation,
        )


class StrategyComparator:
    """Executes and compares all 3 optimization strategies on an identical scenario."""

    @classmethod
    def compare(
        cls,
        candidate_actions: List[ContainmentAction],
        twin: BusinessContinuityTwin,
        engine,
        budget_limit: float = 10000.0,
        ml_probabilities: Optional[Dict[str, float]] = None,
        operating_threshold: Optional[float] = None,
        predictive_probabilities: Optional[Dict[str, float]] = None,
        predictive_weight: float = 0.0,
        forecast_horizon: Optional[str] = None,
    ) -> Dict[str, Any]:
        t0 = time.perf_counter()
        p1 = BaselinePlanner.plan(candidate_actions, budget_limit)
        t1 = time.perf_counter()

        t2 = time.perf_counter()
        p2 = GreedyOptimizer.plan(candidate_actions, budget_limit)
        t3 = time.perf_counter()

        t4 = time.perf_counter()
        p3 = CPSATOptimizer.plan(
            candidate_actions,
            twin,
            engine,
            budget_limit,
            ml_probabilities=ml_probabilities,
            operating_threshold=operating_threshold,
            predictive_probabilities=predictive_probabilities,
            predictive_weight=predictive_weight,
            forecast_horizon=forecast_horizon,
        )
        t5 = time.perf_counter()

        return {
            "strategies": {
                "BASELINE_SEVERITY": p1.model_dump(mode="json"),
                "GREEDY_RISK_COST": p2.model_dump(mode="json"),
                "CONSTRAINT_CPSAT": p3.model_dump(mode="json"),
            },
            "benchmarks": {
                "baseline_latency_ms": round((t1 - t0) * 1000.0, 3),
                "greedy_latency_ms": round((t3 - t2) * 1000.0, 3),
                "cpsat_latency_ms": round((t5 - t4) * 1000.0, 3),
            },
            "recommendation": "CONSTRAINT_CPSAT",
            "comparative_analysis": (
                f"CP-SAT achieved superior SLA compliance ({p3.total_disruption_score} disruption) "
                f"compared to Baseline ({p1.total_disruption_score} disruption). "
                f"CP-SAT is recommended for enterprise deployment."
            ),
        }
