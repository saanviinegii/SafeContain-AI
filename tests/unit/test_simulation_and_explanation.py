"""Unit tests for Isolated Simulation, Residual Risk Verification, and Decision Explanation."""

import pytest
from backend.app.business.twin import BusinessContinuityTwin
from backend.app.explanation.engine import DecisionExplainer
from backend.app.graph.engine import GraphEngine
from backend.app.ingestion.connectors import SyntheticScenarioGenerator
from backend.app.models.domain import (
    ContainmentAction,
    ContainmentPlan,
    OptimizationStrategy,
    SecurityActionType,
)
from backend.app.simulation.sandbox import SimulationSandbox


def test_isolated_simulation_and_residual_paths():
    engine = GraphEngine(mode="in_memory")
    scenario = SyntheticScenarioGenerator.generate_national_gateway_scenario()

    for node in scenario.nodes:
        engine.add_node(node)
    for edge in scenario.edges:
        engine.add_edge(edge)

    twin = BusinessContinuityTwin()
    twin.discover_dependencies_from_graph(engine)

    # Containment action: Only severing workstation 14 (leaving backup path open!)
    partial_action = ContainmentAction(
        id="act-wrk-14",
        action_type=SecurityActionType.ISOLATE_ENDPOINT,
        target_node_id="wrk-operator-14",
        target_node_name="SOC Workstation 14",
        estimated_risk_reduction=40.0,
        operational_disruption_score=5.0,
        implementation_cost=150.0,
        estimated_duration_minutes=10,
        rationale="Isolate compromised workstation.",
    )
    plan = ContainmentPlan(
        id="plan-partial",
        strategy=OptimizationStrategy.CONSTRAINT_CPSAT,
        actions=[partial_action],
        total_cost=150.0,
        total_disruption_score=5.0,
        predicted_risk_reduction=40.0,
        predicted_residual_risk=50.0,
        satisfies_all_constraints=True,
        objective_score=75.0,
        explanation="Partial containment plan.",
    )

    # Pre-simulation edge count on baseline
    baseline_edges = len(engine._nx_graph.edges())

    # Execute simulation
    sim_result = SimulationSandbox.simulate_containment_plan(plan, engine, twin)

    # 1. Assert baseline graph was NEVER mutated
    assert len(engine._nx_graph.edges()) == baseline_edges

    # 2. Assert residual path was identified (Principle #12)
    # The secondary backup route to the database is still open!
    assert sim_result.residual_attack_path_count >= 1
    assert sim_result.is_fully_contained is False
    assert len(sim_result.unprotected_crown_jewels) >= 1
    assert "db-citizen-identity-prod" in sim_result.unprotected_crown_jewels

    # 3. Assert audit hash generated
    assert len(sim_result.audit_hash) == 64


def test_decision_explanation_and_counterfactual():
    action = ContainmentAction(
        id="act-dc-fw",
        action_type=SecurityActionType.APPLY_FIREWALL_RULE,
        target_node_id="srv-ad-dc01",
        target_node_name="Primary DC",
        estimated_risk_reduction=55.0,
        operational_disruption_score=10.0,
        implementation_cost=300.0,
        estimated_duration_minutes=15,
        rationale="ACL containment.",
    )
    plan = ContainmentPlan(
        id="plan-rec",
        strategy=OptimizationStrategy.CONSTRAINT_CPSAT,
        actions=[action],
        total_cost=300.0,
        total_disruption_score=10.0,
        predicted_risk_reduction=55.0,
        predicted_residual_risk=40.0,
        satisfies_all_constraints=True,
        objective_score=85.0,
        explanation="Recommended plan.",
    )

    # Counterfactual removal of action
    cf_result = DecisionExplainer.evaluate_counterfactual_action_removal(plan, "act-dc-fw")
    assert cf_result.scenario_type == "ACTION_REMOVAL"
    assert cf_result.risk_reduction_delta == -55.0
    assert cf_result.counterfactual_disruption == 0.0
    assert "saves $300.00" in cf_result.explanation

    # Test full explanation structure matching R&D Blueprint Objective #6
    from backend.app.models.domain import SimulationResult
    mock_sim = SimulationResult(
        simulation_id="sim-test-01",
        scenario_id="scen-01",
        applied_action_ids=["act-dc-fw"],
        initial_attack_path_count=3,
        residual_attack_path_count=1,
        initial_risk_score=95.0,
        residual_risk_score=40.0,
        risk_reduction_achieved=55.0,
        disrupted_workflows=[],
        residual_paths=[],
        unprotected_crown_jewels=[],
        is_fully_contained=False,
        explanation="Test simulation",
        audit_hash="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    explanation = DecisionExplainer.explain_recommendation(plan, [], mock_sim)
    assert len(explanation["reasons"]) >= 3
    assert len(explanation["supporting_evidence"]) >= 1
    assert len(explanation["assumptions"]) >= 3
    assert explanation["residual_risk"]["residual_risk"] == 40.0
    assert len(explanation["verification_guidance"]) >= 3
    assert len(explanation["rollback_guidance"]) >= 1
    assert "reasons" in explanation
    assert "supporting_evidence" in explanation
    assert "assumptions" in explanation
    assert "verification_guidance" in explanation
    assert "rollback_guidance" in explanation
