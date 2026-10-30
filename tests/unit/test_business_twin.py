"""Unit tests for the Business Continuity Digital Twin."""

import pytest
from backend.app.business.twin import BusinessContinuityTwin
from backend.app.graph.engine import GraphEngine
from backend.app.ingestion.connectors import SyntheticScenarioGenerator
from backend.app.models.domain import (
    ContainmentAction,
    SecurityActionType,
    WorkflowCriticality,
)


def test_business_twin_dependency_discovery():
    engine = GraphEngine(mode="in_memory")
    scenario = SyntheticScenarioGenerator.generate_national_gateway_scenario()

    for node in scenario.nodes:
        engine.add_node(node)
    for edge in scenario.edges:
        engine.add_edge(edge)

    twin = BusinessContinuityTwin()
    twin.discover_dependencies_from_graph(engine)

    workflows = twin.get_all_workflows()
    assert len(workflows) >= 1
    
    citizen_wf = next(w for w in workflows if w.id == "wf-citizen-auth-service")
    assert citizen_wf.citizen_facing is True
    assert citizen_wf.criticality == WorkflowCriticality.TIER_1_MISSION_CRITICAL
    assert "db-citizen-identity-prod" in citizen_wf.dependent_asset_ids


def test_action_disruption_evaluation():
    engine = GraphEngine(mode="in_memory")
    scenario = SyntheticScenarioGenerator.generate_national_gateway_scenario()

    for node in scenario.nodes:
        engine.add_node(node)
    for edge in scenario.edges:
        engine.add_edge(edge)

    twin = BusinessContinuityTwin()
    twin.discover_dependencies_from_graph(engine)

    # Action A: Disruptive Action - Isolating the database server
    destructive_action = ContainmentAction(
        id="act-db-isolate",
        action_type=SecurityActionType.ISOLATE_ENDPOINT,
        target_node_id="db-citizen-identity-prod",
        target_node_name="National Citizen Registry Database",
        estimated_risk_reduction=95.0,
        operational_disruption_score=100.0,
        implementation_cost=50000.0,
        estimated_duration_minutes=240,
        rationale="Blunt containment isolating production database.",
    )
    assessments_destructive = twin.assess_action_disruption(destructive_action, engine)
    assert len(assessments_destructive) == 1
    assert assessments_destructive[0].workflow_id == "wf-citizen-auth-service"
    assert assessments_destructive[0].violates_sla is True
    assert assessments_destructive[0].financial_impact > 0.0

    # Action B: Targeted Action - Isolating perimeter gateway or lateral workstation
    surgical_action = ContainmentAction(
        id="act-wrk-isolate",
        action_type=SecurityActionType.ISOLATE_ENDPOINT,
        target_node_id="wrk-operator-14",
        target_node_name="Operator Workstation 14",
        estimated_risk_reduction=40.0,
        operational_disruption_score=5.0,
        implementation_cost=200.0,
        estimated_duration_minutes=15,
        rationale="Surgical containment isolating workstation.",
    )
    assessments_surgical = twin.assess_action_disruption(surgical_action, engine)
    # Workstation 14 does not directly support the citizen portal
    assert not any(a.workflow_id == "wf-citizen-auth-service" and a.violates_sla for a in assessments_surgical)
