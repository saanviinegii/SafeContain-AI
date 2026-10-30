"""Unit tests for SafeContain AI Core Domain Models."""

import pytest
from datetime import datetime, timezone
from backend.app.models.domain import (
    GraphNode,
    GraphEdge,
    NodeType,
    RelationshipType,
    EvidenceStatus,
    DataProvenance,
    AttackPath,
    RiskDecomposition,
    BusinessWorkflow,
    WorkflowCriticality,
    ContainmentAction,
    SecurityActionType,
    ContainmentPlan,
    OptimizationStrategy,
    ApprovalStatus,
    UserRole,
    AuditEvent,
)


def test_graph_node_validation():
    """Ensure GraphNode correctly validates attributes and constraints."""
    node = GraphNode(
        id="srv-prod-db-01",
        name="Production Citizen Database",
        type=NodeType.DATABASE,
        criticality=0.95,
        is_crown_jewel=True,
        provenance=DataProvenance.LIVE_TELEMETRY,
    )
    assert node.id == "srv-prod-db-01"
    assert node.type == NodeType.DATABASE
    assert node.criticality == 0.95
    assert node.is_crown_jewel is True
    assert node.provenance == DataProvenance.LIVE_TELEMETRY

    # Test invalid criticality range (< 0.0 or > 1.0)
    with pytest.raises(ValueError):
        GraphNode(id="err", name="Err", type=NodeType.HOST, criticality=1.5)


def test_graph_edge_evidence_status():
    """Verify GraphEdge supports five evidence uncertainty states."""
    edge = GraphEdge(
        id="edge-101",
        source="host-jump-01",
        target="srv-prod-db-01",
        type=RelationshipType.HAS_ACCESS_TO,
        evidence_status=EvidenceStatus.SUSPECTED,
        confidence=0.65,
    )
    assert edge.evidence_status == EvidenceStatus.SUSPECTED
    assert edge.confidence == 0.65
    assert edge.is_active is True


def test_attack_path_modeling():
    """Validate attack path properties and sequences."""
    path = AttackPath(
        id="path-001",
        source_id="endpoint-workstation-07",
        target_id="srv-prod-db-01",
        node_sequence=["endpoint-workstation-07", "host-jump-01", "srv-prod-db-01"],
        edge_sequence=["edge-099", "edge-101"],
        hop_count=2,
        inherent_path_risk=85.0,
        confidence_score=0.65,
        uncertainty_penalty=15.0,
        adjusted_path_risk=100.0,
        choke_point_nodes=["host-jump-01"],
        explanation="Lateral movement via stolen SSH key from workstation to jump host to DB.",
    )
    assert path.hop_count == 2
    assert "host-jump-01" in path.choke_point_nodes
    assert path.is_residual is False


def test_containment_plan_lifecycle():
    """Verify ContainmentPlan adheres to governance states."""
    action = ContainmentAction(
        id="act-001",
        action_type=SecurityActionType.ISOLATE_ENDPOINT,
        target_node_id="endpoint-workstation-07",
        target_node_name="Compromised Workstation",
        estimated_risk_reduction=40.0,
        operational_disruption_score=5.0,
        implementation_cost=150.0,
        estimated_duration_minutes=10,
        rationale="Sever active C2 channel.",
    )
    plan = ContainmentPlan(
        id="plan-opt-01",
        strategy=OptimizationStrategy.CONSTRAINT_CPSAT,
        actions=[action],
        total_cost=150.0,
        total_disruption_score=5.0,
        predicted_risk_reduction=40.0,
        predicted_residual_risk=45.0,
        satisfies_all_constraints=True,
        objective_score=75.0,
        status=ApprovalStatus.DRAFT,
        explanation="Optimal budget-preserving containment plan.",
    )
    assert plan.status == ApprovalStatus.DRAFT
    assert len(plan.actions) == 1
    assert plan.satisfies_all_constraints is True


def test_audit_event_hash_chain():
    """Validate audit event structure for cryptographic hash-chaining."""
    event = AuditEvent(
        event_id="aud-001",
        actor_id="user-sec-lead",
        actor_role=UserRole.SECURITY_ADMIN,
        action="APPROVE_CONTAINMENT_PLAN",
        resource_type="ContainmentPlan",
        resource_id="plan-opt-01",
        previous_hash="0000000000000000000000000000000000000000000000000000000000000000",
        current_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    assert event.actor_role == UserRole.SECURITY_ADMIN
    assert event.previous_hash.startswith("0000")
