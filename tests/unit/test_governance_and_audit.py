"""Unit tests for Governance Approval Workflows and Tamper-Evident Audit Ledger."""

import os
import pytest
from backend.app.audit.ledger import ChainedAuditLedger
from backend.app.governance.workflow import GovernanceWorkflow
from backend.app.models.domain import (
    ApprovalStatus,
    ContainmentPlan,
    OptimizationStrategy,
    UserRole,
)


def test_governance_lifecycle_valid_path():
    plan = ContainmentPlan(
        id="plan-gov-01",
        strategy=OptimizationStrategy.CONSTRAINT_CPSAT,
        actions=[],
        total_cost=0.0,
        total_disruption_score=0.0,
        predicted_risk_reduction=0.0,
        predicted_residual_risk=100.0,
        satisfies_all_constraints=True,
        objective_score=0.0,
        status=ApprovalStatus.DRAFT,
        explanation="Test plan",
    )

    # 1. DRAFT -> ANALYZED
    plan, _ = GovernanceWorkflow.transition_plan(
        plan, ApprovalStatus.ANALYZED, "agent-opt", UserRole.SOC_ANALYST
    )
    assert plan.status == ApprovalStatus.ANALYZED

    # 2. ANALYZED -> SIMULATED
    plan, _ = GovernanceWorkflow.transition_plan(
        plan, ApprovalStatus.SIMULATED, "agent-sim", UserRole.SOC_ANALYST
    )
    assert plan.status == ApprovalStatus.SIMULATED

    # 3. SIMULATED -> PENDING_APPROVAL
    plan, _ = GovernanceWorkflow.transition_plan(
        plan, ApprovalStatus.PENDING_APPROVAL, "analyst-01", UserRole.SOC_ANALYST
    )
    assert plan.status == ApprovalStatus.PENDING_APPROVAL

    # 4. PENDING_APPROVAL -> APPROVED (Authorized by Security Manager)
    plan, _ = GovernanceWorkflow.transition_plan(
        plan, ApprovalStatus.APPROVED, "mgr-01", UserRole.SECURITY_MANAGER
    )
    assert plan.status == ApprovalStatus.APPROVED

    # 5. APPROVED -> EXECUTION_AUTHORIZED (Authorized by Security Manager)
    plan, _ = GovernanceWorkflow.transition_plan(
        plan, ApprovalStatus.EXECUTION_AUTHORIZED, "mgr-01", UserRole.SECURITY_MANAGER
    )
    assert plan.status == ApprovalStatus.EXECUTION_AUTHORIZED


def test_governance_unauthorized_permission_denial():
    plan = ContainmentPlan(
        id="plan-gov-02",
        strategy=OptimizationStrategy.CONSTRAINT_CPSAT,
        actions=[],
        total_cost=0.0,
        total_disruption_score=0.0,
        predicted_risk_reduction=0.0,
        predicted_residual_risk=100.0,
        satisfies_all_constraints=True,
        objective_score=0.0,
        status=ApprovalStatus.PENDING_APPROVAL,
        explanation="Test plan",
    )

    # Viewer or Analyst cannot directly authorize execution or approve
    with pytest.raises(PermissionError) as exc_info:
        GovernanceWorkflow.transition_plan(
            plan, ApprovalStatus.APPROVED, "viewer-01", UserRole.READ_ONLY_VIEWER
        )
    assert "not authorized" in str(exc_info.value)


def test_chained_audit_ledger_tamper_detection(tmp_path):
    storage_file = str(tmp_path / "test_audit.jsonl")
    ledger = ChainedAuditLedger(storage_path=storage_file)

    # Append 3 events
    e1 = ledger.record_event(
        actor_id="user-analyst",
        actor_role=UserRole.SOC_ANALYST,
        action="INGEST_TELEMETRY",
        resource_type="IngestionBatch",
        resource_id="batch-001",
        metadata={"records_count": 50},
    )
    e2 = ledger.record_event(
        actor_id="user-analyst",
        actor_role=UserRole.SOC_ANALYST,
        action="RUN_SIMULATION",
        resource_type="Simulation",
        resource_id="sim-99",
        metadata={"residual_risk": 32.5},
    )
    e3 = ledger.record_event(
        actor_id="user-manager",
        actor_role=UserRole.SECURITY_MANAGER,
        action="APPROVE_PLAN",
        resource_type="ContainmentPlan",
        resource_id="plan-01",
        metadata={"decision": "APPROVED"},
    )

    # Verify untampered integrity passes
    report = ledger.verify_integrity()
    assert report.is_valid is True
    assert report.total_events_checked == 3

    # Tamper with event e2 in memory
    ledger._events[1].metadata["residual_risk"] = 0.0 # Fraudulently altered metric!

    # Verify tampering is caught immediately!
    tamper_report = ledger.verify_integrity()
    assert tamper_report.is_valid is False
    assert tamper_report.tampered_index == 1
    assert "Data tampering detected" in tamper_report.status_summary


def test_blockchain_smart_contract_anchor_and_verification(tmp_path):
    """Verifies R&D Blueprint Page 2 & 4: Blockchain Smart Contract On-Chain Anchoring and Off-Chain Check."""
    storage_file = str(tmp_path / "test_blockchain_audit.jsonl")
    ledger = ChainedAuditLedger(storage_path=storage_file)

    # 1. Anchor evidence snapshot
    e_snap = ledger.record_evidence_snapshot(
        evidence_id="ev-crowdstrike-001",
        source_system="CrowdStrike Falcon",
        raw_payload_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        status="CONFIRMED",
        confidence=0.95,
    )

    # 2. Anchor recommendation
    e_rec = ledger.record_recommendation(
        plan_id="plan-exact-001",
        strategy="CONSTRAINT_CPSAT",
        objective_score=88.5,
        total_cost=2500.0,
        predicted_risk_reduction=45.0,
        actions_count=2,
    )

    # 3. Anchor approval
    e_appr = ledger.record_approval(
        plan_id="plan-exact-001",
        approval_status="APPROVED",
        approval_reference="sig-mgr-raj-2026-auth",
        actor_id="mgr-raj",
        actor_role=UserRole.SECURITY_MANAGER,
        notes="Containment verified and authorized.",
    )

    # Verify on-chain anchor records exist
    anchored = ledger.blockchain_anchor.get_all_anchored_records()
    assert len(anchored) == 3
    assert anchored[0].event_type == "EVIDENCE_SNAPSHOT"
    assert anchored[1].event_type == "RECOMMENDATION"
    assert anchored[2].event_type == "APPROVAL"
    assert anchored[2].approval_reference == "sig-mgr-raj-2026-auth"

    # Verify blockchain integrity check passes for authentic event
    v_res = ledger.verify_blockchain_integrity(e_appr.event_id)
    assert v_res.is_valid is True
    assert v_res.tamper_detected is False
    assert "On-chain hash match verified" in v_res.verification_message

    # Tamper with event e_appr in memory (off-chain modification)
    ledger._events[2].metadata["review_notes"] = "Tampered notes!"

    # Verify on-chain integrity check detects tampering
    tamper_check = ledger.verify_blockchain_integrity(e_appr.event_id)
    assert tamper_check.is_valid is False
    assert tamper_check.tamper_detected is True
    assert "TAMPER DETECTED" in tamper_check.verification_message
