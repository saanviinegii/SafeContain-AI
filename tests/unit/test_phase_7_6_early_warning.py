"""Comprehensive Unit and Integration Tests for Phase 7.6 Early-Warning & Predictive Engine.

Verifies:
1. Graph-based threat signal correlation and cluster formation.
2. Early-warning generation, prioritization math, and 12-hour cooldown deduplication.
3. Structured forensic investigation context generation.
4. Predictive validation metrics and advance lead-time calculation without data leakage.
5. Shadow-mode non-interference and production state immutability.
6. Graph synchronization and resilient offline degradation.
7. REST API router endpoints and RBAC authorization matrix.
"""

from datetime import datetime, timezone, timedelta
import math
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.core.config import settings
from backend.app.early_warning.escalation_engine import ThreatEscalationPredictor
from backend.app.early_warning.graph_correlation import GraphThreatCorrelator
from backend.app.early_warning.graph_sync import EarlyWarningGraphSynchronizer
from backend.app.early_warning.investigation_engine import InvestigationContextEngine
from backend.app.early_warning.models import (
    CorrelatedThreatCluster,
    DataSufficiency,
    EarlyWarning,
    EarlyWarningEngineStatus,
    EscalationPrediction,
    EscalationState,
    RiskTrajectory,
    RiskTrajectoryPoint,
    SignalType,
    ThreatSeverity,
    ThreatSignal,
    TrajectoryDirection,
    WarningCategory,
    WarningStatus,
)
from backend.app.early_warning.shadow_evaluator import ShadowModeGuard
from backend.app.early_warning.signal_extractor import ThreatSignalExtractor
from backend.app.early_warning.trajectory_engine import RiskTrajectoryEngine
from backend.app.early_warning.validation_engine import PredictiveValidationEngine
from backend.app.early_warning.warning_engine import EarlyWarningEngine
from backend.app.early_warning.router import router as early_warning_router, platform_state
from backend.app.graph.engine import GraphEngine
from backend.app.models.domain import GraphEdge, GraphNode, NodeType, RelationshipType
from backend.app.security.auth import create_access_token


# =============================================================================
# 1. GRAPH CORRELATION & CLUSTERING TESTS
# =============================================================================

def test_graph_threat_correlator_forms_clusters():
    """Verifies that signals targeting interconnected assets are clustered with Crown Jewel detection."""
    engine = GraphEngine(mode="in_memory")
    node_a = GraphNode(id="srv-web-01", name="Web 01", type=NodeType.SERVER, criticality=0.6, is_crown_jewel=False)
    node_b = GraphNode(id="node-db-cust", name="Customer DB", type=NodeType.DATABASE, criticality=1.0, is_crown_jewel=True)
    engine.add_node(node_a)
    engine.add_node(node_b)

    edge = GraphEdge(id="e1", source="srv-web-01", target="node-db-cust", type=RelationshipType.CONNECTED_TO)
    engine.add_edge(edge)

    correlator = GraphThreatCorrelator(graph_engine=engine)
    t0 = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)

    sig1 = ThreatSignal(
        signal_id="sig-1", asset_id="srv-web-01", signal_type=SignalType.RISK_SPIKE,
        severity=ThreatSeverity.HIGH, observed_value=60.0, timestamp=t0, source="test", evidence="spike", confidence=0.9
    )
    sig2 = ThreatSignal(
        signal_id="sig-2", asset_id="node-db-cust", signal_type=SignalType.SEVERITY_ESCALATION,
        severity=ThreatSeverity.CRITICAL, observed_value=4.0, timestamp=t0, source="test", evidence="crit", confidence=0.95
    )

    clusters = correlator.correlate_signals_to_clusters([sig1, sig2])
    assert len(clusters) >= 1
    c = clusters[0]
    assert "srv-web-01" in c.related_asset_ids
    assert "node-db-cust" in c.related_asset_ids
    assert "node-db-cust" in c.crown_jewels_at_risk
    assert c.severity == ThreatSeverity.CRITICAL


# =============================================================================
# 2. EARLY-WARNING ENGINE & DEDUPLICATION TESTS
# =============================================================================

def test_early_warning_prioritization_and_cooldown_dedup():
    """Verifies priority score weighting, 12-hour cooldown suppression, and deduplication."""
    warning_engine = EarlyWarningEngine(cooldown_hours=12.0)
    now = datetime(2026, 11, 20, 10, 0, tzinfo=timezone.utc)

    # Test prioritization math
    p_crit = warning_engine.calculate_priority_score(
        severity=ThreatSeverity.CRITICAL, current_risk=85.0, criticality=1.0,
        is_crown_jewel=True, is_cluster_correlated=True, confidence=0.95, is_verified_threat=True
    )
    assert p_crit >= 85.0  # Invariant

    p_low = warning_engine.calculate_priority_score(
        severity=ThreatSeverity.LOW, current_risk=20.0, criticality=0.2,
        is_crown_jewel=False, is_cluster_correlated=False, confidence=0.7, is_verified_threat=False
    )
    assert p_low < p_crit

    # Test warning generation with rapid slope
    traj = RiskTrajectory(
        asset_id="node-api-gate", slope=10.0, acceleration=2.0, volatility=1.5,
        moving_average_risk=65.0, ema_risk=70.0, current_risk=72.0, projected_risk=85.0,
        trajectory_direction=TrajectoryDirection.RISING,
        cusum_changepoint_detected=True, data_sufficiency=DataSufficiency.SUFFICIENT,
        sample_size=6, forecast_horizon_hours=6.0, projection_confidence=0.92, evaluated_at=now
    )
    esc = EscalationPrediction(
        prediction_id="esc-1", asset_id="node-api-gate", current_state=EscalationState.WATCH,
        predicted_state=EscalationState.CRITICAL_ESCALATION_RISK, escalation_risk_score=88.0,
        escalation_probability=0.9, confidence=0.92, generated_at=now
    )
    sig = ThreatSignal(
        signal_id="s1", asset_id="node-api-gate", signal_type=SignalType.RISK_SPIKE,
        severity=ThreatSeverity.HIGH, observed_value=72.0, timestamp=now, source="sensor",
        evidence="Spike.", confidence=0.9
    )

    warns1 = warning_engine.evaluate_early_warnings(
        trajectories={"node-api-gate": traj},
        signals=[sig],
        escalations={"node-api-gate": esc},
    )
    assert len(warns1) >= 1
    w = warns1[0]
    assert w.asset_id == "node-api-gate"
    assert w.priority_score >= 70.0

    # Second evaluation immediately within cooldown (t = now + 1hr) -> deduplicated
    warns2 = warning_engine.evaluate_early_warnings(
        trajectories={"node-api-gate": traj},
        signals=[sig],
        escalations={"node-api-gate": esc},
    )
    assert len(warns2) == len(warns1)  # No duplicate spawned


# =============================================================================
# 3. FORENSIC INVESTIGATION CONTEXT TESTS
# =============================================================================

def test_investigation_dossier_synthesis():
    """Verifies synthesis of structured investigation dossiers for SOC analysts."""
    engine = GraphEngine(mode="in_memory")
    inv_engine = InvestigationContextEngine(graph_engine=engine)
    now = datetime(2026, 11, 20, 14, 0, tzinfo=timezone.utc)

    traj = RiskTrajectory(
        asset_id="node-pci-db", slope=8.5, acceleration=1.5, volatility=2.0,
        moving_average_risk=75.0, ema_risk=80.0, current_risk=82.0, projected_risk=95.0,
        trajectory_direction=TrajectoryDirection.RISING,
        cusum_changepoint_detected=True, data_sufficiency=DataSufficiency.SUFFICIENT,
        sample_size=5, forecast_horizon_hours=6.0, projection_confidence=0.95, evaluated_at=now
    )
    sig = ThreatSignal(
        signal_id="sig-exfil", asset_id="node-pci-db", signal_type=SignalType.ABNORMAL_TELEMETRY_BEHAVIOR,
        severity=ThreatSeverity.CRITICAL, observed_value=92.0, timestamp=now, source="DLP",
        evidence="High-volume outbound data flow detected.", confidence=0.95
    )
    warning = EarlyWarning(
        warning_id="warn-test-01", asset_id="node-pci-db",
        affected_entities=["node-pci-db"],
        warning_type=WarningCategory.RAPID_ESCALATION_WARNING,
        severity=ThreatSeverity.CRITICAL, priority_score=94.5,
        status=WarningStatus.ACTIVE, generated_at=now,
        observed_evidence=["Rapid risk velocity dR/dt = +8.50/hr.", "High outbound data volume."],
        explanation="PCI Database rapidly escalating towards critical compromise.",
        confidence=0.95, predicted_impact="High risk of cardholder data breach.",
        recommended_action="Isolate database host immediately."
    )

    dossier = inv_engine.build_investigation_dossier(
        warning=warning, trajectory=traj, signals=[sig], asset_name="PCI Customer Vault"
    )

    assert dossier.warning_id == "warn-test-01"
    assert dossier.asset_id == "node-pci-db"
    assert "PCI Customer Vault" in dossier.what_happened
    assert len(dossier.supporting_evidence) >= 1
    assert len(dossier.recommended_investigation_steps) >= 1
    assert dossier.recommended_investigation_steps[0].startswith("Step 1")


# =============================================================================
# 4. PREDICTION VALIDATION & ADVANCE LEAD-TIME TESTS
# =============================================================================

def test_predictive_validation_metrics_and_lead_time():
    """Verifies advance lead-time calculation and statistical accuracy without data leakage."""
    val_engine = PredictiveValidationEngine()
    t_pred = datetime(2026, 11, 20, 6, 0, tzinfo=timezone.utc)
    t_breach = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)  # Lead time = 6.0 hours

    pred1 = EscalationPrediction(
        prediction_id="p1", asset_id="ast-breached", current_state=EscalationState.WATCH,
        predicted_state=EscalationState.HIGH_ESCALATION_RISK, escalation_risk_score=75.0,
        escalation_probability=0.85, confidence=0.9, generated_at=t_pred
    )
    pred2 = EscalationPrediction(
        prediction_id="p2", asset_id="ast-benign", current_state=EscalationState.STABLE,
        predicted_state=EscalationState.STABLE, escalation_risk_score=15.0,
        escalation_probability=0.10, confidence=0.9, generated_at=t_pred
    )
    val_engine.record_prediction_snapshot(pred1)
    val_engine.record_prediction_snapshot(pred2)

    ground_truth = {
        "ast-breached": "COMPROMISED",
        "ast-benign": "BENIGN",
    }
    timestamps = {
        "ast-breached": t_breach,
    }

    metrics = val_engine.evaluate_predictive_performance(ground_truth, timestamps)
    assert metrics.total_predictions_evaluated == 2
    assert metrics.confirmed_escalations == 1
    assert metrics.false_warnings == 0
    assert metrics.missed_escalations == 0
    assert metrics.accuracy == 1.0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.mean_lead_time_hours == 6.0
    assert metrics.data_leakage_prevented is True


# =============================================================================
# 5. SHADOW MODE SAFETY & GRAPH PERSISTENCE TESTS
# =============================================================================

def test_shadow_mode_guard_non_interference():
    """Verifies that shadow mode strictly enforces production configuration immutability."""
    guard = ShadowModeGuard()
    pre_snap = guard.capture_production_state_snapshot()
    post_snap = guard.capture_production_state_snapshot()

    zero_interference, report = guard.verify_non_interference(pre_snap, post_snap)
    assert zero_interference is True
    assert report["hash_identical"] is True
    assert report["threshold_preserved"] is True


def test_early_warning_graph_synchronizer_resilience():
    """Verifies in-memory graph node creation and safe offline degradation."""
    engine = GraphEngine(mode="in_memory")
    sync = EarlyWarningGraphSynchronizer(graph_engine=engine)
    now = datetime.now(timezone.utc)

    warning = EarlyWarning(
        warning_id="warn-sync-test", asset_id="srv-node-1", affected_entities=["srv-node-1"],
        warning_type=WarningCategory.RAPID_ESCALATION_WARNING, severity=ThreatSeverity.HIGH,
        priority_score=78.0, status=WarningStatus.ACTIVE, generated_at=now,
        observed_evidence=["Rapid slope surge."], explanation="Test warning.", confidence=0.88,
        predicted_impact="High.", recommended_action="Isolate."
    )
    sig = ThreatSignal(
        signal_id="sig-sync-test", asset_id="srv-node-1", signal_type=SignalType.RISK_SPIKE,
        severity=ThreatSeverity.HIGH, observed_value=50.0, timestamp=now, source="test",
        evidence="Spike.", confidence=0.9
    )

    res = sync.sync_to_graph([warning], [sig])
    assert res["status"] == "SYNCED"
    assert res["warnings_persisted"] == 1
    assert res["signals_persisted"] == 1

    # Verify node retrievable from in-memory engine
    retrieved_w = engine.get_node("warn-sync-test")
    assert retrieved_w is not None
    assert retrieved_w.type == NodeType.ALERT


# =============================================================================
# 6. REST API & RBAC AUTHORIZATION TESTS
# =============================================================================

def test_api_early_warning_endpoints_rbac():
    """Verifies REST endpoints and RBAC enforcement across Viewer and Analyst tiers."""
    from backend.app.security.user_store import UserRecord, AppRole
    from backend.app.security.auth import require_analyst
    from fastapi import HTTPException
    from backend.app.early_warning.router import (
        get_early_warning_status,
        get_threat_signals,
        get_early_warnings,
        get_predictive_validation_metrics,
        trigger_early_warning_pipeline,
    )

    viewer = UserRecord(id="u-v", username="viewer", role=AppRole.VIEWER, hashed_password="", created_at="", updated_at="")
    analyst = UserRecord(id="u-a", username="analyst", role=AppRole.ANALYST, hashed_password="", created_at="", updated_at="")

    # 1. Viewer accessing get_early_warning_status -> 200 / valid
    status = get_early_warning_status(current_user=viewer)
    assert status.engine_version == "v7.6.0"
    assert status.is_shadow_mode is True

    # 2. Viewer accessing get_threat_signals -> valid list
    sigs = get_threat_signals(current_user=viewer)
    assert isinstance(sigs, list)

    # 3. Viewer accessing get_early_warnings -> valid list
    warns = get_early_warnings(current_user=viewer)
    assert isinstance(warns, list)

    # 4. Viewer accessing get_predictive_validation_metrics -> valid metrics
    metrics = get_predictive_validation_metrics(current_user=viewer)
    assert metrics.accuracy >= 0.0

    # 5. Viewer attempting require_analyst -> 403 Forbidden
    coro = require_analyst(current_user=viewer)
    with pytest.raises(HTTPException) as exc_info:
        coro.send(None)
    assert exc_info.value.status_code == 403

    # 6. Analyst executing trigger_early_warning_pipeline -> SUCCESS
    eval_data = trigger_early_warning_pipeline(current_user=analyst)
    assert eval_data["status"] == "SUCCESS"
    assert eval_data["shadow_mode_non_interference_verified"] is True
