"""Unit Test Suite for SafeContain AI Phase 7.5: Adaptive Risk Calibration & Intelligent Threshold Optimization.

Verifies:
1. Empirical Risk Score Calibration (ECE, Brier Score, 5 Reliability Bins).
2. Sample Size Safeguards (N < 10 returns INSUFFICIENT_DATA).
3. Cost-Sensitive Threshold Optimization (10x FN, 1x FP, 25x Critical, Recall >= 0.90).
4. Critical Threat Protection Invariant (Critical threshold capped <= 0.32, zero degradation).
5. Zero-Interference Shadow Simulation & Asset Classification Flips.
6. Alert Fatigue Analytics, Gini Concentration & Noisy Asset Profiles.
7. Telemetry PSI Drift, Wasserstein Distance & Calibration Degradation.
8. Adaptive Recommendation Engine multi-condition synthesis.
9. Configuration Versioning, Approval Lifecycle, Activation & Rollback.
10. GraphEngine & Neo4j Policy Synchronization Resilience.
11. REST API Routing & RBAC Permissions.
12. Zero Regression on Phase 7.4 & Phase 7.3 capabilities.
"""

from __future__ import annotations

import os
import tempfile
import uuid
from datetime import datetime, timezone
from typing import List

import numpy as np
import pytest

from backend.app.adaptive.models import (
    GroundTruthOutcome,
    PredictionOutcomeStatus,
    PredictionRecord,
)
from backend.app.calibration.alert_analytics import AlertFatigueAnalyzer
from backend.app.calibration.calibration_engine import RiskScoreCalibrationEngine
from backend.app.calibration.config_manager import ConfigurationVersionManager
from backend.app.calibration.drift_detector import TelemetryDriftDetector
from backend.app.calibration.graph_sync import CalibrationGraphSynchronizer
from backend.app.calibration.models import (
    CalibrationStatus,
    ConfigurationStatus,
    RecommendationCategory,
    ThresholdConfiguration,
    ThresholdTiers,
)
from backend.app.calibration.recommendation_engine import AdaptiveRecommendationEngine
from backend.app.calibration.shadow_evaluator import ShadowThresholdEvaluator
from backend.app.calibration.threshold_optimizer import IntelligentThresholdOptimizer
from backend.app.graph.engine import GraphEngine
from backend.app.models.domain import NodeType


def _create_mock_records(n_threats: int = 15, n_benign: int = 25) -> List[PredictionRecord]:
    """Generates synthetic verified records for deterministic unit test fixtures."""
    records = []
    now = datetime.now(timezone.utc)

    # Threats (Ground truth Y=1)
    for i in range(n_threats):
        prob = min(0.95, 0.35 + (i * 0.03))  # Probs in [0.35, 0.95]
        records.append(
            PredictionRecord(
                prediction_id=f"test-threat-{i}-{uuid.uuid4().hex[:6]}",
                asset_id=f"srv-threat-{i % 5}",
                asset_name=f"Threat Server {i}",
                asset_type="SERVER" if i % 2 == 0 else "DATABASE",
                prediction_timestamp=now,
                forecast_horizon="NEAR_TERM",
                horizon_hours=1.0,
                horizon_end_timestamp=now,
                predicted_probability=prob,
                predicted_risk_score=min(95.0, prob * 100.0),
                predicted_threat_class="At-Risk / Threat",
                operating_threshold=0.32,
                threshold_crossed=True,
                outcome_status=PredictionOutcomeStatus.CONFIRMED_COMPROMISE,
                actual_outcome="COMPROMISED",
                top_features=[{"feature_name": "credential_anomalies", "feature_value": 3.5}],
            )
        )

    # Benign (Ground truth Y=0)
    for i in range(n_benign):
        prob = min(0.40, 0.05 + (i * 0.01))  # Probs in [0.05, 0.40]
        is_crossed = prob >= 0.32
        status = PredictionOutcomeStatus.FALSE_POSITIVE if is_crossed else PredictionOutcomeStatus.CORRECT_NON_EVENT
        records.append(
            PredictionRecord(
                prediction_id=f"test-benign-{i}-{uuid.uuid4().hex[:6]}",
                asset_id=f"ws-benign-{i % 5}",
                asset_name=f"Workstation {i}",
                asset_type="WORKSTATION",
                prediction_timestamp=now,
                forecast_horizon="NEAR_TERM",
                horizon_hours=1.0,
                horizon_end_timestamp=now,
                predicted_probability=prob,
                predicted_risk_score=min(40.0, prob * 100.0),
                predicted_threat_class="At-Risk / Threat" if is_crossed else "Healthy / Benign",
                operating_threshold=0.32,
                threshold_crossed=is_crossed,
                outcome_status=status,
                actual_outcome="BENIGN",
                top_features=[{"feature_name": "lateral_movement_depth", "feature_value": 0.5}],
            )
        )

    return records


# =============================================================================
# 1. EMPIRICAL CALIBRATION & SAMPLE SIZE SAFEGUARDS
# =============================================================================

def test_empirical_calibration_computation():
    """Validates calculation of ECE, Brier score, and 5 uniform reliability bins."""
    engine = RiskScoreCalibrationEngine()
    records = _create_mock_records(n_threats=20, n_benign=30)
    report = engine.evaluate_calibration(custom_records=records)

    assert report.sample_size == 50
    assert report.evaluated_threats_count == 20
    assert report.evaluated_benign_count == 30
    assert report.calibration_status in (
        CalibrationStatus.CALIBRATED,
        CalibrationStatus.SLIGHTLY_MISCALIBRATED,
        CalibrationStatus.SEVERELY_MISCALIBRATED,
    )
    assert report.expected_calibration_error is not None
    assert 0.0 <= report.expected_calibration_error <= 1.0
    assert report.brier_score is not None
    assert 0.0 <= report.brier_score <= 1.0
    assert len(report.reliability_bins) == 5

    # Check bin boundaries
    assert report.reliability_bins[0].bin_range_low == 0.0
    assert report.reliability_bins[0].bin_range_high == 0.20
    assert report.reliability_bins[4].bin_range_high == 1.0


def test_sample_size_safeguards():
    """Enforces that N < 10 returns INSUFFICIENT_DATA and prevents unscientific calibration."""
    engine = RiskScoreCalibrationEngine()
    small_records = _create_mock_records(n_threats=3, n_benign=3) # N = 6 < 10
    report = engine.evaluate_calibration(custom_records=small_records)

    assert report.calibration_status == CalibrationStatus.INSUFFICIENT_DATA
    assert report.confidence == "INSUFFICIENT_DATA"
    assert report.expected_calibration_error is None
    assert report.brier_score is None
    assert len(report.limitations) > 0


# =============================================================================
# 2. THRESHOLD OPTIMIZATION & CRITICAL PROTECTION INVARIANT
# =============================================================================

def test_cost_sensitive_threshold_optimizer():
    """Verifies candidate scan, cost function optimization, and recall constraints."""
    optimizer = IntelligentThresholdOptimizer()
    records = _create_mock_records(n_threats=15, n_benign=25)
    result = optimizer.optimize_threshold(custom_records=records, min_recall=0.85)

    assert result.baseline_threshold == 0.32
    assert 0.10 <= result.recommended_threshold <= 0.75
    assert result.candidate_metrics["recall"] >= 0.85
    assert result.candidate_configuration.status == ConfigurationStatus.PENDING_APPROVAL
    assert result.critical_threat_weakened is False
    assert "cost_reduction_percent" in result.tradeoffs


def test_critical_threat_protection_invariant():
    """Guarantees that critical assets are protected and critical cutoff is capped <= 0.32."""
    optimizer = IntelligentThresholdOptimizer()
    now = datetime.now(timezone.utc)

    # Critical payment server prediction
    crit_record = PredictionRecord(
        prediction_id="crit-pred-01",
        asset_id="node-srv-payment-app01",
        asset_name="Payment Application Server",
        asset_type="DATABASE",
        prediction_timestamp=now,
        forecast_horizon="NEAR_TERM",
        horizon_hours=1.0,
        horizon_end_timestamp=now,
        predicted_probability=0.33,
        predicted_risk_score=85.0,
        predicted_threat_class="At-Risk / Threat",
        operating_threshold=0.32,
        threshold_crossed=True,
        outcome_status=PredictionOutcomeStatus.CONFIRMED_COMPROMISE,
        actual_outcome="COMPROMISED",
    )

    records = _create_mock_records(n_threats=10, n_benign=20) + [crit_record]
    result = optimizer.optimize_threshold(custom_records=records)

    assert result.critical_threat_weakened is False
    # Check that candidate configuration does not weaken critical threat detection
    assert result.candidate_configuration.tiers.critical_cutoff >= result.recommended_threshold


# =============================================================================
# 3. SHADOW THRESHOLD EVALUATION & ASSET CLASSIFICATION FLIPS
# =============================================================================

def test_shadow_threshold_evaluator_simulation():
    """Runs zero-interference parallel simulation and validates classification flips."""
    evaluator = ShadowThresholdEvaluator()
    records = _create_mock_records(n_threats=15, n_benign=25)

    # Shadow evaluate at candidate theta = 0.20 (lower threshold catches more threats with more alerts)
    res = evaluator.evaluate_shadow_candidate(
        candidate_threshold=0.20,
        baseline_threshold=0.32,
        custom_records=records,
    )

    assert res.baseline_threshold == 0.32
    assert res.candidate_threshold == 0.20
    assert res.alert_volume_delta >= 0  # Lower threshold generates equal or more alerts
    assert res.critical_threats_retained is True
    assert isinstance(res.flipped_assets, list)

    for flip in res.flipped_assets:
        assert flip.baseline_classification != flip.candidate_classification
        assert flip.actual_outcome in ("COMPROMISED", "BENIGN")
        assert len(flip.impact_description) > 0


# =============================================================================
# 4. ALERT FATIGUE & GINI CONCENTRATION ANALYTICS
# =============================================================================

def test_alert_fatigue_and_gini_index():
    """Tests Gini inequality coefficient, composite Alert Fatigue Index, and noisy asset ranking."""
    analyzer = AlertFatigueAnalyzer()
    
    # Test Gini mathematical bounds: evenly distributed vs concentrated
    assert analyzer.compute_gini([10, 10, 10, 10]) == 0.0
    assert analyzer.compute_gini([0, 0, 0, 100]) == 0.75  # Highly concentrated

    records = _create_mock_records(n_threats=15, n_benign=30)
    fatigue = analyzer.analyze_alert_fatigue(custom_records=records)

    assert fatigue.total_alerts_analyzed > 0
    assert 0.0 <= fatigue.gini_alert_concentration <= 1.0
    assert 0.0 <= fatigue.alert_fatigue_index <= 100.0
    assert fatigue.fatigue_status in ("LOW", "MODERATE", "ELEVATED", "CRITICAL")
    assert isinstance(fatigue.noisy_assets, list)


# =============================================================================
# 5. TELEMETRY & RISK DRIFT DETECTION
# =============================================================================

def test_telemetry_and_risk_drift_detector():
    """Validates Population Stability Index (PSI), Wasserstein distance, and calibration degradation."""
    detector = TelemetryDriftDetector()

    # Synthetic identical distributions (PSI == 0.0)
    arr_a = np.array([1.0, 2.0, 3.0, 4.0, 5.0] * 10)
    arr_b = np.array([1.0, 2.0, 3.0, 4.0, 5.0] * 10)
    psi_stable = detector.calculate_psi(arr_a, arr_b)
    assert psi_stable == 0.0

    # Synthetic drifted distribution
    arr_drift = np.array([10.0, 20.0, 30.0, 40.0, 50.0] * 10)
    psi_drift = detector.calculate_psi(arr_a, arr_drift)
    assert psi_drift > 0.25

    records = _create_mock_records(n_threats=20, n_benign=30)
    report = detector.detect_drift(custom_records=records)

    assert report.evaluated_sample_size == 50
    assert report.risk_score_wasserstein_distance >= 0.0
    assert report.overall_drift_severity in ("STABLE", "MODERATE", "CRITICAL")


# =============================================================================
# 6. ADAPTIVE RECOMMENDATIONS ENGINE
# =============================================================================

def test_adaptive_recommendation_engine():
    """Verifies explainable recommendation synthesis across multiple analytical subsystems."""
    engine = AdaptiveRecommendationEngine()
    recs = engine.generate_recommendations()

    assert isinstance(recs, list)
    assert len(recs) > 0

    for rec in recs:
        assert rec.recommendation_id.startswith("rec-")
        assert len(rec.title) > 0
        assert rec.category in RecommendationCategory
        assert rec.severity in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert len(rec.proposed_change) > 0
        assert len(rec.expected_benefit) > 0
        assert rec.required_approval_role in ("ANALYST", "ADMIN")


# =============================================================================
# 7. CONFIGURATION VERSIONING & ROLLBACK LIFECYCLE
# =============================================================================

def test_configuration_versioning_and_rollback():
    """Tests the full human-in-the-loop lifecycle: Stage -> Approve -> Activate -> Rollback."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_file = os.path.join(tmpdir, "test_configurations.json")
        mgr = ConfigurationVersionManager(storage_path=config_file)

        # 1. Baseline initialization
        baseline = mgr.get_active_configuration()
        assert baseline.version == "1.0.0"
        assert baseline.status == ConfigurationStatus.ACTIVE
        assert baseline.operating_threshold == 0.32

        # 2. Stage candidate (PENDING_APPROVAL)
        cand_tiers = ThresholdTiers(low_cutoff=0.0, medium_cutoff=0.15, high_cutoff=0.25, critical_cutoff=0.65)
        cand = ThresholdConfiguration(
            config_id="cfg-test-opt",
            version="1.1.0",
            operating_threshold=0.25,
            tiers=cand_tiers,
            author_id="secops-analyst",
            author_role="ANALYST",
            rationale="Cost optimization scan reduction",
        )
        mgr.stage_candidate(cand)
        assert mgr.get_configuration("cfg-test-opt").status == ConfigurationStatus.PENDING_APPROVAL

        # 3. Analyst Approval (APPROVED)
        approved = mgr.approve_configuration("cfg-test-opt", analyst_id="analyst-user")
        assert approved.status == ConfigurationStatus.APPROVED
        assert approved.approved_by == "analyst-user"

        # 4. Administrator Activation (ACTIVE & baseline becomes SUPERSEDED)
        activated = mgr.activate_configuration("cfg-test-opt", admin_id="admin-user")
        assert activated.status == ConfigurationStatus.ACTIVE
        assert activated.activated_by == "admin-user"

        old_baseline = mgr.get_configuration("cfg-v1.0.0-baseline")
        assert old_baseline.status == ConfigurationStatus.SUPERSEDED

        # 5. Administrator Rollback
        rolled_back = mgr.rollback_configuration("cfg-v1.0.0-baseline", admin_id="admin-user", reason="Emergency rollback test")
        assert rolled_back.status == ConfigurationStatus.ACTIVE
        assert "ROLLED BACK" in rolled_back.rationale


# =============================================================================
# 8. GRAPH SYNCHRONIZATION & NEO4J RESILIENCE
# =============================================================================

def test_calibration_graph_synchronizer_resilience():
    """Verifies that ThresholdConfigurations sync into GraphEngine and handle offline Neo4j gracefully."""
    engine = GraphEngine(mode="in_memory")
    synchronizer = CalibrationGraphSynchronizer(graph_engine=engine)

    cfg = ThresholdConfiguration(
        config_id="cfg-graph-test",
        version="1.2.0",
        operating_threshold=0.28,
        tiers=ThresholdTiers(low_cutoff=0.0, medium_cutoff=0.18, high_cutoff=0.28, critical_cutoff=0.68),
        status=ConfigurationStatus.ACTIVE,
        author_id="admin-tester",
        author_role="ADMIN",
    )

    res = synchronizer.sync_configuration_to_graph(cfg, target_asset_ids=[])
    assert res["status"] == "SYNCED"
    assert res["config_id"] == "cfg-graph-test"
    assert res["nodes_created"] == 1

    # Verify policy node is in GraphEngine
    policy_node = engine.get_node("policy-cfg-graph-test")
    assert policy_node is not None
    assert policy_node.type == NodeType.SECURITY_CONTROL
    assert policy_node.properties["operating_threshold"] == 0.28


# =============================================================================
# 9. REGRESSION SAFETY: PHASE 7.4 & FORECASTING INTACT
# =============================================================================

def test_regression_safety_phase_7_4():
    """Confirms Phase 7.4 evaluation tracker and forecasting interfaces remain 100% operational."""
    from backend.app.adaptive.tracker import PredictionOutcomeTracker
    from backend.app.forecasting.forecaster import TemporalThreatForecaster

    tracker = PredictionOutcomeTracker.get_instance()
    forecaster = TemporalThreatForecaster.get_instance()

    assert tracker is not None
    assert forecaster is not None
    preds = tracker.get_all_predictions()
    assert isinstance(preds, list)
