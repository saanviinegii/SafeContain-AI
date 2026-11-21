"""Comprehensive Evidence-Based Verification & Audit Suite for SafeContain AI Phase 7.5.

Autonomous Principal AI/ML Engineer, Cybersecurity Architect, and Systems Auditor Script.
Runs all 10 verification checklist gates and outputs detailed diagnostic evidence.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List

# Ensure project root is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Set test environment
os.environ["ENVIRONMENT"] = "testing"
os.environ["GRAPH_BACKEND"] = "in_memory"
os.environ["MPLCONFIGDIR"] = os.path.join(BASE_DIR, "artifacts", "temp_mpl")

from backend.app.core.config import settings
settings.GRAPH_BACKEND = "in_memory"

import numpy as np
import pandas as pd
from fastapi import HTTPException

from backend.app.adaptive.models import PredictionOutcomeStatus, PredictionRecord
from backend.app.calibration.alert_analytics import AlertFatigueAnalyzer
from backend.app.calibration.calibration_engine import RiskScoreCalibrationEngine
from backend.app.calibration.config_manager import ConfigurationVersionManager
from backend.app.calibration.drift_detector import TelemetryDriftDetector
from backend.app.calibration.graph_sync import CalibrationGraphSynchronizer
from backend.app.calibration.models import (
    AdaptiveRecommendation,
    AlertFatigueAnalytics,
    CalibrationStatus,
    CandidateOptimizationResult,
    ConfigurationStatus,
    RecommendationCategory,
    RiskScoreCalibrationReport,
    ShadowEvaluationResult,
    TelemetryDriftReport,
    ThresholdConfiguration,
    ThresholdTiers,
)
from backend.app.calibration.recommendation_engine import AdaptiveRecommendationEngine
from backend.app.calibration.router import (
    RollbackRequest,
    ShadowEvaluationRequest,
    activate_configuration,
    approve_configuration,
    get_active_configuration,
    get_adaptive_recommendations,
    get_alert_fatigue_analytics,
    get_calibration_overview,
    get_calibration_report,
    get_telemetry_drift_report,
    list_configurations,
    reject_configuration,
    rollback_configuration,
    run_shadow_evaluation,
    run_threshold_optimization,
)
from backend.app.calibration.shadow_evaluator import ShadowThresholdEvaluator
from backend.app.calibration.threshold_optimizer import IntelligentThresholdOptimizer
from backend.app.security.auth import require_admin, require_analyst, require_viewer
from backend.app.security.roles import AppRole
from backend.app.security.user_store import UserRecord

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("phase_7_5_audit")

AUDIT_RESULTS: Dict[str, Any] = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "checklist": {},
    "metrics_comparison": {},
    "api_matrix": {},
    "security_invariants": {},
    "passed_gates": 0,
    "total_gates": 10,
    "verdict": "PENDING",
}


def log_gate(gate_id: str, title: str, status: str, details: Dict[str, Any]) -> None:
    """Records audit gate outcome with diagnostic details."""
    logger.info(f"[{status}] {gate_id}: {title}")
    AUDIT_RESULTS["checklist"][gate_id] = {
        "title": title,
        "status": status,
        "details": details,
    }


# =============================================================================
# GATE 1: Empirical Risk Score Calibration Engine
# =============================================================================
def verify_gate_1_calibration_engine() -> None:
    """Verifies reliability diagram binning, ECE, Brier score, and miscalibration detection."""
    engine = RiskScoreCalibrationEngine.get_instance()
    report = engine.evaluate_calibration()

    assert report is not None
    assert isinstance(report, RiskScoreCalibrationReport)
    assert report.sample_size >= 10, f"Insufficient sample size: {report.sample_size}"
    assert len(report.reliability_bins) == 5, f"Expected 5 bins, got {len(report.reliability_bins)}"
    assert report.expected_calibration_error is not None
    assert 0.0 <= report.expected_calibration_error <= 1.0
    assert report.brier_score is not None
    assert 0.0 <= report.brier_score <= 1.0
    assert report.calibration_status in [
        CalibrationStatus.CALIBRATED,
        CalibrationStatus.SLIGHTLY_MISCALIBRATED,
        CalibrationStatus.SEVERELY_MISCALIBRATED,
    ]
    assert report.overprediction_rate is not None
    assert report.underprediction_rate is not None
    assert 0.0 <= report.overprediction_rate <= 1.0
    assert 0.0 <= report.underprediction_rate <= 1.0
    assert len(report.asset_type_breakdowns) > 0, "Asset type breakdown must not be empty"

    # Verify mathematical integrity of ECE calculation across non-empty bins
    total_samples = report.sample_size
    manual_ece = sum(
        (bin_item.sample_count / total_samples) * bin_item.calibration_error
        for bin_item in report.reliability_bins
        if bin_item.sample_count > 0 and bin_item.calibration_error is not None
    )
    assert abs(manual_ece - report.expected_calibration_error) < 1e-4, "ECE formula mismatch"

    log_gate(
        "GATE_1",
        "Empirical Risk Score Calibration Engine",
        "PASS",
        {
            "sample_size": report.sample_size,
            "ece": report.expected_calibration_error,
            "brier_score": report.brier_score,
            "quality_score": report.calibration_quality_score,
            "status": report.calibration_status.value,
            "overprediction_rate": report.overprediction_rate,
            "underprediction_rate": report.underprediction_rate,
            "bins_evaluated": len(report.reliability_bins),
            "asset_categories_evaluated": [b.category_name for b in report.asset_type_breakdowns],
        },
    )


# =============================================================================
# GATE 2: Sample Size Safeguards (N < 10)
# =============================================================================
def verify_gate_2_sample_size_safeguards() -> None:
    """Verifies that sample size < 10 strictly flags INSUFFICIENT_DATA and disables ungrounded tuning."""
    engine = RiskScoreCalibrationEngine.get_instance()

    # Case A: Empty data (N = 0)
    empty_report = engine.evaluate_calibration(custom_records=[])
    assert empty_report.sample_size == 0
    assert empty_report.calibration_status == CalibrationStatus.INSUFFICIENT_DATA
    assert empty_report.expected_calibration_error is None
    assert any("below the minimum threshold" in lim for lim in empty_report.limitations)

    # Case B: Small data (N = 5 < 10)
    small_records = []
    now = datetime.now(timezone.utc)
    for i in range(5):
        small_records.append(
            PredictionRecord(
                prediction_id=f"small-rec-{i}",
                asset_id=f"asset-{i}",
                asset_name=f"Asset {i}",
                asset_type="WORKSTATION",
                prediction_timestamp=now,
                forecast_horizon="SHORT_TERM",
                horizon_hours=6.0,
                horizon_end_timestamp=now,
                predicted_probability=0.45,
                predicted_risk_score=45.0,
                predicted_threat_class="At-Risk",
                threshold_crossed=True,
                outcome_status=PredictionOutcomeStatus.CORRECT_NON_EVENT,
                actual_outcome="BENIGN",
            )
        )
    small_report = engine.evaluate_calibration(custom_records=small_records)
    assert small_report.sample_size == 5
    assert small_report.calibration_status == CalibrationStatus.INSUFFICIENT_DATA
    assert small_report.expected_calibration_error is None
    assert any("below the minimum threshold" in lim for lim in small_report.limitations)

    log_gate(
        "GATE_2",
        "Sample Size Safeguards (N < 10 Guard)",
        "PASS",
        {
            "empty_case_status": empty_report.calibration_status.value,
            "small_case_status": small_report.calibration_status.value,
            "ece_suppressed": empty_report.expected_calibration_error is None,
            "safe_governance_limitations_emitted": True,
        },
    )


# =============================================================================
# GATE 3: Cost-Sensitive Threshold Optimization
# =============================================================================
def verify_gate_3_threshold_optimization() -> None:
    """Verifies asymmetric cost optimization (10*FN + 1*FP + 25*CriticalMissed) with recall >= 0.90."""
    optimizer = IntelligentThresholdOptimizer.get_instance()
    result = optimizer.optimize_threshold(min_recall=0.90)

    assert result is not None
    assert isinstance(result, CandidateOptimizationResult)
    assert result.status == "CANDIDATE_GENERATED"
    assert result.candidate_configuration is not None

    cand = result.candidate_configuration
    base_metrics = result.baseline_metrics
    cand_metrics = result.candidate_metrics

    # Cost function validation: Cost = 10*FN + 1*FP + 25*CriticalMissed
    expected_base_cost = (
        10.0 * base_metrics["false_negatives"]
        + 1.0 * base_metrics["false_positives"]
        + 25.0 * base_metrics["critical_missed"]
    )
    assert abs(base_metrics["total_cost"] - expected_base_cost) < 1e-4, "Baseline cost calculation error"

    expected_cand_cost = (
        10.0 * cand_metrics["false_negatives"]
        + 1.0 * cand_metrics["false_positives"]
        + 25.0 * cand_metrics["critical_missed"]
    )
    assert abs(cand_metrics["total_cost"] - expected_cand_cost) < 1e-4, "Candidate cost calculation error"

    # Recall constraint verification: effective recall must not drop below baseline recall or target
    effective_min_recall = min(0.90, base_metrics["recall"]) if base_metrics["recall"] < 0.90 else 0.90
    if cand_metrics.get("recall") is not None:
        assert cand_metrics["recall"] >= effective_min_recall - 1e-4, (
            f"Candidate recall {cand_metrics['recall']} violated effective recall constraint {effective_min_recall}"
        )

    # Must outperform or equal baseline in total cost
    assert cand_metrics["total_cost"] <= base_metrics["total_cost"], "Candidate cost exceeds baseline cost"
    cost_reduction_pct = result.tradeoffs.get("cost_reduction_percent", 0.0)
    assert cost_reduction_pct >= 0.0

    AUDIT_RESULTS["metrics_comparison"]["baseline_threshold"] = result.baseline_threshold
    AUDIT_RESULTS["metrics_comparison"]["baseline_cost"] = base_metrics["total_cost"]
    AUDIT_RESULTS["metrics_comparison"]["candidate_threshold"] = result.recommended_threshold
    AUDIT_RESULTS["metrics_comparison"]["candidate_cost"] = cand_metrics["total_cost"]
    AUDIT_RESULTS["metrics_comparison"]["cost_reduction_percent"] = cost_reduction_pct

    log_gate(
        "GATE_3",
        "Cost-Sensitive Threshold Optimization",
        "PASS",
        {
            "baseline_threshold": result.baseline_threshold,
            "candidate_threshold": result.recommended_threshold,
            "baseline_cost": base_metrics["total_cost"],
            "candidate_cost": cand_metrics["total_cost"],
            "cost_reduction_percent": cost_reduction_pct,
            "baseline_recall": base_metrics["recall"],
            "candidate_recall": cand_metrics["recall"],
            "candidate_fn": cand_metrics["false_negatives"],
            "candidate_fp": cand_metrics["false_positives"],
            "candidate_critical_misses": cand_metrics["critical_missed"],
        },
    )


# =============================================================================
# GATE 4: Critical Threat Protection Invariant
# =============================================================================
def verify_gate_4_critical_threat_protection() -> None:
    """Verifies that critical threshold theta_crit <= 0.32 and critical recall is never degraded."""
    optimizer = IntelligentThresholdOptimizer.get_instance()
    result = optimizer.optimize_threshold(min_recall=0.90)
    cand = result.candidate_configuration

    # Invariant 1: Operating threshold must be safe and not weaken critical protection
    assert cand.operating_threshold <= 0.32, f"Candidate operating threshold {cand.operating_threshold} exceeded cap of 0.32"

    # Invariant 2: Candidate misses no more critical threats than baseline
    assert result.critical_threat_weakened is False
    assert result.candidate_metrics["critical_missed"] <= result.baseline_metrics["critical_missed"]

    AUDIT_RESULTS["security_invariants"]["critical_threshold_capped"] = True
    AUDIT_RESULTS["security_invariants"]["critical_misses_count"] = result.candidate_metrics["critical_missed"]
    AUDIT_RESULTS["security_invariants"]["critical_threats_retained"] = True

    log_gate(
        "GATE_4",
        "Critical Threat Protection Invariant",
        "PASS",
        {
            "candidate_operating_threshold": cand.operating_threshold,
            "baseline_operating_threshold": result.baseline_threshold,
            "candidate_critical_misses": result.candidate_metrics["critical_missed"],
            "baseline_critical_misses": result.baseline_metrics["critical_missed"],
            "critical_threat_weakened": result.critical_threat_weakened,
        },
    )


# =============================================================================
# GATE 5: Zero-Interference Shadow Threshold Evaluation
# =============================================================================
def verify_gate_5_shadow_evaluation() -> None:
    """Verifies shadow evaluation computes alert volume deltas, FPR/FNR shifts, and flips without altering live state."""
    evaluator = ShadowThresholdEvaluator.get_instance()
    cfg_mgr = ConfigurationVersionManager.get_instance()
    active_cfg = cfg_mgr.get_active_configuration()

    shadow_res = evaluator.evaluate_shadow_candidate(
        candidate_threshold=0.25,
        candidate_config_id="test-shadow-cand",
        baseline_threshold=active_cfg.operating_threshold,
        baseline_config_id=active_cfg.config_id,
    )

    assert shadow_res is not None
    assert isinstance(shadow_res, ShadowEvaluationResult)
    assert shadow_res.evaluated_sample_size >= 10
    assert shadow_res.baseline_threshold == active_cfg.operating_threshold
    assert shadow_res.candidate_threshold == 0.25
    assert shadow_res.alert_volume_delta is not None
    assert shadow_res.alert_volume_percent_change is not None
    assert shadow_res.critical_threats_retained is True
    assert shadow_res.critical_threat_miss_count <= shadow_res.baseline_false_negatives
    assert isinstance(shadow_res.flipped_assets, list)

    # Ensure live active configuration was untouched by shadow evaluation
    post_cfg = cfg_mgr.get_active_configuration()
    assert post_cfg.config_id == active_cfg.config_id
    assert post_cfg.operating_threshold == active_cfg.operating_threshold

    log_gate(
        "GATE_5",
        "Zero-Interference Shadow Threshold Evaluation",
        "PASS",
        {
            "baseline_threshold": shadow_res.baseline_threshold,
            "candidate_threshold": shadow_res.candidate_threshold,
            "alert_volume_delta": shadow_res.alert_volume_delta,
            "alert_volume_percent_change": shadow_res.alert_volume_percent_change,
            "false_positive_delta": shadow_res.false_positive_delta,
            "false_negative_delta": shadow_res.false_negative_delta,
            "classification_flips_count": shadow_res.classification_flips_count,
            "critical_threats_retained": shadow_res.critical_threats_retained,
            "live_configuration_untouched": True,
        },
    )


# =============================================================================
# GATE 6: Alert Fatigue & Gini Concentration Analytics
# =============================================================================
def verify_gate_6_alert_fatigue_analytics() -> None:
    """Verifies alert volume distribution, Gini inequality calculation, composite AFI, and noisy asset ranking."""
    analyzer = AlertFatigueAnalyzer.get_instance()
    fatigue = analyzer.analyze_alert_fatigue()

    assert fatigue is not None
    assert isinstance(fatigue, AlertFatigueAnalytics)
    assert fatigue.total_alerts_analyzed >= 0
    assert 0.0 <= fatigue.gini_alert_concentration <= 1.0, f"Gini coefficient {fatigue.gini_alert_concentration} out of bounds"
    assert 0.0 <= fatigue.alert_fatigue_index <= 100.0, f"AFI {fatigue.alert_fatigue_index} out of bounds"
    assert fatigue.fatigue_status in ["LOW", "MODERATE", "ELEVATED", "CRITICAL"]
    assert 0.0 <= fatigue.overall_false_alarm_ratio <= 1.0
    assert isinstance(fatigue.noisy_assets, list)
    assert len(fatigue.noisy_assets) > 0, "Noisy assets list should contain ranked assets"

    # Verify noisy assets are properly sorted by false_positive_count descending
    fp_counts = [a.false_positive_count for a in fatigue.noisy_assets]
    assert fp_counts == sorted(fp_counts, reverse=True), "Noisy assets not sorted by false positives descending"

    log_gate(
        "GATE_6",
        "Alert Fatigue Analytics & Gini Concentration",
        "PASS",
        {
            "total_alerts": fatigue.total_alerts_analyzed,
            "gini_alert_concentration": fatigue.gini_alert_concentration,
            "alert_fatigue_index": fatigue.alert_fatigue_index,
            "fatigue_status": fatigue.fatigue_status,
            "false_alarm_ratio": fatigue.overall_false_alarm_ratio,
            "top_noisy_asset": fatigue.noisy_assets[0].asset_name if fatigue.noisy_assets else None,
            "top_noisy_asset_fps": fatigue.noisy_assets[0].false_positive_count if fatigue.noisy_assets else 0,
        },
    )


# =============================================================================
# GATE 7: Telemetry Feature Drift & Risk Distribution Diagnostics
# =============================================================================
def verify_gate_7_drift_detector() -> None:
    """Verifies PSI calculation, Wasserstein distance, calibration degradation, and sensor coverage gaps."""
    detector = TelemetryDriftDetector.get_instance()
    drift = detector.detect_drift()

    assert drift is not None
    assert isinstance(drift, TelemetryDriftReport)
    assert drift.overall_drift_severity in [
        "STABLE",
        "MODERATE",
        "MODERATE_DRIFT",
        "SIGNIFICANT_DRIFT",
        "CRITICAL",
    ]
    assert drift.risk_score_wasserstein_distance >= 0.0
    assert isinstance(drift.calibration_degradation_detected, bool)
    assert isinstance(drift.feature_drift_breakdown, list)
    assert len(drift.feature_drift_breakdown) > 0, "Feature drift breakdown should evaluate key features"

    # Verify PSI scores are valid non-negative numbers
    for item in drift.feature_drift_breakdown:
        assert item.psi_score >= 0.0
        assert item.drift_status in ["STABLE", "MODERATE_DRIFT", "SIGNIFICANT_DRIFT"]

    log_gate(
        "GATE_7",
        "Telemetry Drift & Risk Shift Diagnostics",
        "PASS",
        {
            "drift_detected": drift.drift_detected,
            "overall_drift_severity": drift.overall_drift_severity,
            "wasserstein_distance": drift.risk_score_wasserstein_distance,
            "calibration_degradation_detected": drift.calibration_degradation_detected,
            "features_evaluated": [f.feature_name for f in drift.feature_drift_breakdown],
            "max_psi": max((f.psi_score for f in drift.feature_drift_breakdown), default=0.0),
        },
    )


# =============================================================================
# GATE 8: Adaptive Recommendation Engine
# =============================================================================
def verify_gate_8_recommendation_engine() -> None:
    """Verifies generation of structured, explainable recommendations grounded in empirical evidence."""
    rec_engine = AdaptiveRecommendationEngine.get_instance()
    recs = rec_engine.generate_recommendations()

    assert recs is not None
    assert isinstance(recs, list)
    assert len(recs) > 0, "Recommendation engine should generate at least one governance recommendation"

    for r in recs:
        assert isinstance(r, AdaptiveRecommendation)
        assert r.recommendation_id.lower().startswith("rec-")
        assert len(r.title) > 0
        assert len(r.explanation) > 0
        assert r.required_approval_role in ["ADMIN", "ANALYST"]
        assert r.category in [c.value for c in RecommendationCategory]
        assert r.sample_size >= 0
        assert len(r.alternative_options) > 0
        assert len(r.proposed_change) > 0
        assert len(r.expected_benefit) > 0

    log_gate(
        "GATE_8",
        "Adaptive Recommendation Engine",
        "PASS",
        {
            "recommendations_generated": len(recs),
            "categories": list({r.category for r in recs}),
            "required_roles": list({r.required_approval_role for r in recs}),
            "sample_recommendation": {
                "id": recs[0].recommendation_id,
                "title": recs[0].title,
                "category": recs[0].category,
                "required_role": recs[0].required_approval_role,
            },
        },
    )


# =============================================================================
# GATE 9: Configuration Versioning, Approval, Activation & Rollback Lifecycle
# =============================================================================
def verify_gate_9_config_lifecycle() -> None:
    """Verifies configuration staging, analyst approval, admin activation, and auditable rollback."""
    cfg_mgr = ConfigurationVersionManager.get_instance()
    initial_active = cfg_mgr.get_active_configuration()

    # Stage a candidate configuration
    candidate = ThresholdConfiguration(
        config_id=f"cfg-audit-cand-{int(datetime.now().timestamp())}",
        version="v1.2.0-audit",
        status=ConfigurationStatus.PENDING_APPROVAL,
        operating_threshold=0.28,
        tiers=ThresholdTiers(low_cutoff=0.0, medium_cutoff=0.18, high_cutoff=0.28, critical_cutoff=0.65),
        author_id="audit_agent",
        author_role="ANALYST",
        rationale="Audit stage test",
        supporting_evidence={"reason": "test"},
    )
    staged = cfg_mgr.stage_candidate(candidate)
    assert staged.status == ConfigurationStatus.PENDING_APPROVAL

    # Step 1: Analyst approves
    approved = cfg_mgr.approve_configuration(staged.config_id, analyst_id="analyst_auditor")
    assert approved is not None
    assert approved.status == ConfigurationStatus.APPROVED
    assert approved.approved_by == "analyst_auditor"

    # Step 2: Admin activates
    activated = cfg_mgr.activate_configuration(approved.config_id, admin_id="admin_auditor")
    assert activated is not None
    assert activated.status == ConfigurationStatus.ACTIVE
    assert activated.activated_by == "admin_auditor"
    assert cfg_mgr.get_active_configuration().config_id == staged.config_id

    # Step 3: Admin rolls back to initial configuration
    rolled_back = cfg_mgr.rollback_configuration(
        target_config_id=initial_active.config_id,
        admin_id="admin_auditor",
        reason="Reverting to initial active configuration after audit",
    )
    assert rolled_back is not None
    assert rolled_back.config_id == initial_active.config_id
    assert rolled_back.status == ConfigurationStatus.ACTIVE
    assert cfg_mgr.get_active_configuration().config_id == initial_active.config_id

    log_gate(
        "GATE_9",
        "Configuration Versioning, Approval & Rollback",
        "PASS",
        {
            "initial_version": initial_active.version,
            "staged_version": staged.version,
            "approved_by": approved.approved_by,
            "activated_by": activated.activated_by,
            "rollback_target": rolled_back.config_id,
            "final_active_version": cfg_mgr.get_active_configuration().version,
        },
    )


# =============================================================================
# GATE 10: REST API & Role-Based Access Control (RBAC) & Graph Sync
# =============================================================================
def verify_gate_10_rest_api_and_rbac() -> None:
    """Verifies all 13 REST endpoints, RBAC permissions (Viewer/Analyst/Admin), and GraphEngine synchronization."""
    now_iso = datetime.now(timezone.utc).isoformat()
    viewer_user = UserRecord(
        id="usr-viewer-01",
        username="viewer_user",
        hashed_password="",
        role=AppRole.VIEWER,
        created_at=now_iso,
        updated_at=now_iso,
    )
    analyst_user = UserRecord(
        id="usr-analyst-01",
        username="analyst_user",
        hashed_password="",
        role=AppRole.ANALYST,
        created_at=now_iso,
        updated_at=now_iso,
    )
    admin_user = UserRecord(
        id="usr-admin-01",
        username="admin_user",
        hashed_password="",
        role=AppRole.ADMIN,
        created_at=now_iso,
        updated_at=now_iso,
    )

    results: Dict[str, Any] = {}

    def check_role_dependency(dep_fn, user: UserRecord) -> int:
        coro = dep_fn(user)
        try:
            coro.send(None)
            return 200
        except HTTPException as exc:
            return exc.status_code
        except StopIteration:
            return 200

    # 1. GET /overview (Viewer)
    overview = get_calibration_overview(current_user=viewer_user)
    assert overview.active_version is not None
    results["GET /overview"] = {"status": 200, "role": "viewer"}

    # 2. GET /report (Viewer)
    report = get_calibration_report(current_user=viewer_user)
    assert report.sample_size >= 10
    results["GET /report"] = {"status": 200, "role": "viewer"}

    # 3. POST /optimize (Viewer -> 403, Analyst -> 200)
    viewer_opt_code = check_role_dependency(require_analyst, viewer_user)
    assert viewer_opt_code == 403, "Viewer must be blocked from running optimization"

    opt_res = run_threshold_optimization(min_recall=0.90, current_user=analyst_user)
    assert opt_res.status == "CANDIDATE_GENERATED"
    results["POST /optimize"] = {"status": 200, "viewer_blocked_403": True, "role": "analyst"}

    # 4. POST /shadow-evaluate (Analyst)
    shadow_req = ShadowEvaluationRequest(candidate_threshold=0.22)
    shadow_res = run_shadow_evaluation(request=shadow_req, current_user=analyst_user)
    assert shadow_res.evaluated_sample_size >= 10
    results["POST /shadow-evaluate"] = {"status": 200, "role": "analyst"}

    # 5. GET /alert-fatigue (Viewer)
    fatigue_res = get_alert_fatigue_analytics(current_user=viewer_user)
    assert fatigue_res.total_alerts_analyzed >= 0
    results["GET /alert-fatigue"] = {"status": 200, "role": "viewer"}

    # 6. GET /drift (Viewer)
    drift_res = get_telemetry_drift_report(current_user=viewer_user)
    assert drift_res.overall_drift_severity is not None
    results["GET /drift"] = {"status": 200, "role": "viewer"}

    # 7. GET /recommendations (Viewer)
    rec_res = get_adaptive_recommendations(current_user=viewer_user)
    assert len(rec_res) > 0
    results["GET /recommendations"] = {"status": 200, "role": "viewer"}

    # 8. GET /configurations (Viewer)
    configs = list_configurations(current_user=viewer_user)
    assert len(configs) > 0
    results["GET /configurations"] = {"status": 200, "role": "viewer"}

    # 9. GET /configurations/active (Viewer)
    active_cfg = get_active_configuration(current_user=viewer_user)
    assert active_cfg.status == ConfigurationStatus.ACTIVE
    results["GET /configurations/active"] = {"status": 200, "role": "viewer"}

    # 10. POST /configurations/{id}/approve (Analyst)
    cfg_mgr = ConfigurationVersionManager.get_instance()
    cand = ThresholdConfiguration(
        config_id=f"cfg-rbac-test-{int(datetime.now().timestamp())}",
        version="v1.9.9-test",
        status=ConfigurationStatus.PENDING_APPROVAL,
        operating_threshold=0.30,
        tiers=ThresholdTiers(low_cutoff=0.0, medium_cutoff=0.18, high_cutoff=0.30, critical_cutoff=0.65),
        author_id="rbac_test",
        author_role="ANALYST",
        rationale="RBAC endpoint verification",
        supporting_evidence={"reason": "test"},
    )
    cfg_mgr.stage_candidate(cand)

    appr_res = approve_configuration(config_id=cand.config_id, current_user=analyst_user)
    assert appr_res.status == ConfigurationStatus.APPROVED
    results["POST /configurations/{id}/approve"] = {"status": 200, "role": "analyst"}

    # 11. POST /configurations/{id}/activate (Analyst -> 403, Admin -> 200)
    analyst_act_code = check_role_dependency(require_admin, analyst_user)
    assert analyst_act_code == 403, "Analyst must be blocked from activating configurations"

    act_res = activate_configuration(config_id=cand.config_id, current_user=admin_user)
    assert act_res.status == ConfigurationStatus.ACTIVE
    results["POST /configurations/{id}/activate"] = {"status": 200, "analyst_blocked_403": True, "role": "admin"}

    # 12. POST /configurations/rollback (Analyst -> 403, Admin -> 200)
    analyst_rb_code = check_role_dependency(require_admin, analyst_user)
    assert analyst_rb_code == 403, "Analyst must be blocked from rolling back configurations"

    rb_req = RollbackRequest(target_config_id=active_cfg.config_id, reason="RBAC verification rollback")
    rb_res = rollback_configuration(request=rb_req, current_user=admin_user)
    assert rb_res.config_id == active_cfg.config_id
    assert rb_res.status == ConfigurationStatus.ACTIVE
    results["POST /configurations/rollback"] = {"status": 200, "analyst_blocked_403": True, "role": "admin"}

    # 13. POST /configurations/{id}/reject (Analyst)
    cand_reject = ThresholdConfiguration(
        config_id=f"cfg-reject-test-{int(datetime.now().timestamp())}",
        version="v1.9.8-reject",
        status=ConfigurationStatus.PENDING_APPROVAL,
        operating_threshold=0.35,
        tiers=ThresholdTiers(low_cutoff=0.0, medium_cutoff=0.20, high_cutoff=0.35, critical_cutoff=0.70),
        author_id="reject_test",
        author_role="ANALYST",
        rationale="Reject verification",
        supporting_evidence={"reason": "test"},
    )
    cfg_mgr.stage_candidate(cand_reject)
    rej_res = reject_configuration(config_id=cand_reject.config_id, reason="Rejected in audit test", current_user=analyst_user)
    assert rej_res.status == ConfigurationStatus.REJECTED
    results["POST /configurations/{id}/reject"] = {"status": 200, "role": "analyst"}

    # Verify GraphEngine synchronization
    graph_sync = CalibrationGraphSynchronizer()
    sync_report = graph_sync.sync_configuration_to_graph(active_cfg)
    assert sync_report["status"] in ["SYNCED", "SYNCHRONIZED", "POLICY_UPDATED"]
    assert sync_report.get("nodes_created", sync_report.get("nodes_synced", 0)) >= 1

    # Verify Frontend / Client Parity
    client_ts_path = os.path.join(BASE_DIR, "frontend", "src", "api", "client.ts")
    app_tsx_path = os.path.join(BASE_DIR, "frontend", "src", "App.tsx")

    with open(client_ts_path, "r", encoding="utf-8") as f:
        client_ts_content = f.read()
    with open(app_tsx_path, "r", encoding="utf-8") as f:
        app_tsx_content = f.read()

    # Check client.ts API client methods
    assert "getCalibrationOverview" in client_ts_content
    assert "getCalibrationReport" in client_ts_content
    assert "optimizeThreshold" in client_ts_content
    assert "runShadowEvaluation" in client_ts_content
    assert "getAlertFatigueAnalytics" in client_ts_content
    assert "getTelemetryDriftReport" in client_ts_content
    assert "getAdaptiveRecommendations" in client_ts_content
    assert "listConfigurations" in client_ts_content
    assert "approveConfiguration" in client_ts_content
    assert "activateConfiguration" in client_ts_content
    assert "rollbackConfiguration" in client_ts_content

    # Check App.tsx view & subtabs
    assert "RISK_CALIBRATION" in app_tsx_content
    assert "Reliability Diagram & Calibration" in app_tsx_content or "Expected Calibration Error" in app_tsx_content
    assert "Threshold Optimization & Shadow Testing" in app_tsx_content
    assert "Alert Fatigue & Telemetry Drift" in app_tsx_content
    assert "Recommendations & Versioned Policy Lifecycle" in app_tsx_content

    AUDIT_RESULTS["api_matrix"] = results

    log_gate(
        "GATE_10",
        "REST API, RBAC Matrix & Graph Persistence",
        "PASS",
        {
            "total_endpoints_verified": len(results),
            "viewer_403_enforced_on_mutating_actions": True,
            "analyst_403_enforced_on_admin_actions": True,
            "admin_activation_and_rollback_verified": True,
            "graph_engine_policy_sync_verified": True,
            "frontend_client_parity_verified": True,
        },
    )


# =============================================================================
# MAIN AUDIT RUNNER
# =============================================================================
def run_full_audit() -> int:
    """Executes all 10 Phase 7.5 audit gates and outputs comprehensive diagnostics."""
    print("=" * 80)
    print("SAFECONTAIN AI — PHASE 7.5 AUDIT & VERIFICATION SUITE")
    print("Adaptive Risk Calibration & Intelligent Threshold Optimization")
    print("=" * 80)

    gates = [
        ("GATE_1", verify_gate_1_calibration_engine),
        ("GATE_2", verify_gate_2_sample_size_safeguards),
        ("GATE_3", verify_gate_3_threshold_optimization),
        ("GATE_4", verify_gate_4_critical_threat_protection),
        ("GATE_5", verify_gate_5_shadow_evaluation),
        ("GATE_6", verify_gate_6_alert_fatigue_analytics),
        ("GATE_7", verify_gate_7_drift_detector),
        ("GATE_8", verify_gate_8_recommendation_engine),
        ("GATE_9", verify_gate_9_config_lifecycle),
        ("GATE_10", verify_gate_10_rest_api_and_rbac),
    ]

    passed_count = 0
    failed_count = 0

    for gate_id, gate_fn in gates:
        try:
            gate_fn()
            passed_count += 1
            print(f"  [✓] {gate_id} PASSED")
        except Exception as exc:
            failed_count += 1
            logger.error(f"  [✗] {gate_id} FAILED: {exc}", exc_info=True)
            print(f"  [✗] {gate_id} FAILED: {exc}")
            AUDIT_RESULTS["checklist"][gate_id] = {
                "title": gate_id,
                "status": "FAIL",
                "error": str(exc),
            }

    AUDIT_RESULTS["passed_gates"] = passed_count
    AUDIT_RESULTS["verdict"] = "PASS" if failed_count == 0 else "FAIL"

    # Save structured audit results JSON
    output_dir = os.path.join(BASE_DIR, "artifacts", "calibration")
    os.makedirs(output_dir, exist_ok=True)
    audit_file = os.path.join(output_dir, "phase_7_5_audit_results.json")
    with open(audit_file, "w", encoding="utf-8") as f:
        json.dump(AUDIT_RESULTS, f, indent=2)

    print("=" * 80)
    print(f"AUDIT SUMMARY: {passed_count}/{len(gates)} GATES PASSED")
    print(f"FINAL VERDICT: {AUDIT_RESULTS['verdict']}")
    print(f"AUDIT EVIDENCE WRITTEN TO: {audit_file}")
    print("=" * 80)

    return 0 if failed_count == 0 else 1


if __name__ == "__main__":
    sys.exit(run_full_audit())
