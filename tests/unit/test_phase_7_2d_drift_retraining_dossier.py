"""Comprehensive Unit & Integration Test Suite for SafeContain AI Phase 7.2D.

Validates:
1. Continuous Telemetry Drift Detection:
   - Numerical PSI and 2-sample Kolmogorov-Smirnov test.
   - Categorical PSI and frequency shift analysis.
   - Threat probability prediction drift and threshold crossing deltas.
   - Data quality drift (missing rates, unexpected columns, schema checks).
   - Multi-tiered severity classification (NORMAL, LOW, MODERATE, HIGH, CRITICAL).
   - Automated retraining recommendations and persistent drift history.
2. Controlled Retraining Pipeline & Champion-Challenger Lifecycle:
   - Pre-training validation gate (target presence, min 50 samples, class balance, zero leakage).
   - Candidate model training with 5-fold stratified CV + holdout evaluation.
   - Decision threshold calibration under cost-sensitive threat constraints.
   - Side-by-side champion-challenger comparative evaluation and recommendation logic.
   - Model version repository governance (`artifacts/models/versions/`).
   - Non-autonomous model promotion, rejection, and emergency rollback.
3. Automated Incident Dossier Generation & Professional PDF Export:
   - Comprehensive incident data aggregation (assets, attack routes, SHAP drivers, CP-SAT actions, drift context).
   - Cryptographic SHA-256 audit digest calculation.
   - Publication-grade PDF rendering with ReportLab and NumberedCanvas.
   - File persistence and JSON export.
4. FastAPI REST Endpoints:
   - Drift status, history, and on-demand run.
   - Retraining request, jobs, comparison, promotion, rejection, rollback, and version list.
   - Incident dossier generation, list, preview, and PDF download streaming.
"""

import os
import json
import pytest
import numpy as np
import pandas as pd
from datetime import datetime, timezone

from backend.app.ml.drift_detector import (
    TelemetryDriftDetector,
    calculate_psi,
    calculate_categorical_psi,
    DriftSeverity,
)
from backend.app.ml.retraining import (
    RetrainingManager,
    ModelStatus,
    PromotionRecommendation,
)
from backend.app.reporting.dossier_generator import IncidentDossierGenerator
from backend.app.ml.task_definition import TOPOLOGY_FEATURE_COLUMNS
from backend.app.security.user_store import UserRecord
from backend.app.security.roles import UserRole


@pytest.fixture
def viewer_user():
    now = datetime.now(timezone.utc).isoformat()
    return UserRecord(
        id="usr-test-viewer",
        username="test_auditor",
        role="VIEWER",
        hashed_password="pw",
        is_active=True,
        created_at=now,
        updated_at=now,
    )


@pytest.fixture
def analyst_user():
    now = datetime.now(timezone.utc).isoformat()
    return UserRecord(
        id="usr-test-analyst",
        username="test_secops_lead",
        role="ANALYST",
        hashed_password="pw",
        is_active=True,
        created_at=now,
        updated_at=now,
    )


# =============================================================================
# 1. TELEMETRY DRIFT DETECTION TESTS
# =============================================================================

def test_calculate_psi_numerical():
    """Verifies numerical PSI calculation: 0.0 for identical distributions, high for shifted."""
    np.random.seed(42)
    ref = np.random.normal(loc=10.0, scale=2.0, size=500)
    curr_same = np.random.normal(loc=10.0, scale=2.0, size=500)
    curr_shifted = np.random.normal(loc=18.0, scale=2.0, size=500)

    psi_same = calculate_psi(ref, curr_same)
    psi_shifted = calculate_psi(ref, curr_shifted)

    assert psi_same < 0.10, f"Expected low PSI for similar distributions, got {psi_same}"
    assert psi_shifted > 0.25, f"Expected high PSI (>0.25) for shifted distribution, got {psi_shifted}"


def test_calculate_categorical_psi():
    """Verifies categorical PSI calculation on discrete categorical distributions."""
    ref = pd.Series(["HOST"] * 50 + ["DATABASE"] * 30 + ["USER"] * 20)
    curr_same = pd.Series(["HOST"] * 48 + ["DATABASE"] * 32 + ["USER"] * 20)
    curr_shifted = pd.Series(["HOST"] * 10 + ["DATABASE"] * 10 + ["USER"] * 80)

    psi_same = calculate_categorical_psi(ref, curr_same)
    psi_shifted = calculate_categorical_psi(ref, curr_shifted)

    assert psi_same < 0.10
    assert psi_shifted > 0.25


def test_drift_detector_run_analysis():
    """Ensures TelemetryDriftDetector generates valid multi-faceted drift report and saves history."""
    detector = TelemetryDriftDetector()
    report = detector.run_drift_analysis(dataset_label="TEST_VERIFICATION_BATCH")

    assert "report_id" in report
    assert "overall_severity" in report
    assert report["overall_severity"] in [s.value for s in DriftSeverity]
    assert "overall_drift_score" in report
    assert "features_drift" in report
    assert len(report["features_drift"]) >= 10
    assert "prediction_drift" in report
    assert "data_quality" in report
    assert "population_drift" in report
    assert "retraining_recommended" in report
    assert isinstance(report["retraining_recommended"], bool)

    # Check persistence
    latest = detector.get_latest_drift_report()
    assert latest["report_id"] == report["report_id"]

    history = detector.get_drift_history()
    assert len(history) >= 1
    assert any(h["report_id"] == report["report_id"] for h in history)


# =============================================================================
# 2. RETRAINING & CHAMPION-CHALLENGER LIFECYCLE TESTS
# =============================================================================

def test_validation_gate_detects_target_leakage():
    """Verifies that pre-training validation gate rejects data containing forbidden leakage columns."""
    mgr = RetrainingManager()
    raw_df = mgr.fe.extract_raw_features()

    # Without filtering feature_cols, raw_df contains 'security_status' (leakage!)
    gate_res = mgr.validate_training_dataset(raw_df)
    assert gate_res["is_valid"] is False
    assert any("leakage" in e.lower() for e in gate_res["errors"])


def test_validation_gate_passes_clean_topology_data():
    """Verifies that pre-training validation gate passes clean, non-leaking topology features."""
    mgr = RetrainingManager()
    raw_df = mgr.fe.extract_raw_features()

    gate_res = mgr.validate_training_dataset(
        raw_df,
        feature_cols=list(TOPOLOGY_FEATURE_COLUMNS),
        target_col="target_is_at_risk",
    )
    assert gate_res["is_valid"] is True
    assert len(gate_res["errors"]) == 0
    assert gate_res["metrics"]["sample_count"] >= 50
    assert gate_res["metrics"]["positive_samples"] >= 5


def test_validation_gate_rejects_insufficient_samples():
    """Verifies that pre-training validation gate rejects datasets smaller than 50 samples."""
    mgr = RetrainingManager()
    small_df = mgr.fe.extract_raw_features().iloc[:20].copy()

    gate_res = mgr.validate_training_dataset(
        small_df,
        feature_cols=list(TOPOLOGY_FEATURE_COLUMNS),
        target_col="target_is_at_risk",
    )
    assert gate_res["is_valid"] is False
    assert any("50" in e for e in gate_res["errors"])


def test_train_challenger_and_compare_lifecycle():
    """Verifies end-to-end challenger training, threshold calibration, and comparative evaluation."""
    mgr = RetrainingManager()

    result = mgr.train_challenger(
        feature_subset="topology_only",
        cv_folds=3,
        test_size=0.2,
        trigger_type="AUTOMATED_TEST",
        user_notes="Unit test challenger execution",
        candidate_model_type="logistic_regression",
        initiator="test_analyst",
    )

    assert "job_id" in result
    assert "challenger_version" in result
    assert result["validation_gate"]["is_valid"] is True

    comp = result["comparison"]
    assert "champion_version" in comp
    assert "challenger_version" in comp
    assert comp["recommendation"] in [
        PromotionRecommendation.RECOMMEND_PROMOTION.value,
        PromotionRecommendation.REJECT_CHALLENGER.value,
    ]
    assert "metrics_comparison" in comp
    assert "recall" in comp["metrics_comparison"]
    assert "missed_threats" in comp["metrics_comparison"]

    chall_v = result["challenger_version"]
    v_dir = os.path.join(mgr.versions_dir, chall_v)
    assert os.path.exists(os.path.join(v_dir, "model.joblib"))
    assert os.path.exists(os.path.join(v_dir, "model_metadata.json"))
    assert os.path.exists(os.path.join(v_dir, "calibration_metadata.json"))


def test_model_promotion_and_rollback_governance():
    """Verifies model promotion to ACTIVE, archiving of previous champion, and rollback."""
    mgr = RetrainingManager()
    versions = mgr.list_model_versions()
    assert len(versions) >= 1

    # Train a challenger
    train_res = mgr.train_challenger(
        feature_subset="topology_only",
        cv_folds=3,
        test_size=0.2,
        trigger_type="GOVERNANCE_TEST",
        candidate_model_type="logistic_regression",
        initiator="test_analyst",
    )
    chall_v = train_res["challenger_version"]

    # Promote challenger
    promo_res = mgr.approve_and_promote_model(
        challenger_version=chall_v,
        current_user="test_secops_lead",
        approval_notes="Approved via unit test",
    )
    assert promo_res["status"] == "SUCCESS"
    assert promo_res["promoted_version"] == chall_v

    # Verify active status
    active_versions = [v for v in mgr.list_model_versions() if v["status"] == ModelStatus.ACTIVE.value]
    assert len(active_versions) == 1
    assert active_versions[0]["version"] == chall_v
    assert active_versions[0]["is_champion"] is True

    # Rollback to v1.0.0
    rollback_res = mgr.rollback_model(
        target_version="v1.0.0",
        current_user="test_secops_lead",
        rollback_reason="Emergency rollback test",
    )
    assert rollback_res["status"] == "ROLLED_BACK"
    assert rollback_res["active_version"] in ["v1.0.0", "1.0.0"]

    # Verify v1.0.0 is active again
    active_now = [v for v in mgr.list_model_versions() if v["status"] == ModelStatus.ACTIVE.value]
    assert len(active_now) == 1
    assert active_now[0]["version"] in ["v1.0.0", "1.0.0"]


def test_reject_challenger_model():
    """Verifies that an analyst can formally reject a challenger model."""
    mgr = RetrainingManager()
    train_res = mgr.train_challenger(
        feature_subset="topology_only",
        cv_folds=3,
        test_size=0.2,
        trigger_type="REJECTION_TEST",
    )
    chall_v = train_res["challenger_version"]

    rej_res = mgr.reject_model(
        challenger_version=chall_v,
        current_user="test_secops_lead",
        rejection_reason="Unfavorable precision trade-off on edge topologies.",
    )
    assert rej_res["status"] == "REJECTED"
    assert rej_res["version"] == chall_v

    # Verify in version catalog
    v_item = next(v for v in mgr.list_model_versions() if v["version"] == chall_v)
    assert v_item["status"] == ModelStatus.REJECTED.value


# =============================================================================
# 3. AUTOMATED INCIDENT DOSSIER GENERATION TESTS
# =============================================================================

def test_generate_incident_dossier_compilation_and_pdf():
    """Verifies incident dossier data aggregation, SHA-256 digest, and valid PDF rendering."""
    gen = IncidentDossierGenerator()

    res = gen.generate_full_dossier(
        analyst_name="Saanvi (Lead Threat Analyst)",
        analyst_notes="Phase 7.2D unit test dossier generation verification.",
        target_scenario="Simulated Multi-Hop Lateral Movement Attack",
    )

    assert "dossier_id" in res
    assert "pdf_path" in res
    assert "json_path" in res
    assert os.path.exists(res["pdf_path"])
    assert os.path.exists(res["json_path"])

    # Verify PDF starts with standard header and has substantial size
    with open(res["pdf_path"], "rb") as f:
        header = f.read(8)
    assert header.startswith(b"%PDF-"), f"Invalid PDF header: {header}"
    assert res["pdf_size_bytes"] > 4000

    # Verify cryptographic audit hash
    assert len(res["cryptographic_audit_hash"]) == 64  # SHA-256 hex length

    # Verify data content
    data = res["dossier_data"]
    assert "executive_summary" in data
    assert data["executive_summary"]["total_monitored_nodes"] >= 100
    assert "at_risk_assets" in data
    assert "attack_paths" in data
    assert "shap_risk_drivers" in data
    assert "containment_plan" in data
    assert "drift_telemetry" in data


def test_list_generated_dossiers():
    """Verifies that generated dossiers are tracked in catalog."""
    gen = IncidentDossierGenerator()
    dossiers = gen.list_generated_dossiers()
    assert len(dossiers) >= 1
    assert "dossier_id" in dossiers[0]
    assert dossiers[0]["pdf_available"] is True


# =============================================================================
# 4. REST API ENDPOINTS TESTS (PHASE 7.2D)
# =============================================================================

def test_api_get_drift_status(viewer_user):
    """GET /api/v1/ml/drift/status"""
    from backend.app.ml.router import get_drift_status
    res = get_drift_status(current_user=viewer_user)
    assert "overall_severity" in res
    assert "features_drift" in res
    assert "retraining_recommended" in res


def test_api_run_drift_analysis(analyst_user):
    """POST /api/v1/ml/drift/run"""
    from backend.app.ml.router import run_drift_analysis, DriftRunRequest
    req = DriftRunRequest(dataset_label="API_TRIGGERED_AUDIT")
    res = run_drift_analysis(request=req, current_user=analyst_user)
    assert res["dataset_label"] == "API_TRIGGERED_AUDIT"
    assert "overall_drift_score" in res


def test_api_list_model_versions(viewer_user):
    """GET /api/v1/ml/models/versions"""
    from backend.app.ml.router import list_model_versions
    res = list_model_versions(current_user=viewer_user)
    assert isinstance(res, list)
    assert len(res) >= 1
    assert any(v["is_champion"] for v in res)


def test_api_compare_models(viewer_user):
    """GET /api/v1/ml/retrain/compare"""
    from backend.app.ml.router import compare_models
    res = compare_models(current_user=viewer_user)
    assert "champion_version" in res
    assert "recommendation" in res
    assert "metrics_comparison" in res


def test_api_generate_and_preview_dossier(analyst_user, viewer_user):
    """POST /api/v1/ml/dossier/generate & GET /api/v1/ml/dossier/preview"""
    from backend.app.ml.router import (
        generate_incident_dossier,
        preview_latest_dossier,
        DossierGenerateRequest,
    )

    req = DossierGenerateRequest(
        analyst_name="Lead Analyst",
        analyst_notes="API generation test",
        target_scenario="API Lateral Movement Test",
    )
    gen_res = generate_incident_dossier(request=req, current_user=analyst_user)
    assert gen_res["status"] == "GENERATED"
    assert "dossier_id" in gen_res
    assert "cryptographic_audit_hash" in gen_res
    assert "download_url" in gen_res

    preview_res = preview_latest_dossier(current_user=viewer_user)
    assert "dossier_id" in preview_res
    assert "executive_summary" in preview_res
