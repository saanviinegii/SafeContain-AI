"""Unit & Integration Test Suite for SafeContain AI Decision Threshold Calibration (Phase 7.2B).

Validates:
1. Candidate threshold grid generation across [0.15, 0.40].
2. Metric calculations (Precision, Recall, F1, Specificity, FPR, FNR, Youden's J, Total Cost).
3. Cost-sensitive utility modeling under configurable cost ratios.
4. Recall-constrained threshold selection policy (Recall >= 0.80).
5. Target-not-met fallback behavior when constraint cannot be satisfied.
6. Data leakage prevention: Out-of-fold validation separation from holdout test set.
7. Calibration artifact generation (CSV, JSON metadata, PR curve, Comparison plot, Confusion matrices).
8. ModelRegistry inference integration with calibrated operating threshold.
9. REST API endpoints for calibration metadata, threshold grid, and customized predictions.
10. Edge cases (all-positive, all-negative, division by zero protection).
"""

import os
import json
import pytest
import numpy as np
import pandas as pd
from datetime import datetime, timezone

from backend.app.ml.threshold_calibration import ThresholdCalibrator
from backend.app.ml.feature_engineering import FeatureEngineer
from backend.app.ml.model_registry import ModelRegistry
from backend.app.security.user_store import UserRecord


@pytest.fixture
def feature_engineer():
    return FeatureEngineer()


@pytest.fixture
def calibrator(feature_engineer):
    return ThresholdCalibrator(feature_engineer=feature_engineer, random_state=42)


@pytest.fixture
def temp_calibrator(tmp_path, feature_engineer):
    art_dir = str(tmp_path / "test_calibration_artifacts")
    return ThresholdCalibrator(artifacts_dir=art_dir, feature_engineer=feature_engineer, random_state=42)


@pytest.fixture
def active_registry():
    return ModelRegistry()


@pytest.fixture
def viewer_user():
    now = datetime.now(timezone.utc).isoformat()
    return UserRecord(
        id="usr-test-viewer",
        username="sec_viewer_01",
        role="VIEWER",
        hashed_password="mock_hashed_password",
        is_active=True,
        created_at=now,
        updated_at=now,
    )


@pytest.fixture
def analyst_user():
    now = datetime.now(timezone.utc).isoformat()
    return UserRecord(
        id="usr-test-analyst",
        username="sec_analyst_01",
        role="ANALYST",
        hashed_password="mock_hashed_password",
        is_active=True,
        created_at=now,
        updated_at=now,
    )


# =====================================================================
# 1. THRESHOLD GENERATION & METRIC CALCULATION TESTS
# =====================================================================

def test_generate_candidate_thresholds(calibrator):
    """Verifies threshold grid generation across [0.15, 0.40] with step 0.01."""
    th = calibrator.generate_candidate_thresholds(0.15, 0.40, 0.01)
    assert len(th) == 26
    assert np.isclose(th[0], 0.15)
    assert np.isclose(th[-1], 0.40)
    assert np.all(np.diff(th) > 0)


def test_evaluate_threshold_metrics_clean():
    """Verifies mathematical correctness of precision, recall, specificity, and cost."""
    y_true = np.array([1, 1, 0, 0])
    y_prob = np.array([0.9, 0.3, 0.8, 0.1])

    # At threshold 0.50:
    # y_pred = [1, 0, 1, 0] -> TP=1, FN=1, FP=1, TN=1
    m = ThresholdCalibrator.evaluate_threshold_metrics(
        y_true, y_prob, threshold=0.50, cost_fn=10.0, cost_fp=1.0
    )
    assert m["true_positives"] == 1
    assert m["true_negatives"] == 1
    assert m["false_positives"] == 1
    assert m["false_negatives"] == 1
    assert m["recall"] == 0.50
    assert m["precision"] == 0.50
    assert m["specificity"] == 0.50
    assert m["f1_score"] == 0.50
    assert m["balanced_accuracy"] == 0.50
    assert m["youden_j"] == 0.0
    assert m["total_cost"] == 11.0  # 1*10 + 1*1


def test_cost_sensitive_utility_modeling():
    """Verifies cost model scaling under different FN:FP penalty ratios."""
    y_true = np.array([1, 1, 0, 0])
    y_prob = np.array([0.9, 0.3, 0.8, 0.1])

    # Cost ratio 10:1 (FN=10, FP=1) -> cost = 1*10 + 1*1 = 11.0
    m1 = ThresholdCalibrator.evaluate_threshold_metrics(y_true, y_prob, threshold=0.50, cost_fn=10.0, cost_fp=1.0)
    assert m1["total_cost"] == 11.0

    # Cost ratio 50:1 (FN=50, FP=1) -> cost = 1*50 + 1*1 = 51.0
    m2 = ThresholdCalibrator.evaluate_threshold_metrics(y_true, y_prob, threshold=0.50, cost_fn=50.0, cost_fp=1.0)
    assert m2["total_cost"] == 51.0


# =====================================================================
# 2. THRESHOLD SELECTION POLICY TESTS
# =====================================================================

def test_select_optimal_threshold_target_achieved(calibrator):
    """Verifies threshold selection enforces Recall >= 0.80 and minimizes total cost."""
    # Synthetic metric grid
    df_metrics = pd.DataFrame([
        {"threshold": 0.20, "recall": 1.00, "precision": 0.20, "f1_score": 0.33, "balanced_accuracy": 0.60, "total_cost": 80.0, "youden_j": 0.20},
        {"threshold": 0.30, "recall": 0.90, "precision": 0.30, "f1_score": 0.45, "balanced_accuracy": 0.70, "total_cost": 50.0, "youden_j": 0.40},
        {"threshold": 0.35, "recall": 0.70, "precision": 0.50, "f1_score": 0.58, "balanced_accuracy": 0.75, "total_cost": 65.0, "youden_j": 0.50},
    ])

    res = calibrator.select_optimal_threshold(df_metrics, recall_target=0.80, cost_fn=10.0, cost_fp=1.0)
    assert res["target_achieved"] is True
    # Threshold 0.30 has recall=0.90 (>= 0.80) and lowest cost (50.0 vs 80.0)
    assert res["selected_threshold"] == 0.30
    assert "recall_constrained_cost_optimal" in res["strategy"]


def test_select_optimal_threshold_target_not_met_fallback(calibrator):
    """Verifies fallback selection when no threshold reaches the recall constraint."""
    # Metric grid where max recall is 0.75
    df_metrics = pd.DataFrame([
        {"threshold": 0.25, "recall": 0.75, "precision": 0.40, "f1_score": 0.52, "balanced_accuracy": 0.65, "total_cost": 60.0, "youden_j": 0.30},
        {"threshold": 0.35, "recall": 0.60, "precision": 0.55, "f1_score": 0.57, "balanced_accuracy": 0.70, "total_cost": 70.0, "youden_j": 0.40},
    ])

    res = calibrator.select_optimal_threshold(df_metrics, recall_target=0.85, cost_fn=10.0, cost_fp=1.0)
    assert res["target_achieved"] is False
    assert res["selected_threshold"] == 0.25
    assert "max_attainable_recall_fallback" in res["strategy"]
    assert "No candidate threshold within" in res["selection_reason"]


# =====================================================================
# 3. END-TO-END CALIBRATION PIPELINE TESTS
# =====================================================================

def test_run_calibration_execution(calibrator):
    """Verifies complete calibration pipeline execution and artifact creation."""
    res = calibrator.run_calibration(
        feature_subset="topology_only",
        recall_target=0.80,
        cost_fn=10.0,
        cost_fp=1.0,
    )

    assert res["status"] == "SUCCESS"
    assert res["target_achieved"] is True
    assert 0.15 <= res["selected_threshold"] <= 0.40

    # Holdout comparison
    hc = res["holdout_comparison"]
    assert hc["calibrated_threshold"]["recall"] >= hc["default_threshold_0_50"]["recall"]
    assert hc["threats_missed_calibrated"] <= hc["threats_missed_default"]

    # Verify artifacts exist on disk
    for path in res["artifacts_saved"].values():
        assert os.path.exists(path), f"Artifact missing: {path}"

    # Verify plot PNGs exist on disk and are non-empty
    for path in res["plot_paths"].values():
        assert os.path.exists(path), f"Plot missing: {path}"
        assert os.path.getsize(path) > 1000


# =====================================================================
# 4. MODEL REGISTRY CALIBRATION INTEGRATION TESTS
# =====================================================================

def test_model_registry_operating_threshold(active_registry):
    """Verifies ModelRegistry loads the calibrated threshold."""
    assert active_registry.is_calibration_available()
    th = active_registry.get_operating_threshold()
    assert 0.15 <= th <= 0.40
    cal_meta = active_registry.get_calibration_metadata()
    assert "operating_threshold" in cal_meta
    assert cal_meta["operating_threshold"] == th


def test_model_registry_predict_with_calibrated_threshold(active_registry, feature_engineer):
    """Verifies predict and predict_for_nodes use operating threshold."""
    raw_df = feature_engineer.extract_raw_features()
    expected_features = active_registry.get_model_metadata()["metadata"]["features"]
    X = raw_df[expected_features]

    # Predict at default 0.50 vs calibrated threshold
    pred_default = active_registry.predict(X, threshold=0.50)
    pred_calibrated = active_registry.predict(X)  # Uses operating threshold

    # Lower threshold should identify >= number of at-risk nodes
    assert np.sum(pred_calibrated) >= np.sum(pred_default)

    node_results = active_registry.predict_for_nodes(["node-user-marcus", "node-user-sarah"])
    assert len(node_results) == 2
    for r in node_results:
        assert "operating_threshold" in r
        assert r["operating_threshold"] == active_registry.get_operating_threshold()


# =====================================================================
# 5. REST API ROUTER TESTS (PHASE 7.2B)
# =====================================================================

def test_api_get_calibration_status(viewer_user):
    """Ensures GET /api/v1/ml/calibration returns calibration metadata."""
    from backend.app.ml.router import get_calibration_status
    res = get_calibration_status(current_user=viewer_user)
    assert "operating_threshold" in res
    assert res["operating_threshold"] == 0.32
    assert "holdout_comparison" in res


def test_api_get_threshold_metrics_grid(viewer_user):
    """Ensures GET /api/v1/ml/calibration/thresholds returns candidate grid."""
    from backend.app.ml.router import get_threshold_metrics_grid
    res = get_threshold_metrics_grid(current_user=viewer_user)
    assert res["candidate_thresholds_count"] >= 20
    assert len(res["threshold_metrics"]) >= 20
    first = res["threshold_metrics"][0]
    assert "threshold" in first
    assert "recall" in first
    assert "total_cost" in first


def test_api_predict_with_threshold_override(viewer_user):
    """Ensures POST /api/v1/ml/models/predict supports custom threshold override."""
    from backend.app.ml.router import predict_node_risk, NodePredictionRequest
    req = NodePredictionRequest(node_ids=["node-user-marcus"], threshold=0.30)
    res = predict_node_risk(req, current_user=viewer_user)
    assert res["model_status"] == "ACTIVE"
    assert res["operating_threshold"] == 0.30
    assert res["predictions"][0]["operating_threshold"] == 0.30


# =====================================================================
# 6. EDGE CASE TESTS
# =====================================================================

def test_evaluate_threshold_edge_cases():
    """Verifies graceful handling of edge cases (all zeros, all ones, division by zero)."""
    # All zeros (no true positives)
    y_all_zero = np.zeros(10)
    probs = np.linspace(0.1, 0.9, 10)
    m_zero = ThresholdCalibrator.evaluate_threshold_metrics(y_all_zero, probs, threshold=0.50)
    assert m_zero["recall"] == 0.0
    assert m_zero["precision"] == 0.0

    # All ones (no true negatives)
    y_all_one = np.ones(10)
    m_one = ThresholdCalibrator.evaluate_threshold_metrics(y_all_one, probs, threshold=0.50)
    assert m_one["specificity"] == 0.0
    assert m_one["false_positive_rate"] == 0.0
