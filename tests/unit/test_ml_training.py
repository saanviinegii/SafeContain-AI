"""Unit & Integration Test Suite for SafeContain AI ML Model Training & Optimization (Phase 7.2A).

Validates:
1. Hyperparameter search grid definitions and execution.
2. Holdout test set separation and strict data leakage isolation.
3. Multi-candidate cross-validation and winning model selection.
4. Model artifact persistence (joblib, metadata, comparison CSV, plots).
5. Model registry loading, caching, and inference.
6. Feature schema validation and missing feature handling.
7. Probability calibration and risk tier assignment.
8. Training reproducibility under fixed random seed.
9. REST API endpoints for active model metadata, comparison, and node risk prediction.
"""

import os
import json
import pytest
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline

from backend.app.ml.feature_engineering import FeatureEngineer
from backend.app.ml.hyperparameter_search import HyperparameterOptimizer
from backend.app.ml.model_trainer import ModelTrainer
from backend.app.ml.model_registry import ModelRegistry
from backend.app.security.user_store import UserRecord
from datetime import datetime, timezone


@pytest.fixture
def feature_engineer():
    return FeatureEngineer()


@pytest.fixture
def optimizer():
    return HyperparameterOptimizer(random_state=42)


@pytest.fixture
def temp_trainer(tmp_path, feature_engineer):
    artifacts_dir = str(tmp_path / "test_artifacts")
    return ModelTrainer(
        artifacts_dir=artifacts_dir,
        feature_engineer=feature_engineer,
        random_state=42,
    )


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
# 1. HYPERPARAMETER SEARCH TESTS
# =====================================================================

def test_hyperparameter_optimizer_grids(optimizer, feature_engineer):
    """Verifies that all 3 candidate models have valid search grids."""
    _, _, num_cols, cat_cols = feature_engineer.get_features_and_target("topology_only")
    grids = optimizer.get_candidate_grids(num_cols, cat_cols)

    assert "logistic_regression" in grids
    assert "random_forest" in grids
    assert "gradient_boosting" in grids

    for model_name, (pipe, grid) in grids.items():
        assert isinstance(pipe, Pipeline)
        assert isinstance(grid, dict)
        assert len(grid) > 0


def test_hyperparameter_search_execution(optimizer, feature_engineer):
    """Verifies grid search runs on training split and returns optimized estimator."""
    X, y, num_cols, cat_cols = feature_engineer.get_features_and_target("topology_only")
    grids = optimizer.get_candidate_grids(num_cols, cat_cols)
    pipe, grid = grids["logistic_regression"]

    # Target smaller grid for fast test execution
    test_grid = {"clf__C": [0.1, 1.0], "clf__solver": ["liblinear"]}
    res = optimizer.optimize_candidate(
        model_name="logistic_regression",
        pipeline=pipe,
        param_grid=test_grid,
        X_train=X.iloc[:60],
        y_train=y.iloc[:60],
        cv_folds=3,
        scoring="balanced_accuracy",
    )

    assert res["model_name"] == "logistic_regression"
    assert "best_estimator" in res
    assert "best_params" in res
    assert res["best_cv_score"] > 0.0


# =====================================================================
# 2. MODEL TRAINER & HOLDOUT EVALUATION TESTS
# =====================================================================

def test_model_trainer_pipeline_execution(temp_trainer):
    """Executes full training pipeline on temporary directory and verifies artifacts."""
    results = temp_trainer.run_pipeline(
        feature_subset="topology_only",
        test_size=0.20,
        cv_folds=3,
    )

    assert results["status"] == "SUCCESS"
    assert results["total_samples"] == 120
    assert results["train_samples"] == 96
    assert results["holdout_test_samples"] == 24
    assert results["best_model"] in ["logistic_regression", "random_forest", "gradient_boosting"]

    # Verify holdout test metrics
    ht = results["holdout_evaluation"]
    assert 0.0 <= ht["accuracy"] <= 1.0
    assert 0.0 <= ht["balanced_accuracy"] <= 1.0
    assert 0.0 <= ht["false_positive_rate"] <= 1.0
    assert 0.0 <= ht["false_negative_rate"] <= 1.0

    # Verify artifacts exist on disk
    for path in results["artifacts_saved"].values():
        assert os.path.exists(path), f"Artifact missing: {path}"

    # Verify plots exist on disk
    for path in results["plot_paths"].values():
        assert os.path.exists(path), f"Plot missing: {path}"
        assert os.path.getsize(path) > 1000


def test_model_trainer_reproducibility(tmp_path, feature_engineer):
    """Ensures identical random seed produces identical holdout evaluation scores."""
    trainer1 = ModelTrainer(artifacts_dir=str(tmp_path / "art1"), feature_engineer=feature_engineer, random_state=999)
    trainer2 = ModelTrainer(artifacts_dir=str(tmp_path / "art2"), feature_engineer=feature_engineer, random_state=999)

    res1 = trainer1.run_pipeline(feature_subset="topology_only", test_size=0.25, cv_folds=3)
    res2 = trainer2.run_pipeline(feature_subset="topology_only", test_size=0.25, cv_folds=3)

    assert res1["best_model"] == res2["best_model"]
    assert res1["holdout_evaluation"]["accuracy"] == res2["holdout_evaluation"]["accuracy"]
    assert res1["holdout_evaluation"]["balanced_accuracy"] == res2["holdout_evaluation"]["balanced_accuracy"]


# =====================================================================
# 3. MODEL REGISTRY & INFERENCE TESTS
# =====================================================================

def test_model_registry_active_model_loading(active_registry):
    """Verifies that the model registry loads the active serialized model."""
    assert active_registry.is_model_available()
    pipe, meta = active_registry.load_model()
    assert isinstance(pipe, Pipeline)
    assert meta["model_name"] in ["logistic_regression", "random_forest", "gradient_boosting"]
    assert len(meta["features"]) > 0


def test_model_registry_feature_validation_raises(active_registry):
    """Ensures feature validation raises ValueError if required features are missing."""
    invalid_df = pd.DataFrame({"dummy_column": [1, 2, 3]})
    with pytest.raises(ValueError) as excinfo:
        active_registry.predict(invalid_df)
    assert "Feature schema mismatch" in str(excinfo.value)


def test_model_registry_predict_and_proba(active_registry, feature_engineer):
    """Verifies predict and predict_proba return valid arrays with calibrated probabilities."""
    X, _, _, _ = feature_engineer.get_features_and_target("topology_only")
    preds = active_registry.predict(X)
    probs = active_registry.predict_proba(X)

    assert len(preds) == len(X)
    assert set(np.unique(preds)).issubset({0, 1})

    assert probs.shape == (len(X), 2)
    assert np.all(probs >= 0.0) and np.all(probs <= 1.0)
    # Probabilities should sum to approximately 1.0
    assert np.allclose(np.sum(probs, axis=1), 1.0, atol=1e-5)


def test_model_registry_predict_for_nodes(active_registry):
    """Verifies risk tier assignment and structured output for nodes."""
    node_results = active_registry.predict_for_nodes(["node-user-marcus", "node-user-sarah"])
    assert len(node_results) == 2
    for r in node_results:
        assert "node_id" in r
        assert "risk_probability" in r
        assert "risk_tier" in r
        assert r["risk_tier"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


# =====================================================================
# 4. REST API ENDPOINT TESTS (PHASE 7.2A)
# =====================================================================

def test_api_get_active_model(viewer_user):
    """Ensures GET /api/v1/ml/models/active returns active model metadata."""
    from backend.app.ml.router import get_active_model
    res = get_active_model(current_user=viewer_user)
    assert res["status"] == "ACTIVE"
    assert "metadata" in res
    assert "model_name" in res["metadata"]


def test_api_get_model_comparison(viewer_user):
    """Ensures GET /api/v1/ml/models/comparison returns comparative metrics."""
    from backend.app.ml.router import get_model_comparison
    res = get_model_comparison(current_user=viewer_user)
    assert res["models_count"] >= 3
    assert len(res["comparison"]) >= 3
    model_names = [m["model_name"] for m in res["comparison"]]
    assert "logistic_regression" in model_names
    assert "random_forest" in model_names


def test_api_predict_nodes(viewer_user):
    """Ensures POST /api/v1/ml/models/predict returns risk predictions."""
    from backend.app.ml.router import predict_node_risk, NodePredictionRequest
    req = NodePredictionRequest(node_ids=["node-user-marcus"])
    res = predict_node_risk(req, current_user=viewer_user)
    assert res["model_status"] == "ACTIVE"
    assert res["total_evaluated"] == 1
    pred = res["predictions"][0]
    assert pred["node_id"] == "node-user-marcus"
    assert "risk_probability" in pred
    assert "risk_tier" in pred
