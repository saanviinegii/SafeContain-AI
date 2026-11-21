"""Comprehensive Unit Test Suite for SafeContain AI Machine Learning Pipeline (Phase 7.1).

Validates:
1. Dataset loading and inventory generation.
2. Data quality checks, referential integrity, and missing values.
3. Task definitions, leakage guards, and forbidden column prevention.
4. Graph feature engineering, PageRank, degree centrality, and preprocessors.
5. Baseline pipelines (Logistic Regression, Random Forest, Dummy, Isolation Forest).
6. Stratified K-Fold cross validation and metric aggregation.
7. Unsupervised Isolation Forest anomaly detection and ranking.
8. Reproducibility under fixed random seed.
9. Model pipeline serialization and deserialization.
"""

import os
import tempfile
import pytest
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline

from backend.app.ml.dataset_loader import (
    DatasetLoader,
    DEFAULT_ML_DATASET_DIR,
    EXPECTED_DATASET_FILES,
)
from backend.app.ml.data_validation import DataValidator
from backend.app.ml.task_definition import (
    TASK_NODE_RISK_CLASSIFICATION,
    TASK_NODE_ANOMALY_DETECTION,
    TOPOLOGY_FEATURE_COLUMNS,
    TELEMETRY_FEATURE_COLUMNS,
    FORBIDDEN_LEAKAGE_COLUMNS,
    assert_no_target_leakage,
)
from backend.app.ml.feature_engineering import FeatureEngineer
from backend.app.ml.evaluation import (
    compute_classification_metrics,
    aggregate_cv_metrics,
    compute_anomaly_metrics,
)
from backend.app.ml.baseline import (
    build_baseline_pipeline,
    BaselineManager,
)


@pytest.fixture
def loader():
    return DatasetLoader(DEFAULT_ML_DATASET_DIR)


@pytest.fixture
def validator(loader):
    return DataValidator(loader)


@pytest.fixture
def feature_engineer(loader):
    return FeatureEngineer(loader)


@pytest.fixture
def baseline_manager(feature_engineer):
    return BaselineManager(feature_engineer)


# =====================================================================
# 1. DATASET LOADER TESTS
# =====================================================================

def test_dataset_loader_discovers_all_expected_files(loader):
    """Ensures all 12 expected enterprise CSV files are discovered."""
    available = loader.get_available_files()
    for expected in EXPECTED_DATASET_FILES:
        assert expected in available, f"Missing expected dataset file: {expected}"


def test_dataset_loader_reads_tables(loader):
    """Verifies that nodes and relationships are properly loaded with non-zero rows."""
    nodes_df = loader.load_table("nodes.csv")
    rels_df = loader.load_table("relationships.csv")
    assert isinstance(nodes_df, pd.DataFrame)
    assert len(nodes_df) == 120
    assert isinstance(rels_df, pd.DataFrame)
    assert len(rels_df) == 285


def test_dataset_loader_missing_file_raises_error():
    """Ensures loading a non-existent file raises FileNotFoundError."""
    loader = DatasetLoader("/tmp/non_existent_ml_dir_xyz")
    with pytest.raises(FileNotFoundError):
        loader.load_table("nodes.csv")


def test_dataset_loader_inventory_summary(loader):
    """Verifies complete inventory summary generation with columns and nulls."""
    inventory = loader.get_inventory_summary()
    assert inventory["total_files"] >= 12
    assert inventory["total_records"] > 500
    assert len(inventory["missing_expected_files"]) == 0
    assert "nodes.csv" in inventory["tables"]
    assert inventory["tables"]["nodes.csv"]["records"] == 120
    assert inventory["tables"]["nodes.csv"]["total_nulls"] == 0


# =====================================================================
# 2. DATA VALIDATION TESTS
# =====================================================================

def test_data_validator_passes_on_enterprise_data(validator):
    """Verifies that data validator reports PASSED on valid enterprise data."""
    report = validator.validate_dataset_quality()
    assert report["validation_status"] == "PASSED"
    assert len(report["issues"]) == 0
    assert report["total_nodes"] == 120
    assert report["total_relationships"] == 285
    assert report["total_assets"] == 35


def test_data_validator_target_distribution(validator):
    """Verifies ground truth class distribution reflects real dataset."""
    report = validator.validate_dataset_quality()
    dist = report["target_distribution"]
    assert dist["binary_healthy_count"] == 97
    assert dist["binary_at_risk_count"] == 23
    assert 0.18 < dist["at_risk_prevalence"] < 0.20


def test_data_validator_detects_duplicate_pks(tmp_path):
    """Ensures validator detects duplicate primary keys."""
    # Create mock dataset with duplicate node_id
    mock_dir = tmp_path / "mock_data"
    mock_dir.mkdir()
    nodes = pd.DataFrame({
        "node_id": ["node-1", "node-1"],
        "node_type": ["SERVER", "SERVER"],
        "environment": ["PROD", "PROD"],
        "exposure": ["INTERNAL", "INTERNAL"],
        "criticality": [0.8, 0.8],
        "security_status": ["HEALTHY", "HEALTHY"],
    })
    nodes.to_csv(mock_dir / "nodes.csv", index=False)
    pd.DataFrame({
        "relationship_id": ["rel-1"], "source_id": ["node-1"], "target_id": ["node-1"],
        "relationship_type": ["CONNECTS_TO"], "privilege_level": ["USER"]
    }).to_csv(mock_dir / "relationships.csv", index=False)
    pd.DataFrame({"asset_id": ["asset-1"], "node_id": ["node-1"]}).to_csv(mock_dir / "assets.csv", index=False)
    pd.DataFrame({"vulnerability_id": ["vuln-1"], "asset_id": ["asset-1"]}).to_csv(mock_dir / "vulnerabilities.csv", index=False)
    pd.DataFrame({"alert_id": ["al-1"], "source_node_id": ["node-1"], "target_node_id": ["node-1"]}).to_csv(mock_dir / "security_alerts.csv", index=False)
    pd.DataFrame({"evidence_id": ["ev-1"], "related_node_id": ["node-1"]}).to_csv(mock_dir / "evidence.csv", index=False)

    val = DataValidator(DatasetLoader(str(mock_dir)))
    report = val.validate_dataset_quality()
    assert report["validation_status"] == "FAILED"
    assert any("duplicate primary key" in issue for issue in report["issues"])


# =====================================================================
# 3. TASK DEFINITIONS & LEAKAGE GUARDS
# =====================================================================

def test_task_definitions_metadata():
    """Ensures task definitions contain required operational metadata."""
    assert TASK_NODE_RISK_CLASSIFICATION.target_column == "target_is_at_risk"
    assert "balanced_accuracy" in TASK_NODE_RISK_CLASSIFICATION.primary_metrics
    assert len(TASK_NODE_RISK_CLASSIFICATION.leakage_risks) > 0

    assert TASK_NODE_ANOMALY_DETECTION.target_column == ""
    assert "anomaly_score_distribution" in TASK_NODE_ANOMALY_DETECTION.primary_metrics


def test_leakage_guard_raises_on_forbidden_columns():
    """Ensures assert_no_target_leakage raises ValueError if forbidden column is present."""
    # Clean features should pass
    clean_features = ["in_degree", "out_degree", "criticality", "exposure"]
    assert_no_target_leakage(clean_features)

    # Leaking features must raise ValueError
    leaky_features = ["in_degree", "security_status", "criticality"]
    with pytest.raises(ValueError) as excinfo:
        assert_no_target_leakage(leaky_features)
    assert "CRITICAL TARGET LEAKAGE DETECTED" in str(excinfo.value)

    leaky_features_2 = ["target_is_at_risk", "in_degree"]
    with pytest.raises(ValueError):
        assert_no_target_leakage(leaky_features_2)


# =====================================================================
# 4. FEATURE ENGINEERING TESTS
# =====================================================================

def test_feature_engineering_extracts_all_nodes(feature_engineer):
    """Verifies that all 120 enterprise nodes have engineered features."""
    raw_df = feature_engineer.extract_raw_features()
    assert len(raw_df) == 120
    assert "pagerank" in raw_df.columns
    assert "in_degree" in raw_df.columns
    assert "out_degree" in raw_df.columns
    assert "is_high_privilege_connected" in raw_df.columns
    assert "target_is_at_risk" in raw_df.columns


def test_feature_engineering_subsets_and_leakage_free(feature_engineer):
    """Verifies topology_only and full feature subsets are non-empty and leak-free."""
    X_top, y_top, num_top, cat_top = feature_engineer.get_features_and_target("topology_only")
    assert len(X_top) == 120
    assert len(y_top) == 120
    assert "security_status" not in X_top.columns
    assert "target_is_at_risk" not in X_top.columns
    assert len(num_top) > 0
    assert len(cat_top) > 0

    X_full, y_full, num_full, cat_full = feature_engineer.get_features_and_target("full")
    assert len(X_full.columns) > len(X_top.columns)
    assert "security_status" not in X_full.columns
    assert "target_is_at_risk" not in X_full.columns


def test_feature_engineering_preprocessor(feature_engineer):
    """Verifies that ColumnTransformer transforms both numeric and categorical data cleanly."""
    X_top, _, num_cols, cat_cols = feature_engineer.get_features_and_target("topology_only")
    preprocessor = FeatureEngineer.build_preprocessor(num_cols, cat_cols)
    transformed = preprocessor.fit_transform(X_top)
    assert isinstance(transformed, np.ndarray)
    assert transformed.shape[0] == 120
    assert not np.isnan(transformed).any()


# =====================================================================
# 5. BASELINE MODEL & CROSS-VALIDATION TESTS
# =====================================================================

def test_build_baseline_pipeline_types():
    """Verifies pipeline construction across supported model types."""
    num_cols = ["criticality", "in_degree"]
    cat_cols = ["exposure"]

    for m in ["logistic_regression", "random_forest", "dummy_stratified", "dummy_prior", "isolation_forest"]:
        pipe = build_baseline_pipeline(m, num_cols, cat_cols)
        assert isinstance(pipe, Pipeline)

    with pytest.raises(ValueError):
        build_baseline_pipeline("unsupported_model_xyz", num_cols, cat_cols)


def test_baseline_cross_validation_logistic_regression(baseline_manager):
    """Verifies 5-fold cross validation executes and returns valid metrics."""
    res = baseline_manager.run_cross_validation(
        model_type="logistic_regression",
        feature_subset="topology_only",
        cv_folds=5,
        random_state=42,
    )
    assert res["model_type"] == "logistic_regression"
    assert res["cv_folds"] == 5
    metrics = res["metrics"]
    assert "accuracy_mean" in metrics
    assert "balanced_accuracy_mean" in metrics
    assert "roc_auc_mean" in metrics
    assert 0.0 <= metrics["accuracy_mean"] <= 1.0
    assert 0.0 <= metrics["roc_auc_mean"] <= 1.0


def test_baseline_train_test_split_evaluation(baseline_manager):
    """Verifies train/test evaluation strictly separates splits and returns test metrics."""
    res = baseline_manager.train_test_evaluate(
        model_type="random_forest",
        feature_subset="topology_only",
        test_size=0.20,
        random_state=42,
    )
    assert res["train_samples"] == 96
    assert res["test_samples"] == 24
    test_metrics = res["test_metrics"]
    assert "accuracy" in test_metrics
    assert "precision" in test_metrics
    assert "recall" in test_metrics
    assert "f1_score" in test_metrics
    assert test_metrics["confusion_matrix"]["true_positives"] >= 0


def test_unsupervised_isolation_forest(baseline_manager):
    """Verifies unsupervised Isolation Forest detects expected anomaly proportion."""
    res = baseline_manager.run_isolation_forest_anomaly_detection(
        feature_subset="topology_only",
        contamination=0.10,
        random_state=42,
    )
    assert res["model_type"] == "isolation_forest"
    results = res["results"]
    assert results["total_entities_evaluated"] == 120
    assert results["anomalies_detected"] == 12
    assert results["empirical_contamination_rate"] == 0.10
    assert len(results["top_anomalous_entities"]) > 0


def test_baseline_reproducibility(baseline_manager):
    """Ensures identical random seed produces bitwise identical cross-validation scores."""
    res1 = baseline_manager.run_cross_validation(
        model_type="logistic_regression",
        feature_subset="topology_only",
        cv_folds=3,
        random_state=12345,
    )
    res2 = baseline_manager.run_cross_validation(
        model_type="logistic_regression",
        feature_subset="topology_only",
        cv_folds=3,
        random_state=12345,
    )
    assert res1["metrics"]["accuracy_mean"] == res2["metrics"]["accuracy_mean"]
    assert res1["metrics"]["roc_auc_mean"] == res2["metrics"]["roc_auc_mean"]


def test_pipeline_serialization(baseline_manager, tmp_path):
    """Ensures trained pipeline can be serialized and deserialized with joblib."""
    pipe = build_baseline_pipeline(
        "logistic_regression",
        numeric_cols=["criticality", "in_degree"],
        categorical_cols=["exposure"],
        random_state=42,
    )
    X = pd.DataFrame({
        "criticality": [0.8, 0.4, 0.9, 0.2],
        "in_degree": [5, 1, 8, 0],
        "exposure": ["INTERNAL", "DMZ", "INTERNAL", "RESTRICTED_ISOLATED"],
    })
    y = np.array([1, 0, 1, 0])
    pipe.fit(X, y)

    save_path = str(tmp_path / "baseline_model.joblib")
    baseline_manager.save_pipeline(pipe, save_path)
    assert os.path.exists(save_path)

    loaded = baseline_manager.load_pipeline(save_path)
    preds = loaded.predict(X)
    assert np.array_equal(pipe.predict(X), preds)


def test_baseline_comparison_execution(baseline_manager):
    """Ensures compare_all_baselines returns multi-model benchmark results."""
    comp = baseline_manager.compare_all_baselines(
        feature_subset="topology_only",
        cv_folds=3,
        random_state=42,
    )
    models = comp["comparison"]
    assert "dummy_stratified" in models
    assert "logistic_regression" in models
    assert "random_forest" in models
    for m in models.values():
        assert "accuracy_mean" in m
        assert "roc_auc_mean" in m


# =====================================================================
# 6. REST API ROUTE HANDLER TESTS (RBAC & FUNCTIONALITY)
# =====================================================================

@pytest.fixture
def analyst_user():
    from backend.app.security.user_store import UserRecord
    from datetime import datetime, timezone
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


def test_api_get_dataset_inventory(analyst_user):
    """Ensures inventory endpoint returns complete dataset overview."""
    from backend.app.ml.router import get_dataset_inventory
    data = get_dataset_inventory(current_user=analyst_user)
    assert data["total_files"] >= 12
    assert "nodes.csv" in data["tables"]


def test_api_run_dataset_validation(analyst_user):
    """Ensures data validation endpoint returns PASSED report."""
    from backend.app.ml.router import run_dataset_validation
    data = run_dataset_validation(current_user=analyst_user)
    assert data["validation_status"] == "PASSED"
    assert data["total_nodes"] == 120


def test_api_list_supported_tasks(analyst_user):
    """Ensures tasks endpoint returns supported ML problems."""
    from backend.app.ml.router import list_supported_tasks
    data = list_supported_tasks(current_user=analyst_user)
    assert len(data["tasks"]) == 2
    task_ids = [t["task_id"] for t in data["tasks"]]
    assert "TASK_NODE_RISK_CLASSIFICATION" in task_ids
    assert "TASK_NODE_ANOMALY_DETECTION" in task_ids


def test_api_get_features_schema(analyst_user):
    """Ensures schema endpoint returns topology and telemetry features."""
    from backend.app.ml.router import get_features_schema
    data = get_features_schema(current_user=analyst_user)
    assert "topology_features" in data
    assert "telemetry_features" in data
    assert "forbidden_leakage_columns" in data
    assert "security_status" in data["forbidden_leakage_columns"]


def test_api_baseline_cross_validate(analyst_user):
    """Ensures cross-validation endpoint executes and returns metrics."""
    from backend.app.ml.router import cross_validate_baseline, CrossValidateRequest
    req = CrossValidateRequest(model_type="logistic_regression", feature_subset="topology_only", cv_folds=3)
    res = cross_validate_baseline(req, current_user=analyst_user)
    assert res["model_type"] == "logistic_regression"
    assert "metrics" in res
    assert "accuracy_mean" in res["metrics"]


def test_api_baseline_train_test(analyst_user):
    """Ensures train/test endpoint executes with feature importances."""
    from backend.app.ml.router import train_test_baseline, TrainTestRequest
    req = TrainTestRequest(model_type="random_forest", feature_subset="topology_only", test_size=0.2)
    res = train_test_baseline(req, current_user=analyst_user)
    assert res["train_samples"] == 96
    assert res["test_samples"] == 24
    assert "accuracy" in res["test_metrics"]


def test_api_baseline_compare(analyst_user):
    """Ensures baseline compare endpoint benchmarks all models."""
    from backend.app.ml.router import compare_baselines, CompareBaselinesRequest
    req = CompareBaselinesRequest(feature_subset="topology_only", cv_folds=3)
    res = compare_baselines(req, current_user=analyst_user)
    assert "dummy_stratified" in res["comparison"]
    assert "logistic_regression" in res["comparison"]
    assert "random_forest" in res["comparison"]


def test_api_anomaly_detect(analyst_user):
    """Ensures Isolation Forest anomaly detection endpoint returns outliers."""
    from backend.app.ml.router import detect_anomalies, AnomalyDetectRequest
    req = AnomalyDetectRequest(feature_subset="topology_only", contamination=0.10)
    res = detect_anomalies(req, current_user=analyst_user)
    assert res["model_type"] == "isolation_forest"
    assert res["results"]["anomalies_detected"] == 12
    assert len(res["results"]["top_anomalous_entities"]) > 0

