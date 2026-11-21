"""SafeContain AI Machine Learning Package.

Provides dataset discovery, data quality validation, graph-topological
feature engineering, baseline models, and cross-validation pipelines.
"""

from backend.app.ml.dataset_loader import DatasetLoader, DEFAULT_ML_DATASET_DIR
from backend.app.ml.data_validation import DataValidator
from backend.app.ml.task_definition import (
    MLTaskType,
    TaskDefinition,
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
from backend.app.ml.hyperparameter_search import HyperparameterOptimizer
from backend.app.ml.model_trainer import ModelTrainer, DEFAULT_ARTIFACTS_DIR
from backend.app.ml.model_registry import ModelRegistry
from backend.app.ml.threshold_calibration import ThresholdCalibrator, DEFAULT_CALIBRATION_DIR
from backend.app.ml.explainability import ShapExplainerService

__all__ = [
    "DatasetLoader",
    "DEFAULT_ML_DATASET_DIR",
    "DataValidator",
    "MLTaskType",
    "TaskDefinition",
    "TASK_NODE_RISK_CLASSIFICATION",
    "TASK_NODE_ANOMALY_DETECTION",
    "TOPOLOGY_FEATURE_COLUMNS",
    "TELEMETRY_FEATURE_COLUMNS",
    "FORBIDDEN_LEAKAGE_COLUMNS",
    "assert_no_target_leakage",
    "FeatureEngineer",
    "compute_classification_metrics",
    "aggregate_cv_metrics",
    "compute_anomaly_metrics",
    "build_baseline_pipeline",
    "BaselineManager",
    "HyperparameterOptimizer",
    "ModelTrainer",
    "DEFAULT_ARTIFACTS_DIR",
    "ModelRegistry",
    "ThresholdCalibrator",
    "DEFAULT_CALIBRATION_DIR",
    "ShapExplainerService",
]
