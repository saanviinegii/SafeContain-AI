"""FastAPI REST Router for SafeContain AI Machine Learning Pipeline.

Exposes endpoints for dataset discovery, quality validation, feature schema inspection,
baseline cross-validation, train/test evaluation, and unsupervised anomaly detection.
"""

import os
import json
from typing import Any, Dict, List, Optional
import pandas as pd
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

from backend.app.ml.dataset_loader import DatasetLoader
from backend.app.ml.data_validation import DataValidator
from backend.app.ml.feature_engineering import FeatureEngineer
from backend.app.ml.baseline import BaselineManager
from backend.app.ml.task_definition import (
    TASK_NODE_RISK_CLASSIFICATION,
    TASK_NODE_ANOMALY_DETECTION,
    TOPOLOGY_FEATURE_COLUMNS,
    TELEMETRY_FEATURE_COLUMNS,
    FORBIDDEN_LEAKAGE_COLUMNS,
)
from backend.app.security.auth import (
    UserRecord,
    get_current_user,
    require_analyst,
    require_viewer,
)

router = APIRouter(prefix="/ml", tags=["Machine Learning Pipeline"])

# Shared singleton instances
_dataset_loader = DatasetLoader()
_data_validator = DataValidator(_dataset_loader)
_feature_engineer = FeatureEngineer(_dataset_loader)
_baseline_manager = BaselineManager(_feature_engineer)

from backend.app.ml.model_registry import ModelRegistry
_model_registry = ModelRegistry(feature_engineer=_feature_engineer)

from backend.app.ml.explainability import ShapExplainerService
_shap_service = ShapExplainerService(
    model_registry=_model_registry,
    feature_engineer=_feature_engineer,
)

from backend.app.ml.drift_detector import TelemetryDriftDetector
_drift_detector = TelemetryDriftDetector(
    model_registry=_model_registry,
    feature_engineer=_feature_engineer,
)

from backend.app.ml.retraining import RetrainingManager
_retraining_manager = RetrainingManager(
    feature_engineer=_feature_engineer,
    model_registry=_model_registry,
)

from backend.app.reporting.dossier_generator import IncidentDossierGenerator
_dossier_generator = IncidentDossierGenerator(
    model_registry=_model_registry,
    drift_detector=_drift_detector,
    shap_service=_shap_service,
)


# --- Request Models ---

class CrossValidateRequest(BaseModel):
    model_type: str = Field(
        default="logistic_regression",
        description="Baseline model: 'logistic_regression', 'random_forest', 'dummy_stratified', or 'dummy_prior'",
    )
    feature_subset: str = Field(
        default="topology_only",
        description="Feature subset: 'topology_only' (leak-free) or 'full' (with telemetry)",
    )
    cv_folds: int = Field(default=5, ge=2, le=10, description="Number of CV folds")
    random_state: int = Field(default=42, description="Random seed for reproducibility")


class TrainTestRequest(BaseModel):
    model_type: str = Field(
        default="logistic_regression",
        description="Baseline model: 'logistic_regression' or 'random_forest'",
    )
    feature_subset: str = Field(
        default="topology_only",
        description="Feature subset: 'topology_only' or 'full'",
    )
    test_size: float = Field(default=0.20, gt=0.05, lt=0.50, description="Test split proportion")
    random_state: int = Field(default=42, description="Random seed for reproducibility")


class AnomalyDetectRequest(BaseModel):
    feature_subset: str = Field(
        default="topology_only",
        description="Feature subset: 'topology_only' or 'full'",
    )
    contamination: float = Field(
        default=0.10,
        gt=0.01,
        lt=0.50,
        description="Expected anomaly contamination fraction",
    )
    random_state: int = Field(default=42, description="Random seed for reproducibility")


class CompareBaselinesRequest(BaseModel):
    feature_subset: str = Field(
        default="topology_only",
        description="Feature subset: 'topology_only' or 'full'",
    )
    cv_folds: int = Field(default=5, ge=2, le=10, description="Number of CV folds")
    random_state: int = Field(default=42, description="Random seed for reproducibility")


class DriftRunRequest(BaseModel):
    dataset_label: str = Field(default="MANUAL_AUDIT", description="Label for current telemetry sample")


class RetrainRequest(BaseModel):
    feature_subset: str = Field(default="topology_only", description="Feature subset ('topology_only' or 'full')")
    cv_folds: int = Field(default=5, ge=2, le=10, description="Cross-validation fold count")
    test_size: float = Field(default=0.2, ge=0.1, le=0.4, description="Holdout test split ratio")
    trigger_type: str = Field(default="MANUAL", description="Retraining trigger context")
    candidate_model_type: str = Field(default="logistic_regression", description="Candidate algorithm ('logistic_regression', 'random_forest')")
    user_notes: str = Field(default="", description="Analyst justification or notes")


class ModelPromotionRequest(BaseModel):
    challenger_version: str = Field(..., description="Semantic version of challenger model to promote")
    approval_notes: str = Field(default="", description="Governance approval rationale")


class ModelRejectionRequest(BaseModel):
    challenger_version: str = Field(..., description="Semantic version of candidate model to reject")
    rejection_reason: str = Field(..., description="Justification for rejecting candidate model")


class ModelRollbackRequest(BaseModel):
    target_version: str = Field(..., description="Archived semantic version to restore as active champion")
    rollback_reason: str = Field(default="Emergency rollback requested by SecOps.", description="Rollback justification")


class DossierGenerateRequest(BaseModel):
    incident_id: Optional[str] = Field(default=None, description="Optional incident identifier")
    analyst_name: str = Field(default="SecOps Lead Analyst", description="Name of investigator")
    analyst_notes: str = Field(default="", description="Strategic commentary or containment context")
    target_scenario: str = Field(default="Live Enterprise Multi-Hop Threat Vector", description="Scenario context")


# --- Endpoints ---

@router.get("/datasets/inventory", summary="Get dataset inventory summary")
def get_dataset_inventory(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns record counts, features, null counts, and file list of all enterprise datasets."""
    return _dataset_loader.get_inventory_summary()


@router.get("/datasets/validation", summary="Run data quality audit")
def run_dataset_validation(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Performs data quality, integrity, and class distribution checks across datasets."""
    return _data_validator.validate_dataset_quality()


@router.get("/tasks", summary="List supported ML tasks")
def list_supported_tasks(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns definitions, objectives, and leakage guardrails for supported ML tasks."""
    return {
        "tasks": [
            {
                "task_id": TASK_NODE_RISK_CLASSIFICATION.task_id,
                "task_name": TASK_NODE_RISK_CLASSIFICATION.task_name,
                "task_type": TASK_NODE_RISK_CLASSIFICATION.task_type.value,
                "description": TASK_NODE_RISK_CLASSIFICATION.description,
                "target_column": TASK_NODE_RISK_CLASSIFICATION.target_column,
                "primary_metrics": TASK_NODE_RISK_CLASSIFICATION.primary_metrics,
                "allowed_feature_subsets": TASK_NODE_RISK_CLASSIFICATION.allowed_feature_subsets,
                "leakage_risks": TASK_NODE_RISK_CLASSIFICATION.leakage_risks,
                "limitations": TASK_NODE_RISK_CLASSIFICATION.limitations,
            },
            {
                "task_id": TASK_NODE_ANOMALY_DETECTION.task_id,
                "task_name": TASK_NODE_ANOMALY_DETECTION.task_name,
                "task_type": TASK_NODE_ANOMALY_DETECTION.task_type.value,
                "description": TASK_NODE_ANOMALY_DETECTION.description,
                "target_column": TASK_NODE_ANOMALY_DETECTION.target_column,
                "primary_metrics": TASK_NODE_ANOMALY_DETECTION.primary_metrics,
                "allowed_feature_subsets": TASK_NODE_ANOMALY_DETECTION.allowed_feature_subsets,
                "leakage_risks": TASK_NODE_ANOMALY_DETECTION.leakage_risks,
                "limitations": TASK_NODE_ANOMALY_DETECTION.limitations,
            },
        ]
    }


@router.get("/features/schema", summary="Get feature engineering schema")
def get_features_schema(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns engineered feature definitions, types, and leakage isolation policy."""
    subsets = _feature_engineer.get_feature_subsets()
    return {
        "feature_subsets": subsets,
        "topology_features": TOPOLOGY_FEATURE_COLUMNS,
        "telemetry_features": TELEMETRY_FEATURE_COLUMNS,
        "forbidden_leakage_columns": list(FORBIDDEN_LEAKAGE_COLUMNS),
        "total_topology_features": len(TOPOLOGY_FEATURE_COLUMNS),
        "total_full_features": len(TOPOLOGY_FEATURE_COLUMNS) + len(TELEMETRY_FEATURE_COLUMNS),
        "leakage_isolation_policy": (
            "Target column 'security_status' and derived 'target_is_at_risk' are strictly excluded. "
            "All scalers and encoders are fitted solely on training splits."
        ),
    }


@router.post("/baseline/cross-validate", summary="Run Stratified K-Fold cross-validation")
def cross_validate_baseline(
    request: CrossValidateRequest,
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Executes multi-metric Stratified K-Fold cross validation on a baseline model."""
    try:
        return _baseline_manager.run_cross_validation(
            model_type=request.model_type,
            feature_subset=request.feature_subset,
            cv_folds=request.cv_folds,
            random_state=request.random_state,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cross-validation failed: {str(e)}",
        )


@router.post("/baseline/train-test", summary="Train and evaluate on train/test split")
def train_test_baseline(
    request: TrainTestRequest,
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Fits pipeline strictly on training split and evaluates on unseen test split."""
    try:
        return _baseline_manager.train_test_evaluate(
            model_type=request.model_type,
            feature_subset=request.feature_subset,
            test_size=request.test_size,
            random_state=request.random_state,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Train/test evaluation failed: {str(e)}",
        )


@router.post("/baseline/compare", summary="Compare all baseline models")
def compare_baselines(
    request: CompareBaselinesRequest,
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Compares Dummy, Logistic Regression, and Random Forest baseline models across CV folds."""
    try:
        return _baseline_manager.compare_all_baselines(
            feature_subset=request.feature_subset,
            cv_folds=request.cv_folds,
            random_state=request.random_state,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Baseline comparison failed: {str(e)}",
        )


@router.post("/anomaly/detect", summary="Run Isolation Forest anomaly detection")
def detect_anomalies(
    request: AnomalyDetectRequest,
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Runs unsupervised Isolation Forest anomaly detection on enterprise graph entities."""
    try:
        return _baseline_manager.run_isolation_forest_anomaly_detection(
            feature_subset=request.feature_subset,
            contamination=request.contamination,
            random_state=request.random_state,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Anomaly detection failed: {str(e)}",
        )


# =====================================================================
# PHASE 7.2A: MODEL REGISTRY, INFERENCE & TRAINING PIPELINE ENDPOINTS
# =====================================================================

from backend.app.ml.model_trainer import ModelTrainer
from backend.app.ml.model_registry import ModelRegistry

_model_registry = ModelRegistry(feature_engineer=_feature_engineer)
_model_trainer = ModelTrainer(feature_engineer=_feature_engineer)


class TrainPipelineRequest(BaseModel):
    feature_subset: str = Field(
        default="topology_only",
        description="Feature subset: 'topology_only' or 'full'",
    )
    cv_folds: int = Field(default=5, ge=2, le=10, description="Cross-validation folds")
    test_size: float = Field(default=0.20, gt=0.05, lt=0.50, description="Holdout test proportion")
    random_state: int = Field(default=42, description="Random seed")


class NodePredictionRequest(BaseModel):
    node_ids: Optional[List[str]] = Field(
        default=None,
        description="Specific node IDs to predict. If omitted, evaluates all graph nodes.",
    )
    threshold: Optional[float] = Field(
        default=None,
        ge=0.01,
        le=0.99,
        description="Optional decision threshold override. If omitted, uses calibrated operating threshold.",
    )



@router.get("/models/active", summary="Get active registered model metadata")
def get_active_model(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns metadata, hyperparameter configuration, and test metrics of active model."""
    return _model_registry.get_model_metadata()


@router.get("/models/comparison", summary="Get model comparison metrics")
def get_model_comparison(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns cross-validation comparison metrics across all evaluated candidate models."""
    csv_path = os.path.join(_model_trainer.metrics_dir, "model_comparison.csv")
    if not os.path.exists(csv_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Model comparison metrics not found. Run training pipeline first.",
        )
    df = pd.read_csv(csv_path)
    return {
        "models_count": len(df),
        "comparison": df.to_dict(orient="records"),
    }


@router.post("/models/predict", summary="Predict cybersecurity risk for enterprise nodes")
def predict_node_risk(
    request: NodePredictionRequest,
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Evaluates calibrated risk probabilities and predicted compromise tiers for enterprise nodes."""
    try:
        predictions = _model_registry.predict_for_nodes(
            node_ids=request.node_ids,
            threshold=request.threshold,
        )
        return {
            "model_status": "ACTIVE",
            "operating_threshold": _model_registry.get_operating_threshold() if request.threshold is None else request.threshold,
            "total_evaluated": len(predictions),
            "predictions": predictions,
        }
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Inference failed: {str(e)}",
        )


@router.post("/train/run", summary="Run full ML training and hyperparameter optimization")
def trigger_training_pipeline(
    request: TrainPipelineRequest,
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Executes full ML training pipeline with hyperparameter optimization and holdout evaluation."""
    try:
        return _model_trainer.run_pipeline(
            feature_subset=request.feature_subset,
            test_size=request.test_size,
            cv_folds=request.cv_folds,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Training pipeline execution failed: {str(e)}",
        )


# =====================================================================
# PHASE 7.2B: DECISION THRESHOLD CALIBRATION ENDPOINTS
# =====================================================================

from backend.app.ml.threshold_calibration import ThresholdCalibrator

_threshold_calibrator = ThresholdCalibrator(feature_engineer=_feature_engineer)


class CalibrationRunRequest(BaseModel):
    feature_subset: str = Field(default="topology_only", description="Feature subset: 'topology_only' or 'full'")
    recall_target: float = Field(default=0.80, ge=0.50, le=0.99, description="Target threat recall constraint")
    cost_fn: float = Field(default=10.0, ge=1.0, description="Cost penalty for False Negative")
    cost_fp: float = Field(default=1.0, ge=0.1, description="Cost penalty for False Positive")
    start_th: float = Field(default=0.15, ge=0.05, le=0.50, description="Minimum search threshold")
    stop_th: float = Field(default=0.40, ge=0.10, le=0.90, description="Maximum search threshold")
    step_th: float = Field(default=0.01, ge=0.005, le=0.05, description="Search resolution step")


@router.get("/calibration", summary="Get current decision threshold calibration status")
def get_calibration_status(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns the calibrated operating threshold, strategy, target status, and holdout comparison."""
    return _model_registry.get_calibration_metadata()


@router.get("/calibration/thresholds", summary="Get threshold comparison metric grid")
def get_threshold_metrics_grid(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns candidate thresholds with recall, precision, specificity, F1, and cost utility."""
    csv_path = os.path.join(_threshold_calibrator.calibration_dir, "threshold_metrics.csv")
    if not os.path.exists(csv_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threshold metrics not found. Run threshold calibration first.",
        )
    df = pd.read_csv(csv_path)
    return {
        "candidate_thresholds_count": len(df),
        "threshold_metrics": df.to_dict(orient="records"),
    }


# =====================================================================
# PHASE 7.2C: EXPLAINABLE AI, LIVE GRAPH RISK & ML OPTIMIZATION ENDPOINTS
# =====================================================================

class ExplainRequest(BaseModel):
    node_ids: Optional[List[str]] = Field(default=None, description="Optional subset of node IDs to explain")
    top_n: int = Field(default=5, ge=1, le=13, description="Number of top influential features to return")
    threshold: Optional[float] = Field(default=None, description="Optional decision threshold override")


class MLOptimizeRequest(BaseModel):
    budget_limit: float = Field(default=10000.0, ge=100.0, description="Containment budget cap in dollars")
    threshold_override: Optional[float] = Field(default=None, ge=0.05, le=0.95, description="Operating threshold override")


@router.get("/health", summary="Get ML pipeline and explainability health status")
def get_ml_health(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns operational health, active model version, operating threshold, and SHAP readiness."""
    is_trained = _model_registry.is_model_available()
    is_calibrated = _model_registry.is_calibration_available()
    return {
        "status": "HEALTHY" if is_trained else "UNINITIALIZED",
        "is_model_available": is_trained,
        "is_calibration_active": is_calibrated,
        "operating_threshold": _model_registry.get_operating_threshold(),
        "shap_explainer_ready": is_trained,
        "model_type": "LogisticRegression (liblinear, C=0.5, balanced)" if is_trained else None,
        "feature_count": 13,
    }


@router.get("/models", summary="List ML models and active status")
def list_models(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns active model metadata, features schema, and calibration status."""
    return {
        "active_model": _model_registry.get_model_metadata(),
        "calibration": _model_registry.get_calibration_metadata(),
    }


@router.get("/assets", summary="List all network assets with ML risk scores")
def list_assets_ml_risk(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns calibrated ML threat probabilities and risk tiers for all enterprise graph assets."""
    preds = _model_registry.predict_for_nodes()
    return {
        "total_assets": len(preds),
        "operating_threshold": _model_registry.get_operating_threshold(),
        "threats_count": sum(1 for p in preds if p["is_at_risk"]),
        "assets": preds,
    }


@router.get("/assets/{asset_id}/risk", summary="Get single asset ML risk evaluation")
def get_asset_risk(
    asset_id: str,
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns calibrated threat probability, decision threshold, and risk tier for a specific asset."""
    preds = _model_registry.predict_for_nodes(node_ids=[asset_id])
    if not preds:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{asset_id}' not found in active graph dataset.",
        )
    return preds[0]


@router.get("/assets/{asset_id}/explanation", summary="Get SHAP feature explanation for asset")
def get_asset_explanation(
    asset_id: str,
    top_n: int = Query(default=5, ge=1, le=13),
    threshold: Optional[float] = None,
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns detailed SHAP feature attributions, base value, and analyst summary for an asset."""
    try:
        return _shap_service.explain_asset(
            node_id=asset_id,
            top_n=top_n,
            threshold=threshold,
        )
    except KeyError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SHAP explanation failed: {str(e)}",
        )


@router.post("/explain", summary="Generate SHAP feature explanations on demand")
def explain_assets_on_demand(
    request: ExplainRequest,
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Computes SHAP explanations for requested asset IDs or all network assets on demand."""
    try:
        if request.node_ids:
            explanations = [
                _shap_service.explain_asset(
                    nid,
                    top_n=request.top_n,
                    threshold=request.threshold,
                )
                for nid in request.node_ids
            ]
        else:
            raw_all = _shap_service.get_all_asset_explanations(
                top_n=request.top_n,
                threshold=request.threshold,
            )
            explanations = list(raw_all.values())

        return {
            "total_explained": len(explanations),
            "operating_threshold": _model_registry.get_operating_threshold() if request.threshold is None else request.threshold,
            "explanations": explanations,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Batch explanation failed: {str(e)}",
        )


@router.get("/graph-risk", summary="Get comprehensive graph ML risk map")
def get_graph_risk_intelligence(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns high-performance map of ML threat probabilities and risk tiers for frontend graph."""
    try:
        preds = _model_registry.predict_for_nodes()
        th = _model_registry.get_operating_threshold()

        risk_map = {}
        for p in preds:
            nid = p["node_id"]
            risk_map[nid] = {
                "node_id": nid,
                "ml_probability": p["risk_probability"],
                "decision_threshold": th,
                "predicted_class": "At-Risk / Threat" if p["is_at_risk"] else "Healthy / Benign",
                "threshold_crossed": bool(p["is_at_risk"]),
                "risk_tier": p["risk_tier"],
                "node_type": p["node_type"],
                "criticality": p["criticality"],
                "explanation_available": True,
            }

        return {
            "operating_threshold": th,
            "total_nodes": len(preds),
            "threats_detected": sum(1 for p in preds if p["is_at_risk"]),
            "risk_map": risk_map,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate graph risk intelligence: {str(e)}",
        )


@router.post("/containment/optimize", summary="Run ML-augmented CP-SAT containment optimization")
def run_ml_containment_optimization(
    request: MLOptimizeRequest,
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Executes CP-SAT containment optimization incorporating calibrated ML threat probabilities."""
    try:
        from backend.app.api.v1.router import platform_ctx
        from backend.app.optimization.solver import CPSATOptimizer
        from backend.app.planning.catalog import ActionCatalog

        paths = platform_ctx.engine.find_attack_paths()
        nodes = {n.id: n for n in platform_ctx.engine.get_all_nodes()}
        candidates = ActionCatalog.generate_candidate_actions(paths, nodes)

        plan = CPSATOptimizer.plan(
            candidate_actions=candidates,
            twin=platform_ctx.twin,
            engine=platform_ctx.engine,
            budget_limit=request.budget_limit,
            operating_threshold=request.threshold_override,
            model_registry=_model_registry,
        )

        # Anchor recommendation in cryptographic audit ledger
        platform_ctx.current_plan = plan
        platform_ctx.ledger.record_recommendation(
            plan_id=plan.id,
            strategy=plan.strategy.value,
            objective_score=plan.objective_score,
            total_cost=plan.total_cost,
            predicted_risk_reduction=plan.predicted_risk_reduction,
            actions_count=len(plan.actions),
        )

        return {
            "plan": plan.model_dump(mode="json"),
            "operating_threshold": request.threshold_override or _model_registry.get_operating_threshold(),
            "selected_actions_count": len(plan.actions),
            "total_candidates": len(candidates),
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"ML-augmented containment optimization failed: {str(e)}",
        )


# =============================================================================
# Phase 7.2D: Continuous Telemetry Drift Detection Endpoints
# =============================================================================

@router.get("/drift/status", summary="Get latest telemetry drift report")
def get_drift_status(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns the latest feature drift, prediction drift, data quality, and retraining recommendation."""
    try:
        report = _drift_detector.get_latest_drift_report()
        return report
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve telemetry drift status: {str(e)}",
        )


@router.get("/drift/history", summary="Get historical drift monitoring timeline")
def get_drift_history(
    current_user: UserRecord = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    """Returns historical drift assessments for trend analysis and audit review."""
    try:
        return _drift_detector.get_drift_history()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve drift history: {str(e)}",
        )


@router.post("/drift/run", summary="Execute on-demand telemetry drift analysis")
def run_drift_analysis(
    request: DriftRunRequest,
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Executes full drift detection pipeline comparing active telemetry against baseline training reference."""
    try:
        report = _drift_detector.run_drift_analysis(dataset_label=request.dataset_label)
        return report
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute drift analysis: {str(e)}",
        )


# =============================================================================
# Phase 7.2D: Retraining & Champion-Challenger Lifecycle Governance
# =============================================================================

@router.post("/retrain/request", summary="Trigger candidate model retraining job")
def trigger_retraining(
    request: RetrainRequest,
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Validates pre-training quality gate, trains challenger model, calibrates threshold, and compares against champion."""
    try:
        result = _retraining_manager.train_challenger(
            feature_subset=request.feature_subset,
            cv_folds=request.cv_folds,
            test_size=request.test_size,
            trigger_type=request.trigger_type,
            user_notes=request.user_notes,
            candidate_model_type=request.candidate_model_type,
            initiator=current_user.username,
        )
        return result
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Retraining execution failed: {str(e)}",
        )


@router.get("/retrain/jobs", summary="List historical retraining jobs")
def list_retraining_jobs(
    current_user: UserRecord = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    """Returns log of all executed retraining jobs, triggers, statuses, and performance outcomes."""
    try:
        return _retraining_manager.list_retraining_jobs()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve retraining jobs: {str(e)}",
        )


@router.get("/retrain/compare", summary="Compare Champion vs Challenger models")
def compare_models(
    challenger_version: Optional[str] = Query(default=None, description="Candidate version (defaults to latest)"),
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Generates side-by-side metric comparison and automated promotion recommendation."""
    try:
        target_v = challenger_version if isinstance(challenger_version, str) else None
        comparison = _retraining_manager.compare_champion_challenger(challenger_version=target_v)
        return comparison
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Model comparison failed: {str(e)}",
        )


@router.post("/retrain/approve", summary="Promote challenger model to active champion")
def approve_model_promotion(
    request: ModelPromotionRequest,
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Governance gate: Promotes approved candidate model to production champion with atomic backup."""
    try:
        promo = _retraining_manager.approve_and_promote_model(
            challenger_version=request.challenger_version,
            current_user=current_user.username,
            approval_notes=request.approval_notes,
        )
        return promo
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Model promotion failed: {str(e)}",
        )


@router.post("/retrain/reject", summary="Reject candidate challenger model")
def reject_model(
    request: ModelRejectionRequest,
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Formally records rejection of a candidate model with analyst justification."""
    try:
        rej = _retraining_manager.reject_model(
            challenger_version=request.challenger_version,
            current_user=current_user.username,
            rejection_reason=request.rejection_reason,
        )
        return rej
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Model rejection failed: {str(e)}",
        )


@router.post("/retrain/rollback", summary="Emergency rollback to previous model version")
def rollback_model(
    request: ModelRollbackRequest,
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Emergency governance rollback: Restores designated archived version to active production champion."""
    try:
        res = _retraining_manager.rollback_model(
            target_version=request.target_version,
            current_user=current_user.username,
            rollback_reason=request.rollback_reason,
        )
        return res
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Model rollback failed: {str(e)}",
        )


@router.get("/models/versions", summary="List registered model versions and statuses")
def list_model_versions(
    current_user: UserRecord = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    """Returns all registered model versions, deployment states, and validation metrics."""
    try:
        return _retraining_manager.list_model_versions()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list model versions: {str(e)}",
        )


# =============================================================================
# Phase 7.2D: Incident Dossier Generation & Professional PDF Export
# =============================================================================

@router.post("/dossier/generate", summary="Generate automated incident containment dossier")
def generate_incident_dossier(
    request: DossierGenerateRequest,
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Aggregates real telemetry, attack paths, ML probabilities, SHAP drivers, CP-SAT actions, and renders PDF."""
    try:
        result = _dossier_generator.generate_full_dossier(
            incident_id=request.incident_id,
            analyst_name=request.analyst_name or current_user.username,
            analyst_notes=request.analyst_notes,
            target_scenario=request.target_scenario,
        )
        return {
            "status": "GENERATED",
            "dossier_id": result["dossier_id"],
            "generated_at": result["generated_at"],
            "pdf_size_bytes": result["pdf_size_bytes"],
            "cryptographic_audit_hash": result["cryptographic_audit_hash"],
            "executive_summary": result["executive_summary"],
            "download_url": f"/api/v1/ml/dossier/download?dossier_id={result['dossier_id']}",
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate incident dossier: {str(e)}",
        )


@router.get("/dossier/list", summary="List generated incident dossiers")
def list_generated_dossiers(
    current_user: UserRecord = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    """Returns catalog of all historical and active generated incident dossiers."""
    try:
        return _dossier_generator.list_generated_dossiers()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list incident dossiers: {str(e)}",
        )


@router.get("/dossier/download", summary="Download official incident dossier PDF")
def download_incident_dossier(
    dossier_id: Optional[str] = Query(default=None, description="Specific dossier ID to download"),
    filename: Optional[str] = Query(default=None, description="Optional filename override"),
    current_user: UserRecord = Depends(require_viewer),
):
    """Streams binary PDF file for direct browser download and audit submission."""
    try:
        dossiers_dir = _dossier_generator.dossiers_dir
        if not os.path.exists(dossiers_dir):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No dossiers directory found.")

        target_file = None
        target_fn = filename if isinstance(filename, str) else None
        target_did = dossier_id if isinstance(dossier_id, str) else None

        if target_fn:
            cand = os.path.join(dossiers_dir, os.path.basename(target_fn))
            if os.path.exists(cand):
                target_file = cand
        elif target_did:
            cand = os.path.join(dossiers_dir, f"incident_dossier_{target_did}.pdf")
            if os.path.exists(cand):
                target_file = cand

        if not target_file:
            # Pick latest PDF
            pdfs = [
                os.path.join(dossiers_dir, f)
                for f in os.listdir(dossiers_dir)
                if f.endswith(".pdf")
            ]
            if not pdfs:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No generated PDF dossiers available.")
            pdfs.sort(key=os.path.getmtime, reverse=True)
            target_file = pdfs[0]

        return FileResponse(
            path=target_file,
            media_type="application/pdf",
            filename=os.path.basename(target_file),
            headers={
                "Content-Disposition": f'attachment; filename="{os.path.basename(target_file)}"',
            },
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to stream incident dossier PDF: {str(e)}",
        )


@router.get("/dossier/preview", summary="Preview latest incident dossier metadata")
def preview_latest_dossier(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns preview metadata and summary for the most recently generated incident dossier."""
    try:
        dossiers = _dossier_generator.list_generated_dossiers()
        if not dossiers:
            # Generate one on the fly if none exist
            return _dossier_generator.generate_full_dossier()
        latest_meta = dossiers[0]
        json_path = os.path.join(_dossier_generator.dossiers_dir, latest_meta["json_file"])
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to preview incident dossier: {str(e)}",
        )



