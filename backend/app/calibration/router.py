"""FastAPI REST Router for Phase 7.5 Adaptive Risk Calibration & Intelligent Threshold Optimization.

Provides REST endpoints with role-based access control (VIEWER, ANALYST, ADMIN) for empirical risk
calibration reports, cost-sensitive threshold optimization, shadow evaluation, alert fatigue analytics,
telemetry drift detection, governance recommendations, and versioned policy activation/rollback.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.app.calibration.alert_analytics import AlertFatigueAnalyzer
from backend.app.calibration.calibration_engine import RiskScoreCalibrationEngine
from backend.app.calibration.config_manager import ConfigurationVersionManager
from backend.app.calibration.drift_detector import TelemetryDriftDetector
from backend.app.calibration.graph_sync import CalibrationGraphSynchronizer
from backend.app.calibration.models import (
    AdaptiveRecommendation,
    AlertFatigueAnalytics,
    CandidateOptimizationResult,
    ConfigurationStatus,
    RiskScoreCalibrationReport,
    ShadowEvaluationResult,
    TelemetryDriftReport,
    ThresholdConfiguration,
)
from backend.app.calibration.recommendation_engine import AdaptiveRecommendationEngine
from backend.app.calibration.threshold_optimizer import IntelligentThresholdOptimizer
from backend.app.security.auth import require_admin, require_analyst, require_viewer
from backend.app.security.user_store import UserRecord

logger = logging.getLogger("safecontain.calibration.router")

router = APIRouter(prefix="/calibration", tags=["Adaptive Risk Calibration & Threshold Optimization (Phase 7.5)"])


# Request payload models
class ShadowEvaluationRequest(BaseModel):
    candidate_threshold: float = Field(..., ge=0.05, le=0.95, description="Candidate threshold theta to test in shadow mode")
    candidate_config_id: Optional[str] = Field(default=None, description="Optional ID of staged candidate configuration")


class RollbackRequest(BaseModel):
    target_config_id: str = Field(..., description="Configuration ID to reactivate")
    reason: str = Field(..., min_length=5, description="Auditable justification for reverting active threshold policy")


class CalibrationOverview(BaseModel):
    active_version: str
    active_threshold: float
    calibration_status: str
    calibration_quality_score: Optional[float]
    expected_calibration_error: Optional[float]
    brier_score: Optional[float]
    alert_fatigue_index: float
    fatigue_status: str
    drift_detected: bool
    drift_severity: str
    total_evaluated_samples: int
    pending_recommendations_count: int


# Subsystem factories
def _get_calib_engine() -> RiskScoreCalibrationEngine:
    return RiskScoreCalibrationEngine.get_instance()


def _get_optimizer() -> IntelligentThresholdOptimizer:
    return IntelligentThresholdOptimizer.get_instance()


def _get_shadow_evaluator():
    from backend.app.calibration.shadow_evaluator import ShadowThresholdEvaluator
    return ShadowThresholdEvaluator.get_instance()


def _get_fatigue_analyzer() -> AlertFatigueAnalyzer:
    return AlertFatigueAnalyzer.get_instance()


def _get_drift_detector() -> TelemetryDriftDetector:
    return TelemetryDriftDetector.get_instance()


def _get_rec_engine() -> AdaptiveRecommendationEngine:
    return AdaptiveRecommendationEngine.get_instance()


def _get_config_manager() -> ConfigurationVersionManager:
    return ConfigurationVersionManager.get_instance()


def _get_graph_sync() -> CalibrationGraphSynchronizer:
    return CalibrationGraphSynchronizer()


# =============================================================================
# 1. OVERVIEW & CALIBRATION REPORT ENDPOINTS
# =============================================================================

@router.get("/overview", summary="High-level risk calibration & threshold governance overview", response_model=CalibrationOverview)
def get_calibration_overview(
    current_user: UserRecord = Depends(require_viewer),
) -> CalibrationOverview:
    """Returns high-level KPI overview of active threshold policy, calibration quality, fatigue index, and drift."""
    cfg_mgr = _get_config_manager()
    calib_engine = _get_calib_engine()
    fatigue_analyzer = _get_fatigue_analyzer()
    drift_detector = _get_drift_detector()
    rec_engine = _get_rec_engine()

    active_cfg = cfg_mgr.get_active_configuration()
    calib_rep = calib_engine.evaluate_calibration()
    fatigue_rep = fatigue_analyzer.analyze_alert_fatigue()
    drift_rep = drift_detector.detect_drift()
    recs = rec_engine.generate_recommendations()

    return CalibrationOverview(
        active_version=active_cfg.version,
        active_threshold=active_cfg.operating_threshold,
        calibration_status=calib_rep.calibration_status.value,
        calibration_quality_score=calib_rep.calibration_quality_score,
        expected_calibration_error=calib_rep.expected_calibration_error,
        brier_score=calib_rep.brier_score,
        alert_fatigue_index=fatigue_rep.alert_fatigue_index,
        fatigue_status=fatigue_rep.fatigue_status,
        drift_detected=drift_rep.drift_detected,
        drift_severity=drift_rep.overall_drift_severity,
        total_evaluated_samples=calib_rep.sample_size,
        pending_recommendations_count=len(recs),
    )


@router.get("/report", summary="Detailed empirical risk calibration report", response_model=RiskScoreCalibrationReport)
def get_calibration_report(
    current_user: UserRecord = Depends(require_viewer),
) -> RiskScoreCalibrationReport:
    """Returns empirical calibration report including reliability bins, Brier score, and category breakdowns."""
    engine = _get_calib_engine()
    return engine.evaluate_calibration()


# =============================================================================
# 2. THRESHOLD OPTIMIZATION & SHADOW EVALUATION ENDPOINTS
# =============================================================================

@router.post("/optimize", summary="Evaluate and discover optimal cost-sensitive threshold candidate", response_model=CandidateOptimizationResult)
def run_threshold_optimization(
    min_recall: float = Query(default=0.90, ge=0.50, le=1.0, description="Minimum recall constraint"),
    current_user: UserRecord = Depends(require_analyst),
) -> CandidateOptimizationResult:
    """Scans candidate thresholds and stages optimal candidate configuration in PENDING_APPROVAL status."""
    optimizer = _get_optimizer()
    cfg_mgr = _get_config_manager()

    result = optimizer.optimize_threshold(min_recall=min_recall)
    if result.status == "CANDIDATE_GENERATED":
        # Stage the generated candidate configuration
        cfg_mgr.stage_candidate(result.candidate_configuration)

    return result


@router.post("/shadow-evaluate", summary="Run zero-interference shadow simulation of candidate threshold", response_model=ShadowEvaluationResult)
def run_shadow_evaluation(
    request: ShadowEvaluationRequest,
    current_user: UserRecord = Depends(require_analyst),
) -> ShadowEvaluationResult:
    """Evaluates candidate threshold in parallel with active baseline without altering production containment."""
    evaluator = _get_shadow_evaluator()
    cfg_mgr = _get_config_manager()
    active_cfg = cfg_mgr.get_active_configuration()

    return evaluator.evaluate_shadow_candidate(
        candidate_threshold=request.candidate_threshold,
        candidate_config_id=request.candidate_config_id,
        baseline_threshold=active_cfg.operating_threshold,
        baseline_config_id=active_cfg.config_id,
    )


# =============================================================================
# 3. ALERT FATIGUE & DRIFT ANALYTICS ENDPOINTS
# =============================================================================

@router.get("/alert-fatigue", summary="SOC alert quality, Gini concentration, and noisy asset analytics", response_model=AlertFatigueAnalytics)
def get_alert_fatigue_analytics(
    current_user: UserRecord = Depends(require_viewer),
) -> AlertFatigueAnalytics:
    """Returns alert volume distribution, Gini inequality coefficient, and top noisy assets."""
    analyzer = _get_fatigue_analyzer()
    return analyzer.analyze_alert_fatigue()


@router.get("/drift", summary="Telemetry feature drift and risk distribution shift diagnostics", response_model=TelemetryDriftReport)
def get_telemetry_drift_report(
    current_user: UserRecord = Depends(require_viewer),
) -> TelemetryDriftReport:
    """Computes PSI feature stability, Wasserstein distance on risk scores, and sensor coverage gaps."""
    detector = _get_drift_detector()
    return detector.detect_drift()


# =============================================================================
# 4. RECOMMENDATIONS ENDPOINTS
# =============================================================================

@router.get("/recommendations", summary="Governance and threshold recommendations for SOC leadership", response_model=List[AdaptiveRecommendation])
def get_adaptive_recommendations(
    current_user: UserRecord = Depends(require_viewer),
) -> List[AdaptiveRecommendation]:
    """Generates explainable, evidence-grounded recommendations across calibration, alert fatigue, and drift."""
    rec_engine = _get_rec_engine()
    return rec_engine.generate_recommendations()


# =============================================================================
# 5. CONFIGURATION GOVERNANCE, APPROVAL & ROLLBACK ENDPOINTS
# =============================================================================

@router.get("/configurations", summary="List all historical and active threshold configurations", response_model=List[ThresholdConfiguration])
def list_configurations(
    current_user: UserRecord = Depends(require_viewer),
) -> List[ThresholdConfiguration]:
    """Returns full auditable version history of threshold configurations."""
    mgr = _get_config_manager()
    return mgr.list_configurations()


@router.get("/configurations/active", summary="Get currently active threshold configuration", response_model=ThresholdConfiguration)
def get_active_configuration(
    current_user: UserRecord = Depends(require_viewer),
) -> ThresholdConfiguration:
    """Returns active configuration governing live threat scoring and containment thresholds."""
    mgr = _get_config_manager()
    return mgr.get_active_configuration()


@router.post("/configurations/{config_id}/approve", summary="Analyst approval of staged candidate configuration", response_model=ThresholdConfiguration)
def approve_configuration(
    config_id: str,
    current_user: UserRecord = Depends(require_analyst),
) -> ThresholdConfiguration:
    """Analyst signs off on staged candidate configuration, advancing it to APPROVED state."""
    mgr = _get_config_manager()
    cfg = mgr.approve_configuration(config_id=config_id, analyst_id=current_user.username)
    if not cfg:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration '{config_id}' not found.",
        )
    return cfg


@router.post("/configurations/{config_id}/reject", summary="Reject candidate configuration", response_model=ThresholdConfiguration)
def reject_configuration(
    config_id: str,
    reason: str = Query(default="Rejected by analyst during triage review", description="Rejection rationale"),
    current_user: UserRecord = Depends(require_analyst),
) -> ThresholdConfiguration:
    """Analyst or Admin rejects candidate configuration."""
    mgr = _get_config_manager()
    cfg = mgr.reject_configuration(config_id=config_id, user_id=current_user.username, reason=reason)
    if not cfg:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration '{config_id}' not found.",
        )
    return cfg


@router.post("/configurations/{config_id}/activate", summary="Administrator activation of threshold configuration", response_model=ThresholdConfiguration)
def activate_configuration(
    config_id: str,
    current_user: UserRecord = Depends(require_admin),
) -> ThresholdConfiguration:
    """Administrator activates an approved configuration. Synchronizes policy to GraphEngine and Neo4j."""
    mgr = _get_config_manager()
    cfg = mgr.activate_configuration(config_id=config_id, admin_id=current_user.username)
    if not cfg:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Configuration '{config_id}' not found.",
        )

    # Synchronize activated configuration to graph
    graph_sync = _get_graph_sync()
    graph_sync.sync_configuration_to_graph(cfg)

    return cfg


@router.post("/configurations/rollback", summary="Administrator rollback of active threshold policy", response_model=ThresholdConfiguration)
def rollback_configuration(
    request: RollbackRequest,
    current_user: UserRecord = Depends(require_admin),
) -> ThresholdConfiguration:
    """Administrator reverts active threshold policy to a previous configuration version."""
    mgr = _get_config_manager()
    cfg = mgr.rollback_configuration(
        target_config_id=request.target_config_id,
        admin_id=current_user.username,
        reason=request.reason,
    )
    if not cfg:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Target configuration '{request.target_config_id}' not found.",
        )

    # Synchronize rolled back configuration to graph
    graph_sync = _get_graph_sync()
    graph_sync.sync_configuration_to_graph(cfg)

    return cfg
