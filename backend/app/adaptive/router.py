"""FastAPI REST Router for Phase 7.4 Adaptive Threat Intelligence & Predictive Feedback Loop."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.app.adaptive.evaluation_engine import TemporalEvaluationEngine
from backend.app.adaptive.feedback_engine import AdaptiveFeedbackEngine
from backend.app.adaptive.graph_sync import AdaptiveGraphSynchronizer
from backend.app.adaptive.intelligence_quality import ThreatIntelligenceQualityEngine
from backend.app.adaptive.metrics import AdaptiveMetricsCalculator
from backend.app.adaptive.models import (
    AdaptiveFeedbackInsights,
    AdaptiveSummary,
    PredictionOutcomeStatus,
    PredictionRecord,
    PredictivePerformanceMetrics,
    ThreatIntelQualityMetrics,
)
from backend.app.adaptive.shap_analyzer import ExplanationQualityAnalyzer
from backend.app.adaptive.tracker import PredictionOutcomeTracker
from backend.app.security.auth import require_analyst, require_viewer
from backend.app.security.user_store import UserRecord

router = APIRouter(prefix="/adaptive", tags=["Adaptive Intelligence & Feedback Loop (Phase 7.4)"])


def _get_tracker() -> PredictionOutcomeTracker:
    return PredictionOutcomeTracker.get_instance()


def _get_eval_engine() -> TemporalEvaluationEngine:
    return TemporalEvaluationEngine(tracker=_get_tracker())


def _get_metrics_calc() -> AdaptiveMetricsCalculator:
    return AdaptiveMetricsCalculator(tracker=_get_tracker())


def _get_feedback_engine() -> AdaptiveFeedbackEngine:
    return AdaptiveFeedbackEngine(tracker=_get_tracker(), metrics_calc=_get_metrics_calc())


# =============================================================================
# 1. SUMMARY & PERFORMANCE METRICS ENDPOINTS
# =============================================================================

@router.get("/summary", summary="Get executive adaptive intelligence operational overview", response_model=AdaptiveSummary)
def get_adaptive_summary(
    current_user: UserRecord = Depends(require_viewer),
) -> AdaptiveSummary:
    """Returns high-level KPI overview across all registered, evaluated, and pending forecasts."""
    tracker = _get_tracker()
    metrics_calc = _get_metrics_calc()

    all_preds = tracker.get_all_predictions()
    total_count = len(all_preds)

    m = metrics_calc.calculate_metrics()
    evaluated_count = m.evaluated_count
    pending_count = m.pending_count
    insufficient_count = m.insufficient_evidence_count

    data_status = "SUFFICIENT" if evaluated_count >= 10 else "INSUFFICIENT_EVALUATED_DATA" if total_count > 0 else "EMPTY"
    notes = (
        f"Evaluated {evaluated_count} of {total_count} forecasts against observed telemetry."
        if evaluated_count > 0
        else "No predictions have completed their forecast horizons yet. Awaiting horizon elapsing or trigger benchmark bootstrap."
    )

    return AdaptiveSummary(
        total_predictions=total_count,
        evaluated_predictions=evaluated_count,
        pending_predictions=pending_count,
        insufficient_evidence_predictions=insufficient_count,
        overall_precision=m.precision,
        overall_recall=m.recall,
        overall_f1=m.f1_score,
        overall_brier_score=m.brier_score,
        operating_threshold=0.32,
        data_quality_status=data_status,
        data_quality_notes=notes,
        latest_evaluated_at=m.calculated_at if evaluated_count > 0 else None,
        active_model_version="v7.3.0_temporal_gradient_boost",
        generated_at=datetime.now(timezone.utc),
    )


@router.get("/metrics", summary="Get detailed performance metrics across horizons", response_model=Dict[str, Any])
def get_predictive_metrics(
    horizon: Optional[str] = Query(default=None, description="Optional horizon filter (NEAR_TERM, SHORT_TERM, MEDIUM_TERM)"),
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Retrieves precision, recall, F1, Brier score, confusion matrix, and horizon comparison breakdown."""
    metrics_calc = _get_metrics_calc()
    h_str = horizon if isinstance(horizon, str) else None
    overall = metrics_calc.calculate_metrics(horizon=h_str)
    horizon_comparisons = metrics_calc.compare_horizons()
    asset_type_perf = metrics_calc.breakdown_by_asset_type()

    return {
        "metrics": overall.model_dump(mode="json"),
        "horizon_comparisons": [h.model_dump(mode="json") for h in horizon_comparisons],
        "asset_type_performance": [a.model_dump(mode="json") for a in asset_type_perf],
        "calculated_at": datetime.now(timezone.utc).isoformat(),
    }


get_adaptive_metrics = get_predictive_metrics


# =============================================================================
# 2. PREDICTION OUTCOMES AUDIT TABLE ENDPOINTS
# =============================================================================

@router.get("/predictions", summary="List traceable prediction records with filtering and pagination")
def list_predictions(
    horizon: Optional[str] = Query(default=None, description="Filter by horizon"),
    status: Optional[str] = Query(default=None, description="Filter by outcome status (CONFIRMED_COMPROMISE, FALSE_POSITIVE, etc.)"),
    asset_id: Optional[str] = Query(default=None, description="Filter by asset ID or name"),
    limit: int = Query(default=50, ge=1, le=500, description="Page limit"),
    offset: int = Query(default=0, ge=0, description="Page offset"),
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Retrieves paginated prediction records with full outcome traceability."""
    tracker = _get_tracker()
    h_str = horizon if isinstance(horizon, str) else None
    s_str = status if isinstance(status, str) else None
    a_str = asset_id if isinstance(asset_id, str) else None
    lim = limit if isinstance(limit, int) else 50
    off = offset if isinstance(offset, int) else 0

    items, total = tracker.list_predictions(
        horizon=h_str,
        status=s_str,
        asset_id=a_str,
        limit=lim,
        offset=off,
    )
    return {
        "total": total,
        "limit": lim,
        "offset": off,
        "predictions": [p.model_dump(mode="json") for p in items],
    }


@router.get("/predictions/{prediction_id}", summary="Get detailed record for an individual prediction", response_model=PredictionRecord)
def get_prediction_detail(
    prediction_id: str,
    current_user: UserRecord = Depends(require_viewer),
) -> PredictionRecord:
    """Retrieves granular details of a specific prediction including SHAP drivers, evidence IDs, and outcome notes."""
    tracker = _get_tracker()
    rec = tracker.get_prediction(prediction_id)
    if not rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Prediction record '{prediction_id}' not found.",
        )
    return rec


# =============================================================================
# 3. FEEDBACK INSIGHTS, THREAT QUALITY & SHAP ANALYSIS ENDPOINTS
# =============================================================================

@router.get("/feedback", summary="Get evidence-based adaptive feedback insights", response_model=AdaptiveFeedbackInsights)
def get_adaptive_feedback(
    current_user: UserRecord = Depends(require_viewer),
) -> AdaptiveFeedbackInsights:
    """Returns insights on repeated false positives, missed threat vectors, weak asset classes, and error drivers."""
    engine = _get_feedback_engine()
    return engine.generate_feedback_insights()


@router.get("/threat-quality", summary="Get threat intelligence evidence quality audit", response_model=ThreatIntelQualityMetrics)
def get_threat_intelligence_quality(
    current_user: UserRecord = Depends(require_viewer),
) -> ThreatIntelQualityMetrics:
    """Audits source confirmation rates, multi-source independence, and indicator reliability."""
    quality_engine = ThreatIntelligenceQualityEngine()
    return quality_engine.evaluate_quality()


@router.get("/shap-analysis", summary="Analyze relationship between SHAP attributions and evaluated outcomes")
def get_shap_outcome_analysis(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Examines which features drive true positive predictions vs systematic false alarms."""
    analyzer = ExplanationQualityAnalyzer(tracker=_get_tracker())
    return analyzer.analyze_explanation_quality()


# =============================================================================
# 4. MUTATING AUDIT & EVALUATION ACTIONS (ANALYST PRIVILEGES)
# =============================================================================

class EvaluateRequest(BaseModel):
    force_recompute: bool = Field(default=False, description="Re-evaluate already evaluated records")
    evaluation_time_override: Optional[datetime] = Field(default=None, description="Optional simulated evaluation timestamp")


@router.post("/evaluate", summary="Trigger temporal evaluation of eligible elapsed forecasts")
def trigger_temporal_evaluation(
    request: EvaluateRequest = EvaluateRequest(),
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Evaluates all registered predictions whose forecasting horizons have elapsed against real telemetry."""
    engine = _get_eval_engine()
    result = engine.evaluate_all_eligible_predictions(
        evaluation_time=request.evaluation_time_override,
        force_recompute=request.force_recompute,
    )
    return {
        "status": "COMPLETED",
        "result": result,
    }


@router.post("/sync-graph", summary="Synchronize evaluated outcomes into Neo4j Aura & GraphEngine")
def sync_outcomes_to_graph(
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Persists prediction outcome nodes and asset relationships into the graph store."""
    tracker = _get_tracker()
    synchronizer = AdaptiveGraphSynchronizer()
    records = tracker.get_all_predictions()
    return synchronizer.sync_outcomes_to_graph(records)


@router.post("/bootstrap", summary="Bootstrap benchmark predictions across scenario time intervals")
def bootstrap_benchmark_predictions(
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Generates and evaluates benchmark predictions using genuine historical alerts from the incident dataset."""
    engine = _get_eval_engine()
    res = engine.bootstrap_benchmark_evaluation()
    return {
        "status": "BOOTSTRAP_COMPLETE",
        "summary": res,
    }
