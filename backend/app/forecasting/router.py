"""FastAPI REST API Router for Phase 7.3 Temporal Threat Propagation Forecasting.

Exposes endpoints for asset forecasts, horizon selection, graph risk propagation,
empirical baseline evaluation, and on-demand predictive recalculation with JWT RBAC enforcement.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.app.forecasting.forecaster import TemporalThreatForecaster
from backend.app.forecasting.models import (
    AssetRiskForecast,
    ForecastHorizon,
    ForecastingEvaluationResult,
    ForecastingSummary,
    RiskTrend,
)
from backend.app.security.auth import require_analyst, require_viewer
from backend.app.security.user_store import UserRecord

router = APIRouter(prefix="/forecast", tags=["Predictive Threat Forecasting (Phase 7.3)"])


def _parse_horizon(horizon_str: Optional[str]) -> ForecastHorizon:
    if not horizon_str:
        return ForecastHorizon.SHORT_TERM
    h_upper = horizon_str.upper().strip()
    try:
        return ForecastHorizon(h_upper)
    except ValueError:
        return ForecastHorizon.SHORT_TERM


@router.get("/summary", summary="Get executive forecasting summary metrics", response_model=ForecastingSummary)
def get_forecasting_summary(
    horizon: Optional[str] = Query(default="SHORT_TERM", description="Forecast horizon (NEAR_TERM, SHORT_TERM, MEDIUM_TERM)"),
    current_user: UserRecord = Depends(require_viewer),
) -> ForecastingSummary:
    """Returns high-level KPI overview across all enterprise asset threat forecasts."""
    h = _parse_horizon(horizon)
    forecaster = TemporalThreatForecaster.get_instance()
    return forecaster.get_forecasting_summary(horizon=h)


@router.get("/assets", summary="List predictive forecasts across enterprise assets", response_model=List[AssetRiskForecast])
def list_asset_forecasts(
    horizon: Optional[str] = Query(default="SHORT_TERM", description="Forecast horizon"),
    trend: Optional[str] = Query(default=None, description="Filter by RiskTrend (ACCELERATING, ELEVATED, STABLE, DECLINING)"),
    crown_jewels_only: bool = Query(default=False, description="Filter for crown jewels only"),
    min_probability: Optional[float] = Query(default=None, ge=0.0, le=1.0, description="Minimum future compromise probability"),
    current_user: UserRecord = Depends(require_viewer),
) -> List[AssetRiskForecast]:
    """Retrieves ranked asset risk forecasts for the chosen temporal horizon."""
    h = _parse_horizon(horizon)
    forecaster = TemporalThreatForecaster.get_instance()
    forecasts = forecaster.forecast_all_assets(horizon=h)

    # Filtering
    if trend is not None and isinstance(trend, str):
        t_upper = trend.upper().strip()
        forecasts = [f for f in forecasts if f.risk_trend.value == t_upper]

    if isinstance(crown_jewels_only, bool) and crown_jewels_only:
        forecasts = [f for f in forecasts if f.is_crown_jewel]

    if min_probability is not None and isinstance(min_probability, (int, float)):
        forecasts = [f for f in forecasts if f.predicted_future_probability >= min_probability]

    return forecasts


@router.get("/assets/{asset_id}", summary="Get detailed forecast for a specific asset", response_model=AssetRiskForecast)
def get_asset_forecast_detail(
    asset_id: str,
    horizon: Optional[str] = Query(default="SHORT_TERM", description="Forecast horizon"),
    current_user: UserRecord = Depends(require_viewer),
) -> AssetRiskForecast:
    """Retrieves detailed forecast for an individual asset with SHAP attribution and propagation hops."""
    h = _parse_horizon(horizon)
    forecaster = TemporalThreatForecaster.get_instance()
    forecast = forecaster.get_asset_forecast(asset_id=asset_id, horizon=h)
    if not forecast:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{asset_id}' not found in enterprise topology.",
        )
    return forecast


@router.get("/propagation", summary="Analyze graph risk propagation and downstream exposure")
def get_graph_propagation_analysis(
    horizon: Optional[str] = Query(default="SHORT_TERM", description="Forecast horizon"),
    cutoff_threshold: float = Query(default=0.35, ge=0.1, le=0.9, description="Minimum propagation exposure factor"),
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Identifies exposed downstream assets and multi-hop lateral contagion vectors."""
    h = _parse_horizon(horizon)
    forecaster = TemporalThreatForecaster.get_instance()
    return forecaster.get_propagation_analysis(horizon=h, cutoff_threshold=cutoff_threshold)


@router.get("/horizons", summary="Get supported forecasting horizons and parameters")
def get_forecasting_horizons(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns metadata describing supported temporal horizons and sliding windows."""
    return {
        "supported_horizons": [
            {
                "id": ForecastHorizon.NEAR_TERM.value,
                "label": "Near-Term (+2h)",
                "hours": 2.0,
                "description": "Immediate tactical threat window for rapid response and containment.",
            },
            {
                "id": ForecastHorizon.SHORT_TERM.value,
                "label": "Short-Term (+6h)",
                "hours": 6.0,
                "description": "Operational shift window capturing multi-hop lateral propagation.",
            },
            {
                "id": ForecastHorizon.MEDIUM_TERM.value,
                "label": "Medium-Term (+18h)",
                "hours": 18.0,
                "description": "Extended campaign window projecting secondary persistence and exfiltration.",
            },
        ],
        "default_horizon": ForecastHorizon.SHORT_TERM.value,
        "operating_threshold": 0.32,
    }


@router.get("/evaluate", summary="Evaluate forecasting model against baseline", response_model=ForecastingEvaluationResult)
def evaluate_forecast_model(
    horizon: Optional[str] = Query(default="SHORT_TERM", description="Forecast horizon to evaluate"),
    force_refresh: bool = Query(default=False, description="Re-run cross-validation audit"),
    current_user: UserRecord = Depends(require_viewer),
) -> ForecastingEvaluationResult:
    """Evaluates the temporal forecasting model against static persistence baseline with 5-fold cross validation."""
    h = _parse_horizon(horizon)
    forecaster = TemporalThreatForecaster.get_instance()
    return forecaster.evaluate_against_baseline(horizon=h, force_refresh=force_refresh)


@router.post("/recalculate", summary="Trigger on-demand forecast recalculation", response_model=ForecastingSummary)
def recalculate_forecasts(
    horizon: Optional[str] = Query(default="SHORT_TERM", description="Forecast horizon to recalculate"),
    current_user: UserRecord = Depends(require_analyst),
) -> ForecastingSummary:
    """Forces cache invalidation, model re-training, and full forecast re-computation across all assets."""
    h = _parse_horizon(horizon)
    forecaster = TemporalThreatForecaster.get_instance()
    forecaster.forecast_all_assets(horizon=h, force_refresh=True)
    return forecaster.get_forecasting_summary(horizon=h)


class PredictivePlanRequest(BaseModel):
    horizon: str = Field(default="SHORT_TERM", description="Forecast horizon to use")
    budget_limit: float = Field(default=10000.0, ge=0.0, description="Hard containment budget limit in USD")
    predictive_weight: float = Field(default=0.5, ge=0.0, le=2.0, description="Weight multiplier for future threat probabilities")
    threshold_override: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Optional override for operating decision threshold")


@router.post("/plan", summary="Generate predictive CP-SAT containment plan")
def generate_predictive_plan(
    request: PredictivePlanRequest,
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Generates an optimal CP-SAT containment plan incorporating future threat propagation probabilities."""
    from backend.app.api.v1.router import platform_ctx
    from backend.app.optimization.solver import CPSATOptimizer
    from backend.app.planning.catalog import ActionCatalog

    h = _parse_horizon(request.horizon)
    forecaster = TemporalThreatForecaster.get_instance()
    forecasts = forecaster.forecast_all_assets(horizon=h)
    predictive_probs = {f.asset_id: f.predicted_future_probability for f in forecasts}

    if len(platform_ctx.engine.get_all_nodes()) == 0:
        from backend.app.ingestion.connectors import SyntheticScenarioGenerator
        scenario = SyntheticScenarioGenerator.generate_national_gateway_scenario()
        for node in scenario.nodes:
            platform_ctx.engine.add_node(node)
        for edge in scenario.edges:
            platform_ctx.engine.add_edge(edge)
        platform_ctx.twin.discover_dependencies_from_graph(platform_ctx.engine)

    paths = platform_ctx.engine.find_attack_paths()
    nodes = {n.id: n for n in platform_ctx.engine.get_all_nodes()}
    candidates = ActionCatalog.generate_candidate_actions(paths, nodes)

    plan = CPSATOptimizer.plan(
        candidate_actions=candidates,
        twin=platform_ctx.twin,
        engine=platform_ctx.engine,
        budget_limit=request.budget_limit,
        operating_threshold=request.threshold_override,
        predictive_probabilities=predictive_probs,
        predictive_weight=request.predictive_weight,
        forecast_horizon=h.value,
    )

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
        "status": "SUCCESS",
        "plan": plan.model_dump(mode="json"),
        "predictive_weight": request.predictive_weight,
        "forecast_horizon": h.value,
    }
