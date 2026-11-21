"""Domain models, Pydantic schemas, and Enums for Phase 7.3 Temporal Threat Forecasting Engine."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ForecastHorizon(str, Enum):
    """Supported temporal forecasting horizons."""
    NEAR_TERM = "NEAR_TERM"       # +1h to +3h (default: 2 hours)
    SHORT_TERM = "SHORT_TERM"     # +4h to +8h (default: 6 hours)
    MEDIUM_TERM = "MEDIUM_TERM"   # +12h to +24h (default: 18 hours)
    CUSTOM = "CUSTOM"             # Configurable window


class RiskTrend(str, Enum):
    """Qualitative threat acceleration trajectory."""
    ACCELERATING = "ACCELERATING"   # Delta >= +0.15: Rapidly increasing breach likelihood
    ELEVATED = "ELEVATED"           # Delta in [+0.05, +0.15): Moderately increasing risk
    STABLE = "STABLE"               # Delta in [-0.05, +0.05): Stationary risk posture
    DECLINING = "DECLINING"         # Delta < -0.05: Attenuating risk or contained vector


class ForecastFeatureContribution(BaseModel):
    """SHAP or feature importance contribution for an individual forecast."""
    feature_name: str = Field(..., description="Name of the temporal or graph feature")
    feature_value: float = Field(..., description="Observed feature value")
    contribution_score: float = Field(..., description="SHAP attribution value or weight")
    direction: str = Field(..., description="'INCREASES_RISK' or 'DECREASES_RISK'")
    description: str = Field(..., description="Human-readable explanation of feature impact")


class PropagationHop(BaseModel):
    """A directed hop along a graph risk propagation vector."""
    source_node_id: str
    target_node_id: str
    relationship_type: str
    propagation_factor: float = Field(..., ge=0.0, le=1.0, description="Attenuation/transmission factor")
    hop_distance: int = Field(..., ge=1, description="Topological distance from primary breach")
    evidence_context: str = Field(default="", description="Contextual evidence or vulnerability link")


class AssetRiskForecast(BaseModel):
    """Comprehensive predictive threat forecast for an individual enterprise asset."""
    asset_id: str = Field(..., description="Graph node identifier")
    asset_name: str = Field(..., description="Human-readable asset label")
    asset_type: str = Field(default="SERVER", description="Node type category")
    criticality: float = Field(..., ge=0.0, le=1.0, description="Base asset business criticality")
    is_crown_jewel: bool = Field(default=False, description="Whether asset is designated crown jewel")

    # Current vs Future Risk Metrics
    current_risk_score: float = Field(..., ge=0.0, le=100.0, description="Current inherent risk score")
    current_ml_probability: float = Field(..., ge=0.0, le=1.0, description="Current baseline ML probability P(Y=1)")
    forecast_horizon: ForecastHorizon = Field(..., description="Selected forecast horizon")
    forecast_window_hours: float = Field(..., gt=0.0, description="Horizon duration in hours")
    predicted_future_probability: float = Field(..., ge=0.0, le=1.0, description="Projected future compromise probability P_future")
    predicted_future_risk: float = Field(..., ge=0.0, le=100.0, description="Projected future composite risk score")

    # Trajectory & Trend
    risk_trend: RiskTrend = Field(..., description="Qualitative trajectory")
    risk_delta: float = Field(..., description="P_future - P_current difference")
    prediction_confidence: float = Field(default=0.85, ge=0.0, le=1.0, description="Statistical prediction confidence")

    # Explainability & Graph Attribution
    top_contributing_features: List[ForecastFeatureContribution] = Field(default_factory=list)
    propagation_hops: List[PropagationHop] = Field(default_factory=list)
    forecast_explanation: str = Field(..., description="Explainable SOC briefing on projected risk")
    upstream_breach_nodes: List[str] = Field(default_factory=list, description="Nodes driving upstream threat")

    # Metadata & Provenance
    model_version: str = Field(default="v7.3.0_temporal_gradient_boost", description="Model version tag")
    prediction_timestamp: datetime = Field(..., description="UTC timestamp of forecast generation")
    prediction_id: Optional[str] = Field(default=None, description="Unique deterministic identifier for Phase 7.4 adaptive tracking")


class ForecastingSummary(BaseModel):
    """High-level operational overview across all enterprise asset forecasts."""
    total_assets_evaluated: int
    horizon: ForecastHorizon
    horizon_hours: float
    high_risk_forecast_count: int = Field(..., description="Assets exceeding operating threshold theta*")
    accelerating_assets_count: int = Field(..., description="Assets with RiskTrend.ACCELERATING")
    top_projected_targets: List[str] = Field(default_factory=list, description="Asset IDs facing highest forecast risk")
    crown_jewels_at_risk_projected: List[str] = Field(default_factory=list, description="Crown jewels with elevated forecast")
    mean_forecast_probability: float = Field(..., ge=0.0, le=1.0)
    model_version: str
    model_type: str
    operating_threshold: float = Field(default=0.32, description="Calibrated operating threshold")
    generated_at: datetime


class ForecastingEvaluationResult(BaseModel):
    """Empirical evaluation metrics comparing the forecasting model against baseline."""
    model_name: str
    baseline_name: str
    horizon: ForecastHorizon
    test_samples: int
    roc_auc: float
    brier_score: float
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    baseline_roc_auc: float
    baseline_brier_score: float
    baseline_accuracy: float
    relative_improvement_roc_auc: float
    evaluation_notes: str
    evaluated_at: datetime
