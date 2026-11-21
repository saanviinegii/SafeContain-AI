"""Pydantic models, Enums, and contracts for Phase 7.4 Adaptive Threat Intelligence & Predictive Feedback Loop."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PredictionOutcomeStatus(str, Enum):
    """Traceable evaluation outcome classification for individual forecasts."""
    CONFIRMED_COMPROMISE = "CONFIRMED_COMPROMISE"   # True Positive: Predicted threat confirmed by subsequent telemetry/incident
    FALSE_POSITIVE = "FALSE_POSITIVE"               # False Positive: Predicted threat but verified benign/healthy throughout window
    FALSE_NEGATIVE = "FALSE_NEGATIVE"               # False Negative: Predicted benign but actually suffered subsequent compromise
    CORRECT_NON_EVENT = "CORRECT_NON_EVENT"         # True Negative: Predicted benign and verified uncompromised
    PENDING_EVALUATION = "PENDING_EVALUATION"       # Horizon window has not yet elapsed (t_eval < t_pred + H)
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE" # Window elapsed, but telemetry is inconclusive
    EXPIRED_UNOBSERVED = "EXPIRED_UNOBSERVED"       # Window expired without sensor coverage / telemetry


class GroundTruthOutcome(str, Enum):
    """Empirical ground truth observed in telemetry or analyst findings."""
    COMPROMISED = "COMPROMISED"
    BENIGN = "BENIGN"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNOBSERVED = "UNOBSERVED"


class PredictionRecord(BaseModel):
    """Traceable forecast record capturing predictions, metadata, and subsequent evaluated outcomes."""
    prediction_id: str = Field(..., description="Unique deterministic prediction identifier")
    asset_id: str = Field(..., description="Target enterprise asset identifier")
    asset_name: str = Field(..., description="Human-readable asset label")
    asset_type: str = Field(default="SERVER", description="Asset category tier")
    prediction_timestamp: datetime = Field(..., description="Timestamp when prediction was issued (t_pred)")
    forecast_horizon: str = Field(..., description="Forecasting horizon identifier (NEAR_TERM, SHORT_TERM, MEDIUM_TERM)")
    horizon_hours: float = Field(..., gt=0.0, description="Duration of prediction window in hours (H)")
    horizon_end_timestamp: datetime = Field(..., description="Exact cutoff timestamp (t_pred + H) when horizon elapses")

    # Forecast values
    predicted_probability: float = Field(..., ge=0.0, le=1.0, description="Model output probability P(Y=1)")
    predicted_risk_score: float = Field(..., ge=0.0, le=100.0, description="Projected composite risk score")
    predicted_threat_class: str = Field(..., description="'At-Risk / Threat' or 'Healthy / Benign'")
    model_version: str = Field(default="v7.3.0_temporal_gradient_boost", description="Model version generating forecast")
    operating_threshold: float = Field(default=0.32, description="Calibrated decision threshold theta*")
    threshold_crossed: bool = Field(..., description="Whether predicted_probability >= operating_threshold")

    # Explainability & Topology context
    top_features: List[Dict[str, Any]] = Field(default_factory=list, description="Top SHAP feature drivers")
    propagation_depth: int = Field(default=0, ge=0, description="Lateral propagation hop depth")
    forecast_explanation: str = Field(default="", description="Explainable SOC briefing on projected trajectory")

    # Evaluated Outcome tracking
    outcome_status: PredictionOutcomeStatus = Field(
        default=PredictionOutcomeStatus.PENDING_EVALUATION,
        description="Outcome classification status",
    )
    outcome_evaluation_timestamp: Optional[datetime] = Field(default=None, description="Timestamp when outcome was evaluated")
    actual_outcome: Optional[str] = Field(default=None, description="Actual observed outcome (COMPROMISED, BENIGN, etc.)")
    outcome_source: Optional[str] = Field(default=None, description="Source of validation (SECURITY_ALERTS, EDR, ANALYST)")
    evidence_ids: List[str] = Field(default_factory=list, description="Observed alert or evidence IDs validating outcome")
    evaluation_notes: Optional[str] = Field(default=None, description="Analyst or engine evaluation rationale")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PredictivePerformanceMetrics(BaseModel):
    """Performance metrics calculated strictly from genuinely evaluated predictions."""
    horizon: str
    sample_size: int
    evaluated_count: int
    pending_count: int
    insufficient_evidence_count: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    false_positive_rate: Optional[float] = None
    false_negative_rate: Optional[float] = None
    accuracy: Optional[float] = None
    brier_score: Optional[float] = None
    confusion_matrix: List[List[int]] = Field(default_factory=lambda: [[0, 0], [0, 0]])
    operating_threshold: float = 0.32
    data_status: str = Field(default="VALID", description="'VALID', 'INSUFFICIENT_EVALUATED_DATA', or 'EMPTY'")
    calculated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class HorizonComparisonItem(BaseModel):
    """Per-horizon empirical performance comparative breakdown."""
    horizon: str
    horizon_hours: float
    sample_size: int
    evaluated_count: int
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    brier_score: Optional[float] = None
    status: str
    recommendation: str


class AssetTypePerformance(BaseModel):
    """Performance breakdown segmented by asset category."""
    asset_type: str
    total_predictions: int
    evaluated_count: int
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    false_positives: int = 0
    false_negatives: int = 0


class AdaptiveFeedbackInsights(BaseModel):
    """Evidence-based feedback insights identifying model strengths, weaknesses, and error drivers."""
    repeated_false_positives: List[Dict[str, Any]] = Field(default_factory=list)
    repeated_false_negatives: List[Dict[str, Any]] = Field(default_factory=list)
    weakest_horizon: Optional[str] = None
    strongest_horizon: Optional[str] = None
    weak_asset_types: List[str] = Field(default_factory=list)
    error_associated_features: List[Dict[str, Any]] = Field(default_factory=list)
    threat_indicator_insights: List[Dict[str, Any]] = Field(default_factory=list)
    recommended_policy_adjustments: List[str] = Field(default_factory=list)
    governance_note: str = Field(
        default="Feedback layer is non-autonomous: operational containment policies and thresholds require human analyst authorization.",
    )
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ThreatIntelQualityMetrics(BaseModel):
    """Evaluates threat indicator reliability, source confirmation, and independence."""
    total_evaluated_indicators: int
    source_reliability: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    multi_source_independence_rate: float = 0.0
    freshness_distribution: Dict[str, int] = Field(default_factory=dict)
    top_validated_indicators: List[Dict[str, Any]] = Field(default_factory=list)
    noisy_indicators: List[Dict[str, Any]] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ModelReliabilityReport(BaseModel):
    """Tracks predictive model reliability, calibration stability, and challenger governance."""
    champion_version: str = "v7.3.0_temporal_gradient_boost"
    evaluated_predictions_count: int = 0
    historical_accuracy_trend: List[Dict[str, Any]] = Field(default_factory=list)
    calibration_drift_detected: bool = False
    calibration_drift_score: float = 0.0
    challenger_comparison: Optional[Dict[str, Any]] = None
    governance_status: str = "CHAMPION_ACTIVE"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AdaptiveSummary(BaseModel):
    """Executive operational overview combining tracking, performance, feedback, and data quality."""
    total_predictions: int
    evaluated_predictions: int
    pending_predictions: int
    insufficient_evidence_predictions: int
    overall_precision: Optional[float] = None
    overall_recall: Optional[float] = None
    overall_f1: Optional[float] = None
    overall_brier_score: Optional[float] = None
    operating_threshold: float = 0.32
    data_quality_status: str = "SUFFICIENT"
    data_quality_notes: str = ""
    latest_evaluated_at: Optional[datetime] = None
    active_model_version: str = "v7.3.0_temporal_gradient_boost"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
