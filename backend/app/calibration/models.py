"""Data models, Enums, and contracts for Phase 7.5 Adaptive Risk Calibration & Intelligent Threshold Optimization."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# =============================================================================
# 1. CALIBRATION MODELS & ENUMS
# =============================================================================

class CalibrationStatus(str, Enum):
    """Overall status rating for empirical risk score calibration."""
    CALIBRATED = "CALIBRATED"                           # ECE < 0.08: Risk scores closely match empirical frequencies
    SLIGHTLY_MISCALIBRATED = "SLIGHTLY_MISCALIBRATED"   # ECE in [0.08, 0.18): Minor over/underprediction
    SEVERELY_MISCALIBRATED = "SEVERELY_MISCALIBRATED"   # ECE >= 0.18: Significant deviation from reality
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"             # N < 10: Insufficient observations to evaluate reliably


class ReliabilityBin(BaseModel):
    """Calibration bin comparing mean forecast probability against empirical threat rate."""
    bin_index: int = Field(..., description="0-indexed bin identifier (e.g. 0 to 4 for 5 bins)")
    bin_range_low: float = Field(..., ge=0.0, le=1.0, description="Lower probability boundary")
    bin_range_high: float = Field(..., ge=0.0, le=1.0, description="Upper probability boundary")
    sample_count: int = Field(default=0, ge=0, description="Number of evaluated forecasts in bin")
    mean_predicted_probability: Optional[float] = Field(default=None, description="Average forecast probability in bin")
    empirical_threat_rate: Optional[float] = Field(default=None, description="Observed threat compromise frequency in bin")
    calibration_error: Optional[float] = Field(default=None, description="|mean_pred - empirical_rate|")
    bin_status: str = Field(default="CALIBRATED", description="'CALIBRATED', 'OVERPREDICTING', 'UNDERPREDICTING', or 'EMPTY'")


class CategoryCalibrationBreakdown(BaseModel):
    """Segmented calibration performance across an asset category or horizon."""
    category_name: str
    sample_size: int
    brier_score: Optional[float] = None
    expected_calibration_error: Optional[float] = None
    overprediction_rate: Optional[float] = None
    underprediction_rate: Optional[float] = None
    calibration_status: CalibrationStatus
    confidence: str


class RiskScoreCalibrationReport(BaseModel):
    """Comprehensive empirical calibration report evaluating risk scores against observed telemetry."""
    calibration_status: CalibrationStatus
    expected_calibration_error: Optional[float] = Field(default=None, description="ECE across 5 probability bins")
    brier_score: Optional[float] = Field(default=None, description="Mean squared prediction error")
    overprediction_rate: Optional[float] = Field(default=None, description="Proportion of bins where prediction exceeds actual by > 0.10")
    underprediction_rate: Optional[float] = Field(default=None, description="Proportion of bins where actual exceeds prediction by > 0.10")
    calibration_quality_score: Optional[float] = Field(default=None, ge=0.0, le=100.0, description="100 * (1 - ECE)")
    sample_size: int = Field(default=0, ge=0)
    evaluated_threats_count: int = Field(default=0, ge=0)
    evaluated_benign_count: int = Field(default=0, ge=0)
    time_window_start: Optional[datetime] = None
    time_window_end: Optional[datetime] = None
    reliability_bins: List[ReliabilityBin] = Field(default_factory=list)
    asset_type_breakdowns: List[CategoryCalibrationBreakdown] = Field(default_factory=list)
    horizon_breakdowns: List[CategoryCalibrationBreakdown] = Field(default_factory=list)
    confidence: str = Field(default="MEDIUM", description="'HIGH', 'MEDIUM', 'LOW', or 'INSUFFICIENT_DATA'")
    data_source: str = Field(default="PHASE_7_4_EVALUATED_TELEMETRY")
    limitations: List[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# 2. THRESHOLD OPTIMIZATION & CONFIGURATION MODELS
# =============================================================================

class ConfigurationStatus(str, Enum):
    """Lifecycle status of a risk threshold configuration."""
    ACTIVE = "ACTIVE"                       # Currently governing live threat detection
    PENDING_APPROVAL = "PENDING_APPROVAL"   # Generated candidate awaiting analyst sign-off
    APPROVED = "APPROVED"                   # Approved by analyst, ready for admin activation
    REJECTED = "REJECTED"                   # Rejected by SOC analyst or administrator
    SUPERSEDED = "SUPERSEDED"               # Previously active, replaced by newer configuration
    ROLLED_BACK = "ROLLED_BACK"             # Reactivated via rollback action


class ThresholdTiers(BaseModel):
    """Categorical risk tier boundaries (Low, Medium, High, Critical)."""
    low_cutoff: float = Field(default=0.0, ge=0.0, le=1.0)
    medium_cutoff: float = Field(default=0.20, ge=0.0, le=1.0)
    high_cutoff: float = Field(default=0.32, ge=0.0, le=1.0)
    critical_cutoff: float = Field(default=0.70, ge=0.0, le=1.0)


class ThresholdConfiguration(BaseModel):
    """Versioned threshold configuration with governance provenance and audit trail."""
    config_id: str = Field(..., description="Unique configuration identifier (e.g. cfg-v1.0.0-baseline)")
    version: str = Field(..., description="Semantic version string (e.g. 1.0.0)")
    operating_threshold: float = Field(..., ge=0.05, le=0.95, description="Primary binary decision threshold theta*")
    tiers: ThresholdTiers = Field(default_factory=ThresholdTiers)
    status: ConfigurationStatus = Field(default=ConfigurationStatus.PENDING_APPROVAL)
    author_id: str = Field(default="system")
    author_role: str = Field(default="ANALYST")
    rationale: str = Field(default="")
    supporting_evidence: Dict[str, Any] = Field(default_factory=dict)
    parent_version: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    activated_by: Optional[str] = None
    activated_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CandidateOptimizationResult(BaseModel):
    """Result of threshold optimization scan across candidate thresholds."""
    status: str = Field(default="CANDIDATE_GENERATED", description="'CANDIDATE_GENERATED', 'NO_CHANGE_RECOMMENDED', or 'INSUFFICIENT_DATA'")
    baseline_threshold: float = Field(default=0.32)
    recommended_threshold: float = Field(default=0.32)
    optimization_objective: str = Field(default="Recall-Constrained Cost Optimal (FN:10x, FP:1x, Crit:25x)")
    minimum_recall_constraint: float = Field(default=0.90)
    critical_threat_weakened: bool = Field(default=False)
    candidate_configuration: ThresholdConfiguration
    baseline_metrics: Dict[str, Any]
    candidate_metrics: Dict[str, Any]
    tradeoffs: Dict[str, Any]
    confidence: str
    rationale: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# 3. SHADOW THRESHOLD EVALUATION MODELS
# =============================================================================

class AssetClassificationFlip(BaseModel):
    """Specific enterprise asset whose classification status differs between baseline and candidate."""
    asset_id: str
    asset_name: str
    asset_type: str
    is_crown_jewel: bool
    predicted_probability: float
    baseline_classification: str     # 'THREAT' or 'BENIGN'
    candidate_classification: str    # 'THREAT' or 'BENIGN'
    actual_outcome: str              # 'COMPROMISED' or 'BENIGN'
    impact_description: str


class ShadowEvaluationResult(BaseModel):
    """Parallel comparative evaluation between active production baseline and shadow candidate."""
    evaluation_id: str
    baseline_config_id: str
    candidate_config_id: str
    evaluated_sample_size: int
    baseline_threshold: float
    candidate_threshold: float
    
    # Volume differences
    baseline_alert_count: int
    candidate_alert_count: int
    alert_volume_delta: int
    alert_volume_percent_change: float

    # Error differences
    baseline_false_positives: int
    candidate_false_positives: int
    false_positive_delta: int
    
    baseline_false_negatives: int
    candidate_false_negatives: int
    false_negative_delta: int

    # Core performance metrics
    baseline_precision: Optional[float]
    candidate_precision: Optional[float]
    baseline_recall: Optional[float]
    candidate_recall: Optional[float]
    baseline_f1: Optional[float]
    candidate_f1: Optional[float]

    # Safety checks
    critical_threats_retained: bool
    critical_threat_miss_count: int
    classification_flips_count: int
    flipped_assets: List[AssetClassificationFlip] = Field(default_factory=list)

    tradeoff_summary: str
    recommendation: str
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# 4. ALERT FATIGUE & NOISY ASSET ANALYTICS
# =============================================================================

class NoisyAssetItem(BaseModel):
    """Asset exhibiting high alert volume with low confirmed threat conversion."""
    asset_id: str
    asset_name: str
    asset_type: str
    total_alerts: int
    false_positive_count: int
    confirmed_breach_count: int
    false_alarm_rate: float
    primary_alert_driver: str
    recommended_mitigation: str


class AlertFatigueAnalytics(BaseModel):
    """SOC alert quality, concentration, and fatigue assessment."""
    total_alerts_analyzed: int
    mean_alerts_per_asset: float
    max_alerts_single_asset: int
    gini_alert_concentration: float = Field(..., ge=0.0, le=1.0, description="0 = evenly spread, 1 = concentrated on single node")
    alert_fatigue_index: float = Field(..., ge=0.0, le=100.0, description="Composite fatigue burden score")
    total_false_positives: int
    total_confirmed_threats: int
    overall_false_alarm_ratio: float
    noisy_assets: List[NoisyAssetItem] = Field(default_factory=list)
    severity_distribution: Dict[str, int] = Field(default_factory=dict)
    fatigue_status: str = Field(default="MODERATE", description="'LOW', 'MODERATE', 'ELEVATED', or 'CRITICAL'")
    governance_advisory: str
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# 5. TELEMETRY & RISK DRIFT MODELS
# =============================================================================

class FeatureDriftItem(BaseModel):
    """Feature-level distribution shift measurement using Population Stability Index."""
    feature_name: str
    psi_score: float = Field(..., ge=0.0, description="Population Stability Index")
    ks_statistic: Optional[float] = None
    drift_status: str = Field(description="'STABLE', 'MODERATE_DRIFT', or 'SIGNIFICANT_DRIFT'")
    baseline_mean: float
    current_mean: float
    delta_percent: float


class TelemetryDriftReport(BaseModel):
    """Evaluates telemetry feature stability, risk score distribution shifts, and sensor gaps."""
    drift_detected: bool
    overall_drift_severity: str = Field(default="STABLE", description="'STABLE', 'MODERATE', or 'CRITICAL'")
    risk_score_wasserstein_distance: float
    calibration_degradation_detected: bool
    baseline_brier_score: Optional[float]
    current_brier_score: Optional[float]
    sensor_coverage_gap_count: int
    evaluated_sample_size: int
    feature_drift_breakdown: List[FeatureDriftItem] = Field(default_factory=list)
    confidence: str
    baseline_window: str
    current_window: str
    explanation: str
    recommended_action: str
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# 6. ADAPTIVE RECOMMENDATIONS MODELS
# =============================================================================

class RecommendationCategory(str, Enum):
    THRESHOLD_OPTIMIZATION = "THRESHOLD_OPTIMIZATION"
    CALIBRATION_WARNING = "CALIBRATION_WARNING"
    ALERT_FATIGUE_MITIGATION = "ALERT_FATIGUE_MITIGATION"
    TELEMETRY_DRIFT_ALERT = "TELEMETRY_DRIFT_ALERT"
    DATA_QUALITY_WARNING = "DATA_QUALITY_WARNING"
    NOMINAL_OPERATION = "NOMINAL_OPERATION"


class AdaptiveRecommendation(BaseModel):
    """Explainable, evidence-grounded governance recommendation for SOC leadership."""
    recommendation_id: str
    title: str
    category: RecommendationCategory
    severity: str = Field(default="MEDIUM", description="'INFO', 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL'")
    explanation: str
    supporting_evidence: Dict[str, Any]
    sample_size: int
    confidence_level: str = Field(default="MEDIUM", description="'HIGH', 'MEDIUM', or 'LOW'")
    proposed_change: str
    expected_benefit: str
    potential_risk: str
    alternative_options: List[str] = Field(default_factory=list)
    required_approval_role: str = Field(default="ANALYST", description="'ANALYST' or 'ADMIN'")
    status: str = Field(default="PENDING_REVIEW")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
