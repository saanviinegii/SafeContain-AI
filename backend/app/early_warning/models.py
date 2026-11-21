"""Domain models, Pydantic schemas, and Enums for Phase 7.6 Predictive Threat Intelligence & Early-Warning Engine."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# =============================================================================
# ENUMS
# =============================================================================

class ThreatSeverity(str, Enum):
    """Standardized multi-level threat severity."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SignalType(str, Enum):
    """Extracted behavioral and anomaly signal categories."""
    RAPID_RISK_INCREASE = "RAPID_RISK_INCREASE"
    DEVIATION_FROM_BASELINE = "DEVIATION_FROM_BASELINE"
    REPEATED_SUSPICIOUS_EVENTS = "REPEATED_SUSPICIOUS_EVENTS"
    ABNORMAL_TELEMETRY_BEHAVIOR = "ABNORMAL_TELEMETRY_BEHAVIOR"
    UNUSUAL_EVENT_FREQUENCY = "UNUSUAL_EVENT_FREQUENCY"
    REPEATED_ANOMALY_PATTERNS = "REPEATED_ANOMALY_PATTERNS"
    RISK_SPIKE = "RISK_SPIKE"
    PERSISTENT_SUSPICIOUS_ACTIVITY = "PERSISTENT_SUSPICIOUS_ACTIVITY"
    SEVERITY_ESCALATION = "SEVERITY_ESCALATION"
    VULNERABILITY_EXPOSURE_SURGE = "VULNERABILITY_EXPOSURE_SURGE"


class TrajectoryDirection(str, Enum):
    """Qualitative direction of risk movement over time."""
    RISING = "RISING"
    FALLING = "FALLING"
    STABLE = "STABLE"
    VOLATILE = "VOLATILE"


class DataSufficiency(str, Enum):
    """Status rating for analytical sufficiency of historical telemetry."""
    SUFFICIENT = "SUFFICIENT"       # >= 3 observations: full trajectory math supported
    SPARSE = "SPARSE"               # 2 observations: minimal slope, volatility suppressed
    INSUFFICIENT = "INSUFFICIENT"   # 1 observation: point observation only
    NO_DATA = "NO_DATA"             # 0 observations


class EscalationState(str, Enum):
    """Predictive threat escalation posture."""
    STABLE = "STABLE"
    WATCH = "WATCH"
    ESCALATING = "ESCALATING"
    HIGH_ESCALATION_RISK = "HIGH_ESCALATION_RISK"
    CRITICAL_ESCALATION_RISK = "CRITICAL_ESCALATION_RISK"


class WarningCategory(str, Enum):
    """Taxonomy of evidence-grounded early warnings."""
    RISK_TREND_WARNING = "Risk Trend Warning"
    RAPID_ESCALATION_WARNING = "Rapid Escalation Warning"
    REPEATED_SUSPICIOUS_ACTIVITY_WARNING = "Repeated Suspicious Activity Warning"
    CORRELATED_THREAT_WARNING = "Correlated Threat Warning"
    DEPENDENCY_RISK_WARNING = "Dependency Risk Warning"
    POTENTIAL_THREAT_CLUSTER_WARNING = "Potential Threat Cluster Warning"
    CRITICAL_ESCALATION_WARNING = "Critical Escalation Warning"


class WarningStatus(str, Enum):
    """Operational lifecycle status of early warnings."""
    ACTIVE = "ACTIVE"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    SUPPRESSED_COOLDOWN = "SUPPRESSED_COOLDOWN"
    RESOLVED = "RESOLVED"
    EXPIRED = "EXPIRED"


# =============================================================================
# WAVE 1: CORE PREDICTIVE MODELS
# =============================================================================

class ThreatSignal(BaseModel):
    """Evidence-based anomaly or telemetry signal extracted from observed events."""
    model_config = ConfigDict(extra="ignore")

    signal_id: str = Field(description="Unique deterministic signal identifier")
    asset_id: str = Field(description="Target enterprise asset node identifier")
    signal_type: SignalType = Field(description="Signal classification category")
    severity: ThreatSeverity = Field(default=ThreatSeverity.MEDIUM)
    observed_value: float = Field(description="Measured numerical observation")
    baseline_value: Optional[float] = Field(default=None, description="Normal baseline reference")
    deviation: Optional[float] = Field(default=None, description="Calculated deviation from baseline")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = Field(default="Telemetry_Engine", description="Source sensor or detection system")
    evidence: str = Field(description="Human-readable forensic observation explanation")
    confidence: float = Field(default=0.85, ge=0.0, le=1.0, description="Verification confidence")
    related_entities: List[str] = Field(default_factory=list, description="Related nodes, CVEs, or alert IDs")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RiskTrajectoryPoint(BaseModel):
    """Discrete historical risk measurement point."""
    model_config = ConfigDict(extra="ignore")

    timestamp: Optional[datetime] = None
    risk_score: Optional[float] = None
    source: str = Field(default="ML_RISK_SCORE")


class RiskTrajectory(BaseModel):
    """Mathematical trajectory analysis across historical risk observations."""
    model_config = ConfigDict(extra="ignore")

    asset_id: str
    current_risk: float = Field(ge=0.0, le=100.0, description="Most recent measured risk score")
    historical_values: List[RiskTrajectoryPoint] = Field(default_factory=list)
    trend_direction: TrajectoryDirection = Field(default=TrajectoryDirection.STABLE)
    slope: float = Field(default=0.0, description="Risk velocity dR/dt (points per hour)")
    acceleration: float = Field(default=0.0, description="Risk acceleration d2R/dt2 (points per hour^2)")
    volatility: float = Field(default=0.0, ge=0.0, description="Sample standard deviation of risk changes")
    moving_average: float = Field(default=0.0, ge=0.0, le=100.0, description="Rolling window arithmetic mean")
    ema: float = Field(default=0.0, ge=0.0, le=100.0, description="Exponential moving average")
    change_point_detected: bool = Field(default=False, description="Whether CUSUM change-point break was triggered")
    change_point_description: Optional[str] = Field(default=None)
    data_sufficiency: DataSufficiency = Field(default=DataSufficiency.INSUFFICIENT)
    forecast_horizon_hours: float = Field(default=6.0, gt=0.0, description="Forecast window in hours")
    projected_risk: float = Field(default=0.0, ge=0.0, le=100.0, description="Bounded projected risk score")
    projection_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notes: str = Field(default="")


class EscalationPrediction(BaseModel):
    """Evidence-grounded threat escalation state prediction."""
    model_config = ConfigDict(extra="ignore")

    prediction_id: str = Field(description="Unique deterministic prediction identifier")
    asset_id: str
    asset_name: str = Field(default="")
    is_crown_jewel: bool = Field(default=False)
    criticality: float = Field(default=0.5, ge=0.0, le=1.0)
    current_state: EscalationState = Field(default=EscalationState.STABLE)
    predicted_state: EscalationState = Field(default=EscalationState.STABLE)
    escalation_risk_score: float = Field(ge=0.0, le=100.0, description="Composite threat escalation score")
    escalation_probability: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Only set if statistically justified")
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    contributing_signals: List[ThreatSignal] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    prediction_horizon_hours: float = Field(default=6.0, gt=0.0)
    data_sufficiency: DataSufficiency = Field(default=DataSufficiency.SUFFICIENT)
    recommended_investigation_actions: List[str] = Field(default_factory=list)
    is_critical_threat_protected: bool = Field(default=False, description="True if invariant prevented downgrade")
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# WAVE 2: GRAPH CORRELATION, EARLY WARNINGS & INVESTIGATION MODELS
# =============================================================================

class CorrelatedThreatCluster(BaseModel):
    """Cluster of threat signals and assets linked through graph relationships."""
    model_config = ConfigDict(extra="ignore")

    cluster_id: str
    cluster_name: str
    primary_pattern: str
    severity: ThreatSeverity
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    related_asset_ids: List[str] = Field(default_factory=list)
    crown_jewels_at_risk: List[str] = Field(default_factory=list)
    signals: List[ThreatSignal] = Field(default_factory=list)
    attack_path_ids: List[str] = Field(default_factory=list)
    graph_evidence: List[str] = Field(default_factory=list)
    recommended_containment_posture: str = Field(default="")
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EarlyWarning(BaseModel):
    """Prioritized early warning directive generated prior to critical breach escalation."""
    model_config = ConfigDict(extra="ignore")

    warning_id: str
    asset_id: str
    affected_entities: List[str] = Field(default_factory=list)
    warning_type: WarningCategory
    severity: ThreatSeverity
    priority_score: float = Field(ge=0.0, le=100.0, description="Explainable prioritization rank")
    status: WarningStatus = Field(default=WarningStatus.ACTIVE)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    cooldown_until: Optional[datetime] = None
    observed_evidence: List[str] = Field(default_factory=list)
    historical_context: str = Field(default="")
    explanation: str
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    predicted_impact: str
    recommended_action: str
    contributing_signal_ids: List[str] = Field(default_factory=list)
    trajectory_summary: Optional[Dict[str, Any]] = None


class InvestigationContext(BaseModel):
    """Structured forensic investigation dossier supporting SOC triage."""
    model_config = ConfigDict(extra="ignore")

    investigation_id: str
    warning_id: str
    asset_id: str
    asset_name: str
    what_happened: str
    what_was_observed: str
    what_changed: str
    why_it_matters: str
    related_assets: List[str] = Field(default_factory=list)
    relevant_graph_relationships: List[str] = Field(default_factory=list)
    risk_trajectory_evolution: str
    potential_escalation: str
    supporting_evidence: List[str] = Field(default_factory=list)
    uncertainty_factors: List[str] = Field(default_factory=list)
    recommended_investigation_steps: List[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =============================================================================
# WAVE 3: VALIDATION & SYSTEM STATUS MODELS
# =============================================================================

class PredictiveValidationMetric(BaseModel):
    """Empirical validation metrics comparing historical predictions to subsequent telemetry."""
    model_config = ConfigDict(extra="ignore")

    total_predictions_evaluated: int
    confirmed_escalations: int
    false_warnings: int
    missed_escalations: int
    accuracy: float = Field(ge=0.0, le=1.0)
    precision: float = Field(ge=0.0, le=1.0)
    recall: float = Field(ge=0.0, le=1.0)
    f1_score: float = Field(ge=0.0, le=1.0)
    brier_score: Optional[float] = None
    mean_lead_time_hours: float = Field(default=0.0, description="Average advance warning time before breach")
    data_leakage_prevented: bool = Field(default=True)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EarlyWarningEngineStatus(BaseModel):
    """Overall operational health and configuration state of Phase 7.6."""
    model_config = ConfigDict(extra="ignore")

    engine_version: str = "v7.6.0"
    is_shadow_mode: bool = True
    active_warnings_count: int
    critical_warnings_count: int
    escalating_assets_count: int
    extracted_signals_count: int
    threat_clusters_count: int
    graph_persistence_backend: str
    neo4j_live: bool
    production_config_protected: bool = True
    active_threshold: float = 0.32
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
