"""SafeContain AI Threat Intelligence Correlation Engine Data Models (Phase 7.2E).

Defines standardized schemas for:
- Normalized Threat Indicators (IP, Domain, URL, Hash, CVE, Behavior, Signature, Asset)
- Evidence-grounded Threat Correlations with transparent multi-factor scoring
- Incident Clusters grouping related telemetry, attack paths, and ML risk predictions
- Source adapter metadata and provenance tracking
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class IndicatorType(str, Enum):
    """Normalized threat intelligence indicator categories."""
    IP_ADDRESS = "IP_ADDRESS"
    DOMAIN = "DOMAIN"
    URL = "URL"
    FILE_HASH = "FILE_HASH"
    VULNERABILITY_CVE = "VULNERABILITY_CVE"
    SUSPICIOUS_BEHAVIOR = "SUSPICIOUS_BEHAVIOR"
    THREAT_SIGNATURE = "THREAT_SIGNATURE"
    ASSET_IDENTIFIER = "ASSET_IDENTIFIER"


class ThreatSeverity(str, Enum):
    """Standardized multi-level threat severity."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConfidenceLevel(str, Enum):
    """Categorical confidence rating based on multi-source verification."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatIndicator(BaseModel):
    """Standardized threat intelligence indicator with provenance attribution."""
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Unique deterministic indicator identifier")
    type: IndicatorType = Field(description="Indicator category")
    value: str = Field(description="Normalized indicator value (e.g. IP, CVE, hash)")
    title: str = Field(default="", description="Descriptive indicator name")
    severity: ThreatSeverity = Field(default=ThreatSeverity.MEDIUM)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0, description="Verification confidence [0.0 - 1.0]")
    source: str = Field(default="Internal_Telemetry", description="Originating intelligence source")
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    associated_asset_ids: List[str] = Field(default_factory=list, description="Targeted or observed graph node IDs")
    associated_alert_ids: List[str] = Field(default_factory=list, description="Linked telemetry alert IDs")
    associated_cves: List[str] = Field(default_factory=list, description="Associated CVE vulnerability IDs")
    description: Optional[str] = Field(default=None)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CorrelationScoringBreakdown(BaseModel):
    """Transparent, non-overlapping scoring component weights."""
    indicator_match_score: float = Field(description="Shared CVE, hash, or exact indicator overlap [0.0 - 1.0]")
    graph_proximity_score: float = Field(description="Topological proximity between associated assets [0.0 - 1.0]")
    attack_path_relevance_score: float = Field(description="Traversed by or adjacent to active attack routes [0.0 - 1.0]")
    freshness_reliability_score: float = Field(description="Temporal freshness and source reliability decay [0.0 - 1.0]")
    total_composite_score: float = Field(description="Weighted composite score [0.0 - 1.0]")


class ThreatCorrelation(BaseModel):
    """Evidence-grounded correlation between threat indicators, assets, and events."""
    model_config = ConfigDict(extra="ignore")

    correlation_id: str = Field(description="Unique correlation record ID")
    correlation_score: float = Field(ge=0.0, le=1.0, description="Correlation strength [0.0 - 1.0]")
    confidence_level: ConfidenceLevel = Field(description="Confidence rating")
    severity: ThreatSeverity = Field(description="Derived threat severity")
    primary_indicator: ThreatIndicator
    correlated_indicator: ThreatIndicator
    related_assets: List[str] = Field(default_factory=list, description="Associated node IDs")
    crown_jewels_affected: List[str] = Field(default_factory=list, description="High-criticality targets in scope")
    associated_attack_paths: List[str] = Field(default_factory=list, description="Viable attack routes linking entities")
    correlation_reasons: List[str] = Field(default_factory=list, description="Explicit explainability statements")
    evidence_references: List[str] = Field(default_factory=list, description="Supporting alert and evidence IDs")
    graph_hops_distance: int = Field(default=1, description="Shortest path distance between associated assets")
    scoring_breakdown: CorrelationScoringBreakdown
    # Distinct risk context (never combined with correlation score to avoid double counting)
    ml_risk_context: Dict[str, Any] = Field(default_factory=dict, description="Distinct ML prediction context")
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IncidentCluster(BaseModel):
    """Unified incident cluster grouping related threat events, indicators, and attack paths."""
    model_config = ConfigDict(extra="ignore")

    cluster_id: str = Field(description="Unique cluster identifier (e.g. CLUST-2026-001)")
    name: str = Field(description="Human-readable incident campaign title")
    description: str = Field(description="Synthesized operational briefing")
    severity: ThreatSeverity = Field(description="Aggregate incident severity")
    confidence_score: float = Field(ge=0.0, le=1.0, description="Aggregate cluster confidence [0.0 - 1.0]")
    confidence_level: ConfidenceLevel
    indicators: List[ThreatIndicator] = Field(default_factory=list)
    affected_assets: List[str] = Field(default_factory=list, description="Graph node IDs in cluster")
    crown_jewels_at_risk: List[str] = Field(default_factory=list, description="Critical assets exposed")
    related_alert_ids: List[str] = Field(default_factory=list)
    related_evidence_ids: List[str] = Field(default_factory=list)
    attack_path_ids: List[str] = Field(default_factory=list)
    ml_assessment: Dict[str, Any] = Field(default_factory=dict, description="Assets crossing threshold, top SHAP drivers")
    cluster_explanation: str = Field(description="Narrative explanation of how indicators and assets form this cluster")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = Field(default="ACTIVE", description="ACTIVE | INVESTIGATING | CONTAINED | RESOLVED")


class ThreatIntelSummary(BaseModel):
    """High-level summary metrics for operational dashboards."""
    total_indicators: int
    active_clusters_count: int
    compromised_assets_count: int
    crown_jewels_at_risk_count: int
    highest_severity: ThreatSeverity
    mean_correlation_confidence: float
    indicators_by_type: Dict[str, int]
    sources_distribution: Dict[str, int]
