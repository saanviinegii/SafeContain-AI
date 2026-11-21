"""FastAPI REST Router for SafeContain AI Threat Intelligence Correlation Engine (Phase 7.2E).

Exposes endpoints for:
- Threat Intelligence summary KPI metrics
- Querying and filtering normalized indicators (IP, CVE, Hash, Domain, Behavior)
- Exploring pairwise evidence-grounded correlations
- Reviewing unified incident clusters and cluster details
- Real-time indicator lookup and graph matching
- Synchronizing correlated intelligence into Neo4j Aura
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from backend.app.security.auth import (
    UserRecord,
    require_analyst,
    require_viewer,
)
from backend.app.threat_intel.models import (
    IncidentCluster,
    IndicatorType,
    ThreatCorrelation,
    ThreatIndicator,
    ThreatIntelSummary,
    ThreatSeverity,
)
from backend.app.threat_intel.engine import ThreatCorrelationEngine
from backend.app.threat_intel.clustering import IncidentClusterEngine
from backend.app.threat_intel.graph_sync import ThreatIntelGraphSynchronizer

router = APIRouter(prefix="/threat-intelligence", tags=["Threat Intelligence Correlation Engine"])

# Shared Singleton Instances
_correlation_engine = ThreatCorrelationEngine()
_cluster_engine = IncidentClusterEngine(correlation_engine=_correlation_engine)
_graph_synchronizer = ThreatIntelGraphSynchronizer()


# -----------------------------------------------------------------------------
# Request Models
# -----------------------------------------------------------------------------

class MatchIndicatorRequest(BaseModel):
    query: str = Field(..., min_length=2, description="Indicator value, IP, domain, hash, or CVE")


class CorrelateRequest(BaseModel):
    force_refresh: bool = Field(default=False, description="Whether to invalidate cache and recompute")
    clustering_threshold: Optional[float] = Field(default=0.45, ge=0.1, le=0.9, description="Minimum correlation score")


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------

@router.get("/summary", summary="Get threat intelligence summary metrics", response_model=ThreatIntelSummary)
def get_threat_intel_summary(
    current_user: UserRecord = Depends(require_viewer),
) -> ThreatIntelSummary:
    """Returns high-level KPI metrics across threat indicators, active clusters, and affected assets."""
    try:
        indicators = _correlation_engine.collect_all_indicators()
        clusters = _cluster_engine.form_incident_clusters()

        # Type distribution
        type_dist: Dict[str, int] = {}
        source_dist: Dict[str, int] = {}
        for ind in indicators:
            t = ind.type.value
            type_dist[t] = type_dist.get(t, 0) + 1
            src = ind.source
            source_dist[src] = source_dist.get(src, 0) + 1

        all_affected: set = set()
        all_crown_jewels: set = set()
        conf_scores: List[float] = []

        for c in clusters:
            all_affected.update(c.affected_assets)
            all_crown_jewels.update(c.crown_jewels_at_risk)
            conf_scores.append(c.confidence_score)

        mean_conf = round(sum(conf_scores) / len(conf_scores), 4) if conf_scores else 0.85
        has_crit = any(c.severity == ThreatSeverity.CRITICAL for c in clusters)
        has_high = any(c.severity == ThreatSeverity.HIGH for c in clusters)
        highest_sev = ThreatSeverity.CRITICAL if has_crit else (ThreatSeverity.HIGH if has_high else ThreatSeverity.MEDIUM)

        return ThreatIntelSummary(
            total_indicators=len(indicators),
            active_clusters_count=len(clusters),
            compromised_assets_count=len(all_affected),
            crown_jewels_at_risk_count=len(all_crown_jewels),
            highest_severity=highest_sev,
            mean_correlation_confidence=mean_conf,
            indicators_by_type=type_dist,
            sources_distribution=source_dist,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate threat intelligence summary: {str(e)}",
        )


@router.get("/indicators", summary="List normalized threat indicators")
def list_indicators(
    type: Optional[str] = Query(default=None, description="Filter by IndicatorType"),
    severity: Optional[str] = Query(default=None, description="Filter by ThreatSeverity"),
    asset_id: Optional[str] = Query(default=None, description="Filter by associated asset ID"),
    current_user: UserRecord = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    """Returns catalog of normalized indicators with optional categorical filtering."""
    try:
        indicators = _correlation_engine.collect_all_indicators()
        filtered = indicators

        if isinstance(type, str) and type.strip():
            type_clean = type.strip().upper()
            filtered = [i for i in filtered if i.type.value == type_clean]

        if isinstance(severity, str) and severity.strip():
            sev_clean = severity.strip().upper()
            filtered = [i for i in filtered if i.severity.value == sev_clean]

        if isinstance(asset_id, str) and asset_id.strip():
            aid_clean = asset_id.strip().lower()
            filtered = [i for i in filtered if any(aid_clean in a.lower() for a in i.associated_asset_ids)]

        return [i.model_dump(mode="json") for i in filtered]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve threat indicators: {str(e)}",
        )


@router.get("/indicators/{indicator_id}", summary="Get indicator details by ID")
def get_indicator_detail(
    indicator_id: str,
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Retrieves single indicator details, linked assets, alerts, and CVE references."""
    ind = _correlation_engine.sources[0].lookup_indicator(indicator_id)
    if not ind:
        # Search in collected
        for item in _correlation_engine.collect_all_indicators():
            if item.id.lower() == indicator_id.lower() or item.value.lower() == indicator_id.lower():
                ind = item
                break

    if not ind:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat indicator '{indicator_id}' not found.",
        )

    return ind.model_dump(mode="json")


@router.get("/correlations", summary="List correlated threat indicator relationships")
def list_correlations(
    min_score: float = Query(default=0.40, ge=0.0, le=1.0, description="Minimum correlation score filter"),
    current_user: UserRecord = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    """Returns evidence-grounded threat correlations with multi-factor scoring breakdown and explanations."""
    try:
        score_floor = min_score if isinstance(min_score, (int, float)) else 0.40
        correlations = _correlation_engine.correlate_indicators()
        filtered = [c for c in correlations if c.correlation_score >= score_floor]
        return [c.model_dump(mode="json") for c in filtered]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to compute threat correlations: {str(e)}",
        )


@router.get("/clusters", summary="List active incident clusters")
def list_incident_clusters(
    current_user: UserRecord = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    """Returns all synthesized incident clusters grouping indicators, assets, and attack routes."""
    try:
        clusters = _cluster_engine.form_incident_clusters()
        return [c.model_dump(mode="json") for c in clusters]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list incident clusters: {str(e)}",
        )


@router.get("/clusters/{cluster_id}", summary="Get detailed incident cluster information")
def get_cluster_detail(
    cluster_id: str,
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Retrieves in-depth cluster metadata, indicators, affected assets, ML probabilities, and attack paths."""
    cluster = _cluster_engine.get_cluster_by_id(cluster_id)
    if not cluster:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident cluster '{cluster_id}' not found.",
        )
    return cluster.model_dump(mode="json")


@router.post("/correlate", summary="Trigger on-demand threat intelligence correlation analysis")
def run_correlation(
    request: CorrelateRequest,
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Executes full pairwise correlation and incident clustering across telemetry and graph entities."""
    try:
        if request.clustering_threshold is not None:
            _cluster_engine.clustering_threshold = request.clustering_threshold

        correlations = _correlation_engine.correlate_indicators(force_refresh=request.force_refresh)
        clusters = _cluster_engine.form_incident_clusters(force_refresh=request.force_refresh)

        return {
            "status": "COMPLETED",
            "correlations_identified": len(correlations),
            "clusters_formed": len(clusters),
            "total_indicators_evaluated": len(_correlation_engine.collect_all_indicators()),
            "timestamp": _cluster_engine._last_clustered_at.isoformat() if _cluster_engine._last_clustered_at else None,
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Correlation execution failed: {str(e)}",
        )


@router.post("/match", summary="Match arbitrary indicator query against enterprise graph")
def match_indicator(
    request: MatchIndicatorRequest,
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Performs real-time graph lookup and indicator matching for an IP, domain, hash, or CVE."""
    try:
        result = _correlation_engine.match_indicator(query=request.query)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Indicator match failed: {str(e)}",
        )


@router.post("/sync-graph", summary="Synchronize threat intelligence into Neo4j graph")
def sync_threat_intel_to_graph(
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Idempotently syncs correlated indicators, clusters, and edges into Neo4j Aura (or GraphEngine dual-store)."""
    try:
        indicators = _correlation_engine.collect_all_indicators()
        correlations = _correlation_engine.correlate_indicators()
        clusters = _cluster_engine.form_incident_clusters()

        res = _graph_synchronizer.sync_to_graph(
            indicators=indicators,
            correlations=correlations,
            clusters=clusters,
        )
        return res
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Graph synchronization failed: {str(e)}",
        )
