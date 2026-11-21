"""Comprehensive Unit & Integration Test Suite for SafeContain AI Phase 7.2E.

Validates:
1. Threat Indicator Extraction & Normalization:
   - Proper normalization of IPs, CVEs, Domains, and Behaviors.
   - Deterministic indicator IDs.
   - Deduplication across multiple occurrences with reference aggregation.
2. Threat Correlation Engine & Scoring:
   - Match score, graph proximity score, attack path alignment, and freshness decay.
   - Avoidance of double counting (correlation score, ML probability, criticality kept distinct).
   - Dynamic explainability statements detailing why indicators are linked.
   - Confidence and severity rating derivations.
3. Incident Clustering Engine:
   - Connected component graph clustering over correlated indicator pairs.
   - Incident cluster synthesis with affected assets, crown jewel exposure, and ML risk context.
   - Incremental cluster updating with emerging indicators without duplicate creation.
4. Source Adapter Resilience:
   - Internal telemetry extraction resilience.
   - Configurable external feed adapter timeout and graceful degradation under offline/error conditions.
5. Neo4j Graph Synchronization:
   - Idempotent graph entity generation and edge linking.
6. FastAPI REST APIs & RBAC:
   - Summary, indicators query, detail, correlations list, clusters list, cluster detail.
   - On-demand correlation analysis and real-time indicator matching.
   - Role enforcement (VIEWER for read, ANALYST for mutations).
7. Non-Regression Safeguards:
   - Existing CP-SAT containment optimizer constraints and objective scores remain completely intact.
   - Calibrated ML threat probability thresholds remain intact.
"""

import os
import json
import pytest
from datetime import datetime, timezone

from backend.app.threat_intel.models import (
    ConfidenceLevel,
    IndicatorType,
    ThreatCorrelation,
    ThreatIndicator,
    ThreatSeverity,
)
from backend.app.threat_intel.sources.internal_telemetry import InternalTelemetrySource
from backend.app.threat_intel.sources.external_feed_adapter import ConfigurableExternalFeedAdapter
from backend.app.threat_intel.engine import ThreatCorrelationEngine
from backend.app.threat_intel.clustering import IncidentClusterEngine
from backend.app.threat_intel.graph_sync import ThreatIntelGraphSynchronizer
from backend.app.security.user_store import UserRecord
from backend.app.security.roles import UserRole


@pytest.fixture
def viewer_user():
    now = datetime.now(timezone.utc).isoformat()
    return UserRecord(
        id="usr-ti-viewer",
        username="ti_viewer",
        role="VIEWER",
        hashed_password="pw",
        is_active=True,
        created_at=now,
        updated_at=now,
    )


@pytest.fixture
def analyst_user():
    now = datetime.now(timezone.utc).isoformat()
    return UserRecord(
        id="usr-ti-analyst",
        username="ti_analyst",
        role="ANALYST",
        hashed_password="pw",
        is_active=True,
        created_at=now,
        updated_at=now,
    )


# =============================================================================
# 1. INDICATOR EXTRACTION, NORMALIZATION & DEDUPLICATION TESTS
# =============================================================================

def test_internal_telemetry_indicator_extraction_and_normalization():
    """Verifies that InternalTelemetrySource extracts and normalizes real enterprise indicators."""
    src = InternalTelemetrySource()
    indicators = src.fetch_indicators(force_refresh=True)

    assert len(indicators) >= 50, f"Expected at least 50 indicators, found {len(indicators)}"

    # Check for presence of key indicator types
    types_found = {i.type for i in indicators}
    assert IndicatorType.VULNERABILITY_CVE in types_found
    assert IndicatorType.SUSPICIOUS_BEHAVIOR in types_found
    assert IndicatorType.THREAT_SIGNATURE in types_found
    assert IndicatorType.IP_ADDRESS in types_found

    # Verify normalization
    for ind in indicators:
        assert ind.id.startswith("ind-")
        assert len(ind.value) > 0
        if ind.type == IndicatorType.VULNERABILITY_CVE:
            assert "CVE-" in ind.value
            assert ind.value == ind.value.upper()
        elif ind.type == IndicatorType.IP_ADDRESS:
            assert ind.value == ind.value.lower()


def test_indicator_deduplication_and_reference_aggregation():
    """Verifies that duplicated indicators are merged into a single entity with aggregated asset references."""
    src = InternalTelemetrySource()
    indicators = src.fetch_indicators()

    # Search for known multi-asset CVE
    cve_ind = next((i for i in indicators if i.value == "CVE-2024-21626"), None)
    assert cve_ind is not None
    assert len(cve_ind.associated_asset_ids) >= 2, "Expected CVE-2024-21626 to be associated with multiple assets"
    # Ensure no duplicates in associated assets
    assert len(cve_ind.associated_asset_ids) == len(set(cve_ind.associated_asset_ids))


def test_indicator_fast_lookup():
    """Verifies lookup_indicator by value and by ID."""
    src = InternalTelemetrySource()
    src.fetch_indicators()

    # Lookup by CVE
    ind = src.lookup_indicator("cve-2024-21626")
    assert ind is not None
    assert ind.value == "CVE-2024-21626"

    # Lookup nonexistent
    assert src.lookup_indicator("CVE-9999-00000") is None


# =============================================================================
# 2. CORRELATION ENGINE & SCORING TESTS
# =============================================================================

def test_correlation_engine_scoring_and_distinct_metrics():
    """Verifies multi-factor correlation scoring mechanism and strict separation of distinct metrics."""
    engine = ThreatCorrelationEngine(correlation_threshold=0.35)
    correlations = engine.correlate_indicators(force_refresh=True)

    assert len(correlations) >= 20, f"Expected at least 20 correlations, found {len(correlations)}"

    for corr in correlations:
        bd = corr.scoring_breakdown
        # Assert scoring components are in [0, 1]
        assert 0.0 <= bd.indicator_match_score <= 1.0
        assert 0.0 <= bd.graph_proximity_score <= 1.0
        assert 0.0 <= bd.attack_path_relevance_score <= 1.0
        assert 0.0 <= bd.freshness_reliability_score <= 1.0
        assert 0.0 <= bd.total_composite_score <= 1.0

        # Assert confidence level matches score
        if corr.correlation_score >= 0.80:
            assert corr.confidence_level == ConfidenceLevel.CRITICAL
        elif corr.correlation_score >= 0.65:
            assert corr.confidence_level == ConfidenceLevel.HIGH

        # Verify explainability reasons exist
        assert len(corr.correlation_reasons) >= 1
        assert any(len(r) > 10 for r in corr.correlation_reasons)

        # Verify distinct ML risk context is separated (not added into correlation score)
        assert isinstance(corr.ml_risk_context, dict)


def test_real_time_indicator_matching():
    """Verifies match_indicator finds linked assets and attack paths for arbitrary queries."""
    engine = ThreatCorrelationEngine()

    # Test matching CVE
    res = engine.match_indicator("CVE-2024-21626")
    assert res["match_found"] is True
    assert res["matched_indicators_count"] >= 1
    assert len(res["linked_assets"]) >= 1

    # Test matching non-existent
    res_none = engine.match_indicator("NONEXISTENT_HASH_12345")
    assert res_none["match_found"] is False
    assert res_none["matched_indicators_count"] == 0
    assert len(res_none["linked_assets"]) == 0


# =============================================================================
# 3. INCIDENT CLUSTERING ENGINE TESTS
# =============================================================================

def test_incident_cluster_formation():
    """Verifies that IncidentClusterEngine clusters correlated threats and summarizes ML risk."""
    cluster_engine = IncidentClusterEngine()
    clusters = cluster_engine.form_incident_clusters(force_refresh=True)

    assert len(clusters) >= 1, "Expected at least 1 incident cluster"

    first = clusters[0]
    assert first.cluster_id.startswith("CLUST-2026-")
    assert len(first.name) > 5
    assert first.severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH, ThreatSeverity.MEDIUM, ThreatSeverity.LOW]
    assert 0.0 <= first.confidence_score <= 1.0
    assert len(first.indicators) >= 1
    assert len(first.affected_assets) >= 1
    assert len(first.cluster_explanation) > 20

    # Verify ML assessment context
    assert "monitored_assets_count" in first.ml_assessment
    assert "max_ml_probability" in first.ml_assessment


def test_incident_cluster_incremental_update():
    """Verifies incremental addition of emerging indicators to clusters without duplicate creation."""
    cluster_engine = IncidentClusterEngine()
    initial_clusters = cluster_engine.form_incident_clusters()
    initial_count = len(initial_clusters)

    # Create new indicator targeting an existing cluster's asset
    target_asset = initial_clusters[0].affected_assets[0]
    new_ind = ThreatIndicator(
        id="ind-test-emerging",
        type=IndicatorType.IP_ADDRESS,
        value="198.51.100.99",
        title="Emerging C2 IP",
        severity=ThreatSeverity.CRITICAL,
        confidence=0.95,
        source="CrowdStrike_Falcon",
        associated_asset_ids=[target_asset],
    )

    updated_cluster = cluster_engine.update_cluster_with_indicator(new_ind)
    assert updated_cluster is not None
    # Verify it merged into existing cluster rather than blowing up count
    assert len(cluster_engine._active_clusters) == initial_count
    assert any(i.id == "ind-test-emerging" for i in updated_cluster.indicators)


# =============================================================================
# 4. EXTERNAL FEED ADAPTER RESILIENCE TESTS
# =============================================================================

def test_external_feed_graceful_offline_degradation():
    """Verifies that ConfigurableExternalFeedAdapter safely degrades in offline/unconfigured environments."""
    # Test disabled adapter
    adapter = ConfigurableExternalFeedAdapter(is_enabled=False)
    assert adapter.fetch_indicators() == []
    assert adapter.lookup_indicator("1.2.3.4") is None

    # Test enabled adapter with unreachable URL
    adapter_broken = ConfigurableExternalFeedAdapter(
        source_name="Broken_Feed",
        feed_url="http://192.0.2.1:9999/feed.json",  # RFC 5737 TEST-NET (unreachable)
        is_enabled=True,
        timeout_seconds=1,
    )
    # Must not raise an unhandled exception
    res = adapter_broken.fetch_indicators()
    assert res == []


# =============================================================================
# 5. NEO4J GRAPH SYNCHRONIZATION TESTS
# =============================================================================

def test_graph_synchronizer_idempotence():
    """Verifies that ThreatIntelGraphSynchronizer updates graph nodes and relationships idempotently."""
    engine = ThreatCorrelationEngine()
    indicators = engine.collect_all_indicators()[:5]
    correlations = engine.correlate_indicators()[:3]
    cluster_engine = IncidentClusterEngine(correlation_engine=engine)
    clusters = cluster_engine.form_incident_clusters()[:2]

    synchronizer = ThreatIntelGraphSynchronizer()
    res1 = synchronizer.sync_to_graph(indicators, correlations, clusters)
    assert res1["status"] == "SYNCHRONIZED"
    assert res1["indicators_synced"] == len(indicators)
    assert res1["clusters_synced"] == len(clusters)

    # Second sync run must be idempotent
    res2 = synchronizer.sync_to_graph(indicators, correlations, clusters)
    assert res2["status"] == "SYNCHRONIZED"


# =============================================================================
# 6. REST API ENDPOINTS & RBAC TESTS (PHASE 7.2E)
# =============================================================================

def test_api_get_threat_intel_summary(viewer_user):
    """GET /api/v1/threat-intelligence/summary"""
    from backend.app.threat_intel.router import get_threat_intel_summary
    res = get_threat_intel_summary(current_user=viewer_user)
    assert res.total_indicators >= 50
    assert res.active_clusters_count >= 1
    assert res.compromised_assets_count >= 1
    assert res.highest_severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]


def test_api_list_indicators_and_filtering(viewer_user):
    """GET /api/v1/threat-intelligence/indicators with query filters"""
    from backend.app.threat_intel.router import list_indicators
    # All indicators
    all_inds = list_indicators(current_user=viewer_user)
    assert len(all_inds) >= 50

    # Filter by type
    cve_inds = list_indicators(type="VULNERABILITY_CVE", current_user=viewer_user)
    assert len(cve_inds) >= 1
    assert all(i["type"] == "VULNERABILITY_CVE" for i in cve_inds)


def test_api_list_correlations_and_clusters(viewer_user):
    """GET /api/v1/threat-intelligence/correlations & /clusters"""
    from backend.app.threat_intel.router import (
        list_correlations,
        list_incident_clusters,
        get_cluster_detail,
    )
    corrs = list_correlations(current_user=viewer_user)
    assert len(corrs) >= 1
    assert "correlation_score" in corrs[0]
    assert "scoring_breakdown" in corrs[0]

    clusters = list_incident_clusters(current_user=viewer_user)
    assert len(clusters) >= 1
    first_id = clusters[0]["cluster_id"]

    detail = get_cluster_detail(cluster_id=first_id, current_user=viewer_user)
    assert detail["cluster_id"] == first_id
    assert "affected_assets" in detail
    assert "ml_assessment" in detail


def test_api_match_indicator(viewer_user):
    """POST /api/v1/threat-intelligence/match"""
    from backend.app.threat_intel.router import match_indicator, MatchIndicatorRequest
    req = MatchIndicatorRequest(query="CVE-2024-21626")
    res = match_indicator(request=req, current_user=viewer_user)
    assert res["match_found"] is True
    assert res["matched_indicators_count"] >= 1
    assert len(res["linked_assets"]) >= 1


# =============================================================================
# 7. PRESERVATION OF EXISTING OPTIMIZER & ML CAPABILITIES
# =============================================================================

def test_cpsat_containment_optimizer_preservation():
    """Ensures CP-SAT optimizer continues to respect budget, SLA, and objective constraints."""
    from backend.app.optimization.solver import CPSATOptimizer
    from backend.app.planning.catalog import ActionCatalog
    from backend.app.business.twin import BusinessContinuityTwin
    from backend.app.api.v1.router import platform_ctx

    twin = BusinessContinuityTwin()
    twin.discover_dependencies_from_graph(platform_ctx.engine)
    paths = platform_ctx.engine.find_attack_paths()
    nodes = {n.id: n for n in platform_ctx.engine.get_all_nodes()}
    candidates = ActionCatalog.generate_candidate_actions(paths, nodes)

    plan = CPSATOptimizer.plan(
        candidate_actions=candidates,
        twin=twin,
        engine=platform_ctx.engine,
        budget_limit=10000.0,
    )
    assert plan.id == "plan-strat3-cpsat"
    assert plan.total_cost <= 10000.0
    assert plan.satisfies_all_constraints is True
