"""SafeContain AI Threat Intelligence Correlation Engine (Phase 7.2E).

Correlates threat intelligence indicators, graph topology relationships, security telemetry alerts,
calibrated machine learning threat predictions, and active attack paths into prioritized,
evidence-grounded security intelligence.

Core Design Principles:
1. Transparent, multi-factor scoring: Match, Graph Proximity, Attack Path, and Freshness.
2. Distinct metric preservation: Correlation score, ML probability P(Y=1), asset criticality, and
   existing graph risk scores remain strictly separated to avoid double-counting.
3. Explainable by design: Every correlation details explicit reasons why entities are linked.
"""

from __future__ import annotations

import math
import uuid
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx
import pandas as pd

from backend.app.ml.model_registry import ModelRegistry
from backend.app.ml.feature_engineering import FeatureEngineer
from backend.app.threat_intel.models import (
    ConfidenceLevel,
    CorrelationScoringBreakdown,
    IndicatorType,
    ThreatCorrelation,
    ThreatIndicator,
    ThreatSeverity,
)
from backend.app.threat_intel.sources.base import BaseThreatIntelSource
from backend.app.threat_intel.sources.internal_telemetry import InternalTelemetrySource
from backend.app.threat_intel.sources.external_feed_adapter import ConfigurableExternalFeedAdapter

logger = logging.getLogger("safecontain.threat_intel.engine")


class ThreatCorrelationEngine:
    """Orchestrates indicator collection, topological proximity calculation, attack path alignment, and correlation."""

    def __init__(
        self,
        sources: Optional[List[BaseThreatIntelSource]] = None,
        model_registry: Optional[ModelRegistry] = None,
        feature_engineer: Optional[FeatureEngineer] = None,
        match_weight: float = 0.35,
        graph_weight: float = 0.25,
        path_weight: float = 0.25,
        freshness_weight: float = 0.15,
        correlation_threshold: float = 0.40,
    ):
        self.fe = feature_engineer or FeatureEngineer()
        self.registry = model_registry or ModelRegistry(feature_engineer=self.fe)
        self.sources = sources or [
            InternalTelemetrySource(dataset_loader=self.fe.loader),
            ConfigurableExternalFeedAdapter(),
        ]

        # Scoring weights (must sum to 1.0)
        total_w = match_weight + graph_weight + path_weight + freshness_weight
        self.w_match = match_weight / total_w
        self.w_graph = graph_weight / total_w
        self.w_path = path_weight / total_w
        self.w_fresh = freshness_weight / total_w
        self.correlation_threshold = correlation_threshold

        self._cached_correlations: Optional[List[ThreatCorrelation]] = None
        self._indicators_cache: Optional[List[ThreatIndicator]] = None
        self._nx_graph: Optional[nx.DiGraph] = None
        self._crown_jewel_ids: Set[str] = set()

    # -------------------------------------------------------------------------
    # Graph & Attack Path Context Preparation
    # -------------------------------------------------------------------------

    def _ensure_graph_context(self) -> nx.DiGraph:
        """Constructs topological graph and identifies crown jewels."""
        if self._nx_graph is not None:
            return self._nx_graph

        G = nx.DiGraph()
        try:
            nodes_df = self.fe.loader.load_table("nodes.csv")
            rels_df = self.fe.loader.load_table("relationships.csv")

            for _, r in nodes_df.iterrows():
                nid = str(r["node_id"])
                is_cj = (
                    str(r.get("tags", "")).upper().find("CROWN_JEWEL") != -1
                    or float(r.get("criticality", 0.0)) >= 0.85
                    or str(r.get("node_type", "")).upper() in ("DATABASE", "PRIVILEGED_IDENTITY")
                )
                if is_cj:
                    self._crown_jewel_ids.add(nid)
                G.add_node(nid, criticality=float(r.get("criticality", 0.5)), is_crown_jewel=is_cj)

            for _, r in rels_df.iterrows():
                G.add_edge(str(r["source_id"]), str(r["target_id"]), rel_type=str(r.get("relationship_type", "CONNECTED_TO")))

        except Exception as e:
            logger.warning("Error building graph topology for correlation engine: %s", e)

        self._nx_graph = G
        return G

    def _get_active_attack_paths(self) -> List[Dict[str, Any]]:
        """Retrieves attack paths efficiently from dataset or runtime engine."""
        attack_paths = []
        try:
            paths_df = self.fe.loader.load_table("attack_paths.csv")
            for _, r in paths_df.iterrows():
                seq_str = str(r.get("path_sequence", ""))
                seq = [s.strip() for s in seq_str.split("->") if s.strip()] if "->" in seq_str else [s.strip() for s in seq_str.split(";") if s.strip()]
                attack_paths.append({
                    "path_id": str(r.get("path_id", "")),
                    "source": str(r.get("entry_node_id", "")),
                    "target": str(r.get("crown_jewel_id", "")),
                    "sequence": seq,
                    "criticality": str(r.get("criticality", "HIGH")),
                    "confidence": float(r.get("confidence", 0.8)),
                })
        except Exception:
            pass

        if not attack_paths:
            try:
                from backend.app.api.v1.router import platform_ctx
                paths = platform_ctx.engine.find_attack_paths()
                for p in paths:
                    attack_paths.append({
                        "path_id": p.id,
                        "source": p.source_node_id,
                        "target": p.target_crown_jewel_id,
                        "sequence": p.node_sequence,
                        "criticality": p.criticality.value if hasattr(p.criticality, "value") else str(p.criticality),
                        "confidence": p.confidence_score,
                    })
            except Exception as e:
                logger.warning("Error querying runtime attack paths: %s", e)

        return attack_paths

    # -------------------------------------------------------------------------
    # Indicator Aggregation & Normalization
    # -------------------------------------------------------------------------

    def collect_all_indicators(self, force_refresh: bool = False) -> List[ThreatIndicator]:
        """Polls all active source adapters, aggregating and deduplicating indicators."""
        if not force_refresh and self._indicators_cache is not None:
            return self._indicators_cache

        aggregated: Dict[str, ThreatIndicator] = {}

        for source in self.sources:
            if not source.is_enabled:
                continue
            try:
                inds = source.fetch_indicators()
                for ind in inds:
                    key = f"{ind.type.value}::{ind.value.lower()}"
                    if key in aggregated:
                        # Merge
                        existing = aggregated[key]
                        existing.associated_asset_ids = sorted(list(set(existing.associated_asset_ids + ind.associated_asset_ids)))
                        existing.associated_alert_ids = sorted(list(set(existing.associated_alert_ids + ind.associated_alert_ids)))
                        existing.associated_cves = sorted(list(set(existing.associated_cves + ind.associated_cves)))
                        existing.confidence = max(existing.confidence, ind.confidence)
                        if ind.severity == ThreatSeverity.CRITICAL or (ind.severity == ThreatSeverity.HIGH and existing.severity != ThreatSeverity.CRITICAL):
                            existing.severity = ind.severity
                    else:
                        aggregated[key] = ind
            except Exception as e:
                logger.warning("Source %s failed during indicator collection: %s", source.source_name, e)

        self._indicators_cache = list(aggregated.values())
        return self._indicators_cache

    # -------------------------------------------------------------------------
    # Correlation Scoring Mechanism
    # -------------------------------------------------------------------------

    def correlate_indicators(self, force_refresh: bool = False) -> List[ThreatCorrelation]:
        """Executes full pairwise and bipartite correlation across threat indicators and graph entities."""
        if not force_refresh and self._cached_correlations is not None:
            return self._cached_correlations

        indicators = self.collect_all_indicators(force_refresh=force_refresh)
        G = self._ensure_graph_context()
        attack_paths = self._get_active_attack_paths()

        # Pre-fetch ML threat predictions for distinct context
        ml_preds_map: Dict[str, Dict[str, Any]] = {}
        try:
            preds = self.registry.predict_for_nodes()
            th = self.registry.get_operating_threshold()
            for p in preds:
                ml_preds_map[p["node_id"]] = {
                    "ml_probability": p["risk_probability"],
                    "threshold_crossed": bool(p["is_at_risk"]),
                    "risk_tier": p["risk_tier"],
                    "operating_threshold": th,
                }
        except Exception as e:
            logger.warning("ML predictions unavailable for correlation context: %s", e)

        correlations: List[ThreatCorrelation] = []
        n = len(indicators)

        for i in range(n):
            for j in range(i + 1, n):
                ind1 = indicators[i]
                ind2 = indicators[j]

                # 1. Indicator Match Score (Shared CVE, Shared Alerts, or Co-occurring Assets)
                shared_assets = set(ind1.associated_asset_ids).intersection(set(ind2.associated_asset_ids))
                shared_alerts = set(ind1.associated_alert_ids).intersection(set(ind2.associated_alert_ids))
                shared_cves = set(ind1.associated_cves).intersection(set(ind2.associated_cves))

                match_reasons: List[str] = []
                match_score = 0.0

                if shared_cves:
                    match_score += 0.50
                    match_reasons.append(f"Shared vulnerability identifier: {', '.join(sorted(shared_cves))}")

                if shared_alerts:
                    match_score += 0.35
                    match_reasons.append(f"Observed in same security incident alerts: {', '.join(sorted(shared_alerts)[:3])}")

                if shared_assets:
                    match_score += 0.40
                    match_reasons.append(f"Co-located on monitored assets: {', '.join(sorted(shared_assets)[:3])}")

                match_score = min(1.0, match_score)

                # 2. Graph Proximity Score
                min_hops = 999
                all_assets_1 = ind1.associated_asset_ids
                all_assets_2 = ind2.associated_asset_ids
                combined_assets = sorted(list(set(all_assets_1 + all_assets_2)))

                if shared_assets:
                    min_hops = 0
                elif all_assets_1 and all_assets_2:
                    for a1 in all_assets_1:
                        for a2 in all_assets_2:
                            if G.has_node(a1) and G.has_node(a2):
                                try:
                                    # Undirected shortest path for topological neighborhood
                                    d = nx.shortest_path_length(G.to_undirected(), a1, a2)
                                    if d < min_hops:
                                        min_hops = d
                                except nx.NetworkXNoPath:
                                    pass

                if min_hops == 0:
                    graph_score = 1.0
                    graph_reason = "Indicators directly converge on the same asset entity."
                elif min_hops == 1:
                    graph_score = 0.85
                    graph_reason = "Associated assets possess direct topological relationship (1 hop)."
                elif min_hops == 2:
                    graph_score = 0.65
                    graph_reason = "Associated assets share common operational bridge (2 hops)."
                elif min_hops <= 3:
                    graph_score = 0.40
                    graph_reason = f"Assets reside within topological neighborhood ({min_hops} hops)."
                else:
                    graph_score = 0.15
                    graph_reason = "Assets are topologically distant or in disparate subnets."

                # 3. Attack Path Alignment
                relevant_paths: List[str] = []
                path_reasons: List[str] = []
                path_score = 0.10

                for p in attack_paths:
                    seq_set = set(p.get("sequence", []))
                    has_a1 = any(a in seq_set for a in all_assets_1)
                    has_a2 = any(a in seq_set for a in all_assets_2)

                    if has_a1 and has_a2:
                        path_score = max(path_score, 1.0)
                        relevant_paths.append(p["path_id"])
                        path_reasons.append(f"Both indicators flank active attack route {p['path_id']} targeting crown jewel {p.get('target', 'Core Database')}")
                    elif has_a1 or has_a2:
                        path_score = max(path_score, 0.70)
                        relevant_paths.append(p["path_id"])
                        path_reasons.append(f"Indicator touches verified lateral attack path {p['path_id']}")

                # 4. Freshness & Source Reliability Score
                now = datetime.now(timezone.utc)
                hours1 = max(0.0, (now - ind1.last_seen).total_seconds() / 3600.0)
                hours2 = max(0.0, (now - ind2.last_seen).total_seconds() / 3600.0)
                mean_hours = (hours1 + hours2) / 2.0
                # Exponential decay over 7 days (168 hours)
                freshness_decay = math.exp(-0.01 * mean_hours)
                source_rel = (ind1.confidence + ind2.confidence) / 2.0
                freshness_score = round(min(1.0, freshness_decay * source_rel), 4)

                # Composite Correlation Score
                composite_score = round(
                    self.w_match * match_score
                    + self.w_graph * graph_score
                    + self.w_path * path_score
                    + self.w_fresh * freshness_score,
                    4
                )

                # Filter out weak/insignificant correlations
                if composite_score < self.correlation_threshold:
                    continue

                # Derive Confidence Level
                if composite_score >= 0.80:
                    conf_level = ConfidenceLevel.CRITICAL
                elif composite_score >= 0.65:
                    conf_level = ConfidenceLevel.HIGH
                elif composite_score >= 0.50:
                    conf_level = ConfidenceLevel.MEDIUM
                else:
                    conf_level = ConfidenceLevel.LOW

                # Derive Severity (max of indicator severities + attack path elevation)
                has_crit = ind1.severity == ThreatSeverity.CRITICAL or ind2.severity == ThreatSeverity.CRITICAL
                has_high = ind1.severity == ThreatSeverity.HIGH or ind2.severity == ThreatSeverity.HIGH
                is_on_path = len(relevant_paths) > 0

                if has_crit or (has_high and is_on_path):
                    sev = ThreatSeverity.CRITICAL
                elif has_high or is_on_path:
                    sev = ThreatSeverity.HIGH
                else:
                    sev = ThreatSeverity.MEDIUM

                # Identify Crown Jewels in scope
                cj_in_scope = sorted(list(self._crown_jewel_ids.intersection(set(combined_assets))))

                # Compile Evidence References
                ev_refs = sorted(list(set(ind1.associated_alert_ids + ind2.associated_alert_ids)))

                # Consolidate Narrative Reasons
                all_reasons = []
                if match_reasons:
                    all_reasons.extend(match_reasons)
                all_reasons.append(graph_reason)
                if path_reasons:
                    all_reasons.extend(path_reasons[:2])

                # Distinct ML Risk Context (Never conflated with correlation score)
                ml_context: Dict[str, Any] = {}
                for a in combined_assets:
                    if a in ml_preds_map:
                        ml_context[a] = ml_preds_map[a]

                corr_id = f"corr-{uuid.uuid4().hex[:8]}"
                scoring_bd = CorrelationScoringBreakdown(
                    indicator_match_score=round(match_score, 4),
                    graph_proximity_score=round(graph_score, 4),
                    attack_path_relevance_score=round(path_score, 4),
                    freshness_reliability_score=round(freshness_score, 4),
                    total_composite_score=composite_score,
                )

                correlation_record = ThreatCorrelation(
                    correlation_id=corr_id,
                    correlation_score=composite_score,
                    confidence_level=conf_level,
                    severity=sev,
                    primary_indicator=ind1,
                    correlated_indicator=ind2,
                    related_assets=combined_assets,
                    crown_jewels_affected=cj_in_scope,
                    associated_attack_paths=sorted(list(set(relevant_paths))),
                    correlation_reasons=all_reasons,
                    evidence_references=ev_refs,
                    graph_hops_distance=min_hops if min_hops != 999 else -1,
                    scoring_breakdown=scoring_bd,
                    ml_risk_context=ml_context,
                )
                correlations.append(correlation_record)

        # Sort correlations by score descending
        correlations.sort(key=lambda c: c.correlation_score, reverse=True)
        self._cached_correlations = correlations
        logger.info("Threat correlation engine identified %d correlated indicator pairs.", len(correlations))
        return correlations

    # -------------------------------------------------------------------------
    # Real-Time Indicator Matching
    # -------------------------------------------------------------------------

    def match_indicator(self, query: str) -> Dict[str, Any]:
        """Matches an arbitrary query (IP, domain, hash, CVE, asset) against active threat intelligence."""
        q_clean = query.strip().lower()
        indicators = self.collect_all_indicators()
        G = self._ensure_graph_context()
        attack_paths = self._get_active_attack_paths()

        matched_indicators: List[ThreatIndicator] = []
        for ind in indicators:
            if (
                q_clean in ind.value.lower()
                or q_clean in ind.title.lower()
                or any(q_clean in a.lower() for a in ind.associated_asset_ids)
                or any(q_clean in c.lower() for c in ind.associated_cves)
            ):
                matched_indicators.append(ind)

        # Find linked assets and crown jewels
        linked_assets: Set[str] = set()
        linked_alerts: Set[str] = set()
        linked_cves: Set[str] = set()

        for ind in matched_indicators:
            linked_assets.update(ind.associated_asset_ids)
            linked_alerts.update(ind.associated_alert_ids)
            linked_cves.update(ind.associated_cves)

        # Determine attack path associations
        intersecting_paths = []
        for p in attack_paths:
            seq = p.get("sequence", [])
            if any(a in seq for a in linked_assets):
                intersecting_paths.append(p)

        crown_jewels = sorted(list(self._crown_jewel_ids.intersection(linked_assets)))

        return {
            "query": query,
            "match_found": len(matched_indicators) > 0,
            "matched_indicators_count": len(matched_indicators),
            "matched_indicators": [m.model_dump(mode="json") for m in matched_indicators],
            "linked_assets": sorted(list(linked_assets)),
            "crown_jewels_exposed": crown_jewels,
            "associated_attack_paths": intersecting_paths,
            "linked_alerts_count": len(linked_alerts),
            "linked_cves": sorted(list(linked_cves)),
            "max_severity": max([m.severity.value for m in matched_indicators], default="NONE") if matched_indicators else "NONE",
        }

    def clear_cache(self) -> None:
        """Clears in-memory correlation caches."""
        self._cached_correlations = None
        self._indicators_cache = None
        self._nx_graph = None
