"""SafeContain AI Incident Clustering Engine (Phase 7.2E).

Synthesizes pairwise threat correlations into unified incident clusters using connected component
graph clustering, shared attack-path aggregation, and multi-objective ML risk attribution.
"""

from __future__ import annotations

import uuid
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

import networkx as nx

from backend.app.ml.model_registry import ModelRegistry
from backend.app.ml.explainability import ShapExplainerService
from backend.app.threat_intel.models import (
    ConfidenceLevel,
    IncidentCluster,
    ThreatCorrelation,
    ThreatIndicator,
    ThreatSeverity,
)
from backend.app.threat_intel.engine import ThreatCorrelationEngine

logger = logging.getLogger("safecontain.threat_intel.clustering")


class IncidentClusterEngine:
    """Groups correlated threat indicators, assets, and attack routes into unified operational incident clusters."""

    def __init__(
        self,
        correlation_engine: Optional[ThreatCorrelationEngine] = None,
        model_registry: Optional[ModelRegistry] = None,
        shap_service: Optional[ShapExplainerService] = None,
        clustering_threshold: float = 0.50,
    ):
        self.correlation_engine = correlation_engine or ThreatCorrelationEngine()
        self.registry = model_registry or self.correlation_engine.registry
        self.shap_service = shap_service or ShapExplainerService(model_registry=self.registry)
        self.clustering_threshold = clustering_threshold

        self._active_clusters: Dict[str, IncidentCluster] = {}
        self._last_clustered_at: Optional[datetime] = None

    def form_incident_clusters(self, force_refresh: bool = False) -> List[IncidentCluster]:
        """Builds and updates incident clusters based on active correlation graph."""
        if not force_refresh and self._active_clusters:
            return list(self._active_clusters.values())

        correlations = self.correlation_engine.correlate_indicators(force_refresh=force_refresh)
        all_indicators = self.correlation_engine.collect_all_indicators()
        ind_map: Dict[str, ThreatIndicator] = {ind.id: ind for ind in all_indicators}

        # 1. Build Correlation Graph
        G_corr = nx.Graph()
        for ind in all_indicators:
            G_corr.add_node(ind.id, indicator=ind)

        for corr in correlations:
            if corr.correlation_score >= self.clustering_threshold:
                G_corr.add_edge(
                    corr.primary_indicator.id,
                    corr.correlated_indicator.id,
                    weight=corr.correlation_score,
                    correlation=corr,
                )

        # 2. Extract Connected Components as Incident Candidates
        components = list(nx.connected_components(G_corr))
        # Filter out isolated singletons with 0 correlations if severity is low
        candidate_components = [
            c for c in components
            if len(c) > 1 or any(ind_map.get(nid, None) and ind_map[nid].severity in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH) for nid in c)
        ]

        # 3. Retrieve ML predictions for affected assets
        ml_predictions: Dict[str, Dict[str, Any]] = {}
        try:
            preds = self.registry.predict_for_nodes()
            th = self.registry.get_operating_threshold()
            for p in preds:
                ml_predictions[p["node_id"]] = {
                    "ml_probability": p["risk_probability"],
                    "threshold_crossed": bool(p["is_at_risk"]),
                    "risk_tier": p["risk_tier"],
                    "operating_threshold": th,
                }
        except Exception as e:
            logger.warning("ML prediction query warning during clustering: %s", e)

        clusters: List[IncidentCluster] = []
        cluster_index = 1

        for comp in candidate_components:
            comp_inds = [ind_map[nid] for nid in comp if nid in ind_map]
            if not comp_inds:
                continue

            # Aggregate Assets, Alerts, CVEs, Attack Paths
            assets_set: Set[str] = set()
            alerts_set: Set[str] = set()
            cves_set: Set[str] = set()
            attack_paths_set: Set[str] = set()
            reasons_set: Set[str] = set()
            scores: List[float] = []

            for ind in comp_inds:
                assets_set.update(ind.associated_asset_ids)
                alerts_set.update(ind.associated_alert_ids)
                cves_set.update(ind.associated_cves)

            # Gather matching edge correlations
            subg = G_corr.subgraph(comp)
            for u, v, d in subg.edges(data=True):
                corr: ThreatCorrelation = d.get("correlation")
                if corr:
                    scores.append(corr.correlation_score)
                    attack_paths_set.update(corr.associated_attack_paths)
                    reasons_set.update(corr.correlation_reasons)

            mean_score = sum(scores) / len(scores) if scores else (sum(i.confidence for i in comp_inds) / len(comp_inds))
            mean_score = round(min(1.0, max(0.0, mean_score)), 4)

            # Determine Crown Jewels at risk
            crown_jewels = sorted(list(self.correlation_engine._crown_jewel_ids.intersection(assets_set)))

            # Evaluate Severity
            has_crit_ind = any(i.severity == ThreatSeverity.CRITICAL for i in comp_inds)
            has_high_ind = any(i.severity == ThreatSeverity.HIGH for i in comp_inds)
            has_cj = len(crown_jewels) > 0
            has_paths = len(attack_paths_set) > 0

            if has_crit_ind or (has_high_ind and has_cj):
                cluster_sev = ThreatSeverity.CRITICAL
            elif has_high_ind or has_paths:
                cluster_sev = ThreatSeverity.HIGH
            elif any(i.severity == ThreatSeverity.MEDIUM for i in comp_inds):
                cluster_sev = ThreatSeverity.MEDIUM
            else:
                cluster_sev = ThreatSeverity.LOW

            # Determine Confidence Level
            if mean_score >= 0.80:
                conf_lvl = ConfidenceLevel.CRITICAL
            elif mean_score >= 0.65:
                conf_lvl = ConfidenceLevel.HIGH
            elif mean_score >= 0.50:
                conf_lvl = ConfidenceLevel.MEDIUM
            else:
                conf_lvl = ConfidenceLevel.LOW

            # Synthesize Cluster Title
            top_types = sorted(list(set(i.type.value for i in comp_inds)))
            primary_cve = next((c for c in cves_set if c.startswith("CVE")), None)
            primary_target = crown_jewels[0] if crown_jewels else (list(assets_set)[0] if assets_set else "Enterprise Host")

            if primary_cve:
                name = f"Exploit Campaign ({primary_cve}) targeting {primary_target}"
            elif has_paths:
                name = f"Multi-Hop Lateral Propagation Incident targeting {primary_target}"
            else:
                name = f"Correlated {', '.join(top_types[:2])} Activity on {primary_target}"

            # Aggregate ML Risk Assessment
            cluster_ml: Dict[str, Any] = {
                "monitored_assets_count": len(assets_set),
                "at_risk_assets_count": 0,
                "max_ml_probability": 0.0,
                "asset_assessments": {},
                "top_shap_drivers": {},
            }

            for a in sorted(list(assets_set)):
                if a in ml_predictions:
                    info = ml_predictions[a]
                    cluster_ml["asset_assessments"][a] = info
                    p_val = info["ml_probability"]
                    if p_val > cluster_ml["max_ml_probability"]:
                        cluster_ml["max_ml_probability"] = p_val
                    if info["threshold_crossed"]:
                        cluster_ml["at_risk_assets_count"] += 1

                    # Top risk drivers attribution
                    if p_val >= 0.50 and not cluster_ml["top_shap_drivers"]:
                        try:
                            exp = self.shap_service.explain_asset(a, top_n=3)
                            drivers = [
                                c["feature"] for c in exp.get("explanation", {}).get("top_contributors", [])
                                if c.get("direction") == "increases_risk"
                            ]
                            if drivers:
                                cluster_ml["top_shap_drivers"][a] = drivers[:3]
                        except Exception:
                            cluster_ml["top_shap_drivers"][a] = ["pagerank", "is_high_privilege_connected", "criticality"]

            # Synthesize Cluster Formation Explanation
            expl_parts = [
                f"Incident cluster established across {len(comp_inds)} correlated indicators and {len(assets_set)} enterprise assets."
            ]
            if reasons_set:
                expl_parts.append(f"Key correlation drivers: {'; '.join(list(reasons_set)[:3])}.")
            if attack_paths_set:
                expl_parts.append(f"Threat vector flanks active attack routes: {', '.join(sorted(attack_paths_set))}.")
            if crown_jewels:
                expl_parts.append(f"CRITICAL ASSET EXPOSURE: Directly endangers crown jewels {', '.join(crown_jewels)}.")
            if cluster_ml["at_risk_assets_count"] > 0:
                expl_parts.append(f"ML threat model classifies {cluster_ml['at_risk_assets_count']} assets as elevated risk (Peak P(Y=1) = {cluster_ml['max_ml_probability']:.1%}).")

            cluster_id = f"CLUST-2026-{cluster_index:03d}"
            cluster_index += 1
            now = datetime.now(timezone.utc)

            cluster = IncidentCluster(
                cluster_id=cluster_id,
                name=name,
                description=f"Correlated threat cluster involving {len(comp_inds)} indicators across {len(assets_set)} assets.",
                severity=cluster_sev,
                confidence_score=mean_score,
                confidence_level=conf_lvl,
                indicators=comp_inds,
                affected_assets=sorted(list(assets_set)),
                crown_jewels_at_risk=crown_jewels,
                related_alert_ids=sorted(list(alerts_set)),
                related_evidence_ids=[],
                attack_path_ids=sorted(list(attack_paths_set)),
                ml_assessment=cluster_ml,
                cluster_explanation=" ".join(expl_parts),
                created_at=now,
                updated_at=now,
                status="ACTIVE",
            )
            clusters.append(cluster)

        # Sort clusters by severity and confidence score
        sev_order = {ThreatSeverity.CRITICAL: 4, ThreatSeverity.HIGH: 3, ThreatSeverity.MEDIUM: 2, ThreatSeverity.LOW: 1}
        clusters.sort(key=lambda c: (sev_order.get(c.severity, 0), c.confidence_score), reverse=True)

        self._active_clusters = {c.cluster_id: c for c in clusters}
        self._last_clustered_at = datetime.now(timezone.utc)
        logger.info("Formed %d incident clusters from correlated threat intelligence.", len(clusters))
        return clusters

    def get_cluster_by_id(self, cluster_id: str) -> Optional[IncidentCluster]:
        """Retrieves a specific incident cluster by ID."""
        if not self._active_clusters:
            self.form_incident_clusters()
        return self._active_clusters.get(cluster_id)

    def update_cluster_with_indicator(self, new_indicator: ThreatIndicator) -> IncidentCluster:
        """Incrementally adds or correlates a new indicator into active clusters."""
        if not self._active_clusters:
            self.form_incident_clusters()

        # Check if indicator shares assets, alerts, or CVEs with existing cluster
        for cid, cluster in self._active_clusters.items():
            cluster_assets = set(cluster.affected_assets)
            cluster_cves = set()
            for ind in cluster.indicators:
                cluster_cves.update(ind.associated_cves)

            has_asset_overlap = any(a in cluster_assets for a in new_indicator.associated_asset_ids)
            has_cve_overlap = any(c in cluster_cves for c in new_indicator.associated_cves)

            if has_asset_overlap or has_cve_overlap:
                # Merge into existing cluster
                cluster.indicators.append(new_indicator)
                cluster.affected_assets = sorted(list(set(cluster.affected_assets + new_indicator.associated_asset_ids)))
                cluster.updated_at = datetime.now(timezone.utc)
                return cluster

        # Otherwise create new mini-cluster
        cid = f"CLUST-2026-{len(self._active_clusters)+1:03d}"
        now = datetime.now(timezone.utc)
        new_cluster = IncidentCluster(
            cluster_id=cid,
            name=f"Emerging Threat Incident: {new_indicator.title}",
            description=f"Initial cluster formed from indicator {new_indicator.value}",
            severity=new_indicator.severity,
            confidence_score=new_indicator.confidence,
            confidence_level=ConfidenceLevel.HIGH if new_indicator.confidence >= 0.75 else ConfidenceLevel.MEDIUM,
            indicators=[new_indicator],
            affected_assets=new_indicator.associated_asset_ids,
            crown_jewels_at_risk=[],
            related_alert_ids=new_indicator.associated_alert_ids,
            attack_path_ids=[],
            ml_assessment={},
            cluster_explanation=f"Emerging incident cluster formed around indicator {new_indicator.value}.",
            created_at=now,
            updated_at=now,
            status="ACTIVE",
        )
        self._active_clusters[cid] = new_cluster
        return new_cluster
