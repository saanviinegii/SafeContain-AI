"""Module 7.6.4: Neo4j Graph Threat Signal Correlation & Clustering Engine.

Discovers multi-asset threat clusters by correlating behavioral threat signals
across graph topology, attack paths, and dependency relationships using SafeContain AI's
Dual-Engine Graph Infrastructure (Neo4j Aura cloud with resilient in-memory fallback).
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.app.early_warning.models import (
    CorrelatedThreatCluster,
    ThreatSeverity,
    ThreatSignal,
)
from backend.app.graph.engine import GraphEngine

logger = logging.getLogger("safecontain.early_warning.graph_correlation")


def _resolve_graph_engine(engine: Optional[Any] = None) -> Any:
    if engine is not None:
        return engine
    try:
        from backend.app.api.v1.router import platform_ctx
        if platform_ctx and hasattr(platform_ctx, "engine") and platform_ctx.engine:
            return platform_ctx.engine
    except Exception:
        pass
    try:
        from backend.app.graph.engine import GraphEngine
        return GraphEngine(mode="in_memory")
    except Exception:
        return None


class GraphThreatCorrelator:
    """Correlates threat signals across enterprise infrastructure topology to discover emerging clusters."""

    def __init__(self, graph_engine: Optional[Any] = None):
        self.engine = _resolve_graph_engine(graph_engine)

    def correlate_signals_to_clusters(
        self,
        signals: List[ThreatSignal],
        max_hops: int = 2,
    ) -> List[CorrelatedThreatCluster]:
        """Groups discrete threat signals into graph-correlated incident clusters."""
        if not signals:
            return []

        # 1. Map signals to affected assets
        asset_signals: Dict[str, List[ThreatSignal]] = {}
        for s in signals:
            asset_signals.setdefault(s.asset_id, []).append(s)
            for rel in s.related_entities:
                if rel.startswith("node-") or rel.startswith("srv-") or rel.startswith("ast-"):
                    asset_signals.setdefault(rel, []).append(s)

        # 2. Build topological adjacency clusters using graph relationships
        # Query graph edges linking affected assets within max_hops
        all_affected = list(asset_signals.keys())
        clusters: List[CorrelatedThreatCluster] = []
        visited_assets: Set[str] = set()

        for asset_id in all_affected:
            if asset_id in visited_assets:
                continue

            # Find connected cluster components
            cluster_assets: Set[str] = {asset_id}
            queue = [asset_id]
            visited_assets.add(asset_id)

            while queue:
                curr = queue.pop(0)
                # Query in-memory graph or Neo4j for neighbors
                neighbors = self._get_asset_neighbors(curr)
                for n_id in neighbors:
                    if n_id in all_affected and n_id not in cluster_assets:
                        cluster_assets.add(n_id)
                        visited_assets.add(n_id)
                        queue.append(n_id)

            # Compile signals belonging to this connected asset group
            cluster_sigs: List[ThreatSignal] = []
            seen_sig_ids = set()
            for ca in cluster_assets:
                for sig in asset_signals.get(ca, []):
                    if sig.signal_id not in seen_sig_ids:
                        cluster_sigs.append(sig)
                        seen_sig_ids.add(sig.signal_id)

            if not cluster_sigs:
                continue

            # Determine cluster properties
            cluster = self._build_cluster_record(list(cluster_assets), cluster_sigs)
            clusters.append(cluster)

        # Sort clusters by severity (CRITICAL -> HIGH -> MEDIUM -> LOW)
        sev_rank = {ThreatSeverity.CRITICAL: 4, ThreatSeverity.HIGH: 3, ThreatSeverity.MEDIUM: 2, ThreatSeverity.LOW: 1}
        clusters.sort(key=lambda c: (sev_rank.get(c.severity, 1), len(c.signals)), reverse=True)
        return clusters

    def _get_asset_neighbors(self, asset_id: str) -> List[str]:
        """Retrieves 1-hop topological neighbors from GraphEngine."""
        neighbors: List[str] = []
        try:
            # Check in-memory networkx graph
            if hasattr(self.engine, "_nx_graph") and self.engine._nx_graph.has_node(asset_id):
                succ = list(self.engine._nx_graph.successors(asset_id))
                pred = list(self.engine._nx_graph.predecessors(asset_id))
                neighbors = list(set(succ + pred))
            elif hasattr(self.engine, "get_all_edges"):
                edges = self.engine.get_all_edges()
                for e in edges:
                    src = getattr(e, "source", None) or getattr(e, "source_id", None)
                    tgt = getattr(e, "target", None) or getattr(e, "target_id", None)
                    if src == asset_id and tgt:
                        neighbors.append(tgt)
                    elif tgt == asset_id and src:
                        neighbors.append(src)
        except Exception as e:
            logger.debug("Neighbor lookup error for %s: %s", asset_id, e)

        return list(set(neighbors))

    def _build_cluster_record(
        self,
        asset_ids: List[str],
        signals: List[ThreatSignal],
    ) -> CorrelatedThreatCluster:
        """Synthesizes an explainable CorrelatedThreatCluster from grouped assets and signals."""
        now = datetime.now(timezone.utc)
        sorted_assets = sorted(asset_ids)

        # Check for Crown Jewels among cluster assets
        crown_jewels: List[str] = []
        for aid in sorted_assets:
            node = self.engine.get_node(aid)
            if node and getattr(node, "is_crown_jewel", False):
                crown_jewels.append(aid)

        # Compute cluster severity
        has_critical = any(s.severity == ThreatSeverity.CRITICAL for s in signals)
        has_high = any(s.severity == ThreatSeverity.HIGH for s in signals)
        if has_critical or len(crown_jewels) > 0:
            severity = ThreatSeverity.CRITICAL
        elif has_high or len(signals) >= 3:
            severity = ThreatSeverity.HIGH
        else:
            severity = ThreatSeverity.MEDIUM

        # Identify primary pattern
        signal_types = set(s.signal_type.value for s in signals)
        if "RISK_SPIKE" in signal_types and len(asset_ids) > 1:
            pattern = "Multi-Asset Lateral Risk Propagation"
        elif "SEVERITY_ESCALATION" in signal_types:
            pattern = "Rapid Privilege & Severity Escalation Cluster"
        elif "REPEATED_SUSPICIOUS_EVENTS" in signal_types:
            pattern = "Concentrated Persistent Anomaly Hotspot"
        elif "VULNERABILITY_EXPOSURE_SURGE" in signal_types:
            pattern = "Vulnerability-Targeted Breach Vector"
        else:
            pattern = "Topological Threat Co-Occurrence"

        # Unique deterministic cluster ID
        token_input = f"{':'.join(sorted_assets)}:{':'.join(sorted(s.signal_id for s in signals))}"
        cluster_token = hashlib.sha256(token_input.encode("utf-8")).hexdigest()[:10]
        cluster_id = f"clust-early-{cluster_token}"

        # Explainable graph evidence
        evidence_list = [
            f"Correlated {len(signals)} behavioral signals across {len(asset_ids)} interconnected topological assets.",
            f"Cluster assets in scope: {', '.join(sorted_assets[:5])}{' (+more)' if len(sorted_assets) > 5 else ''}.",
        ]
        if crown_jewels:
            evidence_list.append(f"HIGH IMPACT: Cluster directly threatens {len(crown_jewels)} designated Enterprise Crown Jewels ({', '.join(crown_jewels)}).")

        return CorrelatedThreatCluster(
            cluster_id=cluster_id,
            cluster_name=f"{pattern} ({sorted_assets[0]})",
            primary_pattern=pattern,
            severity=severity,
            confidence=0.88,
            related_asset_ids=sorted_assets,
            crown_jewels_at_risk=crown_jewels,
            signals=signals,
            attack_path_ids=[],
            graph_evidence=evidence_list,
            recommended_containment_posture="Isolate lateral transmission links between affected assets and partition Crown Jewels." if severity == ThreatSeverity.CRITICAL else "Inspect ingress traffic and monitor dependency access.",
            detected_at=now,
        )
