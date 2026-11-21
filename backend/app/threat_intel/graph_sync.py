"""SafeContain AI Neo4j Threat Intelligence Graph Synchronizer (Phase 7.2E).

Synchronizes correlated threat indicators and incident clusters into Neo4j Aura (or GraphEngine dual-store).
Enforces:
1. Idempotent Cypher MERGE operations avoiding duplicate nodes or edges.
2. Dual-mode support: Syncs directly to Neo4j Aura if live; syncs into GraphEngine in-memory store if offline.
3. Complete preservation of existing asset, relationship, and attack-path graph entities.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from backend.app.models.domain import (
    DataProvenance,
    EvidenceStatus,
    GraphEdge,
    GraphNode,
    NodeType,
    RelationshipType,
)
from backend.app.threat_intel.models import (
    IncidentCluster,
    ThreatCorrelation,
    ThreatIndicator,
)

logger = logging.getLogger("safecontain.threat_intel.graph_sync")


class ThreatIntelGraphSynchronizer:
    """Manages idempotent synchronization of threat intelligence entities into Neo4j and GraphEngine."""

    def __init__(self, graph_engine=None):
        if graph_engine is None:
            try:
                from backend.app.graph.engine import GraphEngine
                self.engine = GraphEngine.get_instance()
            except Exception:
                from backend.app.api.v1.router import platform_ctx
                self.engine = platform_ctx.engine
        else:
            self.engine = graph_engine

    def sync_to_graph(
        self,
        indicators: List[ThreatIndicator],
        correlations: List[ThreatCorrelation],
        clusters: List[IncidentCluster],
    ) -> Dict[str, Any]:
        """Synchronizes threat indicators, incident clusters, and correlation links into the graph."""
        nodes_created = 0
        edges_created = 0

        # ---------------------------------------------------------------------
        # 1. Update In-Memory GraphEngine Store
        # ---------------------------------------------------------------------
        now = datetime.now(timezone.utc)

        # Add Indicator Nodes
        for ind in indicators:
            node_id = f"threat-ind-{ind.id}"
            g_node = GraphNode(
                id=node_id,
                name=ind.title or f"{ind.type.value}: {ind.value}",
                type=NodeType.THREAT,
                criticality=0.9 if ind.severity.value == "CRITICAL" else 0.7 if ind.severity.value == "HIGH" else 0.5,
                is_compromised=True,
                properties={
                    "indicator_id": ind.id,
                    "indicator_type": ind.type.value,
                    "indicator_value": ind.value,
                    "severity": ind.severity.value,
                    "confidence": ind.confidence,
                    "source": ind.source,
                },
                provenance=DataProvenance.LIVE_TELEMETRY,
                created_at=now,
                updated_at=now,
            )
            self.engine.add_node(g_node)
            nodes_created += 1

            # Link Indicator to Associated Assets (INDICATES / OBSERVED_IN)
            for asset_id in ind.associated_asset_ids:
                if self.engine.get_node(asset_id) is not None:
                    edge_id = f"edge-ind-{ind.id}-{asset_id}"
                    g_edge = GraphEdge(
                        id=edge_id,
                        source=node_id,
                        target=asset_id,
                        type=RelationshipType.OBSERVED_IN,
                        evidence_status=EvidenceStatus.CONFIRMED,
                        confidence=ind.confidence,
                        weight=1.0,
                        properties={"indicator_type": ind.type.value},
                        provenance=DataProvenance.LIVE_TELEMETRY,
                    )
                    self.engine.add_edge(g_edge)
                    edges_created += 1

        # Add Incident Cluster Nodes
        for cluster in clusters:
            cluster_node_id = f"incident-{cluster.cluster_id.lower()}"
            c_node = GraphNode(
                id=cluster_node_id,
                name=cluster.name,
                type=NodeType.INCIDENT,
                criticality=0.95 if cluster.severity.value == "CRITICAL" else 0.8 if cluster.severity.value == "HIGH" else 0.6,
                is_compromised=True,
                properties={
                    "cluster_id": cluster.cluster_id,
                    "severity": cluster.severity.value,
                    "confidence_score": cluster.confidence_score,
                    "confidence_level": cluster.confidence_level.value,
                    "status": cluster.status,
                },
                provenance=DataProvenance.LIVE_TELEMETRY,
                created_at=now,
                updated_at=now,
            )
            self.engine.add_node(c_node)
            nodes_created += 1

            # Link Cluster to Affected Assets
            for asset_id in cluster.affected_assets:
                if self.engine.get_node(asset_id) is not None:
                    edge_id = f"edge-clust-{cluster.cluster_id}-{asset_id}"
                    g_edge = GraphEdge(
                        id=edge_id,
                        source=cluster_node_id,
                        target=asset_id,
                        type=RelationshipType.ASSOCIATED_WITH,
                        evidence_status=EvidenceStatus.CONFIRMED,
                        confidence=cluster.confidence_score,
                        weight=1.0,
                        properties={"relationship": "AFFECTS_ASSET"},
                        provenance=DataProvenance.LIVE_TELEMETRY,
                    )
                    self.engine.add_edge(g_edge)
                    edges_created += 1

        # Add Correlation Edges between Indicators
        for corr in correlations[:50]:  # Top 50 strongest correlations
            src_node = f"threat-ind-{corr.primary_indicator.id}"
            dst_node = f"threat-ind-{corr.correlated_indicator.id}"
            if self.engine.get_node(src_node) is not None and self.engine.get_node(dst_node) is not None:
                edge_id = f"edge-corr-{corr.correlation_id}"
                g_edge = GraphEdge(
                    id=edge_id,
                    source=src_node,
                    target=dst_node,
                    type=RelationshipType.CONNECTED_TO,
                    evidence_status=EvidenceStatus.CONFIRMED,
                    confidence=corr.correlation_score,
                    weight=round(1.0 - corr.correlation_score + 0.1, 2),
                    properties={
                        "correlation_score": corr.correlation_score,
                        "reasons": corr.correlation_reasons[:2],
                    },
                    provenance=DataProvenance.LIVE_TELEMETRY,
                )
                self.engine.add_edge(g_edge)
                edges_created += 1

        # ---------------------------------------------------------------------
        # 2. Synchronize to Live Neo4j Aura (if connected)
        # ---------------------------------------------------------------------
        neo4j_synced = False
        if hasattr(self.engine, "is_neo4j_live") and self.engine.is_neo4j_live:
            try:
                sync_res = self.engine.sync_to_neo4j()
                neo4j_synced = sync_res.get("success", False)
                logger.info("Synchronized threat intelligence to live Neo4j Aura: %s", sync_res)
            except Exception as e:
                logger.warning("Neo4j Aura threat intelligence synchronization failed: %s", e)

        return {
            "status": "SYNCHRONIZED",
            "indicators_synced": len(indicators),
            "clusters_synced": len(clusters),
            "correlations_synced": min(50, len(correlations)),
            "graph_nodes_updated": nodes_created,
            "graph_edges_updated": edges_created,
            "neo4j_aura_live": bool(getattr(self.engine, "is_neo4j_live", False)),
            "neo4j_synced": neo4j_synced,
            "synchronized_at": now.isoformat(),
        }
