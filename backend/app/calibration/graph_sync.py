"""Module 7.5.8: Graph Persistence for Risk Calibration & Threshold Policies.

Synchronizes versioned ThresholdConfigurations, calibration policies, and evidence linkages
into the SafeContain AI GraphEngine and Neo4j Aura cloud graph with resilient offline fallback.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.app.calibration.models import ThresholdConfiguration
from backend.app.models.domain import (
    DataProvenance,
    GraphEdge,
    GraphNode,
    NodeType,
    RelationshipType,
)

logger = logging.getLogger("safecontain.calibration.graph_sync")


class CalibrationGraphSynchronizer:
    """Manages idempotent synchronization of calibration policies and threshold metadata into graph stores."""

    def __init__(self, graph_engine=None):
        if graph_engine is None:
            try:
                from backend.app.api.v1.router import platform_ctx
                self.engine = platform_ctx.engine
            except Exception:
                try:
                    from backend.app.graph.engine import GraphEngine
                    self.engine = GraphEngine(mode="in_memory")
                except Exception:
                    self.engine = None
        else:
            self.engine = graph_engine

    def sync_configuration_to_graph(
        self,
        config: ThresholdConfiguration,
        target_asset_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Synchronizes an active or staged ThresholdConfiguration into GraphEngine and Neo4j."""
        now = datetime.now(timezone.utc)
        nodes_created = 0
        edges_created = 0

        if not self.engine:
            return {
                "status": "SKIPPED",
                "message": "GraphEngine not available in current execution context.",
                "config_id": config.config_id,
            }

        # ---------------------------------------------------------------------
        # 1. Update In-Memory GraphEngine Store
        # ---------------------------------------------------------------------
        policy_node_id = f"policy-{config.config_id}"
        policy_node = GraphNode(
            id=policy_node_id,
            name=f"Threshold Policy: v{config.version} (theta={config.operating_threshold:.2f})",
            type=NodeType.SECURITY_CONTROL,
            criticality=0.8,
            is_compromised=False,
            properties={
                "config_id": config.config_id,
                "version": config.version,
                "operating_threshold": config.operating_threshold,
                "low_cutoff": config.tiers.low_cutoff,
                "medium_cutoff": config.tiers.medium_cutoff,
                "high_cutoff": config.tiers.high_cutoff,
                "critical_cutoff": config.tiers.critical_cutoff,
                "status": config.status.value,
                "rationale": config.rationale,
                "author_id": config.author_id,
                "author_role": config.author_role,
            },
            provenance=DataProvenance.LIVE_TELEMETRY,
            created_at=config.created_at,
            updated_at=now,
        )
        self.engine.add_node(policy_node)
        nodes_created += 1

        # Determine target assets to link (defaults to all known host/server nodes in graph)
        if target_asset_ids is None:
            all_nodes = self.engine.get_all_nodes()
            target_asset_ids = [n.id for n in all_nodes if n.type in (NodeType.SERVER, NodeType.HOST, NodeType.DATABASE, NodeType.ENDPOINT)]

        for aid in target_asset_ids:
            asset_node = self.engine.get_node(aid)
            if asset_node is not None:
                if not hasattr(asset_node, "properties") or asset_node.properties is None:
                    asset_node.properties = {}
                asset_node.properties["risk_operating_threshold"] = config.operating_threshold
                asset_node.properties["calibration_policy_version"] = config.version
                asset_node.properties["calibration_status"] = config.status.value

                # Link Policy -> Asset
                edge_id = f"edge-policy-{config.config_id}-{aid}"
                edge = GraphEdge(
                    id=edge_id,
                    source_id=policy_node_id,
                    target_id=aid,
                    relationship=RelationshipType.CONTROLLED_BY,
                    weight=1.0,
                    properties={
                        "policy_version": config.version,
                        "operating_threshold": config.operating_threshold,
                    },
                    created_at=now,
                )
                self.engine.add_edge(edge)
                edges_created += 1

        # ---------------------------------------------------------------------
        # 2. Resilient Neo4j Aura Cloud Synchronization
        # ---------------------------------------------------------------------
        neo4j_synced = False
        try:
            if hasattr(self.engine, "_neo4j_driver") and self.engine._neo4j_driver is not None:
                with self.engine._neo4j_driver.session() as session:
                    # Merge Policy node
                    session.run(
                        """
                        MERGE (p:Policy:SecurityControl {id: $id})
                        SET p.name = $name,
                            p.version = $version,
                            p.operating_threshold = $operating_threshold,
                            p.low_cutoff = $low_cutoff,
                            p.medium_cutoff = $medium_cutoff,
                            p.high_cutoff = $high_cutoff,
                            p.critical_cutoff = $critical_cutoff,
                            p.status = $status,
                            p.rationale = $rationale,
                            p.updated_at = $updated_at
                        """,
                        id=policy_node_id,
                        name=policy_node.name,
                        version=config.version,
                        operating_threshold=config.operating_threshold,
                        low_cutoff=config.tiers.low_cutoff,
                        medium_cutoff=config.tiers.medium_cutoff,
                        high_cutoff=config.tiers.high_cutoff,
                        critical_cutoff=config.tiers.critical_cutoff,
                        status=config.status.value,
                        rationale=config.rationale,
                        updated_at=now.isoformat(),
                    )

                    # Update asset relationships in batch
                    for aid in target_asset_ids[:25]: # Batch top 25 to optimize network
                        session.run(
                            """
                            MATCH (p:Policy {id: $p_id})
                            MATCH (a:Asset {id: $a_id})
                            MERGE (p)-[r:APPLIES_TO]->(a)
                            SET a.risk_operating_threshold = $operating_threshold,
                                a.calibration_policy_version = $version,
                                r.updated_at = $updated_at
                            """,
                            p_id=policy_node_id,
                            a_id=aid,
                            operating_threshold=config.operating_threshold,
                            version=config.version,
                            updated_at=now.isoformat(),
                        )
                    neo4j_synced = True
        except Exception as e:
            logger.info("Neo4j Aura cloud sync skipped (%s); in-memory GraphEngine persistence active.", e)

        return {
            "status": "SYNCED",
            "config_id": config.config_id,
            "version": config.version,
            "nodes_created": nodes_created,
            "edges_created": edges_created,
            "neo4j_cloud_synced": neo4j_synced,
            "timestamp": now.isoformat(),
        }

