"""Neo4j & GraphEngine Persistence for Prediction Outcomes & Feedback (Phase 7.4).

Idempotently synchronizes evaluated prediction outcomes, model versions, and observed telemetry linkages
into the SafeContain AI graph store (Neo4j Aura cloud with seamless in-memory fallback).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.app.adaptive.models import PredictionRecord
from backend.app.models.domain import (
    DataProvenance,
    EvidenceStatus,
    GraphEdge,
    GraphNode,
    NodeType,
    RelationshipType,
)

logger = logging.getLogger("safecontain.adaptive.graph_sync")


class AdaptiveGraphSynchronizer:
    """Manages idempotent graph synchronization of prediction outcomes and evaluation links."""

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

    def sync_outcomes_to_graph(self, records: List[PredictionRecord]) -> Dict[str, Any]:
        """Synchronizes evaluated predictions and their asset linkages into GraphEngine and Neo4j Aura."""
        now = datetime.now(timezone.utc)
        nodes_created = 0
        edges_created = 0

        if not self.engine:
            return {
                "status": "SKIPPED",
                "message": "GraphEngine not initialized in current context.",
                "records_synced": 0,
            }

        # ---------------------------------------------------------------------
        # 1. Update In-Memory GraphEngine Store
        # ---------------------------------------------------------------------
        for r in records:
            p_node_id = f"pred-node-{r.prediction_id}"
            is_error = r.outcome_status.value in ("FALSE_POSITIVE", "FALSE_NEGATIVE")
            crit = 0.9 if r.outcome_status.value == "CONFIRMED_COMPROMISE" else 0.5 if is_error else 0.3

            pred_node = GraphNode(
                id=p_node_id,
                name=f"Forecast: {r.asset_name} ({r.forecast_horizon})",
                type=NodeType.EVIDENCE,
                criticality=crit,
                is_compromised=bool(r.actual_outcome == "COMPROMISED"),
                properties={
                    "prediction_id": r.prediction_id,
                    "target_asset_id": r.asset_id,
                    "forecast_horizon": r.forecast_horizon,
                    "horizon_hours": r.horizon_hours,
                    "predicted_probability": r.predicted_probability,
                    "predicted_risk_score": r.predicted_risk_score,
                    "outcome_status": r.outcome_status.value,
                    "actual_outcome": r.actual_outcome or "PENDING",
                    "model_version": r.model_version,
                    "operating_threshold": r.operating_threshold,
                },
                provenance=DataProvenance.LIVE_TELEMETRY,
                created_at=r.prediction_timestamp,
                updated_at=r.outcome_evaluation_timestamp or now,
            )
            self.engine.add_node(pred_node)
            nodes_created += 1

            # Update target asset node with outcome tracking metadata
            target_asset_node = self.engine.get_node(r.asset_id)
            if target_asset_node is not None:
                if not hasattr(target_asset_node, "properties") or target_asset_node.properties is None:
                    target_asset_node.properties = {}
                target_asset_node.properties["adaptive_outcome_status"] = r.outcome_status.value
                target_asset_node.properties["adaptive_predicted_probability"] = r.predicted_probability

            # Edge from Prediction to Target Asset (PREDICTED_FOR)
            if self.engine.get_node(r.asset_id) is not None:
                edge_id = f"edge-pred-{r.prediction_id}-{r.asset_id}"
                g_edge = GraphEdge(
                    id=edge_id,
                    source=p_node_id,
                    target=r.asset_id,
                    type=RelationshipType.ASSOCIATED_WITH,
                    evidence_status=EvidenceStatus.CONFIRMED if r.outcome_status.value == "CONFIRMED_COMPROMISE" else EvidenceStatus.HYPOTHETICAL,
                    confidence=r.predicted_probability,
                    weight=round(r.predicted_probability, 2),
                    properties={
                        "relationship": "FORECAST_TARGET",
                        "outcome_status": r.outcome_status.value,
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
                logger.info("Synchronized prediction outcomes to live Neo4j Aura: %s", sync_res)
            except Exception as e:
                logger.warning("Neo4j Aura synchronization failed: %s", e)

        return {
            "status": "SYNCHRONIZED",
            "records_synced": len(records),
            "nodes_updated": nodes_created,
            "graph_nodes_updated": nodes_created,
            "edges_updated": edges_created,
            "graph_edges_updated": edges_created,
            "neo4j_aura_live": bool(getattr(self.engine, "is_neo4j_live", False)),
            "neo4j_synced": neo4j_synced,
            "synchronized_at": now.isoformat(),
        }
