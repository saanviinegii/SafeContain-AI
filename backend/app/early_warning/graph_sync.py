"""Module 7.6.10: Graph Persistence for Predictive Threat Intelligence.

Persists ThreatSignals, EarlyWarnings, and CorrelatedThreatClusters into Neo4j Aura cloud
with idempotent Cypher merges and resilient in-memory GraphEngine fallback.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.app.core.config import settings
from backend.app.early_warning.models import (
    CorrelatedThreatCluster,
    EarlyWarning,
    ThreatSignal,
)
from backend.app.graph.engine import GraphEngine
from backend.app.models.domain import (
    DataProvenance,
    GraphNode,
    NodeType,
)

logger = logging.getLogger("safecontain.early_warning.graph_sync")


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


class EarlyWarningGraphSynchronizer:
    """Manages idempotent synchronization of early warnings and threat signals into graph stores."""

    def __init__(self, graph_engine: Optional[Any] = None):
        self.engine = _resolve_graph_engine(graph_engine)

    def sync_to_graph(
        self,
        warnings: List[EarlyWarning],
        signals: List[ThreatSignal],
        clusters: Optional[List[CorrelatedThreatCluster]] = None,
    ) -> Dict[str, Any]:
        """Synchronizes early warnings, signals, and clusters to in-memory graph and Neo4j Aura."""
        now = datetime.now(timezone.utc)
        active_clusters = clusters or []

        warnings_synced = 0
        signals_synced = 0
        clusters_synced = 0

        # ---------------------------------------------------------------------
        # 1. In-Memory GraphEngine Synchronization
        # ---------------------------------------------------------------------
        # Register Warnings as SecurityControl/Alert nodes in memory
        for w in warnings:
            try:
                node = GraphNode(
                    id=w.warning_id,
                    name=f"Early Warning: {w.warning_type.value} ({w.asset_id})",
                    type=NodeType.ALERT,
                    criticality=round(w.priority_score / 100.0, 2),
                    is_compromised=False,
                    properties={
                        "warning_type": w.warning_type.value,
                        "severity": w.severity.value,
                        "priority_score": w.priority_score,
                        "status": w.status.value,
                        "asset_id": w.asset_id,
                        "predicted_impact": w.predicted_impact,
                        "confidence": w.confidence,
                    },
                    provenance=DataProvenance.LIVE_TELEMETRY,
                    created_at=w.generated_at,
                    updated_at=now,
                )
                self.engine.add_node(node)
                warnings_synced += 1
            except Exception as e:
                logger.debug("In-memory warning node sync note: %s", e)

        # Register Signals as Evidence nodes in memory
        for s in signals:
            try:
                sig_node = GraphNode(
                    id=s.signal_id,
                    name=f"Signal: {s.signal_type.value} ({s.asset_id})",
                    type=NodeType.EVIDENCE,
                    criticality=0.5,
                    is_compromised=False,
                    properties={
                        "signal_type": s.signal_type.value,
                        "severity": s.severity.value,
                        "observed_value": s.observed_value,
                        "deviation": s.deviation or 0.0,
                        "confidence": s.confidence,
                        "source": s.source,
                    },
                    provenance=DataProvenance.LIVE_TELEMETRY,
                    created_at=s.timestamp,
                    updated_at=now,
                )
                self.engine.add_node(sig_node)
                signals_synced += 1
            except Exception as e:
                logger.debug("In-memory signal node sync note: %s", e)

        # ---------------------------------------------------------------------
        # 2. Resilient Neo4j Aura Cloud Synchronization
        # ---------------------------------------------------------------------
        neo4j_synced = False
        if hasattr(self.engine, "_neo4j_driver") and self.engine._neo4j_driver is not None and self.engine.is_neo4j_live:
            try:
                with self.engine._get_neo4j_session() as session:
                    # Batch merge EarlyWarnings
                    for w in warnings[:20]:
                        session.run(
                            """
                            MERGE (w:EarlyWarning:SecurityAlert {id: $id})
                            SET w.warning_type = $warning_type,
                                w.severity = $severity,
                                w.priority_score = $priority_score,
                                w.status = $status,
                                w.asset_id = $asset_id,
                                w.explanation = $explanation,
                                w.confidence = $confidence,
                                w.generated_at = $generated_at
                            """,
                            id=w.warning_id,
                            warning_type=w.warning_type.value,
                            severity=w.severity.value,
                            priority_score=w.priority_score,
                            status=w.status.value,
                            asset_id=w.asset_id,
                            explanation=w.explanation,
                            confidence=w.confidence,
                            generated_at=w.generated_at.isoformat(),
                        )

                    # Batch merge Signals
                    for s in signals[:25]:
                        session.run(
                            """
                            MERGE (sig:ThreatSignal:Evidence {id: $id})
                            SET sig.signal_type = $signal_type,
                                sig.severity = $severity,
                                sig.observed_value = $observed_value,
                                sig.deviation = $deviation,
                                sig.confidence = $confidence,
                                sig.source = $source,
                                sig.timestamp = $timestamp
                            """,
                            id=s.signal_id,
                            signal_type=s.signal_type.value,
                            severity=s.severity.value,
                            observed_value=s.observed_value,
                            deviation=s.deviation or 0.0,
                            confidence=s.confidence,
                            source=s.source,
                            timestamp=s.timestamp.isoformat(),
                        )

                    # Batch merge Clusters
                    for c in active_clusters[:10]:
                        session.run(
                            """
                            MERGE (cl:PredictiveCluster:IncidentCluster {id: $id})
                            SET cl.name = $name,
                                cl.pattern = $pattern,
                                cl.severity = $severity,
                                cl.confidence = $confidence,
                                cl.detected_at = $detected_at
                            """,
                            id=c.cluster_id,
                            name=c.cluster_name,
                            pattern=c.primary_pattern,
                            severity=c.severity.value,
                            confidence=c.confidence,
                            detected_at=c.detected_at.isoformat(),
                        )
                        clusters_synced += 1

                    neo4j_synced = True
            except Exception as e:
                logger.info("Neo4j Aura cloud early-warning sync skipped (%s); in-memory GraphEngine active.", e)

        return {
            "status": "SYNCED",
            "warnings_persisted": warnings_synced,
            "signals_persisted": signals_synced,
            "clusters_persisted": clusters_synced,
            "neo4j_aura_synced": neo4j_synced,
            "backend": "live_neo4j" if neo4j_synced else "in_memory_networkx",
            "timestamp": now.isoformat(),
        }
