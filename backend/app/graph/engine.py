"""SafeContain AI Dual-Engine Graph Infrastructure.

Provides an enterprise-grade graph interface supporting both live Neo4j Cypher
and an in-memory NetworkX directed multigraph engine with snapshot cloning.
"""

import copy
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
import networkx as nx

from backend.app.core.config import settings
from backend.app.models.domain import (
    AttackPath,
    DataProvenance,
    EvidenceStatus,
    GraphEdge,
    GraphNode,
    NodeType,
    RelationshipType,
)

logger = logging.getLogger(__name__)


class GraphEngine:
    """Unified Graph Intelligence Engine with Dual-Engine Architecture."""

    def __init__(self, mode: Optional[str] = None):
        self.mode = mode or settings.GRAPH_BACKEND
        self._nx_graph: nx.DiGraph = nx.DiGraph()
        self._node_store: Dict[str, GraphNode] = {}
        self._edge_store: Dict[str, GraphEdge] = {}
        self._neo4j_driver = None
        self._neo4j_available = False

        if self.mode in ("dual", "neo4j"):
            self._init_neo4j_connection()

    def _init_neo4j_connection(self) -> None:
        """Attempts connection to live Neo4j instance if configured and reachable."""
        try:
            from neo4j import GraphDatabase
            driver = GraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
                connection_timeout=settings.NEO4J_CONNECTION_TIMEOUT,
                max_connection_pool_size=settings.NEO4J_MAX_CONNECTION_POOL_SIZE,
            )
            # Verify connectivity
            driver.verify_connectivity()
            self._neo4j_driver = driver
            self._neo4j_available = True
            logger.info("Connected to live Neo4j instance at %s", settings.NEO4J_URI)
        except Exception as e:
            logger.info("Live Neo4j not reachable (%s). Operating in high-performance in-memory graph mode.", str(e))
            self._neo4j_available = False

    @property
    def is_neo4j_live(self) -> bool:
        """Returns True if connected to live Neo4j database."""
        return self._neo4j_available

    def clear(self) -> None:
        """Clears all in-memory graph structures."""
        self._nx_graph.clear()
        self._node_store.clear()
        self._edge_store.clear()

    def add_node(self, node: GraphNode) -> None:
        """Adds or updates a node in the graph."""
        self._node_store[node.id] = node
        self._nx_graph.add_node(
            node.id,
            name=node.name,
            type=node.type.value,
            criticality=node.criticality,
            is_compromised=node.is_compromised,
            is_crown_jewel=node.is_crown_jewel,
            properties=node.properties,
            provenance=node.provenance.value,
        )

    def add_edge(self, edge: GraphEdge) -> None:
        """Adds or updates a directed edge in the graph."""
        self._edge_store[edge.id] = edge
        if edge.is_active:
            self._nx_graph.add_edge(
                edge.source,
                edge.target,
                id=edge.id,
                type=edge.type.value,
                evidence_status=edge.evidence_status.value,
                confidence=edge.confidence,
                weight=edge.weight,
                provenance=edge.provenance.value,
            )

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Retrieves a node by identifier."""
        return self._node_store.get(node_id)

    def get_edge(self, edge_id: str) -> Optional[GraphEdge]:
        """Retrieves an edge by identifier."""
        return self._edge_store.get(edge_id)

    def get_all_nodes(self) -> List[GraphNode]:
        """Returns all nodes registered in the engine."""
        return list(self._node_store.values())

    def get_all_edges(self) -> List[GraphEdge]:
        """Returns all edges registered in the engine."""
        return list(self._edge_store.values())

    def remove_edge(self, edge_id: str) -> bool:
        """Deactivates an edge from the graph traversal topology."""
        if edge_id in self._edge_store:
            edge = self._edge_store[edge_id]
            edge.is_active = False
            if self._nx_graph.has_edge(edge.source, edge.target):
                self._nx_graph.remove_edge(edge.source, edge.target)
            return True
        return False

    def clone_isolated_snapshot(self) -> "GraphEngine":
        """Creates a forensically isolated, deep-copied graph instance for simulation.
        
        Guarantees that simulation interventions NEVER mutate the production graph.
        """
        snapshot = GraphEngine(mode="in_memory")
        snapshot._node_store = {k: v.model_copy(deep=True) for k, v in self._node_store.items()}
        snapshot._edge_store = {k: v.model_copy(deep=True) for k, v in self._edge_store.items()}
        snapshot._nx_graph = self._nx_graph.copy()
        return snapshot

    def find_attack_paths(
        self,
        max_depth: int = 7,
        max_paths_per_pair: int = 10
    ) -> List[AttackPath]:
        """Discovers all directed attack paths from compromised nodes to crown jewels."""
        from backend.app.graph.algorithms import discover_attack_paths
        return discover_attack_paths(self, max_depth, max_paths_per_pair)

    def export_topology(self) -> Dict[str, Any]:
        """Exports graph topology as JSON-serializable dictionary."""
        return {
            "nodes": [n.model_dump(mode="json") for n in self.get_all_nodes()],
            "edges": [e.model_dump(mode="json") for e in self.get_all_edges()],
            "backend": "neo4j_live" if self.is_neo4j_live else "in_memory_networkx",
        }

    def import_topology(self, data: Dict[str, Any]) -> None:
        """Imports graph topology from validated data dictionary."""
        self.clear()
        for raw_node in data.get("nodes", []):
            self.add_node(GraphNode.model_validate(raw_node))
        for raw_edge in data.get("edges", []):
            self.add_edge(GraphEdge.model_validate(raw_edge))
