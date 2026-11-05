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
            self.init_neo4j_schema()
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

    def init_neo4j_schema(self) -> None:
        """Initializes constraints and traversal indexes in live Neo4j."""
        if not self.is_neo4j_live or not self._neo4j_driver:
            return
        constraints = [
            "CREATE CONSTRAINT c_host_id IF NOT EXISTS FOR (h:Host) REQUIRE h.id IS UNIQUE",
            "CREATE CONSTRAINT c_server_id IF NOT EXISTS FOR (s:Server) REQUIRE s.id IS UNIQUE",
            "CREATE CONSTRAINT c_endpoint_id IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.id IS UNIQUE",
            "CREATE CONSTRAINT c_database_id IF NOT EXISTS FOR (d:Database) REQUIRE d.id IS UNIQUE",
            "CREATE CONSTRAINT c_user_id IF NOT EXISTS FOR (u:User) REQUIRE u.id IS UNIQUE",
            "CREATE CONSTRAINT c_workflow_id IF NOT EXISTS FOR (w:BusinessWorkflow) REQUIRE w.id IS UNIQUE",
            "CREATE CONSTRAINT c_threat_id IF NOT EXISTS FOR (t:Threat) REQUIRE t.id IS UNIQUE",
        ]
        try:
            with self._neo4j_driver.session(database=settings.NEO4J_DATABASE) as session:
                for statement in constraints:
                    try:
                        session.run(statement)
                    except Exception:
                        pass
        except Exception as e:
            logger.warning("Notice during Neo4j schema constraint initialization: %s", str(e))

    def sync_to_neo4j(self) -> Dict[str, Any]:
        """Synchronizes all in-memory nodes and edges into live Neo4j database."""
        if not self.is_neo4j_live or not self._neo4j_driver:
            return {
                "status": "OFFLINE",
                "message": "Neo4j is not connected. Operating in in-memory mode.",
                "synced_nodes": 0,
                "synced_edges": 0,
            }

        synced_nodes = 0
        synced_edges = 0
        try:
            with self._neo4j_driver.session(database=settings.NEO4J_DATABASE) as session:
                for node in self.get_all_nodes():
                    label = node.type.value if hasattr(node.type, "value") else str(node.type)
                    clean_label = "".join(c for c in label if c.isalnum() or c == "_") or "Node"
                    cypher = f"""
                    MERGE (n:{clean_label} {{id: $id}})
                    SET n.name = $name,
                        n.type = $type,
                        n.criticality = $criticality,
                        n.is_compromised = $is_compromised,
                        n.is_crown_jewel = $is_crown_jewel,
                        n.provenance = $provenance
                    """
                    session.run(
                        cypher,
                        id=node.id,
                        name=node.name,
                        type=clean_label,
                        criticality=node.criticality,
                        is_compromised=node.is_compromised,
                        is_crown_jewel=node.is_crown_jewel,
                        provenance=node.provenance.value if hasattr(node.provenance, "value") else str(node.provenance),
                    )
                    synced_nodes += 1

                for edge in self.get_all_edges():
                    rel_type = edge.type.value if hasattr(edge.type, "value") else str(edge.type)
                    clean_rel = "".join(c for c in rel_type if c.isalnum() or c == "_") or "CONNECTED_TO"
                    cypher = f"""
                    MATCH (s {{id: $source}}), (t {{id: $target}})
                    MERGE (s)-[r:{clean_rel} {{id: $id}}]->(t)
                    SET r.type = $rel_type,
                        r.evidence_status = $evidence_status,
                        r.confidence = $confidence,
                        r.weight = $weight,
                        r.is_active = $is_active,
                        r.provenance = $provenance
                    """
                    session.run(
                        cypher,
                        source=edge.source,
                        target=edge.target,
                        id=edge.id,
                        rel_type=clean_rel,
                        evidence_status=edge.evidence_status.value if hasattr(edge.evidence_status, "value") else str(edge.evidence_status),
                        confidence=float(edge.confidence),
                        weight=float(edge.weight),
                        is_active=bool(edge.is_active),
                        provenance=edge.provenance.value if hasattr(edge.provenance, "value") else str(edge.provenance),
                    )
                    synced_edges += 1

            return {
                "status": "SYNCED",
                "uri": settings.NEO4J_URI,
                "database": settings.NEO4J_DATABASE,
                "synced_nodes": synced_nodes,
                "synced_edges": synced_edges,
            }
        except Exception as e:
            logger.error("Failed to sync topology to Neo4j: %s", str(e))
            return {
                "status": "ERROR",
                "error": str(e),
                "synced_nodes": synced_nodes,
                "synced_edges": synced_edges,
            }

    def get_neo4j_status(self) -> Dict[str, Any]:
        """Queries live connectivity, node count, and edge count from Neo4j."""
        if not self.is_neo4j_live or not self._neo4j_driver:
            return {
                "connected": False,
                "uri": settings.NEO4J_URI,
                "backend": "in_memory_networkx",
                "message": "Neo4j is currently unreachable or unconfigured. Operating in fallback in-memory mode."
            }
        try:
            with self._neo4j_driver.session(database=settings.NEO4J_DATABASE) as session:
                node_res = session.run("MATCH (n) RETURN count(n) as node_count")
                node_count = node_res.single()["node_count"]
                edge_res = session.run("MATCH ()-[r]->() RETURN count(r) as edge_count")
                edge_count = edge_res.single()["edge_count"]
                return {
                    "connected": True,
                    "uri": settings.NEO4J_URI,
                    "database": settings.NEO4J_DATABASE,
                    "backend": "live_neo4j",
                    "neo4j_node_count": node_count,
                    "neo4j_edge_count": edge_count,
                    "in_memory_nodes": len(self._node_store),
                    "in_memory_edges": len(self._edge_store),
                }
        except Exception as e:
            return {
                "connected": False,
                "uri": settings.NEO4J_URI,
                "backend": "in_memory_networkx",
                "error": str(e),
            }

    def load_from_neo4j(self) -> Dict[str, Any]:
        """Imports topology from live Neo4j into in-memory engine."""
        if not self.is_neo4j_live or not self._neo4j_driver:
            return {"status": "OFFLINE", "message": "Neo4j not connected."}
        try:
            loaded_nodes = 0
            loaded_edges = 0
            with self._neo4j_driver.session(database=settings.NEO4J_DATABASE) as session:
                self.clear()
                nodes_res = session.run(
                    "MATCH (n) RETURN n.id as id, n.name as name, n.type as type, "
                    "n.criticality as criticality, n.is_compromised as is_compromised, "
                    "n.is_crown_jewel as is_crown_jewel, n.provenance as provenance, labels(n) as labels"
                )
                for record in nodes_res:
                    nid = record["id"]
                    if not nid:
                        continue
                    type_str = record["type"] or (record["labels"][0] if record["labels"] else "Host")
                    try:
                        ntype = NodeType(type_str)
                    except Exception:
                        ntype = NodeType.HOST
                    prov_str = record["provenance"] or "LIVE_TELEMETRY"
                    try:
                        prov = DataProvenance(prov_str)
                    except Exception:
                        prov = DataProvenance.LIVE_TELEMETRY

                    node = GraphNode(
                        id=nid,
                        name=record["name"] or nid,
                        type=ntype,
                        criticality=float(record["criticality"] or 0.5),
                        is_compromised=bool(record["is_compromised"] or False),
                        is_crown_jewel=bool(record["is_crown_jewel"] or False),
                        provenance=prov,
                    )
                    self.add_node(node)
                    loaded_nodes += 1

                edges_res = session.run(
                    "MATCH (s)-[r]->(t) RETURN r.id as id, s.id as source, t.id as target, "
                    "type(r) as rel_type, r.evidence_status as evidence_status, "
                    "r.confidence as confidence, r.weight as weight, r.is_active as is_active, "
                    "r.provenance as provenance"
                )
                for record in edges_res:
                    if not record["source"] or not record["target"]:
                        continue
                    eid = record["id"] or f"edge-{record['source']}-{record['target']}"
                    r_str = record["rel_type"] or "CONNECTED_TO"
                    try:
                        rtype = RelationshipType(r_str)
                    except Exception:
                        rtype = RelationshipType.CONNECTED_TO
                    ev_str = record["evidence_status"] or "CONFIRMED"
                    try:
                        ev_status = EvidenceStatus(ev_str)
                    except Exception:
                        ev_status = EvidenceStatus.CONFIRMED
                    prov_str = record["provenance"] or "LIVE_TELEMETRY"
                    try:
                        prov = DataProvenance(prov_str)
                    except Exception:
                        prov = DataProvenance.LIVE_TELEMETRY

                    edge = GraphEdge(
                        id=eid,
                        source=record["source"],
                        target=record["target"],
                        type=rtype,
                        evidence_status=ev_status,
                        confidence=float(record["confidence"] or 1.0),
                        weight=float(record["weight"] or 1.0),
                        is_active=bool(record["is_active"] if record["is_active"] is not None else True),
                        provenance=prov,
                    )
                    self.add_edge(edge)
                    loaded_edges += 1

            return {
                "status": "LOADED",
                "loaded_nodes": loaded_nodes,
                "loaded_edges": loaded_edges,
            }
        except Exception as e:
            logger.error("Failed to load topology from Neo4j: %s", str(e))
            return {"status": "ERROR", "error": str(e)}
