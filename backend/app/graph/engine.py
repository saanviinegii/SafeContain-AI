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


def _clean_properties_map(raw_props: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Prepares extended property map containing only primitive types safe for Cypher."""
    if not isinstance(raw_props, dict):
        return {}
    clean = {}
    for k, v in raw_props.items():
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            clean[k] = v
        elif isinstance(v, (list, set, tuple)):
            clean[k] = [str(x) for x in v]
        else:
            clean[k] = str(v)
    return clean


class GraphEngine:
    """Unified Graph Intelligence Engine with Dual-Engine Architecture."""

    def __init__(self, mode: Optional[str] = None):
        self.mode = mode or settings.GRAPH_BACKEND
        self._nx_graph: nx.DiGraph = nx.DiGraph()
        self._node_store: Dict[str, GraphNode] = {}
        self._edge_store: Dict[str, GraphEdge] = {}
        self._neo4j_driver = None
        self._neo4j_available = False
        self._last_connection_error: Optional[str] = None
        self._active_database: Optional[str] = None

        if self.mode in ("dual", "neo4j"):
            self._init_neo4j_connection()

    def _init_neo4j_connection(self) -> None:
        """Attempts connection to live Neo4j instance if configured and reachable."""
        redacted_uri = settings.NEO4J_URI.split("@")[-1] if "@" in settings.NEO4J_URI else settings.NEO4J_URI
        print(f"[SAFECONTAIN NEO4J] Initializing driver: mode={self.mode}, uri={redacted_uri}, user={settings.NEO4J_USER}")
        try:
            from neo4j import GraphDatabase
            from neo4j.exceptions import AuthError, ServiceUnavailable
            driver = None
            last_err = None

            # Prepare prioritized list of secure Aura connection protocols
            candidate_uris = [settings.NEO4J_URI]
            if settings.NEO4J_URI.startswith("neo4j+s://"):
                candidate_uris.append(settings.NEO4J_URI.replace("neo4j+s://", "neo4j+ssc://"))
                host = settings.NEO4J_URI.split("://")[-1].split(":")[0]
                candidate_uris.append(f"bolt+ssc://{host}:7687")
                candidate_uris.append(f"bolt+s://{host}:7687")
            elif settings.NEO4J_URI.startswith("bolt+s://"):
                candidate_uris.append(settings.NEO4J_URI.replace("bolt+s://", "bolt+ssc://"))

            timeout_sec = min(3.0, float(getattr(settings, "NEO4J_CONNECTION_TIMEOUT", 8.0) or 3.0))
            for cand_uri in candidate_uris:
                try:
                    cand = GraphDatabase.driver(
                        cand_uri,
                        auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
                        connection_timeout=timeout_sec,
                        max_connection_pool_size=settings.NEO4J_MAX_CONNECTION_POOL_SIZE,
                    )
                    cand.verify_connectivity()
                    driver = cand
                    break
                except Exception as cand_err:
                    last_err = cand_err
                    # If authentication was rejected or DNS cannot resolve hostname, abort candidate loop immediately
                    err_str = str(cand_err)
                    if isinstance(cand_err, AuthError) or "Unauthorized" in err_str or "getaddrinfo failed" in err_str or "Name or service not known" in err_str:
                        break

            if not driver:
                raise last_err or RuntimeError("Failed to establish Neo4j driver connection")

            # Discover active database name dynamically without assuming instance ID
            self._active_database = None
            db_candidates = []
            if settings.NEO4J_DATABASE:
                db_candidates.append(settings.NEO4J_DATABASE)
            if settings.AURA_INSTANCEID and settings.AURA_INSTANCEID not in db_candidates:
                db_candidates.append(settings.AURA_INSTANCEID)
            db_candidates.append("neo4j")

            # Probe candidate databases with RETURN 1 AS connection_test
            for db in db_candidates:
                try:
                    with driver.session(database=db) as s:
                        probe_res = s.run("RETURN 1 AS connection_test").single()
                        if probe_res and probe_res["connection_test"] == 1:
                            self._active_database = db
                            break
                except Exception:
                    pass

            if not self._active_database:
                try:
                    with driver.session() as s:
                        probe_res = s.run("RETURN 1 AS connection_test").single()
                        if not probe_res or probe_res["connection_test"] != 1:
                            raise RuntimeError("Verification Cypher query 'RETURN 1 AS connection_test' failed")
                        try:
                            db_info = s.run("CALL db.info() YIELD name RETURN name").single()
                            if db_info and db_info["name"]:
                                self._active_database = str(db_info["name"])
                        except Exception:
                            pass
                except Exception as probe_err:
                    raise probe_err

            self._neo4j_driver = driver
            self._neo4j_available = True
            self._last_connection_error = None
            logger.info("Connected to live Neo4j instance at %s (database: %s)", settings.NEO4J_URI, self._active_database)
            print(f"[SAFECONTAIN NEO4J] SUCCESS: Driver connected and verified to {redacted_uri} (active database: '{self._active_database}')")
            self.init_neo4j_schema()
        except Exception as e:
            self._neo4j_available = False
            self._last_connection_error = str(e)
            print(f"[SAFECONTAIN NEO4J] ERROR: Failed to connect to Neo4j Aura at {redacted_uri}: {str(e)}")
            if self.mode == "neo4j":
                print(f"[SAFECONTAIN NEO4J] CRITICAL: GRAPH_BACKEND='neo4j' requires live Neo4j. System marked DEGRADED.")
                logger.error(
                    "Configured GRAPH_BACKEND is 'neo4j', but Neo4j is unreachable at %s: %s. Status marked as DEGRADED.",
                    settings.NEO4J_URI, str(e)
                )
            else:
                print(f"[SAFECONTAIN NEO4J] Operating in resilient DUAL fallback mode (NetworkX in-memory active).")
                logger.info(
                    "Live Neo4j not reachable (%s). Operating in high-performance in-memory graph mode.", str(e)
                )

    def _get_neo4j_session(self):
        """Returns a session targeting the verified database, or default database if none specified."""
        if not self._neo4j_driver:
            raise RuntimeError("Neo4j driver is not initialized")
        if self._active_database:
            return self._neo4j_driver.session(database=self._active_database)
        return self._neo4j_driver.session()

    @property
    def active_database(self) -> Optional[str]:
        """Returns the verified active database name in Neo4j."""
        return self._active_database

    @property
    def is_neo4j_live(self) -> bool:
        """Returns True if connected to live Neo4j database."""
        return self._neo4j_available

    @property
    def last_connection_error(self) -> Optional[str]:
        """Returns the most recent connection failure error message, if any."""
        return self._last_connection_error

    def clear(self) -> None:
        """Clears all in-memory graph structures."""
        self._nx_graph.clear()
        self._node_store.clear()
        self._edge_store.clear()

    def add_node(self, node: GraphNode, persist_to_neo4j: bool = False) -> None:
        """Adds or updates a node in the in-memory graph, optionally persisting to Neo4j."""
        dataset_id = node.dataset_id or node.properties.get("dataset_id")
        source_file = node.source_file or node.properties.get("source_file") or node.properties.get("source_dataset")
        batch_id = node.ingestion_batch_id or node.properties.get("upload_batch_id")
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
            dataset_id=dataset_id,
            source_file=source_file,
            ingestion_batch_id=batch_id,
            is_demo=node.is_demo,
        )
        if persist_to_neo4j and self.is_neo4j_live:
            self.create_or_update_node_in_neo4j(node)

    def add_edge(self, edge: GraphEdge, persist_to_neo4j: bool = False) -> None:
        """Adds or updates a directed edge in the in-memory graph, optionally persisting to Neo4j."""
        dataset_id = edge.dataset_id or edge.properties.get("dataset_id")
        source_file = edge.source_file or edge.properties.get("source_file") or edge.properties.get("source_filename")
        batch_id = edge.ingestion_batch_id or edge.properties.get("upload_batch_id")
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
                dataset_id=dataset_id,
                source_file=source_file,
                ingestion_batch_id=batch_id,
                is_demo=edge.is_demo,
            )
        if persist_to_neo4j and self.is_neo4j_live:
            self.create_or_update_edge_in_neo4j(edge)

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

    def export_topology(self, dataset_id: Optional[str] = None) -> Dict[str, Any]:
        """Exports graph topology as JSON-serializable dictionary.
        
        Supports dataset-scoped filtering:
        - If dataset_id is provided and not 'all': filters nodes and edges strictly belonging to that dataset.
        - If dataset_id is None or 'all': returns all currently loaded nodes and edges.
        """
        all_nodes = self.get_all_nodes()
        all_edges = self.get_all_edges()

        if dataset_id and dataset_id != "all":
            filtered_nodes = [
                n for n in all_nodes
                if (n.dataset_id == dataset_id or n.properties.get("dataset_id") == dataset_id or n.properties.get("upload_batch_id") == dataset_id)
            ]
            node_id_set = {n.id for n in filtered_nodes}
            filtered_edges = [
                e for e in all_edges
                if (
                    e.dataset_id == dataset_id or
                    e.properties.get("dataset_id") == dataset_id or
                    e.properties.get("upload_batch_id") == dataset_id or
                    (e.source in node_id_set and e.target in node_id_set)
                )
            ]
            return {
                "nodes": [n.model_dump(mode="json") for n in filtered_nodes],
                "edges": [e.model_dump(mode="json") for e in filtered_edges],
                "dataset_id": dataset_id,
                "backend": "neo4j_live" if self.is_neo4j_live else "in_memory_networkx",
            }

        return {
            "nodes": [n.model_dump(mode="json") for n in all_nodes],
            "edges": [e.model_dump(mode="json") for e in all_edges],
            "dataset_id": "all",
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
            "CREATE CONSTRAINT c_device_id IF NOT EXISTS FOR (dev:Device) REQUIRE dev.id IS UNIQUE",
            "CREATE CONSTRAINT c_database_id IF NOT EXISTS FOR (d:Database) REQUIRE d.id IS UNIQUE",
            "CREATE CONSTRAINT c_user_id IF NOT EXISTS FOR (u:User) REQUIRE u.id IS UNIQUE",
            "CREATE CONSTRAINT c_permission_id IF NOT EXISTS FOR (p:Permission) REQUIRE p.id IS UNIQUE",
            "CREATE CONSTRAINT c_alert_id IF NOT EXISTS FOR (a:Alert) REQUIRE a.id IS UNIQUE",
            "CREATE CONSTRAINT c_workflow_id IF NOT EXISTS FOR (w:BusinessWorkflow) REQUIRE w.id IS UNIQUE",
            "CREATE CONSTRAINT c_threat_id IF NOT EXISTS FOR (t:Threat) REQUIRE t.id IS UNIQUE",
        ]
        indexes = [
            "CREATE INDEX idx_host_compromised IF NOT EXISTS FOR (h:Host) ON (h.is_compromised)",
            "CREATE INDEX idx_server_crown_jewel IF NOT EXISTS FOR (s:Server) ON (s.is_crown_jewel)",
            "CREATE INDEX idx_db_crown_jewel IF NOT EXISTS FOR (d:Database) ON (d.is_crown_jewel)",
            "CREATE INDEX idx_host_dataset IF NOT EXISTS FOR (h:Host) ON (h.dataset_id)",
            "CREATE INDEX idx_server_dataset IF NOT EXISTS FOR (s:Server) ON (s.dataset_id)",
            "CREATE INDEX idx_endpoint_dataset IF NOT EXISTS FOR (e:Endpoint) ON (e.dataset_id)",
            "CREATE INDEX idx_device_dataset IF NOT EXISTS FOR (d:Device) ON (d.dataset_id)",
            "CREATE INDEX idx_node_dataset IF NOT EXISTS FOR (n:Node) ON (n.dataset_id)",
        ]
        try:
            with self._get_neo4j_session() as session:
                for statement in constraints + indexes:
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
            with self._get_neo4j_session() as session:
                for node in self.get_all_nodes():
                    label = node.type.value if hasattr(node.type, "value") else str(node.type)
                    clean_label = "".join(c for c in label if c.isalnum() or c == "_") or "Node"
                    props = _clean_properties_map(node.properties)
                    did = node.dataset_id or node.properties.get("dataset_id") or ""
                    src_f = node.source_file or node.properties.get("source_file") or node.properties.get("source_dataset") or ""
                    bid = node.ingestion_batch_id or node.properties.get("upload_batch_id") or ""
                    cypher = f"""
                    MERGE (n:{clean_label} {{id: $id}})
                    SET n.name = $name,
                        n.type = $type,
                        n.criticality = $criticality,
                        n.is_compromised = $is_compromised,
                        n.is_crown_jewel = $is_crown_jewel,
                        n.provenance = $provenance,
                        n.dataset_id = $dataset_id,
                        n.source_file = $source_file,
                        n.ingestion_batch_id = $batch_id,
                        n.is_demo = $is_demo
                    SET n += $props
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
                        dataset_id=did,
                        source_file=src_f,
                        batch_id=bid,
                        is_demo=bool(node.is_demo),
                        props=props,
                    )
                    synced_nodes += 1

                for edge in self.get_all_edges():
                    rel_type = edge.type.value if hasattr(edge.type, "value") else str(edge.type)
                    clean_rel = "".join(c for c in rel_type if c.isalnum() or c == "_") or "CONNECTED_TO"
                    props = _clean_properties_map(edge.properties)
                    did = edge.dataset_id or edge.properties.get("dataset_id") or ""
                    src_f = edge.source_file or edge.properties.get("source_file") or edge.properties.get("source_filename") or ""
                    bid = edge.ingestion_batch_id or edge.properties.get("upload_batch_id") or ""
                    cypher = f"""
                    MATCH (s {{id: $source}}), (t {{id: $target}})
                    MERGE (s)-[r:{clean_rel} {{id: $id}}]->(t)
                    SET r.type = $rel_type,
                        r.evidence_status = $evidence_status,
                        r.confidence = $confidence,
                        r.weight = $weight,
                        r.is_active = $is_active,
                        r.provenance = $provenance,
                        r.dataset_id = $dataset_id,
                        r.source_file = $source_file,
                        r.ingestion_batch_id = $batch_id,
                        r.is_demo = $is_demo
                    SET r += $props
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
                        dataset_id=did,
                        source_file=src_f,
                        batch_id=bid,
                        is_demo=bool(edge.is_demo),
                        props=props,
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
        redacted_uri = settings.NEO4J_URI.split("@")[-1] if "@" in settings.NEO4J_URI else settings.NEO4J_URI
        if not self.is_neo4j_live or not self._neo4j_driver:
            is_auth_error = "Unauthorized" in (self.last_connection_error or "") or "authentication" in (self.last_connection_error or "").lower()
            status_val = "AUTHENTICATION_FAILED" if is_auth_error else ("DEGRADED" if self.mode == "neo4j" else "OFFLINE_FALLBACK")
            return {
                "connected": False,
                "configured_backend": self.mode,
                "active_engine": "in_memory_networkx",
                "status": status_val,
                "uri": redacted_uri,
                "database": self._active_database or settings.NEO4J_DATABASE,
                "last_error": self.last_connection_error,
                "message": (
                    "CRITICAL: Neo4j authentication failed with credentials in .env. Verify NEO4J_USER and NEO4J_PASSWORD."
                    if is_auth_error
                    else ("CRITICAL: Neo4j is required by GRAPH_BACKEND=neo4j but live connection failed. Running in degraded state."
                          if self.mode == "neo4j"
                          else "Neo4j Aura is currently unreachable or unconfigured. Operating in resilient dual fallback in-memory mode.")
                ),
                "in_memory_nodes": len(self._node_store),
                "in_memory_edges": len(self._edge_store),
            }
        try:
            with self._get_neo4j_session() as session:
                node_res = session.run("MATCH (n) RETURN count(n) as node_count")
                node_count = node_res.single()["node_count"]
                edge_res = session.run("MATCH ()-[r]->() RETURN count(r) as edge_count")
                edge_count = edge_res.single()["edge_count"]
                return {
                    "connected": True,
                    "configured_backend": self.mode,
                    "active_engine": "live_neo4j",
                    "status": "CONNECTED",
                    "uri": redacted_uri,
                    "database": self._active_database or settings.NEO4J_DATABASE,
                    "neo4j_node_count": node_count,
                    "neo4j_edge_count": edge_count,
                    "in_memory_nodes": len(self._node_store),
                    "in_memory_edges": len(self._edge_store),
                }
        except Exception as e:
            return {
                "connected": False,
                "configured_backend": self.mode,
                "active_engine": "in_memory_networkx",
                "status": "DEGRADED",
                "uri": redacted_uri,
                "database": self._active_database or settings.NEO4J_DATABASE,
                "last_error": str(e),
                "message": f"Connection lost during status query: {str(e)}",
            }

    def load_from_neo4j(self) -> Dict[str, Any]:
        """Imports topology from live Neo4j into in-memory engine."""
        if not self.is_neo4j_live or not self._neo4j_driver:
            return {"status": "OFFLINE", "message": "Neo4j not connected."}
        try:
            loaded_nodes = 0
            loaded_edges = 0
            with self._get_neo4j_session() as session:
                self.clear()
                reserved_node_keys = {"id", "name", "type", "criticality", "is_compromised", "is_crown_jewel", "provenance", "dataset_id", "source_file", "ingestion_batch_id", "is_demo"}
                reserved_edge_keys = {"id", "source", "target", "type", "evidence_status", "confidence", "weight", "is_active", "provenance", "dataset_id", "source_file", "ingestion_batch_id", "is_demo"}
                nodes_res = session.run(
                    "MATCH (n) RETURN n.id as id, n.name as name, n.type as type, "
                    "n.criticality as criticality, n.is_compromised as is_compromised, "
                    "n.is_crown_jewel as is_crown_jewel, n.provenance as provenance, "
                    "n.dataset_id as dataset_id, n.source_file as source_file, "
                    "n.ingestion_batch_id as ingestion_batch_id, n.is_demo as is_demo, "
                    "properties(n) as props, labels(n) as labels"
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

                    raw_props = record.get("props") or {}
                    ext_props = {k: v for k, v in raw_props.items() if k not in reserved_node_keys}

                    node = GraphNode(
                        id=nid,
                        name=record["name"] or nid,
                        type=ntype,
                        criticality=float(record["criticality"] or 0.5),
                        is_compromised=bool(record["is_compromised"] or False),
                        is_crown_jewel=bool(record["is_crown_jewel"] or False),
                        provenance=prov,
                        dataset_id=record.get("dataset_id") or ext_props.get("dataset_id"),
                        source_file=record.get("source_file") or ext_props.get("source_file"),
                        ingestion_batch_id=record.get("ingestion_batch_id") or ext_props.get("upload_batch_id"),
                        is_demo=bool(record.get("is_demo") or False),
                        properties=ext_props,
                    )
                    self.add_node(node)
                    loaded_nodes += 1

                edges_res = session.run(
                    "MATCH (s)-[r]->(t) RETURN r.id as id, s.id as source, t.id as target, "
                    "type(r) as rel_type, r.evidence_status as evidence_status, "
                    "r.confidence as confidence, r.weight as weight, r.is_active as is_active, "
                    "r.provenance as provenance, r.dataset_id as dataset_id, "
                    "r.source_file as source_file, r.ingestion_batch_id as ingestion_batch_id, "
                    "r.is_demo as is_demo, properties(r) as props"
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

                    raw_props = record.get("props") or {}
                    ext_props = {k: v for k, v in raw_props.items() if k not in reserved_edge_keys}

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
                        dataset_id=record.get("dataset_id") or ext_props.get("dataset_id"),
                        source_file=record.get("source_file") or ext_props.get("source_file"),
                        ingestion_batch_id=record.get("ingestion_batch_id") or ext_props.get("upload_batch_id"),
                        is_demo=bool(record.get("is_demo") or False),
                        properties=ext_props,
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

    def create_or_update_node_in_neo4j(self, node: GraphNode) -> bool:
        """Persists or updates an individual node in live Neo4j."""
        if not self.is_neo4j_live or not self._neo4j_driver:
            return False
        label = node.type.value if hasattr(node.type, "value") else str(node.type)
        clean_label = "".join(c for c in label if c.isalnum() or c == "_") or "Node"
        props = _clean_properties_map(node.properties)
        did = node.dataset_id or node.properties.get("dataset_id") or ""
        src_f = node.source_file or node.properties.get("source_file") or node.properties.get("source_dataset") or ""
        bid = node.ingestion_batch_id or node.properties.get("upload_batch_id") or ""

        cypher = f"""
        MERGE (n:{clean_label} {{id: $id}})
        SET n.name = $name,
            n.type = $type,
            n.criticality = $criticality,
            n.is_compromised = $is_compromised,
            n.is_crown_jewel = $is_crown_jewel,
            n.provenance = $provenance,
            n.dataset_id = $dataset_id,
            n.source_file = $source_file,
            n.ingestion_batch_id = $batch_id,
            n.is_demo = $is_demo
        SET n += $props
        """
        try:
            with self._get_neo4j_session() as session:
                session.run(
                    cypher,
                    id=node.id,
                    name=node.name,
                    type=clean_label,
                    criticality=node.criticality,
                    is_compromised=node.is_compromised,
                    is_crown_jewel=node.is_crown_jewel,
                    provenance=node.provenance.value if hasattr(node.provenance, "value") else str(node.provenance),
                    dataset_id=did,
                    source_file=src_f,
                    batch_id=bid,
                    is_demo=bool(node.is_demo),
                    props=props,
                )
            return True
        except Exception as e:
            logger.error("Failed to persist node %s to Neo4j: %s", node.id, str(e))
            return False

    def get_node_from_neo4j(self, node_id: str) -> Optional[GraphNode]:
        """Retrieves an individual node from live Neo4j by ID."""
        if not self.is_neo4j_live or not self._neo4j_driver:
            return None
        cypher = "MATCH (n {id: $id}) RETURN n.id as id, n.name as name, n.type as type, n.criticality as criticality, n.is_compromised as is_compromised, n.is_crown_jewel as is_crown_jewel, n.provenance as provenance, properties(n) as props, labels(n) as labels"
        reserved_node_keys = {"id", "name", "type", "criticality", "is_compromised", "is_crown_jewel", "provenance"}
        try:
            with self._get_neo4j_session() as session:
                result = session.run(cypher, id=node_id)
                rec = result.single()
                if not rec:
                    return None
                type_str = rec["type"] or (rec["labels"][0] if rec["labels"] else "Host")
                try:
                    ntype = NodeType(type_str)
                except Exception:
                    ntype = NodeType.HOST
                prov_str = rec["provenance"] or "LIVE_TELEMETRY"
                try:
                    prov = DataProvenance(prov_str)
                except Exception:
                    prov = DataProvenance.LIVE_TELEMETRY
                raw_props = rec.get("props") or {}
                ext_props = {k: v for k, v in raw_props.items() if k not in reserved_node_keys}
                return GraphNode(
                    id=rec["id"],
                    name=rec["name"] or rec["id"],
                    type=ntype,
                    criticality=float(rec["criticality"] or 0.5),
                    is_compromised=bool(rec["is_compromised"] or False),
                    is_crown_jewel=bool(rec["is_crown_jewel"] or False),
                    provenance=prov,
                    properties=ext_props,
                )
        except Exception as e:
            logger.error("Failed to retrieve node %s from Neo4j: %s", node_id, str(e))
            return None

    def delete_node_from_neo4j(self, node_id: str) -> bool:
        """Deletes a node and all its incident relationships from live Neo4j."""
        if not self.is_neo4j_live or not self._neo4j_driver:
            return False
        cypher = "MATCH (n {id: $id}) DETACH DELETE n"
        try:
            with self._get_neo4j_session() as session:
                session.run(cypher, id=node_id)
            return True
        except Exception as e:
            logger.error("Failed to delete node %s from Neo4j: %s", node_id, str(e))
            return False

    def create_or_update_edge_in_neo4j(self, edge: GraphEdge) -> bool:
        """Persists or updates an individual relationship in live Neo4j."""
        if not self.is_neo4j_live or not self._neo4j_driver:
            return False
        rel_type = edge.type.value if hasattr(edge.type, "value") else str(edge.type)
        clean_rel = "".join(c for c in rel_type if c.isalnum() or c == "_") or "CONNECTED_TO"
        props = _clean_properties_map(edge.properties)
        did = edge.dataset_id or edge.properties.get("dataset_id") or ""
        src_f = edge.source_file or edge.properties.get("source_file") or edge.properties.get("source_filename") or ""
        bid = edge.ingestion_batch_id or edge.properties.get("upload_batch_id") or ""

        cypher = f"""
        MATCH (s {{id: $source}}), (t {{id: $target}})
        MERGE (s)-[r:{clean_rel} {{id: $id}}]->(t)
        SET r.type = $rel_type,
            r.evidence_status = $evidence_status,
            r.confidence = $confidence,
            r.weight = $weight,
            r.is_active = $is_active,
            r.provenance = $provenance,
            r.dataset_id = $dataset_id,
            r.source_file = $source_file,
            r.ingestion_batch_id = $batch_id,
            r.is_demo = $is_demo
        SET r += $props
        """
        try:
            with self._get_neo4j_session() as session:
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
                    dataset_id=did,
                    source_file=src_f,
                    batch_id=bid,
                    is_demo=bool(edge.is_demo),
                    props=props,
                )
            return True
        except Exception as e:
            logger.error("Failed to persist edge %s to Neo4j: %s", edge.id, str(e))
            return False

    def batch_upsert_nodes_in_neo4j(self, nodes: List[GraphNode], chunk_size: int = 200) -> int:
        """Persists or updates a list of nodes in live Neo4j using UNWIND batching."""
        if not self.is_neo4j_live or not self._neo4j_driver or not nodes:
            return 0
        total_synced = 0
        try:
            with self._get_neo4j_session() as session:
                for i in range(0, len(nodes), chunk_size):
                    chunk = nodes[i:i + chunk_size]
                    batch_params = []
                    for n in chunk:
                        label = n.type.value if hasattr(n.type, "value") else str(n.type)
                        clean_label = "".join(c for c in label if c.isalnum() or c == "_") or "Node"
                        props = _clean_properties_map(n.properties)
                        did = n.dataset_id or n.properties.get("dataset_id") or ""
                        src_f = n.source_file or n.properties.get("source_file") or n.properties.get("source_dataset") or ""
                        bid = n.ingestion_batch_id or n.properties.get("upload_batch_id") or ""
                        batch_params.append({
                            "id": n.id,
                            "name": n.name,
                            "type": clean_label,
                            "criticality": float(n.criticality),
                            "is_compromised": bool(n.is_compromised),
                            "is_crown_jewel": bool(n.is_crown_jewel),
                            "provenance": n.provenance.value if hasattr(n.provenance, "value") else str(n.provenance),
                            "dataset_id": did,
                            "source_file": src_f,
                            "batch_id": bid,
                            "is_demo": bool(n.is_demo),
                            "props": props
                        })
                    cypher = """
                    UNWIND $batch AS item
                    MERGE (n:Node {id: item.id})
                    SET n.name = item.name,
                        n.type = item.type,
                        n.criticality = item.criticality,
                        n.is_compromised = item.is_compromised,
                        n.is_crown_jewel = item.is_crown_jewel,
                        n.provenance = item.provenance,
                        n.dataset_id = item.dataset_id,
                        n.source_file = item.source_file,
                        n.ingestion_batch_id = item.batch_id,
                        n.is_demo = item.is_demo
                    SET n += item.props
                    """
                    session.run(cypher, batch=batch_params)
                    total_synced += len(chunk)
            return total_synced
        except Exception as e:
            logger.error("Failed to batch upsert nodes to Neo4j: %s", str(e))
            return total_synced

    def batch_upsert_edges_in_neo4j(self, edges: List[GraphEdge], chunk_size: int = 200) -> int:
        """Persists or updates a list of edges in live Neo4j using UNWIND batching."""
        if not self.is_neo4j_live or not self._neo4j_driver or not edges:
            return 0
        total_synced = 0
        try:
            with self._get_neo4j_session() as session:
                for i in range(0, len(edges), chunk_size):
                    chunk = edges[i:i + chunk_size]
                    batch_params = []
                    for e in chunk:
                        rel_type = e.type.value if hasattr(e.type, "value") else str(e.type)
                        clean_rel = "".join(c for c in rel_type if c.isalnum() or c == "_") or "CONNECTED_TO"
                        props = _clean_properties_map(e.properties)
                        did = e.dataset_id or e.properties.get("dataset_id") or ""
                        src_f = e.source_file or e.properties.get("source_file") or e.properties.get("source_filename") or ""
                        bid = e.ingestion_batch_id or e.properties.get("upload_batch_id") or ""
                        batch_params.append({
                            "id": e.id,
                            "source": e.source,
                            "target": e.target,
                            "rel_type": clean_rel,
                            "evidence_status": e.evidence_status.value if hasattr(e.evidence_status, "value") else str(e.evidence_status),
                            "confidence": float(e.confidence),
                            "weight": float(e.weight),
                            "is_active": bool(e.is_active),
                            "provenance": e.provenance.value if hasattr(e.provenance, "value") else str(e.provenance),
                            "dataset_id": did,
                            "source_file": src_f,
                            "batch_id": bid,
                            "is_demo": bool(e.is_demo),
                            "props": props
                        })
                    cypher = """
                    UNWIND $batch AS item
                    MATCH (s {id: item.source}), (t {id: item.target})
                    MERGE (s)-[r:CONNECTED_TO {id: item.id}]->(t)
                    SET r.type = item.rel_type,
                        r.evidence_status = item.evidence_status,
                        r.confidence = item.confidence,
                        r.weight = item.weight,
                        r.is_active = item.is_active,
                        r.provenance = item.provenance,
                        r.dataset_id = item.dataset_id,
                        r.source_file = item.source_file,
                        r.ingestion_batch_id = item.batch_id,
                        r.is_demo = item.is_demo
                    SET r += item.props
                    """
                    session.run(cypher, batch=batch_params)
                    total_synced += len(chunk)
            return total_synced
        except Exception as e:
            logger.error("Failed to batch upsert edges to Neo4j: %s", str(e))
            return total_synced

    def delete_dataset_scoped(self, dataset_id: str) -> Dict[str, Any]:
        """Safely and permanently deletes only entities belonging to a specific dataset_id.
        
        Strict Safety Contract (Phase 4):
        1. NEVER executes 'MATCH (n) DETACH DELETE n'!
        2. Scoped strictly to nodes and relationships tagged with dataset_id = $dataset_id.
        3. Preserves unrelated datasets and demo scenarios completely.
        4. Synchronizes both live Neo4j AuraDB and active NetworkX in-memory graph.
        5. Returns verified counts of deleted nodes and relationships.
        """
        if not dataset_id or not dataset_id.strip():
            raise ValueError("A valid non-empty dataset_id is required for deletion.")

        deleted_nodes = 0
        deleted_edges = 0
        neo4j_deleted_nodes = 0
        neo4j_deleted_edges = 0

        # Step 1: Neo4j Scoped Deletion
        if self.is_neo4j_live and self._neo4j_driver:
            try:
                with self._get_neo4j_session() as session:
                    # Count before deletion for verification
                    count_nodes_query = "MATCH (n {dataset_id: $dataset_id}) RETURN count(n) as cnt"
                    n_cnt_res = session.run(count_nodes_query, dataset_id=dataset_id).single()
                    n_cnt = n_cnt_res["cnt"] if n_cnt_res else 0

                    count_edges_query = "MATCH ()-[r {dataset_id: $dataset_id}]->() RETURN count(r) as cnt"
                    e_cnt_res = session.run(count_edges_query, dataset_id=dataset_id).single()
                    e_cnt = e_cnt_res["cnt"] if e_cnt_res else 0
                    
                    # 1. Delete relationships where relationship itself belongs to dataset
                    del_rel_query = "MATCH ()-[r {dataset_id: $dataset_id}]->() DELETE r"
                    session.run(del_rel_query, dataset_id=dataset_id)
                    
                    # 2. Delete relationships connected to nodes belonging to dataset
                    del_incident_query = "MATCH (n {dataset_id: $dataset_id})-[r]->() DELETE r"
                    session.run(del_incident_query, dataset_id=dataset_id)
                    del_incident_in = "MATCH ()-[r]->(n {dataset_id: $dataset_id}) DELETE r"
                    session.run(del_incident_in, dataset_id=dataset_id)
                    
                    # 3. Delete the nodes belonging to dataset
                    del_nodes_query = "MATCH (n {dataset_id: $dataset_id}) DELETE n"
                    session.run(del_nodes_query, dataset_id=dataset_id)
                    
                    neo4j_deleted_nodes = n_cnt
                    neo4j_deleted_edges = e_cnt
            except Exception as e:
                logger.error("Error executing Neo4j dataset scoped deletion for %s: %s", dataset_id, str(e))

        # Step 2: NetworkX / In-Memory Scoped Deletion
        nodes_to_remove = [
            nid for nid, node in self._node_store.items()
            if (node.dataset_id == dataset_id or node.properties.get("dataset_id") == dataset_id or node.properties.get("upload_batch_id") == dataset_id)
        ]
        
        edges_to_remove = [
            eid for eid, edge in self._edge_store.items()
            if (
                edge.dataset_id == dataset_id or
                edge.properties.get("dataset_id") == dataset_id or
                edge.properties.get("upload_batch_id") == dataset_id or
                edge.source in nodes_to_remove or
                edge.target in nodes_to_remove
            )
        ]

        for eid in edges_to_remove:
            edge = self._edge_store.pop(eid, None)
            if edge and self._nx_graph.has_edge(edge.source, edge.target):
                try:
                    self._nx_graph.remove_edge(edge.source, edge.target)
                except Exception:
                    pass
            deleted_edges += 1

        for nid in nodes_to_remove:
            self._node_store.pop(nid, None)
            if self._nx_graph.has_node(nid):
                try:
                    self._nx_graph.remove_node(nid)
                except Exception:
                    pass
            deleted_nodes += 1

        logger.info(
            "Scoped deletion completed for dataset %s: In-Memory (%d nodes, %d edges), Neo4j (%d nodes, %d edges). Remaining: %d nodes, %d edges.",
            dataset_id, deleted_nodes, deleted_edges, neo4j_deleted_nodes, neo4j_deleted_edges, len(self._node_store), len(self._edge_store)
        )

        return {
            "dataset_id": dataset_id,
            "status": "DELETED",
            "nodes_deleted": deleted_nodes,
            "edges_deleted": deleted_edges,
            "in_memory_deleted_nodes": deleted_nodes,
            "in_memory_deleted_edges": deleted_edges,
            "neo4j_deleted_nodes": neo4j_deleted_nodes,
            "neo4j_deleted_edges": neo4j_deleted_edges,
            "remaining_nodes": len(self._node_store),
            "remaining_edges": len(self._edge_store),
            "neo4j_synced": self.is_neo4j_live,
        }

    def get_edge_from_neo4j(self, edge_id: str) -> Optional[GraphEdge]:
        """Retrieves an edge from live Neo4j by ID."""
        if not self.is_neo4j_live or not self._neo4j_driver:
            return None
        cypher = "MATCH (s)-[r {id: $id}]->(t) RETURN r.id as id, s.id as source, t.id as target, type(r) as rel_type, r.evidence_status as evidence_status, r.confidence as confidence, r.weight as weight, r.is_active as is_active, r.provenance as provenance, properties(r) as props"
        reserved_edge_keys = {"id", "source", "target", "type", "evidence_status", "confidence", "weight", "is_active", "provenance"}
        try:
            with self._get_neo4j_session() as session:
                result = session.run(cypher, id=edge_id)
                rec = result.single()
                if not rec:
                    return None
                r_str = rec["rel_type"] or "CONNECTED_TO"
                try:
                    rtype = RelationshipType(r_str)
                except Exception:
                    rtype = RelationshipType.CONNECTED_TO
                    ev_status = EvidenceStatus.CONFIRMED
                prov_str = rec["provenance"] or "LIVE_TELEMETRY"
                try:
                    prov = DataProvenance(prov_str)
                except Exception:
                    prov = DataProvenance.LIVE_TELEMETRY
                raw_props = rec.get("props") or {}
                ext_props = {k: v for k, v in raw_props.items() if k not in reserved_edge_keys}
                return GraphEdge(
                    id=rec["id"],
                    source=rec["source"],
                    target=rec["target"],
                    type=rtype,
                    evidence_status=ev_status,
                    confidence=float(rec["confidence"] or 1.0),
                    weight=float(rec["weight"] or 1.0),
                    is_active=bool(rec["is_active"] if rec["is_active"] is not None else True),
                    provenance=prov,
                    properties=ext_props,
                )
        except Exception as e:
            logger.error("Failed to retrieve edge %s from Neo4j: %s", edge_id, str(e))
            return None

    def delete_edge_from_neo4j(self, edge_id: str) -> bool:
        """Deletes a relationship from live Neo4j by ID."""
        if not self.is_neo4j_live or not self._neo4j_driver:
            return False
        cypher = "MATCH ()-[r {id: $id}]->() DELETE r"
        try:
            with self._get_neo4j_session() as session:
                session.run(cypher, id=edge_id)
            return True
        except Exception as e:
            logger.error("Failed to delete edge %s from Neo4j: %s", edge_id, str(e))
            return False

    def get_database_statistics(self) -> Dict[str, Any]:
        """Returns deep statistics across nodes, labels, relationships, and evidence states."""
        if not self.is_neo4j_live or not self._neo4j_driver:
            # Return in-memory engine statistics
            node_types = {}
            for n in self._node_store.values():
                val = n.type.value if hasattr(n.type, "value") else str(n.type)
                node_types[val] = node_types.get(val, 0) + 1
            rel_types = {}
            ev_stats = {}
            for e in self._edge_store.values():
                rval = e.type.value if hasattr(e.type, "value") else str(e.type)
                rel_types[rval] = rel_types.get(rval, 0) + 1
                estat = e.evidence_status.value if hasattr(e.evidence_status, "value") else str(e.evidence_status)
                ev_stats[estat] = ev_stats.get(estat, 0) + 1
            return {
                "backend": "in_memory_networkx",
                "connected": False,
                "total_nodes": len(self._node_store),
                "total_edges": len(self._edge_store),
                "nodes_by_label": node_types,
                "edges_by_type": rel_types,
                "edges_by_evidence_status": ev_stats,
            }
        try:
            with self._get_neo4j_session() as session:
                node_res = session.run("MATCH (n) RETURN labels(n)[0] as label, count(n) as count")
                nodes_by_label = {rec["label"] or "Unlabeled": rec["count"] for rec in node_res}
                edge_res = session.run("MATCH ()-[r]->() RETURN type(r) as rel_type, count(r) as count")
                edges_by_type = {rec["rel_type"]: rec["count"] for rec in edge_res}
                ev_res = session.run("MATCH ()-[r]->() RETURN coalesce(r.evidence_status, 'CONFIRMED') as ev_status, count(r) as count")
                edges_by_evidence = {rec["ev_status"]: rec["count"] for rec in ev_res}
                return {
                    "backend": "live_neo4j",
                    "connected": True,
                    "uri": settings.NEO4J_URI,
                    "database": self._active_database or settings.NEO4J_DATABASE,
                    "total_nodes": sum(nodes_by_label.values()),
                    "total_edges": sum(edges_by_type.values()),
                    "nodes_by_label": nodes_by_label,
                    "edges_by_type": edges_by_type,
                    "edges_by_evidence_status": edges_by_evidence,
                }
        except Exception as e:
            logger.error("Failed to query Neo4j database statistics: %s", str(e))
            return {
                "backend": "live_neo4j_error",
                "connected": False,
                "error": str(e),
            }

    def close(self) -> None:
        """Safely closes the Neo4j driver connection lifecycle on shutdown."""
        if self._neo4j_driver:
            try:
                self._neo4j_driver.close()
                self._neo4j_available = False
                logger.info("Neo4j driver connection safely closed.")
            except Exception as e:
                logger.warning("Error during Neo4j driver close: %s", str(e))
