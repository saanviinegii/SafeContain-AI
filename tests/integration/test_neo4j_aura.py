"""Real Neo4j Aura Integration Test Suite.

Conforms strictly to SafeContain AI Master Prompt Part 4:
1. Connects to real Neo4j Aura (using official neo4j driver).
2. Creates a unique test node.
3. Creates a relationship.
4. Reads the node and relationship back.
5. Confirms persistence.
6. Cleans up the test data.

Never reports Neo4j as connected if the actual connection failed.
Separates skipped tests from passed tests when external live Aura credentials are not configured.
"""

import uuid
import pytest
from backend.app.core.config import settings
from backend.app.graph.engine import GraphEngine
from backend.app.models.domain import (
    DataProvenance,
    EvidenceStatus,
    GraphEdge,
    GraphNode,
    NodeType,
    RelationshipType,
)


def test_real_neo4j_aura_lifecycle():
    """Validates real Neo4j Aura connectivity and atomic CRUD operations without mocking."""
    # Attempt real connection
    engine = GraphEngine(mode="neo4j")

    if not engine.is_neo4j_live:
        pytest.skip(
            f"Real Neo4j Aura integration test skipped: Live instance at '{settings.NEO4J_URI}' "
            "is not reachable. Provide NEO4J_URI, NEO4J_USER, and NEO4J_PASSWORD in .env to run live."
        )

    # Generate unique test identifiers to ensure complete test isolation
    test_uid = uuid.uuid4().hex[:8]
    node1_id = f"test-aura-node1-{test_uid}"
    node2_id = f"test-aura-node2-{test_uid}"
    edge_id = f"test-aura-edge-{test_uid}"

    try:
        # 1. Create unique test nodes
        node1 = GraphNode(
            id=node1_id,
            name=f"Aura Integration Node 1 ({test_uid})",
            type=NodeType.SERVER,
            criticality=0.85,
            is_compromised=True,
            is_crown_jewel=False,
            provenance=DataProvenance.LIVE_TELEMETRY,
        )
        node2 = GraphNode(
            id=node2_id,
            name=f"Aura Integration Target ({test_uid})",
            type=NodeType.DATABASE,
            criticality=1.0,
            is_compromised=False,
            is_crown_jewel=True,
            provenance=DataProvenance.LIVE_TELEMETRY,
        )

        assert engine.create_or_update_node_in_neo4j(node1) is True
        assert engine.create_or_update_node_in_neo4j(node2) is True

        # 2. Create relationship between them
        edge = GraphEdge(
            id=edge_id,
            source=node1_id,
            target=node2_id,
            type=RelationshipType.CONNECTED_TO,
            evidence_status=EvidenceStatus.CONFIRMED,
            confidence=0.96,
            weight=1.5,
            is_active=True,
            provenance=DataProvenance.LIVE_TELEMETRY,
        )
        assert engine.create_or_update_edge_in_neo4j(edge) is True

        # 3. Read node and relationship back from live database in a NEW separate database session
        # This proves persistence across independent sessions on Neo4j Aura (Part 4 / Section 1.9)
        with engine._get_neo4j_session() as session2:
            res_node = session2.run("MATCH (n:Server {id: $id}) RETURN n.id as id, n.criticality as criticality, n.is_compromised as is_compromised", id=node1_id)
            rec_node = res_node.single()
            assert rec_node is not None
            assert rec_node["id"] == node1_id
            assert float(rec_node["criticality"]) == 0.85
            assert rec_node["is_compromised"] is True

            res_edge = session2.run("MATCH (s)-[r:CONNECTED_TO {id: $id}]->(t) RETURN r.id as id, s.id as source, t.id as target, r.confidence as confidence", id=edge_id)
            rec_edge = res_edge.single()
            assert rec_edge is not None
            assert rec_edge["id"] == edge_id
            assert rec_edge["source"] == node1_id
            assert rec_edge["target"] == node2_id
            assert float(rec_edge["confidence"]) == 0.96

        # 4. Confirm persistence via database statistics
        stats = engine.get_database_statistics()
        assert stats["connected"] is True
        assert stats["backend"] == "live_neo4j"
        assert stats["total_nodes"] >= 2

    finally:
        # 5. Clean up test data safely to prevent database pollution
        engine.delete_edge_from_neo4j(edge_id)
        engine.delete_node_from_neo4j(node1_id)
        engine.delete_node_from_neo4j(node2_id)

        # 6. Verify clean deletion
        assert engine.get_node_from_neo4j(node1_id) is None
        assert engine.get_node_from_neo4j(node2_id) is None
        assert engine.get_edge_from_neo4j(edge_id) is None

        # 7. Close driver safely
        engine.close()


def test_real_neo4j_aura_connectivity_and_verification_query():
    """Validates driver verification, RETURN 1 Cypher execution, and dynamic database discovery."""
    engine = GraphEngine(mode="neo4j")

    if not engine.is_neo4j_live:
        pytest.skip("Real Neo4j Aura integration test skipped: Live instance not reachable.")

    try:
        # Verify driver connectivity
        assert engine._neo4j_driver is not None

        # Execute real Cypher verification query (RETURN 1)
        with engine._get_neo4j_session() as session:
            result = session.run("RETURN 1 as probe").single()
            assert result is not None
            assert result["probe"] == 1

        # Verify active database is discovered and non-empty
        assert engine.active_database is not None
        assert len(engine.active_database) > 0

        # Verify status endpoint returns real connected diagnostic
        status = engine.get_neo4j_status()
        assert status["connected"] is True
        assert status["status"] == "CONNECTED"
        assert status["active_engine"] == "live_neo4j"
        assert "neo4j_node_count" in status
    finally:
        engine.close()
