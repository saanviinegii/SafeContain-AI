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

        # 3. Read node and relationship back from live database
        retrieved_node1 = engine.get_node_from_neo4j(node1_id)
        assert retrieved_node1 is not None
        assert retrieved_node1.id == node1_id
        assert retrieved_node1.criticality == 0.85
        assert retrieved_node1.is_compromised is True

        retrieved_edge = engine.get_edge_from_neo4j(edge_id)
        assert retrieved_edge is not None
        assert retrieved_edge.id == edge_id
        assert retrieved_edge.source == node1_id
        assert retrieved_edge.target == node2_id
        assert retrieved_edge.confidence == 0.96

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
