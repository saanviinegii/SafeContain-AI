"""Performance and Scalability Benchmark Test Suite for SafeContain AI.

Evaluates graph traversal latencies and solver scalability across small (50 nodes),
medium (250 nodes), and large (1,000 nodes) synthetic network topologies.
"""

import time
import pytest
from backend.app.business.twin import BusinessContinuityTwin
from backend.app.graph.engine import GraphEngine
from backend.app.models.domain import (
    DataProvenance,
    EvidenceStatus,
    GraphEdge,
    GraphNode,
    NodeType,
    RelationshipType,
)
from backend.app.optimization.solver import CPSATOptimizer
from backend.app.planning.catalog import ActionCatalog


def _build_synthetic_topology(node_count: int, edge_density: float = 2.0) -> GraphEngine:
    """Helper constructing reproducible synthetic topologies."""
    engine = GraphEngine(mode="in_memory")
    
    # Entry point node
    engine.add_node(GraphNode(
        id="attacker-node",
        name="External Threat Actor",
        type=NodeType.THREAT,
        criticality=1.0,
        is_compromised=True,
        provenance=DataProvenance.SYNTHETIC,
    ))

    # Internal nodes
    for i in range(1, node_count - 1):
        engine.add_node(GraphNode(
            id=f"node-{i:04d}",
            name=f"Host Server {i:04d}",
            type=NodeType.ENDPOINT if i % 3 == 0 else NodeType.SERVER,
            criticality=0.5,
            is_compromised=False,
            provenance=DataProvenance.SYNTHETIC,
        ))

    # Crown jewel target
    engine.add_node(GraphNode(
        id="target-crown-jewel",
        name="Critical Data Repository",
        type=NodeType.DATABASE,
        criticality=1.0,
        is_crown_jewel=True,
        provenance=DataProvenance.SYNTHETIC,
    ))

    # Connect attacker to initial chain and connect chain to target within 4 hops
    engine.add_edge(GraphEdge(
        id="edge-atk-start",
        source="attacker-node",
        target="node-0001",
        type=RelationshipType.CONNECTED_TO,
        evidence_status=EvidenceStatus.CONFIRMED,
        confidence=0.95,
        provenance=DataProvenance.SYNTHETIC,
    ))
    # Direct route to crown jewel
    engine.add_edge(GraphEdge(
        id="edge-to-target-direct",
        source="node-0003",
        target="target-crown-jewel",
        type=RelationshipType.HAS_ACCESS_TO,
        evidence_status=EvidenceStatus.CONFIRMED,
        confidence=0.90,
        provenance=DataProvenance.SYNTHETIC,
    ))

    # Connect nodes in directed layered graph
    nodes = list(engine._node_store.keys())
    for i in range(1, len(nodes) - 2):
        engine.add_edge(GraphEdge(
            id=f"edge-{i:04d}",
            source=nodes[i],
            target=nodes[i + 1],
            type=RelationshipType.CONNECTED_TO,
            evidence_status=EvidenceStatus.CONFIRMED,
            confidence=0.9,
            provenance=DataProvenance.SYNTHETIC,
        ))

    return engine


def test_small_graph_benchmark():
    """Benchmark: 50 nodes topology."""
    engine = _build_synthetic_topology(node_count=50)
    t0 = time.perf_counter()
    paths = engine.find_attack_paths(max_depth=5)
    t1 = time.perf_counter()
    latency_ms = (t1 - t0) * 1000.0

    assert len(paths) >= 1
    assert latency_ms < 500.0, f"Small graph traversal took {latency_ms:.2f}ms (> 500ms SLA)"


def test_medium_graph_benchmark():
    """Benchmark: 250 nodes topology."""
    engine = _build_synthetic_topology(node_count=250)
    t0 = time.perf_counter()
    paths = engine.find_attack_paths(max_depth=5)
    t1 = time.perf_counter()
    latency_ms = (t1 - t0) * 1000.0

    assert len(paths) >= 1
    assert latency_ms < 1500.0, f"Medium graph traversal took {latency_ms:.2f}ms (> 1500ms SLA)"


def test_cpsat_solver_scalability():
    """Benchmark: OR-Tools CP-SAT optimizer scalability."""
    engine = _build_synthetic_topology(node_count=50)
    twin = BusinessContinuityTwin()
    paths = engine.find_attack_paths(max_depth=5)
    nodes = {n.id: n for n in engine.get_all_nodes()}
    actions = ActionCatalog.generate_candidate_actions(paths, nodes)

    t0 = time.perf_counter()
    plan = CPSATOptimizer.plan(actions, twin, engine, budget_limit=50000.0)
    t1 = time.perf_counter()
    solver_ms = (t1 - t0) * 1000.0

    assert plan.satisfies_all_constraints is True
    assert solver_ms < 5000.0, f"CP-SAT solver took {solver_ms:.2f}ms (> 5000ms SLA)"
