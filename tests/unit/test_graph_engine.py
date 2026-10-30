"""Unit tests for the Dual Graph Engine and Attack Path Traversal."""

import pytest
from backend.app.graph.engine import GraphEngine
from backend.app.ingestion.connectors import SyntheticScenarioGenerator
from backend.app.models.domain import NodeType, RelationshipType


def test_graph_engine_population_and_retrieval():
    engine = GraphEngine(mode="in_memory")
    scenario = SyntheticScenarioGenerator.generate_national_gateway_scenario()

    for node in scenario.nodes:
        engine.add_node(node)
    for edge in scenario.edges:
        engine.add_edge(edge)

    assert len(engine.get_all_nodes()) == len(scenario.nodes)
    assert len(engine.get_all_edges()) == len(scenario.edges)

    dc_node = engine.get_node("srv-ad-dc01")
    assert dc_node is not None
    assert dc_node.name == "Primary Domain Controller (DC01)"


def test_attack_path_discovery_multi_route():
    engine = GraphEngine(mode="in_memory")
    scenario = SyntheticScenarioGenerator.generate_national_gateway_scenario()

    for node in scenario.nodes:
        engine.add_node(node)
    for edge in scenario.edges:
        engine.add_edge(edge)

    paths = engine.find_attack_paths()
    assert len(paths) >= 2, "Must discover both primary DC path and secondary backup path"

    # Verify high-value target is citizen database
    target_ids = {p.target_id for p in paths}
    assert "db-citizen-identity-prod" in target_ids

    # Verify end-to-end path from external attacker to database crown jewel
    ext_to_db_path = next(
        p for p in paths
        if p.source_id == "ext-attacker-c2" and p.target_id == "db-citizen-identity-prod"
    )
    assert ext_to_db_path.adjusted_path_risk > 0.0
    assert len(ext_to_db_path.node_sequence) >= 4
    assert ext_to_db_path.hop_count >= 3


def test_isolated_snapshot_immutability():
    """Verify Principle #9: Simulations must operate on isolated graph copy without mutating original."""
    engine = GraphEngine(mode="in_memory")
    scenario = SyntheticScenarioGenerator.generate_national_gateway_scenario()

    for node in scenario.nodes:
        engine.add_node(node)
    for edge in scenario.edges:
        engine.add_edge(edge)

    orig_edge_count = len(engine._nx_graph.edges())
    
    # Fork isolated snapshot
    snapshot = engine.clone_isolated_snapshot()
    assert len(snapshot._nx_graph.edges()) == orig_edge_count

    # Mutate snapshot by removing edge
    snapshot.remove_edge("edge-user-to-dc")
    assert len(snapshot._nx_graph.edges()) == orig_edge_count - 1

    # Assert ORIGINAL graph remains completely unmodified!
    assert len(engine._nx_graph.edges()) == orig_edge_count
    assert engine._nx_graph.has_edge("usr-admin-rajesh", "srv-ad-dc01") is True
    assert snapshot._nx_graph.has_edge("usr-admin-rajesh", "srv-ad-dc01") is False


def test_topology_export_import():
    engine = GraphEngine(mode="in_memory")
    scenario = SyntheticScenarioGenerator.generate_national_gateway_scenario()

    for node in scenario.nodes:
        engine.add_node(node)
    for edge in scenario.edges:
        engine.add_edge(edge)

    exported = engine.export_topology()
    assert "nodes" in exported and "edges" in exported

    new_engine = GraphEngine(mode="in_memory")
    new_engine.import_topology(exported)
    assert len(new_engine.get_all_nodes()) == len(engine.get_all_nodes())
    assert len(new_engine.get_all_edges()) == len(engine.get_all_edges())
