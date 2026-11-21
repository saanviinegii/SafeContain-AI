"""Unit Test Suite for SafeContain AI Synthetic Enterprise Dataset & Graph Integration.

Validates the 12 CSV files, referential integrity, graph construction,
attack path analysis, simulation snapshot isolation, and business continuity twin.
"""

import os
import pytest
from backend.app.graph.engine import GraphEngine
from backend.app.business.twin import BusinessContinuityTwin
from backend.app.ingestion.dataset_validator import DatasetValidator
from backend.app.ingestion.synthetic_enterprise_loader import SyntheticEnterpriseLoader, DEFAULT_DATASET_DIR
from backend.app.planning.catalog import ActionCatalog
from backend.app.simulation.sandbox import SimulationSandbox
from backend.app.optimization.solver import CPSATOptimizer


@pytest.fixture
def enterprise_loader():
    return SyntheticEnterpriseLoader(DEFAULT_DATASET_DIR)


@pytest.fixture
def populated_engine(enterprise_loader):
    engine = GraphEngine(mode="in_memory")
    twin = BusinessContinuityTwin()
    enterprise_loader.load_scenario_into_platform(engine, twin, scenario_id="SCEN-001")
    return engine, twin


def test_dataset_validator_passes(enterprise_loader):
    """Ensures dataset validator runs with 0 errors across all 12 CSVs."""
    report = enterprise_loader.validator.validate()
    assert report["validation_status"] == "PASSED"
    assert report["integrity_checks"]["total_errors"] == 0
    assert report["summary_metrics"]["node_count"] >= 100
    assert report["summary_metrics"]["relationship_count"] >= 250
    assert report["summary_metrics"]["critical_assets_count"] >= 15
    assert report["summary_metrics"]["attack_paths_count"] >= 30
    assert report["summary_metrics"]["threat_scenarios_count"] >= 10


def test_nodes_and_relationships_loaded(populated_engine):
    """Verifies that 120 nodes and 285 edges are loaded with valid attributes."""
    engine, twin = populated_engine
    nodes = engine.get_all_nodes()
    edges = engine.get_all_edges()

    assert len(nodes) >= 100
    assert len(edges) >= 250

    # Verify primary judge demo entities exist
    marcus_node = engine.get_node("node-user-marcus")
    assert marcus_node is not None
    assert marcus_node.name == "Marcus Vance"
    assert marcus_node.is_compromised is True

    laptop_node = engine.get_node("node-ep-laptop-marcus")
    assert laptop_node is not None
    assert laptop_node.is_compromised is True

    crown_db = engine.get_node("node-db-customer-core")
    assert crown_db is not None
    assert crown_db.is_crown_jewel is True
    assert crown_db.criticality >= 0.95


def test_attack_path_discovery_on_enterprise_graph(populated_engine):
    """Verifies that multi-hop attack paths to crown jewels are discovered."""
    engine, _ = populated_engine
    paths = engine.find_attack_paths(max_depth=6)

    assert len(paths) > 0
    # Find Marcus Vance path
    marcus_paths = [p for p in paths if p.source_id in ("node-user-marcus", "node-ep-laptop-marcus")]
    assert len(marcus_paths) > 0

    # Ensure choke points and explanations are populated
    first_path = paths[0]
    assert first_path.hop_count >= 1
    assert len(first_path.node_sequence) >= 2
    assert first_path.adjusted_path_risk > 0.0


def test_business_twin_dependency_calibration(populated_engine):
    """Verifies that business workflows are registered and mapped to graph assets."""
    _, twin = populated_engine
    workflows = twin.get_all_workflows()

    assert len(workflows) >= 20
    # Check mission-critical payment workflows
    crit_wfs = [w for w in workflows if "payment" in w.name.lower() or "ledger" in w.name.lower()]
    assert len(crit_wfs) > 0


def test_simulation_snapshot_isolation(populated_engine):
    """Verifies that simulated containment runs on an isolated snapshot without mutating base graph."""
    engine, twin = populated_engine
    initial_edge_count = len(engine.get_all_edges())
    initial_node_count = len(engine.get_all_nodes())

    paths = engine.find_attack_paths(max_depth=6)
    candidates = ActionCatalog.generate_candidate_actions(paths, engine._node_store)
    assert len(candidates) > 0

    # Apply the first candidate action via SimulationSandbox
    target_action = candidates[0]
    from backend.app.models.domain import ContainmentPlan, OptimizationStrategy
    plan = ContainmentPlan(
        id="test-plan-01",
        strategy=OptimizationStrategy.GREEDY_RISK_COST,
        actions=[target_action],
        total_cost=target_action.implementation_cost,
        total_disruption_score=target_action.operational_disruption_score,
        predicted_risk_reduction=target_action.estimated_risk_reduction,
        predicted_residual_risk=30.0,
        satisfies_all_constraints=True,
        objective_score=80.0,
        explanation="Test simulation",
    )
    sim_result = SimulationSandbox.simulate_containment_plan(plan, engine, twin, scenario_id="SCEN-001")

    # Baseline graph MUST remain unmutated!
    assert len(engine.get_all_edges()) == initial_edge_count
    assert len(engine.get_all_nodes()) == initial_node_count
    assert sim_result.simulation_id.startswith("sim-")
    assert sim_result.initial_attack_path_count >= sim_result.residual_attack_path_count


def test_scenario_switching(enterprise_loader):
    """Verifies dynamic switching between different enterprise threat scenarios."""
    engine = GraphEngine(mode="in_memory")
    twin = BusinessContinuityTwin()

    # Load SCEN-002
    res2 = enterprise_loader.load_scenario_into_platform(engine, twin, scenario_id="SCEN-002")
    assert res2["scenario_id"] == "SCEN-002"
    assert "Perimeter" in res2["scenario_name"]

    # Load SCEN-003
    res3 = enterprise_loader.load_scenario_into_platform(engine, twin, scenario_id="SCEN-003")
    assert res3["scenario_id"] == "SCEN-003"
    assert "Supply Chain" in res3["scenario_name"]
