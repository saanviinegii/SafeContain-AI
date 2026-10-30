"""Unit tests for the Tri-Level Response Optimization Engine."""

import pytest
from backend.app.business.twin import BusinessContinuityTwin
from backend.app.graph.engine import GraphEngine
from backend.app.ingestion.connectors import SyntheticScenarioGenerator
from backend.app.optimization.solver import (
    BaselinePlanner,
    CPSATOptimizer,
    GreedyOptimizer,
    StrategyComparator,
)
from backend.app.planning.catalog import ActionCatalog
from backend.app.models.domain import OptimizationStrategy


def test_action_catalog_generation():
    engine = GraphEngine(mode="in_memory")
    scenario = SyntheticScenarioGenerator.generate_national_gateway_scenario()

    for node in scenario.nodes:
        engine.add_node(node)
    for edge in scenario.edges:
        engine.add_edge(edge)

    paths = engine.find_attack_paths()
    nodes = {n.id: n for n in engine.get_all_nodes()}
    actions = ActionCatalog.generate_candidate_actions(paths, nodes)

    assert len(actions) >= 3
    action_types = {a.action_type.value for a in actions}
    assert "ISOLATE_ENDPOINT" in action_types


def test_optimization_strategies_comparison():
    engine = GraphEngine(mode="in_memory")
    scenario = SyntheticScenarioGenerator.generate_national_gateway_scenario()

    for node in scenario.nodes:
        engine.add_node(node)
    for edge in scenario.edges:
        engine.add_edge(edge)

    twin = BusinessContinuityTwin()
    twin.discover_dependencies_from_graph(engine)

    paths = engine.find_attack_paths()
    nodes = {n.id: n for n in engine.get_all_nodes()}
    actions = ActionCatalog.generate_candidate_actions(paths, nodes)

    budget = 5000.0

    # 1. Baseline
    plan_baseline = BaselinePlanner.plan(actions, budget_limit=budget)
    assert plan_baseline.strategy == OptimizationStrategy.BASELINE_SEVERITY
    assert plan_baseline.total_cost <= budget

    # 2. Greedy
    plan_greedy = GreedyOptimizer.plan(actions, budget_limit=budget)
    assert plan_greedy.strategy == OptimizationStrategy.GREEDY_RISK_COST
    assert plan_greedy.total_cost <= budget

    # 3. CP-SAT
    plan_cpsat = CPSATOptimizer.plan(actions, twin, engine, budget_limit=budget)
    assert plan_cpsat.strategy == OptimizationStrategy.CONSTRAINT_CPSAT
    assert plan_cpsat.total_cost <= budget
    assert plan_cpsat.satisfies_all_constraints is True

    # Comparative analysis
    comp = StrategyComparator.compare(actions, twin, engine, budget_limit=budget)
    assert "strategies" in comp
    assert "benchmarks" in comp
    assert comp["benchmarks"]["cpsat_latency_ms"] >= 0.0
