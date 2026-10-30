"""Unit tests for Evidence Uncertainty, Freshness Decay, and Risk Engine."""

from datetime import datetime, timezone, timedelta
import pytest

from backend.app.evidence.engine import EvidenceEngine
from backend.app.graph.engine import GraphEngine
from backend.app.ingestion.connectors import SyntheticScenarioGenerator
from backend.app.models.domain import (
    DataProvenance,
    EvidenceStatus,
    GraphEdge,
    RelationshipType,
)
from backend.app.risk.engine import RiskEngine


def test_evidence_freshness_and_temporal_decay():
    evidence_eng = EvidenceEngine()
    now = datetime.now(timezone.utc)
    
    # Fresh edge (verified 2 hours ago)
    fresh_edge = GraphEdge(
        id="edge-fresh",
        source="host-01",
        target="host-02",
        type=RelationshipType.CONNECTED_TO,
        evidence_status=EvidenceStatus.CONFIRMED,
        confidence=0.95,
        last_verified_at=now - timedelta(hours=2),
    )
    assert evidence_eng.evaluate_freshness(fresh_edge, now) == EvidenceStatus.CONFIRMED
    assert evidence_eng.calculate_decayed_confidence(fresh_edge, now) > 0.94

    # Stale edge (verified 120 hours ago > threshold 72h)
    stale_edge = GraphEdge(
        id="edge-stale",
        source="host-01",
        target="host-03",
        type=RelationshipType.CONNECTED_TO,
        evidence_status=EvidenceStatus.CONFIRMED,
        confidence=0.90,
        last_verified_at=now - timedelta(hours=120),
    )
    assert evidence_eng.evaluate_freshness(stale_edge, now) == EvidenceStatus.STALE
    assert evidence_eng.calculate_decayed_confidence(stale_edge, now) < 0.80


def test_sensitivity_drift_analysis():
    engine = GraphEngine(mode="in_memory")
    scenario = SyntheticScenarioGenerator.generate_national_gateway_scenario()

    for node in scenario.nodes:
        engine.add_node(node)
    for edge in scenario.edges:
        engine.add_edge(edge)

    paths = engine.find_attack_paths()
    evidence_eng = EvidenceEngine()
    sensitivity_results = evidence_eng.run_sensitivity_analysis(paths, engine)

    assert len(sensitivity_results) > 0
    # Check that both confirmed hypothesis and disputed hypothesis were generated
    scenarios = [s.new_status for s in sensitivity_results]
    assert EvidenceStatus.CONFIRMED in scenarios
    assert EvidenceStatus.DISPUTED in scenarios


def test_decomposed_risk_calculation():
    engine = GraphEngine(mode="in_memory")
    scenario = SyntheticScenarioGenerator.generate_national_gateway_scenario()

    for node in scenario.nodes:
        engine.add_node(node)
    for edge in scenario.edges:
        engine.add_edge(edge)

    paths = engine.find_attack_paths()
    risk_decomp = RiskEngine.decompose_system_risk(paths, engine.get_all_nodes())

    assert risk_decomp.inherent_risk > 0.0
    assert risk_decomp.observed_risk > 0.0
    assert risk_decomp.potential_risk >= risk_decomp.observed_risk
    assert risk_decomp.uncertainty_adjusted_risk > 0.0
    assert len(risk_decomp.contributing_factors) == 3
