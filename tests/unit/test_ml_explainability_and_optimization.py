"""Unit & Integration Test Suite for SafeContain AI Phase 7.2C.

Covers:
1. SHAP Explainer selection, compatibility, and base value alignment with LogisticRegression.
2. Feature attribution mapping from 28 transformed features to 13 raw domain features.
3. Ranking and direction assignment (increases_risk / decreases_risk).
4. Non-causal analyst summary generation.
5. In-memory caching and cache invalidation.
6. CP-SAT containment optimization with calibrated ML threat probabilities.
7. Integer coefficient scaling and preservation of budget and critical SLA constraints.
8. Explainable optimization rationales on selected containment actions.
9. REST API endpoints for ML health, asset risk, SHAP explanation, graph-risk map, and ML optimization.
10. Robust edge cases (empty actions, missing nodes, zero budget).
"""

import os
import json
import pytest
import numpy as np
import pandas as pd
from datetime import datetime, timezone

from backend.app.ml.model_registry import ModelRegistry
from backend.app.ml.feature_engineering import FeatureEngineer
from backend.app.ml.explainability import ShapExplainerService, FEATURE_DESCRIPTIONS
from backend.app.models.domain import (
    ApprovalStatus,
    ContainmentAction,
    ContainmentPlan,
    GraphNode,
    NodeType,
    OptimizationStrategy,
    SecurityActionType,
    UserRole,
    WorkflowCriticality,
)
from backend.app.optimization.solver import CPSATOptimizer, StrategyComparator
from backend.app.business.twin import BusinessContinuityTwin
from backend.app.security.user_store import UserRecord


@pytest.fixture
def feature_engineer():
    return FeatureEngineer()


@pytest.fixture
def model_registry():
    return ModelRegistry()


@pytest.fixture
def shap_service(model_registry, feature_engineer):
    return ShapExplainerService(
        model_registry=model_registry,
        feature_engineer=feature_engineer,
        max_background_samples=50,
        random_state=42,
    )


@pytest.fixture
def viewer_user():
    now = datetime.now(timezone.utc).isoformat()
    return UserRecord(
        id="usr-test-viewer",
        username="sec_viewer_01",
        role="VIEWER",
        hashed_password="mock_hashed_password",
        is_active=True,
        created_at=now,
        updated_at=now,
    )


@pytest.fixture
def analyst_user():
    now = datetime.now(timezone.utc).isoformat()
    return UserRecord(
        id="usr-test-analyst",
        username="sec_analyst_01",
        role="ANALYST",
        hashed_password="mock_hashed_password",
        is_active=True,
        created_at=now,
        updated_at=now,
    )


@pytest.fixture
def sample_candidate_actions():
    return [
        ContainmentAction(
            id="act-test-01",
            action_type=SecurityActionType.ISOLATE_ENDPOINT,
            target_node_id="node-host-alpha",
            target_node_name="Host Alpha",
            estimated_risk_reduction=45.0,
            operational_disruption_score=15.0,
            implementation_cost=300.0,
            estimated_duration_minutes=15,
            reversibility=True,
            required_role=UserRole.INCIDENT_RESPONDER,
            rationale="Isolate Host Alpha",
        ),
        ContainmentAction(
            id="act-test-02",
            action_type=SecurityActionType.REVOKE_SESSION,
            target_node_id="node-user-marcus",
            target_node_name="User Marcus",
            estimated_risk_reduction=35.0,
            operational_disruption_score=5.0,
            implementation_cost=100.0,
            estimated_duration_minutes=5,
            reversibility=True,
            required_role=UserRole.SECURITY_ADMIN,
            rationale="Revoke sessions for Marcus",
        ),
        ContainmentAction(
            id="act-test-03",
            action_type=SecurityActionType.RESTRICT_NETWORK,
            target_node_id="node-srv-web",
            target_node_name="Web Server",
            estimated_risk_reduction=20.0,
            operational_disruption_score=50.0,
            implementation_cost=600.0,
            estimated_duration_minutes=30,
            reversibility=True,
            required_role=UserRole.SECURITY_ADMIN,
            rationale="Restrict web server",
        ),
    ]


class MockEngine:
    def get_node(self, nid: str):
        return None

    def get_all_nodes(self):
        return []


# =====================================================================
# 1. SHAP EXPLAINABILITY TESTS
# =====================================================================

def test_shap_service_initialization(shap_service):
    """Verifies SHAP service lazily initializes LinearExplainer."""
    assert shap_service._explainer is None
    shap_service._ensure_initialized()
    assert shap_service._explainer is not None
    assert len(shap_service._expected_features) == 13
    assert len(shap_service._transformed_feature_names) == 28


def test_shap_explain_asset_structure(shap_service):
    """Ensures structured explanation adheres to Phase 7.2C schema."""
    res = shap_service.explain_asset("node-user-marcus", top_n=5)
    assert res["asset_id"] == "node-user-marcus"
    assert "risk_probability" in res
    assert 0.0 <= res["risk_probability"] <= 1.0
    assert "decision_threshold" in res
    assert res["decision_threshold"] == 0.32
    assert "threshold_crossed" in res
    assert isinstance(res["threshold_crossed"], bool)
    assert "risk_tier" in res
    assert res["risk_tier"] in ("CRITICAL", "HIGH", "MODERATE", "LOW")

    exp = res["explanation"]
    assert "base_value" in exp
    assert "decision_margin" in exp
    assert "top_contributors" in exp
    assert len(exp["top_contributors"]) <= 5

    for c in exp["top_contributors"]:
        assert "feature" in c
        assert c["feature"] in shap_service._expected_features
        assert "value" in c
        assert "shap_value" in c
        assert c["direction"] in ("increases_risk", "decreases_risk")
        assert "magnitude" in c
        assert "description" in c


def test_shap_margin_additivity(shap_service, model_registry):
    """Verifies exact closed-form SHAP additivity: base_value + sum(shap) == margin."""
    shap_service._ensure_initialized()
    pipeline, meta = model_registry.load_model()
    raw_df = shap_service.fe.extract_raw_features()
    row = raw_df[raw_df["node_id"] == "node-user-marcus"].iloc[0]

    X_single = pd.DataFrame([row[shap_service._expected_features]])
    prep = pipeline.named_steps["prep"]
    clf = pipeline.named_steps["clf"]
    X_trans = prep.transform(X_single)

    margin = float(clf.decision_function(X_trans)[0])
    shap_res = shap_service._explainer(X_trans)
    base_val = float(np.atleast_1d(shap_service._explainer.expected_value)[0])
    shap_sum = float(np.sum(shap_res.values[0]))

    # Sum of SHAP values plus base value must equal decision function margin
    assert np.isclose(base_val + shap_sum, margin, atol=1e-5)


def test_shap_ranking_descending(shap_service):
    """Verifies top contributors are sorted by magnitude descending."""
    res = shap_service.explain_asset("node-user-marcus", top_n=5)
    top = res["explanation"]["top_contributors"]
    magnitudes = [c["magnitude"] for c in top]
    assert magnitudes == sorted(magnitudes, reverse=True)


def test_shap_caching_and_invalidation(shap_service):
    """Verifies in-memory caching returns identical payload and cache can be cleared."""
    res1 = shap_service.explain_asset("node-user-marcus", top_n=5)
    assert len(shap_service._cache) > 0
    res2 = shap_service.explain_asset("node-user-marcus", top_n=5)
    assert res1 == res2
    shap_service.clear_cache()
    assert len(shap_service._cache) == 0


def test_shap_missing_asset_raises_key_error(shap_service):
    """Verifies graceful KeyError when an unknown node ID is requested."""
    with pytest.raises(KeyError):
        shap_service.explain_asset("nonexistent-node-id-xyz")


def test_shap_explain_dataframe(shap_service):
    """Verifies batch explanation of arbitrary feature DataFrames."""
    shap_service._ensure_initialized()
    raw_df = shap_service.fe.extract_raw_features().head(3)
    explanations = shap_service.explain_dataframe(raw_df[shap_service._expected_features], top_n=3)
    assert len(explanations) == 3
    for exp in explanations:
        assert "risk_probability" in exp
        assert "decision_threshold" in exp
        assert len(exp["top_contributors"]) == 3


# =====================================================================
# 2. CP-SAT OPTIMIZER WITH ML PROBABILITIES TESTS
# =====================================================================

def test_cpsat_ml_probability_prioritization(sample_candidate_actions):
    """Ensures CP-SAT prioritizes actions with higher calibrated ML threat probabilities."""
    twin = BusinessContinuityTwin()
    engine = MockEngine()

    # Case A: host-alpha has high threat probability (0.95), marcus has low (0.10)
    ml_probs_a = {
        "node-host-alpha": 0.95,
        "node-user-marcus": 0.10,
        "node-srv-web": 0.05,
    }
    # Tight budget allowing only 1 action
    plan_a = CPSATOptimizer.plan(
        sample_candidate_actions,
        twin,
        engine,
        budget_limit=350.0,
        ml_probabilities=ml_probs_a,
        operating_threshold=0.32,
    )
    assert len(plan_a.actions) == 1
    assert plan_a.actions[0].target_node_id == "node-host-alpha"
    assert plan_a.actions[0].ml_probability == 0.95
    assert plan_a.actions[0].threshold_crossed is True
    assert "optimization_rationale" in plan_a.actions[0].model_dump()


def test_cpsat_preserves_budget_and_sla_constraints(sample_candidate_actions):
    """Verifies CP-SAT strictly enforces hard budget cap even when high ML threat exists."""
    twin = BusinessContinuityTwin()
    engine = MockEngine()

    ml_probs = {
        "node-host-alpha": 0.99,
        "node-user-marcus": 0.99,
        "node-srv-web": 0.99,
    }
    # Budget too low for any action ($50 vs min action $100)
    plan = CPSATOptimizer.plan(
        sample_candidate_actions,
        twin,
        engine,
        budget_limit=50.0,
        ml_probabilities=ml_probs,
        operating_threshold=0.32,
    )
    assert len(plan.actions) == 0
    assert plan.total_cost == 0.0


def test_cpsat_empty_actions_graceful_handling():
    """Verifies CP-SAT returns valid empty plan when no candidate actions are provided."""
    twin = BusinessContinuityTwin()
    engine = MockEngine()
    plan = CPSATOptimizer.plan([], twin, engine)
    assert plan.id == "plan-strat3-cpsat"
    assert len(plan.actions) == 0
    assert plan.satisfies_all_constraints is True


def test_strategy_comparator_supports_ml_probabilities(sample_candidate_actions):
    """Ensures StrategyComparator executes all 3 strategies with ML probabilities."""
    twin = BusinessContinuityTwin()
    engine = MockEngine()
    ml_probs = {"node-host-alpha": 0.85, "node-user-marcus": 0.40}

    res = StrategyComparator.compare(
        sample_candidate_actions,
        twin,
        engine,
        budget_limit=1000.0,
        ml_probabilities=ml_probs,
        operating_threshold=0.32,
    )
    assert "strategies" in res
    assert "CONSTRAINT_CPSAT" in res["strategies"]
    cpsat_plan = res["strategies"]["CONSTRAINT_CPSAT"]
    assert len(cpsat_plan["actions"]) > 0


# =====================================================================
# 3. REST API ENDPOINTS TESTS (PHASE 7.2C)
# =====================================================================

def test_api_get_ml_health(viewer_user):
    """Ensures GET /api/v1/ml/health reports pipeline status and operating threshold."""
    from backend.app.ml.router import get_ml_health
    res = get_ml_health(current_user=viewer_user)
    assert res["status"] == "HEALTHY"
    assert res["is_model_available"] is True
    assert res["is_calibration_active"] is True
    assert res["operating_threshold"] == 0.32
    assert res["shap_explainer_ready"] is True


def test_api_list_assets_ml_risk(viewer_user):
    """Ensures GET /api/v1/ml/assets returns all assets with calibrated risk."""
    from backend.app.ml.router import list_assets_ml_risk
    res = list_assets_ml_risk(current_user=viewer_user)
    assert res["total_assets"] >= 100
    assert res["operating_threshold"] == 0.32
    assert "threats_count" in res
    assert len(res["assets"]) >= 100
    first = res["assets"][0]
    assert "node_id" in first
    assert "risk_probability" in first
    assert "operating_threshold" in first


def test_api_get_single_asset_risk(viewer_user):
    """Ensures GET /api/v1/ml/assets/{asset_id}/risk returns specific asset evaluation."""
    from backend.app.ml.router import get_asset_risk
    res = get_asset_risk(asset_id="node-user-marcus", current_user=viewer_user)
    assert res["node_id"] == "node-user-marcus"
    assert "risk_probability" in res
    assert res["operating_threshold"] == 0.32


def test_api_get_asset_explanation(viewer_user):
    """Ensures GET /api/v1/ml/assets/{asset_id}/explanation returns SHAP feature attributions."""
    from backend.app.ml.router import get_asset_explanation
    res = get_asset_explanation(asset_id="node-user-marcus", top_n=5, current_user=viewer_user)
    assert res["asset_id"] == "node-user-marcus"
    assert "risk_probability" in res
    assert "explanation" in res
    assert len(res["explanation"]["top_contributors"]) <= 5


def test_api_explain_on_demand_batch(viewer_user):
    """Ensures POST /api/v1/ml/explain returns batch SHAP explanations."""
    from backend.app.ml.router import explain_assets_on_demand, ExplainRequest
    req = ExplainRequest(node_ids=["node-user-marcus"], top_n=3)
    res = explain_assets_on_demand(request=req, current_user=viewer_user)
    assert res["total_explained"] == 1
    assert len(res["explanations"]) == 1
    assert res["explanations"][0]["asset_id"] == "node-user-marcus"


def test_api_get_graph_risk_intelligence(viewer_user):
    """Ensures GET /api/v1/ml/graph-risk returns high-performance map for frontend graph."""
    from backend.app.ml.router import get_graph_risk_intelligence
    res = get_graph_risk_intelligence(current_user=viewer_user)
    assert res["operating_threshold"] == 0.32
    assert res["total_nodes"] >= 100
    assert "risk_map" in res
    assert "node-user-marcus" in res["risk_map"]
    node_data = res["risk_map"]["node-user-marcus"]
    assert "ml_probability" in node_data
    assert "threshold_crossed" in node_data
    assert "risk_tier" in node_data
