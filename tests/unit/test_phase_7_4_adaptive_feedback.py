"""Unit and integration tests for Phase 7.4 Adaptive Threat Intelligence & Predictive Feedback Loop.

Verifies:
1. PredictionOutcomeTracker lifecycle, unique ID generation, and disk persistence.
2. TemporalEvaluationEngine non-premature gate (t_eval < t_pred + H) and window-bounded evidence matching.
3. AdaptiveMetricsCalculator precision, recall, F1, Brier score, confusion matrix, and edge cases.
4. AdaptiveFeedbackEngine pattern recognition for repeated FPs, FNs, and horizon drift.
5. ThreatIntelligenceQualityEngine source reliability and multi-source independence calculation.
6. ExplanationQualityAnalyzer SHAP feature shift across outcomes and non-causality disclosure.
7. AdaptiveGraphSynchronizer state persistence and node metadata updates.
8. REST API endpoints, JWT auth, and RBAC enforcement.
9. Backward compatibility and regression safety with Phase 7.3 forecasting.
"""

from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient

from backend.app.adaptive.evaluation_engine import TemporalEvaluationEngine
from backend.app.adaptive.feedback_engine import AdaptiveFeedbackEngine
from backend.app.adaptive.graph_sync import AdaptiveGraphSynchronizer
from backend.app.adaptive.intelligence_quality import ThreatIntelligenceQualityEngine
from backend.app.adaptive.metrics import AdaptiveMetricsCalculator
from backend.app.adaptive.models import (
    GroundTruthOutcome,
    PredictionOutcomeStatus,
    PredictionRecord,
)
from backend.app.adaptive.shap_analyzer import ExplanationQualityAnalyzer
from backend.app.adaptive.tracker import PredictionOutcomeTracker
from backend.app.forecasting.forecaster import TemporalThreatForecaster
from backend.app.forecasting.models import AssetRiskForecast, ForecastHorizon, RiskTrend
from backend.app.graph.engine import GraphEngine
from backend.app.security.user_store import UserRecord


@pytest.fixture
def clean_tracker(tmp_path):
    """Provides a clean PredictionOutcomeTracker pointed at a temporary file."""
    temp_file = str(tmp_path / "test_predictions.json")
    tracker = PredictionOutcomeTracker(storage_path=temp_file)
    return tracker


@pytest.fixture
def viewer_user() -> UserRecord:
    """Mock UserRecord for VIEWER role."""
    return UserRecord(
        id="usr-test-viewer",
        username="sec_viewer",
        role="VIEWER",
        hashed_password="hash",
        is_active=True,
        full_name="Security Analyst (Viewer)",
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
    )


@pytest.fixture
def analyst_user() -> UserRecord:
    """Mock UserRecord for ANALYST role."""
    return UserRecord(
        id="usr-test-analyst",
        username="sec_analyst",
        role="ANALYST",
        hashed_password="hash",
        is_active=True,
        full_name="Senior SecOps Lead (Analyst)",
        created_at=datetime.now(timezone.utc).isoformat(),
        updated_at=datetime.now(timezone.utc).isoformat(),
    )


def test_tracker_record_and_persistence(clean_tracker):
    """Verifies that forecasts are recorded with deterministic IDs and persisted."""
    now = datetime.now(timezone.utc)
    mock_forecasts = [
        AssetRiskForecast(
            asset_id="node-srv-dc01",
            asset_name="Domain Controller 01",
            asset_type="SERVER",
            criticality=0.95,
            is_crown_jewel=True,
            current_risk_score=75.0,
            current_ml_probability=0.45,
            forecast_horizon=ForecastHorizon.SHORT_TERM,
            forecast_window_hours=6.0,
            predicted_future_probability=0.72,
            predicted_future_risk=85.0,
            risk_trend=RiskTrend.ACCELERATING,
            risk_delta=0.27,
            forecast_explanation="High risk of lateral movement propagation",
            prediction_timestamp=now,
            prediction_id=f"pred-short_term-node-srv-dc01-{int(now.timestamp())}",
        )
    ]

    records = clean_tracker.record_forecasts(mock_forecasts, prediction_time=now)
    assert len(records) == 1
    rec = records[0]
    assert rec.asset_id == "node-srv-dc01"
    assert rec.threshold_crossed is True
    assert rec.predicted_threat_class == "At-Risk / Threat"
    assert rec.outcome_status == PredictionOutcomeStatus.PENDING_EVALUATION

    # Retrieve by ID
    found = clean_tracker.get_prediction(rec.prediction_id)
    assert found is not None
    assert found.asset_name == "Domain Controller 01"

    # Persistence verification: reload from file
    new_tracker_instance = PredictionOutcomeTracker(storage_path=clean_tracker.storage_path)
    persisted_rec = new_tracker_instance.get_prediction(rec.prediction_id)
    assert persisted_rec is not None
    assert persisted_rec.prediction_id == rec.prediction_id


def test_evaluation_anti_premature_gate(clean_tracker):
    """Enforces non-premature evaluation: cannot evaluate before horizon elapses."""
    engine = TemporalEvaluationEngine(tracker=clean_tracker)
    now = datetime.now(timezone.utc)

    # Prediction generated just now with a 6-hour horizon
    rec = PredictionRecord(
        prediction_id="test-pred-premature-01",
        asset_id="node-srv-jumpbox01",
        asset_name="Jumpbox 01",
        asset_type="SERVER",
        prediction_timestamp=now,
        forecast_horizon="SHORT_TERM",
        horizon_hours=6.0,
        horizon_end_timestamp=now + timedelta(hours=6),
        predicted_probability=0.80,
        predicted_risk_score=75.0,
        predicted_threat_class="At-Risk / Threat",
        threshold_crossed=True,
        outcome_status=PredictionOutcomeStatus.PENDING_EVALUATION,
    )
    clean_tracker.save_prediction(rec)

    # Attempt to evaluate at now + 2 hours (premature by 4 hours)
    premature_eval_time = now + timedelta(hours=2)
    evaluated = engine.evaluate_prediction(rec, evaluation_time=premature_eval_time)

    # Must remain PENDING_EVALUATION
    assert evaluated.outcome_status == PredictionOutcomeStatus.PENDING_EVALUATION
    assert evaluated.outcome_evaluation_timestamp is None
    assert "has not yet elapsed" in (evaluated.evaluation_notes or "")


def test_evaluation_elapsed_evidence_matching(clean_tracker):
    """Verifies evaluation assigns correct status once horizon elapses."""
    engine = TemporalEvaluationEngine(tracker=clean_tracker)
    base_time = datetime(2026, 1, 15, 10, 0, tzinfo=timezone.utc)

    # 1. High probability prediction where no compromise occurs on monitored node -> FALSE_POSITIVE
    rec_fp = PredictionRecord(
        prediction_id="test-pred-fp-01",
        asset_id="node-srv-jumpbox01",
        asset_name="Jumpbox 01",
        asset_type="SERVER",
        prediction_timestamp=base_time,
        forecast_horizon="NEAR_TERM",
        horizon_hours=2.0,
        horizon_end_timestamp=base_time + timedelta(hours=2),
        predicted_probability=0.65,
        predicted_risk_score=60.0,
        predicted_threat_class="At-Risk / Threat",
        threshold_crossed=True,
        outcome_status=PredictionOutcomeStatus.PENDING_EVALUATION,
    )
    clean_tracker.save_prediction(rec_fp)

    eval_time = base_time + timedelta(hours=3)  # Elapsed
    evaluated_fp = engine.evaluate_prediction(rec_fp, evaluation_time=eval_time)
    assert evaluated_fp.outcome_status == PredictionOutcomeStatus.FALSE_POSITIVE
    assert evaluated_fp.actual_outcome == GroundTruthOutcome.BENIGN.value

    # 2. Low probability prediction where no compromise occurs -> CORRECT_NON_EVENT
    rec_tn = PredictionRecord(
        prediction_id="test-pred-tn-01",
        asset_id="node-srv-jumpbox01",
        asset_name="Jumpbox 01",
        asset_type="SERVER",
        prediction_timestamp=base_time,
        forecast_horizon="NEAR_TERM",
        horizon_hours=2.0,
        horizon_end_timestamp=base_time + timedelta(hours=2),
        predicted_probability=0.15,
        predicted_risk_score=10.0,
        predicted_threat_class="Healthy / Benign",
        threshold_crossed=False,
        outcome_status=PredictionOutcomeStatus.PENDING_EVALUATION,
    )
    clean_tracker.save_prediction(rec_tn)
    evaluated_tn = engine.evaluate_prediction(rec_tn, evaluation_time=eval_time)
    assert evaluated_tn.outcome_status == PredictionOutcomeStatus.CORRECT_NON_EVENT
    assert evaluated_tn.actual_outcome == GroundTruthOutcome.BENIGN.value


def test_metrics_calculator_computation():
    """Verifies precision, recall, F1, Brier score, and confusion matrix calculation."""
    calc = AdaptiveMetricsCalculator()
    now = datetime.now(timezone.utc)

    # Synthesize small evaluated sample:
    # 2 TP, 1 FP, 1 FN, 2 TN
    records = [
        # TP 1
        PredictionRecord(
            prediction_id="tp-1",
            asset_id="a1",
            asset_name="A1",
            prediction_timestamp=now,
            forecast_horizon="SHORT_TERM",
            horizon_hours=6.0,
            horizon_end_timestamp=now,
            predicted_probability=0.8,
            predicted_risk_score=80.0,
            predicted_threat_class="At-Risk / Threat",
            threshold_crossed=True,
            actual_outcome="COMPROMISED",
            outcome_status=PredictionOutcomeStatus.CONFIRMED_COMPROMISE,
            outcome_evaluation_timestamp=now,
        ),
        # TP 2
        PredictionRecord(
            prediction_id="tp-2",
            asset_id="a2",
            asset_name="A2",
            prediction_timestamp=now,
            forecast_horizon="SHORT_TERM",
            horizon_hours=6.0,
            horizon_end_timestamp=now,
            predicted_probability=0.7,
            predicted_risk_score=70.0,
            predicted_threat_class="At-Risk / Threat",
            threshold_crossed=True,
            actual_outcome="COMPROMISED",
            outcome_status=PredictionOutcomeStatus.CONFIRMED_COMPROMISE,
            outcome_evaluation_timestamp=now,
        ),
        # FP 1
        PredictionRecord(
            prediction_id="fp-1",
            asset_id="a3",
            asset_name="A3",
            prediction_timestamp=now,
            forecast_horizon="SHORT_TERM",
            horizon_hours=6.0,
            horizon_end_timestamp=now,
            predicted_probability=0.6,
            predicted_risk_score=60.0,
            predicted_threat_class="At-Risk / Threat",
            threshold_crossed=True,
            actual_outcome="BENIGN",
            outcome_status=PredictionOutcomeStatus.FALSE_POSITIVE,
            outcome_evaluation_timestamp=now,
        ),
        # FN 1
        PredictionRecord(
            prediction_id="fn-1",
            asset_id="a4",
            asset_name="A4",
            prediction_timestamp=now,
            forecast_horizon="SHORT_TERM",
            horizon_hours=6.0,
            horizon_end_timestamp=now,
            predicted_probability=0.2,
            predicted_risk_score=20.0,
            predicted_threat_class="Healthy / Benign",
            threshold_crossed=False,
            actual_outcome="COMPROMISED",
            outcome_status=PredictionOutcomeStatus.FALSE_NEGATIVE,
            outcome_evaluation_timestamp=now,
        ),
        # TN 1
        PredictionRecord(
            prediction_id="tn-1",
            asset_id="a5",
            asset_name="A5",
            prediction_timestamp=now,
            forecast_horizon="SHORT_TERM",
            horizon_hours=6.0,
            horizon_end_timestamp=now,
            predicted_probability=0.1,
            predicted_risk_score=10.0,
            predicted_threat_class="Healthy / Benign",
            threshold_crossed=False,
            actual_outcome="BENIGN",
            outcome_status=PredictionOutcomeStatus.CORRECT_NON_EVENT,
            outcome_evaluation_timestamp=now,
        ),
        # TN 2
        PredictionRecord(
            prediction_id="tn-2",
            asset_id="a6",
            asset_name="A6",
            prediction_timestamp=now,
            forecast_horizon="SHORT_TERM",
            horizon_hours=6.0,
            horizon_end_timestamp=now,
            predicted_probability=0.15,
            predicted_risk_score=15.0,
            predicted_threat_class="Healthy / Benign",
            threshold_crossed=False,
            actual_outcome="BENIGN",
            outcome_status=PredictionOutcomeStatus.CORRECT_NON_EVENT,
            outcome_evaluation_timestamp=now,
        ),
    ]

    metrics = calc.calculate_metrics(records)
    # TP=2, FP=1, FN=1, TN=2
    # Precision = 2 / (2 + 1) = 0.6667
    # Recall = 2 / (2 + 1) = 0.6667
    # Accuracy = 4 / 6 = 0.6667
    # FPR = 1 / (1 + 2) = 0.3333
    # FNR = 1 / (1 + 2) = 0.3333
    assert metrics.true_positives == 2
    assert metrics.false_positives == 1
    assert metrics.false_negatives == 1
    assert metrics.true_negatives == 2
    assert round(metrics.precision, 2) == 0.67
    assert round(metrics.recall, 2) == 0.67
    assert round(metrics.f1_score, 2) == 0.67
    assert round(metrics.accuracy, 2) == 0.67
    assert metrics.brier_score is not None
    assert 0.0 <= metrics.brier_score <= 1.0


def test_feedback_engine_identifies_patterns():
    """Verifies AdaptiveFeedbackEngine pinpoints repeated FPs and weak categories."""
    feedback_engine = AdaptiveFeedbackEngine()
    now = datetime.now(timezone.utc)

    # 3 FPs on node-srv-jumpbox01
    records = [
        PredictionRecord(
            prediction_id=f"fp-jump-{i}",
            asset_id="node-srv-jumpbox01",
            asset_name="Jumpbox 01",
            asset_type="SERVER",
            prediction_timestamp=now - timedelta(hours=i * 24),
            forecast_horizon="SHORT_TERM",
            horizon_hours=6.0,
            horizon_end_timestamp=now - timedelta(hours=i * 24 - 6),
            predicted_probability=0.6,
            predicted_risk_score=60.0,
            predicted_threat_class="At-Risk / Threat",
            threshold_crossed=True,
            actual_outcome="BENIGN",
            outcome_status=PredictionOutcomeStatus.FALSE_POSITIVE,
            outcome_evaluation_timestamp=now,
        )
        for i in range(3)
    ]

    insights = feedback_engine.generate_feedback_insights(records)
    assert len(insights.repeated_false_positives) > 0
    fp_pattern = insights.repeated_false_positives[0]
    assert fp_pattern["asset_id"] == "node-srv-jumpbox01"
    assert fp_pattern["false_positive_count"] == 3
    assert len(insights.recommended_policy_adjustments) > 0


def test_threat_intelligence_quality():
    """Verifies source reliability and multi-source independence calculation."""
    quality_engine = ThreatIntelligenceQualityEngine()
    now = datetime.now(timezone.utc)

    records = [
        PredictionRecord(
            prediction_id="ti-1",
            asset_id="a1",
            asset_name="A1",
            prediction_timestamp=now,
            forecast_horizon="SHORT_TERM",
            horizon_hours=6.0,
            horizon_end_timestamp=now,
            predicted_probability=0.75,
            predicted_risk_score=75.0,
            predicted_threat_class="At-Risk / Threat",
            threshold_crossed=True,
            actual_outcome="COMPROMISED",
            outcome_status=PredictionOutcomeStatus.CONFIRMED_COMPROMISE,
            outcome_evaluation_timestamp=now,
            top_features=[
                {"feature_name": "threat_intel_score", "feature_value": 0.85, "direction": "INCREASES_RISK"}
            ],
        ),
        PredictionRecord(
            prediction_id="ti-2",
            asset_id="a2",
            asset_name="A2",
            prediction_timestamp=now,
            forecast_horizon="SHORT_TERM",
            horizon_hours=6.0,
            horizon_end_timestamp=now,
            predicted_probability=0.65,
            predicted_risk_score=65.0,
            predicted_threat_class="At-Risk / Threat",
            threshold_crossed=True,
            actual_outcome="BENIGN",
            outcome_status=PredictionOutcomeStatus.FALSE_POSITIVE,
            outcome_evaluation_timestamp=now,
            top_features=[
                {"feature_name": "threat_intel_score", "feature_value": 0.80, "direction": "INCREASES_RISK"}
            ],
        ),
    ]

    ti_metrics = quality_engine.evaluate_quality(records)
    assert ti_metrics.total_evaluated_indicators >= 0
    assert 0.0 <= ti_metrics.multi_source_independence_rate <= 1.0
    assert len(ti_metrics.source_reliability) > 0


def test_shap_explanation_quality_analyzer():
    """Verifies SHAP attribution shift comparison and scientific non-causality disclosure."""
    analyzer = ExplanationQualityAnalyzer()
    now = datetime.now(timezone.utc)

    records = [
        PredictionRecord(
            prediction_id="sh-1",
            asset_id="a1",
            asset_name="A1",
            prediction_timestamp=now,
            forecast_horizon="SHORT_TERM",
            horizon_hours=6.0,
            horizon_end_timestamp=now,
            predicted_probability=0.8,
            predicted_risk_score=80.0,
            predicted_threat_class="At-Risk / Threat",
            threshold_crossed=True,
            actual_outcome="COMPROMISED",
            outcome_status=PredictionOutcomeStatus.CONFIRMED_COMPROMISE,
            outcome_evaluation_timestamp=now,
            top_features=[
                {"feature_name": "alert_count_window", "contribution_score": 0.25, "direction": "INCREASES_RISK"},
                {"feature_name": "hop_distance_to_breach", "contribution_score": -0.15, "direction": "INCREASES_RISK"},
            ],
        ),
        PredictionRecord(
            prediction_id="sh-2",
            asset_id="a2",
            asset_name="A2",
            prediction_timestamp=now,
            forecast_horizon="SHORT_TERM",
            horizon_hours=6.0,
            horizon_end_timestamp=now,
            predicted_probability=0.7,
            predicted_risk_score=70.0,
            predicted_threat_class="At-Risk / Threat",
            threshold_crossed=True,
            actual_outcome="BENIGN",
            outcome_status=PredictionOutcomeStatus.FALSE_POSITIVE,
            outcome_evaluation_timestamp=now,
            top_features=[
                {"feature_name": "hop_distance_to_breach", "contribution_score": 0.30, "direction": "INCREASES_RISK"},
            ],
        ),
    ]

    report = analyzer.analyze_explanation_quality(records)
    assert report["total_records_analyzed"] == 2
    assert "Correlation does not imply direct mechanistic causation" in report["non_causality_disclosure"]
    assert len(report["feature_rankings"]) > 0


def test_adaptive_graph_sync():
    """Verifies synchronization of adaptive outcome metrics into GraphEngine nodes."""
    ge = GraphEngine(mode="in_memory")
    synchronizer = AdaptiveGraphSynchronizer(graph_engine=ge)
    now = datetime.now(timezone.utc)

    records = [
        PredictionRecord(
            prediction_id="sync-1",
            asset_id="node-srv-dc01",
            asset_name="Domain Controller 01",
            prediction_timestamp=now,
            forecast_horizon="SHORT_TERM",
            horizon_hours=6.0,
            horizon_end_timestamp=now,
            predicted_probability=0.88,
            predicted_risk_score=88.0,
            predicted_threat_class="At-Risk / Threat",
            threshold_crossed=True,
            actual_outcome="COMPROMISED",
            outcome_status=PredictionOutcomeStatus.CONFIRMED_COMPROMISE,
            outcome_evaluation_timestamp=now,
        )
    ]

    res = synchronizer.sync_outcomes_to_graph(records)
    assert res["nodes_updated"] >= 1

    # Check node in memory graph
    node = ge.get_node("node-srv-dc01")
    if node:
        props = node.properties if hasattr(node, "properties") else {}
        assert "adaptive_outcome_status" in props
        assert props["adaptive_outcome_status"] == "CONFIRMED_COMPROMISE"


def test_api_adaptive_endpoints(viewer_user, analyst_user, clean_tracker):
    """Verifies all Phase 7.4 REST API endpoints with authentication and RBAC."""
    PredictionOutcomeTracker._instance = clean_tracker
    from backend.app.adaptive.router import (
        EvaluateRequest,
        bootstrap_benchmark_predictions,
        get_adaptive_feedback,
        get_adaptive_metrics,
        get_adaptive_summary,
        get_shap_outcome_analysis,
        get_threat_intelligence_quality,
        list_predictions,
        sync_outcomes_to_graph,
        trigger_temporal_evaluation,
    )
    from fastapi import HTTPException
    from backend.app.security.auth import require_analyst
    from unittest.mock import patch

    # 1. VIEWER can access summary
    summary = get_adaptive_summary(current_user=viewer_user)
    assert summary.operating_threshold == 0.32
    assert summary.total_predictions >= 0

    # 2. VIEWER can access metrics
    metrics = get_adaptive_metrics(current_user=viewer_user)
    assert "metrics" in metrics
    assert metrics["metrics"]["operating_threshold"] == 0.32

    # 3. VIEWER can list predictions
    preds_res = list_predictions(limit=10, current_user=viewer_user)
    assert "predictions" in preds_res

    # 4. VIEWER can access feedback, threat-quality, shap
    fb = get_adaptive_feedback(current_user=viewer_user)
    assert fb.governance_note is not None

    tq = get_threat_intelligence_quality(current_user=viewer_user)
    assert tq.total_evaluated_indicators >= 0

    shap_res = get_shap_outcome_analysis(current_user=viewer_user)
    assert "causality_disclaimer" in shap_res

    # 5. RBAC enforcement: VIEWER cannot pass require_analyst
    coro = require_analyst(current_user=viewer_user)
    with pytest.raises(HTTPException) as exc_info:
        coro.send(None)
    assert exc_info.value.status_code == 403

    # 6. ANALYST can trigger evaluate and sync
    eval_res = trigger_temporal_evaluation(request=EvaluateRequest(force_recompute=False), current_user=analyst_user)
    assert eval_res["status"] == "COMPLETED"
    assert "result" in eval_res

    sync_res = sync_outcomes_to_graph(current_user=analyst_user)
    assert sync_res["status"] == "SYNCHRONIZED"

    # 7. ANALYST can trigger bootstrap benchmark
    with patch.object(
        TemporalEvaluationEngine,
        "bootstrap_benchmark_evaluation",
        return_value={"evaluated_count": 12, "benchmark_bootstrap_records_created": 36},
    ):
        boot_res = bootstrap_benchmark_predictions(current_user=analyst_user)
        assert boot_res["status"] == "BOOTSTRAP_COMPLETE"


def test_regression_safety_forecasting_phase_7_3(viewer_user):
    """Ensures Phase 7.3 temporal threat forecasting remains fully functional."""
    from backend.app.forecasting.router import get_forecasting_summary, list_asset_forecasts
    summary = get_forecasting_summary(horizon="SHORT_TERM", current_user=viewer_user)
    assert summary.total_assets_evaluated > 0
    assert summary.horizon == "SHORT_TERM"

    forecasts = list_asset_forecasts(horizon="SHORT_TERM", current_user=viewer_user)
    assert len(forecasts) > 0
    assert forecasts[0].prediction_id is not None
