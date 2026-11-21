"""Unit tests for Phase 7.6 Wave 1 Core Intelligence Modules.

Verifies:
1. Domain models and contract validation.
2. Threat signal extraction engine across multiple telemetry types.
3. Risk trajectory mathematics (slope, acceleration, volatility, moving average, EMA, CUSUM, projection).
4. Threat escalation state prediction across all 5 states.
5. Critical threat protection invariant enforcement.
6. Edge case and data-sufficiency handling (N=0, N=1, N=2, NaN, Inf, duplicate timestamps).
"""

import math
from datetime import datetime, timezone, timedelta
import pytest

from backend.app.early_warning.models import (
    DataSufficiency,
    EscalationPrediction,
    EscalationState,
    RiskTrajectory,
    RiskTrajectoryPoint,
    SignalType,
    ThreatSeverity,
    ThreatSignal,
    TrajectoryDirection,
)
from backend.app.early_warning.signal_extractor import ThreatSignalExtractor
from backend.app.early_warning.trajectory_engine import RiskTrajectoryEngine
from backend.app.early_warning.escalation_engine import ThreatEscalationPredictor


# =============================================================================
# 1. DOMAIN MODELS & CONTRACT VALIDATION TESTS
# =============================================================================

def test_domain_models_valid_construction():
    """Verifies that all domain models instantiate with strict Pydantic v2 validation."""
    now = datetime.now(timezone.utc)
    sig = ThreatSignal(
        signal_id="sig-test-001",
        asset_id="srv-web-01",
        signal_type=SignalType.RISK_SPIKE,
        severity=ThreatSeverity.HIGH,
        observed_value=65.0,
        baseline_value=25.0,
        deviation=40.0,
        timestamp=now,
        source="TestEngine",
        evidence="Surge in risk score.",
        confidence=0.90,
        related_entities=["srv-web-01"],
    )
    assert sig.signal_id == "sig-test-001"
    assert sig.severity == ThreatSeverity.HIGH
    assert sig.deviation == 40.0

    traj = RiskTrajectory(
        asset_id="srv-web-01",
        current_risk=65.0,
        historical_values=[RiskTrajectoryPoint(timestamp=now, risk_score=65.0)],
        trend_direction=TrajectoryDirection.RISING,
        slope=5.2,
        acceleration=0.8,
        volatility=3.5,
        moving_average=55.0,
        ema=60.0,
        change_point_detected=False,
        data_sufficiency=DataSufficiency.SUFFICIENT,
        forecast_horizon_hours=6.0,
        projected_risk=80.0,
        projection_confidence=0.85,
    )
    assert traj.current_risk == 65.0
    assert traj.projected_risk == 80.0


# =============================================================================
# 2. THREAT SIGNAL EXTRACTION ENGINE TESTS
# =============================================================================

def test_signal_extractor_risk_spike_and_velocity():
    """Verifies detection of acute risk spikes and rapid risk velocity."""
    extractor = ThreatSignalExtractor()
    t0 = datetime(2026, 11, 20, 10, 0, tzinfo=timezone.utc)
    points = [
        RiskTrajectoryPoint(timestamp=t0, risk_score=20.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=2), risk_score=22.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=4), risk_score=55.0), # Jump +33.0 in 2h
    ]

    signals = extractor.extract_risk_signals("srv-db-01", points, baseline_risk=20.0)
    assert len(signals) >= 2, "Expected risk spike and rapid velocity signals"

    spike_sigs = [s for s in signals if s.signal_type == SignalType.RISK_SPIKE]
    assert len(spike_sigs) == 1
    assert spike_sigs[0].deviation == 33.0
    assert spike_sigs[0].severity in (ThreatSeverity.HIGH, ThreatSeverity.CRITICAL)

    vel_sigs = [s for s in signals if s.signal_type == SignalType.RAPID_RISK_INCREASE]
    assert len(vel_sigs) == 1
    assert vel_sigs[0].observed_value >= 10.0 # 33 / 2 = 16.5 pts/hr


def test_signal_extractor_alert_concentration_and_escalation():
    """Verifies detection of repeated suspicious alerts, burst frequencies, and severity escalation."""
    extractor = ThreatSignalExtractor()
    t0 = datetime(2026, 11, 20, 8, 0, tzinfo=timezone.utc)
    raw_alerts = [
        {"alert_id": "a1", "target_node_id": "srv-app-01", "alert_type": "PORT_SCAN", "severity": "LOW", "timestamp": t0.isoformat()},
        {"alert_id": "a2", "target_node_id": "srv-app-01", "alert_type": "SUSPICIOUS_LOGIN", "severity": "MEDIUM", "timestamp": (t0 + timedelta(minutes=30)).isoformat()},
        {"alert_id": "a3", "target_node_id": "srv-app-01", "alert_type": "PRIVILEGE_ESCALATION", "severity": "CRITICAL", "timestamp": (t0 + timedelta(minutes=60)).isoformat()},
        {"alert_id": "a4", "target_node_id": "srv-app-01", "alert_type": "MALWARE_EXECUTION", "severity": "CRITICAL", "timestamp": (t0 + timedelta(minutes=90)).isoformat()},
    ]

    signals = extractor.extract_alert_signals(raw_alerts)
    sig_types = [s.signal_type for s in signals]

    assert SignalType.REPEATED_SUSPICIOUS_EVENTS in sig_types
    assert SignalType.SEVERITY_ESCALATION in sig_types

    esc_sig = next(s for s in signals if s.signal_type == SignalType.SEVERITY_ESCALATION)
    assert esc_sig.severity == ThreatSeverity.CRITICAL


def test_signal_extractor_idempotent_deduplication():
    """Verifies that duplicate input feeds do not explode signal count."""
    extractor = ThreatSignalExtractor()
    t0 = datetime(2026, 11, 20, 10, 0, tzinfo=timezone.utc)
    points = [
        RiskTrajectoryPoint(timestamp=t0, risk_score=20.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=2), risk_score=60.0),
    ]

    # Run extraction twice with the exact same data
    first_run = extractor.extract_risk_signals("srv-db-01", points)
    second_run = extractor.extract_risk_signals("srv-db-01", points)

    total_sigs = extractor.get_all_signals()
    assert len(total_sigs) == len(first_run), "Deduplication failed to prevent duplicate signal entries"


# =============================================================================
# 3. RISK TRAJECTORY MATHEMATICS TESTS
# =============================================================================

def test_risk_trajectory_linear_slope_and_rising_direction():
    """Verifies ordinary least squares linear regression slope over time."""
    engine = RiskTrajectoryEngine(default_horizon_hours=6.0)
    t0 = datetime(2026, 11, 20, 0, 0, tzinfo=timezone.utc)

    # Risk strictly increases by +10.0 points every 2 hours (slope = 5.0 pts/hr)
    points = [
        RiskTrajectoryPoint(timestamp=t0, risk_score=10.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=2), risk_score=20.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=4), risk_score=30.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=6), risk_score=40.0),
    ]

    traj = engine.evaluate_trajectory("srv-host-01", points, horizon_hours=6.0)

    assert math.isclose(traj.slope, 5.0, abs_tol=0.01)
    assert traj.trend_direction == TrajectoryDirection.RISING
    assert traj.data_sufficiency == DataSufficiency.SUFFICIENT
    assert traj.projected_risk > traj.current_risk
    assert traj.projected_risk <= 100.0


def test_risk_trajectory_falling_and_stable():
    """Verifies declining and stationary risk trajectories."""
    engine = RiskTrajectoryEngine()
    t0 = datetime(2026, 11, 20, 0, 0, tzinfo=timezone.utc)

    # Falling points: -10 pts every 2 hours (slope = -5.0)
    falling_points = [
        RiskTrajectoryPoint(timestamp=t0, risk_score=80.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=2), risk_score=70.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=4), risk_score=60.0),
    ]
    traj_fall = engine.evaluate_trajectory("srv-host-02", falling_points)
    assert traj_fall.slope < -4.0
    assert traj_fall.trend_direction == TrajectoryDirection.FALLING

    # Stable points: constant risk
    stable_points = [
        RiskTrajectoryPoint(timestamp=t0, risk_score=25.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=2), risk_score=25.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=4), risk_score=25.0),
    ]
    traj_stable = engine.evaluate_trajectory("srv-host-03", stable_points)
    assert math.isclose(traj_stable.slope, 0.0, abs_tol=0.01)
    assert math.isclose(traj_stable.volatility, 0.0, abs_tol=0.01)
    assert traj_stable.trend_direction == TrajectoryDirection.STABLE


def test_risk_trajectory_volatility_and_cusum_break():
    """Verifies volatility standard deviation and CUSUM change-point break detection."""
    engine = RiskTrajectoryEngine()
    t0 = datetime(2026, 11, 20, 0, 0, tzinfo=timezone.utc)

    # Sequence with a sudden structural break after baseline
    break_points = [
        RiskTrajectoryPoint(timestamp=t0, risk_score=20.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=1), risk_score=21.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=2), risk_score=20.5),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=3), risk_score=22.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=4), risk_score=75.0), # Acute CUSUM break
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=5), risk_score=85.0),
    ]

    traj = engine.evaluate_trajectory("srv-host-04", break_points)
    assert traj.volatility > 20.0
    assert traj.change_point_detected is True
    assert "CUSUM Positive Break" in (traj.change_point_description or "")


def test_risk_trajectory_data_sufficiency_safeguards():
    """Verifies that under-sampled histories (N=0, N=1, N=2) fail safe."""
    engine = RiskTrajectoryEngine()
    t0 = datetime(2026, 11, 20, 0, 0, tzinfo=timezone.utc)

    # N = 0
    traj0 = engine.evaluate_trajectory("srv-empty", [])
    assert traj0.data_sufficiency == DataSufficiency.NO_DATA
    assert traj0.current_risk == 0.0
    assert traj0.slope == 0.0

    # N = 1
    traj1 = engine.evaluate_trajectory("srv-single", [RiskTrajectoryPoint(timestamp=t0, risk_score=40.0)])
    assert traj1.data_sufficiency == DataSufficiency.INSUFFICIENT
    assert traj1.current_risk == 40.0
    assert traj1.slope == 0.0
    assert traj1.volatility == 0.0

    # N = 2
    traj2 = engine.evaluate_trajectory("srv-double", [
        RiskTrajectoryPoint(timestamp=t0, risk_score=30.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=2), risk_score=40.0),
    ])
    assert traj2.data_sufficiency == DataSufficiency.SPARSE
    assert traj2.slope > 0.0
    assert traj2.acceleration == 0.0 # Suppressed for N=2


def test_risk_trajectory_robust_against_nan_inf_and_duplicates():
    """Verifies resilient handling of NaN, Inf, and duplicate timestamps."""
    engine = RiskTrajectoryEngine()
    t0 = datetime(2026, 11, 20, 0, 0, tzinfo=timezone.utc)

    messy_points = [
        RiskTrajectoryPoint(timestamp=t0, risk_score=20.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=1), risk_score=float("nan")),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=2), risk_score=float("inf")),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=3), risk_score=30.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=3), risk_score=40.0), # Duplicate timestamp
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=5), risk_score=150.0), # Out of bounds (clamped)
    ]

    cleaned = engine.clean_and_sort_points(messy_points)
    assert len(cleaned) == 3  # NaN and Inf dropped (2 removed), duplicate merged into 1 (1 removed), total 3
    assert cleaned[0].risk_score == 20.0
    assert cleaned[1].risk_score == 35.0  # (30 + 40) / 2
    assert cleaned[2].risk_score == 100.0  # Clamped from 150


# =============================================================================
# 4. THREAT ESCALATION PREDICTION ENGINE TESTS
# =============================================================================

def test_escalation_predictor_five_states():
    """Verifies classification across all 5 formal escalation states."""
    predictor = ThreatEscalationPredictor()
    engine = RiskTrajectoryEngine()
    t0 = datetime(2026, 11, 20, 0, 0, tzinfo=timezone.utc)

    # 1. STABLE
    pts_stable = [RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=i), risk_score=10.0) for i in range(4)]
    traj_stable = engine.evaluate_trajectory("ast-1", pts_stable)
    pred_stable = predictor.predict_escalation("ast-1", traj_stable)
    assert pred_stable.predicted_state == EscalationState.STABLE

    # 2. WATCH (low risk but with an alert signal)
    sample_signal = ThreatSignal(
        signal_id="s1", asset_id="ast-2", signal_type=SignalType.UNUSUAL_EVENT_FREQUENCY,
        severity=ThreatSeverity.LOW, observed_value=3.0, timestamp=t0, source="test", evidence="test", confidence=0.8
    )
    traj_watch = engine.evaluate_trajectory("ast-2", pts_stable)
    pred_watch = predictor.predict_escalation("ast-2", traj_watch, signals=[sample_signal])
    assert pred_watch.predicted_state == EscalationState.WATCH

    # 3. ESCALATING (moderate risk with rising slope)
    pts_esc = [
        RiskTrajectoryPoint(timestamp=t0, risk_score=25.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=1), risk_score=32.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=2), risk_score=42.0),
    ]
    traj_esc = engine.evaluate_trajectory("ast-3", pts_esc)
    pred_esc = predictor.predict_escalation("ast-3", traj_esc)
    assert pred_esc.predicted_state in (EscalationState.ESCALATING, EscalationState.HIGH_ESCALATION_RISK)

    # 4. HIGH ESCALATION RISK
    pts_high = [
        RiskTrajectoryPoint(timestamp=t0, risk_score=45.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=1), risk_score=55.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=2), risk_score=65.0),
    ]
    traj_high = engine.evaluate_trajectory("ast-4", pts_high)
    pred_high = predictor.predict_escalation("ast-4", traj_high)
    assert pred_high.predicted_state == EscalationState.HIGH_ESCALATION_RISK

    # 5. CRITICAL ESCALATION RISK (Crown Jewel with high risk and critical signal)
    crit_signal = ThreatSignal(
        signal_id="s_crit", asset_id="ast-5", signal_type=SignalType.RISK_SPIKE,
        severity=ThreatSeverity.CRITICAL, observed_value=85.0, timestamp=t0, source="test", evidence="crit", confidence=0.95
    )
    pts_crit = [
        RiskTrajectoryPoint(timestamp=t0, risk_score=60.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=1), risk_score=75.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=2), risk_score=90.0),
    ]
    traj_crit = engine.evaluate_trajectory("ast-5", pts_crit)
    pred_crit = predictor.predict_escalation("ast-5", traj_crit, signals=[crit_signal], is_crown_jewel=True)
    assert pred_crit.predicted_state == EscalationState.CRITICAL_ESCALATION_RISK


def test_critical_threat_protection_invariant():
    """Verifies that a verified active critical threat can NEVER be downgraded to WATCH or STABLE."""
    predictor = ThreatEscalationPredictor()
    engine = RiskTrajectoryEngine()
    t0 = datetime(2026, 11, 20, 0, 0, tzinfo=timezone.utc)

    # Adversarial scenario: A compromised asset with falling slope and no historical data
    falling_points = [
        RiskTrajectoryPoint(timestamp=t0, risk_score=30.0),
        RiskTrajectoryPoint(timestamp=t0 + timedelta(hours=2), risk_score=15.0),
    ]
    traj_adversarial = engine.evaluate_trajectory("ast-compromised", falling_points)

    # Call predictor with is_verified_threat=True
    pred = predictor.predict_escalation(
        asset_id="ast-compromised",
        trajectory=traj_adversarial,
        is_verified_threat=True,
        is_crown_jewel=True,
    )

    # Invariant assertion
    assert pred.is_critical_threat_protected is True
    assert pred.predicted_state in (EscalationState.HIGH_ESCALATION_RISK, EscalationState.CRITICAL_ESCALATION_RISK)
    assert pred.predicted_state not in (EscalationState.STABLE, EscalationState.WATCH)
    assert any("CRITICAL SAFETY INVARIANT" in ev for ev in pred.evidence)
