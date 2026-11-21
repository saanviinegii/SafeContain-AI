"""Module 7.6.3: Threat Escalation Prediction Engine.

Evaluates an asset's risk trajectory, multi-source behavioral threat signals, asset criticality,
and topological sensitivity to predict future threat state transitions across 5 formal states:
STABLE, WATCH, ESCALATING, HIGH_ESCALATION_RISK, and CRITICAL_ESCALATION_RISK.

Strictly enforces the Critical Threat Protection Invariant.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.app.early_warning.models import (
    DataSufficiency,
    EscalationPrediction,
    EscalationState,
    RiskTrajectory,
    ThreatSeverity,
    ThreatSignal,
    TrajectoryDirection,
)

logger = logging.getLogger("safecontain.early_warning.escalation_engine")


class ThreatEscalationPredictor:
    """Predicts threat state escalation trajectories using evidence-grounded risk and behavioral indicators."""

    def __init__(self, critical_threshold: float = 70.0, high_threshold: float = 50.0):
        self.critical_threshold = critical_threshold
        self.high_threshold = high_threshold

    def calculate_signal_impact_score(self, signals: List[ThreatSignal]) -> float:
        """Calculates normalized signal impact score [0.0 - 100.0] based on signal count and severities."""
        if not signals:
            return 0.0

        weight_map = {
            ThreatSeverity.CRITICAL: 35.0,
            ThreatSeverity.HIGH: 20.0,
            ThreatSeverity.MEDIUM: 10.0,
            ThreatSeverity.LOW: 5.0,
        }
        total_impact = sum(weight_map.get(s.severity, 10.0) for s in signals)
        return min(100.0, total_impact)

    def predict_escalation(
        self,
        asset_id: str,
        trajectory: RiskTrajectory,
        signals: Optional[List[ThreatSignal]] = None,
        asset_name: Optional[str] = None,
        criticality: float = 0.5,
        is_crown_jewel: bool = False,
        is_verified_threat: bool = False,
    ) -> EscalationPrediction:
        """Predicts future threat state with explainable contributing indicators and invariant protection."""
        now = datetime.now(timezone.utc)
        asset_label = asset_name or asset_id
        active_signals = signals or []

        # ---------------------------------------------------------------------
        # 1. Determine Current Threat State based on empirical current risk
        # ---------------------------------------------------------------------
        current_risk = trajectory.current_risk
        if current_risk >= self.critical_threshold:
            current_state = EscalationState.CRITICAL_ESCALATION_RISK
        elif current_risk >= self.high_threshold:
            current_state = EscalationState.HIGH_ESCALATION_RISK
        elif current_risk >= 30.0:
            current_state = EscalationState.ESCALATING
        elif current_risk >= 15.0 or len(active_signals) > 0:
            current_state = EscalationState.WATCH
        else:
            current_state = EscalationState.STABLE

        # ---------------------------------------------------------------------
        # 2. Compute Multi-Factor Escalation Score [0.0 - 100.0]
        # ---------------------------------------------------------------------
        # Component A: Current Risk (40%)
        risk_comp = current_risk * 0.40

        # Component B: Trajectory Velocity & Acceleration (25%)
        # Positive slope and acceleration elevate future breach probability
        velocity_factor = max(0.0, min(100.0, trajectory.slope * 8.0 + trajectory.acceleration * 15.0))
        if trajectory.trend_direction == TrajectoryDirection.RISING:
            velocity_factor = max(velocity_factor, 20.0)
        elif trajectory.trend_direction == TrajectoryDirection.FALLING:
            velocity_factor = max(0.0, velocity_factor - 15.0)
        velocity_comp = velocity_factor * 0.25

        # Component C: Active Behavioral Threat Signals (20%)
        signal_impact = self.calculate_signal_impact_score(active_signals)
        signal_comp = signal_impact * 0.20

        # Component D: Business Impact & Crown Jewel Sensitivity (15%)
        crit_scale = 100.0 if is_crown_jewel else (criticality * 100.0)
        crit_comp = crit_scale * 0.15

        escalation_score = min(100.0, max(0.0, round(risk_comp + velocity_comp + signal_comp + crit_comp, 2)))

        # ---------------------------------------------------------------------
        # 3. Predict Future Threat State
        # ---------------------------------------------------------------------
        has_critical_signal = any(s.severity == ThreatSeverity.CRITICAL for s in active_signals)

        if escalation_score >= 75.0 or (is_crown_jewel and escalation_score >= 60.0) or (has_critical_signal and current_risk >= 50.0):
            predicted_state = EscalationState.CRITICAL_ESCALATION_RISK
        elif escalation_score >= 55.0 or (current_risk >= 45.0 and trajectory.slope > 0.0):
            predicted_state = EscalationState.HIGH_ESCALATION_RISK
        elif escalation_score >= 35.0 or trajectory.slope >= 0.8:
            predicted_state = EscalationState.ESCALATING
        elif escalation_score >= 20.0 or len(active_signals) > 0:
            predicted_state = EscalationState.WATCH
        else:
            predicted_state = EscalationState.STABLE

        # ---------------------------------------------------------------------
        # 4. Critical Threat Protection Invariant Enforcement
        # ---------------------------------------------------------------------
        # Invariant: A verified active critical threat or confirmed compromise
        # MUST NEVER be downgraded to WATCH or STABLE, regardless of missing data
        # or low prediction confidence.
        is_invariant_triggered = False
        if is_verified_threat:
            if predicted_state in (EscalationState.STABLE, EscalationState.WATCH, EscalationState.ESCALATING):
                predicted_state = EscalationState.CRITICAL_ESCALATION_RISK if is_crown_jewel else EscalationState.HIGH_ESCALATION_RISK
                is_invariant_triggered = True
                escalation_score = max(escalation_score, 75.0 if is_crown_jewel else 60.0)
                logger.warning(
                    "Critical threat protection invariant enforced for asset %s: state clamped to %s.",
                    asset_id,
                    predicted_state.value,
                )

        # ---------------------------------------------------------------------
        # 5. Evidence & Recommended Actions Compilation
        # ---------------------------------------------------------------------
        evidence_items: List[str] = []
        evidence_items.append(f"Current risk posture: {current_risk:.1f} (Trend: {trajectory.trend_direction.value}, Slope: {trajectory.slope:+.2f} pts/hr).")
        if trajectory.change_point_detected and trajectory.change_point_description:
            evidence_items.append(trajectory.change_point_description)
        if active_signals:
            evidence_items.append(f"Observed {len(active_signals)} active behavioral signals (Max severity: {max((s.severity.value for s in active_signals), default='NONE')}).")
        if is_crown_jewel:
            evidence_items.append("Asset is designated as an Enterprise Crown Jewel.")
        if is_invariant_triggered:
            evidence_items.append("CRITICAL SAFETY INVARIANT: Active verified threat detected; state clamped to prevent alert suppression.")

        recommended_actions: List[str] = []
        if predicted_state == EscalationState.CRITICAL_ESCALATION_RISK:
            recommended_actions.append("Initiate immediate SOC containment review and isolate affected lateral ingress routes.")
            recommended_actions.append("Verify forensic process logs and terminate unauthorized parent-child execution chains.")
        elif predicted_state == EscalationState.HIGH_ESCALATION_RISK:
            recommended_actions.append("Elevate monitoring cadence to continuous high-fidelity telemetry streaming.")
            recommended_actions.append("Audit authentication tokens and revoke stale active sessions.")
        elif predicted_state == EscalationState.ESCALATING:
            recommended_actions.append("Inspect recent configuration changes and review upstream network connection attempts.")
        elif predicted_state == EscalationState.WATCH:
            recommended_actions.append("Maintain baseline observation and correlate secondary event telemetry.")
        else:
            recommended_actions.append("Standard periodic telemetry monitoring active.")

        # Generate deterministic prediction identifier
        pred_raw = f"{asset_id}:{predicted_state.value}:{now.strftime('%Y%m%d%H')}:{escalation_score:.1f}"
        pred_token = hashlib.sha256(pred_raw.encode("utf-8")).hexdigest()[:12]
        pred_id = f"esc-{predicted_state.value.lower()[:6]}-{pred_token}"

        # Statistically grounded probability: Only provided when sample size is SUFFICIENT
        # Using sigmoid transformation of escalation score: P = 1 / (1 + exp(-(score - 50)/15))
        escalation_prob = None
        if trajectory.data_sufficiency == DataSufficiency.SUFFICIENT:
            import math
            escalation_prob = round(1.0 / (1.0 + math.exp(-(escalation_score - 50.0) / 15.0)), 4)

        return EscalationPrediction(
            prediction_id=pred_id,
            asset_id=asset_id,
            asset_name=asset_label,
            is_crown_jewel=is_crown_jewel,
            criticality=criticality,
            current_state=current_state,
            predicted_state=predicted_state,
            escalation_risk_score=escalation_score,
            escalation_probability=escalation_prob,
            confidence=trajectory.projection_confidence,
            contributing_signals=active_signals,
            evidence=evidence_items,
            prediction_horizon_hours=trajectory.forecast_horizon_hours,
            data_sufficiency=trajectory.data_sufficiency,
            recommended_investigation_actions=recommended_actions,
            is_critical_threat_protected=is_invariant_triggered,
            generated_at=now,
        )
