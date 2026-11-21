"""Module 7.5.6: Adaptive Recommendation Engine for SafeContain AI.

Synthesizes outputs from calibration evaluation, threshold optimization, alert fatigue analysis,
and drift detection to generate structured, explainable, evidence-grounded governance recommendations.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.app.adaptive.tracker import PredictionOutcomeTracker
from backend.app.calibration.alert_analytics import AlertFatigueAnalyzer
from backend.app.calibration.calibration_engine import RiskScoreCalibrationEngine
from backend.app.calibration.drift_detector import TelemetryDriftDetector
from backend.app.calibration.models import (
    AdaptiveRecommendation,
    CalibrationStatus,
    RecommendationCategory,
)
from backend.app.calibration.threshold_optimizer import IntelligentThresholdOptimizer

logger = logging.getLogger("safecontain.calibration.recommendations")


class AdaptiveRecommendationEngine:
    """Synthesizes systemic telemetry and calibration state to generate actionable SOC recommendations."""

    _instance: Optional["AdaptiveRecommendationEngine"] = None

    def __init__(
        self,
        calibration_engine: Optional[RiskScoreCalibrationEngine] = None,
        optimizer: Optional[IntelligentThresholdOptimizer] = None,
        alert_analyzer: Optional[AlertFatigueAnalyzer] = None,
        drift_detector: Optional[TelemetryDriftDetector] = None,
        tracker: Optional[PredictionOutcomeTracker] = None,
    ):
        self.calibration_engine = calibration_engine or RiskScoreCalibrationEngine.get_instance()
        self.optimizer = optimizer or IntelligentThresholdOptimizer.get_instance()
        self.alert_analyzer = alert_analyzer or AlertFatigueAnalyzer.get_instance()
        self.drift_detector = drift_detector or TelemetryDriftDetector.get_instance()
        self.tracker = tracker or PredictionOutcomeTracker.get_instance()

    @classmethod
    def get_instance(cls) -> "AdaptiveRecommendationEngine":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def generate_recommendations(self) -> List[AdaptiveRecommendation]:
        """Evaluates live calibration and telemetry metrics to generate prioritized recommendations."""
        recommendations: List[AdaptiveRecommendation] = []

        # 1. Gather all analytical subsystem outputs
        calib_report = self.calibration_engine.evaluate_calibration()
        opt_result = self.optimizer.optimize_threshold()
        fatigue_report = self.alert_analyzer.analyze_alert_fatigue()
        drift_report = self.drift_detector.detect_drift()

        n = calib_report.sample_size

        # Rule 1: Data Quality & Sample Size Guard
        if n < 10:
            recommendations.append(
                AdaptiveRecommendation(
                    recommendation_id=f"rec-dq-{uuid.uuid4().hex[:8]}",
                    title="Insufficient Ground-Truth Telemetry for Calibration",
                    category=RecommendationCategory.DATA_QUALITY_WARNING,
                    severity="LOW",
                    explanation=(
                        f"Only {n} forecasts have verified ground-truth outcomes recorded. "
                        "A minimum of 10 evaluated observations is required before adjusting production risk thresholds."
                    ),
                    supporting_evidence={"sample_size": n, "minimum_required": 10},
                    sample_size=n,
                    confidence_level="INSUFFICIENT_DATA",
                    proposed_change="Maintain existing threshold baseline and allow prediction horizons to elapse.",
                    expected_benefit="Prevents rash threshold shifts induced by small-sample statistical variance.",
                    potential_risk="None.",
                    alternative_options=["Run historical benchmark evaluation to ingest ground truth."],
                    required_approval_role="ANALYST",
                    status="PENDING_REVIEW",
                )
            )
            return recommendations

        # Rule 2: Threshold Optimization Recommendation
        if opt_result.status == "CANDIDATE_GENERATED":
            rec_theta = opt_result.recommended_threshold
            base_theta = opt_result.baseline_threshold
            cost_red = opt_result.tradeoffs.get("cost_reduction_percent", 0.0)

            recommendations.append(
                AdaptiveRecommendation(
                    recommendation_id=f"rec-opt-{uuid.uuid4().hex[:8]}",
                    title=f"Adjust Decision Threshold to theta={rec_theta:.2f} (Cost Reduction: {cost_red:.1f}%)",
                    category=RecommendationCategory.THRESHOLD_OPTIMIZATION,
                    severity="HIGH" if cost_red >= 20.0 else "MEDIUM",
                    explanation=opt_result.rationale,
                    supporting_evidence={
                        "baseline_threshold": base_theta,
                        "candidate_threshold": rec_theta,
                        "cost_reduction_percent": cost_red,
                        "alert_delta": opt_result.tradeoffs.get("alert_volume_delta"),
                        "false_positives_delta": opt_result.tradeoffs.get("false_positive_delta"),
                        "false_negatives_delta": opt_result.tradeoffs.get("false_negative_delta"),
                        "candidate_config_id": opt_result.candidate_configuration.config_id,
                    },
                    sample_size=n,
                    confidence_level=opt_result.confidence,
                    proposed_change=(
                        f"Stage candidate threshold configuration '{opt_result.candidate_configuration.version}' "
                        f"(theta={rec_theta:.2f}) for Analyst review and Administrator activation."
                    ),
                    expected_benefit=(
                        f"Lowers composite cybersecurity breach cost by {cost_red:.1f}% while preserving "
                        f"recall at {opt_result.candidate_metrics.get('recall', 0.0) * 100:.1f}%."
                    ),
                    potential_risk=(
                        f"Alters net alert volume by {opt_result.tradeoffs.get('alert_volume_delta', 0):+d} alerts. "
                        "Ensure SOC triage capacity matches projected volume."
                    ),
                    alternative_options=[
                        "Retain baseline threshold theta=0.32 in active production.",
                        "Conduct multi-day shadow mode simulation before approval.",
                    ],
                    required_approval_role="ANALYST",
                    status="PENDING_REVIEW",
                )
            )

        # Rule 3: Calibration Miscalibration Warning
        if calib_report.calibration_status == CalibrationStatus.SEVERELY_MISCALIBRATED:
            recommendations.append(
                AdaptiveRecommendation(
                    recommendation_id=f"rec-calib-{uuid.uuid4().hex[:8]}",
                    title="Severe Model Risk Score Miscalibration Detected",
                    category=RecommendationCategory.CALIBRATION_WARNING,
                    severity="HIGH",
                    explanation=(
                        f"Expected Calibration Error is {calib_report.expected_calibration_error:.4f} (>= 0.18 threshold). "
                        "Reported probabilities deviate substantially from observed empirical compromise rates."
                    ),
                    supporting_evidence={
                        "ece": calib_report.expected_calibration_error,
                        "brier_score": calib_report.brier_score,
                        "overprediction_rate": calib_report.overprediction_rate,
                        "underprediction_rate": calib_report.underprediction_rate,
                    },
                    sample_size=n,
                    confidence_level=calib_report.confidence,
                    proposed_change="Apply Platt scaling or isotonic regression recalibration to model outputs.",
                    expected_benefit="Restores probabilistic reliability of risk scores across all dashboards.",
                    potential_risk="Requires retraining pipeline execution.",
                    alternative_options=["Adjust tier cutoffs temporarily to compensate."],
                    required_approval_role="ADMIN",
                    status="PENDING_REVIEW",
                )
            )

        # Rule 4: Alert Fatigue Mitigation
        if fatigue_report.fatigue_status in ("CRITICAL", "ELEVATED"):
            top_noisy = fatigue_report.noisy_assets[:3]
            noisy_names = [a.asset_name for a in top_noisy]
            recommendations.append(
                AdaptiveRecommendation(
                    recommendation_id=f"rec-fatigue-{uuid.uuid4().hex[:8]}",
                    title=f"Mitigate SOC Alert Fatigue (Index: {fatigue_report.alert_fatigue_index:.1f})",
                    category=RecommendationCategory.ALERT_FATIGUE_MITIGATION,
                    severity="HIGH" if fatigue_report.fatigue_status == "CRITICAL" else "MEDIUM",
                    explanation=fatigue_report.governance_advisory,
                    supporting_evidence={
                        "alert_fatigue_index": fatigue_report.alert_fatigue_index,
                        "total_alerts": fatigue_report.total_alerts_analyzed,
                        "false_alarm_ratio": fatigue_report.overall_false_alarm_ratio,
                        "top_noisy_assets": [a.model_dump() for a in top_noisy],
                    },
                    sample_size=fatigue_report.total_alerts_analyzed,
                    confidence_level="HIGH" if fatigue_report.total_alerts_analyzed >= 50 else "MEDIUM",
                    proposed_change=f"Implement targeted suppression or sensitivity tuning on: {', '.join(noisy_names)}.",
                    expected_benefit=f"Reduces false alarm burden by up to {sum(a.false_positive_count for a in top_noisy)} alerts.",
                    potential_risk="Ensure suppression rules do not mask lateral movement.",
                    alternative_options=["Raise asset-specific threat threshold by 0.05."],
                    required_approval_role="ANALYST",
                    status="PENDING_REVIEW",
                )
            )

        # Rule 5: Telemetry Drift Alert
        if drift_report.overall_drift_severity in ("CRITICAL", "MODERATE"):
            top_drifted = drift_report.feature_drift_breakdown[:3]
            recommendations.append(
                AdaptiveRecommendation(
                    recommendation_id=f"rec-drift-{uuid.uuid4().hex[:8]}",
                    title=f"Telemetry Feature Drift Detected ({drift_report.overall_drift_severity})",
                    category=RecommendationCategory.TELEMETRY_DRIFT_ALERT,
                    severity="HIGH" if drift_report.overall_drift_severity == "CRITICAL" else "MEDIUM",
                    explanation=drift_report.explanation,
                    supporting_evidence={
                        "severity": drift_report.overall_drift_severity,
                        "wasserstein_distance": drift_report.risk_score_wasserstein_distance,
                        "calibration_degraded": drift_report.calibration_degradation_detected,
                        "top_drifted_features": [f.model_dump() for f in top_drifted],
                    },
                    sample_size=drift_report.evaluated_sample_size,
                    confidence_level=drift_report.confidence,
                    proposed_change=drift_report.recommended_action,
                    expected_benefit="Prevents long-term model staleness and maintains containment fidelity.",
                    potential_risk="Retraining requires model verification before deployment.",
                    alternative_options=["Monitor for another 24-hour cycle before retraining."],
                    required_approval_role="ADMIN",
                    status="PENDING_REVIEW",
                )
            )

        # Rule 6: Nominal Operation Fallback
        if not recommendations:
            recommendations.append(
                AdaptiveRecommendation(
                    recommendation_id=f"rec-nominal-{uuid.uuid4().hex[:8]}",
                    title="Nominal Operating Status: Risk Thresholds Well-Calibrated",
                    category=RecommendationCategory.NOMINAL_OPERATION,
                    severity="INFO",
                    explanation="All risk scores, alert volumes, and telemetry distributions are operating within nominal thresholds.",
                    supporting_evidence={
                        "sample_size": n,
                        "ece": calib_report.expected_calibration_error,
                        "fatigue_index": fatigue_report.alert_fatigue_index,
                        "drift_severity": drift_report.overall_drift_severity,
                    },
                    sample_size=n,
                    confidence_level="HIGH",
                    proposed_change="Maintain existing configuration and active monitoring policies.",
                    expected_benefit="Continuous verified threat containment.",
                    potential_risk="None.",
                    alternative_options=[],
                    required_approval_role="ANALYST",
                    status="PENDING_REVIEW",
                )
            )

        return recommendations
