"""Module 7.5.5: Telemetry Drift & Risk Drift Detector for SafeContain AI.

Measures distribution shift across enterprise telemetry features and risk scores over time.
Computes Population Stability Index (PSI), Kolmogorov-Smirnov statistics, 1D Wasserstein distance,
calibration degradation (Brier score delta), and sensor coverage gaps.
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from scipy import stats

from backend.app.adaptive.models import PredictionRecord
from backend.app.adaptive.tracker import PredictionOutcomeTracker
from backend.app.calibration.calibration_engine import RiskScoreCalibrationEngine
from backend.app.calibration.models import (
    FeatureDriftItem,
    TelemetryDriftReport,
)
from backend.app.ml.dataset_loader import DatasetLoader

logger = logging.getLogger("safecontain.calibration.drift")

PSI_STABLE_THRESHOLD = 0.10
PSI_SIGNIFICANT_THRESHOLD = 0.25
EPSILON = 1e-4


class TelemetryDriftDetector:
    """Detects telemetry feature drift, risk score distribution shifts, and sensor coverage gaps."""

    _instance: Optional["TelemetryDriftDetector"] = None

    def __init__(
        self,
        tracker: Optional[PredictionOutcomeTracker] = None,
        loader: Optional[DatasetLoader] = None,
        calibration_engine: Optional[RiskScoreCalibrationEngine] = None,
    ):
        self.tracker = tracker or PredictionOutcomeTracker.get_instance()
        self.loader = loader or DatasetLoader()
        self.calibration_engine = calibration_engine or RiskScoreCalibrationEngine.get_instance()

    @classmethod
    def get_instance(cls) -> "TelemetryDriftDetector":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @staticmethod
    def calculate_psi(
        baseline: np.ndarray,
        current: np.ndarray,
        num_bins: int = 5,
    ) -> float:
        """Calculates Population Stability Index (PSI) between baseline and current distributions."""
        if len(baseline) == 0 or len(current) == 0:
            return 0.0

        # Create quantile-based bins from baseline
        quantiles = np.linspace(0, 100, num_bins + 1)
        bin_edges = np.percentile(baseline, quantiles)
        bin_edges[0] = -np.inf
        bin_edges[-1] = np.inf

        baseline_counts, _ = np.histogram(baseline, bins=bin_edges)
        current_counts, _ = np.histogram(current, bins=bin_edges)

        baseline_pct = np.maximum(baseline_counts / len(baseline), EPSILON)
        current_pct = np.maximum(current_counts / len(current), EPSILON)

        # Normalize to ensure sum is 1.0
        baseline_pct /= np.sum(baseline_pct)
        current_pct /= np.sum(current_pct)

        psi_val = np.sum((current_pct - baseline_pct) * np.log(current_pct / baseline_pct))
        return round(float(max(0.0, psi_val)), 4)

    def detect_drift(
        self,
        custom_records: Optional[List[PredictionRecord]] = None,
    ) -> TelemetryDriftReport:
        """Compares historical baseline vs current window telemetry, risk scores, and calibration."""
        records = custom_records if custom_records is not None else self.tracker.get_all_predictions()
        n = len(records)

        if n < 10:
            return TelemetryDriftReport(
                drift_detected=False,
                overall_drift_severity="STABLE",
                risk_score_wasserstein_distance=0.0,
                calibration_degradation_detected=False,
                baseline_brier_score=None,
                current_brier_score=None,
                sensor_coverage_gap_count=0,
                evaluated_sample_size=n,
                feature_drift_breakdown=[],
                confidence="INSUFFICIENT_DATA",
                baseline_window="N/A",
                current_window="N/A",
                explanation=f"Insufficient sample size ({n} < 10) to evaluate distribution stability.",
                recommended_action="Accumulate additional telemetry before running drift diagnostics.",
            )

        # Split records chronologically into baseline window (earlier 50%) and current window (later 50%)
        sorted_records = sorted(records, key=lambda x: x.prediction_timestamp)
        midpoint = len(sorted_records) // 2

        baseline_records = sorted_records[:midpoint]
        current_records = sorted_records[midpoint:]

        t_base_start = baseline_records[0].prediction_timestamp.strftime("%Y-%m-%d %H:%M")
        t_base_end = baseline_records[-1].prediction_timestamp.strftime("%Y-%m-%d %H:%M")
        t_curr_start = current_records[0].prediction_timestamp.strftime("%Y-%m-%d %H:%M")
        t_curr_end = current_records[-1].prediction_timestamp.strftime("%Y-%m-%d %H:%M")

        base_win_str = f"{t_base_start} to {t_base_end}"
        curr_win_str = f"{t_curr_start} to {t_curr_end}"

        # 1. Risk Score Distribution Shift (Wasserstein Distance)
        base_risks = np.array([r.predicted_risk_score for r in baseline_records], dtype=float)
        curr_risks = np.array([r.predicted_risk_score for r in current_records], dtype=float)
        wasserstein_dist = round(float(stats.wasserstein_distance(base_risks, curr_risks)), 4)

        # 2. Calibration Degradation (Brier score delta)
        base_eval = self.calibration_engine.evaluate_calibration(custom_records=baseline_records)
        curr_eval = self.calibration_engine.evaluate_calibration(custom_records=current_records)

        base_brier = base_eval.brier_score
        curr_brier = curr_eval.brier_score
        calib_degraded = False

        if base_brier is not None and curr_brier is not None:
            # Degraded if Brier score increases by > 0.05
            if curr_brier - base_brier > 0.05:
                calib_degraded = True

        # 3. Feature Drift Breakdown
        # Extract features from top_features dictionaries
        feature_names = set()
        for r in records:
            for feat in r.top_features:
                feature_names.add(feat.get("feature_name", ""))
        feature_names.discard("")

        feature_items: List[FeatureDriftItem] = []
        max_psi = 0.0

        for fname in sorted(list(feature_names)):
            base_vals = [
                float(f.get("feature_value", 0.0))
                for r in baseline_records
                for f in r.top_features
                if f.get("feature_name") == fname
            ]
            curr_vals = [
                float(f.get("feature_value", 0.0))
                for r in current_records
                for f in r.top_features
                if f.get("feature_name") == fname
            ]

            if len(base_vals) >= 5 and len(curr_vals) >= 5:
                arr_base = np.array(base_vals, dtype=float)
                arr_curr = np.array(curr_vals, dtype=float)

                psi = self.calculate_psi(arr_base, arr_curr)
                max_psi = max(max_psi, psi)

                # Two-sample KS test
                try:
                    ks_res = stats.ks_2samp(arr_base, arr_curr)
                    ks_stat = round(float(ks_res.statistic), 4)
                except Exception:
                    ks_stat = None

                b_mean = round(float(np.mean(arr_base)), 4)
                c_mean = round(float(np.mean(arr_curr)), 4)
                delta_pct = (
                    round(float((c_mean - b_mean) / b_mean * 100.0), 2)
                    if abs(b_mean) > 1e-6
                    else 0.0
                )

                if psi >= PSI_SIGNIFICANT_THRESHOLD:
                    drift_status = "SIGNIFICANT_DRIFT"
                elif psi >= PSI_STABLE_THRESHOLD:
                    drift_status = "MODERATE_DRIFT"
                else:
                    drift_status = "STABLE"

                feature_items.append(
                    FeatureDriftItem(
                        feature_name=fname,
                        psi_score=psi,
                        ks_statistic=ks_stat,
                        drift_status=drift_status,
                        baseline_mean=b_mean,
                        current_mean=c_mean,
                        delta_percent=delta_pct,
                    )
                )

        # Sort features by highest PSI first
        feature_items.sort(key=lambda x: -x.psi_score)

        # 4. Sensor Coverage Gaps
        # Check assets that appeared in earlier baseline but have 0 alerts/telemetry in current window
        base_assets = set(r.asset_id for r in baseline_records)
        curr_assets = set(r.asset_id for r in current_records)
        coverage_gaps = len(base_assets - curr_assets)

        # 5. Overall Severity determination
        drift_detected = (max_psi >= PSI_STABLE_THRESHOLD) or (wasserstein_dist > 5.0) or calib_degraded
        if max_psi >= PSI_SIGNIFICANT_THRESHOLD or calib_degraded:
            overall_severity = "CRITICAL"
            explanation = (
                f"Significant telemetry or risk drift detected (Max PSI: {max_psi:.4f}, Wasserstein: {wasserstein_dist:.2f}). "
                f"Calibration degradation: {calib_degraded} (Brier: {base_brier} -> {curr_brier}). "
                "Feature distributions have shifted significantly from training baseline."
            )
            action = "Trigger model retraining pipeline (Phase 7.2D) and update decision threshold baseline."
        elif drift_detected:
            overall_severity = "MODERATE"
            explanation = (
                f"Moderate feature drift observed (Max PSI: {max_psi:.4f}, Wasserstein: {wasserstein_dist:.2f}). "
                "Minor distribution divergence between observation windows."
            )
            action = "Monitor feature stability and test shadow threshold candidate."
        else:
            overall_severity = "STABLE"
            explanation = (
                f"Telemetry feature distributions are stable across windows (Max PSI: {max_psi:.4f}, "
                f"Wasserstein distance: {wasserstein_dist:.2f}). No significant calibration degradation."
            )
            action = "Maintain current operating thresholds and monitoring schedules."

        return TelemetryDriftReport(
            drift_detected=drift_detected,
            overall_drift_severity=overall_severity,
            risk_score_wasserstein_distance=wasserstein_dist,
            calibration_degradation_detected=calib_degraded,
            baseline_brier_score=base_brier,
            current_brier_score=curr_brier,
            sensor_coverage_gap_count=coverage_gaps,
            evaluated_sample_size=n,
            feature_drift_breakdown=feature_items,
            confidence="HIGH" if n >= 100 else "MEDIUM" if n >= 30 else "LOW",
            baseline_window=base_win_str,
            current_window=curr_win_str,
            explanation=explanation,
            recommended_action=action,
            evaluated_at=datetime.now(timezone.utc),
        )
