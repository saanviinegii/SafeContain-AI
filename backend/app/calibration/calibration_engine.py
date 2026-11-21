"""Module 7.5.1: Risk Score Calibration Engine for SafeContain AI.

Evaluates the empirical calibration and reliability of ML risk scores and forecast probabilities
against observed security outcomes from Phase 7.4 evaluated telemetry.
Computes Expected Calibration Error (ECE), Brier Score, reliability bins, and category breakdowns.
Enforces sample-size safeguards (N >= 10).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.app.adaptive.models import PredictionOutcomeStatus, PredictionRecord
from backend.app.adaptive.tracker import PredictionOutcomeTracker
from backend.app.calibration.models import (
    CalibrationStatus,
    CategoryCalibrationBreakdown,
    ReliabilityBin,
    RiskScoreCalibrationReport,
)

logger = logging.getLogger("safecontain.calibration.engine")

MIN_SAMPLE_SIZE = 10
NUM_RELIABILITY_BINS = 5


class RiskScoreCalibrationEngine:
    """Computes empirical calibration, reliability diagrams, and Brier metrics from evaluated forecasts."""

    _instance: Optional["RiskScoreCalibrationEngine"] = None

    def __init__(self, tracker: Optional[PredictionOutcomeTracker] = None):
        self.tracker = tracker or PredictionOutcomeTracker.get_instance()

    @classmethod
    def get_instance(cls) -> "RiskScoreCalibrationEngine":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _extract_ground_truth(self, record: PredictionRecord) -> Optional[int]:
        """Maps record outcome to binary threat indicator Y in {0, 1}, or None if pending/inconclusive."""
        status = record.outcome_status
        actual = (record.actual_outcome or "").upper().strip()

        if status in (PredictionOutcomeStatus.CONFIRMED_COMPROMISE, PredictionOutcomeStatus.FALSE_NEGATIVE):
            return 1
        if status in (PredictionOutcomeStatus.CORRECT_NON_EVENT, PredictionOutcomeStatus.FALSE_POSITIVE):
            return 0

        if actual == "COMPROMISED":
            return 1
        if actual == "BENIGN":
            return 0

        return None

    def get_evaluated_records(self, custom_records: Optional[List[PredictionRecord]] = None) -> List[Tuple[PredictionRecord, float, int]]:
        """Retrieves and filters prediction records with verified ground-truth outcomes.
        
        Returns:
            List of (record, predicted_prob, y_true) tuples.
        """
        all_records = custom_records if custom_records is not None else self.tracker.get_all_predictions()
        evaluated: List[Tuple[PredictionRecord, float, int]] = []

        for r in all_records:
            y = self._extract_ground_truth(r)
            if y is not None:
                p = max(0.0, min(1.0, float(r.predicted_probability)))
                evaluated.append((r, p, y))

        return evaluated

    def compute_brier_score(self, probs: List[float], labels: List[int]) -> Optional[float]:
        """Calculates Brier score: (1/N) * sum((p_i - y_i)^2)."""
        if not probs or len(probs) != len(labels):
            return None
        n = len(probs)
        return float(sum((p - y) ** 2 for p, y in zip(probs, labels)) / n)

    def compute_reliability_bins(
        self,
        probs: List[float],
        labels: List[int],
        num_bins: int = NUM_RELIABILITY_BINS,
    ) -> Tuple[List[ReliabilityBin], float, float, float]:
        """Partitions forecasts into uniform probability bins and calculates ECE, over/underprediction rates."""
        n = len(probs)
        if n == 0:
            return [], 0.0, 0.0, 0.0

        bin_width = 1.0 / num_bins
        bins: List[ReliabilityBin] = []
        weighted_error_sum = 0.0
        overpredicting_bins = 0
        underpredicting_bins = 0
        non_empty_bins = 0

        for b_idx in range(num_bins):
            low = round(b_idx * bin_width, 4)
            high = 1.0 if b_idx == num_bins - 1 else round((b_idx + 1) * bin_width, 4)

            bin_probs: List[float] = []
            bin_labels: List[int] = []

            for p, y in zip(probs, labels):
                if b_idx == num_bins - 1:
                    in_bin = (p >= low and p <= high)
                else:
                    in_bin = (p >= low and p < high)

                if in_bin:
                    bin_probs.append(p)
                    bin_labels.append(y)

            k = len(bin_probs)
            if k > 0:
                mean_p = round(float(sum(bin_probs) / k), 4)
                mean_y = round(float(sum(bin_labels) / k), 4)
                err = round(abs(mean_p - mean_y), 4)
                weighted_error_sum += (k / n) * err
                non_empty_bins += 1

                if mean_p - mean_y > 0.10:
                    b_status = "OVERPREDICTING"
                    overpredicting_bins += 1
                elif mean_y - mean_p > 0.10:
                    b_status = "UNDERPREDICTING"
                    underpredicting_bins += 1
                else:
                    b_status = "CALIBRATED"
            else:
                mean_p = None
                mean_y = None
                err = None
                b_status = "EMPTY"

            bins.append(
                ReliabilityBin(
                    bin_index=b_idx,
                    bin_range_low=low,
                    bin_range_high=high,
                    sample_count=k,
                    mean_predicted_probability=mean_p,
                    empirical_threat_rate=mean_y,
                    calibration_error=err,
                    bin_status=b_status,
                )
            )

        ece = round(float(weighted_error_sum), 4)
        over_rate = round(float(overpredicting_bins / non_empty_bins), 4) if non_empty_bins > 0 else 0.0
        under_rate = round(float(underpredicting_bins / non_empty_bins), 4) if non_empty_bins > 0 else 0.0

        return bins, ece, over_rate, under_rate

    def evaluate_calibration(
        self,
        custom_records: Optional[List[PredictionRecord]] = None,
    ) -> RiskScoreCalibrationReport:
        """Generates a complete empirical calibration report evaluated against ground truth telemetry."""
        evaluated = self.get_evaluated_records(custom_records)
        n = len(evaluated)

        # 1. Sample Size Safeguard
        if n < MIN_SAMPLE_SIZE:
            empty_bins = [
                ReliabilityBin(
                    bin_index=i,
                    bin_range_low=round(i * 0.2, 2),
                    bin_range_high=1.0 if i == 4 else round((i + 1) * 0.2, 2),
                    sample_count=0,
                    bin_status="EMPTY",
                )
                for i in range(5)
            ]
            return RiskScoreCalibrationReport(
                calibration_status=CalibrationStatus.INSUFFICIENT_DATA,
                expected_calibration_error=None,
                brier_score=None,
                overprediction_rate=None,
                underprediction_rate=None,
                calibration_quality_score=None,
                sample_size=n,
                evaluated_threats_count=0,
                evaluated_benign_count=0,
                reliability_bins=empty_bins,
                confidence="INSUFFICIENT_DATA",
                limitations=[
                    f"Sample size of {n} evaluated predictions is below the minimum threshold of {MIN_SAMPLE_SIZE}.",
                    "Calibration metrics and reliability curves require at least 10 ground-truth outcomes to avoid statistical artifacting.",
                ],
            )

        probs = [p for _, p, _ in evaluated]
        labels = [y for _, _, y in evaluated]
        records = [r for r, _, _ in evaluated]

        threats_count = sum(labels)
        benign_count = n - threats_count

        # 2. Overall Reliability & Metrics
        bins, ece, over_rate, under_rate = self.compute_reliability_bins(probs, labels)
        brier = round(self.compute_brier_score(probs, labels) or 0.0, 4)
        quality_score = round(max(0.0, min(100.0, 100.0 * (1.0 - ece))), 2)

        # Status determination
        if ece < 0.08:
            status = CalibrationStatus.CALIBRATED
        elif ece < 0.18:
            status = CalibrationStatus.SLIGHTLY_MISCALIBRATED
        else:
            status = CalibrationStatus.SEVERELY_MISCALIBRATED

        # Confidence determination
        if n >= 100:
            confidence = "HIGH"
        elif n >= 30:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        # 3. Categorical breakdowns by asset type
        asset_types = sorted(list(set(r.asset_type for r in records if r.asset_type)))
        asset_breakdowns: List[CategoryCalibrationBreakdown] = []
        for atype in asset_types:
            cat_pairs = [(p, y) for r, p, y in evaluated if r.asset_type == atype]
            if len(cat_pairs) >= 5:
                cat_p = [p for p, _ in cat_pairs]
                cat_y = [y for _, y in cat_pairs]
                _, cat_ece, cat_over, cat_under = self.compute_reliability_bins(cat_p, cat_y)
                cat_brier = round(self.compute_brier_score(cat_p, cat_y) or 0.0, 4)
                cat_status = (
                    CalibrationStatus.CALIBRATED if cat_ece < 0.08
                    else CalibrationStatus.SLIGHTLY_MISCALIBRATED if cat_ece < 0.18
                    else CalibrationStatus.SEVERELY_MISCALIBRATED
                )
                asset_breakdowns.append(
                    CategoryCalibrationBreakdown(
                        category_name=atype,
                        sample_size=len(cat_pairs),
                        brier_score=cat_brier,
                        expected_calibration_error=cat_ece,
                        overprediction_rate=cat_over,
                        underprediction_rate=cat_under,
                        calibration_status=cat_status,
                        confidence="HIGH" if len(cat_pairs) >= 50 else "MEDIUM" if len(cat_pairs) >= 20 else "LOW",
                    )
                )

        # 4. Categorical breakdowns by forecast horizon
        horizons = sorted(list(set(r.forecast_horizon for r in records if r.forecast_horizon)))
        horizon_breakdowns: List[CategoryCalibrationBreakdown] = []
        for h in horizons:
            cat_pairs = [(p, y) for r, p, y in evaluated if r.forecast_horizon == h]
            if len(cat_pairs) >= 5:
                cat_p = [p for p, _ in cat_pairs]
                cat_y = [y for _, y in cat_pairs]
                _, cat_ece, cat_over, cat_under = self.compute_reliability_bins(cat_p, cat_y)
                cat_brier = round(self.compute_brier_score(cat_p, cat_y) or 0.0, 4)
                cat_status = (
                    CalibrationStatus.CALIBRATED if cat_ece < 0.08
                    else CalibrationStatus.SLIGHTLY_MISCALIBRATED if cat_ece < 0.18
                    else CalibrationStatus.SEVERELY_MISCALIBRATED
                )
                horizon_breakdowns.append(
                    CategoryCalibrationBreakdown(
                        category_name=h,
                        sample_size=len(cat_pairs),
                        brier_score=cat_brier,
                        expected_calibration_error=cat_ece,
                        overprediction_rate=cat_over,
                        underprediction_rate=cat_under,
                        calibration_status=cat_status,
                        confidence="HIGH" if len(cat_pairs) >= 50 else "MEDIUM" if len(cat_pairs) >= 20 else "LOW",
                    )
                )

        # Time window calculation
        timestamps = [r.prediction_timestamp for r in records if r.prediction_timestamp]
        t_start = min(timestamps) if timestamps else None
        t_end = max(timestamps) if timestamps else None

        limitations: List[str] = []
        if n < 50:
            limitations.append("Moderate sample size (N < 50); reliability bin resolutions may fluctuate.")
        if threats_count == 0:
            limitations.append("No confirmed compromises observed in window; empirical rate is zero across all bins.")

        return RiskScoreCalibrationReport(
            calibration_status=status,
            expected_calibration_error=ece,
            brier_score=brier,
            overprediction_rate=over_rate,
            underprediction_rate=under_rate,
            calibration_quality_score=quality_score,
            sample_size=n,
            evaluated_threats_count=threats_count,
            evaluated_benign_count=benign_count,
            time_window_start=t_start,
            time_window_end=t_end,
            reliability_bins=bins,
            asset_type_breakdowns=asset_breakdowns,
            horizon_breakdowns=horizon_breakdowns,
            confidence=confidence,
            data_source="PHASE_7_4_EVALUATED_TELEMETRY",
            limitations=limitations,
            generated_at=datetime.now(timezone.utc),
        )
