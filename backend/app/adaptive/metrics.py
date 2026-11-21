"""Predictive Performance Metrics Calculator for SafeContain AI Phase 7.4.

Computes precision, recall, F1, Brier score, false positive rate, confusion matrices,
and multi-dimensional breakdowns strictly from evaluated forecast records.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import numpy as np

from backend.app.adaptive.models import (
    AssetTypePerformance,
    HorizonComparisonItem,
    PredictionOutcomeStatus,
    PredictionRecord,
    PredictivePerformanceMetrics,
)
from backend.app.adaptive.tracker import PredictionOutcomeTracker

logger = logging.getLogger("safecontain.adaptive.metrics")


class AdaptiveMetricsCalculator:
    """Calculates scientific evaluation metrics across evaluated predictions."""

    def __init__(self, tracker: Optional[PredictionOutcomeTracker] = None):
        self.tracker = tracker or PredictionOutcomeTracker.get_instance()

    def calculate_metrics(
        self,
        horizon: Optional[Any] = None,
        records: Optional[List[PredictionRecord]] = None,
    ) -> PredictivePerformanceMetrics:
        """Computes performance metrics for the specified horizon (or across all horizons)."""
        if isinstance(horizon, list) and records is None:
            records = horizon
            horizon = None

        if records is None:
            all_preds, _ = self.tracker.list_predictions(horizon=horizon, limit=10000)
        else:
            all_preds = records
            if horizon and isinstance(horizon, str):
                h_up = horizon.upper().strip()
                all_preds = [p for p in all_preds if p.forecast_horizon.upper() == h_up]

        sample_size = len(all_preds)
        pending = sum(1 for p in all_preds if p.outcome_status == PredictionOutcomeStatus.PENDING_EVALUATION)
        insufficient = sum(1 for p in all_preds if p.outcome_status in (PredictionOutcomeStatus.INSUFFICIENT_EVIDENCE, PredictionOutcomeStatus.EXPIRED_UNOBSERVED))

        evaluated = [
            p for p in all_preds
            if p.outcome_status in (
                PredictionOutcomeStatus.CONFIRMED_COMPROMISE,
                PredictionOutcomeStatus.FALSE_POSITIVE,
                PredictionOutcomeStatus.FALSE_NEGATIVE,
                PredictionOutcomeStatus.CORRECT_NON_EVENT,
            )
        ]
        n_eval = len(evaluated)

        # Handle empty or insufficient data gracefully
        if n_eval == 0:
            return PredictivePerformanceMetrics(
                horizon=horizon or "ALL",
                sample_size=sample_size,
                evaluated_count=0,
                pending_count=pending,
                insufficient_evidence_count=insufficient,
                true_positives=0,
                false_positives=0,
                true_negatives=0,
                false_negatives=0,
                precision=None,
                recall=None,
                f1_score=None,
                false_positive_rate=None,
                false_negative_rate=None,
                accuracy=None,
                brier_score=None,
                confusion_matrix=[[0, 0], [0, 0]],
                operating_threshold=0.32,
                data_status="INSUFFICIENT_EVALUATED_DATA" if sample_size > 0 else "EMPTY",
            )

        tp = sum(1 for p in evaluated if p.outcome_status == PredictionOutcomeStatus.CONFIRMED_COMPROMISE)
        fp = sum(1 for p in evaluated if p.outcome_status == PredictionOutcomeStatus.FALSE_POSITIVE)
        tn = sum(1 for p in evaluated if p.outcome_status == PredictionOutcomeStatus.CORRECT_NON_EVENT)
        fn = sum(1 for p in evaluated if p.outcome_status == PredictionOutcomeStatus.FALSE_NEGATIVE)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0
        accuracy = (tp + tn) / n_eval if n_eval > 0 else 0.0

        # Brier Score = mean((P_pred - Y_true)^2)
        brier_errors = []
        for p in evaluated:
            y_true = 1.0 if p.actual_outcome == "COMPROMISED" else 0.0
            p_pred = float(p.predicted_probability)
            brier_errors.append((p_pred - y_true) ** 2)
        brier = float(np.mean(brier_errors)) if brier_errors else 0.0

        return PredictivePerformanceMetrics(
            horizon=horizon or "ALL",
            sample_size=sample_size,
            evaluated_count=n_eval,
            pending_count=pending,
            insufficient_evidence_count=insufficient,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            false_positive_rate=round(fpr, 4),
            false_negative_rate=round(fnr, 4),
            accuracy=round(accuracy, 4),
            brier_score=round(brier, 4),
            confusion_matrix=[[tn, fp], [fn, tp]],
            operating_threshold=0.32,
            data_status="VALID",
        )

    def compare_horizons(self) -> List[HorizonComparisonItem]:
        """Generates side-by-side performance comparisons across the supported forecasting horizons."""
        horizons_meta = [
            ("NEAR_TERM", 2.0),
            ("SHORT_TERM", 6.0),
            ("MEDIUM_TERM", 18.0),
        ]
        results: List[HorizonComparisonItem] = []

        for h_name, h_hours in horizons_meta:
            m = self.calculate_metrics(horizon=h_name)
            if m.evaluated_count == 0:
                rec = "Insufficient evaluated predictions to establish empirical performance."
                status = "PENDING_DATA"
            elif (m.f1_score or 0) >= 0.70:
                rec = "Optimal predictive reliability: recommended for high-confidence preemptive actions."
                status = "STRONG"
            elif (m.f1_score or 0) >= 0.50:
                rec = "Moderate predictive reliability: suitable for defensive posture and alerting."
                status = "ACCEPTABLE"
            else:
                rec = "Higher error margin: requires conservative weighting in containment planning."
                status = "NEEDS_MONITORING"

            results.append(
                HorizonComparisonItem(
                    horizon=h_name,
                    horizon_hours=h_hours,
                    sample_size=m.sample_size,
                    evaluated_count=m.evaluated_count,
                    precision=m.precision,
                    recall=m.recall,
                    f1_score=m.f1_score,
                    brier_score=m.brier_score,
                    status=status,
                    recommendation=rec,
                )
            )

        return results

    def breakdown_by_asset_type(self) -> List[AssetTypePerformance]:
        """Computes precision and recall segmented across enterprise asset types."""
        all_preds = self.tracker.get_all_predictions()
        by_type: Dict[str, List[PredictionRecord]] = {}

        for p in all_preds:
            atype = p.asset_type.upper()
            if atype not in by_type:
                by_type[atype] = []
            by_type[atype].append(p)

        results: List[AssetTypePerformance] = []
        for atype, records in sorted(by_type.items()):
            m = self.calculate_metrics(records=records)
            results.append(
                AssetTypePerformance(
                    asset_type=atype,
                    total_predictions=m.sample_size,
                    evaluated_count=m.evaluated_count,
                    precision=m.precision,
                    recall=m.recall,
                    f1_score=m.f1_score,
                    false_positives=m.false_positives,
                    false_negatives=m.false_negatives,
                )
            )
        return results
