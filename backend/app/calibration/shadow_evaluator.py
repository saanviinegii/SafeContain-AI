"""Module 7.5.3: Shadow Threshold Evaluation Engine for SafeContain AI.

Performs zero-interference shadow simulation of candidate threshold configurations in parallel
with the active production baseline. Quantifies alert volume shifts, error deltas (FPR/FNR),
critical asset retention, and granular asset classification flips before any configuration
can be approved or deployed.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.app.adaptive.models import PredictionRecord
from backend.app.adaptive.tracker import PredictionOutcomeTracker
from backend.app.calibration.calibration_engine import RiskScoreCalibrationEngine
from backend.app.calibration.models import (
    AssetClassificationFlip,
    ShadowEvaluationResult,
    ThresholdConfiguration,
)
from backend.app.calibration.threshold_optimizer import IntelligentThresholdOptimizer

logger = logging.getLogger("safecontain.calibration.shadow")


class ShadowThresholdEvaluator:
    """Evaluates candidate thresholds side-by-side with production baseline in offline shadow mode."""

    _instance: Optional["ShadowThresholdEvaluator"] = None

    def __init__(
        self,
        optimizer: Optional[IntelligentThresholdOptimizer] = None,
        calibration_engine: Optional[RiskScoreCalibrationEngine] = None,
        tracker: Optional[PredictionOutcomeTracker] = None,
    ):
        self.optimizer = optimizer or IntelligentThresholdOptimizer.get_instance()
        self.calibration_engine = calibration_engine or RiskScoreCalibrationEngine.get_instance()
        self.tracker = tracker or PredictionOutcomeTracker.get_instance()

    @classmethod
    def get_instance(cls) -> "ShadowThresholdEvaluator":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def evaluate_shadow_candidate(
        self,
        candidate_threshold: float,
        candidate_config_id: Optional[str] = None,
        baseline_threshold: Optional[float] = None,
        baseline_config_id: Optional[str] = "cfg-v1.0.0-baseline",
        custom_records: Optional[List[PredictionRecord]] = None,
    ) -> ShadowEvaluationResult:
        """Runs side-by-side comparative simulation of candidate vs baseline across evaluated telemetry."""
        base_theta = (
            baseline_threshold
            if baseline_threshold is not None
            else self.optimizer.get_baseline_operating_threshold()
        )
        cand_theta = round(candidate_threshold, 4)
        cand_id = candidate_config_id or f"cand-eval-{uuid.uuid4().hex[:8]}"

        evaluated = self.calibration_engine.get_evaluated_records(custom_records)
        n = len(evaluated)

        # Baseline & candidate performance calculations
        base_perf = self.optimizer.evaluate_threshold_performance(base_theta, evaluated)
        cand_perf = self.optimizer.evaluate_threshold_performance(cand_theta, evaluated)

        # Compute volume deltas
        base_alerts = base_perf["total_alerts"]
        cand_alerts = cand_perf["total_alerts"]
        vol_delta = cand_alerts - base_alerts
        pct_change = round(float((vol_delta / base_alerts) * 100.0), 2) if base_alerts > 0 else 0.0

        fp_delta = cand_perf["false_positives"] - base_perf["false_positives"]
        fn_delta = cand_perf["false_negatives"] - base_perf["false_negatives"]

        # Critical threat safety assessment
        crit_retained = cand_perf["critical_missed"] <= base_perf["critical_missed"]
        crit_miss_count = cand_perf["critical_missed"]

        # Identify individual asset classification flips
        flipped_assets: List[AssetClassificationFlip] = []
        for record, prob, y_true in evaluated:
            base_class = "THREAT" if prob >= base_theta else "BENIGN"
            cand_class = "THREAT" if prob >= cand_theta else "BENIGN"

            if base_class != cand_class:
                is_crit = self.optimizer._is_critical_asset(record)
                actual_label = "COMPROMISED" if y_true == 1 else "BENIGN"

                if base_class == "BENIGN" and cand_class == "THREAT":
                    if y_true == 1:
                        impact = "CORRECT DETECTION: Previously missed threat now caught (FN -> TP)."
                    else:
                        impact = "FALSE ALARM: Benign asset flagged as threat (TN -> FP)."
                else: # base_class == "THREAT" and cand_class == "BENIGN"
                    if y_true == 1:
                        impact = "DANGEROUS MISS: Previously detected threat now missed (TP -> FN)!"
                    else:
                        impact = "NOISE REDUCTION: Benign asset false positive suppressed (FP -> TN)."

                flipped_assets.append(
                    AssetClassificationFlip(
                        asset_id=record.asset_id,
                        asset_name=record.asset_name,
                        asset_type=record.asset_type,
                        is_crown_jewel=is_crit,
                        predicted_probability=round(prob, 4),
                        baseline_classification=base_class,
                        candidate_classification=cand_class,
                        actual_outcome=actual_label,
                        impact_description=impact,
                    )
                )

        # Sort flipped assets: critical first, then descending probability
        flipped_assets.sort(key=lambda x: (not x.is_crown_jewel, -x.predicted_probability))

        # Tradeoff summary
        if vol_delta > 0:
            summary = (
                f"Candidate threshold theta={cand_theta:.2f} increases alert volume by {vol_delta} ({pct_change:+0.1f}%). "
                f"Catches {abs(fn_delta)} additional true compromises while introducing {fp_delta} additional false alarms. "
                f"Critical assets retained: {crit_retained}."
            )
        elif vol_delta < 0:
            summary = (
                f"Candidate threshold theta={cand_theta:.2f} reduces alert volume by {abs(vol_delta)} ({pct_change:+0.1f}%). "
                f"Suppresses {abs(fp_delta)} false alarms with {fn_delta} new false negatives. "
                f"Critical assets retained: {crit_retained}."
            )
        else:
            summary = (
                f"Candidate threshold theta={cand_theta:.2f} maintains identical net alert volume. "
                f"Classification flips: {len(flipped_assets)} assets."
            )

        recommendation = (
            "RECOMMENDED FOR ANALYST APPROVAL"
            if (crit_retained and cand_perf["total_cost"] < base_perf["total_cost"])
            else "CAUTION: Potential risk degradation or increased operational burden"
        )

        return ShadowEvaluationResult(
            evaluation_id=f"eval-{uuid.uuid4().hex[:8]}",
            baseline_config_id=baseline_config_id or "cfg-v1.0.0-baseline",
            candidate_config_id=cand_id,
            evaluated_sample_size=n,
            baseline_threshold=base_theta,
            candidate_threshold=cand_theta,
            baseline_alert_count=base_alerts,
            candidate_alert_count=cand_alerts,
            alert_volume_delta=vol_delta,
            alert_volume_percent_change=pct_change,
            baseline_false_positives=base_perf["false_positives"],
            candidate_false_positives=cand_perf["false_positives"],
            false_positive_delta=fp_delta,
            baseline_false_negatives=base_perf["false_negatives"],
            candidate_false_negatives=cand_perf["false_negatives"],
            false_negative_delta=fn_delta,
            baseline_precision=base_perf["precision"],
            candidate_precision=cand_perf["precision"],
            baseline_recall=base_perf["recall"],
            candidate_recall=cand_perf["recall"],
            baseline_f1=base_perf["f1_score"],
            candidate_f1=cand_perf["f1_score"],
            critical_threats_retained=crit_retained,
            critical_threat_miss_count=crit_miss_count,
            classification_flips_count=len(flipped_assets),
            flipped_assets=flipped_assets,
            tradeoff_summary=summary,
            recommendation=recommendation,
            evaluated_at=datetime.now(timezone.utc),
        )
