"""SHAP Explanation Quality & Outcome Correlation Analyzer for SafeContain AI Phase 7.4.

Analyzes the statistical relationship between SHAP feature attributions and empirical prediction outcomes
(True Positives vs False Positives/Negatives) while explicitly distinguishing attribution from causation.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import numpy as np

from backend.app.adaptive.models import PredictionOutcomeStatus, PredictionRecord
from backend.app.adaptive.tracker import PredictionOutcomeTracker

logger = logging.getLogger("safecontain.adaptive.shap_analyzer")


class ExplanationQualityAnalyzer:
    """Analyzes the correlation between SHAP feature attributions and actual evaluated outcomes."""

    def __init__(self, tracker: Optional[PredictionOutcomeTracker] = None):
        self.tracker = tracker or PredictionOutcomeTracker.get_instance()

    def analyze_explanation_quality(
        self,
        records: Optional[List[PredictionRecord]] = None,
    ) -> Dict[str, Any]:
        """Examines which SHAP features drive true positive predictions vs systematic false alarms."""
        all_preds = records if records is not None else self.tracker.get_all_predictions()
        evaluated = [
            p for p in all_preds
            if p.outcome_status in (
                PredictionOutcomeStatus.CONFIRMED_COMPROMISE,
                PredictionOutcomeStatus.FALSE_POSITIVE,
                PredictionOutcomeStatus.FALSE_NEGATIVE,
                PredictionOutcomeStatus.CORRECT_NON_EVENT,
            )
        ]

        if not evaluated:
            return {
                "status": "INSUFFICIENT_EVALUATED_DATA",
                "sample_size": len(all_preds),
                "evaluated_count": 0,
                "message": "Awaiting evaluated forecasts to perform SHAP outcome correlation analysis.",
                "features_driving_true_positives": [],
                "features_driving_false_positives": [],
                "features_driving_false_negatives": [],
                "causality_disclaimer": (
                    "SHAP feature attributions reflect mathematical contribution to model tree splits "
                    "and do not constitute physical or operational causality."
                ),
            }

        tp_records = [p for p in evaluated if p.outcome_status == PredictionOutcomeStatus.CONFIRMED_COMPROMISE]
        fp_records = [p for p in evaluated if p.outcome_status == PredictionOutcomeStatus.FALSE_POSITIVE]
        fn_records = [p for p in evaluated if p.outcome_status == PredictionOutcomeStatus.FALSE_NEGATIVE]
        tn_records = [p for p in evaluated if p.outcome_status == PredictionOutcomeStatus.CORRECT_NON_EVENT]

        def aggregate_shap(records: List[PredictionRecord]) -> Dict[str, Dict[str, Any]]:
            agg: Dict[str, Dict[str, Any]] = {}
            for p in records:
                for feat in p.top_features:
                    fname = feat.get("feature_name", "")
                    cscore = float(feat.get("contribution_score", 0.0))
                    fval = float(feat.get("feature_value", 0.0))
                    if not fname:
                        continue

                    if fname not in agg:
                        agg[fname] = {"count": 0, "sum_score": 0.0, "sum_abs_score": 0.0, "sum_val": 0.0}
                    agg[fname]["count"] += 1
                    agg[fname]["sum_score"] += cscore
                    agg[fname]["sum_abs_score"] += abs(cscore)
                    agg[fname]["sum_val"] += fval

            result = {}
            for fname, item in agg.items():
                cnt = item["count"]
                result[fname] = {
                    "feature_name": fname,
                    "frequency": cnt,
                    "mean_shap": round(item["sum_score"] / cnt, 4),
                    "mean_abs_shap": round(item["sum_abs_score"] / cnt, 4),
                    "mean_feature_value": round(item["sum_val"] / cnt, 3),
                }
            return result

        tp_shap = aggregate_shap(tp_records)
        fp_shap = aggregate_shap(fp_records)
        fn_shap = aggregate_shap(fn_records)

        # Sort features by highest mean contribution
        tp_top = sorted(tp_shap.values(), key=lambda x: (x["mean_abs_shap"], x["frequency"]), reverse=True)[:6]
        fp_top = sorted(fp_shap.values(), key=lambda x: (x["mean_abs_shap"], x["frequency"]), reverse=True)[:6]
        fn_top = sorted(fn_shap.values(), key=lambda x: (x["mean_abs_shap"], x["frequency"]), reverse=True)[:6]

        # Calculate explanation consistency: do true positives exhibit consistent feature sets?
        consistency_score = 0.85
        if tp_top:
            top_tp_features = [f["feature_name"] for f in tp_top[:3]]
            overlap_in_fp = sum(1 for f in fp_top[:3] if f["feature_name"] in top_tp_features)
            # If top TP features also drive FPs, consistency is lower
            consistency_score = max(0.40, round(1.0 - (overlap_in_fp * 0.2), 2))

        return {
            "status": "VALID",
            "sample_size": len(all_preds),
            "evaluated_count": len(evaluated),
            "breakdown": {
                "true_positives_count": len(tp_records),
                "false_positives_count": len(fp_records),
                "false_negatives_count": len(fn_records),
                "true_negatives_count": len(tn_records),
            },
            "features_driving_true_positives": tp_top,
            "features_driving_false_positives": fp_top,
            "features_driving_false_negatives": fn_top,
            "feature_rankings": tp_top,
            "explanation_consistency_score": consistency_score,
            "causality_disclaimer": (
                "SCIENTIFIC NOTICE: SHAP values represent localized feature attribution within Gradient Boosted decision "
                "trees and must not be interpreted as proven adversarial causation. High attribution indicates correlation "
                "with model probability output, not necessarily independent breach necessity."
            ),
            "non_causality_disclosure": (
                "Correlation does not imply direct mechanistic causation: SHAP attribution scores identify empirical tree splits "
                "and statistical risk associations, not physical breach causality."
            ),
            "total_records_analyzed": len(evaluated),
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }
