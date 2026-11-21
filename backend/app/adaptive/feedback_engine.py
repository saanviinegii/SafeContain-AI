"""Adaptive Feedback Engine for SafeContain AI Phase 7.4.

Analyzes evaluated forecast records to discover systematic false positives, missed threat patterns,
horizon disparities, and feature error associations, providing non-autonomous, explainable SecOps insights.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import numpy as np

from backend.app.adaptive.metrics import AdaptiveMetricsCalculator
from backend.app.adaptive.models import (
    AdaptiveFeedbackInsights,
    PredictionOutcomeStatus,
    PredictionRecord,
)
from backend.app.adaptive.tracker import PredictionOutcomeTracker

logger = logging.getLogger("safecontain.adaptive.feedback_engine")


class AdaptiveFeedbackEngine:
    """Discovers systematic model errors, horizon disparities, and threat indicator validity."""

    def __init__(
        self,
        tracker: Optional[PredictionOutcomeTracker] = None,
        metrics_calc: Optional[AdaptiveMetricsCalculator] = None,
    ):
        self.tracker = tracker or PredictionOutcomeTracker.get_instance()
        self.metrics_calc = metrics_calc or AdaptiveMetricsCalculator(tracker=self.tracker)

    def generate_feedback_insights(
        self,
        records: Optional[List[PredictionRecord]] = None,
    ) -> AdaptiveFeedbackInsights:
        """Synthesizes comprehensive, evidence-grounded feedback insights across all evaluated forecasts."""
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
            return AdaptiveFeedbackInsights(
                repeated_false_positives=[],
                repeated_false_negatives=[],
                weakest_horizon=None,
                strongest_horizon=None,
                weak_asset_types=[],
                error_associated_features=[],
                threat_indicator_insights=[],
                recommended_policy_adjustments=[
                    "Awaiting evaluated prediction batch. No model adaptation recommended until prediction horizons elapse."
                ],
                governance_note="Feedback layer is non-autonomous. Evaluation requires ground-truth telemetry observations.",
            )

        # ---------------------------------------------------------------------
        # 1. Discover Repeated False Positives
        # ---------------------------------------------------------------------
        fps = [p for p in evaluated if p.outcome_status == PredictionOutcomeStatus.FALSE_POSITIVE]
        fp_by_asset: Dict[str, List[PredictionRecord]] = {}
        for p in fps:
            fp_by_asset.setdefault(p.asset_id, []).append(p)

        repeated_fps: List[Dict[str, Any]] = []
        for aid, plist in fp_by_asset.items():
            first_p = plist[0]
            mean_prob = float(np.mean([p.predicted_probability for p in plist]))
            repeated_fps.append({
                "asset_id": aid,
                "asset_name": first_p.asset_name,
                "asset_type": first_p.asset_type,
                "false_positive_count": len(plist),
                "mean_predicted_probability": round(mean_prob, 4),
                "operating_threshold": first_p.operating_threshold,
                "primary_driver": first_p.top_features[0]["feature_name"] if first_p.top_features else "exposure",
                "recommended_mitigation": f"Review feature weighting for {first_p.asset_type}; consider baseline suppression.",
            })
        repeated_fps.sort(key=lambda x: (x["false_positive_count"], x["mean_predicted_probability"]), reverse=True)

        # ---------------------------------------------------------------------
        # 2. Discover Repeated False Negatives (Missed Threat Vectors)
        # ---------------------------------------------------------------------
        fns = [p for p in evaluated if p.outcome_status == PredictionOutcomeStatus.FALSE_NEGATIVE]
        fn_by_asset: Dict[str, List[PredictionRecord]] = {}
        for p in fns:
            fn_by_asset.setdefault(p.asset_id, []).append(p)

        repeated_fns: List[Dict[str, Any]] = []
        for aid, plist in fn_by_asset.items():
            first_p = plist[0]
            mean_prob = float(np.mean([p.predicted_probability for p in plist]))
            evid_count = sum(len(p.evidence_ids) for p in plist)
            repeated_fns.append({
                "asset_id": aid,
                "asset_name": first_p.asset_name,
                "asset_type": first_p.asset_type,
                "false_negative_count": len(plist),
                "mean_predicted_probability": round(mean_prob, 4),
                "operating_threshold": first_p.operating_threshold,
                "observed_incident_count": evid_count,
                "recommended_mitigation": "Critical blind spot: investigate unmodeled ingress or sudden lateral traversal.",
            })
        repeated_fns.sort(key=lambda x: (x["false_negative_count"], -x["mean_predicted_probability"]), reverse=True)

        # ---------------------------------------------------------------------
        # 3. Horizon Disparities
        # ---------------------------------------------------------------------
        horizon_comps = self.metrics_calc.compare_horizons()
        eval_horizons = [h for h in horizon_comps if (h.evaluated_count or 0) > 0 and h.f1_score is not None]

        weakest_h = None
        strongest_h = None
        if eval_horizons:
            sorted_by_f1 = sorted(eval_horizons, key=lambda x: x.f1_score or 0.0)
            weakest_h = sorted_by_f1[0].horizon
            strongest_h = sorted_by_f1[-1].horizon

        # ---------------------------------------------------------------------
        # 4. Weak Asset Categories
        # ---------------------------------------------------------------------
        asset_perf = self.metrics_calc.breakdown_by_asset_type()
        weak_types = [
            a.asset_type for a in asset_perf
            if a.evaluated_count >= 2 and (a.f1_score or 0.0) < 0.60
        ]

        # ---------------------------------------------------------------------
        # 5. Features Associated with Prediction Errors
        # ---------------------------------------------------------------------
        error_preds = fps + fns
        correct_preds = [
            p for p in evaluated
            if p.outcome_status in (PredictionOutcomeStatus.CONFIRMED_COMPROMISE, PredictionOutcomeStatus.CORRECT_NON_EVENT)
        ]

        error_feature_counts: Dict[str, Dict[str, float]] = {}
        for p in error_preds:
            for feat in p.top_features[:3]:
                fname = feat.get("feature_name", "")
                if fname:
                    error_feature_counts.setdefault(fname, {"fp_fn_count": 0, "sum_val": 0.0})
                    error_feature_counts[fname]["fp_fn_count"] += 1
                    error_feature_counts[fname]["sum_val"] += float(feat.get("feature_value", 0.0))

        error_features_list = []
        for fname, data in sorted(error_feature_counts.items(), key=lambda x: x[1]["fp_fn_count"], reverse=True)[:5]:
            error_features_list.append({
                "feature_name": fname,
                "error_occurrences": int(data["fp_fn_count"]),
                "mean_value_on_errors": round(data["sum_val"] / max(1, data["fp_fn_count"]), 3),
                "insight": f"Feature '{fname}' frequently appears among top SHAP drivers on prediction misclassifications.",
            })

        # ---------------------------------------------------------------------
        # 6. Threat Indicator Validation Context
        # ---------------------------------------------------------------------
        indicator_insights = []
        try:
            from backend.app.threat_intel.engine import ThreatCorrelationEngine
            ti_engine = ThreatCorrelationEngine()
            indicators = ti_engine.collect_all_indicators()

            # Correlate indicators with confirmed compromise assets
            comp_asset_ids = set(p.asset_id for p in evaluated if p.outcome_status == PredictionOutcomeStatus.CONFIRMED_COMPROMISE)
            fp_asset_ids = set(p.asset_id for p in evaluated if p.outcome_status == PredictionOutcomeStatus.FALSE_POSITIVE)

            for ind in indicators[:8]:
                associated = set(ind.associated_asset_ids)
                confirmed_hits = len(associated.intersection(comp_asset_ids))
                false_alarm_hits = len(associated.intersection(fp_asset_ids))

                if confirmed_hits > 0 or false_alarm_hits > 0:
                    indicator_insights.append({
                        "indicator_id": ind.id,
                        "indicator_type": ind.type.value,
                        "indicator_value": ind.value,
                        "source": ind.source,
                        "severity": ind.severity.value,
                        "confirmed_breach_hits": confirmed_hits,
                        "false_alarm_hits": false_alarm_hits,
                        "empirical_reliability": round(confirmed_hits / max(1, confirmed_hits + false_alarm_hits), 2),
                    })
        except Exception as e:
            logger.warning("Could not correlate threat indicators with outcomes: %s", e)

        # ---------------------------------------------------------------------
        # 7. Formulate Governance-Compliant Recommendations
        # ---------------------------------------------------------------------
        recommendations = []
        if repeated_fps:
            recommendations.append(
                f"Identified {len(repeated_fps)} asset(s) with repeated false positives. Recommend calibrating "
                f"asset-specific exposure dampening before triggering automated containment."
            )
        if repeated_fns:
            recommendations.append(
                f"CRITICAL: {len(repeated_fns)} asset(s) sustained unpredicted compromises. Recommend expanding "
                f"lateral attack path discovery and lowering threshold on upstream ingress nodes."
            )
        if weakest_h:
            recommendations.append(
                f"Forecast horizon '{weakest_h}' exhibits lower comparative accuracy. Recommend conservative "
                f"weighting in CP-SAT preemptive optimization."
            )
        if not recommendations:
            recommendations.append("Model operating within nominal accuracy boundaries across all evaluated horizons.")

        return AdaptiveFeedbackInsights(
            repeated_false_positives=repeated_fps[:10],
            repeated_false_negatives=repeated_fns[:10],
            weakest_horizon=weakest_h,
            strongest_horizon=strongest_h,
            weak_asset_types=weak_types,
            error_associated_features=error_features_list,
            threat_indicator_insights=indicator_insights[:10],
            recommended_policy_adjustments=recommendations,
            governance_note="Feedback layer is non-autonomous: operational containment policies and thresholds require human analyst authorization.",
        )
