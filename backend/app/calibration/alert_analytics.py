"""Module 7.5.4: Alert Fatigue & False-Positive Analytics for SafeContain AI.

Analyzes enterprise alert distributions, false-positive frequencies, Gini concentration index,
and identifies noisy assets causing operational alert fatigue in SOC workflows.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from backend.app.adaptive.models import PredictionOutcomeStatus, PredictionRecord
from backend.app.adaptive.tracker import PredictionOutcomeTracker
from backend.app.calibration.models import (
    AlertFatigueAnalytics,
    NoisyAssetItem,
)
from backend.app.ml.dataset_loader import DatasetLoader

logger = logging.getLogger("safecontain.calibration.alert_analytics")


class AlertFatigueAnalyzer:
    """Computes alert distribution metrics, Gini concentration, and noisy asset profiles."""

    _instance: Optional["AlertFatigueAnalyzer"] = None

    def __init__(
        self,
        tracker: Optional[PredictionOutcomeTracker] = None,
        loader: Optional[DatasetLoader] = None,
    ):
        self.tracker = tracker or PredictionOutcomeTracker.get_instance()
        self.loader = loader or DatasetLoader()

    @classmethod
    def get_instance(cls) -> "AlertFatigueAnalyzer":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @staticmethod
    def compute_gini(counts: List[int]) -> float:
        """Computes Gini concentration coefficient: 0 = evenly distributed, 1 = concentrated on one asset."""
        if not counts or sum(counts) == 0:
            return 0.0
        sorted_counts = sorted(counts)
        k = len(sorted_counts)
        total = sum(sorted_counts)
        numerator = sum((2 * (i + 1) - k - 1) * count for i, count in enumerate(sorted_counts))
        gini = numerator / (k * total)
        return round(float(max(0.0, min(1.0, gini))), 4)

    def analyze_alert_fatigue(
        self,
        custom_records: Optional[List[PredictionRecord]] = None,
    ) -> AlertFatigueAnalytics:
        """Analyzes SOC alert fatigue, Gini concentration, and noisy asset hotspots."""
        records = custom_records if custom_records is not None else self.tracker.get_all_predictions()

        # Aggregate alerts, FPs, and confirmed breaches per asset
        asset_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "name": "",
            "type": "SERVER",
            "alerts": 0,
            "fps": 0,
            "tps": 0,
            "features": Counter(),
        })

        severity_counts: Counter = Counter()
        total_fps = 0
        total_tps = 0
        total_alerts = 0

        for r in records:
            aid = r.asset_id
            name = r.asset_name
            atype = r.asset_type

            # An alert is triggered if threshold is crossed (predicted threat)
            is_alert = r.threshold_crossed or (r.predicted_probability >= 0.32)
            if is_alert:
                total_alerts += 1
                asset_stats[aid]["alerts"] += 1
                asset_stats[aid]["name"] = name
                asset_stats[aid]["type"] = atype

                # Severity assignment based on risk score
                if r.predicted_risk_score >= 80.0:
                    severity_counts["CRITICAL"] += 1
                elif r.predicted_risk_score >= 50.0:
                    severity_counts["HIGH"] += 1
                elif r.predicted_risk_score >= 25.0:
                    severity_counts["MEDIUM"] += 1
                else:
                    severity_counts["LOW"] += 1

                # Track feature contributors
                for feat in r.top_features:
                    fname = feat.get("feature_name", "unknown")
                    asset_stats[aid]["features"][fname] += 1

                # Outcome tracking
                if r.outcome_status == PredictionOutcomeStatus.FALSE_POSITIVE or r.actual_outcome == "BENIGN":
                    asset_stats[aid]["fps"] += 1
                    total_fps += 1
                elif r.outcome_status == PredictionOutcomeStatus.CONFIRMED_COMPROMISE or r.actual_outcome == "COMPROMISED":
                    asset_stats[aid]["tps"] += 1
                    total_tps += 1

        asset_counts = [stat["alerts"] for stat in asset_stats.values()]
        total_assets = len(asset_stats)

        mean_alerts = round(float(total_alerts / total_assets), 2) if total_assets > 0 else 0.0
        max_alerts = max(asset_counts) if asset_counts else 0
        gini = self.compute_gini(asset_counts) if asset_counts else 0.0

        overall_fa_ratio = round(float(total_fps / total_alerts), 4) if total_alerts > 0 else 0.0

        # Composite Alert Fatigue Index (0 to 100)
        # Weights: 40% False Alarm Rate, 30% Gini concentration, 30% alert volume load
        volume_burden = min(1.0, mean_alerts / 5.0) if mean_alerts > 0 else 0.0
        afi = round(
            float(
                (40.0 * overall_fa_ratio)
                + (30.0 * gini)
                + (30.0 * volume_burden)
            ),
            2,
        )

        if afi >= 75.0:
            fatigue_status = "CRITICAL"
        elif afi >= 50.0:
            fatigue_status = "ELEVATED"
        elif afi >= 25.0:
            fatigue_status = "MODERATE"
        else:
            fatigue_status = "LOW"

        # Identify noisy assets (assets with high alerts and high false alarm rate)
        noisy_list: List[NoisyAssetItem] = []
        for aid, data in asset_stats.items():
            alerts_count = data["alerts"]
            fps_count = data["fps"]
            tps_count = data["tps"]

            if alerts_count > 0:
                fa_rate = round(float(fps_count / alerts_count), 4)
                # Noisy condition: >= 1 FP or high alert volume
                if fps_count > 0 or alerts_count >= 3:
                    top_driver = "general_telemetry_variance"
                    if data["features"]:
                        top_driver = data["features"].most_common(1)[0][0]

                    # Recommended mitigation
                    if fa_rate >= 0.75:
                        mitigation = f"High noise ({fa_rate * 100:.0f}% false alarms). Implement asset suppression rule on '{top_driver}'."
                    elif fa_rate >= 0.40:
                        mitigation = f"Moderate noise. Calibrate risk sensitivity baseline for {data['type']} tier."
                    else:
                        mitigation = "High alert frequency with true threats. Maintain active monitoring and incident response prioritization."

                    noisy_list.append(
                        NoisyAssetItem(
                            asset_id=aid,
                            asset_name=data["name"] or aid,
                            asset_type=data["type"],
                            total_alerts=alerts_count,
                            false_positive_count=fps_count,
                            confirmed_breach_count=tps_count,
                            false_alarm_rate=fa_rate,
                            primary_alert_driver=top_driver,
                            recommended_mitigation=mitigation,
                        )
                    )

        # Sort noisy assets: highest FP count first, then highest alerts
        noisy_list.sort(key=lambda x: (-x.false_positive_count, -x.total_alerts))

        # Advisory synthesis
        if fatigue_status in ("CRITICAL", "ELEVATED"):
            advisory = (
                f"Alert Fatigue Index is {afi:.1f} ({fatigue_status}). {total_fps} of {total_alerts} alerts are false alarms "
                f"({overall_fa_ratio * 100:.1f}%). Alert concentration Gini is {gini:.2f}. "
                f"Prioritize tuning thresholds for top noisy assets: {', '.join([n.asset_name for n in noisy_list[:3]])}."
            )
        else:
            advisory = (
                f"Alert Fatigue Index is {afi:.1f} ({fatigue_status}). False alarm ratio is controlled at {overall_fa_ratio * 100:.1f}%. "
                f"Alert distribution Gini is {gini:.2f}."
            )

        return AlertFatigueAnalytics(
            total_alerts_analyzed=total_alerts,
            mean_alerts_per_asset=mean_alerts,
            max_alerts_single_asset=max_alerts,
            gini_alert_concentration=gini,
            alert_fatigue_index=afi,
            total_false_positives=total_fps,
            total_confirmed_threats=total_tps,
            overall_false_alarm_ratio=overall_fa_ratio,
            noisy_assets=noisy_list[:15], # Top 15 noisy assets
            severity_distribution=dict(severity_counts),
            fatigue_status=fatigue_status,
            governance_advisory=advisory,
            analyzed_at=datetime.now(timezone.utc),
        )
