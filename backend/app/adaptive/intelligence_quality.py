"""Threat Intelligence Evidence Quality Engine for SafeContain AI Phase 7.4.

Evaluates empirical source reliability, indicator freshness, cross-source confirmation independence,
and historical validity against ground-truth security outcomes without treating repetition as proof.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
import pandas as pd

from backend.app.adaptive.models import ThreatIntelQualityMetrics

logger = logging.getLogger("safecontain.adaptive.intelligence_quality")


class ThreatIntelligenceQualityEngine:
    """Audits the provenance, independence, freshness, and empirical accuracy of threat indicators."""

    def __init__(self, threat_engine: Optional[Any] = None):
        if threat_engine is None:
            from backend.app.threat_intel.engine import ThreatCorrelationEngine
            self.threat_engine = ThreatCorrelationEngine()
        else:
            self.threat_engine = threat_engine

    def evaluate_quality(
        self,
        records: Optional[List[PredictionRecord]] = None,
    ) -> ThreatIntelQualityMetrics:
        """Evaluates source confirmation rates, multi-source independence, and indicator reliability."""
        indicators = self.threat_engine.collect_all_indicators()

        # Check telemetry for confirmed events
        alerts_df = self.threat_engine.fe.loader.load_table("security_alerts.csv")
        alerts_df["ts"] = pd.to_datetime(alerts_df["timestamp"], utc=True)
        confirmed_nodes = set(alerts_df["target_node_id"].dropna()).union(set(alerts_df["source_node_id"].dropna()))

        now = datetime.now(timezone.utc)

        # ---------------------------------------------------------------------
        # 1. Source Reliability Breakdown
        # ---------------------------------------------------------------------
        source_stats: Dict[str, Dict[str, Any]] = {}
        for ind in indicators:
            src = ind.source or "Unknown Source"
            if src not in source_stats:
                source_stats[src] = {
                    "total_indicators": 0,
                    "confirmed_hits": 0,
                    "mean_confidence": 0.0,
                    "severity_breakdown": {},
                }

            s = source_stats[src]
            s["total_indicators"] += 1
            s["mean_confidence"] += float(ind.confidence)

            sev = ind.severity.value
            s["severity_breakdown"][sev] = s["severity_breakdown"].get(sev, 0) + 1

            # Check if any associated asset suffered verified alert
            if any(aid in confirmed_nodes for aid in ind.associated_asset_ids):
                s["confirmed_hits"] += 1

        for src, s in source_stats.items():
            tot = max(1, s["total_indicators"])
            s["confirmation_rate"] = round(s["confirmed_hits"] / tot, 4)
            s["mean_confidence"] = round(s["mean_confidence"] / tot, 4)

        # ---------------------------------------------------------------------
        # 2. Multi-Source Independence vs Single-Source Repetition
        # ---------------------------------------------------------------------
        # Group by indicator value to detect multi-source confirmation
        by_val: Dict[str, Set[str]] = {}
        for ind in indicators:
            by_val.setdefault(ind.value.lower(), set()).add(ind.source)

        multi_source_count = sum(1 for sources in by_val.values() if len(sources) > 1)
        total_unique_vals = max(1, len(by_val))
        independence_ratio = round(multi_source_count / total_unique_vals, 4)

        # ---------------------------------------------------------------------
        # 3. Freshness Distribution
        # ---------------------------------------------------------------------
        freshness_dist = {
            "within_24h": 0,
            "1_to_7_days": 0,
            "8_to_30_days": 0,
            "older_than_30d": 0,
        }

        for ind in indicators:
            try:
                seen_dt = datetime.fromisoformat(ind.last_seen.replace("Z", "+00:00"))
                age_days = (now - seen_dt).total_seconds() / 86400.0
                if age_days <= 1.0:
                    freshness_dist["within_24h"] += 1
                elif age_days <= 7.0:
                    freshness_dist["1_to_7_days"] += 1
                elif age_days <= 30.0:
                    freshness_dist["8_to_30_days"] += 1
                else:
                    freshness_dist["older_than_30d"] += 1
            except Exception:
                freshness_dist["1_to_7_days"] += 1

        # ---------------------------------------------------------------------
        # 4. Top Validated vs Noisy Indicators
        # ---------------------------------------------------------------------
        validated_list: List[Dict[str, Any]] = []
        noisy_list: List[Dict[str, Any]] = []

        for ind in indicators:
            associated = set(ind.associated_asset_ids)
            has_confirmed_hit = bool(associated.intersection(confirmed_nodes))
            distinct_sources = len(by_val.get(ind.value.lower(), set()))

            item = {
                "indicator_id": ind.id,
                "type": ind.type.value,
                "value": ind.value,
                "source": ind.source,
                "confidence": ind.confidence,
                "distinct_sources_count": distinct_sources,
                "has_incident_confirmation": has_confirmed_hit,
                "independent_confirmation": distinct_sources > 1,
            }

            if has_confirmed_hit:
                validated_list.append(item)
            elif ind.severity.value in ("CRITICAL", "HIGH"):
                # High severity but unconfirmed in actual enterprise telemetry
                noisy_list.append(item)

        validated_list.sort(key=lambda x: (x["independent_confirmation"], x["confidence"]), reverse=True)
        noisy_list.sort(key=lambda x: x["confidence"], reverse=True)

        return ThreatIntelQualityMetrics(
            total_evaluated_indicators=len(indicators),
            source_reliability=source_stats,
            multi_source_independence_rate=independence_ratio,
            freshness_distribution=freshness_dist,
            top_validated_indicators=validated_list[:10],
            noisy_indicators=noisy_list[:10],
        )
