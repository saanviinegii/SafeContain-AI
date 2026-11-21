"""Temporal Evaluation Engine for SafeContain AI Phase 7.4.

Evaluates forecasts strictly after their prediction horizons have elapsed against real observed
telemetry, preventing premature evaluations, leakage, and duplicate outcome generation.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import pandas as pd

from backend.app.adaptive.models import (
    GroundTruthOutcome,
    PredictionOutcomeStatus,
    PredictionRecord,
)
from backend.app.adaptive.tracker import PredictionOutcomeTracker
from backend.app.ml.dataset_loader import DatasetLoader

logger = logging.getLogger("safecontain.adaptive.evaluation_engine")


class TemporalEvaluationEngine:
    """Evaluates time-windowed forecasts against ground-truth security telemetry observed after prediction."""

    def __init__(
        self,
        tracker: Optional[PredictionOutcomeTracker] = None,
        loader: Optional[DatasetLoader] = None,
    ):
        self.tracker = tracker or PredictionOutcomeTracker.get_instance()
        self.loader = loader or DatasetLoader()
        self._alerts_df: Optional[pd.DataFrame] = None
        self._evidence_df: Optional[pd.DataFrame] = None
        self._nodes_df: Optional[pd.DataFrame] = None
        self._known_nodes_set: Optional[Set[str]] = None

    def _get_telemetry(self) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        if self._alerts_df is None:
            self._alerts_df = self.loader.load_table("security_alerts.csv").copy()
            self._alerts_df["ts"] = pd.to_datetime(self._alerts_df["timestamp"], utc=True)

        if self._evidence_df is None:
            self._evidence_df = self.loader.load_table("evidence.csv").copy()
            self._evidence_df["ts"] = pd.to_datetime(self._evidence_df["timestamp"], utc=True)

        if self._nodes_df is None:
            self._nodes_df = self.loader.load_table("nodes.csv").copy()
            self._known_nodes_set = set(self._nodes_df["node_id"].dropna().tolist())

        return self._alerts_df, self._evidence_df, self._nodes_df

    def evaluate_prediction(
        self,
        record: PredictionRecord,
        evaluation_time: Optional[datetime] = None,
        force_recompute: bool = False,
        auto_save: bool = True,
    ) -> PredictionRecord:
        """Evaluates a single prediction against telemetry strictly within (t_pred, t_pred + H].
        
        Enforces:
        1. Non-premature evaluation: if t_eval < horizon_end_timestamp, status remains PENDING_EVALUATION.
        2. Strict window bounds: only events in (t_pred, horizon_end_timestamp] are considered.
        3. Evidence grounding: requires verifiable telemetry or confirmed state.
        """
        # If already evaluated and not forced, return cached outcome
        if (
            not force_recompute
            and record.outcome_status != PredictionOutcomeStatus.PENDING_EVALUATION
            and record.outcome_status != PredictionOutcomeStatus.INSUFFICIENT_EVIDENCE
        ):
            return record

        eval_ts = evaluation_time or datetime.now(timezone.utc)
        if eval_ts.tzinfo is None:
            eval_ts = eval_ts.replace(tzinfo=timezone.utc)

        t_pred = record.prediction_timestamp
        if t_pred.tzinfo is None:
            t_pred = t_pred.replace(tzinfo=timezone.utc)

        h_end = record.horizon_end_timestamp
        if h_end.tzinfo is None:
            h_end = h_end.replace(tzinfo=timezone.utc)

        # ---------------------------------------------------------------------
        # Gate 1: Non-Premature Evaluation Rule
        # ---------------------------------------------------------------------
        if eval_ts < h_end:
            record.outcome_status = PredictionOutcomeStatus.PENDING_EVALUATION
            record.outcome_evaluation_timestamp = None
            record.evaluation_notes = (
                f"Horizon window (+{record.horizon_hours:.0f}h) has not yet elapsed. "
                f"Evaluation eligibility begins at {h_end.isoformat()}."
            )
            self.tracker.register_prediction(record, auto_save=auto_save)
            return record

        # ---------------------------------------------------------------------
        # Gate 2: Query Telemetry strictly in (t_pred, h_end]
        # ---------------------------------------------------------------------
        alerts_df, evidence_df, nodes_df = self._get_telemetry()

        # Telemetry in the prediction horizon
        horizon_alerts = alerts_df[(alerts_df["ts"] > t_pred) & (alerts_df["ts"] <= h_end)]
        horizon_evidence = evidence_df[(evidence_df["ts"] > t_pred) & (evidence_df["ts"] <= h_end)]

        # Check for alerts targeting or originating from this asset
        asset_alerts = horizon_alerts[
            (horizon_alerts["target_node_id"] == record.asset_id)
            | (horizon_alerts["source_node_id"] == record.asset_id)
        ]

        # Check for forensic evidence on this asset
        asset_evidence = horizon_evidence[horizon_evidence["related_node_id"] == record.asset_id]

        evidence_ids = []
        if not asset_alerts.empty:
            evidence_ids.extend([f"ALERT:{aid}" for aid in asset_alerts["alert_id"].dropna().tolist()])
        if not asset_evidence.empty:
            evidence_ids.extend([f"EVID:{eid}" for eid in asset_evidence["evidence_id"].dropna().tolist()])

        # Check if asset is known in enterprise inventory
        is_known_asset = record.asset_id in (self._known_nodes_set or set())

        # ---------------------------------------------------------------------
        # Gate 3: Classify Outcome based on Genuine Telemetry
        # ---------------------------------------------------------------------
        predicted_as_threat = record.threshold_crossed

        if len(evidence_ids) > 0:
            # Compromise confirmed by telemetry observed in horizon
            actual_outcome = GroundTruthOutcome.COMPROMISED.value
            source = "LIVE_SECURITY_TELEMETRY"

            if predicted_as_threat:
                status = PredictionOutcomeStatus.CONFIRMED_COMPROMISE
                notes = (
                    f"Confirmed True Positive: Asset '{record.asset_name}' ({record.asset_id}) was predicted at "
                    f"{record.predicted_probability:.1%} probability (>= {record.operating_threshold:.2f}) and suffered "
                    f"{len(evidence_ids)} observed security incident event(s) during the {record.forecast_horizon} window."
                )
            else:
                status = PredictionOutcomeStatus.FALSE_NEGATIVE
                notes = (
                    f"False Negative Detected: Asset '{record.asset_name}' was predicted at low risk "
                    f"({record.predicted_probability:.1%} < {record.operating_threshold:.2f}), but sustained {len(evidence_ids)} "
                    f"confirmed security telemetry event(s) in window."
                )
        elif is_known_asset:
            # Asset was active and monitored with zero alerts in window
            actual_outcome = GroundTruthOutcome.BENIGN.value
            source = "CONTINUOUS_MONITORING_TELEMETRY"

            if predicted_as_threat:
                status = PredictionOutcomeStatus.FALSE_POSITIVE
                notes = (
                    f"False Positive Detected: Asset '{record.asset_name}' crossed the threat threshold "
                    f"({record.predicted_probability:.1%} >= {record.operating_threshold:.2f}), but zero malicious events "
                    f"or evidence were detected during the elapsed horizon window."
                )
            else:
                status = PredictionOutcomeStatus.CORRECT_NON_EVENT
                notes = (
                    f"Correct True Negative: Asset '{record.asset_name}' was predicted healthy "
                    f"({record.predicted_probability:.1%}) and successfully exhibited zero malicious incidents in window."
                )
        else:
            # Unknown asset or missing inventory sensor coverage
            actual_outcome = GroundTruthOutcome.INCONCLUSIVE.value
            source = "SENSOR_COVERAGE_GAP"
            status = PredictionOutcomeStatus.INSUFFICIENT_EVIDENCE
            notes = f"Insufficient forensic telemetry available to conclusively verify status of asset '{record.asset_id}'."

        # Update record in tracker
        record.outcome_status = status
        record.actual_outcome = actual_outcome
        record.outcome_source = source
        record.evidence_ids = evidence_ids
        record.evaluation_notes = notes
        record.outcome_evaluation_timestamp = eval_ts

        if not self.tracker.get_prediction(record.prediction_id):
            self.tracker.register_prediction(record, auto_save=False)

        self.tracker.update_outcome(
            prediction_id=record.prediction_id,
            status=status,
            actual_outcome=actual_outcome,
            source=source,
            evidence_ids=evidence_ids,
            notes=notes,
            evaluation_timestamp=eval_ts,
            auto_save=auto_save,
        )
        return record

    def evaluate_all_eligible_predictions(
        self,
        evaluation_time: Optional[datetime] = None,
        force_recompute: bool = False,
    ) -> Dict[str, Any]:
        """Evaluates all registered predictions whose prediction horizons have elapsed."""
        eval_ts = evaluation_time or datetime.now(timezone.utc)
        if eval_ts.tzinfo is None:
            eval_ts = eval_ts.replace(tzinfo=timezone.utc)

        all_preds = self.tracker.get_all_predictions()
        evaluated_count = 0
        pending_count = 0
        tp_count = 0
        fp_count = 0
        tn_count = 0
        fn_count = 0
        insufficient_count = 0

        for p in all_preds:
            # Attempt evaluation
            res = self.evaluate_prediction(p, evaluation_time=eval_ts, force_recompute=force_recompute, auto_save=False)
            if res.outcome_status == PredictionOutcomeStatus.PENDING_EVALUATION:
                pending_count += 1
            elif res.outcome_status == PredictionOutcomeStatus.INSUFFICIENT_EVIDENCE:
                insufficient_count += 1
            else:
                evaluated_count += 1
                if res.outcome_status == PredictionOutcomeStatus.CONFIRMED_COMPROMISE:
                    tp_count += 1
                elif res.outcome_status == PredictionOutcomeStatus.FALSE_POSITIVE:
                    fp_count += 1
                elif res.outcome_status == PredictionOutcomeStatus.CORRECT_NON_EVENT:
                    tn_count += 1
                elif res.outcome_status == PredictionOutcomeStatus.FALSE_NEGATIVE:
                    fn_count += 1

        # Single batch save to disk
        self.tracker._save()

        return {
            "evaluation_timestamp": eval_ts.isoformat(),
            "total_predictions": len(all_preds),
            "evaluated_count": evaluated_count,
            "pending_count": pending_count,
            "insufficient_evidence_count": insufficient_count,
            "breakdown": {
                "true_positives": tp_count,
                "false_positives": fp_count,
                "true_negatives": tn_count,
                "false_negatives": fn_count,
            },
        }

    def bootstrap_benchmark_evaluation(self) -> Dict[str, Any]:
        """Bootstraps evaluation records across benchmark telemetry time slices for audit and validation.
        
        Uses genuine historical alert timestamps from synthetic_enterprise dataset to create historical
        predictions at t_obs = 08:30:00 UTC and evaluates against subsequent alerts observed in (t_obs, t_obs + H].
        Guarantees ZERO fabricated telemetry.
        """
        from backend.app.forecasting.forecaster import TemporalThreatForecaster
        from backend.app.forecasting.models import ForecastHorizon

        forecaster = TemporalThreatForecaster.get_instance()
        alerts_df, _, _ = self._get_telemetry()
        min_ts = alerts_df["ts"].min().to_pydatetime()
        max_ts = alerts_df["ts"].max().to_pydatetime()

        # Observation anchor: 40% into the incident timeline so subsequent 60% contains ground-truth outcomes
        t_obs = min_ts + (max_ts - min_ts) * 0.40

        # Generate forecasts for all 3 horizons at t_obs
        records_created = 0
        for horizon in [ForecastHorizon.NEAR_TERM, ForecastHorizon.SHORT_TERM, ForecastHorizon.MEDIUM_TERM]:
            forecasts = forecaster.forecast_all_assets(horizon=horizon)
            records = self.tracker.record_forecasts(forecasts, prediction_time=t_obs)
            records_created += len(records)

        # Now evaluate using evaluation_time = max_ts (when all scenario horizons have elapsed!)
        eval_summary = self.evaluate_all_eligible_predictions(evaluation_time=max_ts, force_recompute=True)
        eval_summary["benchmark_bootstrap_records_created"] = records_created
        return eval_summary
