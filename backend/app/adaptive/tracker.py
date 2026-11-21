"""Prediction Outcome Tracker for SafeContain AI Phase 7.4.

Manages the registration, persistence, retrieval, and lifecycle of traceable prediction records
produced by the Phase 7.3 forecasting engine.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.app.adaptive.models import (
    GroundTruthOutcome,
    PredictionOutcomeStatus,
    PredictionRecord,
)
from backend.app.forecasting.models import AssetRiskForecast, ForecastHorizon
from backend.app.ml.model_trainer import DEFAULT_ARTIFACTS_DIR

logger = logging.getLogger("safecontain.adaptive.tracker")

DEFAULT_ADAPTIVE_DIR = os.path.join(DEFAULT_ARTIFACTS_DIR, "adaptive")
DEFAULT_PREDICTIONS_FILE = os.path.join(DEFAULT_ADAPTIVE_DIR, "predictions.json")


class PredictionOutcomeTracker:
    """Manages persistent tracking of all temporal risk predictions and their evaluation lifecycle."""

    _instance: Optional["PredictionOutcomeTracker"] = None

    def __init__(self, storage_path: Optional[str] = None):
        self.storage_path = storage_path or DEFAULT_PREDICTIONS_FILE
        self._predictions: Dict[str, PredictionRecord] = {}
        self._ensure_storage()
        self._load()

    @classmethod
    def get_instance(cls) -> "PredictionOutcomeTracker":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _ensure_storage(self) -> None:
        directory = os.path.dirname(self.storage_path)
        if directory and not os.path.exists(directory):
            try:
                os.makedirs(directory, exist_ok=True)
            except Exception as e:
                logger.warning("Could not create adaptive artifacts directory '%s': %s", directory, e)

    def _load(self) -> None:
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data:
                        rec = PredictionRecord(**item)
                        self._predictions[rec.prediction_id] = rec
                logger.info("Loaded %d prediction records from '%s'", len(self._predictions), self.storage_path)
            except Exception as e:
                logger.error("Failed to load predictions from '%s': %s", self.storage_path, e)

    def _save(self) -> None:
        try:
            self._ensure_storage()
            records_data = [p.model_dump(mode="json") for p in self._predictions.values()]
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(records_data, f, indent=2, default=str)
        except Exception as e:
            logger.error("Failed to save predictions to '%s': %s", self.storage_path, e)

    def register_prediction(self, record: PredictionRecord, auto_save: bool = True) -> PredictionRecord:
        """Stores a new prediction record. If already exists, updates while preserving evaluated outcome."""
        existing = self._predictions.get(record.prediction_id)
        if existing and existing.outcome_status != PredictionOutcomeStatus.PENDING_EVALUATION:
            # Preserve already evaluated outcome
            record.outcome_status = existing.outcome_status
            record.outcome_evaluation_timestamp = existing.outcome_evaluation_timestamp
            record.actual_outcome = existing.actual_outcome
            record.outcome_source = existing.outcome_source
            record.evidence_ids = existing.evidence_ids
            record.evaluation_notes = existing.evaluation_notes

        self._predictions[record.prediction_id] = record
        if auto_save:
            self._save()
        return record

    save_prediction = register_prediction

    def record_forecasts(
        self,
        forecasts: List[AssetRiskForecast],
        prediction_time: Optional[datetime] = None,
    ) -> List[PredictionRecord]:
        """Converts a batch of Phase 7.3 AssetRiskForecast objects into traceable PredictionRecords."""
        records: List[PredictionRecord] = []
        now = prediction_time or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        for f in forecasts:
            h_val = f.forecast_horizon.value if isinstance(f.forecast_horizon, ForecastHorizon) else str(f.forecast_horizon)
            h_hours = float(f.forecast_window_hours)
            h_end = now + timedelta(hours=h_hours)

            # Deterministic, unique prediction ID
            pred_id = f"pred-{h_val.lower()}-{f.asset_id}-{int(now.timestamp())}"

            top_feats = []
            for feat in f.top_contributing_features:
                top_feats.append({
                    "feature_name": feat.feature_name,
                    "feature_value": feat.feature_value,
                    "contribution_score": feat.contribution_score,
                    "direction": feat.direction,
                    "description": feat.description,
                })

            is_threat = bool(f.predicted_future_probability >= 0.32)

            rec = PredictionRecord(
                prediction_id=pred_id,
                asset_id=f.asset_id,
                asset_name=f.asset_name,
                asset_type=f.asset_type,
                prediction_timestamp=now,
                forecast_horizon=h_val,
                horizon_hours=h_hours,
                horizon_end_timestamp=h_end,
                predicted_probability=f.predicted_future_probability,
                predicted_risk_score=f.predicted_future_risk,
                predicted_threat_class="At-Risk / Threat" if is_threat else "Healthy / Benign",
                model_version=f.model_version,
                operating_threshold=0.32,
                threshold_crossed=is_threat,
                top_features=top_feats,
                propagation_depth=len(f.propagation_hops),
                forecast_explanation=f.forecast_explanation,
                outcome_status=PredictionOutcomeStatus.PENDING_EVALUATION,
            )
            self.register_prediction(rec, auto_save=False)
            records.append(rec)

        self._save()
        return records

    def update_outcome(
        self,
        prediction_id: str,
        status: PredictionOutcomeStatus,
        actual_outcome: str,
        source: str,
        evidence_ids: Optional[List[str]] = None,
        notes: Optional[str] = None,
        evaluation_timestamp: Optional[datetime] = None,
        auto_save: bool = True,
    ) -> Optional[PredictionRecord]:
        """Updates the evaluation outcome of an existing prediction record."""
        rec = self._predictions.get(prediction_id)
        if not rec:
            return None

        eval_ts = evaluation_timestamp or datetime.now(timezone.utc)
        rec.outcome_status = status
        rec.actual_outcome = actual_outcome
        rec.outcome_source = source
        rec.outcome_evaluation_timestamp = eval_ts
        rec.evidence_ids = evidence_ids or []
        rec.evaluation_notes = notes

        self._predictions[prediction_id] = rec
        if auto_save:
            self._save()
        return rec

    def get_prediction(self, prediction_id: str) -> Optional[PredictionRecord]:
        return self._predictions.get(prediction_id)

    def list_predictions(
        self,
        horizon: Optional[str] = None,
        status: Optional[str] = None,
        asset_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[PredictionRecord], int]:
        """Queries prediction records with optional filtering and pagination."""
        items = list(self._predictions.values())

        # Sort descending by prediction timestamp
        items.sort(key=lambda x: x.prediction_timestamp, reverse=True)

        if horizon and isinstance(horizon, str):
            h_upper = horizon.upper().strip()
            items = [p for p in items if p.forecast_horizon.upper() == h_upper]

        if status and isinstance(status, str):
            s_upper = status.upper().strip()
            items = [p for p in items if p.outcome_status.value == s_upper]

        if asset_id and isinstance(asset_id, str):
            a_lower = asset_id.lower().strip()
            items = [p for p in items if a_lower in p.asset_id.lower() or a_lower in p.asset_name.lower()]

        total = len(items)
        paged = items[offset : offset + limit]
        return paged, total

    def get_all_predictions(self) -> List[PredictionRecord]:
        return list(self._predictions.values())

    def clear(self) -> None:
        """Clears in-memory and on-disk prediction cache (primarily for tests)."""
        self._predictions.clear()
        if os.path.exists(self.storage_path):
            try:
                os.remove(self.storage_path)
            except Exception:
                pass
