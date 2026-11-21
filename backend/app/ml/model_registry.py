"""Model Registry and Inference Service for SafeContain AI ML Pipeline.

Provides safe model loading, schema verification, feature validation, and real-time
cybersecurity risk prediction for enterprise graph nodes and telemetry.
"""

import os
import json
from typing import Any, Dict, List, Optional, Tuple
import joblib
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline

from backend.app.ml.feature_engineering import FeatureEngineer
from backend.app.ml.model_trainer import DEFAULT_ARTIFACTS_DIR


class ModelRegistry:
    """Manages model artifacts, schema validation, and inference lifecycle."""

    def __init__(
        self,
        artifacts_dir: Optional[str] = None,
        feature_engineer: Optional[FeatureEngineer] = None,
    ):
        self.artifacts_dir = os.path.abspath(artifacts_dir or DEFAULT_ARTIFACTS_DIR)
        self.models_dir = os.path.join(self.artifacts_dir, "models")
        self.calibration_dir = os.path.join(self.artifacts_dir, "calibration")
        self.model_path = os.path.join(self.models_dir, "best_model.joblib")
        self.metadata_path = os.path.join(self.models_dir, "model_metadata.json")
        self.calibration_path = os.path.join(self.calibration_dir, "calibration_metadata.json")

        self.fe = feature_engineer or FeatureEngineer()
        self._cached_model: Optional[Pipeline] = None
        self._cached_metadata: Optional[Dict[str, Any]] = None
        self._cached_calibration: Optional[Dict[str, Any]] = None

    def invalidate_cache(self) -> None:
        """Clears in-memory cached model, metadata, and calibration."""
        self._cached_model = None
        self._cached_metadata = None
        self._cached_calibration = None

    def is_model_available(self) -> bool:
        """Checks if a trained model artifact and its metadata exist on disk."""
        return os.path.isfile(self.model_path) and os.path.isfile(self.metadata_path)

    def is_calibration_available(self) -> bool:
        """Checks if calibrated decision threshold metadata exists on disk."""
        return os.path.isfile(self.calibration_path)

    def get_operating_threshold(self) -> float:
        """Returns the calibrated decision threshold, or defaults to 0.50 if uncalibrated."""
        if self.is_calibration_available():
            try:
                cal_meta = self.get_calibration_metadata()
                if "operating_threshold" in cal_meta:
                    return float(cal_meta["operating_threshold"])
            except Exception:
                pass
        return 0.50

    def get_calibration_metadata(self) -> Dict[str, Any]:
        """Returns decision threshold calibration metadata or status if uncalibrated."""
        if not self.is_calibration_available():
            return {
                "status": "UNCALIBRATED",
                "operating_threshold": 0.50,
                "message": "Model is operating at default uncalibrated threshold 0.50.",
            }
        if self._cached_calibration is not None:
            return self._cached_calibration
        with open(self.calibration_path, "r", encoding="utf-8") as f:
            cal_data = json.load(f)
        self._cached_calibration = cal_data
        return cal_data

    def load_model(self, force_reload: bool = False) -> Tuple[Pipeline, Dict[str, Any]]:

        """Loads and caches the trained pipeline and metadata from disk."""
        if not self.is_model_available():
            raise FileNotFoundError(
                f"No trained model artifact found at {self.model_path}. "
                "Execute the training pipeline via 'python -m backend.app.ml.train' first."
            )

        if not force_reload and self._cached_model is not None and self._cached_metadata is not None:
            return self._cached_model, self._cached_metadata

        # Load metadata
        with open(self.metadata_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)

        # Load serialized pipeline
        pipeline = joblib.load(self.model_path)

        self._cached_model = pipeline
        self._cached_metadata = metadata
        return pipeline, metadata

    def get_model_metadata(self) -> Dict[str, Any]:
        """Returns metadata of currently active model or placeholder if uninitialized."""
        if not self.is_model_available():
            return {
                "status": "UNINITIALIZED",
                "message": "No model artifact registered. Run training pipeline first.",
            }
        _, metadata = self.load_model()
        return {
            "status": "ACTIVE",
            "metadata": metadata,
        }

    def validate_features(self, X: pd.DataFrame, expected_features: List[str]) -> None:
        """Verifies that input DataFrame contains all required feature columns.
        
        Raises:
            ValueError: If required feature columns are missing.
        """
        missing_cols = [c for c in expected_features if c not in X.columns]
        if missing_cols:
            raise ValueError(
                f"Feature schema mismatch. Input DataFrame is missing required features: {missing_cols}"
            )

    def predict(
        self,
        X: pd.DataFrame,
        threshold: Optional[float] = None,
    ) -> np.ndarray:
        """Executes binary classification prediction with threshold calibration."""
        pipeline, metadata = self.load_model()
        expected_features = metadata.get("features", [])
        self.validate_features(X, expected_features)
        X_ordered = X[expected_features]

        th = float(threshold) if threshold is not None else self.get_operating_threshold()
        if hasattr(pipeline, "predict_proba"):
            probs = pipeline.predict_proba(X_ordered)[:, 1]
            return (probs >= th).astype(int)
        return pipeline.predict(X_ordered)

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Computes calibrated probability distributions P(Y=0), P(Y=1)."""
        pipeline, metadata = self.load_model()
        expected_features = metadata.get("features", [])
        self.validate_features(X, expected_features)
        X_ordered = X[expected_features]
        if not hasattr(pipeline, "predict_proba"):
            raise NotImplementedError(f"Model {metadata.get('model_name')} does not support predict_proba.")
        return pipeline.predict_proba(X_ordered)

    def predict_for_nodes(
        self,
        node_ids: Optional[List[str]] = None,
        threshold: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Extracts live features and evaluates risk predictions for specific or all nodes."""
        pipeline, metadata = self.load_model()
        feature_subset = metadata.get("feature_subset", "topology_only")
        raw_df = self.fe.extract_raw_features()

        if node_ids is not None:
            raw_df = raw_df[raw_df["node_id"].isin(node_ids)].copy()
            if len(raw_df) == 0:
                return []

        expected_features = metadata.get("features", [])
        self.validate_features(raw_df, expected_features)

        th = float(threshold) if threshold is not None else self.get_operating_threshold()
        X_input = raw_df[expected_features]
        probabilities = pipeline.predict_proba(X_input) if hasattr(pipeline, "predict_proba") else None

        results = []
        for idx, (_, row) in enumerate(raw_df.iterrows()):
            nid = str(row["node_id"])
            prob_risk = float(probabilities[idx, 1]) if probabilities is not None else 0.5
            pred = int(1 if prob_risk >= th else 0)

            # Assign risk tier based on calibrated probability
            if prob_risk >= 0.75:
                tier = "CRITICAL"
            elif prob_risk >= 0.50:
                tier = "HIGH"
            elif prob_risk >= 0.25:
                tier = "MEDIUM"
            else:
                tier = "LOW"

            results.append({
                "node_id": nid,
                "is_at_risk": pred,
                "risk_probability": round(prob_risk, 4),
                "operating_threshold": round(th, 4),
                "risk_tier": tier,
                "node_type": str(row.get("node_type", "UNKNOWN")),
                "exposure": str(row.get("exposure", "UNKNOWN")),
                "criticality": float(row.get("criticality", 0.5)),
            })

        return results

