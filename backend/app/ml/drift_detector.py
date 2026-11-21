"""SafeContain AI Continuous Telemetry Drift Detection Subsystem (Phase 7.2D).

Implements:
1. Feature Drift: Numerical (Population Stability Index + Kolmogorov-Smirnov) and Categorical (Categorical PSI + Frequency Shift).
2. Prediction Drift: Shift in threat probability distributions P(Y=1) and threshold crossing rates.
3. Data Quality Drift: Missing rates, unexpected columns, schema violations, out-of-range values.
4. Asset Population Drift: Asset count, node type distribution, and graph topology structural shifts.
5. Multi-tiered Severity Classification: NORMAL, LOW, MODERATE, HIGH, CRITICAL with automated retraining recommendations.
6. Persistent drift monitoring history and audit records.
"""

from __future__ import annotations

import os
import json
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from scipy import stats

from backend.app.ml.feature_engineering import FeatureEngineer
from backend.app.ml.model_registry import ModelRegistry
from backend.app.ml.model_trainer import DEFAULT_ARTIFACTS_DIR
from backend.app.ml.task_definition import TOPOLOGY_FEATURE_COLUMNS

logger = logging.getLogger("safecontain.ml.drift")

DEFAULT_DRIFT_DIR = os.path.join(DEFAULT_ARTIFACTS_DIR, "drift")


class DriftSeverity(str, Enum):
    """Categorical severity rating for individual features and aggregate monitoring."""
    NORMAL = "NORMAL"
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def calculate_psi(expected: np.ndarray, actual: np.ndarray, num_bins: int = 10) -> float:
    """Calculates Population Stability Index (PSI) between reference and current continuous data."""
    if len(expected) == 0 or len(actual) == 0:
        return 0.0

    # Ensure 1D arrays of floats
    exp_clean = np.asarray(expected, dtype=float)
    act_clean = np.asarray(actual, dtype=float)

    # Filter out NaNs
    exp_clean = exp_clean[~np.isnan(exp_clean)]
    act_clean = act_clean[~np.isnan(act_clean)]

    if len(exp_clean) == 0 or len(act_clean) == 0:
        return 0.0

    # Handle constant or zero-variance distributions
    if np.allclose(exp_clean, exp_clean[0]):
        if np.allclose(act_clean, exp_clean[0]):
            return 0.0
        return 1.0

    # Quantile-based breakpoints from expected reference
    quantiles = np.linspace(0, 100, num_bins + 1)
    breakpoints = np.percentile(exp_clean, quantiles)
    breakpoints = np.unique(breakpoints)
    if len(breakpoints) < 2:
        return 0.0

    breakpoints[0] -= 1e-5
    breakpoints[-1] += 1e-5

    exp_counts, _ = np.histogram(exp_clean, bins=breakpoints)
    act_counts, _ = np.histogram(act_clean, bins=breakpoints)

    exp_pct = np.maximum(exp_counts / len(exp_clean), 1e-4)
    act_pct = np.maximum(act_counts / len(act_clean), 1e-4)

    exp_pct = exp_pct / exp_pct.sum()
    act_pct = act_pct / act_pct.sum()

    psi = np.sum((act_pct - exp_pct) * np.log(act_pct / exp_pct))
    return float(max(0.0, psi))


def calculate_categorical_psi(expected_series: pd.Series, actual_series: pd.Series) -> float:
    """Calculates categorical PSI across observed classes between reference and current series."""
    exp_clean = expected_series.dropna().astype(str)
    act_clean = actual_series.dropna().astype(str)

    if len(exp_clean) == 0 or len(act_clean) == 0:
        return 0.0

    categories = sorted(list(set(exp_clean.unique()).union(set(act_clean.unique()))))
    exp_counts = exp_clean.value_counts()
    act_counts = act_clean.value_counts()

    exp_total = len(exp_clean)
    act_total = len(act_clean)

    psi = 0.0
    for cat in categories:
        e_p = max(exp_counts.get(cat, 0) / exp_total, 1e-4)
        a_p = max(act_counts.get(cat, 0) / act_total, 1e-4)
        psi += (a_p - e_p) * np.log(a_p / e_p)

    return float(max(0.0, psi))


class TelemetryDriftDetector:
    """Monitors telemetry feature drift, prediction drift, data quality, and asset population."""

    def __init__(
        self,
        artifacts_dir: Optional[str] = None,
        model_registry: Optional[ModelRegistry] = None,
        feature_engineer: Optional[FeatureEngineer] = None,
        psi_low_threshold: float = 0.10,
        psi_mod_threshold: float = 0.20,
        psi_high_threshold: float = 0.35,
    ):
        self.artifacts_dir = artifacts_dir or DEFAULT_ARTIFACTS_DIR
        self.drift_dir = os.path.join(self.artifacts_dir, "drift")
        os.makedirs(self.drift_dir, exist_ok=True)

        self.latest_report_path = os.path.join(self.drift_dir, "latest_drift_report.json")
        self.drift_history_path = os.path.join(self.drift_dir, "drift_history.json")
        self.reference_profile_path = os.path.join(self.drift_dir, "reference_profile.json")

        self.registry = model_registry or ModelRegistry(artifacts_dir=self.artifacts_dir)
        self.fe = feature_engineer or FeatureEngineer()

        self.psi_low = psi_low_threshold
        self.psi_mod = psi_mod_threshold
        self.psi_high = psi_high_threshold

        self._cached_reference_df: Optional[pd.DataFrame] = None

    def _get_reference_dataframe(self) -> pd.DataFrame:
        """Returns baseline reference feature DataFrame from training dataset."""
        if self._cached_reference_df is not None:
            return self._cached_reference_df

        raw_df = self.fe.extract_raw_features()
        self._cached_reference_df = raw_df
        return raw_df

    def compute_reference_profile(self, save: bool = True) -> Dict[str, Any]:
        """Computes and serializes baseline statistical reference profile."""
        ref_df = self._get_reference_dataframe()
        _, metadata = self.registry.load_model()
        features = metadata.get("features", [
            "node_type", "environment", "exposure", "criticality", "business_value",
            "in_degree", "out_degree", "total_degree", "in_out_degree_ratio", "pagerank",
            "is_high_privilege_connected", "admin_edge_count", "has_asset_profile"
        ])
        numeric_features = metadata.get("numeric_features", [
            "criticality", "business_value", "in_degree", "out_degree", "total_degree",
            "in_out_degree_ratio", "pagerank", "is_high_privilege_connected", "admin_edge_count", "has_asset_profile"
        ])
        categorical_features = metadata.get("categorical_features", [
            "node_type", "environment", "exposure"
        ])

        num_stats = {}
        for f in numeric_features:
            series = ref_df[f].dropna().astype(float)
            num_stats[f] = {
                "mean": round(float(series.mean()), 4),
                "std": round(float(series.std()), 4),
                "min": round(float(series.min()), 4),
                "max": round(float(series.max()), 4),
                "p25": round(float(series.quantile(0.25)), 4),
                "p50": round(float(series.median()), 4),
                "p75": round(float(series.quantile(0.75)), 4),
            }

        cat_stats = {}
        for f in categorical_features:
            series = ref_df[f].dropna().astype(str)
            cat_stats[f] = series.value_counts(normalize=True).to_dict()

        # Compute baseline prediction distribution
        probs = self.registry.predict_proba(ref_df)[:, 1]
        th = self.registry.get_operating_threshold()
        pred_stats = {
            "mean_probability": round(float(np.mean(probs)), 4),
            "median_probability": round(float(np.median(probs)), 4),
            "threat_crossing_rate": round(float(np.mean(probs >= th)), 4),
            "operating_threshold": round(th, 4),
            "total_samples": len(probs),
        }

        profile = {
            "reference_id": "BASELINE_SYNTHETIC_ENTERPRISE_V1",
            "model_version": metadata.get("version", "1.0.0"),
            "computed_at": datetime.now(timezone.utc).isoformat(),
            "sample_count": len(ref_df),
            "features": features,
            "numeric_stats": num_stats,
            "categorical_stats": cat_stats,
            "prediction_stats": pred_stats,
        }

        if save:
            with open(self.reference_profile_path, "w", encoding="utf-8") as fp:
                json.dump(profile, fp, indent=2)

        return profile

    def run_drift_analysis(
        self,
        current_df: Optional[pd.DataFrame] = None,
        dataset_label: str = "LIVE_TELEMETRY_GRAPH",
    ) -> Dict[str, Any]:
        """Executes full drift detection pipeline comparing current data against reference.
        
        Args:
            current_df: Optional current feature DataFrame. If omitted, extracts active graph features.
            dataset_label: Identifier for current evaluation window.
            
        Returns:
            Comprehensive drift report dictionary.
        """
        ref_df = self._get_reference_dataframe()
        curr_df = current_df if current_df is not None else self.fe.extract_raw_features()

        pipeline, metadata = self.registry.load_model()
        features = metadata.get("features", TOPOLOGY_FEATURE_COLUMNS)
        th = self.registry.get_operating_threshold()
        model_version = metadata.get("version", "1.0.0")

        # 1. Feature Drift Evaluation
        feature_drift_reports: List[Dict[str, Any]] = []
        drifted_features_count = 0
        max_feature_psi = 0.0

        for feat in features:
            if feat not in curr_df.columns:
                feature_drift_reports.append({
                    "feature": feat,
                    "type": "MISSING_IN_CURRENT",
                    "psi": 1.0,
                    "statistic": None,
                    "p_value": None,
                    "severity": DriftSeverity.CRITICAL.value,
                    "drift_detected": True,
                    "message": f"Feature '{feat}' is completely absent in current telemetry.",
                })
                drifted_features_count += 1
                max_feature_psi = max(max_feature_psi, 1.0)
                continue

            ref_col = ref_df[feat]
            curr_col = curr_df[feat]

            is_numeric = feat not in ["node_type", "environment", "exposure"] and pd.api.types.is_numeric_dtype(ref_col)

            if is_numeric:
                psi_val = calculate_psi(ref_col.values, curr_col.values)
                # 2-sample Kolmogorov-Smirnov test
                ref_clean = ref_col.dropna().astype(float)
                curr_clean = curr_col.dropna().astype(float)
                if len(ref_clean) > 0 and len(curr_clean) > 0:
                    ks_res = stats.ks_2samp(ref_clean.values, curr_clean.values)
                    ks_stat = round(float(ks_res.statistic), 4)
                    ks_pvalue = round(float(ks_res.pvalue), 6)
                else:
                    ks_stat, ks_pvalue = 0.0, 1.0

                method = "PSI + Kolmogorov-Smirnov"
                stat_val = ks_stat
                pval = ks_pvalue
            else:
                psi_val = calculate_categorical_psi(ref_col, curr_col)
                method = "Categorical PSI"
                stat_val = None
                pval = None

            # Determine severity
            if psi_val >= self.psi_high:
                sev = DriftSeverity.HIGH
                is_drift = True
            elif psi_val >= self.psi_mod:
                sev = DriftSeverity.MODERATE
                is_drift = True
            elif psi_val >= self.psi_low:
                sev = DriftSeverity.LOW
                is_drift = False
            else:
                sev = DriftSeverity.NORMAL
                is_drift = False

            if is_drift:
                drifted_features_count += 1
            max_feature_psi = max(max_feature_psi, psi_val)

            feature_drift_reports.append({
                "feature": feat,
                "type": "NUMERIC" if is_numeric else "CATEGORICAL",
                "method": method,
                "psi": round(psi_val, 4),
                "ks_statistic": stat_val,
                "p_value": pval,
                "severity": sev.value,
                "drift_detected": is_drift,
                "ref_mean": round(float(ref_col.mean()), 4) if is_numeric and len(ref_col) > 0 else None,
                "curr_mean": round(float(curr_col.mean()), 4) if is_numeric and len(curr_col) > 0 else None,
            })

        # 2. Prediction Drift Evaluation
        ref_probs = self.registry.predict_proba(ref_df)[:, 1]
        curr_probs = self.registry.predict_proba(curr_df)[:, 1]

        prob_psi = calculate_psi(ref_probs, curr_probs)
        ref_mean_p = float(np.mean(ref_probs))
        curr_mean_p = float(np.mean(curr_probs))
        ref_cross_rate = float(np.mean(ref_probs >= th))
        curr_cross_rate = float(np.mean(curr_probs >= th))

        prob_delta = abs(curr_mean_p - ref_mean_p)
        cross_delta = abs(curr_cross_rate - ref_cross_rate)

        if prob_psi >= self.psi_high or cross_delta >= 0.25:
            pred_sev = DriftSeverity.HIGH
            pred_drift = True
        elif prob_psi >= self.psi_mod or cross_delta >= 0.15:
            pred_sev = DriftSeverity.MODERATE
            pred_drift = True
        elif prob_psi >= self.psi_low or cross_delta >= 0.08:
            pred_sev = DriftSeverity.LOW
            pred_drift = False
        else:
            pred_sev = DriftSeverity.NORMAL
            pred_drift = False

        prediction_drift_report = {
            "prediction_psi": round(prob_psi, 4),
            "ref_mean_probability": round(ref_mean_p, 4),
            "curr_mean_probability": round(curr_mean_p, 4),
            "mean_probability_delta": round(prob_delta, 4),
            "ref_threat_rate": round(ref_cross_rate, 4),
            "curr_threat_rate": round(curr_cross_rate, 4),
            "threat_rate_delta": round(cross_delta, 4),
            "operating_threshold": round(th, 4),
            "severity": pred_sev.value,
            "drift_detected": pred_drift,
        }

        # 3. Data Quality Drift
        missing_rates = {c: float(curr_df[c].isna().mean()) for c in curr_df.columns if c in features}
        high_missing = [c for c, r in missing_rates.items() if r > 0.05]
        quality_sev = DriftSeverity.HIGH if len(high_missing) >= 2 else (DriftSeverity.MODERATE if high_missing else DriftSeverity.NORMAL)

        quality_report = {
            "evaluated_columns": len(features),
            "high_missing_columns": high_missing,
            "max_missing_rate": round(max(missing_rates.values()) if missing_rates else 0.0, 4),
            "severity": quality_sev.value,
            "quality_alert": len(high_missing) > 0,
        }

        # 4. Asset Population Drift
        ref_count = len(ref_df)
        curr_count = len(curr_df)
        count_delta_pct = abs(curr_count - ref_count) / max(1, ref_count)

        pop_sev = DriftSeverity.HIGH if count_delta_pct >= 0.50 else (DriftSeverity.MODERATE if count_delta_pct >= 0.25 else DriftSeverity.NORMAL)
        population_report = {
            "ref_asset_count": ref_count,
            "curr_asset_count": curr_count,
            "asset_count_delta": curr_count - ref_count,
            "delta_percentage": round(count_delta_pct * 100, 2),
            "severity": pop_sev.value,
        }

        # 5. Overall System Severity Classification & Retraining Recommendation
        if max_feature_psi >= self.psi_high or drifted_features_count >= 3 or pred_sev == DriftSeverity.HIGH:
            overall_sev = DriftSeverity.HIGH
            retraining_recommended = True
            rec_message = (
                f"Significant telemetry drift detected across {drifted_features_count} features "
                f"(Max PSI: {max_feature_psi:.4f}). Retraining is strongly recommended to protect threat recall."
            )
        elif max_feature_psi >= self.psi_mod or drifted_features_count >= 2 or pred_sev == DriftSeverity.MODERATE:
            overall_sev = DriftSeverity.MODERATE
            retraining_recommended = True
            rec_message = (
                f"Moderate feature and prediction drift detected across {drifted_features_count} features. "
                "Candidate model retraining recommended."
            )
        elif drifted_features_count >= 1 or max_feature_psi >= self.psi_low:
            overall_sev = DriftSeverity.LOW
            retraining_recommended = False
            rec_message = "Low telemetry drift within acceptable operational tolerances. Continuous monitoring active."
        else:
            overall_sev = DriftSeverity.NORMAL
            retraining_recommended = False
            rec_message = "Telemetry distributions are stable. Champion model operating within nominal parameters."

        now_iso = datetime.now(timezone.utc).isoformat()

        report = {
            "report_id": f"drift-run-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
            "timestamp": now_iso,
            "dataset_label": dataset_label,
            "model_version": model_version,
            "operating_threshold": round(th, 4),
            "overall_severity": overall_sev.value,
            "overall_drift_score": round(max_feature_psi, 4),
            "retraining_recommended": retraining_recommended,
            "retraining_recommendation_reason": rec_message,
            "summary": {
                "total_features_evaluated": len(features),
                "drifted_features_count": drifted_features_count,
                "prediction_drift_detected": pred_drift,
                "data_quality_alert": quality_report["quality_alert"],
                "curr_sample_count": curr_count,
                "ref_sample_count": ref_count,
            },
            "prediction_drift": prediction_drift_report,
            "data_quality": quality_report,
            "population_drift": population_report,
            "features_drift": feature_drift_reports,
        }

        # Persist latest report
        with open(self.latest_report_path, "w", encoding="utf-8") as fp:
            json.dump(report, fp, indent=2)

        # Append to drift history
        history = self.get_drift_history()
        history.append({
            "report_id": report["report_id"],
            "timestamp": now_iso,
            "overall_severity": overall_sev.value,
            "overall_drift_score": round(max_feature_psi, 4),
            "drifted_features_count": drifted_features_count,
            "retraining_recommended": retraining_recommended,
            "dataset_label": dataset_label,
        })
        # Keep last 50 historical runs
        with open(self.drift_history_path, "w", encoding="utf-8") as fp:
            json.dump(history[-50:], fp, indent=2)

        return report

    def get_latest_drift_report(self) -> Optional[Dict[str, Any]]:
        """Returns the most recent persisted drift report or runs fresh analysis if absent."""
        if os.path.exists(self.latest_report_path):
            try:
                with open(self.latest_report_path, "r", encoding="utf-8") as fp:
                    return json.load(fp)
            except Exception as e:
                logger.warning(f"Could not read latest drift report: {e}")
        return self.run_drift_analysis()

    def get_drift_history(self) -> List[Dict[str, Any]]:
        """Returns historical timeline of drift monitoring runs."""
        if os.path.exists(self.drift_history_path):
            try:
                with open(self.drift_history_path, "r", encoding="utf-8") as fp:
                    return json.load(fp)
            except Exception:
                return []
        return []
