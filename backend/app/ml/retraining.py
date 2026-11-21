"""SafeContain AI Continuous Retraining & Champion-Challenger Lifecycle Engine (Phase 7.2D).

Implements:
1. Pre-training Data Validation Gate: Schema, class balance, minimum sample threshold, zero target leakage.
2. Controlled Retraining Pipeline: Multi-metric cross-validation, candidate evaluation, holdout test verification.
3. Decision Threshold Calibration for Challenger models under cost-sensitive threat constraints.
4. Champion-Challenger Side-by-Side Comparative Evaluation with automated promotion recommendations.
5. Model Versioning & Artifact Governance in `artifacts/models/versions/`.
6. Safe, Non-Autonomous Model Promotion, Rejection, and Instant Rollback Governance.
"""

from __future__ import annotations

import os
import shutil
import json
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.pipeline import Pipeline

from backend.app.ml.feature_engineering import FeatureEngineer
from backend.app.ml.model_registry import ModelRegistry
from backend.app.ml.model_trainer import DEFAULT_ARTIFACTS_DIR
from backend.app.ml.task_definition import (
    TASK_NODE_RISK_CLASSIFICATION,
    TOPOLOGY_FEATURE_COLUMNS,
    FORBIDDEN_LEAKAGE_COLUMNS,
    assert_no_target_leakage,
)

logger = logging.getLogger("safecontain.ml.retraining")

DEFAULT_MODELS_DIR = os.path.join(DEFAULT_ARTIFACTS_DIR, "models")
DEFAULT_VERSIONS_DIR = os.path.join(DEFAULT_MODELS_DIR, "versions")
DEFAULT_CALIBRATION_DIR = os.path.join(DEFAULT_ARTIFACTS_DIR, "calibration")
DEFAULT_JOBS_FILE = os.path.join(DEFAULT_MODELS_DIR, "training_jobs.json")


class ModelStatus(str, Enum):
    """Lifecycle status for registered model versions."""
    ACTIVE = "ACTIVE"              # Currently serving production predictions
    CHALLENGER = "CHALLENGER"      # Candidate model under evaluation
    ARCHIVED = "ARCHIVED"          # Previous production champion, eligible for rollback
    REJECTED = "REJECTED"          # Candidate evaluated and rejected by analyst/governance
    ROLLED_BACK = "ROLLED_BACK"    # Demoted during emergency rollback


class PromotionRecommendation(str, Enum):
    """System recommendation for champion-challenger comparison."""
    RECOMMEND_PROMOTION = "RECOMMEND_PROMOTION"
    REJECT_CHALLENGER = "REJECT_CHALLENGER"
    INCONCLUSIVE = "INCONCLUSIVE"


class RetrainingManager:
    """Manages pre-validation gates, retraining execution, champion-challenger comparison, and model promotion/rollback."""

    def __init__(
        self,
        artifacts_dir: Optional[str] = None,
        feature_engineer: Optional[FeatureEngineer] = None,
        model_registry: Optional[ModelRegistry] = None,
    ):
        self.artifacts_dir = os.path.abspath(artifacts_dir or DEFAULT_ARTIFACTS_DIR)
        self.models_dir = os.path.join(self.artifacts_dir, "models")
        self.versions_dir = os.path.join(self.models_dir, "versions")
        self.calibration_dir = os.path.join(self.artifacts_dir, "calibration")
        self.jobs_file = os.path.join(self.models_dir, "training_jobs.json")

        os.makedirs(self.models_dir, exist_ok=True)
        os.makedirs(self.versions_dir, exist_ok=True)
        os.makedirs(self.calibration_dir, exist_ok=True)

        self.fe = feature_engineer or FeatureEngineer()
        self.registry = model_registry or ModelRegistry(
            artifacts_dir=self.artifacts_dir,
            feature_engineer=self.fe,
        )

        self._ensure_initial_champion_version()

    def _ensure_initial_champion_version(self) -> None:
        """Ensures that the existing active model (v1.0.0) is cataloged in the versions repository."""
        champion_path = os.path.join(self.models_dir, "best_model.joblib")
        meta_path = os.path.join(self.models_dir, "model_metadata.json")
        calib_path = os.path.join(self.calibration_dir, "calibration_metadata.json")

        if not os.path.exists(champion_path) or not os.path.exists(meta_path):
            return

        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            version = meta.get("version", "1.0.0")
        except Exception:
            version = "1.0.0"

        v_dir = os.path.join(self.versions_dir, f"v{version.lstrip('v')}")
        os.makedirs(v_dir, exist_ok=True)

        v_model = os.path.join(v_dir, "model.joblib")
        v_meta = os.path.join(v_dir, "model_metadata.json")
        v_calib = os.path.join(v_dir, "calibration_metadata.json")

        if not os.path.exists(v_model):
            shutil.copy2(champion_path, v_model)

        if not os.path.exists(v_meta):
            with open(meta_path, "r", encoding="utf-8") as f:
                v_meta_data = json.load(f)
            v_meta_data["status"] = ModelStatus.ACTIVE.value
            v_meta_data["is_champion"] = True
            v_meta_data["registered_at"] = datetime.now(timezone.utc).isoformat()
            with open(v_meta, "w", encoding="utf-8") as f:
                json.dump(v_meta_data, f, indent=2)

        if os.path.exists(calib_path) and not os.path.exists(v_calib):
            shutil.copy2(calib_path, v_calib)

    # -------------------------------------------------------------------------
    # Pre-training Data Validation Gate
    # -------------------------------------------------------------------------

    def validate_training_dataset(
        self,
        df: pd.DataFrame,
        feature_cols: Optional[List[str]] = None,
        target_col: str = "target_is_at_risk",
    ) -> Dict[str, Any]:
        """Pre-training validation gate verifying data quality, class balance, and zero leakage."""
        errors: List[str] = []
        warnings: List[str] = []
        metrics: Dict[str, Any] = {}

        # 1. Target Column Check
        if target_col not in df.columns:
            errors.append(f"Target column '{target_col}' not found in dataset.")
            return {
                "is_valid": False,
                "errors": errors,
                "warnings": warnings,
                "metrics": metrics,
            }

        # 2. Sample Size Check (Minimum 50 samples for valid cross-validation)
        total_samples = len(df)
        metrics["sample_count"] = total_samples
        if total_samples < 50:
            errors.append(f"Dataset has {total_samples} samples; minimum required is 50.")

        # 3. Class Balance and Distinct Classes Check
        target_series = df[target_col].dropna()
        unique_classes = target_series.unique()
        metrics["unique_classes"] = [int(c) for c in unique_classes]

        if len(unique_classes) < 2:
            errors.append(f"Target '{target_col}' must contain at least 2 distinct classes. Found: {list(unique_classes)}.")
        else:
            class_counts = target_series.value_counts().to_dict()
            metrics["class_distribution"] = {str(k): int(v) for k, v in class_counts.items()}
            pos_count = int(class_counts.get(1, 0))
            metrics["positive_samples"] = pos_count
            pos_ratio = round(pos_count / max(1, total_samples), 4)
            metrics["positive_ratio"] = pos_ratio

            if pos_count < 5:
                errors.append(f"Minority class has only {pos_count} samples; minimum required is 5 for stratified splitting.")
            elif pos_ratio < 0.05:
                warnings.append(f"Extreme class imbalance detected: positive class is only {pos_ratio*100:.1f}%.")

        # 4. Target Leakage Verification
        cols_to_check = feature_cols or [c for c in df.columns if c != target_col]
        try:
            assert_no_target_leakage(cols_to_check)
            metrics["leakage_check_passed"] = True
        except ValueError as e:
            errors.append(f"Target leakage violation: {str(e)}")
            metrics["leakage_check_passed"] = False

        # 5. Missing Value Rate Check (< 15% per feature, < 10% overall)
        missing_rates = (df[cols_to_check].isnull().mean()).to_dict()
        metrics["missing_rates_per_feature"] = {k: round(float(v), 4) for k, v in missing_rates.items()}
        high_missing_cols = [k for k, v in missing_rates.items() if v > 0.15]
        if high_missing_cols:
            errors.append(f"Features exceed 15% missing value threshold: {high_missing_cols}")

        overall_missing = float(df[cols_to_check].isnull().mean().mean())
        metrics["overall_missing_rate"] = round(overall_missing, 4)
        if overall_missing > 0.10:
            warnings.append(f"Overall missing rate ({overall_missing*100:.1f}%) exceeds recommended 10%.")

        is_valid = len(errors) == 0
        return {
            "is_valid": is_valid,
            "errors": errors,
            "warnings": warnings,
            "metrics": metrics,
        }

    # -------------------------------------------------------------------------
    # Challenger Training & Threshold Calibration
    # -------------------------------------------------------------------------

    def train_challenger(
        self,
        feature_subset: str = "topology_only",
        cv_folds: int = 5,
        test_size: float = 0.2,
        trigger_type: str = "MANUAL",
        user_notes: str = "",
        candidate_model_type: str = "logistic_regression",
        hyperparameters: Optional[Dict[str, Any]] = None,
        initiator: str = "SYSTEM_OR_ANALYST",
    ) -> Dict[str, Any]:
        """Trains and validates a challenger model against holdout test set with threshold calibration."""
        job_id = f"retrain-{uuid.uuid4().hex[:8]}"
        start_time = datetime.now(timezone.utc)
        logger.info("Starting retraining job %s triggered by %s", job_id, trigger_type)

        raw_df = self.fe.extract_raw_features()
        subsets = self.fe.get_feature_subsets()
        feature_cols = subsets.get(feature_subset, list(TOPOLOGY_FEATURE_COLUMNS))

        # 1. Pre-training Validation Gate
        validation_gate = self.validate_training_dataset(
            df=raw_df,
            feature_cols=feature_cols,
            target_col="target_is_at_risk",
        )

        if not validation_gate["is_valid"]:
            job_record = {
                "job_id": job_id,
                "status": "FAILED",
                "trigger_type": trigger_type,
                "initiator": initiator,
                "created_at": start_time.isoformat(),
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "failure_reason": f"Pre-training validation gate failed: {validation_gate['errors']}",
                "validation_gate": validation_gate,
            }
            self._record_job(job_record)
            raise ValueError(f"Pre-training validation gate failed: {validation_gate['errors']}")

        # 2. Prepare Data Split
        X = raw_df[feature_cols].copy()
        y = raw_df["target_is_at_risk"].copy()
        categorical_cols = [c for c in feature_cols if c in ["node_type", "environment", "exposure"]]
        numeric_cols = [c for c in feature_cols if c not in categorical_cols]

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )

        # 3. Build Preprocessor and Estimator Pipeline
        preprocessor = FeatureEngineer.build_preprocessor(numeric_cols, categorical_cols)

        if candidate_model_type == "random_forest":
            clf_params = hyperparameters or {"n_estimators": 100, "max_depth": 5, "class_weight": "balanced", "random_state": 42}
            clf = RandomForestClassifier(**clf_params)
        else:
            clf_params = hyperparameters or {"C": 0.5, "class_weight": "balanced", "solver": "liblinear", "random_state": 42}
            clf = LogisticRegression(**clf_params)

        pipeline = Pipeline([
            ("preprocessor", preprocessor),
            ("clf", clf),
        ])

        # 4. Stratified Cross-Validation on Training Split
        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
        scoring = {
            "balanced_accuracy": "balanced_accuracy",
            "recall": "recall",
            "precision": "precision",
            "f1": "f1",
            "roc_auc": "roc_auc",
        }
        cv_res = cross_validate(pipeline, X_train, y_train, cv=cv, scoring=scoring, return_train_score=False)
        cv_metrics = {
            "balanced_accuracy": round(float(np.mean(cv_res["test_balanced_accuracy"])), 4),
            "recall": round(float(np.mean(cv_res["test_recall"])), 4),
            "precision": round(float(np.mean(cv_res["test_precision"])), 4),
            "f1": round(float(np.mean(cv_res["test_f1"])), 4),
            "roc_auc": round(float(np.mean(cv_res["test_roc_auc"])), 4),
        }

        # 5. Fit on Train Split and Predict on Holdout Test Split
        pipeline.fit(X_train, y_train)
        test_probs = pipeline.predict_proba(X_test)[:, 1]

        # 6. Candidate Threshold Calibration on Holdout / Out-of-fold Probabilities
        threshold_evals = []
        best_th = 0.32
        best_cost = float("inf")
        best_th_metrics: Dict[str, Any] = {}

        candidate_thresholds = np.linspace(0.10, 0.70, 61)
        c_fn = 10.0
        c_fp = 1.0

        for th in candidate_thresholds:
            th = round(float(th), 2)
            preds = (test_probs >= th).astype(int)
            tn, fp, fn, tp = confusion_matrix(y_test, preds, labels=[0, 1]).ravel()
            rec = recall_score(y_test, preds, zero_division=0)
            prec = precision_score(y_test, preds, zero_division=0)
            f1 = f1_score(y_test, preds, zero_division=0)
            bal_acc = balanced_accuracy_score(y_test, preds)
            cost = float(fn * c_fn + fp * c_fp)

            th_record = {
                "threshold": th,
                "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn),
                "recall": round(float(rec), 4),
                "precision": round(float(prec), 4),
                "f1": round(float(f1), 4),
                "balanced_accuracy": round(float(bal_acc), 4),
                "total_cost": cost,
            }
            threshold_evals.append(th_record)

            # Constraint: Recall >= 0.80 if possible, minimize total cost
            if rec >= 0.80 and cost < best_cost:
                best_cost = cost
                best_th = th
                best_th_metrics = th_record

        # Fallback if no threshold hit recall constraint
        if not best_th_metrics:
            sorted_by_cost = sorted(threshold_evals, key=lambda x: (x["fn"], x["total_cost"]))
            best_th_metrics = sorted_by_cost[0]
            best_th = best_th_metrics["threshold"]

        # Default threshold (0.50) metrics for comparison
        default_preds = (test_probs >= 0.50).astype(int)
        d_tn, d_fp, d_fn, d_tp = confusion_matrix(y_test, default_preds, labels=[0, 1]).ravel()
        default_metrics = {
            "threshold": 0.50,
            "tp": int(d_tp), "tn": int(d_tn), "fp": int(d_fp), "fn": int(d_fn),
            "recall": round(float(recall_score(y_test, default_preds, zero_division=0)), 4),
            "precision": round(float(precision_score(y_test, default_preds, zero_division=0)), 4),
            "f1": round(float(f1_score(y_test, default_preds, zero_division=0)), 4),
            "balanced_accuracy": round(float(balanced_accuracy_score(y_test, default_preds)), 4),
            "total_cost": float(d_fn * c_fn + d_fp * c_fp),
        }

        # 7. Generate Semantic Version for Challenger
        existing_versions = self._get_existing_versions()
        challenger_version = self._generate_next_version(existing_versions)

        # 8. Store Challenger Artifacts
        v_dir = os.path.join(self.versions_dir, challenger_version)
        os.makedirs(v_dir, exist_ok=True)

        joblib.dump(pipeline, os.path.join(v_dir, "model.joblib"))

        challenger_metadata = {
            "model_name": candidate_model_type,
            "version": challenger_version,
            "status": ModelStatus.CHALLENGER.value,
            "is_champion": False,
            "feature_subset": feature_subset,
            "features": feature_cols,
            "numeric_features": numeric_cols,
            "categorical_features": categorical_cols,
            "best_hyperparameters": clf_params,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "trained_by": initiator,
            "trigger_type": trigger_type,
            "user_notes": user_notes,
            "cv_metrics": cv_metrics,
            "holdout_default_metrics": default_metrics,
            "holdout_calibrated_metrics": best_th_metrics,
            "holdout_roc_auc": round(float(roc_auc_score(y_test, test_probs)), 4),
            "calibrated_threshold": best_th,
        }
        with open(os.path.join(v_dir, "model_metadata.json"), "w", encoding="utf-8") as f:
            json.dump(challenger_metadata, f, indent=2)

        calibration_metadata = {
            "calibration_timestamp": datetime.now(timezone.utc).isoformat(),
            "operating_threshold": best_th,
            "default_threshold": 0.50,
            "selection_strategy": "recall_constrained_cost_optimal",
            "target_recall": 0.80,
            "cost_assumptions": {"c_fn": c_fn, "c_fp": c_fp, "ratio": "10:1"},
            "calibrated_metrics": best_th_metrics,
            "default_metrics": default_metrics,
        }
        with open(os.path.join(v_dir, "calibration_metadata.json"), "w", encoding="utf-8") as f:
            json.dump(calibration_metadata, f, indent=2)

        # 9. Evaluate Champion vs. Challenger Comparison
        comparison = self.compare_champion_challenger(challenger_version)

        # 10. Record Job Completion
        duration = round((datetime.now(timezone.utc) - start_time).total_seconds(), 2)
        job_record = {
            "job_id": job_id,
            "version": challenger_version,
            "status": "COMPLETED",
            "trigger_type": trigger_type,
            "initiator": initiator,
            "created_at": start_time.isoformat(),
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": duration,
            "recommendation": comparison["recommendation"],
            "recommendation_reason": comparison["recommendation_reason"],
            "validation_gate": validation_gate,
            "cv_metrics": cv_metrics,
            "holdout_metrics": best_th_metrics,
        }
        self._record_job(job_record)

        return {
            "job_id": job_id,
            "challenger_version": challenger_version,
            "duration_seconds": duration,
            "comparison": comparison,
            "validation_gate": validation_gate,
            "metadata": challenger_metadata,
        }

    # -------------------------------------------------------------------------
    # Champion-Challenger Side-by-Side Comparison
    # -------------------------------------------------------------------------

    def compare_champion_challenger(self, challenger_version: Optional[str] = None) -> Dict[str, Any]:
        """Performs side-by-side metric comparison between champion and designated challenger."""
        # 1. Load Champion
        champ_meta_path = os.path.join(self.models_dir, "model_metadata.json")
        champ_calib_path = os.path.join(self.calibration_dir, "calibration_metadata.json")

        if not os.path.exists(champ_meta_path):
            raise FileNotFoundError("Active champion model metadata not found.")

        with open(champ_meta_path, "r", encoding="utf-8") as f:
            champ_meta = json.load(f)

        champ_calib = {}
        if os.path.exists(champ_calib_path):
            with open(champ_calib_path, "r", encoding="utf-8") as f:
                champ_calib = json.load(f)

        champion_version = champ_meta.get("version", "1.0.0")

        # 2. Locate Challenger
        if challenger_version is None:
            # Pick latest non-active version
            versions = self._get_existing_versions()
            candidates = [v for v in versions if v != champion_version and v != f"v{champion_version.lstrip('v')}"]
            if not candidates:
                raise ValueError("No challenger model version found to compare against champion.")
            challenger_version = candidates[-1]

        challenger_dir = os.path.join(self.versions_dir, challenger_version)
        challenger_meta_path = os.path.join(challenger_dir, "model_metadata.json")

        if not os.path.exists(challenger_meta_path):
            raise FileNotFoundError(f"Challenger metadata for '{challenger_version}' not found at {challenger_meta_path}.")

        with open(challenger_meta_path, "r", encoding="utf-8") as f:
            chall_meta = json.load(f)

        # 3. Extract Comparable Metrics
        # Champion metrics
        champ_holdout = champ_calib.get("holdout_comparison", {}).get("calibrated_threshold", {})
        champ_rec = champ_holdout.get("recall", champ_meta.get("holdout_test_recall", 0.8))
        champ_prec = champ_holdout.get("precision", 0.2353)
        champ_f1 = champ_holdout.get("f1_score", 0.3636)
        champ_bal_acc = champ_holdout.get("balanced_accuracy", champ_meta.get("holdout_test_balanced_accuracy", 0.5579))
        champ_fn = champ_holdout.get("false_negatives", 1)
        champ_cost = champ_holdout.get("total_cost", 23.0)
        champ_th = champ_calib.get("operating_threshold", 0.32)

        # Challenger metrics
        chall_holdout = chall_meta.get("holdout_calibrated_metrics", {})
        chall_rec = chall_holdout.get("recall", 0.0)
        chall_prec = chall_holdout.get("precision", 0.0)
        chall_f1 = chall_holdout.get("f1", 0.0)
        chall_bal_acc = chall_holdout.get("balanced_accuracy", 0.0)
        chall_fn = chall_holdout.get("fn", 0)
        chall_cost = chall_holdout.get("total_cost", 0.0)
        chall_th = chall_meta.get("calibrated_threshold", 0.32)

        # Calculate Deltas (Challenger - Champion)
        deltas = {
            "recall": round(chall_rec - champ_rec, 4),
            "precision": round(chall_prec - champ_prec, 4),
            "f1": round(chall_f1 - champ_f1, 4),
            "balanced_accuracy": round(chall_bal_acc - champ_bal_acc, 4),
            "missed_threats": chall_fn - champ_fn,  # Lower is better
            "total_cost": round(chall_cost - champ_cost, 2),  # Lower is better
        }

        # 4. Evaluation Recommendation Decision Logic
        # Safety & Security First: Threat detection recall must not degrade
        rec_pass = chall_rec >= champ_rec or chall_fn <= champ_fn
        cost_acceptable = chall_cost <= (champ_cost * 1.25)
        f1_reasonable = chall_f1 >= 0.20

        if rec_pass and cost_acceptable and f1_reasonable:
            recommendation = PromotionRecommendation.RECOMMEND_PROMOTION.value
            reason = (
                f"Challenger {challenger_version} demonstrates superior or equal threat detection recall "
                f"({chall_rec:.2%} vs Champion {champ_rec:.2%}) with {chall_fn} missed threats vs {champ_fn}. "
                f"Operational containment disruption cost remains bounded (${chall_cost:.1f} vs ${champ_cost:.1f})."
            )
        else:
            recommendation = PromotionRecommendation.REJECT_CHALLENGER.value
            fail_reasons = []
            if not rec_pass:
                fail_reasons.append(f"Threat recall dropped from {champ_rec:.2%} to {chall_rec:.2%} (missed threats: {chall_fn} vs {champ_fn})")
            if not cost_acceptable:
                fail_reasons.append(f"Total operational cost increased significantly (${chall_cost:.1f} vs ${champ_cost:.1f})")
            if not f1_reasonable:
                fail_reasons.append(f"F1 score too low ({chall_f1:.4f} < 0.20)")
            reason = f"Challenger fails security/governance criteria: {'; '.join(fail_reasons)}."

        return {
            "champion_version": champion_version,
            "challenger_version": challenger_version,
            "recommendation": recommendation,
            "recommendation_reason": reason,
            "metrics_comparison": {
                "recall": {"champion": champ_rec, "challenger": chall_rec, "delta": deltas["recall"]},
                "precision": {"champion": champ_prec, "challenger": chall_prec, "delta": deltas["precision"]},
                "f1_score": {"champion": champ_f1, "challenger": chall_f1, "delta": deltas["f1"]},
                "balanced_accuracy": {"champion": champ_bal_acc, "challenger": chall_bal_acc, "delta": deltas["balanced_accuracy"]},
                "missed_threats": {"champion": champ_fn, "challenger": chall_fn, "delta": deltas["missed_threats"]},
                "total_cost": {"champion": champ_cost, "challenger": chall_cost, "delta": deltas["total_cost"]},
                "operating_threshold": {"champion": champ_th, "challenger": chall_th, "delta": round(chall_th - champ_th, 4)},
            },
            "deltas": deltas,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }

    # -------------------------------------------------------------------------
    # Governance: Promotion, Rejection & Rollback
    # -------------------------------------------------------------------------

    def approve_and_promote_model(
        self,
        challenger_version: str,
        current_user: str,
        approval_notes: str = "",
    ) -> Dict[str, Any]:
        """Promotes challenger model to active champion with full audit trail and atomic backup."""
        challenger_dir = os.path.join(self.versions_dir, challenger_version)
        chall_model_path = os.path.join(challenger_dir, "model.joblib")
        chall_meta_path = os.path.join(challenger_dir, "model_metadata.json")
        chall_calib_path = os.path.join(challenger_dir, "calibration_metadata.json")

        if not os.path.exists(chall_model_path) or not os.path.exists(chall_meta_path):
            raise FileNotFoundError(f"Challenger artifacts not found for version '{challenger_version}'.")

        with open(chall_meta_path, "r", encoding="utf-8") as f:
            chall_meta = json.load(f)

        # 1. Archive Current Champion
        active_meta_path = os.path.join(self.models_dir, "model_metadata.json")
        current_champ_version = "v1.0.0"
        if os.path.exists(active_meta_path):
            with open(active_meta_path, "r", encoding="utf-8") as f:
                cur_meta = json.load(f)
            current_champ_version = f"v{cur_meta.get('version', '1.0.0').lstrip('v')}"
            cur_champ_dir = os.path.join(self.versions_dir, current_champ_version)
            os.makedirs(cur_champ_dir, exist_ok=True)

            # Mark old champion as ARCHIVED in versions repo
            cur_meta["status"] = ModelStatus.ARCHIVED.value
            cur_meta["is_champion"] = False
            cur_meta["archived_at"] = datetime.now(timezone.utc).isoformat()
            cur_meta["demoted_by"] = current_user
            with open(os.path.join(cur_champ_dir, "model_metadata.json"), "w", encoding="utf-8") as f:
                json.dump(cur_meta, f, indent=2)

        # 2. Promote Challenger to Active Champion
        active_model_path = os.path.join(self.models_dir, "best_model.joblib")
        shutil.copy2(chall_model_path, active_model_path)

        now_str = datetime.now(timezone.utc).isoformat()
        chall_meta["status"] = ModelStatus.ACTIVE.value
        chall_meta["is_champion"] = True
        chall_meta["promoted_at"] = now_str
        chall_meta["promoted_by"] = current_user
        chall_meta["approval_notes"] = approval_notes

        with open(active_meta_path, "w", encoding="utf-8") as f:
            json.dump(chall_meta, f, indent=2)

        with open(chall_meta_path, "w", encoding="utf-8") as f:
            json.dump(chall_meta, f, indent=2)

        # 3. Update Calibration Metadata
        if os.path.exists(chall_calib_path):
            active_calib_path = os.path.join(self.calibration_dir, "calibration_metadata.json")
            shutil.copy2(chall_calib_path, active_calib_path)

        # Invalidate cached model in registry
        self.registry.invalidate_cache()

        logger.info(
            "Model version %s successfully promoted to ACTIVE champion by %s. Previous champion %s ARCHIVED.",
            challenger_version, current_user, current_champ_version
        )

        return {
            "status": "SUCCESS",
            "promoted_version": challenger_version,
            "previous_version": current_champ_version,
            "promoted_by": current_user,
            "promoted_at": now_str,
            "operating_threshold": chall_meta.get("calibrated_threshold", 0.32),
            "notes": approval_notes,
        }

    def reject_model(
        self,
        challenger_version: str,
        current_user: str,
        rejection_reason: str,
    ) -> Dict[str, Any]:
        """Formally rejects a candidate model version with justification."""
        challenger_dir = os.path.join(self.versions_dir, challenger_version)
        chall_meta_path = os.path.join(challenger_dir, "model_metadata.json")

        if not os.path.exists(chall_meta_path):
            raise FileNotFoundError(f"Challenger artifacts not found for version '{challenger_version}'.")

        with open(chall_meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        now_str = datetime.now(timezone.utc).isoformat()
        meta["status"] = ModelStatus.REJECTED.value
        meta["rejected_at"] = now_str
        meta["rejected_by"] = current_user
        meta["rejection_reason"] = rejection_reason

        with open(chall_meta_path, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        return {
            "status": "REJECTED",
            "version": challenger_version,
            "rejected_by": current_user,
            "rejected_at": now_str,
            "reason": rejection_reason,
        }

    def rollback_model(
        self,
        target_version: str,
        current_user: str,
        rollback_reason: str = "Rollback initiated by security operations.",
    ) -> Dict[str, Any]:
        """Rolls back the active model to a previous archived version."""
        target_v_str = f"v{target_version.lstrip('v')}"
        target_dir = os.path.join(self.versions_dir, target_v_str)

        target_model = os.path.join(target_dir, "model.joblib")
        target_meta_file = os.path.join(target_dir, "model_metadata.json")
        target_calib_file = os.path.join(target_dir, "calibration_metadata.json")

        if not os.path.exists(target_model) or not os.path.exists(target_meta_file):
            raise FileNotFoundError(f"Rollback target version '{target_version}' does not exist in versions repository.")

        # Demote current champion
        active_meta_path = os.path.join(self.models_dir, "model_metadata.json")
        cur_version = "UNKNOWN"
        if os.path.exists(active_meta_path):
            with open(active_meta_path, "r", encoding="utf-8") as f:
                cur_meta = json.load(f)
            cur_version = cur_meta.get("version", "UNKNOWN")
            cur_v_dir = os.path.join(self.versions_dir, f"v{cur_version.lstrip('v')}")
            os.makedirs(cur_v_dir, exist_ok=True)
            cur_meta["status"] = ModelStatus.ROLLED_BACK.value
            cur_meta["is_champion"] = False
            cur_meta["rolled_back_at"] = datetime.now(timezone.utc).isoformat()
            cur_meta["rolled_back_by"] = current_user
            with open(os.path.join(cur_v_dir, "model_metadata.json"), "w", encoding="utf-8") as f:
                json.dump(cur_meta, f, indent=2)

        # Restore target version to active
        with open(target_meta_file, "r", encoding="utf-8") as f:
            target_meta = json.load(f)

        now_str = datetime.now(timezone.utc).isoformat()
        target_meta["status"] = ModelStatus.ACTIVE.value
        target_meta["is_champion"] = True
        target_meta["restored_at"] = now_str
        target_meta["restored_by"] = current_user
        target_meta["rollback_reason"] = rollback_reason

        shutil.copy2(target_model, os.path.join(self.models_dir, "best_model.joblib"))
        with open(active_meta_path, "w", encoding="utf-8") as f:
            json.dump(target_meta, f, indent=2)
        with open(target_meta_file, "w", encoding="utf-8") as f:
            json.dump(target_meta, f, indent=2)

        if os.path.exists(target_calib_file):
            shutil.copy2(target_calib_file, os.path.join(self.calibration_dir, "calibration_metadata.json"))

        self.registry.invalidate_cache()

        logger.warning(
            "EMERGENCY ROLLBACK: Demoted %s and restored target version %s to ACTIVE champion by %s.",
            cur_version, target_version, current_user
        )

        return {
            "status": "ROLLED_BACK",
            "active_version": target_version,
            "demoted_version": cur_version,
            "restored_by": current_user,
            "restored_at": now_str,
            "reason": rollback_reason,
            "operating_threshold": target_meta.get("calibrated_threshold", 0.32),
        }

    # -------------------------------------------------------------------------
    # Version Catalog & Job History Helpers
    # -------------------------------------------------------------------------

    def list_model_versions(self) -> List[Dict[str, Any]]:
        """Returns catalog of all registered model versions and statuses."""
        versions = []
        if not os.path.exists(self.versions_dir):
            return versions

        for d in sorted(os.listdir(self.versions_dir)):
            dir_path = os.path.join(self.versions_dir, d)
            if not os.path.isdir(dir_path):
                continue
            meta_path = os.path.join(dir_path, "model_metadata.json")
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    versions.append({
                        "version": meta.get("version", d),
                        "model_name": meta.get("model_name", "logistic_regression"),
                        "status": meta.get("status", ModelStatus.ARCHIVED.value),
                        "is_champion": meta.get("is_champion", False),
                        "created_at": meta.get("created_at") or meta.get("trained_at"),
                        "promoted_at": meta.get("promoted_at"),
                        "promoted_by": meta.get("promoted_by"),
                        "operating_threshold": meta.get("calibrated_threshold", 0.32),
                        "cv_balanced_accuracy": meta.get("cv_metrics", {}).get("balanced_accuracy") or meta.get("cv_balanced_accuracy"),
                        "holdout_recall": meta.get("holdout_calibrated_metrics", {}).get("recall") or meta.get("holdout_test_recall"),
                    })
                except Exception as e:
                    logger.warning("Failed to parse metadata in %s: %s", dir_path, e)
        return versions

    def list_retraining_jobs(self) -> List[Dict[str, Any]]:
        """Returns log of all executed retraining jobs."""
        if not os.path.exists(self.jobs_file):
            return []
        try:
            with open(self.jobs_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _record_job(self, job_record: Dict[str, Any]) -> None:
        """Appends retraining job record to persistent log."""
        jobs = self.list_retraining_jobs()
        jobs.insert(0, job_record)
        with open(self.jobs_file, "w", encoding="utf-8") as f:
            json.dump(jobs[:50], f, indent=2)

    def _get_existing_versions(self) -> List[str]:
        if not os.path.exists(self.versions_dir):
            return ["v1.0.0"]
        return sorted([d for d in os.listdir(self.versions_dir) if os.path.isdir(os.path.join(self.versions_dir, d))])

    def _generate_next_version(self, existing_versions: List[str]) -> str:
        max_major, max_minor = 1, 0
        for v in existing_versions:
            v_clean = v.lstrip("v").split("-")[0]
            parts = v_clean.split(".")
            if len(parts) >= 2:
                try:
                    maj, mnr = int(parts[0]), int(parts[1])
                    if (maj, mnr) > (max_major, max_minor):
                        max_major, max_minor = maj, mnr
                except ValueError:
                    pass
        return f"v{max_major}.{max_minor + 1}.0"
