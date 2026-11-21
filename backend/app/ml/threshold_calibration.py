"""Decision Threshold Calibration & Cost-Sensitive Threat Detection Engine for SafeContain AI.

Evaluates candidate decision thresholds theta in [0.15, 0.40] using out-of-fold cross-validation
probabilities to maximize threat detection recall (Recall >= 0.80) while minimizing false-positive
containment disruption costs, completely free from holdout test set contamination.
"""

import os
import json
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    precision_recall_curve,
    average_precision_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_predict, train_test_split
from sklearn.pipeline import Pipeline

# Headless matplotlib configuration
os.environ["MPLCONFIGDIR"] = tempfile.gettempdir()
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from backend.app.ml.feature_engineering import FeatureEngineer
from backend.app.ml.model_trainer import DEFAULT_ARTIFACTS_DIR


DEFAULT_CALIBRATION_DIR = os.path.join(DEFAULT_ARTIFACTS_DIR, "calibration")


class ThresholdCalibrator:
    """Manages threshold generation, out-of-fold evaluation, cost optimization, and test reporting."""

    def __init__(
        self,
        artifacts_dir: Optional[str] = None,
        feature_engineer: Optional[FeatureEngineer] = None,
        random_state: int = 42,
    ):
        self.artifacts_dir = os.path.abspath(artifacts_dir or DEFAULT_ARTIFACTS_DIR)
        self.calibration_dir = os.path.join(self.artifacts_dir, "calibration")
        self.models_dir = os.path.join(self.artifacts_dir, "models")
        os.makedirs(self.calibration_dir, exist_ok=True)

        self.fe = feature_engineer or FeatureEngineer()
        self.random_state = random_state

    @staticmethod
    def generate_candidate_thresholds(
        start: float = 0.15,
        stop: float = 0.40,
        step: float = 0.01,
    ) -> np.ndarray:
        """Generates candidate decision thresholds with controlled floating-point resolution."""
        return np.round(np.arange(start, stop + (step / 2.0), step), 4)

    @staticmethod
    def evaluate_threshold_metrics(
        y_true: np.ndarray,
        y_prob: np.ndarray,
        threshold: float,
        cost_fn: float = 10.0,
        cost_fp: float = 1.0,
    ) -> Dict[str, Any]:
        """Calculates confusion matrix, accuracy, precision, recall, F1, Youden's J, and total cost."""
        y_pred = (y_prob >= threshold).astype(int)

        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

        rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        spec = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0
        f1 = float(2.0 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
        bal_acc = float((rec + spec) / 2.0)
        acc = float((tp + tn) / len(y_true)) if len(y_true) > 0 else 0.0
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
        youden_j = float(rec + spec - 1.0)
        total_cost = float((fn * cost_fn) + (fp * cost_fp))

        return {
            "threshold": round(float(threshold), 4),
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "recall": round(rec, 4),
            "precision": round(prec, 4),
            "specificity": round(spec, 4),
            "f1_score": round(f1, 4),
            "balanced_accuracy": round(bal_acc, 4),
            "accuracy": round(acc, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "youden_j": round(youden_j, 4),
            "total_cost": round(total_cost, 2),
        }

    def evaluate_all_thresholds(
        self,
        y_true: np.ndarray,
        y_prob: np.ndarray,
        thresholds: Optional[np.ndarray] = None,
        cost_fn: float = 10.0,
        cost_fp: float = 1.0,
    ) -> pd.DataFrame:
        """Evaluates every candidate threshold across the search grid."""
        if thresholds is None:
            thresholds = self.generate_candidate_thresholds(0.15, 0.40, 0.01)

        records = [
            self.evaluate_threshold_metrics(y_true, y_prob, th, cost_fn=cost_fn, cost_fp=cost_fp)
            for th in thresholds
        ]
        return pd.DataFrame(records)

    def select_optimal_threshold(
        self,
        df_metrics: pd.DataFrame,
        recall_target: float = 0.80,
        cost_fn: float = 10.0,
        cost_fp: float = 1.0,
    ) -> Dict[str, Any]:
        """Implements the multi-criteria threshold selection policy.
        
        Selection Hierarchy:
        1. Primary Constraint: Validation Recall >= recall_target (e.g. 0.80).
        2. Cost Optimization: Minimize total cost among compliant thresholds.
        3. Tie-breaker: Maximize F1-score and Balanced Accuracy.
        4. Fallback: If recall_target cannot be met, select threshold maximizing recall within range.
        """
        eligible = df_metrics[df_metrics["recall"] >= recall_target].copy()

        if len(eligible) > 0:
            target_achieved = True
            # Sort by total_cost ascending, then f1_score descending, then balanced_accuracy descending
            sorted_candidates = eligible.sort_values(
                by=["total_cost", "f1_score", "balanced_accuracy"],
                ascending=[True, False, False],
            )
            selected_row = sorted_candidates.iloc[0].to_dict()
            strategy_name = "recall_constrained_cost_optimal"
            reason = (
                f"Selected threshold theta={selected_row['threshold']:.2f} satisfies the primary security "
                f"constraint (Validation Recall {selected_row['recall']:.4f} >= {recall_target:.2f}) while minimizing "
                f"operational containment disruption cost (Total Cost = {selected_row['total_cost']:.1f} "
                f"under {cost_fn:.0f}:{cost_fp:.0f} FN:FP penalty ratio, F1 = {selected_row['f1_score']:.4f})."
            )
        else:
            target_achieved = False
            # Find threshold achieving highest available recall in range
            sorted_candidates = df_metrics.sort_values(
                by=["recall", "balanced_accuracy", "f1_score"],
                ascending=[False, False, False],
            )
            selected_row = sorted_candidates.iloc[0].to_dict()
            strategy_name = "max_attainable_recall_fallback"
            reason = (
                f"No candidate threshold within [0.15, 0.40] met the primary recall target of {recall_target:.2f}. "
                f"Fallback selected threshold theta={selected_row['threshold']:.2f} yielding maximum available "
                f"validation recall ({selected_row['recall']:.4f})."
            )

        # Calculate Youden-optimal threshold for comparative analysis
        youden_row = df_metrics.sort_values(by="youden_j", ascending=False).iloc[0].to_dict()

        return {
            "selected_threshold": selected_row["threshold"],
            "strategy": strategy_name,
            "target_achieved": target_achieved,
            "recall_target": recall_target,
            "cost_assumptions": {
                "cost_false_negative": cost_fn,
                "cost_false_positive": cost_fp,
                "cost_ratio": f"{cost_fn / cost_fp:.1f}:1" if cost_fp > 0 else "N/A",
            },
            "validation_metrics": selected_row,
            "youden_optimal_threshold": {
                "threshold": youden_row["threshold"],
                "youden_j": youden_row["youden_j"],
                "recall": youden_row["recall"],
                "precision": youden_row["precision"],
                "balanced_accuracy": youden_row["balanced_accuracy"],
            },
            "selection_reason": reason,
        }

    def run_calibration(
        self,
        feature_subset: str = "topology_only",
        test_size: float = 0.20,
        cv_folds: int = 5,
        recall_target: float = 0.80,
        cost_fn: float = 10.0,
        cost_fp: float = 1.0,
        start_th: float = 0.15,
        stop_th: float = 0.40,
        step_th: float = 0.01,
    ) -> Dict[str, Any]:
        """Executes full decision threshold calibration pipeline."""
        start_time = datetime.now(timezone.utc)

        # 1. Load Trained Pipeline from Phase 7.2A
        model_path = os.path.join(self.models_dir, "best_model.joblib")
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Trained model artifact not found at {model_path}. Run Phase 7.2A training first."
            )
        pipeline: Pipeline = joblib.load(model_path)

        # 2. Extract Features & Recreate Training/Holdout Split (Zero Leakage)
        X, y, num_cols, cat_cols = self.fe.get_features_and_target(feature_subset)
        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=test_size,
            random_state=self.random_state,
            stratify=y,
        )

        # 3. Generate Out-of-Fold Validation Probabilities on X_train
        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=self.random_state)
        oof_probs = cross_val_predict(
            pipeline,
            X_train,
            y_train,
            cv=cv,
            method="predict_proba",
        )[:, 1]
        y_val = y_train.values

        # 4. Evaluate Candidate Thresholds on Validation Data
        thresholds = self.generate_candidate_thresholds(start_th, stop_th, step_th)
        df_metrics = self.evaluate_all_thresholds(
            y_true=y_val,
            y_prob=oof_probs,
            thresholds=thresholds,
            cost_fn=cost_fn,
            cost_fp=cost_fp,
        )

        # 5. Apply Threshold Selection Policy
        selection_result = self.select_optimal_threshold(
            df_metrics=df_metrics,
            recall_target=recall_target,
            cost_fn=cost_fn,
            cost_fp=cost_fp,
        )
        selected_th = float(selection_result["selected_threshold"])

        # 6. Freeze Threshold and Evaluate on Final Holdout Test Set (X_test)
        y_prob_test = pipeline.predict_proba(X_test)[:, 1]
        y_test_arr = y_test.values

        default_th_eval = self.evaluate_threshold_metrics(
            y_true=y_test_arr,
            y_prob=y_prob_test,
            threshold=0.50,
            cost_fn=cost_fn,
            cost_fp=cost_fp,
        )

        calibrated_th_eval = self.evaluate_threshold_metrics(
            y_true=y_test_arr,
            y_prob=y_prob_test,
            threshold=selected_th,
            cost_fn=cost_fn,
            cost_fp=cost_fp,
        )

        holdout_comparison = {
            "default_threshold_0_50": default_th_eval,
            "calibrated_threshold": calibrated_th_eval,
            "recall_gain": round(calibrated_th_eval["recall"] - default_th_eval["recall"], 4),
            "fnr_reduction": round(default_th_eval["false_negative_rate"] - calibrated_th_eval["false_negative_rate"], 4),
            "threats_missed_default": default_th_eval["false_negatives"],
            "threats_missed_calibrated": calibrated_th_eval["false_negatives"],
            "false_alerts_default": default_th_eval["false_positives"],
            "false_alerts_calibrated": calibrated_th_eval["false_positives"],
        }

        # 7. Generate Calibration Plots
        plot_paths = self._generate_calibration_plots(
            df_metrics=df_metrics,
            y_val=y_val,
            oof_probs=oof_probs,
            y_test=y_test_arr,
            y_prob_test=y_prob_test,
            selected_th=selected_th,
            recall_target=recall_target,
            default_eval=default_th_eval,
            calibrated_eval=calibrated_th_eval,
        )

        # 8. Persist Calibration Artifacts
        artifacts_saved = self._save_calibration_artifacts(
            df_metrics=df_metrics,
            selection_result=selection_result,
            holdout_comparison=holdout_comparison,
            start_time=start_time,
            feature_subset=feature_subset,
        )

        return {
            "status": "SUCCESS",
            "feature_subset": feature_subset,
            "validation_samples": len(y_train),
            "holdout_test_samples": len(y_test),
            "selected_threshold": selected_th,
            "target_achieved": selection_result["target_achieved"],
            "selection_strategy": selection_result["strategy"],
            "selection_reason": selection_result["selection_reason"],
            "validation_metrics": selection_result["validation_metrics"],
            "holdout_comparison": holdout_comparison,
            "artifacts_saved": artifacts_saved,
            "plot_paths": plot_paths,
        }

    def _generate_calibration_plots(
        self,
        df_metrics: pd.DataFrame,
        y_val: np.ndarray,
        oof_probs: np.ndarray,
        y_test: np.ndarray,
        y_prob_test: np.ndarray,
        selected_th: float,
        recall_target: float,
        default_eval: Dict[str, Any],
        calibrated_eval: Dict[str, Any],
    ) -> Dict[str, str]:
        """Generates actual, scientifically grounded visual figures for threshold calibration."""
        plot_files = {}

        # 1. Precision-Recall Curve Plot (Validation OOF)
        prec_arr, rec_arr, _ = precision_recall_curve(y_val, oof_probs)
        ap = average_precision_score(y_val, oof_probs)

        fig_pr, ax_pr = plt.subplots(figsize=(7, 5))
        ax_pr.plot(rec_arr, prec_arr, color="#1f77b4", lw=2.5, label=f"Validation PR Curve (AP = {ap:.3f})")
        ax_pr.axvline(x=recall_target, color="red", linestyle="--", lw=1.8, label=f"Target Recall ({recall_target:.2f})")

        # Mark calibrated threshold point on PR curve
        cal_point = df_metrics[df_metrics["threshold"] == selected_th]
        if len(cal_point) > 0:
            c_rec = cal_point.iloc[0]["recall"]
            c_prec = cal_point.iloc[0]["precision"]
            ax_pr.scatter([c_rec], [c_prec], color="#2ca02c", s=120, zorder=5, label=f"Selected theta={selected_th:.2f}")

        ax_pr.set_xlim([0.0, 1.05])
        ax_pr.set_ylim([0.0, 1.05])
        ax_pr.set_xlabel("Recall (Threat Detection Coverage)", fontweight="bold")
        ax_pr.set_ylabel("Precision (Containment Accuracy)", fontweight="bold")
        ax_pr.set_title("Precision-Recall Calibration Curve (Out-of-Fold Validation)", fontweight="bold")
        ax_pr.legend(loc="upper right")
        ax_pr.grid(True, linestyle=":", alpha=0.6)
        pr_path = os.path.join(self.calibration_dir, "precision_recall_curve.png")
        fig_pr.tight_layout()
        fig_pr.savefig(pr_path, dpi=150)
        plt.close(fig_pr)
        plot_files["precision_recall_curve"] = pr_path

        # 2. Multi-Metric Threshold Comparison Plot
        fig_th, ax1 = plt.subplots(figsize=(8, 5))
        ax1.plot(df_metrics["threshold"], df_metrics["recall"], label="Recall", color="#d62728", lw=2)
        ax1.plot(df_metrics["threshold"], df_metrics["precision"], label="Precision", color="#1f77b4", lw=2)
        ax1.plot(df_metrics["threshold"], df_metrics["f1_score"], label="F1-Score", color="#2ca02c", lw=2)
        ax1.plot(df_metrics["threshold"], df_metrics["balanced_accuracy"], label="Balanced Accuracy", color="#9467bd", linestyle="--", lw=1.8)
        ax1.axvline(x=selected_th, color="black", linestyle=":", lw=2, label=f"Selected theta={selected_th:.2f}")
        ax1.set_xlabel("Decision Threshold (theta)", fontweight="bold")
        ax1.set_ylabel("Metric Score", fontweight="bold")
        ax1.set_ylim([0.0, 1.05])

        ax2 = ax1.twinx()
        ax2.plot(df_metrics["threshold"], df_metrics["total_cost"], color="#ff7f0e", linestyle="-.", lw=1.8, label="Total Disruption Cost")
        ax2.set_ylabel("Cost Utility (FN*10 + FP*1)", color="#ff7f0e", fontweight="bold")

        lines1, labels1 = ax1.get_legend_handles_labels()
        lines2, labels2 = ax2.get_legend_handles_labels()
        ax1.legend(lines1 + lines2, labels1 + labels2, loc="center left", bbox_to_anchor=(0.02, 0.5))
        ax1.set_title("Decision Threshold Calibration Performance & Cost Landscape", fontweight="bold")
        ax1.grid(True, linestyle=":", alpha=0.5)
        comp_path = os.path.join(self.calibration_dir, "threshold_comparison.png")
        fig_th.tight_layout()
        fig_th.savefig(comp_path, dpi=150)
        plt.close(fig_th)
        plot_files["threshold_comparison"] = comp_path

        # 3. Confusion Matrix at Default Threshold (0.50) on Holdout Test Set
        fig_cmd, ax_cmd = plt.subplots(figsize=(5, 4))
        cm_default = np.array([
            [default_eval["true_negatives"], default_eval["false_positives"]],
            [default_eval["false_negatives"], default_eval["true_positives"]],
        ])
        ax_cmd.matshow(cm_default, cmap=plt.cm.Reds, alpha=0.7)
        for i in range(2):
            for j in range(2):
                ax_cmd.text(j, i, str(cm_default[i, j]), ha="center", va="center", fontsize=14, fontweight="bold")
        ax_cmd.set_xticks([0, 1])
        ax_cmd.set_yticks([0, 1])
        ax_cmd.set_xticklabels(["Healthy", "At Risk"])
        ax_cmd.set_yticklabels(["Healthy", "At Risk"])
        ax_cmd.set_title("Confusion Matrix — Default (theta=0.50)", fontweight="bold", pad=12)
        ax_cmd.set_xlabel("Predicted", fontweight="bold")
        ax_cmd.set_ylabel("Actual Ground Truth", fontweight="bold")
        cmd_path = os.path.join(self.calibration_dir, "confusion_matrix_default.png")
        fig_cmd.tight_layout()
        fig_cmd.savefig(cmd_path, dpi=150)
        plt.close(fig_cmd)
        plot_files["confusion_matrix_default"] = cmd_path

        # 4. Confusion Matrix at Calibrated Threshold on Holdout Test Set
        fig_cmc, ax_cmc = plt.subplots(figsize=(5, 4))
        cm_cal = np.array([
            [calibrated_eval["true_negatives"], calibrated_eval["false_positives"]],
            [calibrated_eval["false_negatives"], calibrated_eval["true_positives"]],
        ])
        ax_cmc.matshow(cm_cal, cmap=plt.cm.Greens, alpha=0.7)
        for i in range(2):
            for j in range(2):
                ax_cmc.text(j, i, str(cm_cal[i, j]), ha="center", va="center", fontsize=14, fontweight="bold")
        ax_cmc.set_xticks([0, 1])
        ax_cmc.set_yticks([0, 1])
        ax_cmc.set_xticklabels(["Healthy", "At Risk"])
        ax_cmc.set_yticklabels(["Healthy", "At Risk"])
        ax_cmc.set_title(f"Confusion Matrix — Calibrated (theta={selected_th:.2f})", fontweight="bold", pad=12)
        ax_cmc.set_xlabel("Predicted", fontweight="bold")
        ax_cmc.set_ylabel("Actual Ground Truth", fontweight="bold")
        cmc_path = os.path.join(self.calibration_dir, "confusion_matrix_calibrated.png")
        fig_cmc.tight_layout()
        fig_cmc.savefig(cmc_path, dpi=150)
        plt.close(fig_cmc)
        plot_files["confusion_matrix_calibrated"] = cmc_path

        return plot_files

    def _save_calibration_artifacts(
        self,
        df_metrics: pd.DataFrame,
        selection_result: Dict[str, Any],
        holdout_comparison: Dict[str, Any],
        start_time: datetime,
        feature_subset: str,
    ) -> Dict[str, str]:
        """Saves threshold comparison CSV and calibration metadata JSON to disk."""
        # 1. Save Threshold Metrics CSV
        csv_path = os.path.join(self.calibration_dir, "threshold_metrics.csv")
        df_metrics.to_csv(csv_path, index=False)

        # 2. Save Calibration Metadata JSON
        metadata = {
            "calibration_timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round((datetime.now(timezone.utc) - start_time).total_seconds(), 2),
            "feature_subset": feature_subset,
            "operating_threshold": selection_result["selected_threshold"],
            "default_threshold": 0.50,
            "selection_strategy": selection_result["strategy"],
            "target_achieved": selection_result["target_achieved"],
            "recall_target": selection_result["recall_target"],
            "cost_assumptions": selection_result["cost_assumptions"],
            "selection_reason": selection_result["selection_reason"],
            "youden_optimal": selection_result["youden_optimal_threshold"],
            "validation_metrics": selection_result["validation_metrics"],
            "holdout_comparison": holdout_comparison,
        }
        metadata_path = os.path.join(self.calibration_dir, "calibration_metadata.json")
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        return {
            "threshold_metrics_csv": csv_path,
            "calibration_metadata_json": metadata_path,
        }
