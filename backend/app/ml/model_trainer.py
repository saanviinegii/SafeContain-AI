"""End-to-End Model Training, Optimization & Evaluation Engine for SafeContain AI.

Orchestrates holdout data splitting, multi-candidate hyperparameter search,
scientifically valid cross-validation comparison, winning model selection,
final holdout evaluation, artifact persistence, and metric plot generation.
"""

import os
import json
import hashlib
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
    roc_auc_score,
    average_precision_score,
    roc_curve,
    precision_recall_curve,
)
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.pipeline import Pipeline

# Configure matplotlib headless environment
os.environ["MPLCONFIGDIR"] = tempfile.gettempdir()
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from backend.app.ml.feature_engineering import FeatureEngineer
from backend.app.ml.hyperparameter_search import HyperparameterOptimizer
from backend.app.ml.task_definition import TASK_NODE_RISK_CLASSIFICATION


DEFAULT_ARTIFACTS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "artifacts")
)


class ModelTrainer:
    """Manages full ML model training, hyperparameter optimization, and evaluation."""

    def __init__(
        self,
        artifacts_dir: Optional[str] = None,
        feature_engineer: Optional[FeatureEngineer] = None,
        random_state: int = 42,
    ):
        self.artifacts_dir = os.path.abspath(artifacts_dir or DEFAULT_ARTIFACTS_DIR)
        self.models_dir = os.path.join(self.artifacts_dir, "models")
        self.metrics_dir = os.path.join(self.artifacts_dir, "metrics")
        self.plots_dir = os.path.join(self.artifacts_dir, "plots")
        os.makedirs(self.models_dir, exist_ok=True)
        os.makedirs(self.metrics_dir, exist_ok=True)
        os.makedirs(self.plots_dir, exist_ok=True)

        self.fe = feature_engineer or FeatureEngineer()
        self.random_state = random_state
        self.optimizer = HyperparameterOptimizer(random_state=random_state)

    def run_pipeline(
        self,
        feature_subset: str = "topology_only",
        test_size: float = 0.20,
        cv_folds: int = 5,
    ) -> Dict[str, Any]:
        """Executes the complete Phase 7.2A ML training and comparative evaluation pipeline."""
        start_time = datetime.now(timezone.utc)

        # 1. Feature Extraction & Data Splitting
        X, y, num_cols, cat_cols = self.fe.get_features_and_target(feature_subset)
        features_list = list(X.columns)
        dataset_fingerprint = hashlib.sha256(pd.util.hash_pandas_object(X, index=True).values).hexdigest()[:16]

        # Holdout split: 20% holdout test set is completely withheld from tuning
        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=test_size,
            random_state=self.random_state,
            stratify=y,
        )

        # 2. Hyperparameter Optimization on X_train
        tuned_candidates = self.optimizer.optimize_all_candidates(
            X_train=X_train,
            y_train=y_train,
            numeric_cols=num_cols,
            categorical_cols=cat_cols,
            cv_folds=cv_folds,
            scoring="balanced_accuracy",
        )

        # 3. Multi-Metric Cross-Validation Comparison on X_train
        cv_comparison = self._evaluate_candidates_cross_val(
            tuned_candidates=tuned_candidates,
            X_train=X_train,
            y_train=y_train,
            cv_folds=cv_folds,
        )

        # 4. Model Selection Logic
        best_candidate_name, selection_reason = self._select_best_model(cv_comparison)
        best_tuned_info = tuned_candidates[best_candidate_name]
        best_pipeline: Pipeline = best_tuned_info["best_estimator"]

        # 5. Fit Winning Pipeline on Complete Training Set (X_train)
        best_pipeline.fit(X_train, y_train)

        # 6. Final Holdout Evaluation on Untouched X_test
        holdout_results = self._evaluate_on_holdout(
            pipeline=best_pipeline,
            X_test=X_test,
            y_test=y_test,
        )

        # 7. Generate Evaluation Plots
        plot_paths = self._generate_plots(
            pipeline=best_pipeline,
            X_test=X_test,
            y_test=y_test,
            holdout_results=holdout_results,
            model_name=best_candidate_name,
        )

        # 8. Persist Model & Metrics Artifacts
        artifacts_saved = self._save_artifacts(
            best_pipeline=best_pipeline,
            best_candidate_name=best_candidate_name,
            best_params=best_tuned_info["best_params"],
            features_list=features_list,
            feature_subset=feature_subset,
            num_cols=num_cols,
            cat_cols=cat_cols,
            dataset_fingerprint=dataset_fingerprint,
            cv_comparison=cv_comparison,
            holdout_results=holdout_results,
            selection_reason=selection_reason,
            start_time=start_time,
            cv_folds=cv_folds,
            test_size=test_size,
        )

        return {
            "status": "SUCCESS",
            "task": TASK_NODE_RISK_CLASSIFICATION.task_id,
            "feature_subset": feature_subset,
            "dataset_fingerprint": dataset_fingerprint,
            "total_samples": len(X),
            "train_samples": len(X_train),
            "holdout_test_samples": len(X_test),
            "train_class_distribution": {int(k): int(v) for k, v in y_train.value_counts().items()},
            "test_class_distribution": {int(k): int(v) for k, v in y_test.value_counts().items()},
            "best_model": best_candidate_name,
            "best_hyperparameters": best_tuned_info["best_params"],
            "selection_reason": selection_reason,
            "cv_comparison": cv_comparison,
            "holdout_evaluation": holdout_results,
            "plot_paths": plot_paths,
            "artifacts_saved": artifacts_saved,
        }

    def _evaluate_candidates_cross_val(
        self,
        tuned_candidates: Dict[str, Dict[str, Any]],
        X_train: pd.DataFrame,
        y_train: pd.Series,
        cv_folds: int,
    ) -> Dict[str, Dict[str, Any]]:
        """Computes multi-metric cross-validation across all optimized candidate pipelines."""
        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=self.random_state)
        scoring = [
            "accuracy",
            "balanced_accuracy",
            "precision",
            "recall",
            "f1",
            "roc_auc",
            "average_precision",
        ]

        comparison = {}
        for model_name, candidate_info in tuned_candidates.items():
            pipe = candidate_info["best_estimator"]
            cv_raw = cross_validate(
                pipe,
                X_train,
                y_train,
                cv=cv,
                scoring=scoring,
                return_train_score=False,
            )

            metrics_summary = {}
            for metric in scoring:
                scores_arr = cv_raw[f"test_{metric}"]
                metrics_summary[f"{metric}_mean"] = round(float(np.mean(scores_arr)), 4)
                metrics_summary[f"{metric}_std"] = round(float(np.std(scores_arr)), 4)

            comparison[model_name] = {
                "best_params": candidate_info["best_params"],
                "metrics": metrics_summary,
            }

        return comparison

    def _select_best_model(
        self,
        cv_comparison: Dict[str, Dict[str, Any]],
    ) -> Tuple[str, str]:
        """Selects winning model primarily by CV Balanced Accuracy, then Recall, F1, and simplicity."""
        candidates = list(cv_comparison.keys())

        # Sort primarily by balanced_accuracy_mean, secondarily by recall_mean, tertiary by f1_mean
        sorted_candidates = sorted(
            candidates,
            key=lambda name: (
                cv_comparison[name]["metrics"]["balanced_accuracy_mean"],
                cv_comparison[name]["metrics"]["recall_mean"],
                cv_comparison[name]["metrics"]["f1_mean"],
                cv_comparison[name]["metrics"]["roc_auc_mean"],
            ),
            reverse=True,
        )

        winner = sorted_candidates[0]
        winner_metrics = cv_comparison[winner]["metrics"]

        reason = (
            f"{winner.replace('_', ' ').title()} selected as best model based on superior "
            f"Cross-Validation Balanced Accuracy ({winner_metrics['balanced_accuracy_mean']:.4f} "
            f"+/- {winner_metrics['balanced_accuracy_std']:.4f}), "
            f"Recall on threat class ({winner_metrics['recall_mean']:.4f}), "
            f"ROC-AUC ({winner_metrics['roc_auc_mean']:.4f}), and structural stability."
        )

        return winner, reason

    def _evaluate_on_holdout(
        self,
        pipeline: Pipeline,
        X_test: pd.DataFrame,
        y_test: pd.Series,
    ) -> Dict[str, Any]:
        """Evaluates winning pipeline strictly on the untouched holdout test set."""
        y_true = y_test.values
        y_pred = pipeline.predict(X_test)
        y_prob = pipeline.predict_proba(X_test)[:, 1] if hasattr(pipeline, "predict_proba") else None

        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

        roc_auc = round(float(roc_auc_score(y_true, y_prob)), 4) if y_prob is not None else None
        pr_auc = round(float(average_precision_score(y_true, y_prob)), 4) if y_prob is not None else None

        return {
            "test_samples": len(y_test),
            "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
            "balanced_accuracy": round(float(balanced_accuracy_score(y_true, y_pred)), 4),
            "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
            "f1_score": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
            "roc_auc": roc_auc,
            "average_precision_pr_auc": pr_auc,
            "confusion_matrix": {
                "true_negatives": tn,
                "false_positives": fp,
                "false_negatives": fn,
                "true_positives": tp,
            },
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
        }

    def _generate_plots(
        self,
        pipeline: Pipeline,
        X_test: pd.DataFrame,
        y_test: pd.Series,
        holdout_results: Dict[str, Any],
        model_name: str,
    ) -> Dict[str, str]:
        """Generates actual, scientifically grounded evaluation curves and charts."""
        y_true = y_test.values
        y_prob = pipeline.predict_proba(X_test)[:, 1] if hasattr(pipeline, "predict_proba") else None

        plot_files = {}

        # 1. Confusion Matrix Plot
        fig_cm, ax_cm = plt.subplots(figsize=(6, 5))
        cm_data = np.array([
            [holdout_results["confusion_matrix"]["true_negatives"], holdout_results["confusion_matrix"]["false_positives"]],
            [holdout_results["confusion_matrix"]["false_negatives"], holdout_results["confusion_matrix"]["true_positives"]],
        ])
        cax = ax_cm.matshow(cm_data, cmap=plt.cm.Blues, alpha=0.85)
        fig_cm.colorbar(cax)
        for i in range(2):
            for j in range(2):
                ax_cm.text(j, i, str(cm_data[i, j]), ha="center", va="center", fontsize=14, fontweight="bold")
        ax_cm.set_xticks([0, 1])
        ax_cm.set_yticks([0, 1])
        ax_cm.set_xticklabels(["Healthy (0)", "At Risk (1)"])
        ax_cm.set_yticklabels(["Healthy (0)", "At Risk (1)"])
        ax_cm.set_xlabel("Predicted Label", fontweight="bold")
        ax_cm.set_ylabel("True Ground-Truth", fontweight="bold")
        ax_cm.set_title(f"Confusion Matrix — {model_name.replace('_', ' ').title()}", fontweight="bold", pad=15)
        cm_path = os.path.join(self.plots_dir, "confusion_matrix.png")
        fig_cm.tight_layout()
        fig_cm.savefig(cm_path, dpi=150)
        plt.close(fig_cm)
        plot_files["confusion_matrix"] = cm_path

        # 2. ROC Curve Plot
        if y_prob is not None:
            fpr_arr, tpr_arr, _ = roc_curve(y_true, y_prob)
            fig_roc, ax_roc = plt.subplots(figsize=(6, 5))
            ax_roc.plot(fpr_arr, tpr_arr, color="#1f77b4", lw=2.5, label=f"ROC Curve (AUC = {holdout_results['roc_auc']:.3f})")
            ax_roc.plot([0, 1], [0, 1], color="grey", lw=1.5, linestyle="--", label="Random Chance Baseline")
            ax_roc.set_xlim([0.0, 1.0])
            ax_roc.set_ylim([0.0, 1.05])
            ax_roc.set_xlabel("False Positive Rate (FPR)", fontweight="bold")
            ax_roc.set_ylabel("True Positive Rate (Recall)", fontweight="bold")
            ax_roc.set_title("Receiver Operating Characteristic (ROC)", fontweight="bold")
            ax_roc.legend(loc="lower right")
            ax_roc.grid(True, linestyle=":", alpha=0.6)
            roc_path = os.path.join(self.plots_dir, "roc_curve.png")
            fig_roc.tight_layout()
            fig_roc.savefig(roc_path, dpi=150)
            plt.close(fig_roc)
            plot_files["roc_curve"] = roc_path

            # 3. Precision-Recall Curve Plot
            prec_arr, rec_arr, _ = precision_recall_curve(y_true, y_prob)
            fig_pr, ax_pr = plt.subplots(figsize=(6, 5))
            ax_pr.plot(rec_arr, prec_arr, color="#2ca02c", lw=2.5, label=f"PR Curve (AP = {holdout_results['average_precision_pr_auc']:.3f})")
            no_skill = np.sum(y_true) / len(y_true)
            ax_pr.plot([0, 1], [no_skill, no_skill], color="grey", lw=1.5, linestyle="--", label=f"No-Skill Baseline ({no_skill:.2f})")
            ax_pr.set_xlim([0.0, 1.0])
            ax_pr.set_ylim([0.0, 1.05])
            ax_pr.set_xlabel("Recall (Threat Class)", fontweight="bold")
            ax_pr.set_ylabel("Precision", fontweight="bold")
            ax_pr.set_title("Precision-Recall Curve", fontweight="bold")
            ax_pr.legend(loc="upper right")
            ax_pr.grid(True, linestyle=":", alpha=0.6)
            pr_path = os.path.join(self.plots_dir, "precision_recall_curve.png")
            fig_pr.tight_layout()
            fig_pr.savefig(pr_path, dpi=150)
            plt.close(fig_pr)
            plot_files["precision_recall_curve"] = pr_path

        return plot_files

    def _save_artifacts(
        self,
        best_pipeline: Pipeline,
        best_candidate_name: str,
        best_params: Dict[str, Any],
        features_list: List[str],
        feature_subset: str,
        num_cols: List[str],
        cat_cols: List[str],
        dataset_fingerprint: str,
        cv_comparison: Dict[str, Dict[str, Any]],
        holdout_results: Dict[str, Any],
        selection_reason: str,
        start_time: datetime,
        cv_folds: int,
        test_size: float,
    ) -> Dict[str, str]:
        """Saves model binaries, comparison tables, configuration, and evaluation summaries."""
        # 1. Save Serialized Model
        model_path = os.path.join(self.models_dir, "best_model.joblib")
        joblib.dump(best_pipeline, model_path)

        # 2. Save Model Comparison CSV
        comparison_rows = []
        for model_name, data in cv_comparison.items():
            metrics = data["metrics"]
            comparison_rows.append({
                "model_name": model_name,
                "cv_balanced_accuracy": metrics.get("balanced_accuracy_mean"),
                "cv_balanced_accuracy_std": metrics.get("balanced_accuracy_std"),
                "cv_recall": metrics.get("recall_mean"),
                "cv_precision": metrics.get("precision_mean"),
                "cv_f1": metrics.get("f1_mean"),
                "cv_roc_auc": metrics.get("roc_auc_mean"),
                "cv_pr_auc": metrics.get("average_precision_mean"),
                "cv_accuracy": metrics.get("accuracy_mean"),
            })
        comparison_df = pd.DataFrame(comparison_rows)
        csv_path = os.path.join(self.metrics_dir, "model_comparison.csv")
        comparison_df.to_csv(csv_path, index=False)

        # 3. Save Model Metadata JSON
        metadata = {
            "model_name": best_candidate_name,
            "version": "1.0.0",
            "task_id": TASK_NODE_RISK_CLASSIFICATION.task_id,
            "feature_subset": feature_subset,
            "dataset_fingerprint": dataset_fingerprint,
            "features": features_list,
            "numeric_features": num_cols,
            "categorical_features": cat_cols,
            "best_hyperparameters": best_params,
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "training_duration_seconds": round((datetime.now(timezone.utc) - start_time).total_seconds(), 2),
            "random_seed": self.random_state,
            "selection_reason": selection_reason,
            "cv_balanced_accuracy": cv_comparison[best_candidate_name]["metrics"]["balanced_accuracy_mean"],
            "holdout_test_balanced_accuracy": holdout_results["balanced_accuracy"],
            "holdout_test_recall": holdout_results["recall"],
            "holdout_test_roc_auc": holdout_results["roc_auc"],
        }
        metadata_path = os.path.join(self.models_dir, "model_metadata.json")
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        # 4. Save Training Configuration JSON
        config_path = os.path.join(self.metrics_dir, "training_config.json")
        config_data = {
            "task_id": TASK_NODE_RISK_CLASSIFICATION.task_id,
            "feature_subset": feature_subset,
            "test_size": test_size,
            "cv_folds": cv_folds,
            "random_state": self.random_state,
            "optimization_metric": "balanced_accuracy",
            "candidate_models": list(cv_comparison.keys()),
        }
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)

        # 5. Save Evaluation Summary JSON
        summary_path = os.path.join(self.metrics_dir, "evaluation_summary.json")
        summary_data = {
            "selected_model": best_candidate_name,
            "cv_comparison": cv_comparison,
            "holdout_test_results": holdout_results,
            "selection_justification": selection_reason,
        }
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=2)

        return {
            "best_model_joblib": model_path,
            "model_metadata_json": metadata_path,
            "model_comparison_csv": csv_path,
            "training_config_json": config_path,
            "evaluation_summary_json": summary_path,
        }
