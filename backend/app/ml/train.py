"""CLI Command Entrypoint for SafeContain AI ML Training Pipeline.

Usage:
    python -m backend.app.ml.train
    python backend/app/ml/train.py --feature-subset topology_only --cv-folds 5 --random-state 42
"""

import argparse
import sys
from typing import List, Optional
from backend.app.ml.model_trainer import ModelTrainer, DEFAULT_ARTIFACTS_DIR


def main(args: Optional[List[str]] = None) -> int:
    """Parses command line arguments and executes the ML training pipeline."""
    parser = argparse.ArgumentParser(
        description="SafeContain AI — Machine Learning Model Training & Comparative Evaluation"
    )
    parser.add_argument(
        "--feature-subset",
        type=str,
        default="topology_only",
        choices=["topology_only", "full"],
        help="Feature subset to train on ('topology_only' for leak-free graph baseline, 'full' with telemetry).",
    )
    parser.add_argument(
        "--cv-folds",
        type=int,
        default=5,
        help="Number of cross-validation folds (default: 5).",
    )
    parser.add_argument(
        "--test-size",
        type=float,
        default=0.20,
        help="Proportion of dataset to reserve as holdout test set (default: 0.20).",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42).",
    )
    parser.add_argument(
        "--artifacts-dir",
        type=str,
        default=DEFAULT_ARTIFACTS_DIR,
        help="Target directory to save model artifacts and plots.",
    )

    parsed = parser.parse_args(args)

    print("=" * 78)
    print("SAFECONTAIN AI — ML MODEL TRAINING & COMPARATIVE EVALUATION (PHASE 7.2A)")
    print("=" * 78)
    print(f"Feature Subset:      {parsed.feature_subset}")
    print(f"CV Folds:            {parsed.cv_folds}")
    print(f"Holdout Test Size:   {parsed.test_size}")
    print(f"Random State:        {parsed.random_state}")
    print(f"Artifacts Directory: {parsed.artifacts_dir}")
    print("-" * 78)

    trainer = ModelTrainer(
        artifacts_dir=parsed.artifacts_dir,
        random_state=parsed.random_state,
    )

    print("\n[STEP 1/5] Extracting features and isolating holdout test split...")
    try:
        results = trainer.run_pipeline(
            feature_subset=parsed.feature_subset,
            test_size=parsed.test_size,
            cv_folds=parsed.cv_folds,
        )
    except Exception as e:
        print(f"\n[ERROR] ML training pipeline failed: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

    print("\n[STEP 2/5] Hyperparameter optimization complete.")
    print("\n[STEP 3/5] Cross-Validation Model Comparison (5-Fold Stratified):")
    print("-" * 88)
    header = f"{'Candidate Model':<25} | {'CV Bal Acc':<12} | {'CV Recall':<12} | {'CV Precision':<12} | {'CV ROC-AUC':<12}"
    print(header)
    print("-" * 88)
    for model_name, data in results["cv_comparison"].items():
        m = data["metrics"]
        row = (
            f"{model_name:<25} | "
            f"{m['balanced_accuracy_mean']:.4f} (+/-{m['balanced_accuracy_std']:.3f}) | "
            f"{m['recall_mean']:.4f}       | "
            f"{m['precision_mean']:.4f}       | "
            f"{m['roc_auc_mean']:.4f}"
        )
        print(row)
    print("-" * 88)

    print(f"\n[STEP 4/5] Model Selection Result:")
    print(f"  Selected Model:   {results['best_model']}")
    print(f"  Best Parameters:  {results['best_hyperparameters']}")
    print(f"  Justification:    {results['selection_reason']}")

    print("\n[STEP 5/5] Final Holdout Test Set Evaluation (24 Samples, Untouched):")
    ht = results["holdout_evaluation"]
    print(f"  Holdout Accuracy:          {ht['accuracy']:.4f}")
    print(f"  Holdout Balanced Accuracy: {ht['balanced_accuracy']:.4f}")
    print(f"  Holdout Precision:         {ht['precision']:.4f}")
    print(f"  Holdout Recall (Threat):   {ht['recall']:.4f}")
    print(f"  Holdout F1-Score:          {ht['f1_score']:.4f}")
    print(f"  Holdout ROC-AUC:           {ht['roc_auc']:.4f}")
    print(f"  Holdout PR-AUC:            {ht['average_precision_pr_auc']:.4f}")
    print(f"  False Positive Rate (FPR): {ht['false_positive_rate']:.4f}")
    print(f"  False Negative Rate (FNR): {ht['false_negative_rate']:.4f}")
    cm = ht["confusion_matrix"]
    print(f"  Confusion Matrix:          TN={cm['true_negatives']}, FP={cm['false_positives']}, FN={cm['false_negatives']}, TP={cm['true_positives']}")

    print("\n[ARTIFACTS SAVED]")
    for k, v in results["artifacts_saved"].items():
        print(f"  {k:<24}: {v}")
    for k, v in results["plot_paths"].items():
        print(f"  plot_{k:<19}: {v}")

    print("\n" + "=" * 78)
    print("TRAINING PIPELINE SUCCESSFULLY COMPLETED (PHASE 7.2A READY)")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
