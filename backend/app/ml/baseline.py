"""Baseline Model Preparation and Cross-Validation for SafeContain AI ML Pipeline.

Implements standard, reproducible baseline model pipelines (Logistic Regression,
Random Forest, Dummy Classifier, and Isolation Forest) with strict cross-validation.
"""

import os
from typing import Any, Dict, List, Optional
import joblib
import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.pipeline import Pipeline

from backend.app.ml.feature_engineering import FeatureEngineer
from backend.app.ml.evaluation import (
    aggregate_cv_metrics,
    compute_anomaly_metrics,
    compute_classification_metrics,
)
from backend.app.ml.task_definition import (
    TASK_NODE_RISK_CLASSIFICATION,
    TASK_NODE_ANOMALY_DETECTION,
)


def build_baseline_pipeline(
    model_type: str,
    numeric_cols: List[str],
    categorical_cols: List[str],
    random_state: int = 42,
    **kwargs: Any,
) -> Pipeline:
    """Builds a scikit-learn Pipeline with preprocessing and the specified baseline model."""
    preprocessor = FeatureEngineer.build_preprocessor(numeric_cols, categorical_cols)

    if model_type == "logistic_regression":
        classifier = LogisticRegression(
            class_weight="balanced",
            C=kwargs.get("C", 1.0),
            max_iter=kwargs.get("max_iter", 1000),
            random_state=random_state,
        )
        return Pipeline([("prep", preprocessor), ("clf", classifier)])

    elif model_type == "random_forest":
        classifier = RandomForestClassifier(
            n_estimators=kwargs.get("n_estimators", 50),
            max_depth=kwargs.get("max_depth", 4),
            min_samples_leaf=kwargs.get("min_samples_leaf", 2),
            class_weight="balanced",
            random_state=random_state,
        )
        return Pipeline([("prep", preprocessor), ("clf", classifier)])

    elif model_type == "dummy_stratified":
        classifier = DummyClassifier(strategy="stratified", random_state=random_state)
        return Pipeline([("prep", preprocessor), ("clf", classifier)])

    elif model_type == "dummy_prior":
        classifier = DummyClassifier(strategy="prior")
        return Pipeline([("prep", preprocessor), ("clf", classifier)])

    elif model_type == "isolation_forest":
        detector = IsolationForest(
            contamination=kwargs.get("contamination", 0.10),
            n_estimators=kwargs.get("n_estimators", 100),
            random_state=random_state,
        )
        return Pipeline([("prep", preprocessor), ("detector", detector)])

    else:
        raise ValueError(
            f"Unsupported model_type: '{model_type}'. Supported: "
            "['logistic_regression', 'random_forest', 'dummy_stratified', 'dummy_prior', 'isolation_forest']"
        )


class BaselineManager:
    """Orchestrates baseline training, cross-validation, and evaluation experiments."""

    def __init__(self, feature_engineer: Optional[FeatureEngineer] = None):
        self.fe = feature_engineer or FeatureEngineer()

    def run_cross_validation(
        self,
        model_type: str = "logistic_regression",
        feature_subset: str = "topology_only",
        cv_folds: int = 5,
        random_state: int = 42,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Executes Stratified K-Fold cross validation on a supervised baseline model."""
        X, y, num_cols, cat_cols = self.fe.get_features_and_target(feature_subset)

        pipe = build_baseline_pipeline(
            model_type=model_type,
            numeric_cols=num_cols,
            categorical_cols=cat_cols,
            random_state=random_state,
            **kwargs,
        )

        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=random_state)
        scoring = [
            "accuracy",
            "balanced_accuracy",
            "precision",
            "recall",
            "f1",
            "roc_auc",
            "average_precision",
        ]

        cv_raw = cross_validate(
            pipe,
            X,
            y,
            cv=cv,
            scoring=scoring,
            return_train_score=True,
            error_score="raise",
        )

        aggregated = aggregate_cv_metrics(cv_raw)

        return {
            "task": TASK_NODE_RISK_CLASSIFICATION.task_id,
            "model_type": model_type,
            "feature_subset": feature_subset,
            "cv_folds": cv_folds,
            "random_state": random_state,
            "total_samples": len(X),
            "features_used": list(X.columns),
            "metrics": aggregated,
        }

    def train_test_evaluate(
        self,
        model_type: str = "logistic_regression",
        feature_subset: str = "topology_only",
        test_size: float = 0.20,
        random_state: int = 42,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Trains on an isolated training split and evaluates strictly on an unseen test split."""
        X, y, num_cols, cat_cols = self.fe.get_features_and_target(feature_subset)

        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=test_size,
            random_state=random_state,
            stratify=y,
        )

        pipe = build_baseline_pipeline(
            model_type=model_type,
            numeric_cols=num_cols,
            categorical_cols=cat_cols,
            random_state=random_state,
            **kwargs,
        )

        # Fit strictly on train split (Zero Leakage)
        pipe.fit(X_train, y_train)

        # Predict on train
        y_train_pred = pipe.predict(X_train)
        y_train_prob = pipe.predict_proba(X_train) if hasattr(pipe, "predict_proba") else None
        train_metrics = compute_classification_metrics(y_train.values, y_train_pred, y_train_prob)

        # Predict on unseen test
        y_test_pred = pipe.predict(X_test)
        y_test_prob = pipe.predict_proba(X_test) if hasattr(pipe, "predict_proba") else None
        test_metrics = compute_classification_metrics(y_test.values, y_test_pred, y_test_prob)

        # Extract feature coefficients / importances if available
        feature_importance_report = self._extract_feature_importances(pipe, num_cols, cat_cols)

        return {
            "task": TASK_NODE_RISK_CLASSIFICATION.task_id,
            "model_type": model_type,
            "feature_subset": feature_subset,
            "test_size": test_size,
            "random_state": random_state,
            "train_samples": len(X_train),
            "test_samples": len(X_test),
            "train_metrics": train_metrics,
            "test_metrics": test_metrics,
            "feature_importance": feature_importance_report,
        }

    def run_isolation_forest_anomaly_detection(
        self,
        feature_subset: str = "topology_only",
        contamination: float = 0.10,
        random_state: int = 42,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Runs unsupervised Isolation Forest anomaly detection on enterprise graph entities."""
        raw_df = self.fe.extract_raw_features()
        subsets = self.fe.get_feature_subsets()
        feature_cols = subsets[feature_subset]

        categorical_cols = [c for c in feature_cols if c in ["node_type", "environment", "exposure"]]
        numeric_cols = [c for c in feature_cols if c not in categorical_cols]

        X = raw_df[feature_cols].copy()
        node_ids = list(raw_df["node_id"])

        pipe = build_baseline_pipeline(
            model_type="isolation_forest",
            numeric_cols=numeric_cols,
            categorical_cols=categorical_cols,
            random_state=random_state,
            contamination=contamination,
            **kwargs,
        )

        pipe.fit(X)
        detector = pipe.named_steps["detector"]
        preprocessor = pipe.named_steps["prep"]
        X_trans = preprocessor.transform(X)

        scores = detector.decision_function(X_trans)
        outliers = detector.predict(X_trans)

        anomaly_report = compute_anomaly_metrics(scores, outliers, node_ids)

        return {
            "task": TASK_NODE_ANOMALY_DETECTION.task_id,
            "model_type": "isolation_forest",
            "feature_subset": feature_subset,
            "target_contamination": contamination,
            "random_state": random_state,
            "features_used": feature_cols,
            "results": anomaly_report,
        }

    def compare_all_baselines(
        self,
        feature_subset: str = "topology_only",
        cv_folds: int = 5,
        random_state: int = 42,
    ) -> Dict[str, Any]:
        """Runs side-by-side Stratified K-Fold cross-validation comparison of all baseline models."""
        models_to_test = ["dummy_stratified", "logistic_regression", "random_forest"]
        comparison: Dict[str, Any] = {}

        for m in models_to_test:
            cv_res = self.run_cross_validation(
                model_type=m,
                feature_subset=feature_subset,
                cv_folds=cv_folds,
                random_state=random_state,
            )
            comparison[m] = {
                "accuracy_mean": cv_res["metrics"].get("accuracy_mean"),
                "balanced_accuracy_mean": cv_res["metrics"].get("balanced_accuracy_mean"),
                "precision_mean": cv_res["metrics"].get("precision_mean"),
                "recall_mean": cv_res["metrics"].get("recall_mean"),
                "f1_mean": cv_res["metrics"].get("f1_mean"),
                "roc_auc_mean": cv_res["metrics"].get("roc_auc_mean"),
                "average_precision_mean": cv_res["metrics"].get("average_precision_mean"),
            }

        return {
            "feature_subset": feature_subset,
            "cv_folds": cv_folds,
            "random_state": random_state,
            "comparison": comparison,
        }

    def _extract_feature_importances(
        self,
        pipe: Pipeline,
        numeric_cols: List[str],
        categorical_cols: List[str],
    ) -> Optional[List[Dict[str, Any]]]:
        """Extracts named feature coefficients or importances from a fitted pipeline."""
        try:
            preprocessor = pipe.named_steps["prep"]
            clf = pipe.named_steps["clf"]

            feature_names = []
            if "num" in preprocessor.named_transformers_:
                feature_names.extend(numeric_cols)
            if "cat" in preprocessor.named_transformers_:
                cat_encoder = preprocessor.named_transformers_["cat"].named_steps["onehot"]
                encoded_cats = cat_encoder.get_feature_names_out(categorical_cols)
                feature_names.extend(list(encoded_cats))

            if hasattr(clf, "coef_"):
                coefs = clf.coef_[0]
                pairs = sorted(zip(feature_names, coefs), key=lambda x: abs(x[1]), reverse=True)
                return [{"feature": f, "weight": round(float(w), 4)} for f, w in pairs[:15]]
            elif hasattr(clf, "feature_importances_"):
                imps = clf.feature_importances_
                pairs = sorted(zip(feature_names, imps), key=lambda x: x[1], reverse=True)
                return [{"feature": f, "weight": round(float(w), 4)} for f, w in pairs[:15]]
        except Exception:
            return None
        return None

    @staticmethod
    def save_pipeline(pipe: Pipeline, filepath: str) -> None:
        """Serializes trained pipeline to disk."""
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        joblib.dump(pipe, filepath)

    @staticmethod
    def load_pipeline(filepath: str) -> Pipeline:
        """Loads serialized pipeline from disk."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Pipeline model file not found at {filepath}")
        return joblib.load(filepath)
