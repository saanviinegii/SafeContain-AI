"""Hyperparameter Optimization Engine for SafeContain AI ML Pipeline.

Implements rigorous, leak-free hyperparameter optimization across candidate
cybersecurity risk models (Logistic Regression, Random Forest, HistGradientBoosting)
using Stratified K-Fold cross-validation focused on Balanced Accuracy.
"""

from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.pipeline import Pipeline

from backend.app.ml.feature_engineering import FeatureEngineer


class HyperparameterOptimizer:
    """Manages hyperparameter search grids and cross-validation for model candidates."""

    def __init__(self, random_state: int = 42):
        self.random_state = random_state

    def get_candidate_grids(
        self,
        numeric_cols: List[str],
        categorical_cols: List[str],
    ) -> Dict[str, Tuple[Pipeline, Dict[str, List[Any]]]]:
        """Constructs pipeline blueprints and hyperparameter search grids for all candidates."""
        preprocessor = FeatureEngineer.build_preprocessor(numeric_cols, categorical_cols)

        candidates = {}

        # Candidate A: Regularized Logistic Regression (Interpretable Linear Baseline)
        lr_pipe = Pipeline([
            ("prep", preprocessor),
            ("clf", LogisticRegression(random_state=self.random_state, max_iter=1000)),
        ])
        lr_grid = {
            "clf__C": [0.001, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0],
            "clf__solver": ["lbfgs", "liblinear"],
            "clf__class_weight": ["balanced", None],
        }
        candidates["logistic_regression"] = (lr_pipe, lr_grid)

        # Candidate B: Random Forest Classifier (Non-linear Ensemble Baseline)
        rf_pipe = Pipeline([
            ("prep", preprocessor),
            ("clf", RandomForestClassifier(random_state=self.random_state)),
        ])
        rf_grid = {
            "clf__n_estimators": [25, 50, 75],
            "clf__max_depth": [2, 3, 4, 6],
            "clf__min_samples_leaf": [1, 2, 4],
            "clf__class_weight": ["balanced"],
        }
        candidates["random_forest"] = (rf_pipe, rf_grid)

        # Candidate C: HistGradientBoostingClassifier (Gradient Boosted Decision Trees)
        hgb_pipe = Pipeline([
            ("prep", preprocessor),
            ("clf", HistGradientBoostingClassifier(random_state=self.random_state)),
        ])
        hgb_grid = {
            "clf__learning_rate": [0.01, 0.05, 0.1, 0.2],
            "clf__max_iter": [20, 40, 60],
            "clf__max_depth": [2, 3],
            "clf__min_samples_leaf": [2, 5],
            "clf__class_weight": ["balanced"],
        }
        candidates["gradient_boosting"] = (hgb_pipe, hgb_grid)

        return candidates

    def optimize_candidate(
        self,
        model_name: str,
        pipeline: Pipeline,
        param_grid: Dict[str, List[Any]],
        X_train: pd.DataFrame,
        y_train: pd.Series,
        cv_folds: int = 5,
        scoring: str = "balanced_accuracy",
    ) -> Dict[str, Any]:
        """Runs Stratified GridSearchCV on training split for a single model candidate."""
        cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=self.random_state)

        grid_search = GridSearchCV(
            estimator=pipeline,
            param_grid=param_grid,
            cv=cv,
            scoring=scoring,
            n_jobs=-1,
            refit=True,
            return_train_score=True,
        )

        grid_search.fit(X_train, y_train)

        return {
            "model_name": model_name,
            "best_estimator": grid_search.best_estimator_,
            "best_params": grid_search.best_params_,
            "best_cv_score": round(float(grid_search.best_score_), 4),
            "scoring_metric": scoring,
            "cv_folds": cv_folds,
            "total_configurations_evaluated": len(grid_search.cv_results_["params"]),
        }

    def optimize_all_candidates(
        self,
        X_train: pd.DataFrame,
        y_train: pd.Series,
        numeric_cols: List[str],
        categorical_cols: List[str],
        cv_folds: int = 5,
        scoring: str = "balanced_accuracy",
    ) -> Dict[str, Dict[str, Any]]:
        """Executes hyperparameter optimization across all candidate models."""
        candidate_grids = self.get_candidate_grids(numeric_cols, categorical_cols)
        results = {}

        for model_name, (pipe, grid) in candidate_grids.items():
            results[model_name] = self.optimize_candidate(
                model_name=model_name,
                pipeline=pipe,
                param_grid=grid,
                X_train=X_train,
                y_train=y_train,
                cv_folds=cv_folds,
                scoring=scoring,
            )

        return results
