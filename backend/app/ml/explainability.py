"""SafeContain AI Explainable AI (XAI) Service for Cybersecurity Risk Intelligence (Phase 7.2C).

Implements:
1. SHAP-based feature attribution using LinearExplainer for the trained regularized Logistic Regression model.
2. Transparent mapping between transformed one-hot/scaled feature space and raw enterprise asset features.
3. Ranking of positive (increases_risk) and negative (decreases_risk) risk drivers.
4. Base value calibration and log-odds to probability margin alignment.
5. In-memory caching and batch pre-computation for sub-millisecond API response times.
6. Non-causal, human-readable explainability summaries for security analysts.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
import pandas as pd
import shap

from backend.app.ml.feature_engineering import FeatureEngineer
from backend.app.ml.model_registry import ModelRegistry

logger = logging.getLogger("safecontain.ml.explainability")


# Plain-language descriptions for cybersecurity features
FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "pagerank": "Graph centrality score indicating structural importance in the network topology.",
    "in_degree": "Count of inbound network dependencies and authenticating connections.",
    "out_degree": "Count of outbound connections to other network endpoints and services.",
    "total_degree": "Total incident connections in the enterprise infrastructure graph.",
    "in_out_degree_ratio": "Ratio of inbound to outbound edges (identifies traffic sinks vs sources).",
    "is_high_privilege_connected": "Direct connectivity to Domain Admins or elevated credentials.",
    "admin_edge_count": "Total count of active administrative or privileged edges.",
    "business_value": "Financial or operational business valuation of the asset.",
    "has_asset_profile": "Presence of comprehensive host posture and software inventory.",
    "node_type": "Primary asset classification (Host, User, Service, Network, Data).",
    "environment": "Operational enclave (Production, Staging, Internal, DMZ).",
    "exposure": "Network boundary visibility (Internal, External, DMZ).",
    "criticality": "Static asset criticality level (Low, Medium, High, Mission-Critical).",
}


class ShapExplainerService:
    """Provides SHAP feature attribution and explainability for SafeContain AI models."""

    def __init__(
        self,
        model_registry: Optional[ModelRegistry] = None,
        feature_engineer: Optional[FeatureEngineer] = None,
        max_background_samples: int = 100,
        random_state: int = 42,
    ):
        self.registry = model_registry or ModelRegistry()
        self.fe = feature_engineer or FeatureEngineer()
        self.max_background_samples = max_background_samples
        self.random_state = random_state

        self._explainer: Optional[shap.LinearExplainer] = None
        self._background_trans: Optional[np.ndarray] = None
        self._expected_features: List[str] = []
        self._transformed_feature_names: List[str] = []
        self._feature_mapping: Dict[int, Tuple[str, str]] = {}
        self._cache: Dict[str, Dict[str, Any]] = {}

    def _ensure_initialized(self) -> None:
        """Lazily initializes the SHAP explainer from the active trained model."""
        if self._explainer is not None:
            return

        pipeline, metadata = self.registry.load_model()
        clf = pipeline.named_steps.get("clf")
        prep = pipeline.named_steps.get("prep")

        if clf is None or prep is None:
            raise ValueError(
                "Model pipeline is missing required 'prep' or 'clf' steps. "
                f"Available steps: {list(pipeline.named_steps.keys())}"
            )

        self._expected_features = metadata.get("features", [])
        if not self._expected_features:
            raise ValueError("Model metadata contains no feature list.")

        # Extract background data from synthetic enterprise nodes
        raw_df = self.fe.extract_raw_features()
        X_raw = raw_df[self._expected_features]

        # Transform using fitted preprocessor
        X_trans = prep.transform(X_raw)
        self._transformed_feature_names = list(prep.get_feature_names_out())

        # Subsample background if larger than max_background_samples
        n_samples = len(X_trans)
        if n_samples > self.max_background_samples:
            rng = np.random.RandomState(self.random_state)
            indices = rng.choice(n_samples, size=self.max_background_samples, replace=False)
            background = X_trans[indices]
        else:
            background = X_trans

        self._background_trans = background

        # Create SHAP LinearExplainer (Exact, fast, closed-form for linear models)
        self._explainer = shap.LinearExplainer(
            clf,
            background,
            feature_names=self._transformed_feature_names,
        )

        # Build mapping from transformed indices to parent feature names
        self._feature_mapping = {}
        for idx, col_name in enumerate(self._transformed_feature_names):
            parent = self._resolve_parent_feature(col_name)
            self._feature_mapping[idx] = (col_name, parent)

    def _resolve_parent_feature(self, col_name: str) -> str:
        """Resolves a preprocessor transformed column name to its raw parent feature."""
        # e.g., 'num__pagerank' -> 'pagerank'
        if col_name.startswith("num__"):
            return col_name.replace("num__", "")

        # e.g., 'cat__node_type_Host' -> 'node_type'
        cleaned = col_name.replace("cat__", "")
        for feat in self._expected_features:
            if cleaned.startswith(feat):
                return feat
        return cleaned

    def clear_cache(self) -> None:
        """Flushes explanation cache."""
        self._cache.clear()
        self._explainer = None

    def explain_asset(
        self,
        node_id: str,
        top_n: int = 5,
        threshold: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Generates a structured SHAP explanation for a specific graph node.
        
        Args:
            node_id: Graph entity identifier (e.g. 'node-user-marcus')
            top_n: Number of top contributing features to return (default: 5)
            threshold: Optional decision threshold override
            
        Returns:
            Structured explanation dictionary adhering to Phase 7.2C schema.
        """
        cache_key = f"{node_id}:{top_n}:{threshold}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        self._ensure_initialized()
        pipeline, metadata = self.registry.load_model()
        th = (
            float(threshold)
            if threshold is not None and not hasattr(threshold, "default")
            else self.registry.get_operating_threshold()
        )
        model_version = metadata.get("version", "1.0.0")

        # Fetch node features
        raw_df = self.fe.extract_raw_features()
        node_rows = raw_df[raw_df["node_id"] == node_id]
        if len(node_rows) == 0:
            raise KeyError(f"Asset node '{node_id}' not found in active graph dataset.")

        node_row = node_rows.iloc[0]
        X_node = pd.DataFrame([node_row[self._expected_features]])

        # Run prediction
        prob_risk = float(pipeline.predict_proba(X_node)[0, 1])
        threshold_crossed = bool(prob_risk >= th)
        predicted_class = "At-Risk / Threat" if threshold_crossed else "Healthy / Benign"

        if prob_risk >= 0.75:
            risk_tier = "CRITICAL"
        elif prob_risk >= 0.50:
            risk_tier = "HIGH"
        elif prob_risk >= 0.32:
            risk_tier = "MODERATE"
        else:
            risk_tier = "LOW"

        # Transform features and compute SHAP
        prep = pipeline.named_steps["prep"]
        clf = pipeline.named_steps["clf"]
        X_trans = prep.transform(X_node)
        shap_res = self._explainer(X_trans)
        shap_values_trans = shap_res.values[0]

        # Base value (log-odds margin)
        base_val = float(np.atleast_1d(self._explainer.expected_value)[0])
        margin = float(clf.decision_function(X_trans)[0])

        # Aggregate SHAP contributions by parent feature
        aggregated_shap: Dict[str, float] = {f: 0.0 for f in self._expected_features}
        for idx, sval in enumerate(shap_values_trans):
            _, parent = self._feature_mapping[idx]
            if parent in aggregated_shap:
                aggregated_shap[parent] += float(sval)

        # Build feature contributor list
        contributors = []
        for feat in self._expected_features:
            sval = aggregated_shap[feat]
            raw_val = node_row.get(feat)
            # Format value for serialization
            if isinstance(raw_val, (np.floating, float)):
                val_repr = round(float(raw_val), 4)
            elif isinstance(raw_val, (np.integer, int)):
                val_repr = int(raw_val)
            else:
                val_repr = str(raw_val)

            direction = "increases_risk" if sval > 0 else "decreases_risk"
            desc = FEATURE_DESCRIPTIONS.get(feat, "Network posture attribute.")

            contributors.append({
                "feature": feat,
                "value": val_repr,
                "shap_value": round(float(sval), 4),
                "direction": direction,
                "magnitude": round(abs(float(sval)), 4),
                "description": desc,
            })

        # Rank contributors by magnitude descending
        ranked_contributors = sorted(contributors, key=lambda c: c["magnitude"], reverse=True)
        top_contributors = ranked_contributors[:top_n]

        pos_count = sum(1 for c in contributors if c["direction"] == "increases_risk" and abs(c["shap_value"]) > 0.001)
        neg_count = sum(1 for c in contributors if c["direction"] == "decreases_risk" and abs(c["shap_value"]) > 0.001)

        # Generate analyst summary
        top_increasing = [c["feature"] for c in top_contributors if c["direction"] == "increases_risk"]
        top_decreasing = [c["feature"] for c in top_contributors if c["direction"] == "decreases_risk"]

        if threshold_crossed:
            inc_text = f", driven primarily by {', '.join(top_increasing[:2])}" if top_increasing else ""
            summary = (
                f"Model predicts elevated threat probability ({prob_risk:.1%}) exceeding the calibrated "
                f"{th:.2f} threshold (Class: {predicted_class}){inc_text}. Asset warrants targeted containment triage."
            )
        else:
            dec_text = f", moderated by {', '.join(top_decreasing[:2])}" if top_decreasing else ""
            summary = (
                f"Model predicts baseline risk probability ({prob_risk:.1%}) below the {th:.2f} operating "
                f"threshold (Class: {predicted_class}){dec_text}. Asset is classified as benign under current telemetry."
            )

        explanation_payload = {
            "asset_id": node_id,
            "asset_name": str(node_row.get("name", node_id)),
            "model_version": model_version,
            "risk_probability": round(prob_risk, 4),
            "decision_threshold": round(th, 4),
            "predicted_class": predicted_class,
            "threshold_crossed": threshold_crossed,
            "risk_tier": risk_tier,
            "explanation": {
                "base_value": round(base_val, 4),
                "decision_margin": round(margin, 4),
                "top_contributors": top_contributors,
                "all_contributors": ranked_contributors,
                "positive_contributors_count": pos_count,
                "negative_contributors_count": neg_count,
                "summary": summary,
            },
        }

        self._cache[cache_key] = explanation_payload
        return explanation_payload

    def explain_dataframe(
        self,
        X: pd.DataFrame,
        top_n: int = 5,
        threshold: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Generates SHAP explanations for arbitrary input feature rows."""
        self._ensure_initialized()
        pipeline, metadata = self.registry.load_model()
        th = (
            float(threshold)
            if threshold is not None and not hasattr(threshold, "default")
            else self.registry.get_operating_threshold()
        )
        self.registry.validate_features(X, self._expected_features)

        X_input = X[self._expected_features]
        prep = pipeline.named_steps["prep"]
        clf = pipeline.named_steps["clf"]

        X_trans = prep.transform(X_input)
        probabilities = pipeline.predict_proba(X_input)[:, 1]
        margins = clf.decision_function(X_trans)
        shap_res = self._explainer(X_trans)
        base_val = float(np.atleast_1d(self._explainer.expected_value)[0])

        results = []
        for i in range(len(X_input)):
            prob_risk = float(probabilities[i])
            margin = float(margins[i])
            th_crossed = bool(prob_risk >= th)
            row_shap = shap_res.values[i]
            row_raw = X_input.iloc[i]

            aggregated_shap: Dict[str, float] = {f: 0.0 for f in self._expected_features}
            for idx, sval in enumerate(row_shap):
                _, parent = self._feature_mapping[idx]
                if parent in aggregated_shap:
                    aggregated_shap[parent] += float(sval)

            contributors = []
            for feat in self._expected_features:
                sval = aggregated_shap[feat]
                raw_val = row_raw.get(feat)
                if isinstance(raw_val, (np.floating, float)):
                    val_repr = round(float(raw_val), 4)
                elif isinstance(raw_val, (np.integer, int)):
                    val_repr = int(raw_val)
                else:
                    val_repr = str(raw_val)

                contributors.append({
                    "feature": feat,
                    "value": val_repr,
                    "shap_value": round(float(sval), 4),
                    "direction": "increases_risk" if sval > 0 else "decreases_risk",
                    "magnitude": round(abs(float(sval)), 4),
                    "description": FEATURE_DESCRIPTIONS.get(feat, ""),
                })

            ranked = sorted(contributors, key=lambda c: c["magnitude"], reverse=True)
            top = ranked[:top_n]

            results.append({
                "risk_probability": round(prob_risk, 4),
                "decision_threshold": round(th, 4),
                "threshold_crossed": th_crossed,
                "base_value": round(base_val, 4),
                "decision_margin": round(margin, 4),
                "top_contributors": top,
            })

        return results

    def get_all_asset_explanations(
        self,
        top_n: int = 5,
        threshold: Optional[float] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """Pre-computes and returns SHAP explanations for all active nodes in the network."""
        raw_df = self.fe.extract_raw_features()
        all_explanations = {}
        for nid in raw_df["node_id"].unique():
            nid_str = str(nid)
            try:
                all_explanations[nid_str] = self.explain_asset(
                    node_id=nid_str,
                    top_n=top_n,
                    threshold=threshold,
                )
            except Exception as e:
                logger.warning(f"Failed to compute explanation for node '{nid_str}': {e}")
        return all_explanations
