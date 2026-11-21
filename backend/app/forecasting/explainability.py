"""Explainable AI (XAI) Attribution for SafeContain AI Phase 7.3 Forecasting Engine.

Computes SHAP feature importance attributions for temporal threat forecasts,
identifying positive risk accelerants, negative protective factors, and graph evidence.
"""

from typing import Any, Dict, List, Optional
import numpy as np
import pandas as pd
import shap

from backend.app.forecasting.models import ForecastFeatureContribution


FEATURE_DESCRIPTIONS: Dict[str, str] = {
    "alert_count_window": "Security alerts targeting asset in active temporal window",
    "alert_count_prior": "Security alerts targeting asset in preceding baseline window",
    "alert_velocity": "Rate of acceleration in incoming security alerts",
    "max_alert_severity": "Peak severity weight of alerts targeting asset",
    "evidence_count_window": "Forensic evidence and telemetry artifacts gathered on asset",
    "graph_compromise_proximity": "Topological proximity to nearest currently compromised node",
    "neighbor_threat_density_1hop": "Proportion of directly connected graph neighbors experiencing alerts",
    "neighbor_threat_density_2hop": "Proportion of 2-hop graph neighbors experiencing alerts",
    "active_upstream_path_count": "Active lateral attack paths traversing asset from compromised entry points",
    "correlated_indicator_count": "Threat intelligence indicators (CVEs, IPs, hashes) mapped to asset",
    "static_ml_probability": "Baseline inherent compromise probability P(Y=1)",
    "criticality": "Asset business criticality valuation",
    "exposure": "Network perimeter accessibility and DMZ exposure tier",
    "pagerank": "Network connectivity centrality and structural importance",
    "in_degree": "Ingress connectivity degree",
    "out_degree": "Egress connectivity degree",
}


class ForecastExplainer:
    """Computes SHAP feature attributions for temporal threat predictions."""

    def __init__(self, model: Any, feature_names: List[str]):
        self.model = model
        self.feature_names = feature_names
        self._tree_explainer: Optional[shap.TreeExplainer] = None

    def _get_explainer(self) -> shap.TreeExplainer:
        if self._tree_explainer is None:
            self._tree_explainer = shap.TreeExplainer(self.model)
        return self._tree_explainer

    def explain_asset_forecast(
        self,
        feature_row: pd.Series,
        top_n: int = 5,
    ) -> List[ForecastFeatureContribution]:
        """Calculates SHAP feature contributions for a single asset's temporal forecast."""
        x_vec = np.array([feature_row[f] for f in self.feature_names]).reshape(1, -1)

        try:
            explainer = self._get_explainer()
            raw_shap = explainer.shap_values(x_vec)
            # Binary classifier: check shape (1, num_features) or (1, num_features, 2)
            if isinstance(raw_shap, list):
                shap_vals = raw_shap[1][0] if len(raw_shap) > 1 else raw_shap[0][0]
            elif len(raw_shap.shape) == 3:
                shap_vals = raw_shap[0, :, 1]
            else:
                shap_vals = raw_shap[0]
        except Exception:
            # Fallback to feature importance weighting if TreeExplainer encounters unexpected shape
            importances = getattr(self.model, "feature_importances_", np.ones(len(self.feature_names)) / len(self.feature_names))
            shap_vals = (x_vec[0] - np.mean(x_vec[0])) * importances

        contributions: List[ForecastFeatureContribution] = []
        for i, fname in enumerate(self.feature_names):
            val = float(feature_row[fname])
            score = float(shap_vals[i])
            direction = "INCREASES_RISK" if score >= 0.0 else "DECREASES_RISK"
            desc = FEATURE_DESCRIPTIONS.get(fname, f"Observable metric {fname}")

            contributions.append(
                ForecastFeatureContribution(
                    feature_name=fname,
                    feature_value=round(val, 4),
                    contribution_score=round(score, 4),
                    direction=direction,
                    description=desc,
                )
            )

        # Sort by absolute SHAP attribution magnitude
        contributions.sort(key=lambda c: abs(c.contribution_score), reverse=True)
        return contributions[:top_n]

    @staticmethod
    def generate_narrative_explanation(
        asset_id: str,
        asset_name: str,
        p_current: float,
        p_future: float,
        trend: str,
        horizon_label: str,
        top_contributions: List[ForecastFeatureContribution],
        upstream_breaches: List[str],
        is_crown_jewel: bool,
    ) -> str:
        """Synthesizes an explainable SOC narrative detailing why future risk is changing."""
        pct_curr = f"{p_current:.1%}"
        pct_fut = f"{p_future:.1%}"
        delta_str = f"{(p_future - p_current):+.1%}"

        narrative_parts = [
            f"Asset '{asset_name}' ({asset_id}) demonstrates an {trend} threat trajectory over the {horizon_label} forecast window, "
            f"with projected compromise probability moving from {pct_curr} (current) to {pct_fut} (future, {delta_str})."
        ]

        # Top positive risk accelerators
        accelerators = [c for c in top_contributions if c.direction == "INCREASES_RISK"]
        if accelerators:
            acc_names = [f"{c.feature_name} (val: {c.feature_value:.2f}, SHAP: +{c.contribution_score:.2f})" for c in accelerators[:2]]
            narrative_parts.append(f"Primary risk acceleration drivers: {'; '.join(acc_names)}.")

        # Top protective dampeners
        dampeners = [c for c in top_contributions if c.direction == "DECREASES_RISK"]
        if dampeners:
            damp_names = [f"{c.feature_name} (val: {c.feature_value:.2f}, SHAP: {c.contribution_score:.2f})" for c in dampeners[:1]]
            narrative_parts.append(f"Mitigating factors: {'; '.join(damp_names)}.")

        # Upstream breach links
        if upstream_breaches:
            narrative_parts.append(
                f"Lateral contagion vector: Directly exposed to active upstream breaches at {', '.join(upstream_breaches[:3])}."
            )

        # Crown jewel impact
        if is_crown_jewel:
            narrative_parts.append(
                "CRITICAL WARNING: Asset is an enterprise Crown Jewel; projected compromise severely endangers organizational operations."
            )

        return " ".join(narrative_parts)
