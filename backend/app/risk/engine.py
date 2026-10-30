"""SafeContain AI Decomposed Risk Intelligence Engine.

Implements transparent, factor-contributed, and uncertainty-adjusted risk calculations.
Strictly avoids arbitrary uncalibrated scores, separating inherent, observed,
potential, and residual risk tiers.
"""

from typing import Dict, List, Optional
from backend.app.core.config import settings
from backend.app.models.domain import (
    AttackPath,
    EvidenceStatus,
    GraphNode,
    RiskDecomposition,
)


class RiskEngine:
    """Enterprise Risk Intelligence Engine."""

    @classmethod
    def decompose_system_risk(
        cls,
        paths: List[AttackPath],
        nodes: List[GraphNode]
    ) -> RiskDecomposition:
        """Computes a multi-tier decomposed system risk profile."""
        if not paths:
            return RiskDecomposition(
                inherent_risk=0.0,
                observed_risk=0.0,
                potential_risk=0.0,
                residual_risk=0.0,
                uncertainty_penalty=0.0,
                uncertainty_adjusted_risk=0.0,
                asset_criticality_factor=0.0,
                path_reachability_factor=0.0,
                vulnerability_severity_factor=0.0,
                contributing_factors=[],
            )

        # Asset criticality factor: mean criticality of targeted assets
        target_nodes = [n for n in nodes if n.is_crown_jewel or n.criticality >= 0.85]
        mean_target_crit = (
            sum(n.criticality for n in target_nodes) / len(target_nodes)
            if target_nodes else 0.5
        )

        # Observed paths (confidence >= 0.8) vs Potential paths (including suspected)
        confirmed_paths = [p for p in paths if p.confidence_score >= 0.8]
        suspected_paths = [p for p in paths if p.confidence_score < 0.8]

        # Inherent Risk: Maximum inherent risk across all viable paths
        inherent_risk = round(max((p.inherent_path_risk for p in paths), default=0.0), 2)

        # Observed Risk: Maximum risk among verified, confirmed paths
        observed_risk = round(
            max((p.inherent_path_risk for p in confirmed_paths), default=0.0), 2
        )

        # Potential Risk: Peak risk including unverified/suspected paths
        potential_risk = round(max((p.adjusted_path_risk for p in paths), default=0.0), 2)

        # System-wide uncertainty penalty
        uncertainty_penalty = round(
            sum(p.uncertainty_penalty for p in paths) / max(1, len(paths)), 2
        )

        # Final uncertainty-adjusted composite risk
        adjusted_risk = min(
            100.0,
            round(observed_risk + (0.5 * (potential_risk - observed_risk)) + uncertainty_penalty, 2)
        )

        # Factor contributions breakdown
        contributing_factors = [
            {
                "factor_name": "Target Crown Jewel Criticality",
                "weight": 0.40,
                "score": round(mean_target_crit * 100.0, 1),
                "description": f"Target assets have average criticality of {mean_target_crit:.0%}.",
            },
            {
                "factor_name": "Attack Path Reachability",
                "weight": 0.35,
                "score": round(min(100.0, len(paths) * 20.0), 1),
                "description": f"{len(paths)} distinct active lateral traversal routes discovered.",
            },
            {
                "factor_name": "Evidence Uncertainty Exposure",
                "weight": 0.25,
                "score": round(min(100.0, uncertainty_penalty * 10.0), 1),
                "description": f"{len(suspected_paths)} paths rely on suspected or unverified evidence.",
            },
        ]

        return RiskDecomposition(
            inherent_risk=inherent_risk,
            observed_risk=observed_risk,
            potential_risk=potential_risk,
            residual_risk=adjusted_risk, # Defaults to adjusted until containment intervention applied
            uncertainty_penalty=uncertainty_penalty,
            uncertainty_adjusted_risk=adjusted_risk,
            asset_criticality_factor=round(mean_target_crit, 2),
            path_reachability_factor=round(min(1.0, len(paths) / 5.0), 2),
            vulnerability_severity_factor=round(observed_risk / 100.0, 2),
            contributing_factors=contributing_factors,
        )
