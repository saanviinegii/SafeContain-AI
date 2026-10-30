"""SafeContain AI Evidence Uncertainty and Sensitivity Intelligence Engine.

Implements mathematical uncertainty models, freshness decay, and sensitivity analysis
evaluating decision stability under evidence drift and confidence shifts.
"""

from datetime import datetime, timezone, timedelta
import math
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from backend.app.core.config import settings
from backend.app.models.domain import (
    AttackPath,
    DataProvenance,
    EvidenceRecord,
    EvidenceStatus,
    GraphEdge,
)


class SensitivityScenarioResult(BaseModel):
    """Result of sensitivity evaluation under evidence state perturbation."""
    scenario_name: str
    perturbed_edge_id: str
    original_status: EvidenceStatus
    new_status: EvidenceStatus
    original_risk: float
    new_risk: float
    risk_delta: float
    plan_stability_impact: str # NEGLIGIBLE | MODERATE | SIGNIFICANT | STRATEGY_FLIP


class EvidenceEngine:
    """Manages forensic evidence records, uncertainty decay, and sensitivity drift."""

    def __init__(self):
        self._evidence_store: Dict[str, EvidenceRecord] = {}

    def register_evidence(self, record: EvidenceRecord) -> None:
        """Registers an evidence record with timestamp and cryptographic attribution."""
        self._evidence_store[record.id] = record

    def get_evidence(self, record_id: str) -> Optional[EvidenceRecord]:
        return self._evidence_store.get(record_id)

    def evaluate_freshness(self, edge: GraphEdge, current_time: Optional[datetime] = None) -> EvidenceStatus:
        """Evaluates whether an edge has become STALE based on elapsed time."""
        now = current_time or datetime.now(timezone.utc)
        elapsed_hours = (now - edge.last_verified_at).total_seconds() / 3600.0

        if elapsed_hours > settings.EVIDENCE_STALENESS_THRESHOLD_HOURS:
            return EvidenceStatus.STALE
        return edge.evidence_status

    def calculate_decayed_confidence(self, edge: GraphEdge, current_time: Optional[datetime] = None) -> float:
        """Computes exponential temporal decay of confidence for unrefreshed telemetry:
        
        C(t) = C_0 * exp(-lambda * t_days)
        """
        now = current_time or datetime.now(timezone.utc)
        elapsed_days = max(0.0, (now - edge.last_verified_at).total_seconds() / 86400.0)
        decay_constant = settings.CONFIDENCE_DECAY_RATE_PER_DAY
        decayed = edge.confidence * math.exp(-decay_constant * elapsed_days)
        return max(0.05, min(1.0, round(decayed, 4)))

    def run_sensitivity_analysis(
        self,
        paths: List[AttackPath],
        engine
    ) -> List[SensitivityScenarioResult]:
        """Performs sensitivity perturbation across uncertain edges.
        
        Answers: What happens if a suspected relationship is confirmed or refuted?
        """
        results: List[SensitivityScenarioResult] = []

        for path in paths:
            for edge_id in path.edge_sequence:
                edge = engine.get_edge(edge_id)
                if not edge or edge.evidence_status != EvidenceStatus.SUSPECTED:
                    continue

                # Scenario A: Suspected edge is CONFIRMED (Confidence rises to 1.0)
                # Removing uncertainty penalty, increasing confirmed reachability
                orig_risk = path.adjusted_path_risk
                # If confirmed, uncertainty penalty drops to 0 for this edge, but inherent risk remains
                simulated_penalty = max(0.0, path.uncertainty_penalty - (settings.UNCERTAINTY_PENALTY_WEIGHT * 10.0))
                new_risk_confirmed = round(path.inherent_path_risk + simulated_penalty, 2)
                delta_confirmed = round(new_risk_confirmed - orig_risk, 2)

                impact_desc = "MODERATE"
                if abs(delta_confirmed) > 15.0:
                    impact_desc = "STRATEGY_FLIP"

                results.append(SensitivityScenarioResult(
                    scenario_name=f"Hypothesis: Confirm suspected route on edge '{edge_id}'",
                    perturbed_edge_id=edge_id,
                    original_status=EvidenceStatus.SUSPECTED,
                    new_status=EvidenceStatus.CONFIRMED,
                    original_risk=orig_risk,
                    new_risk=new_risk_confirmed,
                    risk_delta=delta_confirmed,
                    plan_stability_impact=impact_desc,
                ))

                # Scenario B: Suspected edge is DISPUTED / REFUTED (Path collapses)
                results.append(SensitivityScenarioResult(
                    scenario_name=f"Hypothesis: Refute suspected route on edge '{edge_id}'",
                    perturbed_edge_id=edge_id,
                    original_status=EvidenceStatus.SUSPECTED,
                    new_status=EvidenceStatus.DISPUTED,
                    original_risk=orig_risk,
                    new_risk=0.0,
                    risk_delta=-orig_risk,
                    plan_stability_impact="STRATEGY_FLIP",
                ))

        return results
