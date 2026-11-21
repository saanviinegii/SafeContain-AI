"""Module 7.6.7: Predictive Investigation Context Engine.

Generates structured, forensic-grade SOC investigation dossiers for early warnings,
synthesizing telemetry observations, risk trajectories, topological context, and recommended actions.
Operates 100% deterministically without external LLM dependencies.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.app.early_warning.models import (
    EarlyWarning,
    InvestigationContext,
    RiskTrajectory,
    ThreatSignal,
)
from backend.app.graph.engine import GraphEngine

logger = logging.getLogger("safecontain.early_warning.investigation_engine")


def _resolve_graph_engine(engine: Optional[Any] = None) -> Any:
    if engine is not None:
        return engine
    try:
        from backend.app.api.v1.router import platform_ctx
        if platform_ctx and hasattr(platform_ctx, "engine") and platform_ctx.engine:
            return platform_ctx.engine
    except Exception:
        pass
    try:
        from backend.app.graph.engine import GraphEngine
        return GraphEngine(mode="in_memory")
    except Exception:
        return None


class InvestigationContextEngine:
    """Builds comprehensive forensic investigation dossiers for active early warnings."""

    def __init__(self, graph_engine: Optional[Any] = None):
        self.graph_engine = _resolve_graph_engine(graph_engine)
        self._investigations_cache: Dict[str, InvestigationContext] = {}

    def build_investigation_dossier(
        self,
        warning: EarlyWarning,
        trajectory: Optional[RiskTrajectory] = None,
        signals: Optional[List[ThreatSignal]] = None,
        asset_name: Optional[str] = None,
    ) -> InvestigationContext:
        """Constructs an evidence-backed SOC investigation context from warning telemetry."""
        now = datetime.now(timezone.utc)
        asset_id = warning.asset_id
        label = asset_name or asset_id
        warning_signals = signals or []

        # 1. Topological Graph Context
        related_nodes = list(warning.affected_entities)
        relevant_relationships: List[str] = []
        try:
            if hasattr(self.graph_engine, "_nx_graph") and self.graph_engine._nx_graph.has_node(asset_id):
                succ = list(self.graph_engine._nx_graph.successors(asset_id))
                pred = list(self.graph_engine._nx_graph.predecessors(asset_id))
                for s in succ[:4]:
                    related_nodes.append(s)
                    relevant_relationships.append(f"({asset_id}) -[:CONNECTED_TO]-> ({s})")
                for p in pred[:4]:
                    related_nodes.append(p)
                    relevant_relationships.append(f"({p}) -[:ACCESSES]-> ({asset_id})")
        except Exception as e:
            logger.debug("Graph context extraction note: %s", e)

        related_nodes = list(set(related_nodes))

        # 2. Section Synthesis
        what_happened = (
            f"The SafeContain Early-Warning Engine issued a {warning.severity.value} priority directive "
            f"('{warning.warning_type.value}') on asset '{label}' ({asset_id}). "
            f"The system detected acute behavioral changes preceding potential breach escalation."
        )

        observed_items = list(warning.observed_evidence)
        if warning_signals:
            for s in warning_signals[:3]:
                observed_items.append(f"[{s.signal_type.value}] {s.evidence}")
        what_was_observed = "\n".join(f"- {item}" for item in observed_items) if observed_items else "Standard baseline anomaly detected."

        # Trajectory evolution text
        if trajectory:
            trajectory_text = (
                f"Risk posture currently measured at {trajectory.current_risk:.1f}/100. "
                f"Trajectory is {trajectory.trend_direction.value} with velocity {trajectory.slope:+.2f} pts/hr "
                f"and acceleration {trajectory.acceleration:+.4f} pts/hr². "
                f"Projected risk over +{trajectory.forecast_horizon_hours:.0f}h horizon: {trajectory.projected_risk:.1f}/100 "
                f"(Confidence: {trajectory.projection_confidence:.0%})."
            )
            what_changed = (
                f"Asset risk velocity shifted by {trajectory.slope:+.2f} points/hour. "
                f"{'Statistical CUSUM change-point break was triggered.' if trajectory.change_point_detected else 'Risk metrics deviate from historical mean.'}"
            )
        else:
            trajectory_text = f"Baseline risk currently at {warning.priority_score:.1f}. Dynamic trajectory metrics unavailable."
            what_changed = "Anomalous event cluster detected across topological neighbors."

        why_it_matters = (
            f"Early intervention prevents lateral traversal and containment disruption. "
            f"{warning.predicted_impact} "
            f"Immediate triage is recommended given the priority rank of {warning.priority_score:.1f}/100."
        )

        potential_escalation = (
            f"If uncontained, adversary activity is projected to cross critical breach thresholds, "
            f"potentially compromising dependent enterprise databases and exposing confidential credentials."
        )

        uncertainty_factors = [
            f"Detection confidence is rated at {warning.confidence:.0%}.",
            "Predictions are probability projections and do not constitute guaranteed breach confirmation.",
            "Lateral propagation speed is subject to active firewall policies and host agent responsiveness.",
        ]

        investigation_steps = [
            f"Step 1: Verify forensic host telemetry for asset '{label}' ({asset_id}).",
            "Step 2: Inspect active parent-child process chains and abnormal outbound socket connections.",
            "Step 3: Review IAM authentication records and invalidate active tokens if credential theft is suspected.",
            f"Step 4: Execute recommended posture: {warning.recommended_action}",
            "Step 5: Follow SafeContain response playbook and stage containment interventions via Optimization Planner.",
        ]

        # Generate unique investigation identifier
        raw = f"{warning.warning_id}:{asset_id}:{now.strftime('%Y%m%d%H')}"
        inv_token = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]
        inv_id = f"inv-{inv_token}"

        dossier = InvestigationContext(
            investigation_id=inv_id,
            warning_id=warning.warning_id,
            asset_id=asset_id,
            asset_name=label,
            what_happened=what_happened,
            what_was_observed=what_was_observed,
            what_changed=what_changed,
            why_it_matters=why_it_matters,
            related_assets=related_nodes,
            relevant_graph_relationships=relevant_relationships,
            risk_trajectory_evolution=trajectory_text,
            potential_escalation=potential_escalation,
            supporting_evidence=warning.observed_evidence,
            uncertainty_factors=uncertainty_factors,
            recommended_investigation_steps=investigation_steps,
            generated_at=now,
        )

        self._investigations_cache[warning.warning_id] = dossier
        return dossier

    def get_dossier_by_warning_id(self, warning_id: str) -> Optional[InvestigationContext]:
        """Retrieves cached investigation dossier by warning identifier."""
        return self._investigations_cache.get(warning_id)
