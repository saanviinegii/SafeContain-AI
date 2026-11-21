"""Module 7.6.5: Early-Warning Engine & Prioritization.

Generates evidence-backed early warnings across 7 operational categories,
prioritizes them through an explainable multi-factor scoring mechanism,
and enforces sliding-window deduplication and cooldown to prevent alert fatigue.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.app.early_warning.models import (
    CorrelatedThreatCluster,
    EscalationPrediction,
    EscalationState,
    EarlyWarning,
    RiskTrajectory,
    ThreatSeverity,
    ThreatSignal,
    TrajectoryDirection,
    WarningCategory,
    WarningStatus,
)

logger = logging.getLogger("safecontain.early_warning.warning_engine")


class EarlyWarningEngine:
    """Manages generation, prioritization, deduplication, and lifecycle tracking of early warnings."""

    def __init__(self, cooldown_hours: float = 12.0):
        self.cooldown_hours = cooldown_hours
        self._warnings_store: Dict[str, EarlyWarning] = {}
        # Key: (asset_id, warning_type_value) -> warning_id
        self._cooldown_index: Dict[str, Tuple[str, datetime]] = {}

    def _generate_warning_id(self, asset_id: str, category: WarningCategory, time_bucket: str) -> str:
        """Generates deterministic warning ID."""
        raw = f"{asset_id}:{category.value}:{time_bucket}"
        token = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]
        return f"warn-{category.value.lower()[:4]}-{token}"

    def calculate_priority_score(
        self,
        severity: ThreatSeverity,
        current_risk: float,
        criticality: float,
        is_crown_jewel: bool,
        is_cluster_correlated: bool,
        confidence: float,
        is_verified_threat: bool = False,
    ) -> float:
        """Computes explainable multi-factor warning prioritization score [0.0 - 100.0].

        Formula:
            Priority = 0.35 * Sev + 0.25 * Risk + 0.20 * Crit + 0.10 * Cluster + 0.10 * Conf
        """
        sev_weights = {
            ThreatSeverity.CRITICAL: 100.0,
            ThreatSeverity.HIGH: 75.0,
            ThreatSeverity.MEDIUM: 50.0,
            ThreatSeverity.LOW: 25.0,
        }
        sev_comp = sev_weights.get(severity, 50.0) * 0.35
        risk_comp = current_risk * 0.25
        crit_scale = 100.0 if is_crown_jewel else (criticality * 100.0)
        crit_comp = crit_scale * 0.20
        cluster_comp = 100.0 * 0.10 if is_cluster_correlated else 20.0 * 0.10
        conf_comp = (confidence * 100.0) * 0.10

        score = sev_comp + risk_comp + crit_comp + cluster_comp + conf_comp
        if is_crown_jewel:
            score = min(100.0, score + 10.0)

        # Critical threat safety invariant: verified critical threats receive >= 85.0
        if is_verified_threat or severity == ThreatSeverity.CRITICAL:
            score = max(score, 85.0)

        return min(100.0, max(0.0, round(score, 2)))

    def evaluate_early_warnings(
        self,
        trajectories: Dict[str, RiskTrajectory],
        signals: List[ThreatSignal],
        escalations: Dict[str, EscalationPrediction],
        clusters: Optional[List[CorrelatedThreatCluster]] = None,
        asset_metadata: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> List[EarlyWarning]:
        """Evaluates all telemetry, trajectories, and clusters to synthesize deduplicated early warnings."""
        now = datetime.now(timezone.utc)
        meta = asset_metadata or {}
        active_clusters = clusters or []

        # Map assets belonging to clusters
        cluster_asset_map: Dict[str, CorrelatedThreatCluster] = {}
        for c in active_clusters:
            for aid in c.related_asset_ids:
                cluster_asset_map[aid] = c

        # Map signals per asset
        asset_signals: Dict[str, List[ThreatSignal]] = {}
        for s in signals:
            asset_signals.setdefault(s.asset_id, []).append(s)

        new_warnings: List[EarlyWarning] = []

        # ---------------------------------------------------------------------
        # 1. Trajectory & Escalation Warnings
        # ---------------------------------------------------------------------
        for asset_id, traj in trajectories.items():
            esc = escalations.get(asset_id)
            a_signals = asset_signals.get(asset_id, [])
            a_meta = meta.get(asset_id, {})
            is_cj = a_meta.get("is_crown_jewel", False) or (esc.is_crown_jewel if esc else False)
            crit = a_meta.get("criticality", 0.5)

            # Warning 1: Critical Escalation Warning
            if esc and esc.predicted_state == EscalationState.CRITICAL_ESCALATION_RISK:
                w = self._create_warning(
                    asset_id=asset_id,
                    category=WarningCategory.CRITICAL_ESCALATION_WARNING,
                    severity=ThreatSeverity.CRITICAL,
                    current_risk=traj.current_risk,
                    criticality=crit,
                    is_crown_jewel=is_cj,
                    is_cluster_correlated=(asset_id in cluster_asset_map),
                    confidence=esc.confidence,
                    evidence=[
                        f"Threat state projected to enter CRITICAL_ESCALATION_RISK within {traj.forecast_horizon_hours:.0f} hours.",
                        f"Escalation score: {esc.escalation_risk_score:.1f} (Slope: {traj.slope:+.2f} pts/hr).",
                    ] + esc.evidence[:2],
                    explanation=f"Critical threat escalation imminent on asset {asset_id}. Behavioral anomaly triggers indicate impending breach threshold violation.",
                    predicted_impact=f"High probability of system compromise and lateral breach toward Crown Jewels.",
                    recommended_action="Execute immediate pre-emptive network segmentation and quarantine compromised credentials.",
                    contributing_signals=[s.signal_id for s in a_signals],
                    traj=traj,
                    now=now,
                )
                if w:
                    new_warnings.append(w)

            # Warning 2: Rapid Escalation Warning (Slope >= 3.0 pts/hr)
            elif traj.slope >= 3.0:
                w = self._create_warning(
                    asset_id=asset_id,
                    category=WarningCategory.RAPID_ESCALATION_WARNING,
                    severity=ThreatSeverity.HIGH,
                    current_risk=traj.current_risk,
                    criticality=crit,
                    is_crown_jewel=is_cj,
                    is_cluster_correlated=(asset_id in cluster_asset_map),
                    confidence=traj.projection_confidence,
                    evidence=[
                        f"Rapid risk acceleration detected: Slope {traj.slope:+.2f} pts/hr.",
                        f"Current risk: {traj.current_risk:.1f} -> Projected: {traj.projected_risk:.1f}.",
                    ],
                    explanation=f"Asset {asset_id} is escalating rapidly along its risk trajectory without sign of attenuation.",
                    predicted_impact=f"Risk projected to reach {traj.projected_risk:.1f} within {traj.forecast_horizon_hours:.0f} hours.",
                    recommended_action="Investigate active execution telemetry and review privileged session logs.",
                    contributing_signals=[s.signal_id for s in a_signals],
                    traj=traj,
                    now=now,
                )
                if w:
                    new_warnings.append(w)

            # Warning 3: Risk Trend Warning (CUSUM structural break or steady elevation)
            elif traj.change_point_detected:
                w = self._create_warning(
                    asset_id=asset_id,
                    category=WarningCategory.RISK_TREND_WARNING,
                    severity=ThreatSeverity.MEDIUM if traj.current_risk < 50.0 else ThreatSeverity.HIGH,
                    current_risk=traj.current_risk,
                    criticality=crit,
                    is_crown_jewel=is_cj,
                    is_cluster_correlated=(asset_id in cluster_asset_map),
                    confidence=traj.projection_confidence,
                    evidence=[
                        traj.change_point_description or "CUSUM structural break detected.",
                        f"Current moving average: {traj.moving_average:.1f}.",
                    ],
                    explanation=f"Statistical change-point break observed on asset {asset_id}. Trend deviates significantly from historical baseline.",
                    predicted_impact=f"Potential transition from dormant to active threat state.",
                    recommended_action="Audit system baseline configuration and verify scheduled jobs.",
                    contributing_signals=[s.signal_id for s in a_signals],
                    traj=traj,
                    now=now,
                )
                if w:
                    new_warnings.append(w)

            # Warning 4: Repeated Suspicious Activity Warning (>= 3 alerts)
            repeated_sigs = [s for s in a_signals if s.signal_type.value == "REPEATED_SUSPICIOUS_EVENTS"]
            if repeated_sigs:
                sig = repeated_sigs[0]
                w = self._create_warning(
                    asset_id=asset_id,
                    category=WarningCategory.REPEATED_SUSPICIOUS_ACTIVITY_WARNING,
                    severity=sig.severity,
                    current_risk=traj.current_risk,
                    criticality=crit,
                    is_crown_jewel=is_cj,
                    is_cluster_correlated=(asset_id in cluster_asset_map),
                    confidence=sig.confidence,
                    evidence=[sig.evidence],
                    explanation=f"Asset {asset_id} is exhibiting persistent anomalous event clusters over a concentrated timeframe.",
                    predicted_impact="Sustained adversary probing or automated brute-force execution.",
                    recommended_action="Block anomalous remote IP addresses and inspect host process parentage.",
                    contributing_signals=[sig.signal_id],
                    traj=traj,
                    now=now,
                )
                if w:
                    new_warnings.append(w)

        # ---------------------------------------------------------------------
        # 2. Correlated Cluster Warnings
        # ---------------------------------------------------------------------
        for c in active_clusters:
            primary_asset = c.related_asset_ids[0] if c.related_asset_ids else "network-cluster"
            w = self._create_warning(
                asset_id=primary_asset,
                category=WarningCategory.POTENTIAL_THREAT_CLUSTER_WARNING,
                severity=c.severity,
                current_risk=60.0 if c.severity == ThreatSeverity.CRITICAL else 40.0,
                criticality=0.8 if c.crown_jewels_at_risk else 0.5,
                is_crown_jewel=bool(c.crown_jewels_at_risk),
                is_cluster_correlated=True,
                confidence=c.confidence,
                evidence=c.graph_evidence,
                explanation=f"Graph correlation engine identified an emerging threat cluster: {c.cluster_name}. Connecting {len(c.related_asset_ids)} assets.",
                predicted_impact=f"Lateral propagation across {len(c.related_asset_ids)} hosts risking Crown Jewels: {', '.join(c.crown_jewels_at_risk) if c.crown_jewels_at_risk else 'None'}.",
                recommended_action=c.recommended_containment_posture,
                contributing_signals=[s.signal_id for s in c.signals],
                traj=None,
                now=now,
                affected_entities=c.related_asset_ids,
            )
            if w:
                new_warnings.append(w)

        # Sort all stored active warnings by priority descending
        return self.get_all_warnings()

    def _create_warning(
        self,
        asset_id: str,
        category: WarningCategory,
        severity: ThreatSeverity,
        current_risk: float,
        criticality: float,
        is_crown_jewel: bool,
        is_cluster_correlated: bool,
        confidence: float,
        evidence: List[str],
        explanation: str,
        predicted_impact: str,
        recommended_action: str,
        contributing_signals: List[str],
        traj: Optional[RiskTrajectory],
        now: datetime,
        affected_entities: Optional[List[str]] = None,
    ) -> Optional[EarlyWarning]:
        """Creates an early warning enforcing sliding-window deduplication and cooldown."""
        cooldown_key = f"{asset_id}:{category.value}"
        time_bucket = now.strftime("%Y%m%d%H")

        # Check cooldown: if warning emitted within cooldown_hours, suppress duplicate
        if cooldown_key in self._cooldown_index:
            existing_id, last_emitted = self._cooldown_index[cooldown_key]
            elapsed_hours = (now - last_emitted).total_seconds() / 3600.0
            if elapsed_hours < self.cooldown_hours:
                # Suppressed by cooldown to prevent alert fatigue
                logger.debug("Warning %s on %s suppressed by cooldown (%.1fh < %.1fh).", category.value, asset_id, elapsed_hours, self.cooldown_hours)
                return None

        # Build new warning
        warning_id = self._generate_warning_id(asset_id, category, time_bucket)
        priority = self.calculate_priority_score(
            severity=severity,
            current_risk=current_risk,
            criticality=criticality,
            is_crown_jewel=is_crown_jewel,
            is_cluster_correlated=is_cluster_correlated,
            confidence=confidence,
        )

        traj_summary = None
        if traj:
            traj_summary = {
                "slope": traj.slope,
                "current_risk": traj.current_risk,
                "projected_risk": traj.projected_risk,
                "trend_direction": traj.trend_direction.value,
                "volatility": traj.volatility,
            }

        entities = affected_entities or [asset_id]
        warning = EarlyWarning(
            warning_id=warning_id,
            asset_id=asset_id,
            affected_entities=entities,
            warning_type=category,
            severity=severity,
            priority_score=priority,
            status=WarningStatus.ACTIVE,
            generated_at=now,
            cooldown_until=now + timedelta(hours=self.cooldown_hours),
            observed_evidence=evidence,
            historical_context=f"Historical telemetry baseline shows current risk at {current_risk:.1f}.",
            explanation=explanation,
            confidence=confidence,
            predicted_impact=predicted_impact,
            recommended_action=recommended_action,
            contributing_signal_ids=contributing_signals,
            trajectory_summary=traj_summary,
        )

        self._warnings_store[warning_id] = warning
        self._cooldown_index[cooldown_key] = (warning_id, now)
        return warning

    def get_all_warnings(
        self,
        severity: Optional[str] = None,
        asset_id: Optional[str] = None,
        category: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[EarlyWarning]:
        """Retrieves prioritized warnings with optional filtering."""
        warnings = list(self._warnings_store.values())

        if severity:
            warnings = [w for w in warnings if w.severity.value == severity.upper()]
        if asset_id:
            warnings = [w for w in warnings if w.asset_id == asset_id or asset_id in w.affected_entities]
        if category:
            warnings = [w for w in warnings if w.warning_type.value.lower() == category.lower()]
        if status:
            warnings = [w for w in warnings if w.status.value == status.upper()]

        # Sort by priority score descending
        warnings.sort(key=lambda w: w.priority_score, reverse=True)
        return warnings

    def get_warning_by_id(self, warning_id: str) -> Optional[EarlyWarning]:
        """Retrieves a specific warning by identifier."""
        return self._warnings_store.get(warning_id)

    def acknowledge_warning(self, warning_id: str) -> bool:
        """Transitions warning status to ACKNOWLEDGED."""
        w = self._warnings_store.get(warning_id)
        if w:
            w.status = WarningStatus.ACKNOWLEDGED
            return True
        return False
