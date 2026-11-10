"""SafeContain AI Tamper-Evident Cryptographic Audit Ledger.

Implements sequential SHA-256 hash chaining across all security decisions,
data ingestions, simulations, and approvals. Provides forward integrity verification
detecting unauthorized tampering or log manipulation.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.app.core.config import settings
from backend.app.models.domain import AuditEvent, UserRole
from backend.app.audit.blockchain import BlockchainLedgerAnchor, BlockchainVerificationResult


class AuditIntegrityReport(BaseModel):
    """Result of full cryptographic audit ledger verification."""
    is_valid: bool
    total_events_checked: int
    tampered_index: Optional[int] = None
    tampered_event_id: Optional[str] = None
    expected_hash: Optional[str] = None
    actual_hash: Optional[str] = None
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status_summary: str


class ChainedAuditLedger:
    """Cryptographic SHA-256 Hash-Chained Audit Ledger."""

    GENESIS_HASH: str = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self, storage_path: Optional[str] = None):
        self.storage_path = storage_path or settings.AUDIT_LEDGER_STORAGE_PATH
        self._events: List[AuditEvent] = []
        self.blockchain_anchor = BlockchainLedgerAnchor()
        self._load_or_initialize()

    def _load_or_initialize(self) -> None:
        """Loads existing ledger entries from disk or initializes empty."""
        self._events = []
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            event = AuditEvent.model_validate_json(line)
                            self._events.append(event)
                            self.blockchain_anchor.anchor_event(event)
            except Exception:
                pass

    @classmethod
    def compute_record_hash(
        cls,
        event_id: str,
        timestamp_str: str,
        actor_id: str,
        actor_role: str,
        organization_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        metadata: Dict[str, Any],
        previous_hash: str,
        event_type: str = "DECISION_EVENT",
        approval_reference: Optional[str] = None,
    ) -> str:
        """Computes deterministic SHA-256 hash across canonical record fields matching R&D on-chain design."""
        app_ref_str = approval_reference or ""
        canonical_str = (
            f"{event_id}|{timestamp_str}|{event_type}|{app_ref_str}|"
            f"{actor_id}|{actor_role}|{organization_id}|"
            f"{action}|{resource_type}|{resource_id}|"
            f"{json.dumps(metadata, sort_keys=True)}|{previous_hash}"
        )
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    def record_event(
        self,
        actor_id: str,
        actor_role: UserRole,
        action: str,
        resource_type: str,
        resource_id: str,
        metadata: Optional[Dict[str, Any]] = None,
        organization_id: str = "ORG-DEFAULT",
        event_type: str = "DECISION_EVENT",
        approval_reference: Optional[str] = None,
    ) -> AuditEvent:
        """Appends a new cryptographically chained audit event and anchors on blockchain ledger."""
        now = datetime.now(timezone.utc)
        event_id = f"aud-{len(self._events) + 1:06d}-{now.strftime('%Y%m%d%H%M%S')}"
        meta = metadata or {}

        previous_hash = (
            self._events[-1].current_hash if self._events else self.GENESIS_HASH
        )

        curr_hash = self.compute_record_hash(
            event_id=event_id,
            timestamp_str=now.isoformat(),
            actor_id=actor_id,
            actor_role=actor_role.value if hasattr(actor_role, "value") else str(actor_role),
            organization_id=organization_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            metadata=meta,
            previous_hash=previous_hash,
            event_type=event_type,
            approval_reference=approval_reference,
        )

        event = AuditEvent(
            event_id=event_id,
            timestamp=now,
            event_type=event_type,
            approval_reference=approval_reference,
            actor_id=actor_id,
            actor_role=actor_role,
            organization_id=organization_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            metadata=meta,
            previous_hash=previous_hash,
            current_hash=curr_hash,
        )

        self._events.append(event)
        self._persist_event(event)
        self.blockchain_anchor.anchor_event(event)
        return event

    def record_evidence_snapshot(
        self,
        evidence_id: str,
        source_system: str,
        raw_payload_hash: str,
        status: str,
        confidence: float,
        actor_id: str = "system",
        actor_role: UserRole = UserRole.SOC_ANALYST,
    ) -> AuditEvent:
        """Anchors an evidence snapshot hash (R&D Blueprint Objective #7)."""
        return self.record_event(
            actor_id=actor_id,
            actor_role=actor_role,
            action="EVIDENCE_SNAPSHOT_ANCHOR",
            event_type="EVIDENCE_SNAPSHOT",
            resource_type="EvidenceRecord",
            resource_id=evidence_id,
            metadata={
                "source_system": source_system,
                "raw_payload_hash": raw_payload_hash,
                "evidence_status": status,
                "confidence_score": confidence,
            },
        )

    def record_recommendation(
        self,
        plan_id: str,
        strategy: str,
        objective_score: float,
        total_cost: float,
        predicted_risk_reduction: float,
        actions_count: int,
        actor_id: str = "optimizer",
        actor_role: UserRole = UserRole.INCIDENT_COMMANDER,
    ) -> AuditEvent:
        """Anchors an optimization recommendation (R&D Blueprint Objective #7)."""
        return self.record_event(
            actor_id=actor_id,
            actor_role=actor_role,
            action="RECOMMENDATION_ANCHOR",
            event_type="RECOMMENDATION",
            resource_type="ContainmentPlan",
            resource_id=plan_id,
            metadata={
                "strategy": strategy,
                "objective_score": objective_score,
                "total_cost": total_cost,
                "predicted_risk_reduction": predicted_risk_reduction,
                "actions_count": actions_count,
            },
        )

    def record_simulation_summary(
        self,
        simulation_id: str,
        scenario_id: str,
        initial_risk: float,
        residual_risk: float,
        blocked_paths_count: int,
        residual_paths_count: int,
        disrupted_workflows_count: int,
        actor_id: str = "simulator",
        actor_role: UserRole = UserRole.SOC_ANALYST,
    ) -> AuditEvent:
        """Anchors a simulation execution summary (R&D Blueprint Objective #7)."""
        return self.record_event(
            actor_id=actor_id,
            actor_role=actor_role,
            action="SIMULATION_SUMMARY_ANCHOR",
            event_type="SIMULATION_SUMMARY",
            resource_type="SimulationResult",
            resource_id=simulation_id,
            metadata={
                "scenario_id": scenario_id,
                "initial_risk_score": initial_risk,
                "residual_risk_score": residual_risk,
                "blocked_paths_count": blocked_paths_count,
                "residual_paths_count": residual_paths_count,
                "disrupted_workflows_count": disrupted_workflows_count,
            },
        )

    def record_approval(
        self,
        plan_id: str,
        approval_status: str,
        approval_reference: str,
        actor_id: str,
        actor_role: UserRole,
        notes: str = "",
    ) -> AuditEvent:
        """Anchors a governance approval decision (R&D Blueprint Objective #7)."""
        return self.record_event(
            actor_id=actor_id,
            actor_role=actor_role,
            action=f"GOVERNANCE_{approval_status}",
            event_type="APPROVAL",
            approval_reference=approval_reference,
            resource_type="ContainmentPlan",
            resource_id=plan_id,
            metadata={
                "target_status": approval_status,
                "approval_reference": approval_reference,
                "review_notes": notes,
            },
        )

    def _persist_event(self, event: AuditEvent) -> None:
        """Persists single event line to JSONL storage."""
        try:
            parent_dir = os.path.dirname(self.storage_path)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir, exist_ok=True)
            with open(self.storage_path, "a", encoding="utf-8") as f:
                f.write(event.model_dump_json() + "\n")
        except Exception:
            pass

    def verify_integrity(self) -> AuditIntegrityReport:
        """Performs full forward cryptographic validation of the ledger chain."""
        if not self._events:
            return AuditIntegrityReport(
                is_valid=True,
                total_events_checked=0,
                status_summary="Ledger is empty (Genesis state).",
            )

        expected_prev_hash = self.GENESIS_HASH

        for idx, event in enumerate(self._events):
            # 1. Validate previous_hash pointer
            if event.previous_hash != expected_prev_hash:
                return AuditIntegrityReport(
                    is_valid=False,
                    total_events_checked=idx,
                    tampered_index=idx,
                    tampered_event_id=event.event_id,
                    expected_hash=expected_prev_hash,
                    actual_hash=event.previous_hash,
                    status_summary=f"Chain broken at record #{idx}: previous_hash pointer mismatch.",
                )

            # 2. Re-compute current hash from canonical contents
            computed_current = self.compute_record_hash(
                event_id=event.event_id,
                timestamp_str=event.timestamp.isoformat(),
                actor_id=event.actor_id,
                actor_role=event.actor_role.value if hasattr(event.actor_role, "value") else str(event.actor_role),
                organization_id=event.organization_id,
                action=event.action,
                resource_type=event.resource_type,
                resource_id=event.resource_id,
                metadata=event.metadata,
                previous_hash=event.previous_hash,
                event_type=event.event_type,
                approval_reference=event.approval_reference,
            )

            if computed_current != event.current_hash:
                return AuditIntegrityReport(
                    is_valid=False,
                    total_events_checked=idx,
                    tampered_index=idx,
                    tampered_event_id=event.event_id,
                    expected_hash=computed_current,
                    actual_hash=event.current_hash,
                    status_summary=f"Data tampering detected at record #{idx}: content hash recomputation failed.",
                )

            expected_prev_hash = event.current_hash

        return AuditIntegrityReport(
            is_valid=True,
            total_events_checked=len(self._events),
            status_summary=f"Ledger verified. All {len(self._events)} records cryptographically intact.",
        )

    def verify_blockchain_integrity(self, event_id: str) -> BlockchainVerificationResult:
        """Verifies off-chain record against on-chain smart contract anchor."""
        event = next((e for e in self._events if e.event_id == event_id), None)
        if not event:
            return BlockchainVerificationResult(
                is_valid=False,
                record_id=event_id,
                recomputed_off_chain_hash="N/A",
                verification_message=f"Event ID {event_id} not found in off-chain store.",
                tamper_detected=False,
            )

        # Recompute hash
        recomputed = self.compute_record_hash(
            event_id=event.event_id,
            timestamp_str=event.timestamp.isoformat(),
            actor_id=event.actor_id,
            actor_role=event.actor_role.value if hasattr(event.actor_role, "value") else str(event.actor_role),
            organization_id=event.organization_id,
            action=event.action,
            resource_type=event.resource_type,
            resource_id=event.resource_id,
            metadata=event.metadata,
            previous_hash=event.previous_hash,
            event_type=event.event_type,
            approval_reference=event.approval_reference,
        )

        return self.blockchain_anchor.verify_event(event, recomputed)

    def get_events(self, limit: int = 100) -> List[AuditEvent]:
        """Returns recent audit events in reverse chronological order."""
        return list(reversed(self._events[-limit:]))
