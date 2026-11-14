"""SafeContain AI Multi-Tier Governance and Human-in-the-Loop Approval Workflow.

Enforces strict separation of duties, role hierarchy, and multi-step containment lifecycle:
DRAFT -> ANALYZED -> SIMULATED -> PENDING_APPROVAL -> APPROVED / REJECTED -> EXECUTION_AUTHORIZED
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from backend.app.models.domain import (
    ApprovalStatus,
    ContainmentPlan,
    UserRole,
)


class GovernanceDecision(BaseModel):
    """Recorded human decision on a containment plan."""
    decision_id: str = Field(default_factory=lambda: f"dec-{uuid.uuid4().hex[:12]}")
    plan_id: str
    decision: ApprovalStatus # APPROVED | REJECTED | EXECUTION_AUTHORIZED
    actor_id: str
    actor_role: UserRole
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notes: str
    rejection_reason: Optional[str] = None


class GovernanceWorkflow:
    """Manages containment plan governance lifecycle and role authorization."""

    # Role permission matrix for approval transitions
    ROLE_PERMISSIONS: Dict[ApprovalStatus, List[UserRole]] = {
        ApprovalStatus.ANALYZED: [
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
            UserRole.SECURITY_ADMIN,
            UserRole.SECURITY_MANAGER,
            UserRole.INCIDENT_COMMANDER,
            UserRole.PLATFORM_ADMIN,
        ],
        ApprovalStatus.SIMULATED: [
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
            UserRole.SECURITY_ADMIN,
            UserRole.SECURITY_MANAGER,
            UserRole.INCIDENT_COMMANDER,
            UserRole.PLATFORM_ADMIN,
        ],
        ApprovalStatus.PENDING_APPROVAL: [
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
            UserRole.SECURITY_ADMIN,
            UserRole.SECURITY_MANAGER,
            UserRole.INCIDENT_COMMANDER,
        ],
        ApprovalStatus.PENDING: [
            UserRole.SOC_ANALYST,
            UserRole.INCIDENT_RESPONDER,
            UserRole.SECURITY_ADMIN,
            UserRole.SECURITY_MANAGER,
            UserRole.INCIDENT_COMMANDER,
        ],
        ApprovalStatus.APPROVED: [
            UserRole.SECURITY_MANAGER,
            UserRole.SECURITY_ADMIN,
            UserRole.INCIDENT_COMMANDER,
        ],
        ApprovalStatus.REJECTED: [
            UserRole.SECURITY_MANAGER,
            UserRole.SECURITY_ADMIN,
            UserRole.INCIDENT_COMMANDER,
            UserRole.INCIDENT_RESPONDER,
        ],
        ApprovalStatus.REVISION_REQUESTED: [
            UserRole.SECURITY_MANAGER,
            UserRole.SECURITY_ADMIN,
            UserRole.INCIDENT_COMMANDER,
            UserRole.INCIDENT_RESPONDER,
        ],
        ApprovalStatus.EXECUTION_AUTHORIZED: [
            UserRole.SECURITY_MANAGER,
            UserRole.INCIDENT_COMMANDER,
            UserRole.PLATFORM_ADMIN,
        ],
    }

    # Strict state transition table
    VALID_TRANSITIONS: Dict[ApprovalStatus, List[ApprovalStatus]] = {
        ApprovalStatus.DRAFT: [ApprovalStatus.ANALYZED],
        ApprovalStatus.ANALYZED: [ApprovalStatus.SIMULATED],
        ApprovalStatus.SIMULATED: [ApprovalStatus.PENDING_APPROVAL, ApprovalStatus.PENDING],
        ApprovalStatus.PENDING_APPROVAL: [ApprovalStatus.APPROVED, ApprovalStatus.REJECTED, ApprovalStatus.REVISION_REQUESTED],
        ApprovalStatus.PENDING: [ApprovalStatus.APPROVED, ApprovalStatus.REJECTED, ApprovalStatus.REVISION_REQUESTED],
        ApprovalStatus.APPROVED: [ApprovalStatus.EXECUTION_AUTHORIZED, ApprovalStatus.REJECTED, ApprovalStatus.REVISION_REQUESTED],
        ApprovalStatus.REJECTED: [ApprovalStatus.DRAFT], # Re-planning required
        ApprovalStatus.REVISION_REQUESTED: [ApprovalStatus.DRAFT, ApprovalStatus.ANALYZED],
        ApprovalStatus.EXECUTION_AUTHORIZED: [], # Terminal governance state
    }

    @classmethod
    def can_transition(
        cls,
        current_status: ApprovalStatus,
        target_status: ApprovalStatus,
        actor_role: UserRole
    ) -> Tuple[bool, Optional[str]]:
        """Verifies both state machine transition legality and actor authorization."""
        # Check transition validity
        allowed_next = cls.VALID_TRANSITIONS.get(current_status, [])
        if target_status not in allowed_next:
            return False, f"Illegal state transition from '{current_status.value}' to '{target_status.value}'."

        # Check role permission
        authorized_roles = cls.ROLE_PERMISSIONS.get(target_status, [])
        if actor_role not in authorized_roles:
            return False, f"Role '{actor_role.value}' is not authorized to transition to '{target_status.value}'."

        return True, None

    @classmethod
    def transition_plan(
        cls,
        plan: ContainmentPlan,
        target_status: ApprovalStatus,
        actor_id: str,
        actor_role: UserRole,
        notes: str = "",
        rejection_reason: Optional[str] = None
    ) -> Tuple[ContainmentPlan, GovernanceDecision]:
        """Applies an authorized governance transition to a containment plan."""
        can_proceed, error_msg = cls.can_transition(plan.status, target_status, actor_role)
        if not can_proceed:
            raise PermissionError(error_msg)

        plan.status = target_status
        decision = GovernanceDecision(
            plan_id=plan.id,
            decision=target_status,
            actor_id=actor_id,
            actor_role=actor_role,
            notes=notes,
            rejection_reason=rejection_reason,
        )
        return plan, decision
