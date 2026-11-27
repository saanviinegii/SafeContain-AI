"""SafeContain AI 2.0 Autonomous Security Testing REST Router.

Exposes endpoints to launch authorized, safe vulnerability tests,
inspect findings, view audit traces, and track infrastructure security posture.
"""

from __future__ import annotations
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.app.security.auth import require_admin, require_analyst, require_viewer
from backend.app.security.user_store import UserRecord
from backend.app.security_testing.models import (
    LaunchSecurityTestRequest,
    SecurityFinding,
    SecurityTestExecution,
)
from backend.app.security_testing.orchestrator import security_testing_orchestrator

router = APIRouter(prefix="/security-testing", tags=["Autonomous Security Testing"])


@router.get("/status")
def get_security_testing_status(current_user: UserRecord = Depends(require_viewer)) -> Dict[str, Any]:
    """Returns the operational status of the autonomous security testing engine."""
    executions = security_testing_orchestrator.list_executions()
    findings = security_testing_orchestrator.list_all_findings()

    return {
        "status": "OPERATIONAL",
        "mode": "AUTHORIZED_NON_DESTRUCTIVE",
        "safety_guardrails_active": True,
        "total_executions": len(executions),
        "total_active_findings": len(findings),
        "critical_findings_count": sum(1 for f in findings if f.severity.value == "CRITICAL"),
        "high_findings_count": sum(1 for f in findings if f.severity.value == "HIGH"),
        "last_execution": executions[0] if executions else None,
    }


@router.get("/executions", response_model=List[SecurityTestExecution])
def list_test_executions(current_user: UserRecord = Depends(require_viewer)) -> List[SecurityTestExecution]:
    """Returns chronological audit records of all security test runs."""
    return security_testing_orchestrator.list_executions()


@router.get("/findings", response_model=List[SecurityFinding])
def list_security_findings(
    severity: str = Query(None, description="Optional severity filter (CRITICAL, HIGH, MEDIUM, LOW)"),
    current_user: UserRecord = Depends(require_viewer)
) -> List[SecurityFinding]:
    """Retrieves all confirmed and verified vulnerability findings."""
    all_findings = security_testing_orchestrator.list_all_findings()
    if severity:
        sev_upper = severity.upper()
        return [f for f in all_findings if f.severity.value == sev_upper]
    return all_findings


@router.post("/launch", response_model=SecurityTestExecution, status_code=status.HTTP_201_CREATED)
def launch_authorized_security_test(
    request: LaunchSecurityTestRequest,
    current_user: UserRecord = Depends(require_analyst)
) -> SecurityTestExecution:
    """Launches an authorized, non-destructive security test across pre-approved scope."""
    from backend.app.api.v1.router import platform_ctx

    try:
        execution = security_testing_orchestrator.launch_test(request, platform_ctx)
        return execution
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
