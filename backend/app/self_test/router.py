"""SafeContain AI 2.0 Autonomous Platform Self-Testing REST Router.

Exposes endpoints to trigger real-time 7-tier architectural diagnostics,
inspect circuit-breaker health, and verify platform components.
"""

from __future__ import annotations
from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status

from backend.app.security.auth import require_admin, require_analyst, require_viewer
from backend.app.security.user_store import UserRecord
from backend.app.self_test.harness import platform_self_test_harness
from backend.app.self_test.models import PlatformSelfTestReport

router = APIRouter(prefix="/self-test", tags=["Autonomous Platform Self-Testing"])


@router.get("/status")
def get_self_test_status(current_user: UserRecord = Depends(require_viewer)) -> Dict[str, Any]:
    """Returns quick circuit breaker state and last test execution summary."""
    last_rep = platform_self_test_harness.get_last_report()
    if not last_rep:
        return {
            "status": "INITIALIZING",
            "platform_state": "HEALTHY_AUTONOMOUS",
            "circuit_breaker_tripped": False,
            "message": "Platform initialized. Run POST /api/v1/self-test/run to execute baseline diagnostic.",
        }

    return {
        "status": "OPERATIONAL",
        "platform_state": last_rep.platform_state.value,
        "circuit_breaker_tripped": last_rep.circuit_breaker_tripped,
        "total_tests": last_rep.total_tests,
        "passed_tests": last_rep.passed_tests,
        "failed_tests": last_rep.failed_tests,
        "last_diagnostic_timestamp": last_rep.timestamp,
        "execution_duration_ms": last_rep.total_duration_ms,
    }


@router.get("/report", response_model=PlatformSelfTestReport)
def get_last_diagnostic_report(current_user: UserRecord = Depends(require_viewer)) -> PlatformSelfTestReport:
    """Retrieves full itemized report of the last 7-tier architectural self-test."""
    from backend.app.api.v1.router import platform_ctx

    rep = platform_self_test_harness.get_last_report()
    if not rep:
        rep = platform_self_test_harness.run_full_diagnostic(platform_ctx)
    return rep


@router.post("/run", response_model=PlatformSelfTestReport, status_code=status.HTTP_200_OK)
def run_platform_diagnostic(current_user: UserRecord = Depends(require_analyst)) -> PlatformSelfTestReport:
    """Executes on-demand comprehensive 7-tier platform self-test (requires ANALYST/ADMIN)."""
    from backend.app.api.v1.router import platform_ctx

    report = platform_self_test_harness.run_full_diagnostic(platform_ctx)
    return report
