"""SafeContain AI 2.0 Autonomous Security Testing Domain Models.

Defines schemas for authorized, non-destructive vulnerability assessments,
service exposures, TLS evaluations, and finding-to-graph enrichment.
"""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field


class SecurityTestType(str, Enum):
    """Categories of authorized security verification."""
    PORT_SCAN = "PORT_SCAN"
    SERVICE_FINGERPRINT = "SERVICE_FINGERPRINT"
    TLS_VALIDATION = "TLS_VALIDATION"
    CVE_VULNERABILITY_MATCH = "CVE_VULNERABILITY_MATCH"
    FIREWALL_SEGMENTATION = "FIREWALL_SEGMENTATION"
    ENDPOINT_POSTURE = "ENDPOINT_POSTURE"


class SecurityTestSeverity(str, Enum):
    """Standard CVSS v3.1 severity tiers."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VerificationState(str, Enum):
    """Lifecycle state of an identified security finding."""
    CONFIRMED = "CONFIRMED"
    VERIFIED = "VERIFIED"
    SUSPECTED = "SUSPECTED"
    MITIGATED = "MITIGATED"


class SecurityFinding(BaseModel):
    """Structured security finding resulting from authorized platform inspection."""
    finding_id: str = Field(default_factory=lambda: f"fnd-{uuid.uuid4().hex[:8]}")
    target_asset_id: str
    target_ip: str
    test_type: SecurityTestType
    cve_id: Optional[str] = None
    title: str
    description: str
    severity: SecurityTestSeverity
    cvss_score: float = 0.0
    confidence: float = 1.0
    evidence: str
    recommendation: str
    verification_state: VerificationState = VerificationState.CONFIRMED
    discovered_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SecurityTestExecution(BaseModel):
    """Record of an executed security testing job."""
    execution_id: str = Field(default_factory=lambda: f"exec-{uuid.uuid4().hex[:8]}")
    test_name: str
    target_scope: List[str]
    start_time: str
    completion_time: Optional[str] = None
    status: str = "COMPLETED"
    targets_inspected: int
    findings_count: int
    findings: List[SecurityFinding]
    safety_profile_used: str = "NON_DESTRUCTIVE_READ_ONLY"


class LaunchSecurityTestRequest(BaseModel):
    """Payload to request an authorized security test execution."""
    target_asset_id: Optional[str] = None
    target_cidr: str = Field(default="10.0.0.0/16")
    test_types: List[SecurityTestType] = Field(default_factory=lambda: [
        SecurityTestType.SERVICE_FINGERPRINT,
        SecurityTestType.CVE_VULNERABILITY_MATCH,
        SecurityTestType.TLS_VALIDATION
    ])
    rate_limit_pps: int = Field(default=50, ge=10, le=500)
