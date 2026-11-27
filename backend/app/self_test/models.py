"""SafeContain AI 2.0 Autonomous Platform Self-Testing Domain Models.

Defines schemas for testing the SafeContain AI application itself across
7 architectural tiers with automated circuit-breaker protection.
"""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field


class TestTier(str, Enum):
    """The 7 internal architectural validation tiers of SafeContain AI 2.0."""
    TIER_1_FRONTEND = "TIER_1_FRONTEND"
    TIER_2_BACKEND_API = "TIER_2_BACKEND_API"
    TIER_3_NEO4J_GRAPH = "TIER_3_NEO4J_GRAPH"
    TIER_4_AIML_SHAP = "TIER_4_AIML_SHAP"
    TIER_5_CPSAT_OPTIMIZER = "TIER_5_CPSAT_OPTIMIZER"
    TIER_6_DATASET_INGESTION = "TIER_6_DATASET_INGESTION"
    TIER_7_AUDIT_MERKLE = "TIER_7_AUDIT_MERKLE"


class TestStatus(str, Enum):
    """Outcome state of an individual component test."""
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class PlatformHealthState(str, Enum):
    """Circuit breaker operational state."""
    HEALTHY_AUTONOMOUS = "HEALTHY_AUTONOMOUS"
    DEGRADED_MANUAL = "DEGRADED_MANUAL"
    CRITICAL_STOPPED = "CRITICAL_STOPPED"


class ComponentTestCaseResult(BaseModel):
    """Result of an individual self-diagnostic test."""
    test_id: str
    tier: TestTier
    test_name: str
    status: TestStatus
    duration_ms: float
    evidence: str
    error_message: Optional[str] = None
    recommended_action: Optional[str] = None


class PlatformSelfTestReport(BaseModel):
    """Aggregated self-diagnostic audit report across all 7 architectural tiers."""
    report_id: str = Field(default_factory=lambda: f"diag-{uuid.uuid4().hex[:8]}")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    platform_state: PlatformHealthState = PlatformHealthState.HEALTHY_AUTONOMOUS
    total_tests: int
    passed_tests: int
    failed_tests: int
    skipped_tests: int
    total_duration_ms: float
    circuit_breaker_tripped: bool = False
    tier_summaries: Dict[str, Dict[str, Any]]
    test_cases: List[ComponentTestCaseResult]
