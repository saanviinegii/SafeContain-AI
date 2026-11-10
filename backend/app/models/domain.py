"""SafeContain AI Unified Core Domain Models.

Formal enterprise Pydantic v2 domain representations for graph entities, relationships,
uncertainty assessments, risk metrics, business workflows, containment actions,
isolated simulations, approvals, and tamper-evident audit records.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


# =====================================================================
# ENUMERATIONS
# =====================================================================

class EvidenceStatus(str, Enum):
    """Cryptographic/forensic uncertainty state of security telemetry."""
    CONFIRMED = "CONFIRMED"      # Multi-source verified, fresh telemetry
    SUSPECTED = "SUSPECTED"      # Single unverified alert or heuristic indicator
    UNKNOWN = "UNKNOWN"          # Potential route with missing telemetry
    DISPUTED = "DISPUTED"        # Contradicting telemetry sources
    STALE = "STALE"              # Prior verified telemetry exceeding freshness threshold


class DataProvenance(str, Enum):
    """Attribution and source classification for auditing and compliance."""
    LIVE_TELEMETRY = "LIVE_TELEMETRY"
    SYNTHETIC = "SYNTHETIC"
    REPLAY = "REPLAY"
    IMPORTED_BASELINE = "IMPORTED_BASELINE"


class NodeType(str, Enum):
    """Normalized infrastructure and threat graph node types."""
    ORGANIZATION = "Organization"
    BUSINESS_UNIT = "BusinessUnit"
    NETWORK = "Network"
    SUBNET = "Subnet"
    HOST = "Host"
    SERVER = "Server"
    ENDPOINT = "Endpoint"
    CLOUD_RESOURCE = "CloudResource"
    APPLICATION = "Application"
    DATABASE = "Database"
    USER = "User"
    SERVICE_ACCOUNT = "ServiceAccount"
    PRIVILEGED_IDENTITY = "PrivilegedIdentity"
    SECURITY_CONTROL = "SecurityControl"
    VULNERABILITY = "Vulnerability"
    THREAT = "Threat"
    INCIDENT = "Incident"
    EVIDENCE = "Evidence"
    BUSINESS_WORKFLOW = "BusinessWorkflow"


class RelationshipType(str, Enum):
    """Normalized graph relationship edges."""
    CONNECTED_TO = "CONNECTED_TO"
    RUNS = "RUNS"
    HOSTS = "HOSTS"
    AUTHENTICATES_TO = "AUTHENTICATES_TO"
    HAS_ACCESS_TO = "HAS_ACCESS_TO"
    DEPENDS_ON = "DEPENDS_ON"
    CONTAINS = "CONTAINS"
    EXPOSED_TO = "EXPOSED_TO"
    VULNERABLE_TO = "VULNERABLE_TO"
    CONTROLLED_BY = "CONTROLLED_BY"
    SUPPORTS_WORKFLOW = "SUPPORTS_WORKFLOW"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    OBSERVED_IN = "OBSERVED_IN"


class SecurityActionType(str, Enum):
    """Formal cybersecurity containment intervention catalog."""
    ISOLATE_ENDPOINT = "ISOLATE_ENDPOINT"
    RESTRICT_NETWORK = "RESTRICT_NETWORK"
    DISABLE_ACCOUNT = "DISABLE_ACCOUNT"
    REVOKE_SESSION = "REVOKE_SESSION"
    ROTATE_CREDENTIALS = "ROTATE_CREDENTIALS"
    ENFORCE_MFA = "ENFORCE_MFA"
    REMOVE_PRIVILEGES = "REMOVE_PRIVILEGES"
    APPLY_FIREWALL_RULE = "APPLY_FIREWALL_RULE"
    PATCH_VULNERABILITY = "PATCH_VULNERABILITY"
    RESTRICT_RESOURCE_ACCESS = "RESTRICT_RESOURCE_ACCESS"
    SINKHOLE_DNS = "SINKHOLE_DNS"
    INCREASE_MONITORING = "INCREASE_MONITORING"


class ApprovalStatus(str, Enum):
    """Strict human-in-the-loop decision state machine."""
    DRAFT = "DRAFT"
    ANALYZED = "ANALYZED"
    SIMULATED = "SIMULATED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTION_AUTHORIZED = "EXECUTION_AUTHORIZED"


class UserRole(str, Enum):
    """Enterprise governance and separation-of-duties role hierarchy."""
    PLATFORM_ADMIN = "PLATFORM_ADMIN"
    SECURITY_ADMIN = "SECURITY_ADMIN"
    SOC_ANALYST = "SOC_ANALYST"
    INCIDENT_RESPONDER = "INCIDENT_RESPONDER"
    INCIDENT_COMMANDER = "INCIDENT_COMMANDER"
    SECURITY_MANAGER = "SECURITY_MANAGER"
    AUDITOR = "AUDITOR"
    READ_ONLY_VIEWER = "READ_ONLY_VIEWER"


class WorkflowCriticality(str, Enum):
    """Impact tier for business continuity digital twin."""
    TIER_1_MISSION_CRITICAL = "TIER_1_MISSION_CRITICAL"  # Citizen service, emergency, live payments
    TIER_2_BUSINESS_CRITICAL = "TIER_2_BUSINESS_CRITICAL" # Customer operations, core ERP
    TIER_3_OPERATIONAL = "TIER_3_OPERATIONAL"             # Internal reporting, developer tooling
    TIER_4_NON_CRITICAL = "TIER_4_NON_CRITICAL"           # Batch archiving, telemetry mirrors


# =====================================================================
# CORE GRAPH & TELEMETRY MODELS
# =====================================================================

class GraphNode(BaseModel):
    """Standardized node entity in the infrastructure graph."""
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(description="Unique entity identifier across systems")
    name: str = Field(description="Human readable name")
    type: NodeType = Field(description="Normalized node class")
    criticality: float = Field(default=0.5, ge=0.0, le=1.0, description="Asset importance [0.0 - 1.0]")
    is_compromised: bool = Field(default=False, description="Flagged by active threat detection")
    is_crown_jewel: bool = Field(default=False, description="Explicit mission-critical target asset")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Metadata key-value attributes")
    provenance: DataProvenance = Field(default=DataProvenance.LIVE_TELEMETRY)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GraphEdge(BaseModel):
    """Standardized directed edge representing relationship or network connectivity."""
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(description="Unique edge identifier")
    source: str = Field(description="Source node ID")
    target: str = Field(description="Target node ID")
    type: RelationshipType = Field(description="Semantic relationship type")
    evidence_status: EvidenceStatus = Field(default=EvidenceStatus.CONFIRMED)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Evidence confidence score [0.0 - 1.0]")
    weight: float = Field(default=1.0, gt=0.0, description="Traversal difficulty or cost weight")
    is_active: bool = Field(default=True, description="False if severed or contained")
    evidence_reference: Optional[str] = Field(default=None, description="Primary reference ID to forensic evidence record")
    evidence_references: List[str] = Field(default_factory=list, description="Supporting evidence record IDs")
    properties: Dict[str, Any] = Field(default_factory=dict)
    provenance: DataProvenance = Field(default=DataProvenance.LIVE_TELEMETRY)
    last_verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EvidenceRecord(BaseModel):
    """Detailed forensic evidence item substantiating an entity or relationship."""
    id: str
    source_system: str = Field(description="e.g. CrowdStrike, Splunk, Okta, Azure Sentinel")
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: EvidenceStatus = Field(default=EvidenceStatus.CONFIRMED)
    confidence_score: float = Field(default=0.9, ge=0.0, le=1.0)
    raw_payload_hash: str = Field(description="SHA-256 hash of original raw log record")
    associated_entity_id: str
    details: Dict[str, Any] = Field(default_factory=dict)
    provenance: DataProvenance = Field(default=DataProvenance.LIVE_TELEMETRY)


# =====================================================================
# ATTACK PATH & RISK INTELLIGENCE MODELS
# =====================================================================

class AttackPath(BaseModel):
    """Exploitable sequence of edges leading to critical infrastructure."""
    id: str
    source_id: str = Field(description="Compromised entry point or attacker-controlled node")
    target_id: str = Field(description="Critical asset or crown jewel target")
    node_sequence: List[str] = Field(description="Ordered list of node IDs in traversal order")
    edge_sequence: List[str] = Field(description="Ordered list of edge IDs traversed")
    hop_count: int = Field(ge=1)
    inherent_path_risk: float = Field(ge=0.0, le=100.0)
    confidence_score: float = Field(ge=0.0, le=1.0, description="Minimum edge confidence along path")
    uncertainty_penalty: float = Field(ge=0.0, description="Risk addition due to suspected/unknown links")
    adjusted_path_risk: float = Field(ge=0.0, le=100.0)
    is_residual: bool = Field(default=False, description="Path remained viable after simulated containment")
    choke_point_nodes: List[str] = Field(default_factory=list, description="Crucial cut-nodes")
    explanation: str = Field(description="Plain-language human-readable explanation of traversal path")


class RiskDecomposition(BaseModel):
    """Transparent multi-factor risk decomposition."""
    inherent_risk: float = Field(ge=0.0, le=100.0, description="Baseline risk without security controls")
    observed_risk: float = Field(ge=0.0, le=100.0, description="Active risk based on confirmed telemetry")
    potential_risk: float = Field(ge=0.0, le=100.0, description="Risk including suspected/unverified paths")
    residual_risk: float = Field(ge=0.0, le=100.0, description="Calculated risk remaining post-intervention")
    uncertainty_penalty: float = Field(ge=0.0, description="Uncertainty weighting factor")
    uncertainty_adjusted_risk: float = Field(ge=0.0, le=100.0)
    asset_criticality_factor: float = Field(ge=0.0, le=1.0)
    path_reachability_factor: float = Field(ge=0.0, le=1.0)
    vulnerability_severity_factor: float = Field(ge=0.0, le=1.0)
    contributing_factors: List[Dict[str, Any]] = Field(default_factory=list)


# =====================================================================
# BUSINESS CONTINUITY DIGITAL TWIN MODELS
# =====================================================================

class BusinessWorkflow(BaseModel):
    """Mission-critical organizational or citizen service workflow."""
    id: str
    name: str
    criticality: WorkflowCriticality
    citizen_facing: bool = False
    dependent_asset_ids: List[str] = Field(default_factory=list, description="Host/DB/App nodes supporting this")
    max_allowable_downtime_hours: float = 0.0
    estimated_hourly_downtime_cost: float = 10000.0
    active_incident_count: int = 0
    operational_status: str = "HEALTHY" # HEALTHY | DEGRADED | AT_RISK | DISRUPTED


class WorkflowDisruptionAssessment(BaseModel):
    """Impact of proposed containment on business continuity."""
    workflow_id: str
    workflow_name: str
    criticality: WorkflowCriticality
    is_disrupted: bool
    estimated_downtime_hours: float
    financial_impact: float
    violates_sla: bool
    disrupting_action_ids: List[str] = Field(default_factory=list)


# =====================================================================
# RESPONSE PLANNING & OPTIMIZATION MODELS
# =====================================================================

class ContainmentAction(BaseModel):
    """Actionable cybersecurity intervention item."""
    id: str
    action_type: SecurityActionType
    target_node_id: str
    target_node_name: str
    estimated_risk_reduction: float = Field(ge=0.0, le=100.0)
    operational_disruption_score: float = Field(ge=0.0, le=100.0, description="Impact on business workflows")
    implementation_cost: float = Field(ge=0.0, description="Financial/operational implementation cost")
    estimated_duration_minutes: int = Field(ge=1)
    reversibility: bool = True
    required_role: UserRole = UserRole.SECURITY_ADMIN
    preconditions: List[str] = Field(default_factory=list)
    mitigated_path_ids: List[str] = Field(default_factory=list)
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    rationale: str


class OptimizationStrategy(str, Enum):
    """Strategy tiers defined in product specification."""
    BASELINE_SEVERITY = "BASELINE_SEVERITY"
    GREEDY_RISK_COST = "GREEDY_RISK_COST"
    CONSTRAINT_CPSAT = "CONSTRAINT_CPSAT"


class ContainmentPlan(BaseModel):
    """Complete, evaluated containment strategy recommendation."""
    id: str
    strategy: OptimizationStrategy
    actions: List[ContainmentAction]
    total_cost: float
    total_disruption_score: float
    predicted_risk_reduction: float
    predicted_residual_risk: float
    satisfies_all_constraints: bool
    constraint_violations: List[str] = Field(default_factory=list)
    objective_score: float
    status: ApprovalStatus = ApprovalStatus.DRAFT
    explanation: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# =====================================================================
# SIMULATION & DECISION INTELLIGENCE MODELS
# =====================================================================

class SimulationResult(BaseModel):
    """Forensically isolated simulation execution result."""
    simulation_id: str
    scenario_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    applied_action_ids: List[str]
    initial_attack_path_count: int
    residual_attack_path_count: int
    initial_risk_score: float
    residual_risk_score: float
    risk_reduction_achieved: float
    disrupted_workflows: List[WorkflowDisruptionAssessment]
    residual_paths: List[AttackPath]
    unprotected_crown_jewels: List[str]
    is_fully_contained: bool
    explanation: str
    audit_hash: str


# =====================================================================
# GOVERNANCE, RBAC & AUDIT LEDGER MODELS
# =====================================================================

class AuditEvent(BaseModel):
    """Cryptographically chained tamper-evident audit record matching R&D on-chain specification."""
    event_id: str = Field(description="Unique record identifier")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str = Field(default="DECISION_EVENT", description="On-chain event type: EVIDENCE_SNAPSHOT | RECOMMENDATION | SIMULATION_SUMMARY | APPROVAL")
    approval_reference: Optional[str] = Field(default=None, description="Minimal on-chain approval reference / signature")
    actor_id: str
    actor_role: UserRole
    organization_id: str = "ORG-DEFAULT"
    action: str
    resource_type: str
    resource_id: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    previous_hash: str = Field(description="SHA-256 hash of previous block/event")
    current_hash: str = Field(description="SHA-256 hash of this record including previous_hash")
