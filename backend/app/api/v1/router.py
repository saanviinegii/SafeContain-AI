"""SafeContain AI Primary REST API Router (v1).

Exposes full functional endpoints for graph intelligence, attack paths, evidence uncertainty,
decomposed risk, business twin, tri-level optimization, isolated simulation,
counterfactual explanation, multi-tier governance, and cryptographic audit.
"""

import io
import json
import os
import uuid
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel, Field

from backend.app.core.config import settings
from backend.app.audit.ledger import AuditIntegrityReport, ChainedAuditLedger
from backend.app.audit.anchor_service import CreateAnchorRequest, AnchorResponse, AnchorPreview
from backend.app.audit.anchor_storage import StoredAnchorManifest
from backend.app.audit.verifier import EvidenceVerificationResult, VerificationStatus
from backend.app.audit.tamper_demo import TamperDemoReport
from backend.app.audit.merkle import MerkleProof
from backend.app.business.twin import BusinessContinuityTwin
from backend.app.evidence.engine import EvidenceEngine, SensitivityScenarioResult
from backend.app.explanation.engine import DecisionExplainer
from backend.app.graph.engine import GraphEngine
from backend.app.ingestion.connectors import (
    EDRConnector,
    IAMConnector,
    SIEMConnector,
    SyntheticScenarioGenerator,
)
from backend.app.ingestion.contracts import IngestionResult
from backend.app.ingestion.synthetic_enterprise_loader import SyntheticEnterpriseLoader, DEFAULT_DATASET_DIR
from backend.app.ingestion.dataset_validator import DatasetValidator
from backend.app.ingestion.service import CSVIngestionSummary, TelemetryIngestionService
from backend.app.models.domain import (
    ApprovalStatus,
    AttackPath,
    AuditEvent,
    BusinessWorkflow,
    ContainmentAction,
    ContainmentPlan,
    DataProvenance,
    GraphEdge,
    GraphNode,
    OptimizationStrategy,
    RiskDecomposition,
    SimulationResult,
    UserRole,
)
from backend.app.observability.metrics import MetricsCollector, SystemMetrics
from backend.app.security.roles import AppRole, normalize_app_role
from backend.app.security.user_store import (
    UserCreateRequest,
    UserRecord,
    UserResponse,
    UserUpdateRequest,
    user_store,
)
from backend.app.security.auth import (
    create_access_token,
    get_current_user,
    require_admin,
    require_analyst,
    require_role,
    require_viewer,
)
from backend.app.optimization.solver import (
    BaselinePlanner,
    CPSATOptimizer,
    GreedyOptimizer,
    StrategyComparator,
)
from backend.app.planning.catalog import ActionCatalog
from backend.app.reporting.exporter import ReportExporter
from backend.app.risk.engine import RiskEngine
from backend.app.governance.workflow import GovernanceWorkflow
from backend.app.simulation.sandbox import SimulationSandbox

api_router = APIRouter()

# Global In-Memory State Container for Session Context
class PlatformContext:
    def __init__(self):
        self.engine = GraphEngine()
        self.twin = BusinessContinuityTwin()
        self.evidence_eng = EvidenceEngine()
        self.ledger = ChainedAuditLedger()
        self.siem_connector = SIEMConnector()
        self.edr_connector = EDRConnector()
        self.iam_connector = IAMConnector()
        self.enterprise_loader = SyntheticEnterpriseLoader()
        self.csv_service = TelemetryIngestionService(self.enterprise_loader)
        self.current_plan: Optional[ContainmentPlan] = None
        self.last_simulation: Optional[SimulationResult] = None
        self.active_scenario_name = "Uninitialized (Clean State)"
        self.last_ingestion_timestamp: Optional[str] = None

platform_ctx = PlatformContext()


# =====================================================================
# AUTHENTICATION & USER MANAGEMENT ENDPOINTS
# =====================================================================

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


@api_router.post("/auth/login", response_model=TokenResponse, tags=["Authentication"])
def login(creds: LoginRequest) -> TokenResponse:
    """Authenticates user credentials and issues a signed, expiring JWT access token."""
    user = user_store.get_user_by_username(creds.username)
    if not user or not user_store.verify_password(creds.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is deactivated. Contact an administrator.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token({
        "sub": user.username,
        "uid": user.id,
        "role": user.role.value,
    })

    # Log successful authentication to audit ledger
    platform_ctx.ledger.record_event(
        actor_id=user.username,
        actor_role=UserRole.PLATFORM_ADMIN if user.role == AppRole.ADMIN else (UserRole.SOC_ANALYST if user.role == AppRole.ANALYST else UserRole.READ_ONLY_VIEWER),
        action="USER_AUTHENTICATION_LOGIN",
        resource_type="UserSession",
        resource_id=user.id,
        metadata={"username": user.username, "role": user.role.value}
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            full_name=user.full_name,
            created_at=user.created_at,
            updated_at=user.updated_at,
        )
    )


@api_router.get("/auth/me", response_model=UserResponse, tags=["Authentication"])
def get_current_user_profile(
    current_user: UserRecord = Depends(get_current_user)
) -> UserResponse:
    """Returns the verified profile and RBAC role of the authenticated caller."""
    if not isinstance(current_user, UserRecord):
        admin = user_store.get_user_by_username("admin")
        current_user = admin or user_store.list_users()[0]

    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role,
        is_active=current_user.is_active,
        full_name=current_user.full_name,
        created_at=current_user.created_at,
        updated_at=current_user.updated_at,
    )


@api_router.post("/auth/users", response_model=UserResponse, tags=["User Management"])
def create_new_user(
    req: UserCreateRequest,
    current_user: UserRecord = Depends(require_admin),
) -> UserResponse:
    """Provisions a new user account (Administrator only)."""
    try:
        new_user = user_store.create_user(
            username=req.username,
            password=req.password,
            role=req.role,
            email=req.email,
            full_name=req.full_name,
        )
        return UserResponse(
            id=new_user.id,
            username=new_user.username,
            email=new_user.email,
            role=new_user.role,
            is_active=new_user.is_active,
            full_name=new_user.full_name,
            created_at=new_user.created_at,
            updated_at=new_user.updated_at,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@api_router.get("/auth/users", response_model=List[UserResponse], tags=["User Management"])
def list_all_users(
    current_user: UserRecord = Depends(require_admin),
) -> List[UserResponse]:
    """Lists all registered platform user accounts (Administrator only)."""
    return user_store.list_users()


@api_router.put("/auth/users/{user_id}/role", response_model=UserResponse, tags=["User Management"])
def update_user_role(
    user_id: str,
    req: UserUpdateRequest,
    current_user: UserRecord = Depends(require_admin),
) -> UserResponse:
    """Updates a user's role (Administrator only)."""
    if not req.role:
        raise HTTPException(status_code=400, detail="New role must be specified.")
    success = user_store.update_user_role(user_id, req.role)
    if not success:
        raise HTTPException(status_code=404, detail=f"User with ID '{user_id}' was not found.")
    updated = user_store.get_user_by_id(user_id)
    return UserResponse(
        id=updated.id,
        username=updated.username,
        email=updated.email,
        role=updated.role,
        is_active=updated.is_active,
        full_name=updated.full_name,
        created_at=updated.created_at,
        updated_at=updated.updated_at,
    )


@api_router.patch("/auth/users/{user_id}/status", response_model=UserResponse, tags=["User Management"])
def update_user_status(
    user_id: str,
    req: UserUpdateRequest,
    current_user: UserRecord = Depends(require_admin),
) -> UserResponse:
    """Activates or deactivates a user account (Administrator only)."""
    if req.is_active is None:
        raise HTTPException(status_code=400, detail="'is_active' boolean flag must be provided.")
    if isinstance(current_user, UserRecord) and current_user.id == user_id and not req.is_active:
        raise HTTPException(status_code=400, detail="Administrators cannot deactivate their own account.")
    success = user_store.set_user_active(user_id, req.is_active)
    if not success:
        raise HTTPException(status_code=404, detail=f"User with ID '{user_id}' was not found.")
    updated = user_store.get_user_by_id(user_id)
    return UserResponse(
        id=updated.id,
        username=updated.username,
        email=updated.email,
        role=updated.role,
        is_active=updated.is_active,
        full_name=updated.full_name,
        created_at=updated.created_at,
        updated_at=updated.updated_at,
    )


# =====================================================================
# SYSTEM & OBSERVABILITY ENDPOINTS
# =====================================================================

@api_router.get("/health", tags=["System"])
def health_check() -> Dict[str, Any]:
    """Liveness & readiness probe with explicit graph backend diagnostic."""
    engine = platform_ctx.engine
    is_live = engine.is_neo4j_live
    configured_mode = engine.mode
    is_degraded = (configured_mode == "neo4j" and not is_live)
    neo4j_stat = engine.get_neo4j_status()
    neo4j_status_val = neo4j_stat.get("status", "DISCONNECTED")

    # Safe redacted URI: scheme://host (no user, no password)
    uri = settings.NEO4J_URI or ""
    redacted_uri = uri.split("@")[-1] if "@" in uri else uri
    node_count = len(engine._node_store)
    edge_count = len(engine._edge_store)

    return {
        "status": "DEGRADED" if is_degraded else ("HEALTHY" if is_live or configured_mode == "dual" else "UNHEALTHY"),
        "service": "SafeContain AI Enterprise Backend",
        "version": "1.0.0",
        "graph_backend": "live_neo4j" if is_live else "in_memory_networkx",
        "configured_graph_backend": configured_mode,
        "neo4j_connected": is_live,
        "neo4j_status": neo4j_status_val,
        "neo4j_database": engine.active_database or (settings.NEO4J_DATABASE if is_live else None),
        "neo4j_uri": redacted_uri,
        "neo4j_last_error": engine.last_connection_error,
        "persistence_status": "PERSISTENT_AURA" if is_live else "EPHEMERAL_MEMORY",
        "fallback_status": "NONE" if is_live else ("DEGRADED" if configured_mode == "neo4j" else "FALLBACK_ACTIVE"),
        "audit_chain_length": len(platform_ctx.ledger._events),
        "dataset_loaded": node_count > 0,
        "node_count": node_count,
        "relationship_count": edge_count,
        "active_scenario": platform_ctx.active_scenario_name,
        "last_ingestion_timestamp": platform_ctx.last_ingestion_timestamp,
        "diagnostics": {
            "active_engine": "live_neo4j" if is_live else "in_memory_networkx",
            "in_memory_nodes": node_count,
            "in_memory_edges": edge_count,
            "is_persistent": is_live,
        },
    }


@api_router.get("/graph/diagnostic", tags=["Graph Intelligence"])
def get_graph_diagnostic(
    current_user: UserRecord = Depends(require_admin),
) -> Dict[str, Any]:
    """Provides deep diagnostic of active graph engine, connection state, and statistics."""
    neo4j_stat = platform_ctx.engine.get_neo4j_status()
    db_stats = platform_ctx.engine.get_database_statistics()
    uri = settings.NEO4J_URI or ""
    redacted_uri = uri.split("@")[-1] if "@" in uri else uri

    config_diagnostic = {
        "GRAPH_BACKEND": settings.GRAPH_BACKEND,
        "NEO4J_URI": redacted_uri,
        "NEO4J_USER_SET": bool(settings.NEO4J_USER),
        "NEO4J_USER_VALUE": settings.NEO4J_USER,
        "NEO4J_PASSWORD_SET": bool(settings.NEO4J_PASSWORD and settings.NEO4J_PASSWORD != "password"),
        "NEO4J_PASSWORD_LENGTH": len(settings.NEO4J_PASSWORD) if settings.NEO4J_PASSWORD else 0,
        "NEO4J_DATABASE": settings.NEO4J_DATABASE or "neo4j",
        "AURA_INSTANCEID": settings.AURA_INSTANCEID,
        "driver_initialized": platform_ctx.engine._neo4j_driver is not None,
        "query_connectivity": platform_ctx.engine.is_neo4j_live,
    }

    return {
        "configured_backend": platform_ctx.engine.mode,
        "active_engine": "live_neo4j" if platform_ctx.engine.is_neo4j_live else "in_memory_networkx",
        "neo4j_connected": platform_ctx.engine.is_neo4j_live,
        "neo4j_uri": redacted_uri,
        "neo4j_database": platform_ctx.engine.active_database or settings.NEO4J_DATABASE,
        "neo4j_status": neo4j_stat.get("status"),
        "last_connection_error": platform_ctx.engine.last_connection_error,
        "configuration_diagnostic": config_diagnostic,
        "topology_in_memory": {
            "nodes": len(platform_ctx.engine._node_store),
            "edges": len(platform_ctx.engine._edge_store),
        },
        "database_statistics": db_stats,
    }


@api_router.get("/metrics", response_model=SystemMetrics, tags=["System"])
def get_metrics(
    current_user: UserRecord = Depends(require_viewer),
) -> SystemMetrics:
    """Exposes real-time operational and solver telemetry."""
    return MetricsCollector.get_metrics(platform_ctx.engine, platform_ctx.ledger)


# =====================================================================
# SCENARIO & INGESTION ENDPOINTS
# =====================================================================

@api_router.get("/ingestion/connectors", tags=["Ingestion"])
def get_registered_connectors(
    current_user: UserRecord = Depends(require_analyst),
) -> List[Dict[str, Any]]:
    """Returns all registered enterprise security connectors, sync modes, and deduplication stats."""
    return [
        {
            "name": platform_ctx.siem_connector.name,
            "provenance": platform_ctx.siem_connector.provenance.value,
            "system_type": "SIEM / Security Information and Event Management",
            "seen_fingerprints": len(platform_ctx.siem_connector._seen_event_hashes),
            "status": "ONLINE",
        },
        {
            "name": platform_ctx.edr_connector.name,
            "provenance": platform_ctx.edr_connector.provenance.value,
            "system_type": "EDR / Endpoint Detection & Response",
            "seen_fingerprints": len(platform_ctx.edr_connector._seen_event_hashes),
            "status": "ONLINE",
        },
        {
            "name": platform_ctx.iam_connector.name,
            "provenance": platform_ctx.iam_connector.provenance.value,
            "system_type": "IAM / Identity & Access Management",
            "seen_fingerprints": len(platform_ctx.iam_connector._seen_event_hashes),
            "status": "ONLINE",
        },
        {
            "name": "SyntheticScenarioGenerator",
            "provenance": "SYNTHETIC",
            "system_type": "Calibrated Scenario Generator",
            "seen_fingerprints": 0,
            "status": "ONLINE",
        },
    ]


@api_router.post("/ingestion/siem", response_model=IngestionResult, tags=["Ingestion"])
def ingest_siem_telemetry(
    payload: List[Dict[str, Any]],
    current_user: UserRecord = Depends(require_analyst),
) -> IngestionResult:
    """Ingests raw SIEM security alerts with SHA-256 deduplication and schema validation."""
    result = platform_ctx.siem_connector.ingest(payload)
    for node in result.nodes:
        platform_ctx.engine.add_node(node)
        if platform_ctx.engine.is_neo4j_live:
            platform_ctx.engine.create_or_update_node_in_neo4j(node)
    for edge in result.edges:
        platform_ctx.engine.add_edge(edge)
        if platform_ctx.engine.is_neo4j_live:
            platform_ctx.engine.create_or_update_edge_in_neo4j(edge)

    MetricsCollector.record_ingestion(result.nodes_created + result.edges_created)
    platform_ctx.twin.discover_dependencies_from_graph(platform_ctx.engine)

    platform_ctx.ledger.record_event(
        actor_id="siem-connector",
        actor_role=UserRole.SOC_ANALYST,
        action="INGEST_SIEM_TELEMETRY",
        resource_type="TelemetryBatch",
        resource_id=f"siem-batch-{uuid.uuid4().hex[:8]}",
        metadata={
            "received": result.total_received,
            "nodes_created": result.nodes_created,
            "edges_created": result.edges_created,
            "duplicates_skipped": result.duplicates_skipped,
            "errors": result.errors_encountered,
        },
    )
    return result


@api_router.post("/ingestion/edr", response_model=IngestionResult, tags=["Ingestion"])
def ingest_edr_telemetry(
    payload: List[Dict[str, Any]],
    current_user: UserRecord = Depends(require_analyst),
) -> IngestionResult:
    """Ingests raw EDR host detections with SHA-256 deduplication and validation."""
    result = platform_ctx.edr_connector.ingest(payload)
    for node in result.nodes:
        platform_ctx.engine.add_node(node)
        if platform_ctx.engine.is_neo4j_live:
            platform_ctx.engine.create_or_update_node_in_neo4j(node)
    for edge in result.edges:
        platform_ctx.engine.add_edge(edge)
        if platform_ctx.engine.is_neo4j_live:
            platform_ctx.engine.create_or_update_edge_in_neo4j(edge)

    MetricsCollector.record_ingestion(result.nodes_created + result.edges_created)
    platform_ctx.twin.discover_dependencies_from_graph(platform_ctx.engine)

    platform_ctx.ledger.record_event(
        actor_id="edr-connector",
        actor_role=UserRole.SOC_ANALYST,
        action="INGEST_EDR_TELEMETRY",
        resource_type="TelemetryBatch",
        resource_id=f"edr-batch-{uuid.uuid4().hex[:8]}",
        metadata={
            "received": result.total_received,
            "nodes_created": result.nodes_created,
            "edges_created": result.edges_created,
            "duplicates_skipped": result.duplicates_skipped,
            "errors": result.errors_encountered,
        },
    )
    return result


@api_router.post(
    "/ingestion/csv",
    response_model=CSVIngestionSummary,
    tags=["Ingestion"],
    summary="Upload and incrementally ingest CSV data into graph"
)
@api_router.post(
    "/ingest/csv",
    response_model=CSVIngestionSummary,
    tags=["Ingestion"],
    include_in_schema=False
)
def upload_and_ingest_csv(
    file: UploadFile = File(..., description="Multipart CSV file (*.csv)"),
    override_provenance: Optional[str] = Form(default=None, description="Optional provenance override (default: CSV)"),
    current_user: UserRecord = Depends(require_admin),
) -> CSVIngestionSummary:
    """Accepts multipart/form-data CSV uploads, validates schemas, and incrementally upserts to Neo4j.
    
    Guarantees:
    - Preserves existing graph data (NEVER resets/clears existing topology).
    - Idempotent upserts: Identical re-uploads are detected as duplicates.
    - Strict provenance labeling: Defaults to DataProvenance.CSV.
    - Parameterized Cypher MERGE for live Neo4j persistence with graceful fallback.
    - Detailed row-by-row validation error reporting.
    """
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file extension. Only .csv files are supported. Provided: '{file.filename}'"
        )

    try:
        raw_bytes = file.file.read()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file stream: {str(e)}"
        )

    prov = None
    if override_provenance:
        try:
            prov = DataProvenance(override_provenance.upper())
        except Exception:
            prov = DataProvenance.CSV

    summary = platform_ctx.csv_service.ingest_csv_payload(
        raw_bytes=raw_bytes,
        filename=file.filename,
        engine=platform_ctx.engine,
        override_provenance=prov
    )

    # Refresh digital twin dependencies if new graph items were ingested
    if summary.accepted_rows > 0:
        platform_ctx.twin.discover_dependencies_from_graph(platform_ctx.engine)
        platform_ctx.last_ingestion_timestamp = datetime.now(timezone.utc).isoformat()

    actor_id = current_user.username if isinstance(current_user, UserRecord) else "csv-uploader"
    actor_role = UserRole.PLATFORM_ADMIN if (isinstance(current_user, UserRecord) and current_user.role == AppRole.ADMIN) else UserRole.SOC_ANALYST

    # Audit trail anchoring
    platform_ctx.ledger.record_event(
        actor_id=actor_id,
        actor_role=actor_role,
        action="CSV_INGESTION_UPLOAD",
        resource_type="CSVUploadBatch",
        resource_id=summary.upload_id,
        metadata={
            "filename": summary.filename,
            "csv_type": summary.csv_type,
            "total_rows": summary.total_rows,
            "accepted_rows": summary.accepted_rows,
            "rejected_rows": summary.rejected_rows,
            "duplicate_rows": summary.duplicate_rows,
            "nodes_created": summary.nodes_created,
            "nodes_updated": summary.nodes_updated,
            "relationships_created": summary.relationships_created,
            "relationships_updated": summary.relationships_updated,
            "neo4j_synced": summary.neo4j_synced,
            "neo4j_status": summary.neo4j_status,
            "status": summary.status,
        }
    )

    return summary


@api_router.post("/scenario/load-synthetic", tags=["Ingestion"])
def load_synthetic_scenario(
    scenario_name: str = "Operation Sovereign Gateway",
    current_user: UserRecord = Depends(require_admin),
) -> Dict[str, Any]:
    """Ingests and initializes the calibrated synthetic scenario with strict provenance labeling."""
    if scenario_name.startswith("SCEN-") or "enterprise" in scenario_name.lower():
        scen_id = scenario_name if scenario_name.startswith("SCEN-") else "SCEN-001"
        res = platform_ctx.enterprise_loader.load_scenario_into_platform(
            platform_ctx.engine,
            platform_ctx.twin,
            scenario_id=scen_id
        )
        canonical_name = f"{res['scenario_name']} ({res['scenario_id']})"
        platform_ctx.active_scenario_name = canonical_name
        platform_ctx.current_plan = None
        platform_ctx.last_simulation = None
        MetricsCollector.record_ingestion(res['nodes_loaded'] + res['edges_loaded'])
        platform_ctx.ledger.record_event(
            actor_id="soc-operator",
            actor_role=UserRole.SOC_ANALYST,
            action="LOAD_ENTERPRISE_SCENARIO",
            resource_type="SyntheticEnterpriseDataset",
            resource_id=scen_id,
            metadata=res,
        )
        return {
            "message": f"Successfully loaded enterprise scenario '{canonical_name}'",
            "scenario_name": canonical_name,
            "nodes_count": res['nodes_loaded'],
            "edges_count": res['edges_loaded'],
            "critical_assets_count": res['critical_assets_count'],
            "attack_paths_count": res['attack_paths_discovered'],
            "provenance": "SYNTHETIC",
        }

    if any(k in scenario_name.lower() for k in ["demo", "hackathon", "contractor", "identity-vault"]):
        result = SyntheticScenarioGenerator.generate_hackathon_demo_scenario()
        canonical_name = "Hackathon Demonstration Scenario"
    else:
        result = SyntheticScenarioGenerator.generate_national_gateway_scenario()
        canonical_name = scenario_name

    platform_ctx.engine.clear()

    for node in result.nodes:
        platform_ctx.engine.add_node(node)
    for edge in result.edges:
        platform_ctx.engine.add_edge(edge)

    platform_ctx.twin.discover_dependencies_from_graph(platform_ctx.engine)
    platform_ctx.active_scenario_name = canonical_name
    MetricsCollector.record_ingestion(len(result.nodes) + len(result.edges))

    if platform_ctx.engine.is_neo4j_live:
        platform_ctx.engine.sync_to_neo4j()

    # Audit the ingestion
    platform_ctx.ledger.record_event(
        actor_id="soc-operator",
        actor_role=UserRole.SOC_ANALYST,
        action="LOAD_SYNTHETIC_SCENARIO",
        resource_type="SyntheticScenario",
        resource_id=canonical_name,
        metadata={
            "nodes_loaded": len(result.nodes),
            "edges_loaded": len(result.edges),
            "provenance": "SYNTHETIC",
        },
    )

    return {
        "message": f"Successfully loaded scenario '{canonical_name}'",
        "scenario_name": canonical_name,
        "nodes_count": len(result.nodes),
        "edges_count": len(result.edges),
        "provenance": "SYNTHETIC",
    }


@api_router.post("/scenario/load-demo", tags=["Ingestion"])
def load_hackathon_demo_scenario(
    current_user: UserRecord = Depends(require_admin),
) -> Dict[str, Any]:
    """Loads the dedicated Hackathon Demonstration Scenario (Suspicious contractor account, 2 attack routes, disruptive vs targeted containment comparison)."""
    return load_synthetic_scenario(scenario_name="Hackathon Demonstration Scenario", current_user=current_user)


# =====================================================================
# ENTERPRISE SYNTHETIC DATASET & DEMONSTRATION CATALOG ENDPOINTS
# =====================================================================

@api_router.get("/dataset/status", tags=["Enterprise Dataset"])
def get_dataset_status(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Provides status, file presence, record counts, active graph backend, and validation metrics."""
    meta = platform_ctx.enterprise_loader.get_dataset_metadata()
    return {
        "dataset_name": meta["dataset_name"],
        "version": meta["version"],
        "provenance": meta["provenance"],
        "active_scenario": platform_ctx.active_scenario_name,
        "active_backend": "live_neo4j" if platform_ctx.engine.is_neo4j_live else "in_memory_networkx",
        "validation_status": meta["validation_status"],
        "files_count": len(meta["files"]),
        "file_record_counts": meta["file_counts"],
        "summary_metrics": meta["summary_metrics"],
        "current_graph_in_memory": {
            "nodes": len(platform_ctx.engine._node_store),
            "edges": len(platform_ctx.engine._edge_store),
            "attack_paths": len(platform_ctx.engine.find_attack_paths(max_depth=6)),
        }
    }


@api_router.get("/dataset/validation", tags=["Enterprise Dataset"])
def get_dataset_validation_report(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns the full data integrity and graph connectivity validation report."""
    return platform_ctx.enterprise_loader.validator.validate()


@api_router.get("/dataset/scenarios", tags=["Enterprise Dataset"])
def list_dataset_threat_scenarios(
    current_user: UserRecord = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    """Returns all 10 pre-configured synthetic demonstration scenarios."""
    return platform_ctx.enterprise_loader.get_threat_scenarios()


@api_router.post("/dataset/import", tags=["Enterprise Dataset"])
def import_enterprise_dataset(
    scenario_id: str = "SCEN-001",
    current_user: UserRecord = Depends(require_admin),
) -> Dict[str, Any]:
    """Imports the full 120-node synthetic enterprise graph and calibrates twin & attack paths."""
    res = platform_ctx.enterprise_loader.load_scenario_into_platform(
        platform_ctx.engine,
        platform_ctx.twin,
        scenario_id=scenario_id
    )
    platform_ctx.active_scenario_name = f"{res['scenario_name']} ({res['scenario_id']})"
    platform_ctx.last_ingestion_timestamp = datetime.now(timezone.utc).isoformat()
    platform_ctx.current_plan = None
    platform_ctx.last_simulation = None

    actor_id = current_user.username if isinstance(current_user, UserRecord) else "sec-admin"
    actor_role = UserRole.PLATFORM_ADMIN if (isinstance(current_user, UserRecord) and current_user.role == AppRole.ADMIN) else UserRole.SECURITY_ADMIN

    platform_ctx.ledger.record_event(
        actor_id=actor_id,
        actor_role=actor_role,
        action="IMPORT_ENTERPRISE_DATASET",
        resource_type="SyntheticEnterpriseDataset",
        resource_id=scenario_id,
        metadata=res
    )
    return res


@api_router.post("/dataset/scenarios/{scenario_id}/load", tags=["Enterprise Dataset"])
def load_specific_threat_scenario(
    scenario_id: str,
    current_user: UserRecord = Depends(require_admin),
) -> Dict[str, Any]:
    """Loads a specific scenario from threat_scenarios.csv (e.g., SCEN-001, SCEN-002, SCEN-003)."""
    return import_enterprise_dataset(scenario_id=scenario_id, current_user=current_user)


@api_router.post("/dataset/reset", tags=["Enterprise Dataset"])
def reset_dataset_environment(
    current_user: UserRecord = Depends(require_admin),
) -> Dict[str, Any]:
    """Resets graph to clean state and re-populates baseline enterprise topology."""
    platform_ctx.engine.clear()
    res = platform_ctx.enterprise_loader.load_scenario_into_platform(
        platform_ctx.engine,
        platform_ctx.twin,
        scenario_id="SCEN-001"
    )
    platform_ctx.active_scenario_name = f"{res['scenario_name']} ({res['scenario_id']})"
    platform_ctx.last_ingestion_timestamp = datetime.now(timezone.utc).isoformat()
    platform_ctx.current_plan = None
    platform_ctx.last_simulation = None

    actor_id = current_user.username if isinstance(current_user, UserRecord) else "sec-admin"
    actor_role = UserRole.PLATFORM_ADMIN if (isinstance(current_user, UserRecord) and current_user.role == AppRole.ADMIN) else UserRole.SECURITY_ADMIN

    platform_ctx.ledger.record_event(
        actor_id=actor_id,
        actor_role=actor_role,
        action="RESET_DATASET_ENVIRONMENT",
        resource_type="SyntheticEnterpriseDataset",
        resource_id="CLEAN_RESET",
        metadata={"reset": True}
    )
    return {"status": "SUCCESS", "message": "Graph and simulation reset to clean baseline", "details": res}


@api_router.get("/dataset/download/{filename}", tags=["Enterprise Dataset"])
def download_dataset_file(
    filename: str,
    current_user: UserRecord = Depends(require_viewer),
):
    """Downloads an individual CSV file from backend/data/synthetic_enterprise/."""
    valid_files = {
        "nodes.csv", "relationships.csv", "assets.csv", "users.csv",
        "vulnerabilities.csv", "security_alerts.csv", "evidence.csv",
        "attack_paths.csv", "interventions.csv", "asset_dependencies.csv",
        "business_impact.csv", "threat_scenarios.csv", "dataset_validation_report.json", "README.md"
    }
    if filename not in valid_files:
        raise HTTPException(status_code=404, detail=f"File '{filename}' not found in dataset")
    path = os.path.join(platform_ctx.enterprise_loader.dataset_dir, filename)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="File not found on disk")
    return FileResponse(path, filename=filename, media_type="text/csv" if filename.endswith(".csv") else "application/json")


@api_router.get("/dataset/download-all", tags=["Enterprise Dataset"])
def download_all_datasets_zip(
    current_user: UserRecord = Depends(require_viewer),
):
    """Packages all 12 CSVs, validation report, and README into a single downloadable ZIP archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for fname in os.listdir(platform_ctx.enterprise_loader.dataset_dir):
            fpath = os.path.join(platform_ctx.enterprise_loader.dataset_dir, fname)
            if os.path.isfile(fpath):
                z.write(fpath, arcname=f"SafeContain_Enterprise_Dataset/{fname}")
    buf.seek(0)
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="SafeContain_Enterprise_Synthetic_Dataset.zip"'}
    )


@api_router.get("/dataset/assets", tags=["Enterprise Dataset"])
def get_dataset_assets(
    current_user: UserRecord = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    """Returns all 35 asset records with business criticality and CIA tiers."""
    return platform_ctx.enterprise_loader._read_csv("assets.csv")


@api_router.get("/dataset/users", tags=["Enterprise Dataset"])
def get_dataset_users(
    current_user: UserRecord = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    """Returns all 30 user and service identity records."""
    return platform_ctx.enterprise_loader._read_csv("users.csv")


@api_router.get("/dataset/vulnerabilities", tags=["Enterprise Dataset"])
def get_dataset_vulnerabilities(
    current_user: UserRecord = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    """Returns all 45 vulnerability records with CVSS scores and remediations."""
    return platform_ctx.enterprise_loader._read_csv("vulnerabilities.csv")


@api_router.get("/dataset/alerts", tags=["Enterprise Dataset"])
def get_dataset_alerts(
    current_user: UserRecord = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    """Returns all 60 security detection alerts."""
    return platform_ctx.enterprise_loader._read_csv("security_alerts.csv")


@api_router.get("/dataset/evidence", tags=["Enterprise Dataset"])
def get_dataset_evidence(
    current_user: UserRecord = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    """Returns all 75 forensic evidence records with uncertainty status."""
    return platform_ctx.enterprise_loader._read_csv("evidence.csv")


@api_router.get("/dataset/interventions", tags=["Enterprise Dataset"])
def get_dataset_interventions(
    current_user: UserRecord = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    """Returns all 45 candidate defensive interventions."""
    return platform_ctx.enterprise_loader._read_csv("interventions.csv")


@api_router.get("/dataset/dependencies", tags=["Enterprise Dataset"])
def get_dataset_dependencies(
    current_user: UserRecord = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    """Returns all 60 cross-asset operational dependencies."""
    return platform_ctx.enterprise_loader._read_csv("asset_dependencies.csv")


@api_router.get("/dataset/business-impact", tags=["Enterprise Dataset"])
def get_dataset_business_impact(
    current_user: UserRecord = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    """Returns all 35 business impact profiles with hourly loss and SLAs."""
    return platform_ctx.enterprise_loader._read_csv("business_impact.csv")


# =====================================================================
# GRAPH & ATTACK PATH ENDPOINTS
# =====================================================================

@api_router.get("/graph/topology", tags=["Graph Intelligence"])
def get_graph_topology(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns normalized infrastructure graph topology."""
    return platform_ctx.engine.export_topology()


@api_router.get("/graph/attack-paths", response_model=List[AttackPath], tags=["Graph Intelligence"])
def get_attack_paths(
    current_user: UserRecord = Depends(require_analyst),
) -> List[AttackPath]:
    """Discovers all directed attack paths from compromised nodes to crown jewels."""
    return platform_ctx.engine.find_attack_paths()


@api_router.get("/graph/neo4j/status", tags=["Graph Intelligence"])
def get_neo4j_connection_status(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns real-time connection status and entity counts for live Neo4j."""
    return platform_ctx.engine.get_neo4j_status()


@api_router.get("/graph/neo4j/statistics", tags=["Graph Intelligence"])
def get_neo4j_database_statistics(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns database statistics across labels, relationship types, and evidence certainty."""
    return platform_ctx.engine.get_database_statistics()


@api_router.post("/graph/neo4j/sync", tags=["Graph Intelligence"])
def sync_topology_to_neo4j(
    current_user: UserRecord = Depends(require_admin),
) -> Dict[str, Any]:
    """Flushes and synchronizes active graph topology into live Neo4j instance."""
    result = platform_ctx.engine.sync_to_neo4j()
    actor_id = current_user.username if isinstance(current_user, UserRecord) else "soc-admin"
    actor_role = UserRole.PLATFORM_ADMIN if (isinstance(current_user, UserRecord) and current_user.role == AppRole.ADMIN) else UserRole.INCIDENT_COMMANDER
    platform_ctx.ledger.record_event(
        actor_id=actor_id,
        actor_role=actor_role,
        action="NEO4J_TOPOLOGY_SYNC",
        resource_type="GraphTopology",
        resource_id=f"neo4j-{settings.NEO4J_DATABASE}",
        metadata=result,
    )
    return result


@api_router.post("/graph/neo4j/load", tags=["Graph Intelligence"])
@api_router.post("/graph/neo4j/reload", tags=["Graph Intelligence"])
@api_router.post("/graph/refresh", tags=["Graph Intelligence"])
def load_topology_from_neo4j(
    current_user: UserRecord = Depends(require_admin),
) -> Dict[str, Any]:
    """Imports topology from live Neo4j into in-memory traversal engine."""
    result = platform_ctx.engine.load_from_neo4j()
    platform_ctx.twin.discover_dependencies_from_graph(platform_ctx.engine)
    actor_id = current_user.username if isinstance(current_user, UserRecord) else "soc-admin"
    actor_role = UserRole.PLATFORM_ADMIN if (isinstance(current_user, UserRecord) and current_user.role == AppRole.ADMIN) else UserRole.INCIDENT_COMMANDER
    platform_ctx.ledger.record_event(
        actor_id=actor_id,
        actor_role=actor_role,
        action="NEO4J_TOPOLOGY_IMPORT",
        resource_type="GraphTopology",
        resource_id=f"neo4j-{settings.NEO4J_DATABASE}",
        metadata=result,
    )
    return result


# =====================================================================
# EVIDENCE & RISK INTELLIGENCE ENDPOINTS
# =====================================================================

@api_router.get("/evidence/sensitivity", response_model=List[SensitivityScenarioResult], tags=["Evidence & Risk"])
def get_evidence_sensitivity(
    current_user: UserRecord = Depends(require_analyst),
) -> List[SensitivityScenarioResult]:
    """Evaluates sensitivity analysis under evidence drift (suspected -> confirmed / disputed)."""
    paths = platform_ctx.engine.find_attack_paths()
    return platform_ctx.evidence_eng.run_sensitivity_analysis(paths, platform_ctx.engine)


@api_router.get("/risk/decompose", response_model=RiskDecomposition, tags=["Evidence & Risk"])
@api_router.get("/risk/decomposed", response_model=RiskDecomposition, tags=["Evidence & Risk"], include_in_schema=False)
def get_decomposed_risk(
    current_user: UserRecord = Depends(require_viewer),
) -> RiskDecomposition:
    """Computes transparent, factor-contributed decomposed risk metrics."""
    paths = platform_ctx.engine.find_attack_paths()
    return RiskEngine.decompose_system_risk(paths, platform_ctx.engine.get_all_nodes())


# =====================================================================
# BUSINESS CONTINUITY TWIN ENDPOINTS
# =====================================================================

@api_router.get("/business/workflows", response_model=List[BusinessWorkflow], tags=["Business Continuity"])
def get_business_workflows(
    current_user: UserRecord = Depends(require_viewer),
) -> List[BusinessWorkflow]:
    """Returns all monitored business and citizen service workflows."""
    return platform_ctx.twin.get_all_workflows()


# =====================================================================
# PLANNING & OPTIMIZATION ENDPOINTS
# =====================================================================

@api_router.get("/planning/candidates", response_model=List[ContainmentAction], tags=["Response Planning"])
@api_router.get("/planning/actions/candidates", response_model=List[ContainmentAction], tags=["Response Planning"], include_in_schema=False)
def get_candidate_actions(
    current_user: UserRecord = Depends(require_analyst),
) -> List[ContainmentAction]:
    """Synthesizes valid candidate containment actions targeting active attack paths."""
    paths = platform_ctx.engine.find_attack_paths()
    nodes = {n.id: n for n in platform_ctx.engine.get_all_nodes()}
    return ActionCatalog.generate_candidate_actions(paths, nodes)


class OptimizeRequest(BaseModel):
    budget_limit: float = Field(default=10000.0, ge=100.0)
    disruption_budget: Optional[float] = None
    strategy: OptimizationStrategy = OptimizationStrategy.CONSTRAINT_CPSAT


@api_router.post("/planning/optimize", tags=["Response Planning"])
@api_router.post("/optimization/compare", tags=["Response Planning"], include_in_schema=False)
@api_router.post("/optimization/containment", tags=["Response Planning"], include_in_schema=False)
def optimize_containment(
    req: OptimizeRequest,
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Solves containment optimization and compares all 3 strategies on identical inputs."""
    effective_budget = req.disruption_budget if req.disruption_budget is not None else req.budget_limit
    paths = platform_ctx.engine.find_attack_paths()
    nodes = {n.id: n for n in platform_ctx.engine.get_all_nodes()}
    candidates = ActionCatalog.generate_candidate_actions(paths, nodes)

    comparison = StrategyComparator.compare(
        candidates, platform_ctx.twin, platform_ctx.engine, effective_budget
    )

    # Store active recommended plan
    if req.strategy == OptimizationStrategy.CONSTRAINT_CPSAT:
        platform_ctx.current_plan = CPSATOptimizer.plan(
            candidates, platform_ctx.twin, platform_ctx.engine, effective_budget
        )
    elif req.strategy == OptimizationStrategy.GREEDY_RISK_COST:
        platform_ctx.current_plan = GreedyOptimizer.plan(candidates, effective_budget)
    else:
        platform_ctx.current_plan = BaselinePlanner.plan(candidates, effective_budget)

    # Anchor recommendation in audit ledger (R&D Blueprint Objective #7)
    if platform_ctx.current_plan:
        platform_ctx.ledger.record_recommendation(
            plan_id=platform_ctx.current_plan.id,
            strategy=platform_ctx.current_plan.strategy.value,
            objective_score=platform_ctx.current_plan.objective_score,
            total_cost=platform_ctx.current_plan.total_cost,
            predicted_risk_reduction=platform_ctx.current_plan.predicted_risk_reduction,
            actions_count=len(platform_ctx.current_plan.actions),
        )

    return comparison


# =====================================================================
# SIMULATION & DECISION EXPLANATION ENDPOINTS
# =====================================================================

class SimulationRequest(BaseModel):
    action_ids: Optional[List[str]] = None
    candidate_action_ids: Optional[List[str]] = None
    strategy: Optional[OptimizationStrategy] = None
    budget_limit: Optional[float] = None
    disruption_budget: Optional[float] = None


@api_router.post("/simulation/run", response_model=SimulationResult, tags=["Simulation"])
@api_router.post("/simulation/what-if", response_model=SimulationResult, tags=["Simulation"], include_in_schema=False)
def run_isolated_simulation(
    req: Optional[SimulationRequest] = None,
    current_user: UserRecord = Depends(require_analyst),
) -> SimulationResult:
    """Executes isolated snapshot simulation and verifies residual attack paths."""
    effective_actions = None
    if req:
        effective_actions = req.action_ids if req.action_ids is not None else req.candidate_action_ids
    effective_budget = None
    if req:
        effective_budget = req.disruption_budget if req.disruption_budget is not None else req.budget_limit

    paths = platform_ctx.engine.find_attack_paths()
    nodes = {n.id: n for n in platform_ctx.engine.get_all_nodes()}
    candidates = ActionCatalog.generate_candidate_actions(paths, nodes)
    candidate_map = {a.id: a for a in candidates}

    target_plan: Optional[ContainmentPlan] = None

    if effective_actions is not None:
        # Build plan with specifically requested containment actions
        selected_actions = [candidate_map[aid] for aid in effective_actions if aid in candidate_map]
        total_cost = sum(a.implementation_cost for a in selected_actions)
        total_disruption = sum(a.operational_disruption_score for a in selected_actions)
        strat = (req.strategy if req else None) or (
            platform_ctx.current_plan.strategy if platform_ctx.current_plan else OptimizationStrategy.CONSTRAINT_CPSAT
        )
        target_plan = ContainmentPlan(
            id=f"plan-whatif-{uuid.uuid4().hex[:8]}",
            strategy=strat,
            actions=selected_actions,
            total_cost=total_cost,
            total_disruption_score=total_disruption,
            predicted_risk_reduction=sum(a.estimated_risk_reduction for a in selected_actions),
            predicted_residual_risk=0.0,
            satisfies_all_constraints=True,
            objective_score=1.0,
            status=ApprovalStatus.DRAFT,
            explanation=f"What-If custom simulation applying {len(selected_actions)} selected containment actions.",
        )
    elif req and req.strategy is not None:
        budget = effective_budget or 10000.0
        if req.strategy == OptimizationStrategy.CONSTRAINT_CPSAT:
            target_plan = CPSATOptimizer.plan(candidates, platform_ctx.twin, platform_ctx.engine, budget)
        elif req.strategy == OptimizationStrategy.GREEDY_RISK_COST:
            target_plan = GreedyOptimizer.plan(candidates, budget)
        else:
            target_plan = BaselinePlanner.plan(candidates, budget)
    elif platform_ctx.current_plan:
        target_plan = platform_ctx.current_plan
    else:
        target_plan = CPSATOptimizer.plan(candidates, platform_ctx.twin, platform_ctx.engine, 10000.0)

    platform_ctx.current_plan = target_plan

    sim_result = SimulationSandbox.simulate_containment_plan(
        target_plan, platform_ctx.engine, platform_ctx.twin
    )
    platform_ctx.current_plan.status = ApprovalStatus.SIMULATED
    platform_ctx.last_simulation = sim_result
    MetricsCollector.record_simulation()

    actor_id = current_user.username if isinstance(current_user, UserRecord) else "soc-analyst"
    actor_role = UserRole.PLATFORM_ADMIN if (isinstance(current_user, UserRecord) and current_user.role == AppRole.ADMIN) else UserRole.SOC_ANALYST

    # Record simulation in audit ledger (R&D Blueprint Objective #7)
    platform_ctx.ledger.record_simulation_summary(
        simulation_id=sim_result.simulation_id,
        scenario_id=platform_ctx.active_scenario_name,
        initial_risk=sim_result.initial_risk_score,
        residual_risk=sim_result.residual_risk_score,
        blocked_paths_count=len(sim_result.applied_action_ids),
        residual_paths_count=sim_result.residual_attack_path_count,
        disrupted_workflows_count=len(sim_result.disrupted_workflows),
        actor_id=actor_id,
        actor_role=actor_role,
    )

    return sim_result


@api_router.get("/explanation/recommendation", tags=["Decision Intelligence"])
def get_decision_explanation(
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Generates mathematically grounded decision justification and counterfactual analysis."""
    if not platform_ctx.current_plan or not platform_ctx.last_simulation:
        run_isolated_simulation(current_user=current_user)

    # Create dummy alternative plan for comparison
    paths = platform_ctx.engine.find_attack_paths()
    nodes = {n.id: n for n in platform_ctx.engine.get_all_nodes()}
    candidates = ActionCatalog.generate_candidate_actions(paths, nodes)
    alt_baseline = BaselinePlanner.plan(candidates, 10000.0)

    explanation = DecisionExplainer.explain_recommendation(
        platform_ctx.current_plan, [alt_baseline], platform_ctx.last_simulation
    )
    return explanation


# =====================================================================
# GOVERNANCE & APPROVAL WORKFLOW ENDPOINTS
# =====================================================================

class GovernanceTransitionRequest(BaseModel):
    target_status: ApprovalStatus
    actor_id: str = "sec-manager-raj"
    actor_role: UserRole = UserRole.SECURITY_MANAGER
    notes: str = "Authorized containment plan post-simulation."
    rejection_reason: Optional[str] = None


@api_router.post("/governance/transition", tags=["Governance"])
def transition_plan_status(
    req: GovernanceTransitionRequest,
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Transitions containment plan approval state machine with role enforcement."""
    if not platform_ctx.current_plan:
        raise HTTPException(status_code=400, detail="No active containment plan to transition.")

    actor_id = req.actor_id
    actor_role = req.actor_role
    if isinstance(current_user, UserRecord):
        actor_id = current_user.username
        if current_user.role == AppRole.ADMIN:
            actor_role = UserRole.INCIDENT_COMMANDER
        elif current_user.role == AppRole.ANALYST:
            actor_role = UserRole.SOC_ANALYST
        else:
            actor_role = UserRole.READ_ONLY_VIEWER

    try:
        updated_plan, decision = GovernanceWorkflow.transition_plan(
            plan=platform_ctx.current_plan,
            target_status=req.target_status,
            actor_id=actor_id,
            actor_role=actor_role,
            notes=req.notes,
            rejection_reason=req.rejection_reason,
        )
        platform_ctx.current_plan = updated_plan

        # Record in cryptographic audit ledger with approval reference (R&D Blueprint Objective #7)
        approval_ref = f"sig-{decision.decision_id[:8]}-{actor_id}"
        platform_ctx.ledger.record_approval(
            plan_id=updated_plan.id,
            approval_status=req.target_status.value,
            approval_reference=approval_ref,
            actor_id=actor_id,
            actor_role=actor_role,
            notes=req.notes,
        )

        return {
            "plan_id": updated_plan.id,
            "status": updated_plan.status.value,
            "decision": decision.model_dump(mode="json"),
        }
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))


# =====================================================================
# AUDIT & VERIFICATION ENDPOINTS
# =====================================================================

@api_router.get("/audit/ledger", response_model=List[AuditEvent], tags=["Audit"])
def get_audit_ledger(
    limit: int = 50,
    current_user: UserRecord = Depends(require_viewer),
) -> List[AuditEvent]:
    """Returns recent cryptographically chained audit records."""
    return platform_ctx.ledger.get_events(limit=limit)


@api_router.get("/audit/verify", response_model=AuditIntegrityReport, tags=["Audit"])
def verify_audit_integrity(
    current_user: UserRecord = Depends(require_viewer),
) -> AuditIntegrityReport:
    """Performs full forward cryptographic SHA-256 hash-chain verification."""
    return platform_ctx.ledger.verify_integrity()


@api_router.get("/audit/blockchain/status", tags=["Audit"])
def get_blockchain_ledger_status(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns smart contract ledger status and on-chain block count (R&D Blueprint Page 4)."""
    return platform_ctx.ledger.blockchain_anchor.get_ledger_status()


@api_router.get("/audit/blockchain/records", tags=["Audit"])
def get_blockchain_anchored_records(
    current_user: UserRecord = Depends(require_viewer),
) -> List[Dict[str, Any]]:
    """Returns all records anchored on the blockchain ledger."""
    records = platform_ctx.ledger.blockchain_anchor.get_all_anchored_records()
    return [r.model_dump(mode="json") for r in records]


@api_router.post("/audit/blockchain/verify", tags=["Audit"])
def verify_blockchain_record_hash(
    event_id: str = Query(..., description="Audit Event ID to verify on-chain"),
    current_user: UserRecord = Depends(require_analyst),
) -> Dict[str, Any]:
    """Recomputes off-chain record hash and verifies against smart contract anchor (R&D Blueprint Page 2)."""
    result = platform_ctx.ledger.verify_blockchain_integrity(event_id)
    return result.model_dump(mode="json")


# =====================================================================
# PHASE 3 — BLOCKCHAIN TRUST & EVIDENCE INTEGRITY ENDPOINTS
# =====================================================================

class VerifyEvidencePayload(BaseModel):
    event_id: str
    anchor_id: Optional[str] = None


class VerifyAnchorPayload(BaseModel):
    anchor_id: str
    expected_root: Optional[str] = None


class TamperDemoPayload(BaseModel):
    event_id: Optional[str] = None
    field_to_tamper: str = "action"
    tampered_value: str = "UNAUTHORIZED_PAYLOAD_MANIPULATION"


@api_router.get("/blockchain/status", tags=["Blockchain Trust"])
def get_blockchain_status(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns complete EVM blockchain connection status, node height, and contract config."""
    return platform_ctx.ledger.blockchain_anchor.get_ledger_status()


@api_router.get("/blockchain/network", tags=["Blockchain Trust"])
def get_blockchain_network(
    current_user: UserRecord = Depends(require_viewer),
) -> Dict[str, Any]:
    """Returns EVM network details, chain ID, RPC connectivity, and block explorer templates."""
    status = platform_ctx.ledger.blockchain_anchor.client.get_status()
    cfg = platform_ctx.ledger.blockchain_anchor.client.config
    return {
        "network_name": cfg.network_name,
        "chain_id": cfg.chain_id,
        "connected": status.connected,
        "mode": status.mode,
        "contract_address": cfg.contract_address,
        "wallet_address": cfg.wallet_address,
        "wallet_balance_eth": status.wallet_balance_eth,
        "current_block_height": status.current_block_height,
        "required_confirmations": cfg.confirmations,
        "explorer_tx_template": cfg.explorer_tx_template,
        "explorer_address_template": cfg.explorer_address_template,
        "status_message": status.status_message,
        "can_anchor_on_chain": status.can_anchor_on_chain,
    }


@api_router.get("/blockchain/anchor-preview", response_model=AnchorPreview, tags=["Blockchain Trust"])
def get_anchor_preview(
    max_records: int = Query(50, ge=1, le=500),
    current_user: UserRecord = Depends(require_viewer),
) -> AnchorPreview:
    """Previews eligible unanchored audit ledger records and validates chain continuity."""
    return platform_ctx.ledger.blockchain_anchor.anchor_service.get_preview(
        ledger_events=platform_ctx.ledger._events,
        max_records=max_records
    )


@api_router.get("/blockchain/anchors", response_model=List[StoredAnchorManifest], tags=["Blockchain Trust"])
def list_blockchain_anchors(
    current_user: UserRecord = Depends(require_viewer),
) -> List[StoredAnchorManifest]:
    """Returns all anchored cryptographic Merkle batches in reverse chronological order."""
    return platform_ctx.ledger.blockchain_anchor.storage.get_all_manifests()


@api_router.get("/blockchain/anchors/{anchor_id}", response_model=StoredAnchorManifest, tags=["Blockchain Trust"])
def get_blockchain_anchor_by_id(
    anchor_id: str,
    current_user: UserRecord = Depends(require_viewer),
) -> StoredAnchorManifest:
    """Retrieves specific batch anchor manifest by unique anchor ID."""
    manifest = platform_ctx.ledger.blockchain_anchor.storage.get_manifest(anchor_id)
    if not manifest:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Anchor manifest with ID '{anchor_id}' not found."
        )
    return manifest


@api_router.post("/blockchain/anchors", response_model=AnchorResponse, tags=["Blockchain Trust"])
def create_blockchain_anchor(
    payload: CreateAnchorRequest,
    current_user: UserRecord = Depends(require_analyst),
) -> AnchorResponse:
    """Anchors an eligible batch of audit records: computes Merkle root and broadcasts to EVM testnet."""
    try:
        actor_id = current_user.username if hasattr(current_user, "username") else "admin"
        res = platform_ctx.ledger.blockchain_anchor.anchor_service.create_anchor(
            ledger_events=platform_ctx.ledger._events,
            request=payload,
            actor_id=actor_id
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@api_router.get("/blockchain/merkle-proof/{event_id}", response_model=MerkleProof, tags=["Blockchain Trust"])
def get_event_merkle_proof(
    event_id: str,
    anchor_id: Optional[str] = Query(None, description="Optional specific anchor ID"),
    current_user: UserRecord = Depends(require_viewer),
) -> MerkleProof:
    """Generates cryptographic Merkle inclusion proof for a specific audit record."""
    storage = platform_ctx.ledger.blockchain_anchor.storage
    target_anchor_id = anchor_id
    if not target_anchor_id:
        # Find latest anchor containing this event
        for m in storage.get_all_manifests():
            if event_id in m.event_ids:
                target_anchor_id = m.anchor_id
                break

    if not target_anchor_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No anchored batch found containing event ID '{event_id}'."
        )

    proof = platform_ctx.ledger.blockchain_anchor.anchor_service.get_merkle_proof(
        anchor_id=target_anchor_id,
        event_id=event_id,
        ledger_events=platform_ctx.ledger._events
    )
    if not proof:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Could not compute Merkle proof for event '{event_id}' in anchor '{target_anchor_id}'."
        )
    return proof


@api_router.post("/blockchain/verify-evidence", response_model=EvidenceVerificationResult, tags=["Blockchain Trust"])
def verify_blockchain_evidence(
    payload: VerifyEvidencePayload,
    current_user: UserRecord = Depends(require_viewer),
) -> EvidenceVerificationResult:
    """Independently verifies record hash, Merkle proof, and on-chain smart contract anchor."""
    event = next((e for e in platform_ctx.ledger._events if e.event_id == payload.event_id), None)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event ID '{payload.event_id}' not found in audit ledger."
        )

    recomputed = platform_ctx.ledger.compute_record_hash(
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

    proof = None
    anchor_id = payload.anchor_id
    if not anchor_id:
        for m in platform_ctx.ledger.blockchain_anchor.storage.get_all_manifests():
            if event.event_id in m.event_ids:
                anchor_id = m.anchor_id
                break

    if anchor_id:
        proof = platform_ctx.ledger.blockchain_anchor.anchor_service.get_merkle_proof(
            anchor_id=anchor_id,
            event_id=event.event_id,
            ledger_events=platform_ctx.ledger._events
        )

    return platform_ctx.ledger.blockchain_anchor.verifier.verify_record(
        event=event,
        recomputed_hash=recomputed,
        anchor_id=anchor_id,
        proof=proof
    )


@api_router.post("/blockchain/tamper-demo", response_model=TamperDemoReport, tags=["Blockchain Trust"])
def run_blockchain_tamper_demo(
    payload: TamperDemoPayload,
    current_user: UserRecord = Depends(require_analyst),
) -> TamperDemoReport:
    """Executes safe, non-destructive tamper demonstration in isolated memory."""
    all_events = platform_ctx.ledger._events
    if not all_events:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Ledger is empty.")

    target_event = None
    if payload.event_id:
        target_event = next((e for e in all_events if e.event_id == payload.event_id), None)
    if not target_event:
        # Default to a representative decision event from recent ledger
        target_event = all_events[-1] if len(all_events) > 0 else all_events[0]

    return platform_ctx.ledger.blockchain_anchor.tamper_demo.run_demonstration(
        target_event=target_event,
        ledger=platform_ctx.ledger,
        field_to_tamper=payload.field_to_tamper,
        tampered_value=payload.tampered_value
    )


@api_router.get("/blockchain/ledger-integrity", response_model=AuditIntegrityReport, tags=["Blockchain Trust"])
def get_blockchain_ledger_integrity(
    current_user: UserRecord = Depends(require_viewer),
) -> AuditIntegrityReport:
    """Executes full forward cryptographic SHA-256 hash-chain validation."""
    return platform_ctx.ledger.verify_integrity()


# =====================================================================
# REPORTING & EXPORT ENDPOINTS
# =====================================================================

@api_router.get("/reports/export", tags=["Reporting"])
def export_incident_report(
    format: str = Query("json"),
    current_user: UserRecord = Depends(require_viewer),
) -> Any:
    """Exports canonical incident report dossier in requested format."""
    if format not in ("json", "csv", "text"):
        raise HTTPException(status_code=400, detail="Invalid format. Supported: 'json', 'csv', 'text'.")
    if not platform_ctx.current_plan or not platform_ctx.last_simulation:
        run_isolated_simulation()

    events = platform_ctx.ledger.get_events(limit=20)

    if format == "csv":
        csv_data = ReportExporter.generate_actions_csv(platform_ctx.current_plan)
        return {"format": "csv", "data": csv_data}
    elif format == "text":
        text_data = ReportExporter.generate_executive_text_summary(
            platform_ctx.active_scenario_name, platform_ctx.last_simulation, platform_ctx.current_plan
        )
        return {"format": "text", "data": text_data}
    else:
        json_data = ReportExporter.generate_incident_json(
            platform_ctx.active_scenario_name, platform_ctx.last_simulation, platform_ctx.current_plan, events
        )
        return {"format": "json", "data": json.loads(json_data)}


# =====================================================================
# MACHINE LEARNING PIPELINE SUBROUTER (PHASE 7.1 - 7.2D)
# =====================================================================
from backend.app.ml.router import router as ml_router
api_router.include_router(ml_router)

# =====================================================================
# THREAT INTELLIGENCE CORRELATION ENGINE SUBROUTER (PHASE 7.2E)
# =====================================================================
from backend.app.threat_intel.router import router as threat_intel_router
api_router.include_router(threat_intel_router)

# =====================================================================
# TEMPORAL THREAT FORECASTING ENGINE SUBROUTER (PHASE 7.3)
# =====================================================================
from backend.app.forecasting.router import router as forecasting_router
api_router.include_router(forecasting_router)

# =====================================================================
# ADAPTIVE INTELLIGENCE & FEEDBACK LOOP SUBROUTER (PHASE 7.4)
# =====================================================================
from backend.app.adaptive.router import router as adaptive_router
api_router.include_router(adaptive_router)

# =====================================================================
# ADAPTIVE RISK CALIBRATION & THRESHOLD OPTIMIZATION SUBROUTER (PHASE 7.5)
# =====================================================================
from backend.app.calibration.router import router as calibration_router
api_router.include_router(calibration_router)

# =====================================================================
# PREDICTIVE THREAT INTELLIGENCE & EARLY-WARNING SUBROUTER (PHASE 7.6)
# =====================================================================
from backend.app.early_warning.router import router as early_warning_router
api_router.include_router(early_warning_router)



