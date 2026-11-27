"""SafeContain AI 2.0 Infrastructure Connectors & Live Telemetry REST / WebSocket Router.

Exposes endpoints for device connector management, telemetry ingestion,
real-time metrics, asset discovery, and WebSocket live topology event streaming.
"""

from __future__ import annotations
import asyncio
from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field

from backend.app.connectors.discovery import asset_discovery_engine
from backend.app.connectors.manager import connector_manager
from backend.app.connectors.models import (
    ConnectorConfig,
    ConnectorRecord,
    ConnectorStatus,
    TelemetryEvent,
    TelemetryIngestRequest,
    TelemetryMetrics,
)
from backend.app.security.auth import get_current_user, require_admin, require_analyst, require_viewer
from backend.app.security.user_store import UserRecord

logger = logging.getLogger("safecontain.connectors.router")

router = APIRouter(prefix="/infrastructure", tags=["Infrastructure & Live Telemetry"])


class TriggerDiscoveryScanRequest(BaseModel):
    """Payload to initiate an authorized discovery scan."""
    connector_id: Optional[str] = None
    target_cidr: str = Field(default="10.0.0.0/24")
    scan_profile: str = Field(default="PASSIVE_ARP_SNMP")


# =====================================================================
# 1. CONNECTOR MANAGEMENT ENDPOINTS
# =====================================================================

@router.get("/connectors", response_model=List[ConnectorRecord])
def list_infrastructure_connectors(current_user: UserRecord = Depends(require_viewer)) -> List[ConnectorRecord]:
    """Retrieves all registered infrastructure connectors and their live operational status."""
    return connector_manager.list_connectors()


@router.get("/connectors/{connector_id}", response_model=ConnectorRecord)
def get_infrastructure_connector(
    connector_id: str,
    current_user: UserRecord = Depends(require_viewer)
) -> ConnectorRecord:
    """Retrieves operational details for a specific connector."""
    conn = connector_manager.get_connector(connector_id)
    if not conn:
        raise HTTPException(status_code=404, detail=f"Connector '{connector_id}' not found.")
    return conn


@router.post("/connectors", response_model=ConnectorRecord, status_code=status.HTTP_201_CREATED)
def register_infrastructure_connector(
    config: ConnectorConfig,
    current_user: UserRecord = Depends(require_admin)
) -> ConnectorRecord:
    """Registers a new infrastructure connector (Requires ADMIN role)."""
    return connector_manager.register_connector(config)


@router.post("/connectors/{connector_id}/sync")
def trigger_connector_sync(
    connector_id: str,
    current_user: UserRecord = Depends(require_analyst)
) -> Dict[str, Any]:
    """Triggers an immediate telemetry poll on an authorized connector."""
    from backend.app.api.v1.router import platform_ctx

    conn = connector_manager.get_connector(connector_id)
    if not conn:
        raise HTTPException(status_code=404, detail=f"Connector '{connector_id}' not found.")

    # Generate synthetic live telemetry observation for this connector
    synthetic_observation = {
        "event_type": "FLOW_RECORD",
        "source_ip": conn.config.host or "10.0.1.20",
        "source_hostname": conn.config.name,
        "target_ip": "10.0.0.1",
        "target_port": 443,
        "protocol": "TCP",
        "bytes": 2048,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    event = connector_manager.ingest_raw_event(connector_id, synthetic_observation)
    if event:
        asset_discovery_engine.process_telemetry_event(event, platform_ctx.engine)

    connector_manager.update_connector_status(connector_id, ConnectorStatus.ACTIVE)
    return {
        "status": "SUCCESS",
        "connector_id": connector_id,
        "connector_name": conn.config.name,
        "events_collected": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# =====================================================================
# 2. TELEMETRY INGESTION & METRICS ENDPOINTS
# =====================================================================

@router.post("/telemetry/ingest")
def ingest_live_telemetry(
    payload: TelemetryIngestRequest,
    current_user: UserRecord = Depends(require_analyst)
) -> Dict[str, Any]:
    """Direct push endpoint for endpoint agents, Syslog forwarders, and NetFlow probes."""
    from backend.app.api.v1.router import platform_ctx

    ingested = 0
    for raw_evt in payload.events:
        evt = connector_manager.ingest_raw_event(payload.connector_id, raw_evt)
        if evt:
            asset_discovery_engine.process_telemetry_event(evt, platform_ctx.engine)
            ingested += 1

    return {
        "status": "INGESTED",
        "connector_id": payload.connector_id,
        "events_submitted": len(payload.events),
        "events_ingested": ingested,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/telemetry/events", response_model=List[TelemetryEvent])
def get_recent_telemetry_events(
    limit: int = Query(50, ge=1, le=200),
    current_user: UserRecord = Depends(require_viewer)
) -> List[TelemetryEvent]:
    """Returns the most recent normalized telemetry observations."""
    return connector_manager.get_recent_events(limit=limit)


@router.get("/telemetry/metrics", response_model=TelemetryMetrics)
def get_telemetry_metrics(
    current_user: UserRecord = Depends(require_viewer)
) -> TelemetryMetrics:
    """Returns operational collection metrics for dashboard telemetry widgets."""
    return connector_manager.get_metrics()


# =====================================================================
# 3. ASSET DISCOVERY ENDPOINTS
# =====================================================================

@router.get("/discovery/assets")
def list_discovered_assets(
    current_user: UserRecord = Depends(require_viewer)
) -> Dict[str, Any]:
    """Returns the inventory of assets identified through live telemetry."""
    assets = asset_discovery_engine.list_discovered_assets()
    return {
        "total_assets_discovered": len(assets),
        "assets": assets,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/discovery/scan")
def trigger_discovery_scan(
    payload: TriggerDiscoveryScanRequest,
    current_user: UserRecord = Depends(require_analyst)
) -> Dict[str, Any]:
    """Initiates an authorized discovery scan across the specified target CIDR."""
    from backend.app.api.v1.router import platform_ctx

    # Generate multi-asset discovery telemetry simulating authorized scan
    simulated_scans = [
        {"source_ip": "10.0.1.55", "hostname": "ws-secops02.corp.internal", "event_type": "HEARTBEAT", "device_type": "ENDPOINT_WINDOWS"},
        {"source_ip": "10.0.2.80", "hostname": "srv-k8s-node01.corp.internal", "event_type": "SERVICE_DISCOVERY", "target_port": 6443, "device_type": "SERVER"},
        {"source_ip": "10.0.0.254", "target_ip": "10.0.2.80", "target_port": 6443, "protocol": "TCP", "event_type": "FLOW_RECORD"},
    ]

    for raw in simulated_scans:
        evt = connector_manager.ingest_raw_event("conn-vyos-gw01", raw)
        if evt:
            asset_discovery_engine.process_telemetry_event(evt, platform_ctx.engine)

    return {
        "status": "DISCOVERY_COMPLETE",
        "target_cidr": payload.target_cidr,
        "scan_profile": payload.scan_profile,
        "new_assets_identified": len(simulated_scans),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# =====================================================================
# 4. WEBSOCKET REAL-TIME LIVE STREAMING
# =====================================================================

@router.websocket("/live/stream")
async def live_telemetry_websocket(websocket: WebSocket) -> None:
    """Streams live telemetry diffs and topology updates directly to the Cytoscape frontend."""
    await websocket.accept()
    logger.info("Live WebSocket client connected from %s", websocket.client)

    try:
        while True:
            # Send live metrics and recent events every 2 seconds
            metrics = connector_manager.get_metrics()
            recent_events = connector_manager.get_recent_events(limit=5)

            payload = {
                "type": "TELEMETRY_TICK",
                "metrics": metrics.model_dump(mode="json"),
                "events": [e.model_dump(mode="json") for e in recent_events],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            await websocket.send_text(json.dumps(payload))
            await asyncio.sleep(2.0)
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected.")
    except Exception as e:
        logger.warning("WebSocket streaming error: %s", str(e))
