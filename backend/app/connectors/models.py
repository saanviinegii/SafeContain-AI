"""SafeContain AI 2.0 Autonomous Infrastructure Connector Domain Models.

Defines schemas for heterogeneous infrastructure inputs (Windows/Linux endpoints,
switches, routers, firewalls, servers, databases, and software feeds),
telemetry events, normalization pipelines, and collector health tracking.
"""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field


class DeviceType(str, Enum):
    """Categorization of managed cyber defense assets and sensory inputs."""
    ENDPOINT_WINDOWS = "ENDPOINT_WINDOWS"
    ENDPOINT_LINUX = "ENDPOINT_LINUX"
    SWITCH = "SWITCH"
    ROUTER = "ROUTER"
    FIREWALL = "FIREWALL"
    SERVER = "SERVER"
    DATABASE = "DATABASE"
    SOFTWARE_SIEM = "SOFTWARE_SIEM"
    SOFTWARE_EDR = "SOFTWARE_EDR"
    SOFTWARE_CSV = "SOFTWARE_CSV"


class ConnectorProtocol(str, Enum):
    """Network and application protocols supported for telemetry collection."""
    AGENT_REST = "AGENT_REST"
    SYSLOG_RFC5424 = "SYSLOG_RFC5424"
    NETFLOW_V9 = "NETFLOW_V9"
    IPFIX = "IPFIX"
    SNMP_V3 = "SNMP_V3"
    REST_API = "REST_API"
    POSTGRESQL_NATIVE = "POSTGRESQL_NATIVE"
    WEBHOOK = "WEBHOOK"
    FILE_STREAM = "FILE_STREAM"


class ConnectorStatus(str, Enum):
    """Live operational state of an infrastructure connector."""
    ACTIVE = "ACTIVE"
    CONFIGURED = "CONFIGURED"
    CONNECTED = "CONNECTED"
    RECEIVING_DATA = "RECEIVING_DATA"
    DEGRADED = "DEGRADED"
    DISCONNECTED = "DISCONNECTED"
    ERROR = "ERROR"
    BLOCKED = "BLOCKED"
    OFFLINE = "OFFLINE"
    UNCONFIGURED = "UNCONFIGURED"


class TelemetryEventType(str, Enum):
    """Normalized telemetry event classifications."""
    HEARTBEAT = "HEARTBEAT"
    PROCESS_SPAWN = "PROCESS_SPAWN"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    FLOW_RECORD = "FLOW_RECORD"
    FIREWALL_ALLOW = "FIREWALL_ALLOW"
    FIREWALL_DENY = "FIREWALL_DENY"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAILURE = "AUTH_FAILURE"
    INTERFACE_STATUS = "INTERFACE_STATUS"
    LLDP_NEIGHBOR = "LLDP_NEIGHBOR"
    SERVICE_DISCOVERY = "SERVICE_DISCOVERY"
    VULNERABILITY_FOUND = "VULNERABILITY_FOUND"


class ConnectorConfig(BaseModel):
    """Static and operational configuration for a device connector."""
    id: str = Field(default_factory=lambda: f"conn-{uuid.uuid4().hex[:8]}")
    name: str
    device_type: DeviceType
    protocol: ConnectorProtocol
    host: Optional[str] = None
    port: Optional[int] = None
    auth_credential_id: Optional[str] = None
    polling_interval_seconds: int = 10
    is_enabled: bool = True
    authorized_scope: List[str] = Field(default_factory=lambda: ["10.0.0.0/8", "192.168.0.0/16"])
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ConnectorRuntime(BaseModel):
    """Real-time observability statistics for a registered connector."""
    connector_id: str
    connection_state: ConnectorStatus = ConnectorStatus.ACTIVE
    authentication_status: str = "AUTHENTICATED"
    last_successful_collection: Optional[str] = None
    last_error: Optional[str] = None
    total_events_collected: int = 0
    bytes_received: int = 0
    collection_latency_ms: float = 0.0
    consecutive_failures: int = 0


class ConnectorRecord(BaseModel):
    """Complete connector representation uniting configuration and runtime health."""
    config: ConnectorConfig
    runtime: ConnectorRuntime


class TelemetryEvent(BaseModel):
    """Canonical normalized telemetry observation ingested by SafeContain AI 2.0."""
    event_id: str = Field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:12]}")
    connector_id: str
    device_type: DeviceType
    event_type: TelemetryEventType
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_ip: Optional[str] = None
    source_mac: Optional[str] = None
    source_hostname: Optional[str] = None
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_transferred: int = 0
    severity: str = "INFO"
    confidence: float = 1.0
    evidence_status: str = "CONFIRMED"
    raw_payload: Dict[str, Any] = Field(default_factory=dict)
    normalized_properties: Dict[str, Any] = Field(default_factory=dict)


class TelemetryIngestRequest(BaseModel):
    """Payload for submitting live telemetry observations from endpoints/probes."""
    connector_id: str
    events: List[Dict[str, Any]]


class TelemetryMetrics(BaseModel):
    """High-level metrics for dashboard visualization of live telemetry collection."""
    total_events_received: int
    events_per_second: float
    online_devices_count: int
    offline_devices_count: int
    newly_discovered_assets_count: int
    active_collectors_count: int
    failed_collectors_count: int
    avg_collection_latency_ms: float
    last_telemetry_timestamp: Optional[str] = None
    collector_health_ratio: float = 1.0
