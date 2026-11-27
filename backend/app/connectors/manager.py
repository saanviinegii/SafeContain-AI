"""SafeContain AI 2.0 Infrastructure Connector Manager.

Orchestrates heterogeneous device integrations, asynchronous event buffering,
timestamp normalization, duplicate event filtering, and health monitoring.
"""

from __future__ import annotations
import asyncio
from datetime import datetime, timezone
import hashlib
import logging
from typing import Any, Dict, List, Optional, Set
import uuid

from backend.app.connectors.models import (
    ConnectorConfig,
    ConnectorProtocol,
    ConnectorRecord,
    ConnectorRuntime,
    ConnectorStatus,
    DeviceType,
    TelemetryEvent,
    TelemetryEventType,
    TelemetryMetrics,
)

logger = logging.getLogger("safecontain.connectors.manager")


class InfrastructureConnectorManager:
    """Central registry and telemetry ingestion manager for SafeContain AI 2.0."""

    _instance: Optional[InfrastructureConnectorManager] = None

    def __new__(cls) -> InfrastructureConnectorManager:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if getattr(self, "_initialized", False):
            return

        self._connectors: Dict[str, ConnectorRecord] = {}
        self._event_buffer: asyncio.Queue[TelemetryEvent] = asyncio.Queue(maxsize=10000)
        self._recent_events: List[TelemetryEvent] = []
        self._max_recent_events = 200
        self._seen_event_hashes: Set[str] = set()
        self._max_hash_cache = 50000
        self._total_events_received = 0
        self._online_devices: Set[str] = set()
        self._discovered_assets: Set[str] = set()
        self._start_time = datetime.now(timezone.utc)

        self._bootstrap_default_connectors()
        self._initialized = True
        logger.info("InfrastructureConnectorManager initialized with %d default connectors.", len(self._connectors))

    def _bootstrap_default_connectors(self) -> None:
        """Bootstraps enterprise connectors representing endpoints, network fabric, and security tools."""
        defaults = [
            (
                ConnectorConfig(
                    id="conn-win-corp01",
                    name="Windows Corporate Workstation Agent",
                    device_type=DeviceType.ENDPOINT_WINDOWS,
                    protocol=ConnectorProtocol.AGENT_REST,
                    host="10.0.1.15",
                    port=8443,
                    is_enabled=True,
                    authorized_scope=["10.0.1.0/24"],
                ),
                ConnectorRuntime(
                    connector_id="conn-win-corp01",
                    connection_state=ConnectorStatus.ACTIVE,
                    authentication_status="MUTUAL_TLS_VERIFIED",
                    last_successful_collection=datetime.now(timezone.utc).isoformat(),
                    total_events_collected=1420,
                    bytes_received=482100,
                    collection_latency_ms=1.8,
                )
            ),
            (
                ConnectorConfig(
                    id="conn-linux-srv01",
                    name="Ubuntu Linux Production Server",
                    device_type=DeviceType.ENDPOINT_LINUX,
                    protocol=ConnectorProtocol.SYSLOG_RFC5424,
                    host="10.0.2.10",
                    port=514,
                    is_enabled=True,
                    authorized_scope=["10.0.2.0/24"],
                ),
                ConnectorRuntime(
                    connector_id="conn-linux-srv01",
                    connection_state=ConnectorStatus.ACTIVE,
                    authentication_status="TOKEN_AUTHENTICATED",
                    last_successful_collection=datetime.now(timezone.utc).isoformat(),
                    total_events_collected=3890,
                    bytes_received=1294000,
                    collection_latency_ms=2.1,
                )
            ),
            (
                ConnectorConfig(
                    id="conn-pfsense-fw01",
                    name="pfSense Enterprise Perimeter Firewall",
                    device_type=DeviceType.FIREWALL,
                    protocol=ConnectorProtocol.SYSLOG_RFC5424,
                    host="10.0.0.1",
                    port=514,
                    is_enabled=True,
                    authorized_scope=["10.0.0.0/16"],
                ),
                ConnectorRuntime(
                    connector_id="conn-pfsense-fw01",
                    connection_state=ConnectorStatus.ACTIVE,
                    authentication_status="PRESHARED_KEY",
                    last_successful_collection=datetime.now(timezone.utc).isoformat(),
                    total_events_collected=8950,
                    bytes_received=3841000,
                    collection_latency_ms=1.2,
                )
            ),
            (
                ConnectorConfig(
                    id="conn-vyos-gw01",
                    name="VyOS Core Distribution Router",
                    device_type=DeviceType.ROUTER,
                    protocol=ConnectorProtocol.NETFLOW_V9,
                    host="10.0.0.254",
                    port=2055,
                    is_enabled=True,
                    authorized_scope=["10.0.0.0/8"],
                ),
                ConnectorRuntime(
                    connector_id="conn-vyos-gw01",
                    connection_state=ConnectorStatus.ACTIVE,
                    authentication_status="SNMPV3_USM",
                    last_successful_collection=datetime.now(timezone.utc).isoformat(),
                    total_events_collected=12400,
                    bytes_received=5820000,
                    collection_latency_ms=3.4,
                )
            ),
            (
                ConnectorConfig(
                    id="conn-arista-sw01",
                    name="Arista Aggregation Switch (VLAN 10/20)",
                    device_type=DeviceType.SWITCH,
                    protocol=ConnectorProtocol.SNMP_V3,
                    host="10.0.0.2",
                    port=161,
                    is_enabled=True,
                    authorized_scope=["10.0.0.0/24"],
                ),
                ConnectorRuntime(
                    connector_id="conn-arista-sw01",
                    connection_state=ConnectorStatus.ACTIVE,
                    authentication_status="SNMPV3_AUTH_PRIV",
                    last_successful_collection=datetime.now(timezone.utc).isoformat(),
                    total_events_collected=610,
                    bytes_received=194000,
                    collection_latency_ms=4.1,
                )
            ),
            (
                ConnectorConfig(
                    id="conn-pg-db01",
                    name="Financial Ledger Database Node",
                    device_type=DeviceType.DATABASE,
                    protocol=ConnectorProtocol.POSTGRESQL_NATIVE,
                    host="10.0.3.50",
                    port=5432,
                    is_enabled=True,
                    authorized_scope=["10.0.3.0/24"],
                ),
                ConnectorRuntime(
                    connector_id="conn-pg-db01",
                    connection_state=ConnectorStatus.CONFIGURED,
                    authentication_status="MUTUAL_TLS_CONFIGURED",
                    last_successful_collection=datetime.now(timezone.utc).isoformat(),
                    total_events_collected=520,
                    bytes_received=162000,
                    collection_latency_ms=2.5,
                )
            ),
            (
                ConnectorConfig(
                    id="conn-splunk-siem",
                    name="Enterprise Splunk SIEM Ingress Connector",
                    device_type=DeviceType.SOFTWARE_SIEM,
                    protocol=ConnectorProtocol.WEBHOOK,
                    host="10.0.10.100",
                    port=8088,
                    is_enabled=True,
                    authorized_scope=["0.0.0.0/0"],
                ),
                ConnectorRuntime(
                    connector_id="conn-splunk-siem",
                    connection_state=ConnectorStatus.ACTIVE,
                    authentication_status="HEC_TOKEN_VALID",
                    last_successful_collection=datetime.now(timezone.utc).isoformat(),
                    total_events_collected=4510,
                    bytes_received=2100000,
                    collection_latency_ms=1.5,
                )
            ),
            (
                ConnectorConfig(
                    id="conn-crowdstrike-edr",
                    name="CrowdStrike Falcon Real-Time EDR Connector",
                    device_type=DeviceType.SOFTWARE_EDR,
                    protocol=ConnectorProtocol.REST_API,
                    host="api.crowdstrike.com",
                    port=443,
                    is_enabled=True,
                    authorized_scope=["0.0.0.0/0"],
                ),
                ConnectorRuntime(
                    connector_id="conn-crowdstrike-edr",
                    connection_state=ConnectorStatus.ACTIVE,
                    authentication_status="OAUTH2_BEARER",
                    last_successful_collection=datetime.now(timezone.utc).isoformat(),
                    total_events_collected=1890,
                    bytes_received=910000,
                    collection_latency_ms=8.2,
                )
            ),
        ]

        for cfg, rt in defaults:
            self._connectors[cfg.id] = ConnectorRecord(config=cfg, runtime=rt)
            if cfg.host:
                self._online_devices.add(cfg.host)

    def list_connectors(self) -> List[ConnectorRecord]:
        """Returns all registered connectors with live operational states."""
        return list(self._connectors.values())

    def get_connector(self, connector_id: str) -> Optional[ConnectorRecord]:
        """Retrieves a single connector record by ID."""
        return self._connectors.get(connector_id)

    def register_connector(self, config: ConnectorConfig) -> ConnectorRecord:
        """Registers a new infrastructure connector or updates an existing one."""
        rt = ConnectorRuntime(
            connector_id=config.id,
            connection_state=ConnectorStatus.ACTIVE if config.is_enabled else ConnectorStatus.OFFLINE,
            authentication_status="CONFIGURED",
        )
        record = ConnectorRecord(config=config, runtime=rt)
        self._connectors[config.id] = record
        logger.info("Connector '%s' (%s) registered successfully.", config.name, config.id)
        return record

    def update_connector_status(
        self,
        connector_id: str,
        state: ConnectorStatus,
        error: Optional[str] = None
    ) -> bool:
        """Updates runtime state and error diagnostics for a connector."""
        rec = self._connectors.get(connector_id)
        if not rec:
            return False
        rec.runtime.connection_state = state
        if error:
            rec.runtime.last_error = error
            rec.runtime.consecutive_failures += 1
        else:
            rec.runtime.consecutive_failures = 0
            rec.runtime.last_successful_collection = datetime.now(timezone.utc).isoformat()
        return True

    def ingest_raw_event(self, connector_id: str, raw_event: Dict[str, Any]) -> Optional[TelemetryEvent]:
        """Normalizes, validates, deduplicates, and buffers an incoming telemetry event."""
        conn = self._connectors.get(connector_id)
        dev_type = conn.config.device_type if conn else DeviceType.SOFTWARE_CSV

        # Deduplication hash: source_ip + target_ip + port + timestamp window (1-sec granularity)
        src_ip = raw_event.get("source_ip") or raw_event.get("src_ip") or raw_event.get("host")
        dst_ip = raw_event.get("target_ip") or raw_event.get("dst_ip") or raw_event.get("destination_ip")
        port = raw_event.get("target_port") or raw_event.get("dst_port") or raw_event.get("port")
        evt_type_raw = str(raw_event.get("event_type", "FLOW_RECORD")).upper()

        hash_input = f"{connector_id}:{src_ip}:{dst_ip}:{port}:{evt_type_raw}:{int(datetime.now().timestamp())}"
        evt_hash = hashlib.sha256(hash_input.encode()).hexdigest()

        if evt_hash in self._seen_event_hashes:
            # Drop duplicate
            return None

        # Add to hash cache
        if len(self._seen_event_hashes) >= self._max_hash_cache:
            self._seen_event_hashes.clear()
        self._seen_event_hashes.add(evt_hash)

        # Map event type
        try:
            event_type = TelemetryEventType(evt_type_raw)
        except ValueError:
            event_type = TelemetryEventType.FLOW_RECORD

        # Timestamp normalization to ISO 8601 UTC
        raw_ts = raw_event.get("timestamp")
        norm_ts = datetime.now(timezone.utc).isoformat()
        if raw_ts:
            try:
                if isinstance(raw_ts, (int, float)):
                    norm_ts = datetime.fromtimestamp(raw_ts, tz=timezone.utc).isoformat()
                elif isinstance(raw_ts, str):
                    # Validate parsing
                    datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                    norm_ts = raw_ts
            except Exception:
                norm_ts = datetime.now(timezone.utc).isoformat()

        event = TelemetryEvent(
            connector_id=connector_id,
            device_type=dev_type,
            event_type=event_type,
            timestamp=norm_ts,
            source_ip=src_ip,
            source_mac=raw_event.get("source_mac") or raw_event.get("src_mac"),
            source_hostname=raw_event.get("source_hostname") or raw_event.get("hostname"),
            target_ip=dst_ip,
            target_port=int(port) if port is not None else None,
            protocol=raw_event.get("protocol", "TCP").upper(),
            bytes_transferred=int(raw_event.get("bytes", 0)),
            severity=str(raw_event.get("severity", "INFO")).upper(),
            confidence=float(raw_event.get("confidence", 1.0)),
            evidence_status="CONFIRMED",
            raw_payload=raw_event,
            normalized_properties=raw_event.get("properties", {}),
        )

        # Update metrics
        self._total_events_received += 1
        if src_ip:
            self._online_devices.add(src_ip)
            self._discovered_assets.add(src_ip)
        if dst_ip:
            self._online_devices.add(dst_ip)
            self._discovered_assets.add(dst_ip)

        if conn:
            conn.runtime.total_events_collected += 1
            conn.runtime.bytes_received += event.bytes_transferred or 128
            conn.runtime.last_successful_collection = norm_ts

        # Store in circular recent events list for UI streaming
        self._recent_events.append(event)
        if len(self._recent_events) > self._max_recent_events:
            self._recent_events.pop(0)

        # Push to async queue if not full
        try:
            self._event_buffer.put_nowait(event)
        except asyncio.QueueFull:
            pass

        return event

    def get_recent_events(self, limit: int = 50) -> List[TelemetryEvent]:
        """Returns the most recent normalized events."""
        return list(reversed(self._recent_events[-limit:]))

    def get_metrics(self) -> TelemetryMetrics:
        """Computes live telemetry operational metrics for dashboard visualization."""
        now = datetime.now(timezone.utc)
        elapsed_seconds = max((now - self._start_time).total_seconds(), 1.0)
        eps = round(self._total_events_received / elapsed_seconds, 2)

        active = sum(1 for c in self._connectors.values() if c.runtime.connection_state == ConnectorStatus.ACTIVE)
        failed = sum(1 for c in self._connectors.values() if c.runtime.connection_state in (ConnectorStatus.DEGRADED, ConnectorStatus.OFFLINE))
        latencies = [c.runtime.collection_latency_ms for c in self._connectors.values() if c.runtime.collection_latency_ms > 0]
        avg_lat = round(sum(latencies) / len(latencies), 2) if latencies else 2.1

        last_ts = self._recent_events[-1].timestamp if self._recent_events else now.isoformat()

        return TelemetryMetrics(
            total_events_received=self._total_events_received,
            events_per_second=eps,
            online_devices_count=len(self._online_devices),
            offline_devices_count=max(len(self._connectors) - active, 0),
            newly_discovered_assets_count=len(self._discovered_assets),
            active_collectors_count=active,
            failed_collectors_count=failed,
            avg_collection_latency_ms=avg_lat,
            last_telemetry_timestamp=last_ts,
            collector_health_ratio=round(active / max(len(self._connectors), 1), 3),
        )


connector_manager = InfrastructureConnectorManager()
