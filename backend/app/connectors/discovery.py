"""SafeContain AI 2.0 Autonomous Asset Discovery and Dynamic Graph Engine.

Performs multi-key identity resolution (UUID > MAC > SID > Hostname > IP),
asset normalization, duplicate entity prevention, and automated Neo4j / NetworkX
graph node and relationship synthesis from streaming telemetry observations.
"""

from __future__ import annotations
from datetime import datetime, timezone
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.app.connectors.models import (
    DeviceType,
    TelemetryEvent,
    TelemetryEventType,
)
from backend.app.models.domain import (
    DataProvenance,
    EvidenceStatus,
    GraphEdge,
    GraphNode,
    NodeType,
    RelationshipType,
)

logger = logging.getLogger("safecontain.connectors.discovery")


class DiscoveredAssetRecord:
    """Canonical representation of an identified enterprise asset."""

    def __init__(
        self,
        asset_id: str,
        name: str,
        device_type: DeviceType,
        ip: str,
        mac: Optional[str] = None,
        hostname: Optional[str] = None,
        hardware_uuid: Optional[str] = None,
        criticality: int = 3,
        owner: str = "Enterprise IT",
        os: str = "Unknown",
    ):
        self.asset_id = asset_id
        self.name = name
        self.device_type = device_type
        self.current_ip = ip
        self.ip_history: List[str] = [ip]
        self.mac = mac
        self.hostname = hostname
        self.hardware_uuid = hardware_uuid
        self.criticality = criticality
        self.owner = owner
        self.os = os
        self.is_online = True
        self.first_seen = datetime.now(timezone.utc).isoformat()
        self.last_seen = self.first_seen
        self.observed_services: Set[int] = set()
        self.confidence = 1.0


class AssetDiscoveryEngine:
    """Discovers, normalizes, deduplicates, and synchronizes assets to Neo4j/NetworkX."""

    _instance: Optional[AssetDiscoveryEngine] = None

    def __new__(cls) -> AssetDiscoveryEngine:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if getattr(self, "_initialized", False):
            return

        self._assets_by_id: Dict[str, DiscoveredAssetRecord] = {}
        # Multi-key resolution lookup maps
        self._uuid_to_id: Dict[str, str] = {}
        self._mac_to_id: Dict[str, str] = {}
        self._hostname_to_id: Dict[str, str] = {}
        self._ip_to_id: Dict[str, str] = {}

        self._bootstrap_known_infrastructure()
        self._initialized = True
        logger.info("AssetDiscoveryEngine initialized with %d baseline assets.", len(self._assets_by_id))

    def _bootstrap_known_infrastructure(self) -> None:
        """Seeds baseline known enterprise network topology."""
        baseline = [
            DiscoveredAssetRecord(
                asset_id="node-fw-01",
                name="Perimeter pfSense Firewall",
                device_type=DeviceType.FIREWALL,
                ip="10.0.0.1",
                mac="00:50:56:A1:00:01",
                hostname="fw-perimeter.corp.internal",
                hardware_uuid="d9a1-fw-0001",
                criticality=5,
                owner="Network Security Ops",
                os="FreeBSD / pfSense 2.7",
            ),
            DiscoveredAssetRecord(
                asset_id="node-rtr-01",
                name="VyOS Core Distribution Router",
                device_type=DeviceType.ROUTER,
                ip="10.0.0.254",
                mac="00:50:56:A1:00:FE",
                hostname="rtr-core.corp.internal",
                hardware_uuid="d9a1-rtr-0254",
                criticality=5,
                owner="Network Infrastructure",
                os="Linux / VyOS 1.4",
            ),
            DiscoveredAssetRecord(
                asset_id="node-sw-01",
                name="Arista Aggregation Switch",
                device_type=DeviceType.SWITCH,
                ip="10.0.0.2",
                mac="00:50:56:A1:00:02",
                hostname="sw-agg01.corp.internal",
                hardware_uuid="d9a1-sw-0002",
                criticality=4,
                owner="Network Infrastructure",
                os="EOS 4.28",
            ),
            DiscoveredAssetRecord(
                asset_id="node-srv-linux01",
                name="Ubuntu Financial API Server",
                device_type=DeviceType.SERVER,
                ip="10.0.2.10",
                mac="00:50:56:B2:02:10",
                hostname="srv-api01.corp.internal",
                hardware_uuid="d9a1-srv-0210",
                criticality=4,
                owner="FinTech Platform Team",
                os="Ubuntu Linux 24.04 LTS",
            ),
            DiscoveredAssetRecord(
                asset_id="node-db-fin01",
                name="PostgreSQL Core Ledger Database",
                device_type=DeviceType.DATABASE,
                ip="10.0.3.50",
                mac="00:50:56:C3:03:50",
                hostname="db-ledger.corp.internal",
                hardware_uuid="d9a1-db-0350",
                criticality=5,
                owner="Data Engineering",
                os="PostgreSQL 16.3 on RHEL 9",
            ),
            DiscoveredAssetRecord(
                asset_id="node-win-dev01",
                name="Windows 11 Developer Workstation",
                device_type=DeviceType.ENDPOINT_WINDOWS,
                ip="10.0.1.15",
                mac="00:50:56:D4:01:15",
                hostname="ws-dev01.corp.internal",
                hardware_uuid="d9a1-ws-0115",
                criticality=2,
                owner="Engineering Staff",
                os="Windows 11 Pro Enterprise",
            ),
        ]

        for asset in baseline:
            self._register_asset(asset)

    def _register_asset(self, asset: DiscoveredAssetRecord) -> None:
        """Stores asset and indexes resolution keys."""
        self._assets_by_id[asset.asset_id] = asset
        if asset.hardware_uuid:
            self._uuid_to_id[asset.hardware_uuid.lower()] = asset.asset_id
        if asset.mac:
            self._mac_to_id[asset.mac.lower().replace("-", ":")] = asset.asset_id
        if asset.hostname:
            self._hostname_to_id[asset.hostname.lower()] = asset.asset_id
        if asset.current_ip:
            self._ip_to_id[asset.current_ip] = asset.asset_id

    def resolve_identity(
        self,
        ip: Optional[str] = None,
        mac: Optional[str] = None,
        hostname: Optional[str] = None,
        uuid_str: Optional[str] = None,
    ) -> Optional[DiscoveredAssetRecord]:
        """Multi-Key 4-Tier Identity Resolution Hierarchy: UUID > MAC > Hostname > IP."""
        # Tier 1: Hardware UUID
        if uuid_str and uuid_str.lower() in self._uuid_to_id:
            return self._assets_by_id[self._uuid_to_id[uuid_str.lower()]]

        # Tier 2: Primary MAC Address
        if mac:
            clean_mac = mac.lower().replace("-", ":")
            if clean_mac in self._mac_to_id:
                return self._assets_by_id[self._mac_to_id[clean_mac]]

        # Tier 3: Static Hostname
        if hostname and hostname.lower() in self._hostname_to_id:
            return self._assets_by_id[self._hostname_to_id[hostname.lower()]]

        # Tier 4: IP Address
        if ip and ip in self._ip_to_id:
            return self._assets_by_id[self._ip_to_id[ip]]

        return None

    def process_telemetry_event(self, event: TelemetryEvent, graph_engine: Any) -> Optional[DiscoveredAssetRecord]:
        """Ingests a telemetry event, updates or creates asset records, and updates the graph."""
        src_ip = event.source_ip
        if not src_ip or src_ip in ("127.0.0.1", "0.0.0.0", "::1"):
            return None

        # Resolve existing entity
        asset = self.resolve_identity(
            ip=src_ip,
            mac=event.source_mac,
            hostname=event.source_hostname,
        )

        now_iso = event.timestamp or datetime.now(timezone.utc).isoformat()

        if asset:
            # Asset exists: Update runtime observation state
            asset.last_seen = now_iso
            asset.is_online = True
            if src_ip not in asset.ip_history:
                asset.ip_history.append(src_ip)
                asset.current_ip = src_ip
                self._ip_to_id[src_ip] = asset.asset_id
            if event.source_mac and not asset.mac:
                asset.mac = event.source_mac
                self._mac_to_id[event.source_mac.lower().replace("-", ":")] = asset.asset_id
            if event.source_hostname and not asset.hostname:
                asset.hostname = event.source_hostname
                self._hostname_to_id[event.source_hostname.lower()] = asset.asset_id
        else:
            # New asset discovered automatically
            new_id = f"node-auto-{uuid.uuid4().hex[:6]}"
            hname = event.source_hostname or f"host-{src_ip.replace('.', '-')}"
            dev_type = event.device_type
            crit = 3
            if dev_type in (DeviceType.DATABASE, DeviceType.FIREWALL, DeviceType.ROUTER):
                crit = 5
            elif dev_type in (DeviceType.SERVER,):
                crit = 4

            asset = DiscoveredAssetRecord(
                asset_id=new_id,
                name=hname,
                device_type=dev_type,
                ip=src_ip,
                mac=event.source_mac,
                hostname=event.source_hostname,
                criticality=crit,
                owner="Auto-Discovered Ingress",
                os="Detected OS",
            )
            self._register_asset(asset)
            logger.info("Auto-discovered new asset %s (%s) from connector %s", asset.name, src_ip, event.connector_id)

        # Synchronize asset node to graph engine
        self._sync_node_to_graph(asset, graph_engine)

        # If event has target, discover and link target asset
        dst_ip = event.target_ip
        if dst_ip and dst_ip not in ("127.0.0.1", "0.0.0.0", "::1", "255.255.255.255"):
            dst_asset = self.resolve_identity(ip=dst_ip)
            if not dst_asset:
                dst_id = f"node-auto-{uuid.uuid4().hex[:6]}"
                dst_asset = DiscoveredAssetRecord(
                    asset_id=dst_id,
                    name=f"host-{dst_ip.replace('.', '-')}",
                    device_type=DeviceType.SERVER if (event.target_port and event.target_port < 1024) else DeviceType.ENDPOINT_LINUX,
                    ip=dst_ip,
                    criticality=3,
                    owner="Auto-Discovered Peer",
                )
                self._register_asset(dst_asset)
                self._sync_node_to_graph(dst_asset, graph_engine)

            # Synthesize relationship
            self._sync_edge_to_graph(asset, dst_asset, event, graph_engine)

        return asset

    def _sync_node_to_graph(self, asset: DiscoveredAssetRecord, graph_engine: Any) -> None:
        """Pushes asset node into the GraphEngine (NetworkX + Neo4j Aura)."""
        node_type_map = {
            DeviceType.ENDPOINT_WINDOWS: NodeType.ENDPOINT,
            DeviceType.ENDPOINT_LINUX: NodeType.ENDPOINT,
            DeviceType.SWITCH: NodeType.ROUTER,
            DeviceType.ROUTER: NodeType.ROUTER,
            DeviceType.FIREWALL: NodeType.FIREWALL,
            DeviceType.SERVER: NodeType.SERVER,
            DeviceType.DATABASE: NodeType.DATABASE,
            DeviceType.SOFTWARE_SIEM: NodeType.SERVER,
            DeviceType.SOFTWARE_EDR: NodeType.SERVER,
            DeviceType.SOFTWARE_CSV: NodeType.SERVER,
        }

        nt = node_type_map.get(asset.device_type, NodeType.ENDPOINT)
        gn = GraphNode(
            id=asset.asset_id,
            name=asset.name,
            type=nt,
            criticality=asset.criticality,
            is_compromised=False,
            is_crown_jewel=(asset.criticality == 5),
            provenance=DataProvenance.LIVE_TELEMETRY,
            properties={
                "ip": asset.current_ip,
                "mac": asset.mac or "",
                "hostname": asset.hostname or "",
                "os": asset.os,
                "owner": asset.owner,
                "is_online": asset.is_online,
                "first_seen": asset.first_seen,
                "last_seen": asset.last_seen,
                "device_type": asset.device_type.value,
            }
        )
        graph_engine.add_node(gn, persist_to_neo4j=True)

    def _sync_edge_to_graph(
        self,
        src: DiscoveredAssetRecord,
        dst: DiscoveredAssetRecord,
        event: TelemetryEvent,
        graph_engine: Any
    ) -> None:
        """Pushes observed communication edge into GraphEngine."""
        port = event.target_port or 0
        proto = event.protocol or "TCP"
        edge_id = f"edge-{src.asset_id}-{dst.asset_id}-{port}"

        edge = GraphEdge(
            id=edge_id,
            source=src.asset_id,
            target=dst.asset_id,
            type=RelationshipType.COMMUNICATES_WITH,
            evidence_status=EvidenceStatus.CONFIRMED,
            confidence=event.confidence,
            weight=1.0,
            is_active=True,
            provenance=DataProvenance.LIVE_TELEMETRY,
            properties={
                "target_port": port,
                "protocol": proto,
                "event_type": event.event_type.value,
                "last_seen": event.timestamp,
                "bytes": event.bytes_transferred,
            }
        )
        graph_engine.add_edge(edge, persist_to_neo4j=True)

    def list_discovered_assets(self) -> List[Dict[str, Any]]:
        """Returns structured inventory of all discovered assets."""
        out = []
        for a in self._assets_by_id.values():
            out.append({
                "asset_id": a.asset_id,
                "name": a.name,
                "device_type": a.device_type.value,
                "ip": a.current_ip,
                "ip_history": a.ip_history,
                "mac": a.mac,
                "hostname": a.hostname,
                "hardware_uuid": a.hardware_uuid,
                "criticality": a.criticality,
                "owner": a.owner,
                "os": a.os,
                "is_online": a.is_online,
                "first_seen": a.first_seen,
                "last_seen": a.last_seen,
                "confidence": a.confidence,
            })
        return out


asset_discovery_engine = AssetDiscoveryEngine()
