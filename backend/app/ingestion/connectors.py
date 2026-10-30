"""Concrete Security Telemetry Connectors & Synthetic Scenario Generator.

Implements resilient ingestion for SIEM, EDR, IAM, Cloud Infrastructure,
and calibrated synthetic security scenarios with complete provenance tracking.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from backend.app.ingestion.contracts import BaseConnector, IngestionError, IngestionResult
from backend.app.models.domain import (
    DataProvenance,
    EvidenceStatus,
    GraphEdge,
    GraphNode,
    NodeType,
    RelationshipType,
)


class SIEMConnector(BaseConnector):
    """Ingests security incident alerts and log telemetry from SIEM platforms."""

    def ingest(self, raw_payload: List[Dict[str, Any]]) -> IngestionResult:
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        errors: List[IngestionError] = []
        duplicates = 0

        for idx, record in enumerate(raw_payload):
            # Check mandatory fields
            alert_id = record.get("alert_id") or record.get("event_id")
            if not alert_id:
                errors.append(IngestionError(
                    record_index=idx,
                    field="alert_id",
                    error_type="MISSING_PRIMARY_KEY",
                    message="SIEM record lacks required 'alert_id' or 'event_id'",
                    raw_snippet=record
                ))
                continue

            # Deduplication via SHA-256 fingerprint
            record_str = json.dumps(record, sort_keys=True, default=str)
            record_hash = hashlib.sha256(record_str.encode("utf-8")).hexdigest()
            if record_hash in self._seen_event_hashes:
                duplicates += 1
                continue
            self._seen_event_hashes.add(record_hash)

            # Extract source and destination entities
            src_ip = record.get("source_ip") or record.get("src_host")
            dst_ip = record.get("dest_ip") or record.get("dest_host")
            threat_name = record.get("threat_name") or record.get("title", "Suspicious Activity")
            severity = float(record.get("severity_score", 0.7))

            # Create Incident/Threat Node
            threat_node_id = f"threat-{alert_id}"
            nodes.append(GraphNode(
                id=threat_node_id,
                name=threat_name,
                type=NodeType.THREAT,
                criticality=min(max(severity, 0.0), 1.0),
                is_compromised=True,
                properties={
                    "severity": severity,
                    "mitre_technique": record.get("mitre_id", "T1078"),
                    "signature": record.get("signature", "Unknown"),
                },
                provenance=self.provenance
            ))

            # If src_ip is present, create or link source host
            if src_ip:
                src_node_id = f"host-{src_ip}"
                nodes.append(GraphNode(
                    id=src_node_id,
                    name=f"Host ({src_ip})",
                    type=NodeType.ENDPOINT,
                    criticality=0.5,
                    is_compromised=True,
                    properties={"ip_address": src_ip},
                    provenance=self.provenance
                ))
                edges.append(GraphEdge(
                    id=f"edge-obs-{alert_id}-src",
                    source=src_node_id,
                    target=threat_node_id,
                    type=RelationshipType.OBSERVED_IN,
                    evidence_status=EvidenceStatus.CONFIRMED,
                    confidence=0.95,
                    provenance=self.provenance
                ))

            # If destination is present, link lateral movement or targeting
            if dst_ip and src_ip:
                dst_node_id = f"host-{dst_ip}"
                nodes.append(GraphNode(
                    id=dst_node_id,
                    name=f"Host ({dst_ip})",
                    type=NodeType.SERVER,
                    criticality=0.8,
                    is_compromised=False,
                    properties={"ip_address": dst_ip},
                    provenance=self.provenance
                ))
                edges.append(GraphEdge(
                    id=f"edge-conn-{src_ip}-{dst_ip}",
                    source=f"host-{src_ip}",
                    target=dst_node_id,
                    type=RelationshipType.CONNECTED_TO,
                    evidence_status=EvidenceStatus.SUSPECTED if severity < 0.8 else EvidenceStatus.CONFIRMED,
                    confidence=severity,
                    provenance=self.provenance
                ))

        return IngestionResult(
            source_name=self.name,
            provenance=self.provenance,
            total_received=len(raw_payload),
            nodes_created=len(nodes),
            edges_created=len(edges),
            duplicates_skipped=duplicates,
            errors_encountered=len(errors),
            is_success=len(errors) == 0,
            nodes=nodes,
            edges=edges,
            errors=errors
        )


class EDRConnector(BaseConnector):
    """Ingests Endpoint Detection and Response telemetry."""

    def ingest(self, raw_payload: List[Dict[str, Any]]) -> IngestionResult:
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        errors: List[IngestionError] = []
        duplicates = 0

        for idx, record in enumerate(raw_payload):
            agent_id = record.get("agent_id") or record.get("device_id")
            if not agent_id:
                errors.append(IngestionError(
                    record_index=idx,
                    field="agent_id",
                    error_type="MISSING_AGENT_ID",
                    message="EDR record lacks required agent or device identifier",
                    raw_snippet=record
                ))
                continue

            record_hash = hashlib.sha256(json.dumps(record, sort_keys=True, default=str).encode()).hexdigest()
            if record_hash in self._seen_event_hashes:
                duplicates += 1
                continue
            self._seen_event_hashes.add(record_hash)

            hostname = record.get("hostname", f"endpoint-{agent_id}")
            is_isolated = record.get("network_containment_status") == "ISOLATED"
            has_detections = bool(record.get("active_detections", False))
            os_type = record.get("os", "Linux")

            host_node = GraphNode(
                id=f"host-{agent_id}",
                name=hostname,
                type=NodeType.ENDPOINT if "workstation" in hostname.lower() else NodeType.SERVER,
                criticality=0.6,
                is_compromised=has_detections,
                properties={
                    "agent_id": agent_id,
                    "os": os_type,
                    "is_isolated": is_isolated,
                    "agent_version": record.get("agent_version", "1.0.0"),
                },
                provenance=self.provenance
            )
            nodes.append(host_node)

            # Ingest associated user if reported by EDR
            logged_in_user = record.get("logged_in_user")
            if logged_in_user:
                user_node_id = f"user-{logged_in_user}"
                nodes.append(GraphNode(
                    id=user_node_id,
                    name=logged_in_user,
                    type=NodeType.USER,
                    criticality=0.4,
                    properties={"username": logged_in_user},
                    provenance=self.provenance
                ))
                edges.append(GraphEdge(
                    id=f"edge-auth-{user_node_id}-{host_node.id}",
                    source=user_node_id,
                    target=host_node.id,
                    type=RelationshipType.AUTHENTICATES_TO,
                    evidence_status=EvidenceStatus.CONFIRMED,
                    confidence=0.98,
                    provenance=self.provenance
                ))

        return IngestionResult(
            source_name=self.name,
            provenance=self.provenance,
            total_received=len(raw_payload),
            nodes_created=len(nodes),
            edges_created=len(edges),
            duplicates_skipped=duplicates,
            errors_encountered=len(errors),
            is_success=len(errors) == 0,
            nodes=nodes,
            edges=edges,
            errors=errors
        )


class IAMConnector(BaseConnector):
    """Ingests Identity, Role, and Privilege Access telemetry."""

    def ingest(self, raw_payload: List[Dict[str, Any]]) -> IngestionResult:
        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []
        errors: List[IngestionError] = []
        duplicates = 0

        for idx, record in enumerate(raw_payload):
            username = record.get("username") or record.get("upn")
            if not username:
                errors.append(IngestionError(
                    record_index=idx,
                    field="username",
                    error_type="MISSING_USER_ID",
                    message="IAM record lacks username/UPN",
                    raw_snippet=record
                ))
                continue

            record_hash = hashlib.sha256(json.dumps(record, sort_keys=True, default=str).encode()).hexdigest()
            if record_hash in self._seen_event_hashes:
                duplicates += 1
                continue
            self._seen_event_hashes.add(record_hash)

            is_privileged = bool(record.get("is_domain_admin", False) or record.get("is_privileged", False))
            user_node_id = f"user-{username}"

            nodes.append(GraphNode(
                id=user_node_id,
                name=username,
                type=NodeType.PRIVILEGED_IDENTITY if is_privileged else NodeType.USER,
                criticality=0.9 if is_privileged else 0.4,
                properties={
                    "department": record.get("department", "IT"),
                    "mfa_enabled": record.get("mfa_enabled", True),
                    "account_enabled": record.get("enabled", True),
                },
                provenance=self.provenance
            ))

            # Role or accessible resources
            for target_res in record.get("accessible_resources", []):
                target_id = f"res-{target_res}"
                edges.append(GraphEdge(
                    id=f"edge-access-{user_node_id}-{target_id}",
                    source=user_node_id,
                    target=target_id,
                    type=RelationshipType.HAS_ACCESS_TO,
                    evidence_status=EvidenceStatus.CONFIRMED,
                    confidence=1.0,
                    provenance=self.provenance
                ))

        return IngestionResult(
            source_name=self.name,
            provenance=self.provenance,
            total_received=len(raw_payload),
            nodes_created=len(nodes),
            edges_created=len(edges),
            duplicates_skipped=duplicates,
            errors_encountered=len(errors),
            is_success=len(errors) == 0,
            nodes=nodes,
            edges=edges,
            errors=errors
        )


class SyntheticScenarioGenerator:
    """Generates deterministic, mathematically sound enterprise security scenarios.
    
    All nodes and edges are strictly labeled with DataProvenance.SYNTHETIC to ensure
    absolute compliance with non-negotiable principle #18 (never misrepresent synthetic data).
    """

    @classmethod
    def generate_national_gateway_scenario(cls) -> IngestionResult:
        """Generates 'Operation Sovereign Gateway': An advanced multi-stage attack topology.
        
        Topology:
        - Compromised perimeter jump host via unpatched CVE
        - Lateral movement through Active Directory privilege escalation
        - Internal database cluster hosting Citizen Identity & Aadhaar/DigiLocker registry
        - Mission-critical citizen authentication workflow dependent on DB
        - Alternative routes (VPN, Backup Staging, Admin SSH) with mixed evidence certainty
        """
        nodes: List[GraphNode] = [
            # External & Perimeter
            GraphNode(
                id="ext-attacker-c2",
                name="External C2 Infrastructure",
                type=NodeType.THREAT,
                criticality=1.0,
                is_compromised=True,
                properties={"ip": "198.51.100.42", "threat_actor": "APT-Sovereign"},
                provenance=DataProvenance.SYNTHETIC,
            ),
            GraphNode(
                id="dmz-gateway-01",
                name="Public Citizen Portal DMZ Gateway",
                type=NodeType.SERVER,
                criticality=0.75,
                is_compromised=True,
                properties={"subnet": "10.0.1.0/24", "cve": "CVE-2026-4428"},
                provenance=DataProvenance.SYNTHETIC,
            ),
            # Internal Workstation & Identity
            GraphNode(
                id="wrk-operator-14",
                name="SOC Operator Workstation 14",
                type=NodeType.ENDPOINT,
                criticality=0.5,
                is_compromised=True,
                properties={"hostname": "DEL-W10-OP14", "user": "s_sharma"},
                provenance=DataProvenance.SYNTHETIC,
            ),
            GraphNode(
                id="usr-admin-rajesh",
                name="Rajesh Verma (Domain Admin)",
                type=NodeType.PRIVILEGED_IDENTITY,
                criticality=0.95,
                is_compromised=True,
                properties={"privilege": "Enterprise Admin", "mfa": False},
                provenance=DataProvenance.SYNTHETIC,
            ),
            GraphNode(
                id="srv-ad-dc01",
                name="Primary Domain Controller (DC01)",
                type=NodeType.SERVER,
                criticality=0.98,
                is_compromised=False,
                is_crown_jewel=True,
                properties={"role": "Identity Provider / Kerberos KDC"},
                provenance=DataProvenance.SYNTHETIC,
            ),
            # Staging & Lateral Hop
            GraphNode(
                id="srv-backup-stage",
                name="Disaster Recovery Backup Stage",
                type=NodeType.SERVER,
                criticality=0.8,
                is_compromised=False,
                properties={"protocol": "NFS/SMB", "sync_window": "Daily 02:00"},
                provenance=DataProvenance.SYNTHETIC,
            ),
            # Crown Jewel: Citizen Records Database
            GraphNode(
                id="db-citizen-identity-prod",
                name="National Citizen Registry Database",
                type=NodeType.DATABASE,
                criticality=1.0,
                is_compromised=False,
                is_crown_jewel=True,
                properties={"records_count": 85000000, "encryption": "AES-256", "data_tier": "Confidential"},
                provenance=DataProvenance.SYNTHETIC,
            ),
            # Mission Critical Workflow Node
            GraphNode(
                id="wf-citizen-auth-service",
                name="National Citizen Identity Verification Portal",
                type=NodeType.BUSINESS_WORKFLOW,
                criticality=1.0,
                properties={
                    "criticality_tier": "TIER_1_MISSION_CRITICAL",
                    "citizen_facing": True,
                    "hourly_downtime_cost": 250000.0,
                    "max_allowable_downtime_hours": 0.0,
                },
                provenance=DataProvenance.SYNTHETIC,
            ),
        ]

        edges: List[GraphEdge] = [
            # Primary Attack Vector
            GraphEdge(
                id="edge-c2-to-dmz",
                source="ext-attacker-c2",
                target="dmz-gateway-01",
                type=RelationshipType.EXPOSED_TO,
                evidence_status=EvidenceStatus.CONFIRMED,
                confidence=1.0,
                provenance=DataProvenance.SYNTHETIC,
            ),
            GraphEdge(
                id="edge-dmz-to-wrk",
                source="dmz-gateway-01",
                target="wrk-operator-14",
                type=RelationshipType.CONNECTED_TO,
                evidence_status=EvidenceStatus.CONFIRMED,
                confidence=0.92,
                provenance=DataProvenance.SYNTHETIC,
            ),
            GraphEdge(
                id="edge-wrk-to-user",
                source="wrk-operator-14",
                target="usr-admin-rajesh",
                type=RelationshipType.AUTHENTICATES_TO,
                evidence_status=EvidenceStatus.CONFIRMED,
                confidence=0.95,
                provenance=DataProvenance.SYNTHETIC,
            ),
            GraphEdge(
                id="edge-user-to-dc",
                source="usr-admin-rajesh",
                target="srv-ad-dc01",
                type=RelationshipType.HAS_ACCESS_TO,
                evidence_status=EvidenceStatus.CONFIRMED,
                confidence=1.0,
                provenance=DataProvenance.SYNTHETIC,
            ),
            GraphEdge(
                id="edge-dc-to-db",
                source="srv-ad-dc01",
                target="db-citizen-identity-prod",
                type=RelationshipType.HAS_ACCESS_TO,
                evidence_status=EvidenceStatus.CONFIRMED,
                confidence=0.98,
                provenance=DataProvenance.SYNTHETIC,
            ),
            # Secondary / Alternative Attack Path (Uncertain & Suspected)
            GraphEdge(
                id="edge-dmz-to-backup",
                source="dmz-gateway-01",
                target="srv-backup-stage",
                type=RelationshipType.CONNECTED_TO,
                evidence_status=EvidenceStatus.SUSPECTED,
                confidence=0.60,
                provenance=DataProvenance.SYNTHETIC,
            ),
            GraphEdge(
                id="edge-backup-to-db",
                source="srv-backup-stage",
                target="db-citizen-identity-prod",
                type=RelationshipType.DEPENDS_ON,
                evidence_status=EvidenceStatus.SUSPECTED,
                confidence=0.55,
                provenance=DataProvenance.SYNTHETIC,
            ),
            # Business Continuity Mapping Edge
            GraphEdge(
                id="edge-db-supports-portal",
                source="db-citizen-identity-prod",
                target="wf-citizen-auth-service",
                type=RelationshipType.SUPPORTS_WORKFLOW,
                evidence_status=EvidenceStatus.CONFIRMED,
                confidence=1.0,
                provenance=DataProvenance.SYNTHETIC,
            ),
        ]

        return IngestionResult(
            source_name="SyntheticScenarioGenerator.OperationSovereignGateway",
            provenance=DataProvenance.SYNTHETIC,
            total_received=len(nodes) + len(edges),
            nodes_created=len(nodes),
            edges_created=len(edges),
            duplicates_skipped=0,
            errors_encountered=0,
            is_success=True,
            nodes=nodes,
            edges=edges,
            errors=[],
        )
