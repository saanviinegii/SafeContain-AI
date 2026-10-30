"""Unit tests for the Security Telemetry Ingestion Framework."""

import pytest
from backend.app.ingestion.connectors import (
    SIEMConnector,
    EDRConnector,
    IAMConnector,
    SyntheticScenarioGenerator,
)
from backend.app.models.domain import DataProvenance, EvidenceStatus, NodeType


def test_siem_connector_validation_and_deduplication():
    connector = SIEMConnector(name="Splunk_SIEM", provenance=DataProvenance.LIVE_TELEMETRY)
    
    payload = [
        # Valid record 1
        {
            "alert_id": "ALERT-9901",
            "source_ip": "10.0.1.15",
            "dest_ip": "10.0.2.50",
            "threat_name": "Pass-the-Hash Detected",
            "severity_score": 0.88,
            "mitre_id": "T1550.002",
        },
        # Duplicate record 1
        {
            "alert_id": "ALERT-9901",
            "source_ip": "10.0.1.15",
            "dest_ip": "10.0.2.50",
            "threat_name": "Pass-the-Hash Detected",
            "severity_score": 0.88,
            "mitre_id": "T1550.002",
        },
        # Malformed record (missing alert_id)
        {
            "source_ip": "10.0.99.1",
            "threat_name": "Anonymous Port Scan",
        },
    ]

    result = connector.ingest(payload)
    assert result.total_received == 3
    assert result.duplicates_skipped == 1
    assert result.errors_encountered == 1
    assert result.errors[0].error_type == "MISSING_PRIMARY_KEY"
    assert result.nodes_created > 0
    assert result.edges_created > 0


def test_edr_connector_agent_status():
    connector = EDRConnector(name="CrowdStrike_Falcon", provenance=DataProvenance.LIVE_TELEMETRY)
    payload = [
        {
            "agent_id": "CS-AGT-4402",
            "hostname": "prod-billing-worker-01",
            "active_detections": True,
            "os": "Ubuntu 24.04",
            "logged_in_user": "svc_billing_batch",
        }
    ]
    result = connector.ingest(payload)
    assert result.is_success is True
    assert result.nodes_created == 2 # 1 Host + 1 User
    assert result.edges_created == 1 # 1 AUTHENTICATES_TO edge
    
    host_node = next(n for n in result.nodes if n.id == "host-CS-AGT-4402")
    assert host_node.is_compromised is True


def test_synthetic_scenario_generator_provenance():
    result = SyntheticScenarioGenerator.generate_national_gateway_scenario()
    assert result.is_success is True
    assert result.provenance == DataProvenance.SYNTHETIC
    
    # Assert every single node and edge has strict SYNTHETIC provenance
    for node in result.nodes:
        assert node.provenance == DataProvenance.SYNTHETIC
    for edge in result.edges:
        assert edge.provenance == DataProvenance.SYNTHETIC

    # Verify crown jewel exists
    crown_jewels = [n for n in result.nodes if n.is_crown_jewel]
    assert len(crown_jewels) >= 2
    assert any(n.id == "db-citizen-identity-prod" for n in crown_jewels)
