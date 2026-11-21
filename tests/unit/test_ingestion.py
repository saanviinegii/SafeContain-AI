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


def test_hackathon_demo_scenario_topology_and_provenance():
    """Validates the Hackathon Demonstration Scenario requirements from Master Prompt Section 9:
    1. Suspicious account user-contractor-guest is compromised.
    2. Two distinct routes to db-citizen-identity-vault:
       Route A (via jump-host-admin) and Route B (via api-gateway-internal -> app-service-auth).
    3. Workflow wf-payment-processing depends on api-gateway-internal.
    4. All nodes and edges have strict DataProvenance.SYNTHETIC.
    """
    result = SyntheticScenarioGenerator.generate_hackathon_demo_scenario()
    assert result.is_success is True
    assert result.provenance == DataProvenance.SYNTHETIC

    node_ids = {n.id for n in result.nodes}
    assert "user-contractor-guest" in node_ids
    assert "jump-host-admin" in node_ids
    assert "api-gateway-internal" in node_ids
    assert "app-service-auth" in node_ids
    assert "db-citizen-identity-vault" in node_ids
    assert "wf-payment-processing" in node_ids

    # Check compromised status
    user_node = next(n for n in result.nodes if n.id == "user-contractor-guest")
    assert user_node.is_compromised is True

    # Check crown jewel
    db_node = next(n for n in result.nodes if n.id == "db-citizen-identity-vault")
    assert db_node.is_crown_jewel is True

    # All nodes and edges are strictly labeled SYNTHETIC
    for node in result.nodes:
        assert node.provenance == DataProvenance.SYNTHETIC
    for edge in result.edges:
        assert edge.provenance == DataProvenance.SYNTHETIC

    # Test loading via API router endpoint
    from backend.app.api.v1.router import load_hackathon_demo_scenario, platform_ctx
    resp = load_hackathon_demo_scenario()
    assert resp["nodes_count"] == len(result.nodes)
    assert resp["edges_count"] == len(result.edges)

    # Verify discovered attack paths has 2 distinct routes from user-contractor-guest to crown jewel
    paths = platform_ctx.engine.find_attack_paths()
    assert len(paths) >= 2
    path_nodes = [tuple(p.node_sequence) for p in paths]
    has_route_a = any("jump-host-admin" in seq and "db-citizen-identity-vault" in seq for seq in path_nodes)
    has_route_b = any("api-gateway-internal" in seq and "app-service-auth" in seq and "db-citizen-identity-vault" in seq for seq in path_nodes)
    assert has_route_a, "Route A via jump-host-admin must be discovered"
    assert has_route_b, "Route B via api-gateway-internal must be discovered"


def test_iam_connector_and_ingestion_api_router():
    """Verify IAM connector and API ingestion endpoints."""
    connector = IAMConnector(name="ActiveDirectory_IAM", provenance=DataProvenance.LIVE_TELEMETRY)
    payload = [
        {
            "username": "rajesh_verma",
            "is_privileged": True,
            "department": "Infrastructure",
            "accessible_resources": ["srv-ad-dc01", "db-citizen-identity-prod"],
        }
    ]
    result = connector.ingest(payload)
    assert result.is_success is True
    assert result.nodes_created == 1
    assert result.edges_created == 2

    # Test API router ingestion functions directly
    from backend.app.api.v1.router import (
        get_registered_connectors,
        ingest_edr_telemetry,
        ingest_siem_telemetry,
    )
    connectors = get_registered_connectors()
    assert len(connectors) >= 3

    siem_res = ingest_siem_telemetry([
        {
            "alert_id": "API-ALERT-001",
            "source_ip": "10.0.5.10",
            "dest_ip": "10.0.5.20",
            "threat_name": "API Lateral Probe",
            "severity_score": 0.9,
        }
    ])
    assert siem_res.is_success is True
    assert siem_res.nodes_created >= 1
