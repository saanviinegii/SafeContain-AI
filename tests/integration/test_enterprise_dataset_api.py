"""Integration Test Suite for SafeContain AI Enterprise Dataset API Endpoints.

Tests all route handlers directly to ensure 100% coverage of dataset status,
validation reports, downloads, scenario switching, and graph analytics.
"""

import pytest
from backend.app.api.v1.router import (
    get_dataset_status,
    get_dataset_validation_report,
    list_dataset_threat_scenarios,
    import_enterprise_dataset,
    load_specific_threat_scenario,
    reset_dataset_environment,
    download_dataset_file,
    download_all_datasets_zip,
    get_dataset_assets,
    get_dataset_users,
    get_dataset_vulnerabilities,
    get_dataset_alerts,
    get_dataset_evidence,
    get_dataset_interventions,
    get_dataset_dependencies,
    get_dataset_business_impact,
    get_graph_topology,
    get_attack_paths,
    get_decomposed_risk,
    platform_ctx,
)


def test_dataset_status_endpoint():
    """Verifies get_dataset_status returns complete catalog metrics."""
    data = get_dataset_status()
    assert data["provenance"] == "SYNTHETIC"
    assert data["validation_status"] == "PASSED"
    assert data["files_count"] == 12
    assert data["file_record_counts"]["nodes.csv"] >= 100
    assert data["file_record_counts"]["relationships.csv"] >= 250


def test_dataset_validation_endpoint():
    """Verifies get_dataset_validation_report returns 0 errors."""
    data = get_dataset_validation_report()
    assert data["validation_status"] == "PASSED"
    assert data["integrity_checks"]["total_errors"] == 0
    assert data["summary_metrics"]["node_count"] >= 100


def test_dataset_scenarios_listing():
    """Verifies list_dataset_threat_scenarios lists all 10 threat scenarios."""
    scenarios = list_dataset_threat_scenarios()
    assert len(scenarios) >= 10
    ids = [s["scenario_id"] for s in scenarios]
    assert "SCEN-001" in ids
    assert "SCEN-002" in ids
    assert "SCEN-003" in ids


def test_dataset_import_and_scenario_load():
    """Verifies importing and loading a specific threat scenario."""
    data = load_specific_threat_scenario(scenario_id="SCEN-001")
    assert data["status"] == "SUCCESS"
    assert data["scenario_id"] == "SCEN-001"
    assert data["nodes_loaded"] >= 100
    assert data["edges_loaded"] >= 250

    # Verify topology reflects enterprise nodes
    topo = get_graph_topology()
    assert len(topo["nodes"]) >= 100
    assert len(topo["edges"]) >= 250

    # Verify attack paths discovered
    paths = get_attack_paths()
    assert len(paths) > 0

    # Verify decomposed risk reflects the enterprise scenario
    risk = get_decomposed_risk()
    assert risk.inherent_risk > 0.0
    assert risk.uncertainty_adjusted_risk > 0.0


def test_dataset_entity_access_endpoints():
    """Verifies the individual REST endpoints for assets, users, vulnerabilities, etc."""
    assert len(get_dataset_assets()) >= 30
    assert len(get_dataset_users()) >= 25
    assert len(get_dataset_vulnerabilities()) >= 40
    assert len(get_dataset_alerts()) >= 50
    assert len(get_dataset_evidence()) >= 60
    assert len(get_dataset_interventions()) >= 40
    assert len(get_dataset_dependencies()) >= 50
    assert len(get_dataset_business_impact()) >= 30


def test_dataset_file_downloads():
    """Verifies download_dataset_file and download_all_datasets_zip."""
    resp_file = download_dataset_file("nodes.csv")
    assert resp_file.path.endswith("nodes.csv")

    resp_zip = download_all_datasets_zip()
    assert resp_zip.media_type == "application/zip"
    assert len(resp_zip.body) > 1000


def test_dataset_reset_endpoint():
    """Verifies reset_dataset_environment clears and re-establishes clean baseline."""
    data = reset_dataset_environment()
    assert data["status"] == "SUCCESS"
    assert data["details"]["nodes_loaded"] >= 100
