"""Integration tests for SafeContain AI Primary REST API Endpoints.

Tests all route handlers directly to ensure 100% coverage of Pydantic schemas,
graph algorithms, CP-SAT optimization, simulation sandboxing, governance transitions,
and cryptographic audit chaining.
"""

import pytest
from starlette.responses import Response

from backend.app.api.v1.router import (
    GovernanceTransitionRequest,
    OptimizeRequest,
    SimulationRequest,
    export_incident_report,
    get_attack_paths,
    get_blockchain_anchored_records,
    get_blockchain_ledger_status,
    get_candidate_actions,
    get_decomposed_risk,
    get_graph_topology,
    get_registered_connectors,
    health_check,
    ingest_siem_telemetry,
    load_synthetic_scenario,
    optimize_containment,
    platform_ctx,
    run_isolated_simulation,
    transition_plan_status,
    verify_audit_integrity,
)
from backend.app.models.domain import ApprovalStatus, OptimizationStrategy, UserRole
from backend.app.security.middleware import SecurityHeadersMiddleware


def test_health_and_security_headers():
    """Verify system health endpoint and security header injection."""
    data = health_check()
    assert data["status"] == "HEALTHY"
    assert "version" in data
    assert "graph_backend" in data

    # Assert security headers applied to HTTP responses
    resp = SecurityHeadersMiddleware.apply_security_headers(
        response=Response(content="{}"),
        path="/api/v1/health",
        correlation_id="test-corr-id-999",
    )
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-Correlation-ID"] == "test-corr-id-999"


def test_scenario_load_and_topology():
    """Verify synthetic scenario generation, loading, and topology export."""
    res_load = load_synthetic_scenario(scenario_name="TestGateway")
    assert res_load["provenance"] == "SYNTHETIC"
    assert res_load["nodes_count"] >= 5
    assert res_load["edges_count"] >= 5

    topo = get_graph_topology()
    assert len(topo["nodes"]) >= 5
    assert len(topo["edges"]) >= 5


def test_attack_paths_and_decomposed_risk():
    """Verify attack path enumeration and transparent risk factor decomposition."""
    paths = get_attack_paths()
    assert len(paths) >= 2
    for p in paths:
        assert p.adjusted_path_risk > 0
        assert p.inherent_path_risk > 0
        assert len(p.node_sequence) >= 2

    risk = get_decomposed_risk()
    assert risk.inherent_risk > 0
    assert risk.observed_risk > 0
    assert len(risk.contributing_factors) == 3


def test_planning_optimization_and_simulation():
    """Verify optimization strategy comparison and isolated snapshot simulation."""
    # Run optimization
    opt_data = optimize_containment(
        OptimizeRequest(budget_limit=5000.0, strategy=OptimizationStrategy.CONSTRAINT_CPSAT)
    )
    assert "strategies" in opt_data
    assert "benchmarks" in opt_data

    # Run simulation
    sim_data = run_isolated_simulation()
    assert sim_data.simulation_id.startswith("sim-")
    assert sim_data.residual_attack_path_count >= 0
    assert len(sim_data.audit_hash) == 64


def test_whatif_simulation_with_custom_actions_and_strategies():
    """Verify what-if custom simulation scenarios without altering base graph."""
    # 1. Fetch candidates
    candidates = get_candidate_actions()
    assert len(candidates) > 0

    # 2. Simulate empty action list -> threat remains uncontained
    empty_sim = run_isolated_simulation(SimulationRequest(action_ids=[]))
    assert empty_sim.residual_attack_path_count == empty_sim.initial_attack_path_count
    assert empty_sim.is_fully_contained is False
    assert empty_sim.residual_risk_score == empty_sim.initial_risk_score

    # 3. Simulate with all candidate actions -> risk reduction achieved
    all_ids = [c.id for c in candidates]
    all_sim = run_isolated_simulation(SimulationRequest(action_ids=all_ids))
    assert all_sim.residual_risk_score < empty_sim.residual_risk_score
    assert all_sim.residual_attack_path_count < empty_sim.residual_attack_path_count
    assert len(all_sim.applied_action_ids) == len(all_ids)

    # 4. Simulate with strategy selection
    strat_sim = run_isolated_simulation(
        SimulationRequest(strategy=OptimizationStrategy.GREEDY_RISK_COST, budget_limit=5000.0)
    )
    assert strat_sim.residual_risk_score >= 0.0


def test_governance_and_audit_verification():
    """Verify multi-tier governance state machine and cryptographic hash-chain verification."""
    # Ensure a plan has been simulated so its status is SIMULATED
    run_isolated_simulation()

    # Transition plan to PENDING_APPROVAL
    res_trans = transition_plan_status(
        GovernanceTransitionRequest(
            target_status=ApprovalStatus.PENDING_APPROVAL,
            actor_id="soc-analyst-1",
            actor_role=UserRole.SOC_ANALYST,
            notes="Ready for manager review.",
        )
    )
    assert res_trans["status"] == ApprovalStatus.PENDING_APPROVAL.value

    # Transition to APPROVED by Security Manager
    res_appr = transition_plan_status(
        GovernanceTransitionRequest(
            target_status=ApprovalStatus.APPROVED,
            actor_id="manager-rajesh",
            actor_role=UserRole.SECURITY_MANAGER,
            notes="Containment plan approved.",
        )
    )
    assert res_appr["status"] == ApprovalStatus.APPROVED.value

    # Verify audit integrity
    audit_report = verify_audit_integrity()
    assert audit_report.is_valid is True
    assert audit_report.total_events_checked > 0

    # Verify blockchain ledger status
    bc_status = get_blockchain_ledger_status()
    assert bc_status["status"] == "ONLINE"
    assert "total_anchored_records" in bc_status
    assert "current_block_height" in bc_status

    bc_records = get_blockchain_anchored_records()
    assert isinstance(bc_records, list)


def test_telemetry_ingestion_connectors():
    """Verify SIEM, EDR, IAM connector status and sample telemetry ingestion."""
    connectors = get_registered_connectors()
    assert len(connectors) >= 3
    conn_names = [c["name"] for c in connectors]
    assert "Splunk_SIEM" in conn_names
    assert "CrowdStrike_Falcon" in conn_names
    assert "ActiveDirectory_IAM" in conn_names

    sample_siem_alert = [
        {
            "alert_id": "siem-ext-test-101",
            "title": "Suspicious PowerShell Invocations",
            "severity": 0.85,
            "source_ip": "10.0.4.15",
            "target_ip": "10.0.4.20",
            "signature": "MITRE-T1059.001",
        }
    ]
    res_ingest = ingest_siem_telemetry(sample_siem_alert)
    assert res_ingest.nodes_created >= 1
    assert res_ingest.total_received == 1


def test_report_exports():
    """Verify incident reporting exports across JSON, CSV, and plain text formats."""
    res_json = export_incident_report(format="json")
    assert res_json["format"] == "json"
    assert "scenario" in res_json["data"]

    res_csv = export_incident_report(format="csv")
    assert res_csv["format"] == "csv"
    assert "Action ID" in res_csv["data"]

    res_text = export_incident_report(format="text")
    assert res_text["format"] == "text"
    assert "SAFECONTAIN AI" in res_text["data"]
