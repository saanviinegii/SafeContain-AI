"""End-to-End SafeContain AI Workflow Integration Test.

Validates the complete 8-phase operational lifecycle:
1. Telemetry Ingestion & Calibrated Demo Scenario Loading
2. Infrastructure Graph Construction & Provenance
3. Directed Attack Path & Choke Point Discovery
4. Multi-Objective Response Planning & CP-SAT Optimization
5. Forensically Isolated Snapshot Simulation & Residual Path Recheck
6. Multi-Tier Role-Based Human Governance Workflow (Pending -> Approved)
7. Cryptographic Audit Hash-Chain Verification & Blockchain Anchoring
8. Comprehensive Incident Dossier Export & Reporting
"""

import pytest
from backend.app.api.v1.router import (
    GovernanceTransitionRequest,
    OptimizeRequest,
    SimulationRequest,
    export_incident_report,
    get_attack_paths,
    get_blockchain_ledger_status,
    get_candidate_actions,
    get_graph_topology,
    health_check,
    load_hackathon_demo_scenario,
    optimize_containment,
    platform_ctx,
    run_isolated_simulation,
    transition_plan_status,
    verify_audit_integrity,
)
from backend.app.models.domain import ApprovalStatus, OptimizationStrategy, UserRole


def test_complete_e2e_hackathon_workflow():
    """Executes the full end-to-end SafeContain AI cyber defense workflow."""

    # 1. Health Probe
    h = health_check()
    assert h["status"] in ("HEALTHY", "DEGRADED")
    assert "graph_backend" in h
    assert "neo4j_connected" in h

    # 2. Ingestion & Scenario Loading
    demo = load_hackathon_demo_scenario()
    assert demo["scenario_name"] == "Hackathon Demonstration Scenario"
    assert demo["nodes_count"] >= 6
    assert demo["edges_count"] >= 8
    assert demo["provenance"] == "SYNTHETIC"

    # 3. Graph Construction & Topology
    topo = get_graph_topology()
    assert len(topo["nodes"]) == demo["nodes_count"]
    assert len(topo["edges"]) == demo["edges_count"]

    # 4. Attack Path Discovery
    paths = get_attack_paths()
    assert len(paths) >= 2, "Must discover both Route A and Route B"
    path_nodes = [tuple(p.node_sequence) for p in paths]
    has_route_a = any("jump-host-admin" in seq and "db-citizen-identity-vault" in seq for seq in path_nodes)
    has_route_b = any("api-gateway-internal" in seq and "app-service-auth" in seq and "db-citizen-identity-vault" in seq for seq in path_nodes)
    assert has_route_a, "Route A via jump-host-admin must be discovered"
    assert has_route_b, "Route B via api-gateway-internal must be discovered"

    # 5. Response Action Catalog & Multi-Objective Planning
    candidates = get_candidate_actions()
    assert len(candidates) >= 2
    candidate_ids = {c.id for c in candidates}
    assert "act-revoke-user-contractor-guest" in candidate_ids
    assert "act-firewall-api-gateway-internal" in candidate_ids

    opt = optimize_containment(OptimizeRequest(budget_limit=10000.0, strategy=OptimizationStrategy.CONSTRAINT_CPSAT))
    assert "strategies" in opt
    assert "CONSTRAINT_CPSAT" in opt["strategies"]
    assert "GREEDY_RISK_COST" in opt["strategies"]
    assert "BASELINE_SEVERITY" in opt["strategies"]

    # 6. Isolated Response Simulation: Disruptive vs Targeted
    # 6a. Disruptive Action on api-gateway-internal
    sim_disruptive = run_isolated_simulation(SimulationRequest(
        action_ids=["act-firewall-api-gateway-internal"],
        strategy=OptimizationStrategy.BASELINE_SEVERITY
    ))
    assert sim_disruptive.residual_attack_path_count > 0, "Route A must remain open when only api gateway is firewalled"
    assert len(sim_disruptive.disrupted_workflows) > 0, "Disruptive action must disrupt payment clearing workflow"
    assert any("payment" in w.workflow_name.lower() for w in sim_disruptive.disrupted_workflows)
    assert not sim_disruptive.is_fully_contained

    # 6b. Targeted Action on user-contractor-guest
    sim_targeted = run_isolated_simulation(SimulationRequest(
        action_ids=["act-revoke-user-contractor-guest"],
        strategy=OptimizationStrategy.CONSTRAINT_CPSAT
    ))
    assert sim_targeted.residual_attack_path_count == 0, "Targeted revocation must cut off all attack routes"
    assert len(sim_targeted.disrupted_workflows) == 0, "Targeted revocation must cause zero workflow disruptions"
    assert sim_targeted.is_fully_contained is True
    assert sim_targeted.audit_hash is not None

    # 7. Multi-Tier Role-Based Human Governance Workflow
    # Step 7a: Transition to PENDING_APPROVAL
    g_pending = transition_plan_status(GovernanceTransitionRequest(
        target_status=ApprovalStatus.PENDING_APPROVAL,
        actor_role=UserRole.SECURITY_MANAGER,
        notes="Pre-demonstration authorization review"
    ))
    assert g_pending["status"] == ApprovalStatus.PENDING_APPROVAL.value

    # Step 7b: Transition to APPROVED
    g_approved = transition_plan_status(GovernanceTransitionRequest(
        target_status=ApprovalStatus.APPROVED,
        actor_role=UserRole.SECURITY_MANAGER,
        notes="Authorized containment plan for automated execution"
    ))
    assert g_approved["status"] == ApprovalStatus.APPROVED.value

    # 8. Cryptographic Audit Integrity & Blockchain Anchor
    integrity = verify_audit_integrity()
    assert integrity.is_valid is True
    assert integrity.total_events_checked > 0
    assert integrity.tampered_event_id is None

    bc = get_blockchain_ledger_status()
    assert "network_id" in bc
    assert "contract_address" in bc
    assert bc["mode"] in ("LOCAL_PERMISSIONED_ANCHOR", "LIVE_TESTNET")

    # 9. Reporting Export
    report = export_incident_report(format="json")
    assert "format" in report
    assert "data" in report
    assert report["data"]["scenario"] == "Hackathon Demonstration Scenario"
