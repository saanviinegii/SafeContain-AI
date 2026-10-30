"""Integration tests for SafeContain AI Primary REST API Endpoints."""

import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_health_and_security_headers():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    
    # Assert security headers are injected
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert "X-Correlation-ID" in response.headers


def test_scenario_load_and_topology():
    res_load = client.post("/api/v1/scenario/load-synthetic?scenario_name=TestGateway")
    assert res_load.status_code == 200
    assert res_load.json()["provenance"] == "SYNTHETIC"

    res_topo = client.get("/api/v1/graph/topology")
    assert res_topo.status_code == 200
    topo = res_topo.json()
    assert len(topo["nodes"]) >= 5
    assert len(topo["edges"]) >= 5


def test_attack_paths_and_decomposed_risk():
    res_paths = client.get("/api/v1/graph/attack-paths")
    assert res_paths.status_code == 200
    paths = res_paths.json()
    assert len(paths) >= 2

    res_risk = client.get("/api/v1/risk/decompose")
    assert res_risk.status_code == 200
    risk = res_risk.json()
    assert risk["inherent_risk"] > 0
    assert risk["observed_risk"] > 0
    assert len(risk["contributing_factors"]) == 3


def test_planning_optimization_and_simulation():
    # Run optimization
    res_opt = client.post("/api/v1/planning/optimize", json={"budget_limit": 5000.0, "strategy": "CONSTRAINT_CPSAT"})
    assert res_opt.status_code == 200
    opt_data = res_opt.json()
    assert "strategies" in opt_data
    assert "benchmarks" in opt_data

    # Run simulation
    res_sim = client.post("/api/v1/simulation/run")
    assert res_sim.status_code == 200
    sim_data = res_sim.json()
    assert "simulation_id" in sim_data
    assert "residual_attack_path_count" in sim_data
    assert len(sim_data["audit_hash"]) == 64


def test_governance_and_audit_verification():
    # Ensure a plan has been simulated so its status is SIMULATED
    client.post("/api/v1/simulation/run")

    # Transition plan to PENDING_APPROVAL
    res_trans = client.post(
        "/api/v1/governance/transition",
        json={
            "target_status": "PENDING_APPROVAL",
            "actor_id": "soc-analyst-1",
            "actor_role": "SOC_ANALYST",
            "notes": "Ready for manager review.",
        }
    )
    assert res_trans.status_code == 200
    assert res_trans.json()["status"] == "PENDING_APPROVAL"

    # Transition to APPROVED by Security Manager
    res_appr = client.post(
        "/api/v1/governance/transition",
        json={
            "target_status": "APPROVED",
            "actor_id": "manager-rajesh",
            "actor_role": "SECURITY_MANAGER",
            "notes": "Containment plan approved.",
        }
    )
    assert res_appr.status_code == 200
    assert res_appr.json()["status"] == "APPROVED"

    # Verify audit integrity
    res_audit = client.get("/api/v1/audit/verify")
    assert res_audit.status_code == 200
    audit_report = res_audit.json()
    assert audit_report["is_valid"] is True
    assert audit_report["total_events_checked"] > 0


def test_report_exports():
    res_json = client.get("/api/v1/reports/export?format=json")
    assert res_json.status_code == 200
    assert res_json.json()["format"] == "json"

    res_csv = client.get("/api/v1/reports/export?format=csv")
    assert res_csv.status_code == 200
    assert "Action ID" in res_csv.json()["data"]

    res_text = client.get("/api/v1/reports/export?format=text")
    assert res_text.status_code == 200
    assert "SAFECONTAIN AI" in res_text.json()["data"]
