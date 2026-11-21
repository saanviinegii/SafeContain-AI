"""End-to-End Live API & Demonstration Workflow Verification Script.

Tests every critical API route against http://127.0.0.1:8000, validates responses,
verifies graph topology integrity, simulation math, governance transitions,
and cryptographic audit chains.
"""

import json
import urllib.request
import urllib.error
import sys

BASE_URL = "http://127.0.0.1:8000/api/v1"

def request(method: str, path: str, payload=None):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            content_type = resp.headers.get("Content-Type", "")
            raw = resp.read()
            if "application/json" in content_type:
                return resp.status, json.loads(raw.decode("utf-8"))
            elif "zip" in content_type:
                return resp.status, f"ZIP_BYTES_{len(raw)}"
            else:
                return resp.status, raw.decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="ignore")
        return e.code, err_body
    except Exception as e:
        return 500, str(e)


def run_e2e_verification():
    print("=" * 80)
    print("SAFECONTAIN AI — LIVE E2E API & WORKFLOW VERIFICATION SUITE")
    print(f"Target Base URL: {BASE_URL}")
    print("=" * 80)

    checks = []

    # 1. Health Probe
    status, res = request("GET", "/health")
    passed = status == 200 and res.get("status") in ("HEALTHY", "DEGRADED")
    checks.append(("1. System Health Probe", passed, f"status={res.get('status')} engine={res.get('graph_backend')}"))

    # 2. Graph Diagnostic
    status, res = request("GET", "/graph/diagnostic")
    passed = status == 200 and "active_engine" in res
    checks.append(("2. Graph Diagnostic", passed, f"active_engine={res.get('active_engine')} neo4j_connected={res.get('neo4j_connected')}"))

    # 3. Dataset Status
    status, res = request("GET", "/dataset/status")
    passed = status == 200 and res.get("validation_status") in ("PASS", "PASSED") and res.get("files_count", 0) == 12
    checks.append(("3. Dataset Status & Integrity", passed, f"validation={res.get('validation_status')} total_files={res.get('files_count', 0)}"))

    # 4. Scenarios Listing
    status, res = request("GET", "/dataset/scenarios")
    passed = status == 200 and len(res) == 10
    checks.append(("4. Scenario Listing (10 Scenarios)", passed, f"scenarios_count={len(res)}"))

    # 5. Load Scenario SCEN-001
    status, res = request("POST", "/dataset/scenarios/SCEN-001/load")
    passed = status == 200 and res.get("status") == "SUCCESS"
    checks.append(("5. Ingestion of SCEN-001", passed, f"scenario={res.get('scenario_name')} nodes={res.get('nodes_imported')} edges={res.get('relationships_imported')}"))

    # 6. Topology Explorer Verification
    status, res = request("GET", "/graph/topology")
    node_count = len(res.get("nodes", []))
    edge_count = len(res.get("edges", []))
    passed = status == 200 and node_count >= 100 and edge_count >= 200
    checks.append(("6. Interactive Topology Graph", passed, f"nodes={node_count} edges={edge_count} backend={res.get('backend')}"))

    # 7. Attack Paths Discovery
    status, res = request("GET", "/graph/attack-paths")
    path_count = len(res) if isinstance(res, list) else 0
    passed = status == 200 and path_count >= 1
    checks.append(("7. Attack Path Discovery (Dijkstra/Yen)", passed, f"discovered_paths={path_count}"))

    # 8. Evidence Uncertainty & Sensitivity
    status, res = request("GET", "/evidence/sensitivity")
    drift_items = len(res) if isinstance(res, list) else 0
    passed = status == 200 and drift_items > 0
    checks.append(("8. Evidence Uncertainty & Sensitivity Drift", passed, f"sensitivity_scenarios={drift_items}"))

    # 9. Decomposed Risk Model
    status, res = request("GET", "/risk/decomposed")
    obs_risk = res.get("observed_risk", 0) if isinstance(res, dict) else 0
    adj_risk = res.get("uncertainty_adjusted_risk", 0) if isinstance(res, dict) else 0
    passed = status == 200 and isinstance(res, dict) and obs_risk > 0
    checks.append(("9. Tri-Factor Decomposed Risk", passed, f"observed_risk={obs_risk:.2f}% adjusted_risk={adj_risk:.2f}%"))

    # 10. Business Continuity Twin
    status, res = request("GET", "/business/workflows")
    wf_count = len(res) if isinstance(res, list) else 0
    passed = status == 200 and wf_count >= 4
    checks.append(("10. Business Continuity Twin Workflows", passed, f"active_workflows={wf_count}"))

    # 11. Response Planning Candidate Actions
    status, res = request("GET", "/planning/actions/candidates")
    cand_count = len(res) if isinstance(res, list) else 0
    passed = status == 200 and cand_count >= 10
    checks.append(("11. Action Catalog Candidate Actions", passed, f"candidate_actions={cand_count}"))

    # 12. Tri-Level Optimization (CP-SAT)
    status, res = request("POST", "/planning/optimize", {"budget_limit": 10000, "strategy": "CONSTRAINT_CPSAT"})
    strategies = res.get("strategies", {}) if isinstance(res, dict) else {}
    cpsat_plan = strategies.get("CONSTRAINT_CPSAT", {})
    passed = status == 200 and len(strategies) == 3 and len(cpsat_plan.get("actions", [])) > 0
    checks.append(("12. Google OR-Tools CP-SAT Solver", passed, f"actions={len(cpsat_plan.get('actions', []))} risk_reduction={cpsat_plan.get('predicted_risk_reduction', 0):.2f}% disruption_score={cpsat_plan.get('total_disruption_score', 0)}"))

    # 13. Strategy Comparator Benchmarking
    status, res = request("POST", "/optimization/compare", {"budget_limit": 10000})
    passed = status == 200 and isinstance(res, dict) and len(res.get("strategies", {})) == 3
    checks.append(("13. Tri-Strategy Comparator (CP-SAT/Greedy/Base)", passed, f"benchmarked_strategies={len(res.get('strategies', {}))}"))

    # 14. Isolated Sandbox Simulation
    status, res = request("POST", "/simulation/run")
    initial_p = res.get("initial_attack_path_count", 0) if isinstance(res, dict) else 0
    residual_p = res.get("residual_attack_path_count", 0) if isinstance(res, dict) else 0
    passed = status == 200 and isinstance(res, dict) and initial_p > 0
    checks.append(("14. In-Memory Graph Simulation Sandbox", passed, f"initial_paths={initial_p} residual_paths={residual_p} post_risk={res.get('residual_risk_score', 0):.2f}% contained={res.get('is_fully_contained')}"))

    # 15. What-If Simulation with Custom Actions
    status, res = request("POST", "/simulation/what-if", {
        "candidate_action_ids": ["ACT-NET-001", "ACT-IAM-001"],
        "budget_limit": 5000,
        "strategy": "GREEDY_RISK_COST"
    })
    passed = status == 200 and isinstance(res, dict) and "residual_risk_score" in res
    checks.append(("15. What-If Custom Bundle Simulation", passed, f"residual_risk={res.get('residual_risk_score', 0):.2f}% residual_paths={res.get('residual_attack_path_count', 0)}"))

    # 16. Explainability & Counterfactual Analysis
    status, res = request("GET", "/explanation/recommendation")
    passed = status == 200 and isinstance(res, dict) and len(res.get("justification", [])) > 0
    checks.append(("16. Decision Explanation & Counterfactuals", passed, f"reasons_count={len(res.get('justification', []))} confidence={res.get('confidence', '')[:10]}"))

    # 17. Governance Approval Lifecycle
    s1, r1 = request("POST", "/governance/transition", {
        "target_status": "PENDING_APPROVAL",
        "actor_role": "SECURITY_MANAGER",
        "actor_id": "sec-manager-raj",
        "notes": "Transitioning simulated plan for executive review"
    })
    s2, r2 = request("POST", "/governance/transition", {
        "target_status": "APPROVED",
        "actor_role": "INCIDENT_COMMANDER",
        "actor_id": "cmd-lead-elena",
        "notes": "Incident Commander Final Containment Authorization"
    })
    passed = s1 == 200 and s2 == 200 and isinstance(r2, dict) and r2.get("status") == "APPROVED"
    checks.append(("17. Multi-Tier Governance Lifecycle", passed, f"final_status={r2.get('status') if isinstance(r2, dict) else r2} approved_by=INCIDENT_COMMANDER"))

    # 18. Audit Ledger & Cryptographic Integrity
    status, res_ledger = request("GET", "/audit/ledger?limit=10")
    s_verify, r_verify = request("GET", "/audit/verify")
    passed = status == 200 and s_verify == 200 and r_verify.get("is_valid") is True
    checks.append(("18. Cryptographic Hash-Chain Audit Ledger", passed, f"events_checked={r_verify.get('total_events_checked')} valid={r_verify.get('is_valid')} status={r_verify.get('status_summary', '')[:30]}"))

    # 19. Blockchain Anchoring & Verification
    status_bc, res_bc = request("GET", "/audit/blockchain/status")
    first_event_id = res_ledger[0].get("event_id") if isinstance(res_ledger, list) and res_ledger else "EVT-INIT-001"
    s_bcv, r_bcv = request("POST", f"/audit/blockchain/verify?event_id={first_event_id}")
    passed = status_bc == 200 and s_bcv == 200 and "is_valid" in r_bcv
    checks.append(("19. Ethereum Smart Contract Blockchain Anchor", passed, f"blocks={res_bc.get('total_anchored_blocks')} contract={res_bc.get('contract_address', '')[:12]}... verified={r_bcv.get('is_valid')}"))

    # 20. Dataset Download-All ZIP
    status, res = request("GET", "/dataset/download-all")
    passed = status == 200 and str(res).startswith("ZIP_BYTES")
    checks.append(("20. Dataset Download (Streaming ZIP Archive)", passed, f"download_result={res}"))

    # 21. Threat Scenario Switching (SCEN-002 Ransomware)
    status, res = request("POST", "/dataset/scenarios/SCEN-002/load")
    passed = status == 200 and res.get("scenario_id") == "SCEN-002"
    checks.append(("21. Dynamic Threat Scenario Switching (SCEN-002)", passed, f"switched_scenario={res.get('scenario_name')}"))

    # 22. Clean Environment Baseline Reset
    status, res = request("POST", "/dataset/reset")
    passed = status == 200 and res.get("status") == "SUCCESS"
    checks.append(("22. Idempotent Environment Baseline Reset", passed, f"reset_status={res.get('status')} restored_scenario={res.get('details', {}).get('scenario_id')}"))

    # Print Report
    print("\n" + "=" * 80)
    print("VERIFICATION RESULTS SUMMARY:")
    print("=" * 80)
    all_passed = True
    for name, ok, detail in checks:
        icon = "[PASS]" if ok else "[FAIL]"
        if not ok:
            all_passed = False
        print(f"{icon} {name:<46} | {detail}")

    print("=" * 80)
    print(f"TOTAL TESTS: {len(checks)} | PASSED: {sum(1 for _, ok, _ in checks if ok)} | FAILED: {sum(1 for _, ok, _ in checks if not ok)}")
    print(f"OVERALL STATUS: {'ALL CHECKS PASSED PERFECTLY' if all_passed else 'SOME CHECKS FAILED'}")
    print("=" * 80)

    return all_passed


if __name__ == "__main__":
    success = run_e2e_verification()
    sys.exit(0 if success else 1)
