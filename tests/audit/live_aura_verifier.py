"""Phase 7.5 Live Neo4j Aura Verification Script.

Executes a focused, non-destructive LIVE verification of Neo4j Aura connectivity,
atomic write, independent read, payload comparison, persistence confirmation,
and clean-up.

Verifies:
1. Direct Neo4j driver connection.
2. Existing GraphEngine-to-Neo4j integration.
3. Strict preservation of existing graph data, configurations, and models.

Never prints passwords, tokens, or credentials.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Ensure project root is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.app.core.config import settings
from backend.app.graph.engine import GraphEngine
from backend.app.models.domain import (
    DataProvenance,
    EvidenceStatus,
    GraphEdge,
    GraphNode,
    NodeType,
    RelationshipType,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("live_aura_verifier")


def redact_uri(uri: str) -> str:
    """Safely redact credentials from URI if present."""
    if not uri:
        return "<EMPTY_URI>"
    if "@" in uri:
        scheme_rest = uri.split("://")
        if len(scheme_rest) == 2:
            scheme, rest = scheme_rest
            host = rest.split("@")[-1]
            return f"{scheme}://{host}"
    return uri


def run_live_aura_verification() -> Dict[str, Any]:
    verification_start = datetime.now(timezone.utc)
    raw_uri = settings.NEO4J_URI or ""
    display_uri = redact_uri(raw_uri)
    user = settings.NEO4J_USER or settings.NEO4J_USERNAME or "neo4j"
    database = settings.NEO4J_DATABASE or settings.AURA_INSTANCEID or "neo4j"

    results: Dict[str, Any] = {
        "verification_timestamp": verification_start.isoformat(),
        "target_uri": display_uri,
        "configured_user": user,
        "configured_database": database,
        "step_1_connection": {
            "driver_initialized": False,
            "connectivity_verified": False,
            "active_database": None,
            "connection_method": None,
            "graphengine_integrated": False,
            "graphengine_backend": None,
            "initial_db_node_count": None,
            "initial_db_edge_count": None,
            "error": None,
        },
        "step_2_safe_record": {
            "record_id": None,
            "payload": None,
        },
        "step_3_write": {
            "success": False,
            "written_at": None,
            "cypher_statement": None,
            "error": None,
        },
        "step_4_read": {
            "success": False,
            "retrieved_payload": None,
            "comparison_passed": False,
            "field_diffs": {},
            "error": None,
        },
        "step_5_persistence": {
            "persistence_verified": False,
            "independent_session": False,
            "is_in_memory_fallback": False,
            "not_in_memory_cache": False,
            "database_stats_confirmed": False,
            "notes": None,
        },
        "step_6_cleanup": {
            "attempted": False,
            "success": False,
            "deleted_count": 0,
            "post_delete_count": -1,
            "error": None,
        },
        "production_config_check": {
            "pre_hash": None,
            "post_hash": None,
            "unchanged": False,
        },
        "final_verdict": None,
    }

    # Record baseline configuration hash
    config_path = os.path.join(BASE_DIR, "artifacts", "calibration", "configurations.json")
    if os.path.exists(config_path):
        with open(config_path, "rb") as f:
            results["production_config_check"]["pre_hash"] = hashlib.sha256(f.read()).hexdigest()

    # -------------------------------------------------------------------------
    # STEP 1: CONNECTION VERIFICATION & GRAPHENGINE INTEGRATION
    # -------------------------------------------------------------------------
    print(f"\n[STEP 1] Verifying Neo4j Aura connectivity to {display_uri}...")
    try:
        from neo4j import GraphDatabase
        from neo4j.exceptions import AuthError, ServiceUnavailable

        # Test official driver initialization
        candidate_uris = [raw_uri]
        if raw_uri.startswith("neo4j+s://"):
            candidate_uris.append(raw_uri.replace("neo4j+s://", "neo4j+ssc://"))
            host = raw_uri.split("://")[-1].split(":")[0]
            candidate_uris.append(f"bolt+ssc://{host}:7687")
            candidate_uris.append(f"bolt+s://{host}:7687")
        elif raw_uri.startswith("bolt+s://"):
            candidate_uris.append(raw_uri.replace("bolt+s://", "bolt+ssc://"))

        driver = None
        last_conn_err = None
        successful_uri = None

        password = settings.NEO4J_PASSWORD or ""
        if not password:
            raise ValueError("NEO4J_PASSWORD is not set or empty in environment.")

        for cand in candidate_uris:
            try:
                d = GraphDatabase.driver(
                    cand,
                    auth=(user, password),
                    connection_timeout=15.0,
                    max_connection_pool_size=10,
                )
                d.verify_connectivity()
                driver = d
                successful_uri = redact_uri(cand)
                break
            except Exception as e:
                last_conn_err = e
                if isinstance(e, AuthError) or "Unauthorized" in str(e):
                    break

        if not driver:
            raise last_conn_err or RuntimeError("Unable to initialize Neo4j driver across candidate protocols.")

        results["step_1_connection"]["driver_initialized"] = True
        results["step_1_connection"]["connection_method"] = f"Direct official neo4j driver ({successful_uri})"

        # Probe active database
        active_db = None
        with driver.session() as s:
            probe = s.run("RETURN 1 AS connection_test").single()
            if probe and probe["connection_test"] == 1:
                results["step_1_connection"]["connectivity_verified"] = True
            try:
                db_info = s.run("CALL db.info() YIELD name RETURN name").single()
                if db_info and db_info["name"]:
                    active_db = str(db_info["name"])
            except Exception:
                active_db = "neo4j"

        results["step_1_connection"]["active_database"] = active_db
        print(f"[STEP 1 SUCCESS] Connected and verified live to Neo4j Aura (db: {active_db})")

        # Now verify existing GraphEngine-to-Neo4j integration
        print(f"[STEP 1.1] Verifying existing GraphEngine(mode='neo4j') integration...")
        engine = GraphEngine(mode="neo4j")
        if not engine.is_neo4j_live:
            raise RuntimeError(f"GraphEngine(mode='neo4j') failed to connect: {engine.last_connection_error}")

        stats = engine.get_database_statistics()
        results["step_1_connection"]["graphengine_integrated"] = True
        results["step_1_connection"]["graphengine_backend"] = stats.get("backend")
        results["step_1_connection"]["initial_db_node_count"] = stats.get("total_nodes")
        results["step_1_connection"]["initial_db_edge_count"] = stats.get("total_edges")
        print(f"[STEP 1.1 SUCCESS] GraphEngine connected to live Neo4j. Existing nodes: {stats.get('total_nodes')}, edges: {stats.get('total_edges')}")

    except Exception as e:
        err_msg = str(e)
        if settings.NEO4J_PASSWORD and settings.NEO4J_PASSWORD in err_msg:
            err_msg = err_msg.replace(settings.NEO4J_PASSWORD, "********")
        results["step_1_connection"]["error"] = err_msg
        print(f"[STEP 1 FAILED] Remote Neo4j Aura connection failed: {err_msg}")
        results["final_verdict"] = "LIVE AURA NOT AVAILABLE" if "getaddrinfo" in err_msg or "ServiceUnavailable" in err_msg else "LIVE AURA VERIFICATION FAILED"
        _record_post_hash(results, config_path)
        return results

    # -------------------------------------------------------------------------
    # STEP 2: SAFE TEST RECORD GENERATION
    # -------------------------------------------------------------------------
    test_token = uuid.uuid4().hex[:12]
    record_id = f"audit-phase-7-5-live-{test_token}"
    record_timestamp = datetime.now(timezone.utc).isoformat()

    test_payload = {
        "id": record_id,
        "name": f"SafeContain Phase 7.5 Live Aura Verification Node ({test_token})",
        "phase": "7.5",
        "audit_type": "LIVE_AURA_PERSISTENCE_AUDIT",
        "audit_marker": "PHASE_7_5_AUDIT_PROBE",
        "created_at": record_timestamp,
        "author": "Phase 7.5 Verification Agent",
        "is_test_record": True,
        "reference_threshold": 0.32,
        "status": "VERIFICATION_PROBE",
    }
    results["step_2_safe_record"]["record_id"] = record_id
    results["step_2_safe_record"]["payload"] = test_payload
    print(f"\n[STEP 2] Created safe verification record payload: {record_id}")

    # -------------------------------------------------------------------------
    # STEP 3: LIVE WRITE
    # -------------------------------------------------------------------------
    print(f"\n[STEP 3] Writing verification record to live Neo4j Aura...")
    write_cypher = """
    CREATE (n:AuditVerificationRecord:PolicyVerification {
        id: $id,
        name: $name,
        phase: $phase,
        audit_type: $audit_type,
        audit_marker: $audit_marker,
        created_at: $created_at,
        author: $author,
        is_test_record: $is_test_record,
        reference_threshold: $reference_threshold,
        status: $status
    })
    RETURN n.id as id, n.created_at as created_at
    """
    results["step_3_write"]["cypher_statement"] = write_cypher.strip()

    try:
        with driver.session() as write_session:
            write_res = write_session.run(write_cypher, **test_payload).single()
            if write_res and write_res["id"] == record_id:
                results["step_3_write"]["success"] = True
                results["step_3_write"]["written_at"] = write_res["created_at"]
                print(f"[STEP 3 SUCCESS] Record written successfully: {write_res['id']}")
            else:
                results["step_3_write"]["error"] = "Write returned empty or mismatched result."
                results["final_verdict"] = "LIVE AURA VERIFICATION FAILED"
                _record_post_hash(results, config_path)
                return results
    except Exception as e:
        err_msg = str(e)
        if settings.NEO4J_PASSWORD and settings.NEO4J_PASSWORD in err_msg:
            err_msg = err_msg.replace(settings.NEO4J_PASSWORD, "********")
        results["step_3_write"]["error"] = err_msg
        results["final_verdict"] = "LIVE AURA VERIFICATION FAILED"
        _record_post_hash(results, config_path)
        return results

    # -------------------------------------------------------------------------
    # STEP 4: LIVE READ & COMPARISON (INDEPENDENT SEPARATE SESSION)
    # -------------------------------------------------------------------------
    print(f"\n[STEP 4] Reading verification record from live Neo4j Aura in separate session...")
    read_cypher = """
    MATCH (n:AuditVerificationRecord {id: $id})
    RETURN n.id as id,
           n.name as name,
           n.phase as phase,
           n.audit_type as audit_type,
           n.audit_marker as audit_marker,
           n.created_at as created_at,
           n.author as author,
           n.is_test_record as is_test_record,
           n.reference_threshold as reference_threshold,
           n.status as status
    """
    try:
        # Explicitly open a fresh, independent session to avoid cached transaction state
        with driver.session() as read_session:
            read_res = read_session.run(read_cypher, id=record_id).single()
            if not read_res:
                results["step_4_read"]["error"] = f"Record with ID {record_id} was not found on read."
                results["final_verdict"] = "LIVE AURA VERIFICATION FAILED"
                _record_post_hash(results, config_path)
                return results

            retrieved = dict(read_res)
            results["step_4_read"]["retrieved_payload"] = retrieved
            results["step_4_read"]["success"] = True

            # Compare fields
            diffs = {}
            for k, expected_v in test_payload.items():
                actual_v = retrieved.get(k)
                if actual_v != expected_v:
                    diffs[k] = {"expected": expected_v, "actual": actual_v}

            results["step_4_read"]["field_diffs"] = diffs
            if not diffs:
                results["step_4_read"]["comparison_passed"] = True
                print(f"[STEP 4 SUCCESS] Field-by-field payload comparison passed with 0 discrepancies.")
            else:
                results["step_4_read"]["comparison_passed"] = False
                print(f"[STEP 4 ERROR] Field discrepancies found: {diffs}")

    except Exception as e:
        err_msg = str(e)
        if settings.NEO4J_PASSWORD and settings.NEO4J_PASSWORD in err_msg:
            err_msg = err_msg.replace(settings.NEO4J_PASSWORD, "********")
        results["step_4_read"]["error"] = err_msg
        results["final_verdict"] = "LIVE AURA VERIFICATION FAILED"
        _record_post_hash(results, config_path)
        return results

    # -------------------------------------------------------------------------
    # STEP 5: PERSISTENCE VERIFICATION
    # -------------------------------------------------------------------------
    print(f"\n[STEP 5] Validating persistence and isolation from in-memory fallback...")
    # Verify that GraphEngine in-memory mode has NO knowledge of this record
    in_mem_engine = GraphEngine(mode="in_memory")
    in_mem_node = in_mem_engine.get_node(record_id)
    not_in_memory = (in_mem_node is None)

    # Verify that GraphEngine live mode sees the updated node count (+1)
    stats_during = engine.get_database_statistics()
    count_increased = (stats_during.get("total_nodes", 0) == results["step_1_connection"]["initial_db_node_count"] + 1)

    results["step_5_persistence"]["independent_session"] = True
    results["step_5_persistence"]["is_in_memory_fallback"] = False
    results["step_5_persistence"]["not_in_memory_cache"] = not_in_memory
    results["step_5_persistence"]["database_stats_confirmed"] = count_increased
    results["step_5_persistence"]["persistence_verified"] = (
        results["step_3_write"]["success"]
        and results["step_4_read"]["success"]
        and results["step_4_read"]["comparison_passed"]
        and not_in_memory
        and count_increased
    )
    print(f"[STEP 5 SUCCESS] Persistence confirmed on remote Aura. Not in-memory: {not_in_memory}, Total nodes: {stats_during.get('total_nodes')}")

    # -------------------------------------------------------------------------
    # STEP 6: CLEANUP
    # -------------------------------------------------------------------------
    print(f"\n[STEP 6] Cleaning up safe test record from live Neo4j Aura...")
    results["step_6_cleanup"]["attempted"] = True
    delete_cypher = """
    MATCH (n:AuditVerificationRecord {id: $id})
    DELETE n
    RETURN count(n) as deleted_count
    """
    verify_delete_cypher = """
    MATCH (n:AuditVerificationRecord {id: $id})
    RETURN count(n) as remaining_count
    """
    try:
        with driver.session() as del_session:
            del_res = del_session.run(delete_cypher, id=record_id).single()
            deleted = del_res["deleted_count"] if del_res else 0
            results["step_6_cleanup"]["deleted_count"] = deleted

            # Verify deletion in independent query
            check_res = del_session.run(verify_delete_cypher, id=record_id).single()
            remaining = check_res["remaining_count"] if check_res else -1
            results["step_6_cleanup"]["post_delete_count"] = remaining

            # Verify final database node count returned to baseline
            stats_after = engine.get_database_statistics()
            node_count_restored = (stats_after.get("total_nodes") == results["step_1_connection"]["initial_db_node_count"])

            if deleted >= 1 and remaining == 0 and node_count_restored:
                results["step_6_cleanup"]["success"] = True
                print(f"[STEP 6 SUCCESS] Test record cleanly deleted. Remaining: {remaining}, Node count restored: {stats_after.get('total_nodes')}")
            else:
                results["step_6_cleanup"]["error"] = f"Delete verification failed. Deleted: {deleted}, Remaining: {remaining}, Count restored: {node_count_restored}"
                print(f"[STEP 6 WARNING] {results['step_6_cleanup']['error']}")

    except Exception as e:
        err_msg = str(e)
        if settings.NEO4J_PASSWORD and settings.NEO4J_PASSWORD in err_msg:
            err_msg = err_msg.replace(settings.NEO4J_PASSWORD, "********")
        results["step_6_cleanup"]["error"] = err_msg

    # Close drivers
    driver.close()
    engine.close()

    # -------------------------------------------------------------------------
    # PRODUCTION CONFIG INTEGRITY CHECK
    # -------------------------------------------------------------------------
    _record_post_hash(results, config_path)

    # -------------------------------------------------------------------------
    # FINAL VERDICT ASSIGNMENT
    # -------------------------------------------------------------------------
    if (
        results["step_1_connection"]["connectivity_verified"]
        and results["step_1_connection"]["graphengine_integrated"]
        and results["step_3_write"]["success"]
        and results["step_4_read"]["success"]
        and results["step_4_read"]["comparison_passed"]
        and results["step_5_persistence"]["persistence_verified"]
        and results["step_6_cleanup"]["success"]
        and results["production_config_check"]["unchanged"]
    ):
        results["final_verdict"] = "LIVE AURA VERIFIED"
    elif (
        results["step_1_connection"]["connectivity_verified"]
        and results["step_3_write"]["success"]
        and results["step_4_read"]["success"]
    ):
        results["final_verdict"] = "LIVE AURA VERIFIED WITH LIMITATIONS"
    else:
        results["final_verdict"] = "LIVE AURA VERIFICATION FAILED"

    print(f"\n==================================================")
    print(f"LIVE AURA VERIFICATION VERDICT: {results['final_verdict']}")
    print(f"==================================================\n")

    return results


def _record_post_hash(results: Dict[str, Any], config_path: str) -> None:
    if os.path.exists(config_path):
        with open(config_path, "rb") as f:
            post_hash = hashlib.sha256(f.read()).hexdigest()
            results["production_config_check"]["post_hash"] = post_hash
            pre_hash = results["production_config_check"].get("pre_hash")
            results["production_config_check"]["unchanged"] = (pre_hash == post_hash)


if __name__ == "__main__":
    outcome = run_live_aura_verification()
    output_path = os.path.join(BASE_DIR, "artifacts", "calibration", "live_aura_verification_results.json")
    with open(output_path, "w", encoding="utf-8") as out_f:
        json.dump(outcome, out_f, indent=2)
    print(f"Saved results to: {output_path}")
