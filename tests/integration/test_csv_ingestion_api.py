"""Targeted Integration Tests for Backend CSV Upload API & Incremental Neo4j Ingestion (Phase 5B.2A).

Verifies:
1. Valid CSV upload (Nodes and Relationships)
2. Invalid extension and malformed row error handling with row-level tracking
3. Duplicate CSV upload and idempotency
4. Incremental persistence (preserving existing graph without deletion or reset)
5. Neo4j offline/fallback handling and graceful degradation
6. Provenance override, audit ledger chaining, and integrity
"""

import io
import pytest
from fastapi import HTTPException, UploadFile

from backend.app.api.v1.router import (
    platform_ctx,
    upload_and_ingest_csv,
)
from backend.app.models.domain import DataProvenance, GraphNode, NodeType


@pytest.fixture(autouse=True)
def ensure_clean_test_context():
    """Initializes platform context with a baseline node for incremental testing."""
    platform_ctx.engine.clear()
    # Add a baseline node that must be preserved across incremental uploads
    baseline_node = GraphNode(
        id="host-baseline-existing",
        name="Existing Baseline Host",
        type=NodeType.SERVER,
        criticality=0.8,
        provenance=DataProvenance.IMPORTED_BASELINE,
    )
    platform_ctx.engine.add_node(baseline_node)
    yield


def test_valid_nodes_csv_upload():
    """Test 1: Valid nodes CSV upload creates nodes with DataProvenance.CSV."""
    csv_content = (
        "node_id,name,node_type,criticality,environment,department,is_crown_jewel,is_compromised\n"
        "srv-app-custom-01,Custom Web Application,SERVER,0.85,Production,Engineering,false,false\n"
        "db-custom-vault-01,Custom Secure Vault,DATABASE,0.98,Production,Finance,true,false\n"
    ).encode("utf-8")

    upload_file = UploadFile(
        filename="custom_nodes.csv",
        file=io.BytesIO(csv_content),
        headers={"content-type": "text/csv"}
    )

    res = upload_and_ingest_csv(file=upload_file)

    assert res.status == "SUCCESS"
    assert res.csv_type == "NODES"
    assert res.total_rows == 2
    assert res.accepted_rows == 2
    assert res.rejected_rows == 0
    assert res.nodes_created == 2
    assert res.nodes_updated == 0

    # Verify nodes exist in engine with correct attributes & provenance
    n1 = platform_ctx.engine.get_node("srv-app-custom-01")
    n2 = platform_ctx.engine.get_node("db-custom-vault-01")
    assert n1 is not None
    assert n1.name == "Custom Web Application"
    assert n1.provenance == DataProvenance.CSV
    assert n2 is not None
    assert n2.is_crown_jewel is True
    assert n2.criticality == 0.98


def test_valid_relationships_csv_upload():
    """Test 2: Valid relationships CSV upload creates edges with DataProvenance.CSV."""
    # Pre-populate endpoints
    platform_ctx.engine.add_node(GraphNode(id="src-host-01", name="Source Host", type=NodeType.HOST))
    platform_ctx.engine.add_node(GraphNode(id="tgt-db-01", name="Target DB", type=NodeType.DATABASE))

    csv_content = (
        "relationship_id,source_id,target_id,relationship_type,confidence,risk_score,is_active\n"
        "rel-src-tgt-access,src-host-01,tgt-db-01,HAS_ACCESS_TO,0.92,35.0,true\n"
    ).encode("utf-8")

    upload_file = UploadFile(
        filename="custom_edges.csv",
        file=io.BytesIO(csv_content),
        headers={"content-type": "text/csv"}
    )

    res = upload_and_ingest_csv(file=upload_file)

    assert res.status == "SUCCESS"
    assert res.csv_type == "RELATIONSHIPS"
    assert res.accepted_rows == 1
    assert res.relationships_created == 1

    edge = platform_ctx.engine.get_edge("rel-src-tgt-access")
    assert edge is not None
    assert edge.source == "src-host-01"
    assert edge.target == "tgt-db-01"
    assert edge.provenance == DataProvenance.CSV


def test_invalid_extension_and_malformed_csv():
    """Test 3: Rejects invalid file extensions and malformed rows with row numbers."""
    # Step A: Invalid extension rejected with HTTP 400
    bad_ext_file = UploadFile(
        filename="unsupported.json",
        file=io.BytesIO(b'{"key": "val"}'),
        headers={"content-type": "application/json"}
    )
    with pytest.raises(HTTPException) as excinfo:
        upload_and_ingest_csv(file=bad_ext_file)
    assert excinfo.value.status_code == 400
    assert "Invalid file extension" in excinfo.value.detail

    # Step B: Malformed rows handled safely without dropping valid rows
    # Row 2 (1st data row): Malformed (too few columns)
    # Row 3 (2nd data row): Invalid criticality ("NOT_A_FLOAT")
    # Row 4 (3rd data row): Missing primary key (empty node_id)
    # Row 5 (4th data row): Valid node
    csv_content = (
        "node_id,name,node_type,criticality\n"
        "bad-col-count\n"
        "node-bad-crit,Node Bad Crit,SERVER,NOT_A_FLOAT\n"
        ",Missing ID Node,SERVER,0.5\n"
        "node-valid-01,Valid Node Survives,ENDPOINT,0.4\n"
    ).encode("utf-8")

    upload_file = UploadFile(
        filename="corrupted_nodes.csv",
        file=io.BytesIO(csv_content),
        headers={"content-type": "text/csv"}
    )

    res = upload_and_ingest_csv(file=upload_file)

    assert res.status == "PARTIAL_SUCCESS"
    assert res.accepted_rows == 1
    assert res.rejected_rows == 3
    assert len(res.validation_errors) == 3

    # Check error row numbers
    error_rows = [err["row"] for err in res.validation_errors]
    assert 2 in error_rows  # Malformed row
    assert 3 in error_rows  # Invalid criticality
    assert 4 in error_rows  # Missing node_id

    # Ensure valid node survived and was added
    surviving = platform_ctx.engine.get_node("node-valid-01")
    assert surviving is not None
    assert surviving.name == "Valid Node Survives"


def test_duplicate_csv_upload_idempotency():
    """Test 4: Re-uploading identical records is idempotent and tracks duplicates."""
    csv_content = (
        "node_id,name,node_type,criticality\n"
        "idempotent-node-01,Idempotent Server,SERVER,0.7\n"
    ).encode("utf-8")

    # First upload
    f1 = UploadFile(filename="idem.csv", file=io.BytesIO(csv_content))
    res1 = upload_and_ingest_csv(file=f1)
    assert res1.nodes_created == 1
    assert res1.duplicate_rows == 0

    # Second upload (identical)
    f2 = UploadFile(filename="idem.csv", file=io.BytesIO(csv_content))
    res2 = upload_and_ingest_csv(file=f2)
    assert res2.nodes_created == 0
    assert res2.duplicate_rows == 1
    assert res2.accepted_rows == 1

    # Graph count check: Node should not be duplicated
    matching = [n for n in platform_ctx.engine.get_all_nodes() if n.id == "idempotent-node-01"]
    assert len(matching) == 1


def test_incremental_upload_preserves_existing_graph():
    """Test 5: Ingestion preserves existing graph data and NEVER deletes or resets."""
    # Ensure baseline node is present
    assert platform_ctx.engine.get_node("host-baseline-existing") is not None
    initial_count = len(platform_ctx.engine.get_all_nodes())

    # Ingest 2 new nodes
    csv_content = (
        "node_id,name,node_type,criticality\n"
        "incremental-node-a,Inc Node A,SERVER,0.5\n"
        "incremental-node-b,Inc Node B,DATABASE,0.9\n"
    ).encode("utf-8")

    f = UploadFile(filename="incremental.csv", file=io.BytesIO(csv_content))
    res = upload_and_ingest_csv(file=f)

    assert res.status == "SUCCESS"
    assert res.nodes_created == 2

    # Baseline node must STILL exist untouched
    baseline = platform_ctx.engine.get_node("host-baseline-existing")
    assert baseline is not None
    assert baseline.name == "Existing Baseline Host"
    assert baseline.provenance == DataProvenance.IMPORTED_BASELINE

    # Total count must be exactly initial_count + 2
    assert len(platform_ctx.engine.get_all_nodes()) == initial_count + 2


def test_neo4j_offline_graceful_handling():
    """Test 6: Graceful fallback and clear reporting when Neo4j is offline or in fallback mode."""
    # Temporarily simulate offline Neo4j state to verify resilience
    original_state = platform_ctx.engine._neo4j_available
    platform_ctx.engine._neo4j_available = False
    try:
        csv_content = (
            "node_id,name,node_type,criticality\n"
            "fallback-node-01,Fallback Test Host,SERVER,0.6\n"
        ).encode("utf-8")

        f = UploadFile(filename="fallback.csv", file=io.BytesIO(csv_content))
        res = upload_and_ingest_csv(file=f)

        assert res.status == "SUCCESS"
        assert res.neo4j_synced is False
        assert res.neo4j_status == "OFFLINE_FALLBACK"
        assert "in_memory_networkx" in res.neo4j_details.get("mode", "")

        # In-memory graph still receives node
        assert platform_ctx.engine.get_node("fallback-node-01") is not None
    finally:
        platform_ctx.engine._neo4j_available = original_state


def test_csv_upload_with_audit_logging_and_provenance_override():
    """Test 7: Direct upload with provenance override and cryptographic audit verification."""
    csv_bytes = (
        "node_id,name,node_type,criticality,environment,department\n"
        "node-audit-test-01,Audit Test Node,SERVER,0.75,Production,Security\n"
    ).encode("utf-8")

    upload_file = UploadFile(
        filename="audit_test.csv",
        file=io.BytesIO(csv_bytes),
        headers={"content-type": "text/csv"}
    )

    res = upload_and_ingest_csv(file=upload_file, override_provenance="LIVE_TELEMETRY")

    assert res.status == "SUCCESS"
    assert res.filename == "audit_test.csv"
    assert res.csv_type == "NODES"
    assert res.total_rows == 1
    assert res.accepted_rows == 1
    assert res.nodes_created == 1

    # Verify provenance override applied
    node = platform_ctx.engine.get_node("node-audit-test-01")
    assert node is not None
    assert node.provenance == DataProvenance.LIVE_TELEMETRY

    # Verify audit event recorded in ledger
    events = platform_ctx.ledger.get_events()
    csv_events = [e for e in events if e.action == "CSV_INGESTION_UPLOAD"]
    assert len(csv_events) > 0
    latest_event = csv_events[-1]
    assert latest_event.resource_id == res.upload_id
    assert latest_event.metadata["filename"] == "audit_test.csv"
    assert latest_event.metadata["accepted_rows"] == 1
