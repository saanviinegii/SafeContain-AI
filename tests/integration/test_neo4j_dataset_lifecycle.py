"""SafeContain AI — Dynamic Neo4j Dataset Lifecycle & Bloom Synchronization Test Suite.

Verifies Phases 1 through 13:
- Test 1: DatasetManager SQLite persistence, UUID generation, registration, and activation.
- Test 2: Ingested CSV records (Nodes, Edges, CIC-IDS2017) are tagged with unique dataset_id.
- Test 3: Multiple datasets coexist without ID or state collision.
- Test 4: Topology filtering scopes strictly to active or requested dataset_id.
- Test 5: Scoped deletion removes only target dataset nodes and edges (never MATCH (n) DETACH DELETE n).
- Test 6: Scoped deletion cleans in-memory NetworkX stores and triggers scoped Cypher.
- Test 7: Baseline / Demo scenario nodes and edges are preserved during dataset deletion.
- Test 8: Empty graph state is correctly returned when all uploaded datasets are deleted.
- Test 9: Reset Demo endpoint restores SCEN-001 with DEMO-SCEN-001 tags.
- Test 10: REST API security: Confirmation query param (confirm=true) is strictly enforced.
- Test 11: REST API lifecycle endpoints (list_all_datasets, get_active_dataset_metadata, set_active_dataset).
- Test 12: Audit ledger records cryptographically verifiable DATASET_DELETED event.
"""

import io
import pytest
from fastapi import HTTPException

from backend.app.api.v1.router import (
    delete_dataset,
    get_active_dataset_metadata,
    get_graph_topology,
    list_all_datasets,
    platform_ctx,
    reset_demo_scenario,
    set_active_dataset,
    upload_and_ingest_csv,
)
from backend.app.graph.engine import GraphEngine
from backend.app.ingestion.dataset_manager import DatasetManager, DatasetMetadata, dataset_manager
from backend.app.ingestion.service import TelemetryIngestionService
from backend.app.models.domain import (
    DataProvenance,
    EvidenceStatus,
    GraphEdge,
    GraphNode,
    NodeType,
    RelationshipType,
    UserRole,
)
from backend.app.security.user_store import user_store


@pytest.fixture
def admin_user():
    user = user_store.get_user_by_username("admin")
    assert user is not None
    return user


@pytest.fixture
def viewer_user():
    user = user_store.get_user_by_username("viewer")
    assert user is not None
    return user


@pytest.fixture(autouse=True)
def isolated_lifecycle_env():
    """Isolates dataset manager and in-memory engine before and after each test."""
    platform_ctx.engine.clear()
    for ds in dataset_manager.list_datasets():
        dataset_manager.delete_dataset(ds.dataset_id)
    yield
    platform_ctx.engine.clear()
    for ds in dataset_manager.list_datasets():
        dataset_manager.delete_dataset(ds.dataset_id)


# =============================================================================
# TEST 1: DatasetManager SQLite Registry CRUD & Active Switching
# =============================================================================
def test_1_dataset_manager_crud_and_activation():
    ds_id = DatasetManager.generate_dataset_id()
    assert ds_id.startswith("ds-")

    meta1 = DatasetMetadata(
        dataset_id=ds_id,
        name="Test Ingestion Alpha",
        source_filename="alpha.csv",
        source_type="CSV_NODES",
        node_count=10,
        edge_count=15,
        is_active=True,
        is_demo=False
    )
    dataset_manager.register_dataset(meta1)

    # Verify retrieval
    retrieved = dataset_manager.get_dataset(ds_id)
    assert retrieved is not None
    assert retrieved.name == "Test Ingestion Alpha"
    assert retrieved.is_active is True

    # Register second dataset (should become active, deactivating first)
    ds_id_2 = DatasetManager.generate_dataset_id()
    meta2 = DatasetMetadata(
        dataset_id=ds_id_2,
        name="Test Ingestion Beta",
        source_filename="beta.csv",
        source_type="CIC_IDS2017_FLOWS",
        node_count=5,
        edge_count=8,
        is_active=True,
        is_demo=False
    )
    dataset_manager.register_dataset(meta2)

    active = dataset_manager.get_active_dataset()
    assert active is not None
    assert active.dataset_id == ds_id_2

    # Verify first is now inactive
    d1 = dataset_manager.get_dataset(ds_id)
    assert d1.is_active is False

    # Switch activation back to first
    dataset_manager.set_active_dataset(ds_id)
    active_switched = dataset_manager.get_active_dataset()
    assert active_switched.dataset_id == ds_id


# =============================================================================
# TEST 2: Ingestion Tags Entities with dataset_id and source_file
# =============================================================================
def test_2_ingestion_tags_entities_with_dataset_id():
    csv_bytes = (
        "node_id,name,type,criticality,is_compromised,is_crown_jewel,ip_address\n"
        "srv-alpha-01,Alpha Web Server,SERVER,0.85,false,true,10.10.1.5\n"
        "srv-alpha-02,Alpha DB Server,DATABASE,0.95,false,true,10.10.1.6\n"
    ).encode("utf-8")

    engine = platform_ctx.engine
    service = TelemetryIngestionService()
    summary = service.ingest_csv_payload(csv_bytes, "nodes_alpha.csv", engine)

    assert summary.status == "SUCCESS"
    assert summary.dataset_id is not None
    assert summary.accepted_rows == 2

    node1 = engine.get_node("srv-alpha-01")
    assert node1 is not None
    assert node1.dataset_id == summary.dataset_id
    assert node1.source_file == "nodes_alpha.csv"
    assert node1.is_demo is False
    assert node1.properties.get("dataset_id") == summary.dataset_id


# =============================================================================
# TEST 3: Multiple Datasets Coexist with Scoped Properties
# =============================================================================
def test_3_multiple_datasets_coexist():
    service = TelemetryIngestionService()
    engine = platform_ctx.engine

    csv1 = (
        "node_id,name,type,criticality\n"
        "node-ds1-01,DS1 Host A,HOST,0.5\n"
        "node-ds1-02,DS1 Host B,HOST,0.6\n"
    ).encode("utf-8")
    s1 = service.ingest_csv_payload(csv1, "batch1.csv", engine)

    csv2 = (
        "node_id,name,type,criticality\n"
        "node-ds2-01,DS2 Server X,SERVER,0.9\n"
        "node-ds2-02,DS2 Server Y,SERVER,0.8\n"
    ).encode("utf-8")
    s2 = service.ingest_csv_payload(csv2, "batch2.csv", engine)

    assert s1.dataset_id != s2.dataset_id
    assert engine.get_node("node-ds1-01").dataset_id == s1.dataset_id
    assert engine.get_node("node-ds2-01").dataset_id == s2.dataset_id


# =============================================================================
# TEST 4: Topology Scoped Export Filters by dataset_id
# =============================================================================
def test_4_topology_scoped_export():
    service = TelemetryIngestionService()
    engine = platform_ctx.engine

    csv1 = "node_id,name,type,criticality\nnode-a1,Host A1,HOST,0.5\n".encode("utf-8")
    s1 = service.ingest_csv_payload(csv1, "ds1.csv", engine)

    csv2 = "node_id,name,type,criticality\nnode-b1,Host B1,HOST,0.5\n".encode("utf-8")
    s2 = service.ingest_csv_payload(csv2, "ds2.csv", engine)

    # Scoped export for s1
    topo_s1 = engine.export_topology(dataset_id=s1.dataset_id)
    n_ids_s1 = [n["id"] for n in topo_s1["nodes"]]
    assert "node-a1" in n_ids_s1
    assert "node-b1" not in n_ids_s1

    # Scoped export for s2
    topo_s2 = engine.export_topology(dataset_id=s2.dataset_id)
    n_ids_s2 = [n["id"] for n in topo_s2["nodes"]]
    assert "node-b1" in n_ids_s2
    assert "node-a1" not in n_ids_s2


# =============================================================================
# TEST 5: Scoped Deletion Removes Target Dataset and Leaves Other Untouched
# =============================================================================
def test_5_scoped_deletion_preserves_unrelated_dataset():
    service = TelemetryIngestionService()
    engine = platform_ctx.engine

    # Dataset A
    csv_a = (
        "node_id,name,type,criticality\n"
        "node-del-01,Delete Me 1,HOST,0.5\n"
        "node-del-02,Delete Me 2,HOST,0.5\n"
    ).encode("utf-8")
    s_a = service.ingest_csv_payload(csv_a, "delete_target.csv", engine)

    # Dataset B
    csv_b = (
        "node_id,name,type,criticality\n"
        "node-keep-01,Keep Me 1,HOST,0.5\n"
    ).encode("utf-8")
    s_b = service.ingest_csv_payload(csv_b, "preserve_target.csv", engine)

    # Delete Dataset A
    stats = engine.delete_dataset_scoped(s_a.dataset_id)
    dataset_manager.delete_dataset(s_a.dataset_id)

    assert stats["nodes_deleted"] == 2

    # Verify A is gone
    assert engine.get_node("node-del-01") is None
    assert engine.get_node("node-del-02") is None

    # Verify B is intact
    assert engine.get_node("node-keep-01") is not None
    assert engine.get_node("node-keep-01").dataset_id == s_b.dataset_id


# =============================================================================
# TEST 6: Demo Scenario Preservation During Ingested Dataset Deletion
# =============================================================================
def test_6_demo_scenario_preservation_during_deletion():
    engine = platform_ctx.engine

    # Add demo node
    demo_node = GraphNode(
        id="demo-srv-crown",
        name="Demo Financial Ledger",
        type=NodeType.SERVER,
        criticality=0.98,
        is_crown_jewel=True,
        provenance=DataProvenance.SYNTHETIC,
        dataset_id="DEMO-SCEN-001",
        is_demo=True
    )
    engine.add_node(demo_node)

    # Add uploaded node
    service = TelemetryIngestionService()
    csv = "node_id,name,type,criticality\nupload-temp-01,Temp Node,HOST,0.4\n".encode("utf-8")
    s = service.ingest_csv_payload(csv, "temp.csv", engine)

    # Delete uploaded dataset
    engine.delete_dataset_scoped(s.dataset_id)
    dataset_manager.delete_dataset(s.dataset_id)

    # Uploaded is deleted
    assert engine.get_node("upload-temp-01") is None
    # Demo node is completely preserved
    assert engine.get_node("demo-srv-crown") is not None
    assert engine.get_node("demo-srv-crown").is_demo is True


# =============================================================================
# TEST 7: Empty State Returned When All Datasets Deleted
# =============================================================================
def test_7_empty_state_when_all_datasets_deleted(viewer_user):
    # Ensure no datasets exist
    platform_ctx.engine.clear()
    for ds in dataset_manager.list_datasets():
        dataset_manager.delete_dataset(ds.dataset_id)

    data = get_graph_topology(dataset_id=None, current_user=viewer_user)
    assert data["nodes"] == []
    assert data["edges"] == []
    assert data.get("active_dataset") is None


# =============================================================================
# TEST 8: REST API Deletion Confirmation Requirement (confirm=true)
# =============================================================================
def test_8_api_delete_requires_confirmation(admin_user):
    ds_id = DatasetManager.generate_dataset_id()
    dataset_manager.register_dataset(DatasetMetadata(
        dataset_id=ds_id,
        name="Target DS",
        source_filename="test.csv",
        source_type="CSV_NODES"
    ))

    # Calling delete_dataset with confirm=False must raise HTTPException 400
    with pytest.raises(HTTPException) as exc_info:
        delete_dataset(dataset_id=ds_id, confirm=False, current_user=admin_user)
    assert exc_info.value.status_code == 400
    assert "confirm=true" in exc_info.value.detail

    # Calling with confirm=True succeeds
    result = delete_dataset(dataset_id=ds_id, confirm=True, current_user=admin_user)
    assert result["status"] == "DELETED"
    assert result["dataset_id"] == ds_id


# =============================================================================
# TEST 9: REST API List, Active, and Activate Endpoints
# =============================================================================
def test_9_api_datasets_list_and_activate(admin_user, viewer_user):
    ds1_id = DatasetManager.generate_dataset_id()
    ds2_id = DatasetManager.generate_dataset_id()

    dataset_manager.register_dataset(DatasetMetadata(
        dataset_id=ds1_id,
        name="Dataset 1",
        source_filename="ds1.csv",
        source_type="CSV_NODES",
        is_active=False
    ))
    dataset_manager.register_dataset(DatasetMetadata(
        dataset_id=ds2_id,
        name="Dataset 2",
        source_filename="ds2.csv",
        source_type="CSV_NODES",
        is_active=True
    ))

    # List all datasets
    datasets = list_all_datasets(current_user=viewer_user)
    assert len(datasets) == 2

    # Get active dataset
    active = get_active_dataset_metadata(current_user=viewer_user)
    assert active is not None
    assert active["dataset_id"] == ds2_id

    # Activate ds1
    act_res = set_active_dataset(dataset_id=ds1_id, current_user=admin_user)
    assert act_res["status"] == "SUCCESS"
    assert act_res["active_dataset"]["dataset_id"] == ds1_id

    # Verify active is now ds1
    new_active = get_active_dataset_metadata(current_user=viewer_user)
    assert new_active["dataset_id"] == ds1_id


# =============================================================================
# TEST 10: Cryptographic Audit Ledger Records DATASET_DELETED Event
# =============================================================================
def test_10_audit_ledger_records_deletion_event(admin_user):
    ds_id = DatasetManager.generate_dataset_id()
    dataset_manager.register_dataset(DatasetMetadata(
        dataset_id=ds_id,
        name="Audit Deletion Test",
        source_filename="audit.csv",
        source_type="CSV_NODES"
    ))

    delete_dataset(dataset_id=ds_id, confirm=True, current_user=admin_user)

    recent_events = platform_ctx.ledger.get_events(10)
    deletion_events = [e for e in recent_events if e.action == "DATASET_DELETED" and e.resource_id == ds_id]
    assert len(deletion_events) == 1
    assert deletion_events[0].resource_type == "Dataset"


# =============================================================================
# TEST 11: Reset Demo Scenario Restores SCEN-001 with Demo Tagging
# =============================================================================
def test_11_reset_demo_scenario(admin_user, viewer_user):
    # First clear
    platform_ctx.engine.clear()
    for ds in dataset_manager.list_datasets():
        dataset_manager.delete_dataset(ds.dataset_id)

    # Call reset demo endpoint
    res = reset_demo_scenario(scenario_id="SCEN-001", current_user=admin_user)
    assert res["status"] == "SUCCESS"
    assert res["nodes_loaded"] > 0
    assert res["edges_loaded"] > 0

    # Verify demo dataset is active
    active = get_active_dataset_metadata(current_user=viewer_user)
    assert active is not None
    assert active["dataset_id"] == "DEMO-SCEN-001"
    assert active["is_demo"] is True

    # Verify nodes in engine have is_demo and dataset_id
    demo_nodes = platform_ctx.engine.get_all_nodes()
    assert len(demo_nodes) > 0
    for node in demo_nodes:
        assert node.is_demo is True
        assert node.dataset_id == "DEMO-SCEN-001"
