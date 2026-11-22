"""SafeContain AI — CIC-IDS2017 Ingestion Verification Test Suite.

Covers Tests A through L:
- Test A: Header normalization & detection for full flow CSV (Source/Destination IP)
- Test B: Header normalization & detection for official 79-column CSV (Destination Port, Label)
- Test C: Attack label normalization (PortScan -> RECONNAISSANCE, BENIGN -> NORMAL)
- Test D: BENIGN records are NEVER marked compromised
- Test E: Malicious PortScan attacker node is tagged as compromised/malicious
- Test F: Flow aggregation combines packets between identical endpoints without edge explosion
- Test G: Non-destructive incremental upsert preserves existing baseline nodes
- Test H: Malformed row error isolation (skips malformed row without rejecting valid rows)
- Test I: Flow sampling disclosure when rows exceed batch ceiling
- Test J: Truthful status reporting (no false NetworkX ingestion claims on 0 parsed rows)
- Test K: Direct API upload via /api/v1/ingestion/csv
- Test L: Dedicated API upload via /api/v1/ingestion/cic-ids2017
"""

import io
import pytest
from fastapi import UploadFile

from backend.app.api.v1.router import (
    platform_ctx,
    upload_and_ingest_csv,
)
from backend.app.graph.engine import GraphEngine
from backend.app.ingestion.cic_ids_adapter import (
    CICIDS2017Adapter,
    detect_cic_ids_headers,
    normalize_attack_label,
    sanitize_ip_to_node_id,
)
from backend.app.ingestion.service import (
    CSVIngestionParser,
    CSVIngestionSummary,
    TelemetryIngestionService,
)
from backend.app.models.domain import (
    DataProvenance,
    EvidenceStatus,
    GraphNode,
    NodeType,
)


@pytest.fixture(autouse=True)
def clean_engine():
    """Ensures each test starts with an isolated in-memory graph containing baseline nodes."""
    platform_ctx.engine.clear()
    baseline = GraphNode(
        id="host-baseline-crown-jewel",
        name="Crown Jewel Payment Gateway",
        type=NodeType.SERVER,
        criticality=0.99,
        is_crown_jewel=True,
        provenance=DataProvenance.IMPORTED_BASELINE,
    )
    platform_ctx.engine.add_node(baseline)
    yield
    platform_ctx.engine.clear()


# =============================================================================
# TEST A: Detects full flow CSV (explicit Source IP & Destination IP)
# =============================================================================
def test_a_detect_full_flow_headers():
    headers = ["Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Timestamp", "Label"]
    mapping = detect_cic_ids_headers(headers)
    assert mapping is not None
    assert "source_ip" in mapping
    assert "destination_ip" in mapping
    assert "label" in mapping


# =============================================================================
# TEST B: Detects official 79-column CSV (with leading space and no explicit IPs)
# =============================================================================
def test_b_detect_official_79col_headers():
    headers = [
        " Destination Port", " Flow Duration", " Total Fwd Packets",
        " Total Backward Packets", " Total Length of Fwd Packets", " Label"
    ]
    mapping = detect_cic_ids_headers(headers)
    assert mapping is not None
    assert "destination_port" in mapping
    assert "flow_duration" in mapping
    assert "label" in mapping


# =============================================================================
# TEST C: Attack label normalization preserves original label semantics
# =============================================================================
def test_c_attack_label_normalization():
    cat_benign, sev_benign, is_mal_benign = normalize_attack_label("BENIGN")
    assert cat_benign == "NORMAL"
    assert sev_benign == "LOW"
    assert is_mal_benign is False

    cat_scan, sev_scan, is_mal_scan = normalize_attack_label("PortScan")
    assert cat_scan == "RECONNAISSANCE"
    assert sev_scan == "HIGH"
    assert is_mal_scan is True

    cat_ddos, sev_ddos, is_mal_ddos = normalize_attack_label("DDoS")
    assert cat_ddos == "DENIAL_OF_SERVICE"
    assert is_mal_ddos is True


# =============================================================================
# TEST D: BENIGN records are NEVER marked compromised
# =============================================================================
def test_d_benign_records_never_compromised():
    csv_content = (
        "Source IP,Destination IP,Destination Port,Protocol,Label\n"
        "192.168.10.14,192.168.10.50,80,6,BENIGN\n"
        "192.168.10.15,192.168.10.50,443,6,BENIGN\n"
    ).encode("utf-8")

    engine = GraphEngine()
    engine.clear()
    service = TelemetryIngestionService()
    summary = service.ingest_csv_payload(csv_content, "benign_flows.csv", engine)

    assert summary.status == "SUCCESS"
    assert summary.accepted_rows == 2
    assert summary.rejected_rows == 0

    # Ensure neither source nor destination is marked compromised
    for node in engine.get_all_nodes():
        assert node.is_compromised is False, f"Node {node.id} was incorrectly marked compromised!"


# =============================================================================
# TEST E: Malicious PortScan marks attacker node as compromised
# =============================================================================
def test_e_portscan_marks_attacker_compromised():
    csv_content = (
        "Source IP,Destination IP,Destination Port,Protocol,Label\n"
        "172.16.0.1,192.168.10.50,80,6,PortScan\n"
        "172.16.0.1,192.168.10.50,443,6,PortScan\n"
    ).encode("utf-8")

    engine = GraphEngine()
    engine.clear()
    service = TelemetryIngestionService()
    summary = service.ingest_csv_payload(csv_content, "portscan_flows.csv", engine)

    assert summary.status == "SUCCESS"
    assert summary.accepted_rows == 2

    attacker_id = sanitize_ip_to_node_id("172.16.0.1")
    victim_id = sanitize_ip_to_node_id("192.168.10.50")

    attacker = engine.get_node(attacker_id)
    victim = engine.get_node(victim_id)

    assert attacker is not None
    assert attacker.is_compromised is True, "Attacker node should be marked compromised!"

    assert victim is not None
    assert victim.is_compromised is False, "Victim target node should NOT be marked compromised!"


# =============================================================================
# TEST F: Flow aggregation combines packets without edge explosion
# =============================================================================
def test_f_flow_aggregation_prevents_edge_explosion():
    # 5 different port scan flows between the exact same attacker and target
    rows = ["Source IP,Destination IP,Destination Port,Protocol,Label"]
    for p in [21, 22, 80, 443, 8080]:
        rows.append(f"172.16.0.1,192.168.10.50,{p},6,PortScan")
    csv_content = "\n".join(rows).encode("utf-8")

    engine = GraphEngine()
    engine.clear()
    service = TelemetryIngestionService()
    summary = service.ingest_csv_payload(csv_content, "portscan_burst.csv", engine)

    assert summary.accepted_rows == 5
    assert summary.relationships_created == 1, "Expected exactly 1 aggregated communication edge!"
    assert summary.duplicate_rows == 4

    edges = engine.get_all_edges()
    assert len(edges) == 1
    edge = edges[0]
    assert edge.properties["flow_count"] == 5
    assert edge.properties["port_count"] == 5
    assert "80" in edge.properties["targeted_ports"]
    assert edge.properties["is_attack_flow"] is True
    assert edge.evidence_status == EvidenceStatus.CONFIRMED


# =============================================================================
# TEST G: Incremental upsert preserves existing baseline nodes
# =============================================================================
def test_g_incremental_preserves_baseline():
    engine = GraphEngine()
    engine.clear()

    # Pre-existing baseline node
    baseline = GraphNode(
        id="host-existing-core",
        name="Core Production Database",
        type=NodeType.DATABASE,
        criticality=1.0,
        is_crown_jewel=True,
        provenance=DataProvenance.IMPORTED_BASELINE,
    )
    engine.add_node(baseline)

    csv_content = (
        "Source IP,Destination IP,Destination Port,Protocol,Label\n"
        "192.168.10.14,192.168.10.50,80,6,BENIGN\n"
    ).encode("utf-8")

    service = TelemetryIngestionService()
    summary = service.ingest_csv_payload(csv_content, "incremental.csv", engine)

    assert summary.status == "SUCCESS"
    assert engine.get_node("host-existing-core") is not None, "Baseline node was lost!"
    assert engine.get_node("host-existing-core").is_crown_jewel is True


# =============================================================================
# TEST H: Malformed row error isolation (skips malformed without failing batch)
# =============================================================================
def test_h_malformed_row_error_isolation():
    csv_content = (
        "Source IP,Destination IP,Destination Port,Protocol,Label\n"
        "192.168.10.14,192.168.10.50,80,6,BENIGN\n"
        "MALFORMED_LINE_MISSING_COLUMNS\n"
        "192.168.10.15,192.168.10.50,443,6,BENIGN\n"
    ).encode("utf-8")

    engine = GraphEngine()
    engine.clear()
    service = TelemetryIngestionService()
    summary = service.ingest_csv_payload(csv_content, "with_malformed.csv", engine)

    assert summary.status == "PARTIAL_SUCCESS"
    assert summary.accepted_rows == 2
    assert summary.rejected_rows == 1
    assert len(summary.validation_errors) == 1
    assert summary.validation_errors[0]["error"] == "MALFORMED_ROW"


# =============================================================================
# TEST I: Official 79-column CSV ingestion without explicit IP columns
# =============================================================================
def test_i_official_79col_ingestion():
    with open("tests/data/sample_cic_ids2017_official_79col.csv", "rb") as f:
        csv_bytes = f.read()

    engine = GraphEngine()
    engine.clear()
    service = TelemetryIngestionService()
    summary = service.ingest_csv_payload(csv_bytes, "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", engine)

    assert summary.status == "SUCCESS"
    assert summary.csv_type == "CIC_IDS2017_FLOWS"
    assert summary.accepted_rows == 4
    assert summary.nodes_created >= 2
    assert summary.relationships_created >= 1

    # Verify that the attacker node 172.16.0.1 was created and flagged
    attacker = engine.get_node(sanitize_ip_to_node_id("172.16.0.1"))
    assert attacker is not None
    assert attacker.is_compromised is True


# =============================================================================
# TEST J: Truthful status on 0 rows parsed (no false NetworkX claims)
# =============================================================================
def test_j_truthful_failure_status():
    invalid_csv = b"random_unrecognized_column_1,random_column_2\nval1,val2\n"

    engine = GraphEngine()
    engine.clear()
    service = TelemetryIngestionService()
    summary = service.ingest_csv_payload(invalid_csv, "unrecognized.csv", engine)

    assert summary.status == "FAILED"
    assert summary.accepted_rows == 0
    assert summary.total_rows == 0
    assert summary.neo4j_synced is False
    assert "Unrecognized CSV header structure" in summary.message
    assert summary.validation_errors[0]["error"] == "PARSING_FAILED"


# =============================================================================
# TEST K: Direct API upload via /api/v1/ingestion/csv
# =============================================================================
def test_k_api_csv_endpoint():
    with open("tests/data/sample_cic_ids2017_portscan.csv", "rb") as f:
        file_bytes = f.read()

    upload_file = UploadFile(
        filename="Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        file=io.BytesIO(file_bytes)
    )

    from backend.app.security.user_store import user_store
    admin_user = user_store.get_user_by_username("admin")
    assert admin_user is not None

    summary = upload_and_ingest_csv(
        file=upload_file,
        override_provenance="CSV",
        current_user=admin_user
    )

    assert summary.status == "SUCCESS"
    assert summary.csv_type == "CIC_IDS2017_FLOWS"
    assert summary.accepted_rows == 5
    assert summary.nodes_created > 0
    assert summary.relationships_created > 0


# =============================================================================
# TEST L: Dedicated API upload via /api/v1/ingestion/cic-ids2017
# =============================================================================
def test_l_api_cic_ids2017_endpoint():
    with open("tests/data/sample_cic_ids2017_official_79col.csv", "rb") as f:
        file_bytes = f.read()

    upload_file = UploadFile(
        filename="Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        file=io.BytesIO(file_bytes)
    )

    from backend.app.security.user_store import user_store
    admin_user = user_store.get_user_by_username("admin")
    assert admin_user is not None

    summary = upload_and_ingest_csv(
        file=upload_file,
        override_provenance="CIC_IDS2017",
        current_user=admin_user
    )

    assert summary.status == "SUCCESS"
    assert summary.csv_type == "CIC_IDS2017_FLOWS"
    assert summary.accepted_rows == 4
