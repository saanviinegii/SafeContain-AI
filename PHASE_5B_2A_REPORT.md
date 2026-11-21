# SafeContain AI — Phase 5B.2A Technical Ingestion Report
**Module:** Backend CSV Upload API & Incremental Neo4j Ingestion  
**Status:** Completed & Validated  
**Targeted Test Suite:** `tests/integration/test_csv_ingestion_api.py` (7/7 Passed in 2.55s)  
**Live Endpoint:** `POST /api/v1/ingestion/csv` (Mounted on `http://127.0.0.1:8000`)  

---

## 1. Executive Summary

Phase 5B.2A implements an enterprise-grade, incremental CSV ingestion engine for SafeContain AI. The service enables SOC analysts and security engineers to upload arbitrary network and telemetry CSV files via `multipart/form-data`, validates them safely row-by-row, detects entities and relations, applies idempotent upserts, attaches strict data provenance labels (`DataProvenance.CSV`), and synchronizes directly with the active Neo4j graph engine with graceful offline fallback.

Crucially:
- **Zero Graph Wiping:** Ingestion never resets, deletes, or truncates existing graph topology or synthetic baselines.
- **Strict Idempotency:** Duplicate rows or re-uploaded identical files are identified, counted, and merged without generating duplicate nodes, edges, or phantom attack paths.
- **Audit Ledger Anchoring:** Every CSV upload batch is automatically hashed and recorded into SafeContain AI's cryptographic SHA-256 audit ledger (`CSV_INGESTION_UPLOAD`).

---

## 2. Architecture & Components

```
                          [ Client / SOC Ingestion ]
                                      │
                     multipart/form-data (*.csv)
                                      ▼
               ┌──────────────────────────────────────────────┐
               │         FastAPI Router & Validation          │
               │        (POST /api/v1/ingestion/csv)          │
               └──────────────────────┬───────────────────────┘
                                      │
                         raw stream / bytes decode
                                      ▼
               ┌──────────────────────────────────────────────┐
               │             CSVIngestionParser               │
               │  - File extension & size limit check (10MB)  │
               │  - Row limit check (max 10,000 rows)         │
               │  - Dynamic header detection (Nodes vs Edges) │
               │  - Row-by-row error tracking (row numbers)   │
               └──────────────────────┬───────────────────────┘
                                      │
                         valid records & errors
                                      ▼
               ┌──────────────────────────────────────────────┐
               │          TelemetryIngestionService           │
               │  - Entity normalization into GraphNode/Edge  │
               │  - Provenance assignment: DataProvenance.CSV │
               │  - Duplicate detection (in-memory & db)      │
               │  - Dynamic Cypher MERGE generation           │
               └──────────────┬───────────────────────────────┘
                              │
             ┌────────────────┴────────────────┐
             ▼                                 ▼
   ┌───────────────────┐             ┌───────────────────┐
   │ In-Memory NetworkX│             │ Neo4j Live Server │
   │   (Dual Fallback) │             │  (Idempotent MERGE│
   │  Preserves State  │             │   Parameterized)  │
   └───────────────────┘             └───────────────────┘
```

### 2.1 Core Implementation Files
1. **`backend/app/models/domain.py`**:
   - Added `CSV = "CSV"` to `DataProvenance(str, Enum)`.
2. **`backend/app/ingestion/service.py`**:
   - `CSVIngestionParser`: Handles UTF-8 streaming, sniffing column headers (`node_id`, `relationship_id`, `source_id`, `target_id`), enforcing field type conversions (criticality, confidence, risk score), and isolating malformed rows without aborting the batch.
   - `CSVIngestionSummary`: Structured Pydantic response detailing rows parsed, created, updated, rejected, duplicates, Neo4j sync status, and row-level error breakdown.
   - `TelemetryIngestionService`: Performs non-destructive incremental graph upserts on `GraphEngine`. Constructs parameterized Cypher `MERGE` queries when Neo4j is connected, and seamlessly falls back to NetworkX in dual mode if Neo4j is offline.
3. **`backend/app/api/v1/router.py`**:
   - Mounted `POST /api/v1/ingestion/csv` and backward-compatible alias `POST /api/v1/ingest/csv`.
   - Records tamper-evident audit events into `platform_ctx.ledger` for every upload.
4. **`requirements.txt`**:
   - Added `python-multipart>=0.0.9`.

---

## 3. API Contract

### Request
- **Method:** `POST`
- **Path:** `/api/v1/ingestion/csv`
- **Content-Type:** `multipart/form-data`
- **Parameters:**
  - `file` (*required*, binary): The CSV file to upload (must have `.csv` extension, max 10MB, max 10,000 rows).
  - `override_provenance` (*optional*, string): Provenance tag override (e.g. `CSV`, `LIVE_TELEMETRY`). Defaults to `CSV`.

#### Supported CSV Schemas

**1. Graph Nodes CSV:**
Required header: `node_id`  
Optional headers: `name`, `node_type`, `criticality`, `environment`, `department`, `is_crown_jewel`, `is_compromised`  
*Example:*
```csv
node_id,name,node_type,criticality,environment,department,is_crown_jewel,is_compromised
srv-app-custom-01,Custom Web Application,SERVER,0.85,Production,Engineering,false,false
db-custom-vault-01,Custom Secure Vault,DATABASE,0.98,Production,Finance,true,false
```

**2. Graph Relationships CSV:**
Required headers: `relationship_id` (or auto-generated), `source_id`, `target_id`  
Optional headers: `relationship_type`, `confidence`, `risk_score`, `is_active`  
*Example:*
```csv
relationship_id,source_id,target_id,relationship_type,confidence,risk_score,is_active
rel-src-tgt-access,src-host-01,tgt-db-01,HAS_ACCESS_TO,0.92,35.0,true
```

---

### Response (`200 OK`)
```json
{
  "upload_id": "csv-batch-94f2de55dc",
  "filename": "live_probe.csv",
  "csv_type": "NODES",
  "total_rows": 1,
  "accepted_rows": 1,
  "rejected_rows": 0,
  "duplicate_rows": 0,
  "nodes_created": 1,
  "nodes_updated": 0,
  "relationships_created": 0,
  "relationships_updated": 0,
  "neo4j_synced": false,
  "neo4j_status": "OFFLINE_FALLBACK",
  "neo4j_details": {
    "mode": "in_memory_networkx",
    "message": "Neo4j is not connected or in fallback mode. Upserted to in-memory graph."
  },
  "validation_errors": [],
  "status": "SUCCESS",
  "message": "Successfully processed 1 rows from 'live_probe.csv'. (1 nodes created, 0 edges created).",
  "timestamp": "2026-11-20T05:15:18.310565Z"
}
```

---

## 4. Safety & Provenance Guarantees

| Requirement | Implementation Mechanism | Validation Status |
|:---|:---|:---:|
| **Zero Graph Erasure** | Uses `add_node` / `add_edge` and Cypher `MERGE`. Never calls `clear()`, `RESET`, or `DETACH DELETE`. | Verified |
| **Strict Provenance** | Assigns `DataProvenance.CSV`. Existing `SYNTHETIC`, `IMPORTED_BASELINE`, or `LIVE_TELEMETRY` nodes remain untouched. | Verified |
| **Idempotent Upserts** | Compares incoming IDs against active store. Identical rows increment `duplicate_rows` without altering graph state. | Verified |
| **Row-Level Fault Tolerance** | Malformed rows are logged with exact CSV line numbers in `validation_errors`. Valid rows in the same file are preserved (`PARTIAL_SUCCESS`). | Verified |
| **Cryptographic Audit** | Upload metadata, batch ID, accepted/rejected counts, and filename are chained into `AuditLedger`. | Verified |

---

## 5. Verification & Test Execution

### 5.1 Targeted Pytest Suite (`tests/integration/test_csv_ingestion_api.py`)

Targeted command executed:
```bash
pytest tests/integration/test_csv_ingestion_api.py -v
```

**Results:**
```text
============================= test session starts =============================
platform win32 -- Python 3.14.8, pytest-9.2.0, pluggy-1.7.0
rootdir: C:\Users\saanv\Desktop\SafeContain AI
collected 7 items

tests/integration/test_csv_ingestion_api.py::test_valid_nodes_csv_upload PASSED                [ 14%]
tests/integration/test_csv_ingestion_api.py::test_valid_relationships_csv_upload PASSED        [ 28%]
tests/integration/test_csv_ingestion_api.py::test_invalid_extension_and_malformed_csv PASSED   [ 42%]
tests/integration/test_csv_ingestion_api.py::test_duplicate_csv_upload_idempotency PASSED     [ 57%]
tests/integration/test_csv_ingestion_api.py::test_incremental_upload_preserves_existing_graph PASSED [ 71%]
tests/integration/test_csv_ingestion_api.py::test_neo4j_offline_graceful_handling PASSED     [ 85%]
tests/integration/test_csv_ingestion_api.py::test_csv_upload_with_audit_logging_and_provenance_override PASSED [100%]

============================== 7 passed in 2.55s ==============================
```

### 5.2 Live HTTP Multipart Probe on Running Server

**Probe 1: Ingestion of new server node via live HTTP POST:**
```json
HTTP/1.1 200 OK
{
  "upload_id": "csv-batch-94f2de55dc",
  "filename": "live_probe.csv",
  "csv_type": "NODES",
  "total_rows": 1,
  "accepted_rows": 1,
  "rejected_rows": 0,
  "duplicate_rows": 0,
  "nodes_created": 1,
  "status": "SUCCESS"
}
```

**Probe 2: Immediate re-upload of identical CSV (Idempotency Check):**
```json
HTTP/1.1 200 OK
{
  "upload_id": "csv-batch-dc80198257",
  "filename": "live_probe.csv",
  "csv_type": "NODES",
  "total_rows": 1,
  "accepted_rows": 1,
  "rejected_rows": 0,
  "duplicate_rows": 1,
  "nodes_created": 0,
  "status": "SUCCESS"
}
```

---

## 6. Current Limitations & Transition

1. **Neo4j Aura Cloud Connectivity:**
   - The backend runs resiliently in dual fallback mode (`in_memory_networkx`). When Neo4j credentials are confirmed live, Cypher `MERGE` statements execute automatically without backend code changes.
2. **Frontend Ingestion UI (Phase 5B.2B):**
   - As per task scope constraints, frontend files were not modified during this phase. Phase 5B.2B will mount the CSV upload file-drop widget into the UI.
