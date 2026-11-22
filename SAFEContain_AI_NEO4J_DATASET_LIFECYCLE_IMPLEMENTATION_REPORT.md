# SafeContain AI — Dynamic Neo4j Dataset Lifecycle & Bloom Synchronization Implementation Report

**Document Status:** Production Verified  
**Date:** November 22, 2026  
**System:** SafeContain AI Enterprise Cybersecurity Decision-Intelligence Platform  
**Target Environment:** FastAPI (Python 3.14), React + TypeScript (Vite), Neo4j AuraDB (`neo4j+s://e5193897.databases.neo4j.io`), NetworkX Engine  

---

## 1. Executive Summary & Root Cause Analysis

### 1.1 The Problem
Prior to this implementation, when security operators removed an uploaded CSV file from the SafeContain AI frontend (or when previous dataset uploads completed), the nodes and relationships created from that CSV remained permanently inside the Neo4j AuraDB instance. As a result:
1. Neo4j AuraDB and Neo4j Bloom continued to display nodes and communication links from previously removed datasets.
2. Analysts inspecting graphs in Neo4j Bloom observed stale topology, phantom attack paths, and confusing overlaps between independent datasets.
3. The frontend application and the backend database were out of sync: the frontend had discarded the file reference, but the database retained all graph entities without any lifecycle ownership or dataset boundary.

### 1.2 Root Cause Analysis
An exhaustive code audit of the ingestion pipeline and graph persistence layer identified four core architectural deficits:

1. **Client-Side Only File Removal (Frontend Evaporation):**  
   In `frontend/src/App.tsx` (line 7660), clicking the "Remove file" (`<XCircle />`) button previously executed only `setCsvFile(null); setCsvUploadSummary(null);`. This was purely local React state mutation. No HTTP request was ever dispatched to the backend, meaning no deletion logic was ever triggered.

2. **Absence of Dataset Scoping & Ownership Identifiers:**  
   In `backend/app/models/domain.py`, `GraphNode` and `GraphEdge` lacked first-class `dataset_id`, `source_file`, and `is_demo` attributes. Ingestion routines only added an ephemeral `upload_batch_id` to entity properties, making it impossible to deterministically query, scope, or delete a dataset's entities without risking deletion of baseline or demo scenario nodes.

3. **Missing Dataset Lifecycle Registry (ACID Persistence):**  
   The platform lacked a persistent dataset management table. Datasets were treated as ad-hoc streaming bursts rather than registered entities with lifecycle states (`ACTIVE`, `INACTIVE`, `is_demo`).

4. **Lack of Scoped Deletion Cypher in Graph Engine:**  
   `GraphEngine` only possessed `clear()`, which purged in-memory NetworkX dictionaries, and `sync_to_neo4j()`, which merged data into Neo4j. There was no mechanism to execute scoped Cypher deletion to safely remove only the nodes and edges belonging to a specific dataset without executing dangerous global deletions like `MATCH (n) DETACH DELETE n`.

---

## 2. Architecture & Design Principles

To resolve these issues permanently while strictly adhering to safety rules, we implemented a comprehensive dataset lifecycle architecture across all platform tiers:

```
                      +---------------------------------------+
                      |       SafeContain AI Frontend         |
                      |  - Active Datasets Table              |
                      |  - Scoped Deletion Modal              |
                      |  - Empty State & Dataset Banner       |
                      +-------------------+-------------------+
                                          |
                                          | REST API (JWT Authenticated)
                                          v
                      +---------------------------------------+
                      |      FastAPI Primary Router (v1)      |
                      |  - GET    /api/v1/datasets            |
                      |  - GET    /api/v1/datasets/active     |
                      |  - POST   /api/v1/datasets/{id}/activ |
                      |  - DELETE /api/v1/datasets/{id}?conf= |
                      |  - POST   /api/v1/datasets/reset-demo |
                      +---------+-------------------+---------+
                                |                   |
                 +--------------+                   +-------------+
                 v                                                v
+-----------------------------------+             +-----------------------------------+
|     DatasetManager (SQLite)       |             |        Dual Graph Engine          |
|  - Table: app_datasets            |             |  - NetworkX In-Memory Store       |
|  - ACID Metadata Registry         |             |  - Neo4j AuraDB Parameterized     |
|  - Active Dataset State Tracking  |             |  - Scoped Cypher Deletion         |
+-----------------------------------+             +-----------------------------------+
```

### 2.1 Core Safety Invariant: Never `MATCH (n) DETACH DELETE n`
Under no circumstances does SafeContain AI execute global unconstrained deletions. All deletions are mathematically scoped by `dataset_id`. Unrelated datasets, baseline assets, and demo scenarios (`DEMO-SCEN-001`) remain completely preserved.

---

## 3. Implementation Details Across Phases

### Phase 1: Database Registry — `app_datasets` Table
Created `backend/app/ingestion/dataset_manager.py` implementing `DatasetManager` and `DatasetMetadata` backed by ACID-compliant SQLite (`safecontain_app.db`):

```sql
CREATE TABLE IF NOT EXISTS app_datasets (
    dataset_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source_filename TEXT NOT NULL,
    source_type TEXT NOT NULL,
    node_count INTEGER DEFAULT 0,
    edge_count INTEGER DEFAULT 0,
    node_ids TEXT,
    edge_ids TEXT,
    is_active INTEGER DEFAULT 0,
    is_demo INTEGER DEFAULT 0,
    uploaded_at TEXT NOT NULL,
    neo4j_synced INTEGER DEFAULT 0,
    neo4j_status TEXT DEFAULT 'OFFLINE_FALLBACK',
    description TEXT
);
```

### Phase 2: Domain Entity Model Enhancement
Updated `backend/app/models/domain.py`:
- `GraphNode`: Added `dataset_id: Optional[str]`, `source_file: Optional[str]`, `ingestion_batch_id: Optional[str]`, and `is_demo: bool = False`.
- `GraphEdge`: Added `dataset_id: Optional[str]`, `source_file: Optional[str]`, `ingestion_batch_id: Optional[str]`, and `is_demo: bool = False`.

### Phase 3: Graph Engine Ingestion & Scoped Deletion
Updated `backend/app/graph/engine.py`:
1. **Schema Indexes:** Added indexes on `:Asset(dataset_id)` and `:Entity(dataset_id)` in Neo4j Aura for sub-millisecond scoped lookups.
2. **Entity Persistence:** Parameterized Cypher queries (`sync_to_neo4j`, `create_or_update_node_in_neo4j`, `create_or_update_edge_in_neo4j`) explicitly tag nodes and edges with `dataset_id`, `source_file`, `ingestion_batch_id`, and `is_demo`.
3. **Scoped Deletion Implementation (`delete_dataset_scoped`):**
   Executes four deterministic parameterized Cypher statements in transaction:
   - Step 3a: Delete relationships belonging to the dataset:  
     `MATCH ()-[r {dataset_id: $dataset_id}]->() DELETE r`
   - Step 3b: Delete incident outgoing relationships from dataset nodes:  
     `MATCH (n {dataset_id: $dataset_id})-[r]->() DELETE r`
   - Step 3c: Delete incident incoming relationships to dataset nodes:  
     `MATCH ()-[r]->(n {dataset_id: $dataset_id}) DELETE r`
   - Step 3d: Delete the nodes belonging strictly to the dataset:  
     `MATCH (n {dataset_id: $dataset_id}) DELETE n`
   - Step 3e: Purge corresponding entities from active in-memory NetworkX dictionaries (`_node_store`, `_edge_store`, `_nx_graph`).
4. **Scoped Topology Export (`export_topology`):**
   `export_topology(dataset_id: Optional[str] = None)` scopes returned nodes and edges strictly to the requested or active dataset.

### Phase 4: Ingestion Pipeline & Adapters
1. **Generic CSV Ingestion (`backend/app/ingestion/service.py`):**
   - Automatically generates a unique `dataset_id` (format: `ds-<12_hex_chars>`).
   - Propagates `dataset_id` to all created `GraphNode` and `GraphEdge` objects.
   - Registers the completed ingestion in `DatasetManager` as `is_active=True`.
   - Returns `dataset_id` in `CSVIngestionSummary`.
2. **CIC-IDS2017 Flow Adapter (`backend/app/ingestion/cic_ids_adapter.py`):**
   - Accepts `dataset_id` in `process_records`.
   - Tags all asset nodes (`src_id`, `dst_id`) and aggregated flow edges with `dataset_id`.
   - Returns lists of `created_node_ids` and `created_edge_ids`.
3. **Synthetic Demo Loader (`backend/app/ingestion/synthetic_enterprise_loader.py`):**
   - Tags all demo nodes and edges with `dataset_id="DEMO-SCEN-001"` and `is_demo=True`.
   - Registers the baseline demo dataset in `DatasetManager`.

### Phase 5: REST API Endpoints (`backend/app/api/v1/router.py`)

| Method | Endpoint | RBAC Required | Description |
|---|---|---|---|
| `GET` | `/api/v1/datasets` | `VIEWER` | List all registered datasets with metadata, entity counts, and active status. |
| `GET` | `/api/v1/datasets/active` | `VIEWER` | Retrieve metadata of currently active dataset, or null if empty. |
| `POST` | `/api/v1/datasets/{id}/activate` | `ANALYST` | Switch the active dataset for topology and risk visualization. |
| `DELETE` | `/api/v1/datasets/{id}?confirm=true` | `ADMIN` | Permanently deletes dataset entities from Neo4j Aura and memory. Requires `confirm=true`. |
| `POST` | `/api/v1/datasets/reset-demo` | `ADMIN` | Restores baseline enterprise demo scenario (`SCEN-001`) into graph and Neo4j. |
| `GET` | `/api/v1/graph/topology?dataset_id=...` | `VIEWER` | Returns topology scoped to active dataset. If all datasets are deleted, returns genuine empty graph. |

### Phase 6: Frontend UI/UX Integration (`frontend/src/App.tsx`)
1. **Dynamic Datasets Lifecycle Table:**  
   Rendered in the *Data Connectors (Integrations)* view, displaying Dataset ID, Name/Source, Type, Entity Counts, Timestamp, Status badge (`ACTIVE` vs `INACTIVE`), and action buttons (`Activate`, `Delete`).
2. **Confirmation Modal for Deletion:**  
   Clicking Delete opens an explicit confirmation dialog detailing the targeted Cypher impact on Neo4j AuraDB before execution.
3. **Synchronized File Removal ("X" Button):**  
   Clicking the file removal "X" button prompts the user if they wish to delete the ingested dataset from Neo4j AuraDB.
4. **Active Dataset Context Banner:**  
   Rendered at the top of *Topology Explorer*, indicating the currently loaded dataset ID, source filename, node/edge counts, and a direct shortcut to Manage Datasets.
5. **Genuine Empty State:**  
   When all datasets are deleted, Topology Explorer displays:  
   *"No dataset currently loaded. Upload a CSV dataset to build and visualize your graph."* with instant action buttons to *Upload CSV Dataset* or *Restore Demo Graph (SCEN-001)*.

---

## 4. Neo4j Bloom Inspection Queries

To verify dataset isolation and Bloom synchronization directly in the Neo4j Browser or Neo4j Bloom console, execute the following Cypher queries:

### 4.1 Check All Active Datasets in Neo4j
```cypher
MATCH (n)
RETURN coalesce(n.dataset_id, 'UNTAGGED_LEGACY') AS dataset_id,
       n.is_demo AS is_demo,
       count(n) AS node_count
ORDER BY node_count DESC;
```

### 4.2 Inspect Entities for a Specific Dataset
```cypher
MATCH (n {dataset_id: 'ds-5a4359cccb'})-[r]->(m {dataset_id: 'ds-5a4359cccb'})
RETURN n, r, m
LIMIT 100;
```

### 4.3 Verify Total Removal After Deletion
```cypher
MATCH (n {dataset_id: 'ds-5a4359cccb'})
RETURN count(n) AS remaining_stale_nodes;
// Must return 0
```

### 4.4 Verify Demo Graph Preservation
```cypher
MATCH (n {dataset_id: 'DEMO-SCEN-001'})
RETURN count(n) AS demo_node_count;
// Returns 35 nodes for baseline enterprise scenario
```

---

## 5. Automated Verification & Test Results

Two dedicated integration test suites were executed, verifying all requirements across both unit and end-to-end integration levels:

### 5.1 Dataset Lifecycle Test Suite (`test_neo4j_dataset_lifecycle.py`)
- **Test 1:** DatasetManager SQLite Registry CRUD & Active Switching (`PASSED`)
- **Test 2:** Ingestion Tags Entities with `dataset_id` and `source_file` (`PASSED`)
- **Test 3:** Multiple Datasets Coexist with Scoped Properties (`PASSED`)
- **Test 4:** Topology Scoped Export Filters by `dataset_id` (`PASSED`)
- **Test 5:** Scoped Deletion Preserves Unrelated Datasets (`PASSED`)
- **Test 6:** Demo Scenario Preservation During Ingested Dataset Deletion (`PASSED`)
- **Test 7:** Empty State Returned When All Datasets Deleted (`PASSED`)
- **Test 8:** REST API Deletion Confirmation Requirement (`confirm=true`) (`PASSED`)
- **Test 9:** REST API List, Active, and Activate Endpoints (`PASSED`)
- **Test 10:** Cryptographic Audit Ledger Records `DATASET_DELETED` Event (`PASSED`)
- **Test 11:** Reset Demo Scenario Restores `SCEN-001` with Demo Tagging (`PASSED`)

### 5.2 CIC-IDS2017 Ingestion Suite (`test_cic_ids2017_ingestion.py`)
- **Test A-L:** Header normalization, flow aggregation, non-destructive upsert, malformed row isolation, and truthful reporting (12/12 `PASSED`).

**Total Test Suite Result: 23 passed in 5.20s (100% Pass Rate).**

### 5.3 Frontend TypeScript Build Verification
```bash
npm --prefix frontend run build
```
Result: **Exit code 0**. Clean build with 1,574 modules transformed and 0 type errors.

---

## 6. Operator Guide

1. **Uploading Datasets:**
   Navigate to *Data Connectors* (`/integrations`). Select any network flow or entity CSV file. Click **Upload & Ingest**. The dataset is assigned a UUID, upserted to Neo4j Aura, and marked active.
2. **Switching Active Datasets:**
   In the *Dynamic Dataset Lifecycle* table, click **Activate** on any registered dataset. The Topology Explorer, Attack Paths, and Risk Analyzer instantly pivot to visualize that dataset.
3. **Deleting Datasets:**
   Click **Delete** next to any dataset in the table. Review the confirmation modal and click **Yes, Delete Dataset**. The nodes and edges are purged from memory and Neo4j AuraDB.
4. **Restoring Demo Scenario:**
   Click **Reset Demo (SCEN-001)** at any time to restore the benchmark enterprise demo graph.
