# SafeContain AI — Neo4j AuraDB Integration & Setup Guide

## 1. Overview

SafeContain AI uses **Neo4j AuraDB** as its persistent enterprise graph database.
It stores the complete IT asset inventory, identity permissions, network topologies, detection alerts, and business workflow dependencies.

The backend features an enterprise-grade **Dual Engine Architecture**:
1. When configured with valid Neo4j Aura credentials, the application connects via the official `neo4j` Python driver over secure TLS (`neo4j+s://` or `bolt+s://`), establishes schema indexes and uniqueness constraints, and performs transactional CRUD.
2. In the absence of live cloud database credentials, the platform seamlessly falls back to the high-performance in-memory NetworkX engine, ensuring zero downtime, resilience during offline demonstrations, and predictable local development.

---

## 2. Neo4j Aura Instance Setup

1. Navigate to [Neo4j Aura Console](https://console.neo4j.io/).
2. Create an **AuraDB Free** or **AuraDB Professional** instance.
3. Download the generated credentials file containing your connection URI, username (`neo4j`), and password.
4. Set the database name (default is `neo4j`).

---

## 3. Environment Variables Configuration

In your project root `.env` file (or Render Cloud Environment Variables dashboard):

```bash
# Graph Engine Mode: 'neo4j' | 'dual' | 'in_memory'
GRAPH_BACKEND=neo4j

# Neo4j Aura Connection URI (Use neo4j+s for AuraDB TLS encryption)
NEO4J_URI=neo4j+s://your-instance-id.databases.neo4j.io

# Authentication Credentials
NEO4J_USER=neo4j
NEO4J_PASSWORD=YourSecureAuraPassword123!
NEO4J_DATABASE=neo4j

# Connection Lifecycle & Pool Management
NEO4J_MAX_CONNECTION_LIFETIME=3600
NEO4J_MAX_CONNECTION_POOL_SIZE=50
NEO4J_CONNECTION_TIMEOUT=5.0
```

---

## 4. Automatic Schema Constraints & Indexes

Upon startup or connectivity verification, SafeContain AI executes Cypher statements to establish uniqueness constraints and indexing for fast path-finding traversals:

```cypher
// Uniqueness constraints
CREATE CONSTRAINT node_id_uniq IF NOT EXISTS FOR (n:Node) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT server_id_uniq IF NOT EXISTS FOR (s:Server) REQUIRE s.id IS UNIQUE;
CREATE CONSTRAINT db_id_uniq IF NOT EXISTS FOR (d:Database) REQUIRE d.id IS UNIQUE;
CREATE CONSTRAINT user_id_uniq IF NOT EXISTS FOR (u:User) REQUIRE u.id IS UNIQUE;
CREATE CONSTRAINT threat_id_uniq IF NOT EXISTS FOR (t:Threat) REQUIRE t.id IS UNIQUE;
CREATE CONSTRAINT wf_id_uniq IF NOT EXISTS FOR (w:BusinessWorkflow) REQUIRE w.id IS UNIQUE;
CREATE CONSTRAINT device_id_uniq IF NOT EXISTS FOR (dev:Device) REQUIRE dev.id IS UNIQUE;
CREATE CONSTRAINT perm_id_uniq IF NOT EXISTS FOR (p:Permission) REQUIRE p.id IS UNIQUE;
CREATE CONSTRAINT alert_id_uniq IF NOT EXISTS FOR (a:Alert) REQUIRE a.id IS UNIQUE;

// Performance indexes
CREATE INDEX node_type_idx IF NOT EXISTS FOR (n:Node) ON (n.type);
CREATE INDEX edge_status_idx IF NOT EXISTS FOR ()-[r:RELATIONSHIP]-() ON (r.evidence_status);
```

---

## 5. Dedicated CRUD & Lifecycle Operations

The backend driver provides atomic transactions and lifecycle cleanup:
- `create_or_update_node_in_neo4j(node: GraphNode)`
- `get_node_from_neo4j(node_id: str)`
- `delete_node_from_neo4j(node_id: str)`
- `create_or_update_edge_in_neo4j(edge: GraphEdge)`
- `get_edge_from_neo4j(edge_id: str)`
- `delete_edge_from_neo4j(edge_id: str)`
- `get_database_statistics()`
- `close()`

### Database Statistics API

```http
GET /api/v1/graph/neo4j/statistics
```

**Sample Response:**
```json
{
  "neo4j_live": true,
  "status": "CONNECTED",
  "database": "neo4j",
  "total_nodes": 14,
  "total_relationships": 16,
  "label_counts": {
    "Server": 4,
    "Database": 1,
    "User": 2,
    "Device": 2,
    "Permission": 2,
    "Alert": 1,
    "BusinessWorkflow": 2
  },
  "schema_constraints_active": true
}
```

---

## 6. Real Database Non-Mocked Integration Test

To verify genuine connectivity to a live Neo4j Aura instance without mocks:

```powershell
# Set your real Aura credentials in your shell or .env
$env:NEO4J_URI = "neo4j+s://your-instance.databases.neo4j.io"
$env:NEO4J_USER = "neo4j"
$env:NEO4J_PASSWORD = "YourPassword"

# Run the real integration test
pytest tests/integration/test_neo4j_aura.py -v
```

**Test Workflow:**
1. Connects to real Neo4j Aura instance.
2. Creates an isolated test node `test-live-aura-probe-...`.
3. Creates a test relationship `CONNECTED_TO`.
4. Reads back the node and relationship from the database.
5. Verifies field persistence and evidence certainty score.
6. Performs atomic cleanup (`DETACH DELETE`), leaving the database clean.
7. If no live instance is available, the test cleanly skips with an explicit notice.
