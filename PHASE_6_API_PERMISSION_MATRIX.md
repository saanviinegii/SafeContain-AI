# SafeContain AI — Phase 6 Complete API Permission Matrix

**Classification Standard:** Role-Based Access Control (RBAC)  
**Tiers:**
- **Public:** No authentication header required.
- **VIEWER+:** Valid JWT bearer token required. Roles: `VIEWER`, `ANALYST`, `ADMIN`.
- **ANALYST+:** Valid JWT bearer token required. Roles: `ANALYST`, `ADMIN`.
- **ADMIN:** Valid JWT bearer token required. Role: `ADMIN` only.

---

| HTTP Method | Endpoint Path | Function / Purpose | Authentication | Required Role | Expected Unauthorized (No/Invalid Token) | Expected Forbidden (Insufficient Role) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **GET** | `/api/v1/health` | Deployment & cluster health check | **Public** | None | N/A (200 OK) | N/A |
| **POST** | `/api/v1/auth/login` | Authenticate user & issue signed JWT | **Public** | None | 401 (Invalid credentials) | N/A |
| **GET** | `/api/v1/auth/me` | Fetch authenticated caller profile & role | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **POST** | `/api/v1/auth/users` | Administrative user account provisioning | Protected | **ADMIN** | 401 Unauthorized | 403 Forbidden |
| **GET** | `/api/v1/auth/users` | List all platform user accounts | Protected | **ADMIN** | 401 Unauthorized | 403 Forbidden |
| **PUT** | `/api/v1/auth/users/{user_id}/role` | Update user RBAC privilege role | Protected | **ADMIN** | 401 Unauthorized | 403 Forbidden |
| **PATCH** | `/api/v1/auth/users/{user_id}/status` | Activate or deactivate user account | Protected | **ADMIN** | 401 Unauthorized | 403 Forbidden |
| **GET** | `/api/v1/graph/diagnostic` | Neo4j Aura & cluster connection diagnostic | Protected | **ADMIN** | 401 Unauthorized | 403 Forbidden |
| **GET** | `/api/v1/metrics` | Real-time platform & SOC metrics | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/ingestion/connectors` | List registered telemetry ingest connectors | Authenticated | **ANALYST+** | 401 Unauthorized | 403 Forbidden |
| **POST** | `/api/v1/ingestion/siem` | Ingest live SIEM telemetry batches | Protected | **ANALYST+** | 401 Unauthorized | 403 Forbidden |
| **POST** | `/api/v1/ingestion/edr` | Ingest live EDR endpoint telemetry | Protected | **ANALYST+** | 401 Unauthorized | 403 Forbidden |
| **POST** | `/api/v1/ingest/csv` | Multipart CSV asset/edge graph upsert | Protected | **ADMIN** | 401 Unauthorized | 403 Forbidden |
| **POST** | `/api/v1/ingestion/csv` | Multipart CSV asset/edge graph upsert | Protected | **ADMIN** | 401 Unauthorized | 403 Forbidden |
| **POST** | `/api/v1/scenario/load-synthetic` | Re-initialize synthetic graph scenario | Protected | **ADMIN** | 401 Unauthorized | 403 Forbidden |
| **POST** | `/api/v1/scenario/load-demo` | Re-initialize demonstration scenario | Protected | **ADMIN** | 401 Unauthorized | 403 Forbidden |
| **GET** | `/api/v1/dataset/status` | Dataset catalog summary & statistics | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/dataset/validation` | Full data integrity validation report | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/dataset/scenarios` | List 10 pre-configured threat scenarios | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **POST** | `/api/v1/dataset/import` | Import synthetic enterprise dataset | Protected | **ADMIN** | 401 Unauthorized | 403 Forbidden |
| **POST** | `/api/v1/dataset/scenarios/{id}/load` | Load specific threat scenario | Protected | **ADMIN** | 401 Unauthorized | 403 Forbidden |
| **POST** | `/api/v1/dataset/reset` | Destructive reset & re-population of graph | Protected | **ADMIN** | 401 Unauthorized | 403 Forbidden |
| **GET** | `/api/v1/dataset/download/{filename}` | Download specific enterprise CSV | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/dataset/download-all` | Download complete dataset archive (ZIP) | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/dataset/assets` | Retrieve 35 enterprise server assets | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/dataset/users` | Retrieve 25 identity accounts | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/dataset/vulnerabilities` | Retrieve 45 known CVE vulnerabilities | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/dataset/alerts` | Retrieve 55 SOC security alerts | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/dataset/evidence` | Retrieve 65 forensic telemetry records | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/dataset/interventions` | Retrieve 45 candidate containment actions | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/dataset/dependencies` | Retrieve 60 cross-asset dependencies | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/dataset/business-impact` | Retrieve 35 business impact profiles | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/graph/topology` | Export normalized infrastructure topology | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/graph/attack-paths` | Compute directed multi-hop attack paths | Authenticated | **ANALYST+** | 401 Unauthorized | 403 Forbidden |
| **GET** | `/api/v1/graph/neo4j/status` | Live AuraDB connection & entity count status | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/graph/neo4j/statistics` | Label, edge type & certainty statistics | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **POST** | `/api/v1/graph/neo4j/sync` | Flush in-memory topology to Neo4j Aura | Protected | **ADMIN** | 401 Unauthorized | 403 Forbidden |
| **POST** | `/api/v1/graph/refresh` | Synchronize in-memory cache from Aura | Protected | **ADMIN** | 401 Unauthorized | 403 Forbidden |
| **POST** | `/api/v1/graph/neo4j/reload` | Synchronize in-memory cache from Aura | Protected | **ADMIN** | 401 Unauthorized | 403 Forbidden |
| **POST** | `/api/v1/graph/neo4j/load` | Synchronize in-memory cache from Aura | Protected | **ADMIN** | 401 Unauthorized | 403 Forbidden |
| **GET** | `/api/v1/evidence/sensitivity` | Evaluate risk drift under evidence drift | Authenticated | **ANALYST+** | 401 Unauthorized | 403 Forbidden |
| **GET** | `/api/v1/risk/decomposed` | Decomposed risk factor breakdown | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/risk/decompose` | Decomposed risk factor breakdown | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/business/workflows` | Business workflow digital twin status | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/planning/actions/candidates` | Candidate containment action catalog | Authenticated | **ANALYST+** | 401 Unauthorized | 403 Forbidden |
| **GET** | `/api/v1/planning/candidates` | Candidate containment action catalog | Authenticated | **ANALYST+** | 401 Unauthorized | 403 Forbidden |
| **POST** | `/api/v1/optimization/containment` | Solve CP-SAT containment optimization | Protected | **ANALYST+** | 401 Unauthorized | 403 Forbidden |
| **POST** | `/api/v1/optimization/compare` | Compare CP-SAT vs Greedy vs Baseline | Protected | **ANALYST+** | 401 Unauthorized | 403 Forbidden |
| **POST** | `/api/v1/planning/optimize` | Solve CP-SAT containment optimization | Protected | **ANALYST+** | 401 Unauthorized | 403 Forbidden |
| **POST** | `/api/v1/simulation/what-if` | Run isolated sandbox what-if simulation | Protected | **ANALYST+** | 401 Unauthorized | 403 Forbidden |
| **POST** | `/api/v1/simulation/run` | Run isolated sandbox what-if simulation | Protected | **ANALYST+** | 401 Unauthorized | 403 Forbidden |
| **GET** | `/api/v1/explanation/recommendation` | Decision explainer & counterfactuals | Authenticated | **ANALYST+** | 401 Unauthorized | 403 Forbidden |
| **POST** | `/api/v1/governance/transition` | Transition containment plan status | Protected | **ANALYST+** | 401 Unauthorized | 403 Forbidden |
| **GET** | `/api/v1/audit/ledger` | Query cryptographic audit trail | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/audit/verify` | Verify cryptographic hash chain integrity | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/audit/blockchain/status` | EVM smart contract anchor status | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **GET** | `/api/v1/audit/blockchain/records` | Query on-chain merkle anchored events | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
| **POST** | `/api/v1/audit/blockchain/verify` | Cryptographically verify on-chain hash | Protected | **ANALYST+** | 401 Unauthorized | 403 Forbidden |
| **GET** | `/api/v1/reports/export` | Export compliance incident reports | Authenticated | **VIEWER+** | 401 Unauthorized | N/A |
