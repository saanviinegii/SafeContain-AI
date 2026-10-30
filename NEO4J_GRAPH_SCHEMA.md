# NEO4J GRAPH SCHEMA SPECIFICATION
## SafeContain AI — GraphOps Infrastructure Model
**Document Version:** 1.0.0  
**Target Graph Engine:** Neo4j 5.20+ (Enterprise / Community)  

---

## 1. Node Labels & Primary Keys

| Node Label | Key Identifier | Description | Key Attributes |
| :--- | :--- | :--- | :--- |
| `:Host` / `:Server` / `:Endpoint` | `id` (e.g. `srv-ad-dc01`) | Compute systems, workstations, and perimeter servers | `name`, `criticality`, `is_compromised`, `is_crown_jewel`, `os`, `provenance` |
| `:Database` | `id` (e.g. `db-citizen-identity-prod`) | Databases and high-value data stores | `name`, `criticality`, `is_crown_jewel`, `records_count`, `provenance` |
| `:User` / `:PrivilegedIdentity` | `id` (e.g. `usr-admin-rajesh`) | Active Directory & IAM user accounts | `name`, `criticality`, `is_compromised`, `privilege`, `mfa_enabled` |
| `:Threat` / `:Incident` | `id` (e.g. `ext-attacker-c2`) | External adversaries, malware, or detected C2 | `name`, `threat_actor`, `criticality`, `ip_address` |
| `:BusinessWorkflow` | `id` (e.g. `wf-citizen-auth-service`) | Citizen portals, ERP, and payment workflows | `name`, `criticality_tier`, `citizen_facing`, `hourly_downtime_cost`, `max_allowable_downtime_hours` |

---

## 2. Relationship Types & Edge Attributes

| Relationship Type | Source $\to$ Target | Semantic Meaning | Attributes |
| :--- | :--- | :--- | :--- |
| `CONNECTED_TO` | `:Host` $\to$ `:Host` | Network layer reachability / routing | `id`, `evidence_status`, `confidence`, `weight`, `is_active`, `provenance` |
| `AUTHENTICATES_TO` | `:User` $\to$ `:Host` | Identity logon session or credential reuse | `id`, `evidence_status`, `confidence`, `weight`, `is_active` |
| `HAS_ACCESS_TO` | `:PrivilegedIdentity` $\to$ `:Host`/`:Database` | Administrative privileges or ACL grant | `id`, `evidence_status`, `confidence`, `weight`, `is_active` |
| `SUPPORTS_WORKFLOW` | `:Database`/`:Server` $\to$ `:BusinessWorkflow` | Direct operational dependency | `id`, `evidence_status`, `confidence`, `weight` |
| `EXPOSED_TO` | `:Threat` $\to$ `:Host` | Active compromise / exploit vector | `id`, `evidence_status`, `confidence` |
| `OBSERVED_IN` | `:Host` $\to$ `:Threat` | Detection telemetry observation | `id`, `evidence_status`, `confidence` |

---

## 3. Cypher DDL Constraints & Index Creation

```cypher
// 1. Uniqueness Constraints
CREATE CONSTRAINT c_host_id IF NOT EXISTS FOR (h:Host) REQUIRE h.id IS UNIQUE;
CREATE CONSTRAINT c_server_id IF NOT EXISTS FOR (s:Server) REQUIRE s.id IS UNIQUE;
CREATE CONSTRAINT c_endpoint_id IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.id IS UNIQUE;
CREATE CONSTRAINT c_database_id IF NOT EXISTS FOR (d:Database) REQUIRE d.id IS UNIQUE;
CREATE CONSTRAINT c_user_id IF NOT EXISTS FOR (u:User) REQUIRE u.id IS UNIQUE;
CREATE CONSTRAINT c_priv_user_id IF NOT EXISTS FOR (p:PrivilegedIdentity) REQUIRE p.id IS UNIQUE;
CREATE CONSTRAINT c_workflow_id IF NOT EXISTS FOR (w:BusinessWorkflow) REQUIRE w.id IS UNIQUE;
CREATE CONSTRAINT c_threat_id IF NOT EXISTS FOR (t:Threat) REQUIRE t.id IS UNIQUE;

// 2. High-Performance Traversal Indexes
CREATE INDEX idx_host_compromised IF NOT EXISTS FOR (h:Host) ON (h.is_compromised);
CREATE INDEX idx_host_crown_jewel IF NOT EXISTS FOR (h:Host) ON (h.is_crown_jewel);
CREATE INDEX idx_database_crown_jewel IF NOT EXISTS FOR (d:Database) ON (d.is_crown_jewel);
CREATE INDEX idx_workflow_citizen IF NOT EXISTS FOR (w:BusinessWorkflow) ON (w.citizen_facing);

// 3. Directed Path Discovery Cypher Query
MATCH path = (src:Threat)-[*1..6]->(target)
WHERE (target.is_crown_jewel = true OR target:Database)
RETURN path, 
       [r IN relationships(path) | r.confidence] AS confidences,
       [r IN relationships(path) | r.evidence_status] AS statuses;
```
