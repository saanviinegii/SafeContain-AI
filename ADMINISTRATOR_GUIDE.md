# SYSTEM ADMINISTRATOR GUIDE
## SafeContain AI — Platform Administration, Secrets & Maintenance
**Document Version:** 1.0.0  

---

## 1. System Administration Operations

### 1.1 Managing Environment Variables & Secrets
SafeContain AI strictly adheres to Non-Negotiable Principle #16 (zero committed secrets). Configuration is managed via `.env` or system environment variables:
- `SECRET_KEY`: Minimum 32-character high-entropy secret for API tokens.
- `NEO4J_PASSWORD`: Production password for Neo4j Bolt connection.
- `DATABASE_URL`: Connection string for PostgreSQL metadata storage.

### 1.2 Monitoring Telemetry & Health Checks
The platform exposes Prometheus metrics at `/api/v1/metrics`:
- `uptime_seconds`: Process runtime.
- `active_graph_nodes` & `active_graph_edges`: Scale of active memory graph.
- `cpsat_last_runtime_ms`: Latency of the mathematical solver.
- `audit_chain_length` & `last_audit_verification_valid`: Integrity health of the audit chain.

### 1.3 Verifying Audit Integrity via CLI
Administrators can execute an on-demand audit check directly via Python:
```bash
python -c "from backend.app.audit.ledger import ChainedAuditLedger; l = ChainedAuditLedger(); print(l.verify_integrity())"
```
If any record hash mismatch is detected, the command immediately returns `is_valid: False` with the tampered record index.
