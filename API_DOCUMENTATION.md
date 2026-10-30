# API DOCUMENTATION SPECIFICATION (v1)
## SafeContain AI — RESTful Interface Catalog
**Base URL:** `http://localhost:8000/api/v1`  
**Interactive Docs:** `http://localhost:8000/docs` (Swagger UI) & `http://localhost:8000/redoc` (ReDoc)  

---

## 1. Endpoints Overview

| HTTP Method | Route | Description | Auth / Role Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Liveness & readiness probe | Public |
| `GET` | `/metrics` | Real-time platform & solver telemetry | Public / Prometheus |
| `POST`| `/scenario/load-synthetic` | Ingests synthetic enterprise incident scenario | `SOC_ANALYST`+ |
| `GET` | `/graph/topology` | Returns complete normalized graph topology | `READ_ONLY_VIEWER`+ |
| `GET` | `/graph/attack-paths` | Discovers directed attack paths & choke points | `READ_ONLY_VIEWER`+ |
| `GET` | `/evidence/sensitivity` | Evaluates evidence drift sensitivity scenarios | `SOC_ANALYST`+ |
| `GET` | `/risk/decompose` | Returns decomposed multi-factor risk profile | `READ_ONLY_VIEWER`+ |
| `GET` | `/business/workflows` | Returns registered business continuity workflows | `READ_ONLY_VIEWER`+ |
| `GET` | `/planning/candidates` | Synthesizes candidate containment actions | `INCIDENT_RESPONDER`+ |
| `POST`| `/planning/optimize` | Executes tri-level response optimization comparison | `INCIDENT_RESPONDER`+ |
| `POST`| `/simulation/run` | Executes isolated snapshot simulation & residual path check | `INCIDENT_RESPONDER`+ |
| `GET` | `/explanation/recommendation` | Returns grounded mathematical decision justification | `READ_ONLY_VIEWER`+ |
| `POST`| `/governance/transition` | Transitions containment plan approval state machine | Role Enforced |
| `GET` | `/audit/ledger` | Lists cryptographically chained audit events | `AUDITOR`+ |
| `GET` | `/audit/verify` | Executes forward cryptographic SHA-256 verification | `AUDITOR`+ |
| `GET` | `/reports/export` | Exports incident report in JSON, CSV, or Text format | `SECURITY_MANAGER`+ |

---

## 2. Sample Payloads

### POST `/planning/optimize`
```json
{
  "budget_limit": 10000.0,
  "strategy": "CONSTRAINT_CPSAT"
}
```

### POST `/governance/transition`
```json
{
  "target_status": "APPROVED",
  "actor_id": "sec-manager-rajesh",
  "actor_role": "SECURITY_MANAGER",
  "notes": "Verified residual risk is below 45% and no citizen SLA outages incurred."
}
```
