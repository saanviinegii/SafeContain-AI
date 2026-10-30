# SECURITY THREAT MODEL SPECIFICATION (STRIDE)
## SafeContain AI — Enterprise Security & Penetration Hardening
**Document Version:** 1.0.0  

---

## 1. STRIDE Threat Analysis & Mitigations

| STRIDE Category | Threat Vector | Platform Vulnerability Risk | Implemented Countermeasure | Verification Test |
| :--- | :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker impersonates SOC Analyst or Admin | Unauthorized plan authorization | JWT authentication, role verification, and audit actor binding | `test_role_escalation_denial` |
| **Tampering** | Rogue DBA alters audit log to hide compromised paths | Historical record fabrication | Cryptographic SHA-256 hash chaining with forward pointer verification | `test_chained_audit_ledger_tamper_detection` |
| **Repudiation** | Operator denies approving a disruptive containment plan | Lack of decision non-repudiation | Immutable audit block containing actor ID, role, timestamp, and notes | `test_governance_lifecycle_valid_path` |
| **Information Disclosure** | Graph topology leakage via API error dumps | Infrastructure reconnaissance | Secure exception handling, sanitized error details, and CORS origin filtering | `test_health_and_security_headers` |
| **Denial of Service** | CP-SAT solver exhaustion via massive graph cycles | Application freeze / OOM | Solver execution timeout bounded to 5.0s, graph cutoff depth of 7 hops | `test_cpsat_solver_scalability` |
| **Elevation of Privilege** | Cypher injection in query search inputs | Remote graph deletion / data exfiltration | Regex AST filter rejecting `MATCH`, `DROP`, `DELETE`, `MERGE`, `--` | `test_cypher_injection_sanitization` |

---

## 2. Mandatory Network Boundaries

- Internal communication between Web Console and FastAPI API is proxied through Nginx on Port 80/443.
- Neo4j Bolt port 7687 and PostgreSQL port 5432 are isolated within a private Docker/Kubernetes bridge network, never exposed to external public interfaces.
