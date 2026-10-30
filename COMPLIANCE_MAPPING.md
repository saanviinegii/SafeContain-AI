# REGULATORY & COMPLIANCE MAPPING SPECIFICATION
## SafeContain AI — Government of India & Global Cybersecurity Standards
**Document Version:** 1.0.0  
**Frameworks Evaluated:** CERT-In, DPDP Act 2023, MeitY, ISO 27001, ISO 22301, NIST CSF 2.0  

---

## 1. Compliance Traceability Matrix

| Requirement / Standard | Applicability | Security Control | Platform Implementation | Evidence / Verification | Implementation Gap / Next Step |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CERT-In Direction 2022 (Sec 70B)** | Mandatory for Indian enterprise & gov SOCs | 6-hour incident logging, NTP time sync, retention of logs for 180 days | Sequential SHA-256 chained audit ledger recording timestamped incident responses in UTC | Verified in `test_audit_event_hash_chain` and `test_chained_audit_ledger_tamper_detection` | Requires external secure Syslog forwarding to remote CERT-In SIEM sink. |
| **DPDP Act 2023 (Digital Personal Data)** | Mandatory for citizen-facing registries | Protection against unauthorized access / processing of citizen personal data | Strict role-based isolation, masking of PII, and non-destructive containment planning | Verified in `test_governance_unauthorized_permission_denial` | Formal Data Protection Officer (DPO) consent workflow integration. |
| **MeitY & GIGW Guidelines** | Government-facing web portals | Zero unauthenticated remote execution, accessible UI typography, robust error handling | Frontend console built with semantic HTML5, WCAG accessible colors, zero raw Cypher exposure | Verified in `test_health_and_security_headers` and frontend production build | Third-party STQC security audit certification pending. |
| **ISO 27001:2022 (A.8.16, A.8.25)** | Enterprise ISMS certification | Monitoring activities, secure system engineering, separation of development/prod | Dual-engine graph separation, input sanitization middleware, automated test gates | Verified in `test_security_headers_verification` | Formal production ISO certification audit. |
| **ISO 22301:2019 (Business Continuity)** | Enterprise resilience & disaster recovery | Business impact analysis (BIA), maximum tolerable period of disruption (MTPD) | Business Continuity Twin modeling citizen services with hard 0.0h downtime constraints | Verified in `test_business_twin_dependency_discovery` and `test_action_disruption_evaluation` | Integration with live CMDB auto-discovery. |
| **NIST SP 800-61r3 (Incident Response)** | Incident handling & containment | Coordinated containment, eradicate threat without business collapse | Tri-level optimization (CP-SAT) prioritizing risk reduction under operational budget | Verified in `test_optimization_strategies_comparison` | Automated playbook integration via SOAR connectors. |
| **NIST SP 800-207 (Zero Trust)** | Identity & access containment | Dynamic risk evaluation, microsegmentation, least privilege enforcement | Action catalog modeling microsegmentation rules, session revocations, MFA enforcement | Verified in `test_action_catalog_generation` | Dynamic policy push to physical SDN switches. |
