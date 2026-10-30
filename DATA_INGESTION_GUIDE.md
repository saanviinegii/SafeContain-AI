# DATA INGESTION & CONNECTOR GUIDE
## SafeContain AI — Telemetry Integration Manual
**Document Version:** 1.0.0  

---

## 1. Supported Telemetry Feeds

SafeContain AI provides normalized, validated ingestion connectors for:
1. **SIEM Platforms (Splunk, Elastic, Syslog):** Normalized security alerts, event timestamps, MITRE ATT&CK techniques, source/destination host addresses.
2. **EDR/XDR Platforms (CrowdStrike Falcon, Microsoft Defender):** Device agents, active detections, host isolation status, logged-in identities.
3. **IAM & Directories (Active Directory, Azure AD, Okta):** User accounts, domain admin privileges, role-based resource access lists.
4. **Cloud Infrastructure (AWS, Azure, GCP):** VPCs, subnets, database clusters, compute instances.
5. **Synthetic Scenario Generator:** Calibrated multi-tier test scenarios labeled strictly as `DataProvenance.SYNTHETIC`.

---

## 2. Ingestion Contracts & Data Formats

### 2.1 SIEM Connector Payload
```json
[
  {
    "alert_id": "ALERT-9921",
    "source_ip": "10.0.1.15",
    "dest_ip": "10.0.2.50",
    "threat_name": "Pass-the-Hash Lateral Movement",
    "severity_score": 0.88,
    "mitre_id": "T1550.002"
  }
]
```

### 2.2 EDR Connector Payload
```json
[
  {
    "agent_id": "CS-AGT-4402",
    "hostname": "prod-billing-worker-01",
    "active_detections": true,
    "os": "Ubuntu 24.04",
    "logged_in_user": "svc_billing_batch"
  }
]
```

### 2.3 Deduplication & Error Handling
- **SHA-256 Event Fingerprinting:** Records are hashed canonically. Identical alerts submitted across sync cycles are skipped with `duplicates_skipped` counter increments.
- **Malformed Record Isolation:** If a record lacks a mandatory primary key (e.g. `alert_id` or `agent_id`), it is routed to an `IngestionError` log without aborting the entire batch.
- **Provenance Attribution:** All ingested entities inherit the connector's provenance tag (`LIVE_TELEMETRY` vs `SYNTHETIC`).
