# BUSINESS CONTINUITY DIGITAL TWIN MODEL
## SafeContain AI — Workflow Dependency and Operational Impact Engine
**Document Version:** 1.0.0  

---

## 1. Mission-Critical Operational Workflows

SafeContain AI establishes a bidirectional dependency twin between IT infrastructure nodes and business processes:

- **Tier-1 (Mission Critical):** Citizen digital identity, Aadhaar/DigiLocker portals, emergency dispatch, real-time RTGS payment settlement.  
  *SLA Downtime Tolerance:* **0.0 Hours** (Zero Outage Mandate).
- **Tier-2 (Business Critical):** Core ERP, customer service desk, billing batch jobs.  
  *SLA Downtime Tolerance:* 2.0 to 4.0 Hours.
- **Tier-3 (Operational):** Internal reporting, developer CI/CD pipelines.  
  *SLA Downtime Tolerance:* 12.0 to 24.0 Hours.
- **Tier-4 (Non-Critical):** Long-term data archiving, telemetry mirror sinks.

---

## 2. Dependency Discovery & Disruption Calculation

### 2.1 Graph Discovery
The twin engine queries edges of type `SUPPORTS_WORKFLOW`:
$$(\text{Asset:Server | Database}) \xrightarrow{\text{SUPPORTS\_WORKFLOW}} (\text{Workflow:BusinessWorkflow})$$

### 2.2 Financial & SLA Blast Radius
For each containment action $a$:
1. **Direct Dependency:** Target node $a.\text{target\_id} \in \text{Workflow}.\text{dependent\_assets}$.
2. **Indirect Dependency:** Target node is an immediate upstream network dependency of a supporting asset.
3. **Financial Impact:**
   $$\text{FinancialLoss}(w) = \text{DowntimeHours}(a) \times \text{HourlyCost}(w)$$
4. **SLA Violation:**
   $$\text{ViolatesSLA}(w) = (\text{DowntimeHours}(a) > \text{MaxDowntime}(w))$$
