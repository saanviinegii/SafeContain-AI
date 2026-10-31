# SafeContain AI — Executive Pitch & Presentation Deck
## Smarter Threat Containment. Less Business Disruption.

**Author / Lead Architect:** Saanvi Negi  
**Project Repository & Prototype URL:** [https://github.com/saanviinegii/SafeContain-AI](https://github.com/saanviinegii/SafeContain-AI)  
**CI/CD Pipeline Status:** [Verified Green (`✔`)](https://github.com/saanviinegii/SafeContain-AI/actions)  

---

### Slide 1: SafeContain AI — Overview
**Smarter Threat Containment. Less Business Disruption.**

- **Maps connected risks and simulates responses** to guide better decisions.
- **Reveals attack paths and shows routes** that remain after containment action.
- **Considers business impact** to preserve critical workflows.
- **Creates tamper-evident records** of decisions and approvals.
- 🔗 **Interactive Prototype Link:** [https://github.com/saanviinegii/SafeContain-AI](https://github.com/saanviinegii/SafeContain-AI)

```
[Compromised Account] ──(Threat Route)──> [Server] ──(Blocked)──X   [Critical Database]
       │                                                                    ▲
       └───────────(Protected Route - Workflows Preserved)──────────────────┘
```

---

### Slide 2: The Problem
**A Blocked Attack Path Is Not Always a Contained Threat.**

- **Fragmented Visibility:** Alerts, accounts, devices, permissions, and assets are viewed as disconnected silos.
- **Incomplete Containment:** Blocking one attack path may leave alternative lateral routes completely open.
- **Operational Disruption:** Disabling shared accounts or services risks interrupting legitimate, mission-critical workflows.
- **The Core Challenge:** Reduce security risk *without* unnecessarily disrupting essential services.

---

### Slide 3: Our Proposed Solution
**Map. Analyse. Optimise. Verify.**

1. **MAP (Build Connected Security Graph):**
   Connect identities, devices, permissions, alerts, servers, assets, and service dependencies in a dual Neo4j / NetworkX graph engine.
2. **ANALYSE (Expose Residual Risk):**
   Identify possible multi-hop attack paths and label relationships with evidence status (`CONFIRMED`, `SUSPECTED`, `UNKNOWN`).
3. **OPTIMISE (Compare Safer Responses):**
   Compare candidate responses across Baseline Severity, Greedy Risk-per-Cost, and Google OR-Tools CP-SAT exact constraint optimization under SLA bounds.
4. **VERIFY (Explain, Protect & Evaluate):**
   Simulate responses on an immutable graph snapshot, recheck residual paths, estimate workflow impact, and present tamper-evident results for human review.

---

### Slide 4: How SafeContain AI Works
**Connected Data. Verified Decisions.**

| Component | Technology | Role & Function |
| :--- | :--- | :--- |
| **Security Data** | SIEM / EDR / IAM Connectors | Alerts, identities, devices, permissions, critical assets |
| **API + Graph** | FastAPI / Pydantic / Neo4j / NetworkX | Dual engine graph querying & topological modeling |
| **Path Analysis** | Python NetworkX Dijkstra Traversal | Multi-hop attack paths & baseline risk calculation |
| **Response Planner** | Action Catalog | Candidate action synthesis & cost/disruption estimation |
| **Simulate + Verify** | Isolated Snapshot Engine | Non-destructive simulation & residual path re-check |
| **Compare** | CP-SAT & Strategy Comparator | Multi-objective tradeoff ranking & SLA constraint checking |
| **Dashboard UI** | React / TypeScript / Cytoscape.js | Topology exploration, risk breakdown, and evidence view |
| **Governance & Audit** | ChainedAuditLedger | SHA-256 sequential cryptographic integrity chain |

---

### Slide 5: Research Gap and Validation
**From Suggested Actions to Measurable Outcomes.**

| Existing Challenge | SafeContain AI Approach | Intended Contribution |
| :--- | :--- | :--- |
| **Fragmented security relationships** | Dual Neo4j graph modeling | Clearer visibility of multi-hop attack paths |
| **Alternative routes remain open** | Simulate and recheck residual paths | Identify residual attack paths post-action |
| **Response actions disrupt services** | Workflow-constrained planning | Evaluate security-continuity trade-offs |
| **Incomplete or uncertain evidence** | 5-state epistemic uncertainty model | Make evidence assumptions explicit |
| **Decisions are hard to audit** | SHA-256 hash-chained tamper ledger | Cryptographically detect changes to records |

---

### Slide 6: Demonstration and Expected Impact
**Test the Response Before You Trust It.**

- **Response Workflow:** `Detect` $\to$ `Map` $\to$ `Plan` $\to$ `Simulate` $\to$ `Verify` $\to$ `Compare` $\to$ `Human Review` $\to$ `Audit`
- **Simulate:** Compare outcomes across effectiveness, workflows, cost, and residual risk before executing interventions.
- **Human Review:** Reviewer examines evidence and approves or rejects the recommended plan (`FOUR_EYES` governance).
- **Audit Integrity:** Selected records are sequentially hashed and timestamped for regulatory compliance.

> **Contain threats intelligently. Preserve essential workflows. Make decisions auditable.**

---

### 🌐 Official Links for Submission & Demonstration

- **GitHub Project Repository:** [https://github.com/saanviinegii/SafeContain-AI](https://github.com/saanviinegii/SafeContain-AI)
- **Automated CI/CD Pipeline:** [https://github.com/saanviinegii/SafeContain-AI/actions](https://github.com/saanviinegii/SafeContain-AI/actions)
- **Local Prototype Dashboard:** `http://localhost:5173` (Launch with `start_evaluation.bat` / `start_evaluation.sh`)
- **Interactive REST API & OpenAPI Docs:** `http://localhost:8000/docs`
