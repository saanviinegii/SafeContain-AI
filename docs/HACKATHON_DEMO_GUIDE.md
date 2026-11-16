# SafeContain AI — 5-Minute Hackathon Demonstration Script & Guide

## 1. Value Proposition (30 Seconds Pitch)

> *"In enterprise cybersecurity, containment is a high-stakes balancing act. Over-containment shuts down revenue and citizen services, while under-containment leads to catastrophic ransomware extortion.*
>
> *SafeContain AI introduces **Uncertainty-Aware Cyber Threat Containment with Business Continuity and Tamper-Evident Dual Audit**.*
>
> *Unlike naive SOAR bots that blindly pull network cables, SafeContain AI models lateral attack paths, factors in forensic uncertainty, protects mission-critical business workflows via Google OR-Tools CP-SAT, simulates outcomes in an isolated digital twin, anchors all decisions to an immutable blockchain ledger, and strictly requires human authorization before execution."*

---

## 2. Live Demo Script (Step-by-Step across the 19 Views)

### Minute 1: The Incident & Topology (Views 1, 2, 3)
1. **Executive Overview (View 1)**:
   - Highlight the banner: Threat Level **CRITICAL**, Inherent Risk **88/100**, and the dual monitored citizen workflows (`wf-national-identity-auth` and `wf-payment-clearing-switch`).
2. **Topology Explorer (View 3)**:
   - Point out the Cytoscape.js interactive graph showing servers, users, permissions, alerts, and the crown jewel database.
   - Explain the color coding: Orange for compromised nodes, Purple for suspected lateral links, Blue for confirmed links.

### Minute 2: Attack Path Analysis & Evidence Uncertainty (Views 4, 5, 7)
3. **Attack Paths (View 4)**:
   - Show that there are **3 distinct attack routes** leading from the external gateway to the crown jewel database.
   - Highlight that Path #1 exploits a suspected lateral link with an uncertainty penalty.
4. **Evidence & Uncertainty (View 5)**:
   - Explain how evidence confidence decays over time using our Bayesian temporal formula:
     $$c(t) = c_0 \cdot e^{-\lambda t}$$
5. **Risk Analysis (View 7)**:
   - Demonstrate the transparent risk decomposition: Inherent Risk (88.0) vs Observed Risk (72.5) vs Potential Risk (95.0).

### Minute 3: Business Continuity & Optimization (Views 8, 9, 10)
6. **Business Continuity Twin (View 8)**:
   - Show how the database supports both the National Identity Gateway and the Payment Clearing Switch.
   - Crucial point: If we simply isolate the database, we cause \$150,000/hr in citizen service downtime.
7. **Strategy Comparator (View 10)**:
   - Compare the three strategies:
     - **Severity Baseline**: High risk reduction but causes unacceptable Tier-1 business workflow outages.
     - **Greedy Baseline**: Quick, but gets trapped in local optima and violates budget limits.
     - **Google OR-Tools CP-SAT (SafeContain AI)**: Mathematically maximizes risk reduction while strictly guaranteeing **zero outage** for Tier-1 services and respecting budget limits.

### Minute 4: Isolated Simulation & What-If Sandbox (Views 11, 12, 13)
8. **Simulation Sandbox (View 11)**:
   - Click **Run Isolated Simulation**.
   - Show that the base graph topology in Neo4j is **unaltered** (immutable snapshot).
   - Point out the Residual Risk dropping from 88 to under 15, with 0 residual attack paths.
9. **Decision Explainer (View 13)**:
   - Walk through the 7-part mathematical explanation:
     - Justification for chosen actions.
     - Counterfactual analysis: why isolating the database was rejected.
     - Explicit model assumptions.
     - Pre/post verification steps.
     - Action rollback and contingency procedures.

### Minute 5: Governance & Blockchain Audit Verification (Views 14, 15, 19)
10. **Approval Center (View 14)**:
    - Demonstrate our strict Human-in-the-Loop Governance:
      - As `SOC_ANALYST`, click "Submit for Manager Review" ($\to$ `PENDING_APPROVAL`).
      - Switch role to `SECURITY_MANAGER` in View 17, and click "Approve Containment Plan" ($\to$ `APPROVED`).
      - Explain that lower roles cannot self-approve (enforced via HTTP 403 Forbidden).
11. **Audit Explorer & Blockchain Verification (View 15)**:
    - Show the audit ledger table featuring the SHA-256 hash chain.
    - Highlight the **Smart Contract Anchor (`SafeContainAuditLedger.sol`)**.
    - Click **Verify On-Chain**: show the instant check recomputing the off-chain record hash and confirming a 100% cryptographic match against the on-chain anchored hash.
12. **Reports Export (View 19)**:
    - Click "Export Complete JSON Dossier" or "Export Executive Text Briefing" to show the generated audit artifact.

---

## 3. High-Impact Answers to Panelist Questions

**Q1: How does SafeContain AI avoid hallucinated or fabricated containment actions?**
> *"Every candidate action is generated deterministically by `ActionCatalog` from active graph choke points. Every optimization score is computed via Google OR-Tools CP-SAT constraint programming, and outcomes are mathematically verified in an isolated NetworkX digital twin. We use zero black-box LLM decision execution."*

**Q2: What happens if an organization does not have a live Neo4j Aura or Ethereum blockchain setup?**
> *"SafeContain AI is designed with an enterprise Dual Engine. It automatically connects to live Neo4j Aura and EVM testnets when credentials are provided, but provides full in-memory NetworkX graph processing and permissioned SHA-256 ledger verification when offline. Zero crash, zero downtime."*

**Q3: Why not execute the containment actions automatically via API?**
> *"Automated destructive actions without human verification pose immense operational and legal risk (e.g., disconnecting hospital or payment switches). SafeContain AI adheres strictly to the CISA and CERT-In human-in-the-loop mandate: the system recommends and simulates, but an authorized human commander must review and sign off."*
