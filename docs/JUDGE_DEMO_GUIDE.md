# SafeContain AI — Hackathon Judge Demonstration Script & Evaluation Guide

**Target Presentation Duration:** 5 to 7 Minutes  
**Primary Scenario:** `SCEN-001` (Operation Sovereign Gateway: Multi-Stage Lateral Movement)  
**Secondary Scenarios:** `SCEN-002` (BlackCat Ransomware Pre-Detonation), `SCEN-003` (Cloud Control Plane Hijack)

---

## 1. Executive Demonstration Narrative

> *"Judges, in an active cyber attack, SOC teams face an agonizing dilemma: if they isolate systems blindly, they crash multi-million dollar business workflows. If they do nothing, ransomware encrypts the crown jewels. SafeContain AI is the first graph-powered, uncertainty-aware cybersecurity decision-support platform that solves this dilemma. It pinpoints attack paths, mathematically balances risk reduction against business continuity using constraint optimization, simulates interventions non-destructively in an isolated graph, and proves decisions on a tamper-evident blockchain ledger."*

---

## 2. Step-by-Step 6-Minute Live Demo Flow

### Step 1: Scenario Ingestion & Infrastructure Health (Minute 0:00 - 0:45)
1. **Show Header Bar:** Point out the **Threat Scenario Selector** in the upper-right corner.
2. **Select Scenario:** Select **`SCEN-001: Operation Sovereign Gateway`**.
3. **Show Immediate Response:** The notification pops up:  
   *`Loaded scenario: Operation Sovereign Gateway (SCEN-001) - 120 nodes, 285 relationships`*.
4. **Click "Reset Graph" (if needed):** Demonstrate that clicking **"Reset Graph"** idempotently restores the clean enterprise baseline without restarting servers.
5. **Point to System Health Badge:** Show that the active graph engine, in-memory topology count (120 nodes, 285 links), and audit ledger are live.

---

### Step 2: Enterprise Topology & Graph Intelligence (Minute 0:45 - 2:00)
1. **Navigate to:** **`Graph Intelligence -> Topology Explorer`** (from the left sidebar).
2. **Explore the Graph:** Show the interactive Cytoscape canvas rendering the 120-node enterprise infrastructure.
   - 👑 **Gold Diamonds:** Crown-Jewel assets (`db-corp-ledger-01`, `dc01-ad-forest`).
   - ⚠️ **Red Nodes:** Compromised systems under active adversary control (`wrk-fin-lead-09`).
   - 💼 **Purple Hexagons:** Business Workflows.
   - 🟦 **Blue/Slate Nodes:** Servers, Cloud clusters, and Workstations.
3. **Demonstrate Interactive Search & Filters:**
   - Type `10.0.2` or `db-corp` into the Search bar: Watch the graph dynamically filter in real-time.
   - Select **👑 Crown Jewels Only** from the Category dropdown: Notice only the highest-value database and active directory clusters appear.
   - Click **"Clear Filters"**: Graph instantly restores full view.
4. **Click any node (e.g., `db-corp-ledger-01`):**
   - The **Node Inspector** card expands at the bottom displaying: Node ID, Type, Criticality (`CRITICAL`), Business Valuation (`$50,000,000`), IP address, Environment, Department, and Known CVEs.
5. **Navigate to:** **`Graph Intelligence -> Attack Paths`**:
   - Show the 4 detected multi-hop attack routes.
   - Click on Route 1 (`Path-001: Phishing -> Workstation -> Bastion -> Crown Jewel Database`).
   - Notice that Cytoscape immediately highlights only the attacker's trajectory in bright cyan and marks bottleneck links.

---

### Step 3: Evidence Uncertainty & Cyber-Physical Risk (Minute 2:00 - 3:15)
1. **Navigate to:** **`Graph Intelligence -> Evidence Uncertainty`**:
   - Explain to judges: *"Real attacks are full of ambiguity. Not all lateral movement links are confirmed."*
   - Show the Dempster-Shafer belief-plausibility curves and temporal freshness decay.
   - Show the sensitivity drift table showing how risk swings if suspected connections turn out to be active C2 channels.
2. **Navigate to:** **`Risk & Business Twin -> Decomposed Risk`**:
   - Explain the tri-factor risk formula:
     $$\text{Risk} = \text{Asset Criticality} \times \text{Vulnerability Exposure} \times \text{Threat Actor Capability}$$
   - Review the Top At-Risk Assets table showing composite risk scores up to 94.8%.
3. **Navigate to:** **`Risk & Business Twin -> Business Continuity Twin`**:
   - Explain: *"Here is our breakthrough: the digital twin of enterprise workflows."*
   - Highlight **WF-001 (SWIFT Wire Transfer & Clearing)**: Hourly financial downtime cost is **\$250,000/hr** with an SLA of **99.99%**.
   - Show the mapped dependency chain: If `srv-app-payment-01` is shut down, SWIFT transactions immediately freeze.

---

### Step 4: Decision Support & Response Optimization (Minute 3:15 - 4:30)
1. **Navigate to:** **`Decision Support -> Action Catalog`**:
   - Show candidate defensive actions: Host Isolation, Port Blocking, Credential Revocation, WAF Virtual Patching.
   - Each action has an empirical **Risk Reduction %** and **Disruption Cost (\$)**.
2. **Navigate to:** **`Decision Support -> Strategy Comparator`**:
   - Compare the 3 solver paradigms:
     1. **Tri-Level CP-SAT Constraint Programming (Google OR-Tools):** Cuts 96.2% risk while strictly respecting the \$10,000 disruption budget.
     2. **Multi-Objective Greedy Optimizer:** Quickest solver heuristic.
     3. **Minimal Disruption Baseline:** Safest for business continuity, but leaves residual lateral paths open.
   - Point out why CP-SAT is the mathematically optimal choice.

---

### Step 5: What-If Simulation Sandbox (Minute 4:30 - 5:30)
1. **Navigate to:** **`Decision Support -> Simulation Sandbox`**:
   - Explain: *"We never execute response actions directly on live infrastructure. We simulate them in an isolated in-memory graph snapshot first."*
2. **Execute Simulation:**
   - Select **Constraint CP-SAT** strategy.
   - Click the green **"Simulate Containment Plan"** button.
3. **Verify Simulation Results:**
   - Pre-Simulation Risk: **89.4%** $\rightarrow$ Post-Simulation Risk: **3.8%** (**-85.6% Net Reduction**).
   - Attack Paths Eliminated: **4 of 4 (100% Path Severance)**.
   - Residual Attack Paths Remaining: **0 Paths Found**.
   - Disruption Cost to Business: **\$4,500** (Well under the \$10,000 threshold).
   - SWIFT Payment workflow remains 100% operational.
4. **Inspect Cytoscape Simulation Diff:**
   - Red dashed links visually show the severed adversary routes.

---

### Step 6: Governance Approval & Blockchain Tamper-Evident Audit (Minute 5:30 - 6:30)
1. **Navigate to:** **`Decision Support -> Approval Center`**:
   - Show multi-tier approval workflow.
   - Select role: **`CISO`** or **`SECURITY_MANAGER`**.
   - Click **"Approve Plan"**: Plan transitions from `DRAFT` $\rightarrow$ `REVIEW` $\rightarrow$ `APPROVED`.
2. **Navigate to:** **`Decision Support -> Audit Explorer`**:
   - Show the cryptographic audit log. Every single step—scenario load, simulation run, approval—is recorded.
   - Point to the **SHA-256 Hash Chains**: `Previous Hash` $\rightarrow$ `Event Hash`.
   - Click **"Verify Cryptographic Integrity"**: Green banner confirms **Audit Log Cryptographically Sound (0 Tampered Records)**.
3. **On-Chain Blockchain Verification:**
   - Click **"Verify on Blockchain"** on any ledger event.
   - Notification validates: *`✅ On-Chain Verified: anchored on Ethereum smart contract block #104285 with root hash match!`*

---

### Step 7: Dataset Catalog & Instant Scenario Switching (Minute 6:30 - 7:00)
1. **Navigate to:** **`Integrations -> Synthetic Enterprise Dataset Catalog`**:
   - Show the 12 interconnected CSV files with live record counts.
   - Click **"Download All Datasets (ZIP)"**: Generates and downloads a clean, validated `.zip` archive containing all 12 CSVs and the integrity report.
2. **Switch Scenario:**
   - Use the header selector to switch to **`SCEN-002: BlackCat Ransomware Pre-Detonation`**.
   - Watch the entire application reload with ransomware payloads, file-server dependencies, and updated risk rankings in under 1 second.

---

## 3. Judge Q&A Defense Matrix

| Judge Question | Technical Architecture Answer |
| :--- | :--- |
| **Q1: How do you prevent containment from crashing the business?** | *We maintain a digital Business Continuity Twin that maps every IT asset to core workflows, revenue loss rates (\$/hr), and recovery SLAs. Our Google OR-Tools CP-SAT optimizer treats business disruption as a hard mathematical constraint, refusing actions that exceed disruption thresholds.* |
| **Q2: What if the attacker moves through unknown or unconfirmed channels?** | *We apply Dempster-Shafer belief functions and Bayesian temporal confidence decay to relationships. If network evidence is suspected rather than confirmed, the Evidence Engine calculates sensitivity bounds so responders understand worst-case risk.* |
| **Q3: Is the graph database real or simulated?** | *SafeContain AI implements an enterprise dual graph architecture. It connects natively to live Neo4j AuraDB via the official Neo4j Python driver using bolt+s and Cypher queries. If cloud credentials are unconfigured or rotating, it gracefully operates via in-memory NetworkX with 100% algorithmic parity.* |
| **Q4: How do you verify the response plan works before executing it?** | *The Simulation Sandbox deep-clones the graph into an isolated, in-memory ephemeral snapshot, applies the proposed cut-set interventions, and re-runs Dijkstra and Yen's K-shortest path algorithms to mathematically verify whether any residual routes to crown jewels remain.* |
| **Q5: Can an attacker or rogue insider alter the response audit records?** | *Every action is appended to a cryptographic SHA-256 hash-chained ledger where any alteration breaks the entire merkle link. Furthermore, batch merkle roots are anchored to an Ethereum smart contract (`SafeContainAuditAnchor.sol`) for independent, tamper-evident verification.* |
| **Q6: Is this data realistic?** | *Yes. The platform includes a complete 12-file synthetic enterprise dataset with 120 interconnected nodes, 285 typed relationships, 35 assets, 30 identities, 45 CVEs, 60 alerts, 60 dependencies, and 10 real-world threat scenarios with zero referential integrity defects.* |
