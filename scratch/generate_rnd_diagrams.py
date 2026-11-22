"""Generate 16 High-Quality Technical Architecture & R&D Diagrams for SafeContain AI.

Outputs crisp PNG diagrams with a consistent enterprise cybersecurity theme:
- Deep Navy: #10233F
- Sky Cyan: #0284C7
- Slate Dark: #1E293B
- Slate Muted: #64748B
- Light Background: #F8FAFC
- Card White: #FFFFFF
- Success Green: #10B981
- Alert Red: #EF4444
- Warning Amber: #F59E0B
- Accent Purple: #7E22CE
"""

import os
import sys

# Ensure matplotlib uses a writable temp cache directory
os.environ["MPLCONFIGDIR"] = os.path.join(os.environ.get("TEMP", "C:\\Temp"), "mpl")

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches

OUTPUT_DIR = os.path.join(os.getcwd(), "docs", "rnd_diagrams")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Color Palette Constants
C_NAVY = "#10233F"
C_BLUE = "#0284C7"
C_CYAN = "#06B6D4"
C_SLATE = "#1E293B"
C_MUTED = "#64748B"
C_LIGHT = "#F8FAFC"
C_WHITE = "#FFFFFF"
C_GREEN = "#10B981"
C_RED = "#EF4444"
C_AMBER = "#F59E0B"
C_PURPLE = "#7E22CE"
C_BORDER = "#CBD5E1"
C_BG_CARD = "#F1F5F9"


def save_fig(fig, filename):
    path = os.path.join(OUTPUT_DIR, filename)
    fig.savefig(path, dpi=200, bbox_inches="tight", facecolor=C_LIGHT)
    plt.close(fig)
    print(f"Generated: {path}")


def draw_box(ax, x, y, w, h, title, subtitle="", bg_color=C_WHITE, border_color=C_BLUE, title_color=C_NAVY, sub_color=C_MUTED, lw=1.5, radius=0.03):
    box = patches.FancyBboxPatch(
        (x, y), w, h,
        boxstyle=f"round,pad=0.01,rounding_size={radius}",
        facecolor=bg_color,
        edgecolor=border_color,
        linewidth=lw,
        zorder=2
    )
    ax.add_patch(box)
    
    # Text
    if subtitle:
        ax.text(x + w/2, y + h*0.62, title, ha="center", va="center", color=title_color, fontsize=8.5, fontweight="bold", zorder=3)
        ax.text(x + w/2, y + h*0.32, subtitle, ha="center", va="center", color=sub_color, fontsize=7, zorder=3)
    else:
        ax.text(x + w/2, y + h*0.5, title, ha="center", va="center", color=title_color, fontsize=8.5, fontweight="bold", zorder=3)


def draw_arrow(ax, x1, y1, x2, y2, color=C_BLUE, label="", lw=1.5, zorder=4):
    ax.annotate(
        "",
        xy=(x2, y2),
        xytext=(x1, y1),
        arrowprops=dict(arrowstyle="-|>", color=color, lw=lw, shrinkA=3, shrinkB=3),
        zorder=zorder
    )
    if label:
        mx = (x1 + x2) / 2
        my = (y1 + y2) / 2 + 0.025
        ax.text(mx, my, label, ha="center", va="bottom", color=color, fontsize=6.5, fontweight="bold", zorder=zorder+1)


# =============================================================================
# DIAGRAM 1: System Architecture
# =============================================================================
def diag_01_system_architecture():
    fig, ax = plt.subplots(figsize=(10, 5.5))
    ax.set_facecolor(C_LIGHT)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    # Header
    ax.text(0.5, 0.95, "SafeContain AI — Multi-Layer System Architecture", ha="center", va="center", color=C_NAVY, fontsize=12, fontweight="bold")
    ax.text(0.5, 0.91, "Modular, Decoupled Enterprise Decision-Intelligence & Containment Platform", ha="center", va="center", color=C_MUTED, fontsize=8)

    layers = [
        ("Layer 5: Presentation & SecOps UI", "React 18 SPA | Cytoscape Attack Graph | 27 Views | Tailwind CSS | Vite", C_PURPLE, 0.74),
        ("Layer 4: Trust & Audit Governance", "SHA-256 Hash Chaining | Merkle Proofs | Solidity Contract | JSON-RPC Client", C_GREEN, 0.57),
        ("Layer 3: Decision & Optimization", "Google OR-Tools CP-SAT 0-1 ILP | Business Continuity Twin | Simulation Sandbox", C_AMBER, 0.40),
        ("Layer 2: Core Intelligence & AI/ML", "Balanced Logistic Regression | Platt Calibration | Linear SHAP | CUSUM Forecasting", C_BLUE, 0.23),
        ("Layer 1: Telemetry & Ingestion", "SIEM (Splunk/ELK) | EDR (CrowdStrike) | IAM (Okta) | 120-Node Enterprise CSV", C_SLATE, 0.06),
    ]

    for title, subtitle, color, y in layers:
        # Background layer container
        draw_box(ax, 0.08, y, 0.84, 0.13, title, subtitle, bg_color=C_WHITE, border_color=color, title_color=color, lw=1.8)

    # Inter-layer connecting arrows
    draw_arrow(ax, 0.5, 0.19, 0.5, 0.23, color=C_SLATE, label="Normalized Telemetry")
    draw_arrow(ax, 0.5, 0.36, 0.5, 0.40, color=C_BLUE, label="Calibrated Threat Probabilities")
    draw_arrow(ax, 0.5, 0.53, 0.5, 0.57, color=C_AMBER, label="Optimal Containment Plans")
    draw_arrow(ax, 0.5, 0.70, 0.5, 0.74, color=C_GREEN, label="Cryptographically Verified Proofs")

    save_fig(fig, "01_system_architecture.png")


# =============================================================================
# DIAGRAM 2: End-to-End Decision Workflow
# =============================================================================
def diag_02_decision_workflow():
    fig, ax = plt.subplots(figsize=(11, 4.5))
    ax.set_facecolor(C_LIGHT)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.5, 0.93, "SafeContain AI — End-to-End Decision-Intelligence Workflow", ha="center", va="center", color=C_NAVY, fontsize=12, fontweight="bold")
    ax.text(0.5, 0.87, "From Alert Ingestion to Mathematical Containment Optimization & Immutable Evidence Anchoring", ha="center", va="center", color=C_MUTED, fontsize=8)

    steps = [
        ("1. Ingest", "SIEM / EDR", 0.03),
        ("2. Graph", "Lateral Paths", 0.17),
        ("3. ML Risk", "θ*=0.32 Calib", 0.31),
        ("4. Forecast", "CUSUM Horizon", 0.45),
        ("5. Business", "SLA Constraints", 0.59),
        ("6. CP-SAT", "0-1 Integer ILP", 0.73),
        ("7. Evidence", "SHA-256 Ledger", 0.87),
    ]

    for title, sub, x in steps:
        draw_box(ax, x, 0.40, 0.10, 0.25, title, sub, bg_color=C_WHITE, border_color=C_BLUE, lw=1.5)

    for i in range(len(steps) - 1):
        x1 = steps[i][2] + 0.10
        x2 = steps[i+1][2]
        draw_arrow(ax, x1, 0.525, x2, 0.525, color=C_CYAN, lw=1.5)

    # Annotations below
    annotations = [
        ("Raw Events", 0.08), ("Multi-Hop Attack Paths", 0.22), ("Leak-Free 13 Features", 0.36),
        ("30/60/90m Trajectory", 0.50), ("Zero-Outage Hard Limits", 0.64), ("Optimal Action Set", 0.78),
        ("Merkle Root Verified", 0.92)
    ]
    for text, x in annotations:
        ax.text(x, 0.28, text, ha="center", va="center", color=C_SLATE, fontsize=6.8, fontweight="bold")

    save_fig(fig, "02_decision_workflow.png")


# =============================================================================
# DIAGRAM 3: Attack Path Graph Analysis
# =============================================================================
def diag_03_attack_path_graph():
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.set_facecolor(C_LIGHT)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.5, 0.94, "Attack Path Graph Intelligence & Multi-Hop Traversal", ha="center", va="center", color=C_NAVY, fontsize=12, fontweight="bold")
    ax.text(0.5, 0.88, "Dijkstra Risk-Weighted Shortest Path from Initial Breach to Crown Jewel Assets", ha="center", va="center", color=C_MUTED, fontsize=8)

    nodes = [
        ("Host 10.0.1.45", "Compromised Workstation\n(Initial Access: Phishing)", 0.05, 0.45, C_RED),
        ("Host 10.0.1.10", "Internal Pivot Server\n(Lateral Move: SSH/RDP)", 0.28, 0.45, C_AMBER),
        ("Host 10.0.2.5", "Domain Controller\n(Privilege Escalation: Kerberoast)", 0.51, 0.45, C_PURPLE),
        ("Host 10.0.3.100", "Payment Gateway\n(Crown Jewel: Transaction API)", 0.74, 0.65, C_NAVY),
        ("Host 10.0.3.200", "Core SQL Cluster\n(Crown Jewel: Customer PII)", 0.74, 0.25, C_NAVY),
    ]

    for title, sub, x, y, col in nodes:
        draw_box(ax, x, y, 0.21, 0.22, title, sub, bg_color=C_WHITE, border_color=col, title_color=col, lw=1.8)

    # Edges
    draw_arrow(ax, 0.26, 0.56, 0.28, 0.56, color=C_RED, label="W_risk = 0.85")
    draw_arrow(ax, 0.49, 0.56, 0.51, 0.56, color=C_AMBER, label="W_risk = 0.92")
    draw_arrow(ax, 0.72, 0.60, 0.74, 0.74, color=C_PURPLE, label="Path 1: API Trust")
    draw_arrow(ax, 0.72, 0.52, 0.74, 0.38, color=C_PURPLE, label="Path 2: DB Creds")

    # Legend / Info Callout
    ax.text(0.5, 0.12, "Algorithm: Dijkstra Shortest Path on Graph G=(V, E, W_risk) | Dual-Engine: Neo4j Aura + NetworkX Local Fallback", ha="center", va="center", color=C_SLATE, fontsize=7.5, fontweight="bold")

    save_fig(fig, "03_attack_path_graph.png")


# =============================================================================
# DIAGRAM 4: Dual-Engine Graph Architecture
# =============================================================================
def diag_04_dual_engine_architecture():
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.set_facecolor(C_LIGHT)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.5, 0.94, "SafeContain AI — Dual-Engine Graph Synchronization Architecture", ha="center", va="center", color=C_NAVY, fontsize=12, fontweight="bold")
    ax.text(0.5, 0.88, "Zero-Downtime High Availability: Cloud Neo4j AuraDB with Instant In-Memory NetworkX Failover", ha="center", va="center", color=C_MUTED, fontsize=8)

    # Left: Neo4j Aura
    draw_box(ax, 0.08, 0.35, 0.35, 0.45, "Persistent Graph Tier\nNeo4j AuraDB (Cloud Managed)", "• Bolt Protocol / Cypher Queries\n• Graph Schema & Node Labels\n• Enterprise Topology Storage\n• Multi-Hop Relationship Indexing\n• Graph Analytics & Subgraphs", bg_color=C_WHITE, border_color=C_BLUE, lw=1.8)

    # Right: NetworkX In-Memory
    draw_box(ax, 0.57, 0.35, 0.35, 0.45, "In-Memory Engine Tier\nNetworkX Engine (Local Runner)", "• Sub-Millisecond Traversal (< 25ms)\n• Dijkstra Attack Path Discovery\n• Graph Snapshot Isolation (Sandbox)\n• Zero Conference-WiFi Dependency\n• Automatic Air-Gap Fallback", bg_color=C_WHITE, border_color=C_GREEN, lw=1.8)

    # Center: Sync Manager
    draw_box(ax, 0.44, 0.45, 0.12, 0.25, "Dual Sync\nManager", "Startup Hydration\n&\nDelta Sync", bg_color=C_BG_CARD, border_color=C_PURPLE, title_color=C_PURPLE, lw=1.5)

    draw_arrow(ax, 0.43, 0.60, 0.44, 0.60, color=C_BLUE, label="Hydrate")
    draw_arrow(ax, 0.56, 0.50, 0.57, 0.50, color=C_GREEN, label="Active")
    draw_arrow(ax, 0.57, 0.45, 0.43, 0.45, color=C_PURPLE, label="Failover")

    ax.text(0.5, 0.18, "Status: GRAPH_BACKEND=dual | Verified: 120 Nodes, 142 Relationships Synchronized Equivalently", ha="center", va="center", color=C_NAVY, fontsize=8, fontweight="bold")

    save_fig(fig, "04_dual_engine_architecture.png")


# =============================================================================
# DIAGRAM 5: ML Risk Pipeline
# =============================================================================
def diag_05_ml_pipeline():
    fig, ax = plt.subplots(figsize=(11, 4.5))
    ax.set_facecolor(C_LIGHT)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.5, 0.94, "SafeContain AI — Machine Learning Risk Intelligence Pipeline", ha="center", va="center", color=C_NAVY, fontsize=12, fontweight="bold")
    ax.text(0.5, 0.88, "Leak-Free Feature Extraction, Balanced Logistic Regression & Cost-Sensitive Calibration", ha="center", va="center", color=C_MUTED, fontsize=8)

    stages = [
        ("1. Data Ingest", "Topology CSV\n& Telemetry", 0.04),
        ("2. Leak-Free", "13 Scaled\nFeatures", 0.20),
        ("3. Model Train", "Balanced LogReg\n(C=0.5, liblinear)", 0.36),
        ("4. Platt Calib", "Empirical P(Y|X)\nRaw Odds -> Prob", 0.52),
        ("5. Threshold", "θ* = 0.32\n10:1 FN:FP Cost", 0.68),
        ("6. Inference", "Threat Exposure\nScore [0, 100]", 0.84),
    ]

    for title, sub, x in stages:
        draw_box(ax, x, 0.38, 0.12, 0.32, title, sub, bg_color=C_WHITE, border_color=C_BLUE, lw=1.5)

    for i in range(len(stages) - 1):
        x1 = stages[i][2] + 0.12
        x2 = stages[i+1][2]
        draw_arrow(ax, x1, 0.54, x2, 0.54, color=C_CYAN, lw=1.5)

    ax.text(0.5, 0.20, "Validated Metrics: 5-Fold CV Balanced Accuracy = 0.6942 | Holdout Threat Recall = 0.8000 | FNR Reduction = 40.0%", ha="center", va="center", color=C_SLATE, fontsize=7.5, fontweight="bold")

    save_fig(fig, "05_ml_pipeline.png")


# =============================================================================
# DIAGRAM 6: SHAP Explainability
# =============================================================================
def diag_06_shap_explainability():
    fig, ax = plt.subplots(figsize=(10, 4.8))
    ax.set_facecolor(C_LIGHT)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.5, 0.94, "Explainable AI (SHAP) Attribution Architecture", ha="center", va="center", color=C_NAVY, fontsize=12, fontweight="bold")
    ax.text(0.5, 0.88, "LinearExplainer Closed-Form Attribution for Instant Mathematical Transparency", ha="center", va="center", color=C_MUTED, fontsize=8)

    # Input Box
    draw_box(ax, 0.05, 0.38, 0.22, 0.35, "Input Asset Vector\n(Host: 10.0.1.45)", "• In-Degree = 4\n• Criticality = Tier 1\n• Failed Logins = 14\n• Port Scan Alerts = 6\n• Out-Degree = 8", bg_color=C_WHITE, border_color=C_SLATE, lw=1.5)

    # Middle: Model & SHAP Explainer
    draw_box(ax, 0.35, 0.38, 0.26, 0.35, "LinearExplainer Engine", "ϕ_i(x) = w_i * (x_i - E[x_i])\n\nInstant Closed-Form\nZero Sampling Variance\nDeterministic Attribution", bg_color=C_WHITE, border_color=C_PURPLE, title_color=C_PURPLE, lw=1.8)

    # Right: Waterfall Features
    draw_box(ax, 0.69, 0.38, 0.26, 0.35, "Feature Attributions\n(SHAP Values)", "(+) Failed Logins: +0.34\n(+) In-Degree: +0.22\n(+) Outbound Flow: +0.18\n(-) Endpoint Patch: -0.12\nBase Value: 0.15 -> Final: 0.77", bg_color=C_WHITE, border_color=C_RED, title_color=C_RED, lw=1.5)

    draw_arrow(ax, 0.27, 0.555, 0.35, 0.555, color=C_BLUE, label="Feature Vector")
    draw_arrow(ax, 0.61, 0.555, 0.69, 0.555, color=C_PURPLE, label="Compute ϕ_i")

    ax.text(0.5, 0.18, "Empowers SOC Analysts: Explains exactly WHY an asset is classified as High Risk in < 5ms", ha="center", va="center", color=C_NAVY, fontsize=8, fontweight="bold")

    save_fig(fig, "06_shap_explainability.png")


# =============================================================================
# DIAGRAM 7: Predictive Intelligence
# =============================================================================
def diag_07_predictive_intelligence():
    fig, ax = plt.subplots(figsize=(10, 4.8))
    ax.set_facecolor(C_LIGHT)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.5, 0.94, "SafeContain AI — Temporal Predictive Threat Intelligence", ha="center", va="center", color=C_NAVY, fontsize=12, fontweight="bold")
    ax.text(0.5, 0.88, "Linear Trajectory, CUSUM Volatility Break Detection & Multi-Horizon Escalation Prediction", ha="center", va="center", color=C_MUTED, fontsize=8)

    # 4 blocks
    draw_box(ax, 0.05, 0.35, 0.20, 0.40, "Signal Extraction", "• Threat Velocity (dv/dt)\n• Alert Concentration\n• Credential Spike\n• Lateral Movement Rate", bg_color=C_WHITE, border_color=C_BLUE, lw=1.5)
    draw_box(ax, 0.28, 0.35, 0.20, 0.40, "Trajectory Modeling", "• Ordinary Least Squares\n• Risk Velocity Slope\n• Volatility Score\n• CUSUM Anomaly Break", bg_color=C_WHITE, border_color=C_AMBER, lw=1.5)
    draw_box(ax, 0.51, 0.35, 0.20, 0.40, "Horizon Forecasting", "• T+30 min: p_30\n• T+60 min: p_60\n• T+90 min: p_90\n• Confidence Bounds", bg_color=C_WHITE, border_color=C_PURPLE, lw=1.5)
    draw_box(ax, 0.74, 0.35, 0.21, 0.40, "Escalation Classifier", "5 Threat States:\n1. STABLE\n2. WATCHLIST\n3. ESCALATING\n4. HIGH_THREAT\n5. IMMINENT_BREACH", bg_color=C_WHITE, border_color=C_RED, title_color=C_RED, lw=1.8)

    draw_arrow(ax, 0.25, 0.55, 0.28, 0.55, color=C_BLUE)
    draw_arrow(ax, 0.48, 0.55, 0.51, 0.55, color=C_AMBER)
    draw_arrow(ax, 0.71, 0.55, 0.74, 0.55, color=C_PURPLE)

    ax.text(0.5, 0.16, "Early-Warning Lead Time: Forecasts lateral escalation 30-90 minutes before crown jewel compromise", ha="center", va="center", color=C_NAVY, fontsize=8, fontweight="bold")

    save_fig(fig, "07_predictive_intelligence.png")


# =============================================================================
# DIAGRAM 8: Business Continuity Twin
# =============================================================================
def diag_08_business_continuity_twin():
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.set_facecolor(C_LIGHT)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.5, 0.94, "Business Continuity Twin & Mission-Critical SLA Modeling", ha="center", va="center", color=C_NAVY, fontsize=12, fontweight="bold")
    ax.text(0.5, 0.88, "Connecting Cybersecurity Response to Enterprise Financial Cost and Operational Disruption", ha="center", va="center", color=C_MUTED, fontsize=8)

    draw_box(ax, 0.06, 0.35, 0.26, 0.42, "Enterprise Asset Graph", "• Asset Criticality Tier\n• Upstream Dependencies\n• Downstream Consumers\n• Service Endpoints\n• Database Bindings", bg_color=C_WHITE, border_color=C_SLATE, lw=1.5)

    draw_box(ax, 0.37, 0.35, 0.26, 0.42, "Workflow Impact Engine", "• Citizen Portal Services\n• Payment Gateway API\n• Core Identity (SSO)\n• Hourly Downtime Cost\n• Cumulative Disruption", bg_color=C_WHITE, border_color=C_BLUE, lw=1.5)

    draw_box(ax, 0.68, 0.35, 0.26, 0.42, "Hard SLA Bounds", "• Zero Outage Constraint\n• Max Allowable Disruption\n• Graceful Fallback Rules\n• Financial Budget Cap\n• Feasibility Evaluation", bg_color=C_WHITE, border_color=C_GREEN, title_color=C_GREEN, lw=1.8)

    draw_arrow(ax, 0.32, 0.56, 0.37, 0.56, color=C_BLUE, label="Map Topology")
    draw_arrow(ax, 0.63, 0.56, 0.68, 0.56, color=C_GREEN, label="Enforce SLA")

    ax.text(0.5, 0.16, "Key Question Solved: Prevents blunt containment from taking down $50k/hr citizen services", ha="center", va="center", color=C_NAVY, fontsize=8, fontweight="bold")

    save_fig(fig, "08_business_continuity_twin.png")


# =============================================================================
# DIAGRAM 9: CP-SAT Optimization
# =============================================================================
def diag_09_cpsat_optimization():
    fig, ax = plt.subplots(figsize=(10.5, 5))
    ax.set_facecolor(C_LIGHT)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.5, 0.94, "Google OR-Tools CP-SAT 0-1 Integer Linear Programming Solver", ha="center", va="center", color=C_NAVY, fontsize=12, fontweight="bold")
    ax.text(0.5, 0.88, "Mathematical Containment Optimization with Strict Budget & Hard SLA Outage Constraints", ha="center", va="center", color=C_MUTED, fontsize=8)

    # 3 columns: Inputs, Solver Formulation, Optimal Output
    draw_box(ax, 0.05, 0.28, 0.26, 0.52, "Candidate Actions (x_i)", "• Host Isolation\n• Network Segmentation\n• Credential Revocation\n• Forensic Snapshot\n• Cost: c_i ($)\n• Disruption: d_i\n• Threat Prob: p_i", bg_color=C_WHITE, border_color=C_SLATE, lw=1.5)

    draw_box(ax, 0.35, 0.25, 0.32, 0.58, "OR-Tools CP-SAT Model", "Maximize Objective:\nΣ [ 100 R_i + 5000 p_i + 5000 w p_fut\n   - 0.1 Cost_i - 20 Disruption_i ] * x_i\n\nSubject to:\n1. Σ Cost_cents_i * x_i <= Budget_cents\n2. x_i == 0 if violates_critical_sla(i)\n3. x_i ∈ {0, 1} (Exact 0-1 ILP)", bg_color=C_WHITE, border_color=C_BLUE, title_color=C_BLUE, lw=1.8)

    draw_box(ax, 0.71, 0.28, 0.25, 0.52, "Optimal Containment Plan", "• Selected Action Set {x_i=1}\n• Exact Residual Risk Delta\n• Total Cost <= Budget Limit\n• 100% SLA Compliance\n• Decision Rationale & SHAP", bg_color=C_WHITE, border_color=C_GREEN, title_color=C_GREEN, lw=1.8)

    draw_arrow(ax, 0.31, 0.54, 0.35, 0.54, color=C_BLUE)
    draw_arrow(ax, 0.67, 0.54, 0.71, 0.54, color=C_GREEN)

    ax.text(0.5, 0.12, "Solver Performance: Computes mathematically guaranteed optimal solution in < 340ms (< 5000ms SLA)", ha="center", va="center", color=C_SLATE, fontsize=7.5, fontweight="bold")

    save_fig(fig, "09_cpsat_optimization.png")


# =============================================================================
# DIAGRAM 10: Audit Hash Chain
# =============================================================================
def diag_10_audit_hash_chain():
    fig, ax = plt.subplots(figsize=(10.5, 4.5))
    ax.set_facecolor(C_LIGHT)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.5, 0.94, "Cryptographic Audit Ledger — SHA-256 Hash Chain", ha="center", va="center", color=C_NAVY, fontsize=12, fontweight="bold")
    ax.text(0.5, 0.88, "Sequential Forward Integrity & Cryptographic Tamper Detection in Append-Only JSONL", ha="center", va="center", color=C_MUTED, fontsize=8)

    blocks = [
        ("Record #1 (Genesis)", "Prev: 00000000...\nPayload: Sys Initialized\nHash: a3f8...c10b", 0.05),
        ("Record #2", "Prev: a3f8...c10b\nPayload: Containment Plan\nHash: 7d1e...994a", 0.36),
        ("Record #3", "Prev: 7d1e...994a\nPayload: Admin Approval\nHash: 44b2...8f31", 0.67),
    ]

    for title, sub, x in blocks:
        draw_box(ax, x, 0.35, 0.28, 0.40, title, sub, bg_color=C_WHITE, border_color=C_PURPLE, title_color=C_PURPLE, lw=1.8)

    draw_arrow(ax, 0.33, 0.55, 0.36, 0.55, color=C_BLUE, label="H_prev link")
    draw_arrow(ax, 0.64, 0.55, 0.67, 0.55, color=C_BLUE, label="H_prev link")

    ax.text(0.5, 0.18, "Tamper Resistance: Any retroactive change to Record #1 instantly invalidates Hash #2 and Hash #3", ha="center", va="center", color=C_RED, fontsize=8, fontweight="bold")

    save_fig(fig, "10_audit_hash_chain.png")


# =============================================================================
# DIAGRAM 11: Merkle Tree Verification
# =============================================================================
def diag_11_merkle_tree_verification():
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.set_facecolor(C_LIGHT)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.5, 0.94, "SafeContain AI — Batch Evidence Merkle Tree Verification", ha="center", va="center", color=C_NAVY, fontsize=12, fontweight="bold")
    ax.text(0.5, 0.88, "Cryptographic Batch Compression with Logarithmic Proof Verification: O(log N)", ha="center", va="center", color=C_MUTED, fontsize=8)

    # Root
    draw_box(ax, 0.38, 0.70, 0.24, 0.16, "Merkle Root (R)", "H(H_12 || H_34)", bg_color=C_WHITE, border_color=C_GREEN, title_color=C_GREEN, lw=2.0)

    # Intermediate Level
    draw_box(ax, 0.18, 0.44, 0.22, 0.15, "Node H_12", "H(L_1 || L_2)", bg_color=C_WHITE, border_color=C_BLUE, lw=1.5)
    draw_box(ax, 0.60, 0.44, 0.22, 0.15, "Node H_34", "H(L_3 || L_4)", bg_color=C_WHITE, border_color=C_BLUE, lw=1.5)

    # Leaves
    draw_box(ax, 0.05, 0.20, 0.18, 0.14, "Leaf L_1", "Audit Event #1", bg_color=C_WHITE, border_color=C_SLATE, lw=1.2)
    draw_box(ax, 0.27, 0.20, 0.18, 0.14, "Leaf L_2", "Audit Event #2", bg_color=C_WHITE, border_color=C_SLATE, lw=1.2)
    draw_box(ax, 0.52, 0.20, 0.18, 0.14, "Leaf L_3", "Audit Event #3", bg_color=C_WHITE, border_color=C_SLATE, lw=1.2)
    draw_box(ax, 0.74, 0.20, 0.18, 0.14, "Leaf L_4", "Audit Event #4", bg_color=C_WHITE, border_color=C_SLATE, lw=1.2)

    # Connections
    draw_arrow(ax, 0.14, 0.34, 0.24, 0.44, color=C_MUTED)
    draw_arrow(ax, 0.36, 0.34, 0.30, 0.44, color=C_MUTED)
    draw_arrow(ax, 0.61, 0.34, 0.68, 0.44, color=C_MUTED)
    draw_arrow(ax, 0.83, 0.34, 0.74, 0.44, color=C_MUTED)

    draw_arrow(ax, 0.29, 0.59, 0.44, 0.70, color=C_BLUE)
    draw_arrow(ax, 0.71, 0.59, 0.56, 0.70, color=C_BLUE)

    ax.text(0.5, 0.08, "Audit Proof: Verifies single record integrity against on-chain root using only sibling hashes in O(log N)", ha="center", va="center", color=C_NAVY, fontsize=8, fontweight="bold")

    save_fig(fig, "11_merkle_tree_verification.png")


# =============================================================================
# DIAGRAM 12: Blockchain Anchoring
# =============================================================================
def diag_12_blockchain_anchoring():
    fig, ax = plt.subplots(figsize=(10.5, 4.8))
    ax.set_facecolor(C_LIGHT)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.5, 0.94, "Blockchain Evidence Anchoring Architecture", ha="center", va="center", color=C_NAVY, fontsize=12, fontweight="bold")
    ax.text(0.5, 0.88, "Off-Chain Evidence Compression + On-Chain Cryptographic Root Commitment", ha="center", va="center", color=C_MUTED, fontsize=8)

    draw_box(ax, 0.05, 0.32, 0.25, 0.45, "SafeContain Core\n(Off-Chain)", "• Audit Event Batching\n• Graph State Snapshots\n• Merkle Tree Generation\n• Proof Manifest Storage\n• Sensitive PII Retained", bg_color=C_WHITE, border_color=C_SLATE, lw=1.5)

    draw_box(ax, 0.36, 0.32, 0.28, 0.45, "Pure Python EVM Client\n(JSON-RPC 2.0)", "• Keccak-256 Hashing\n• ABI Method Encoding\n• EIP-155 Transaction Signing\n• Gas Estimation & Nonce Mgmt\n• Zero Web3.py Dependency", bg_color=C_WHITE, border_color=C_PURPLE, title_color=C_PURPLE, lw=1.8)

    draw_box(ax, 0.69, 0.32, 0.26, 0.45, "SafeContainAuditLedger.sol\n(EVM Smart Contract)", "• recordEvidenceAnchor()\n• Sepolia Testnet (ID 11155111)\n• Contract Address Verified\n• Immutable Block Timestamp\n• Etherscan Public Explorer", bg_color=C_WHITE, border_color=C_GREEN, title_color=C_GREEN, lw=1.8)

    draw_arrow(ax, 0.30, 0.54, 0.36, 0.54, color=C_PURPLE, label="Merkle Root")
    draw_arrow(ax, 0.64, 0.54, 0.69, 0.54, color=C_GREEN, label="Signed Tx")

    ax.text(0.5, 0.16, "Status Distinction: Implemented Architecture + Local Verification Active | Public Broadcast Optional via Config", ha="center", va="center", color=C_SLATE, fontsize=7.5, fontweight="bold")

    save_fig(fig, "12_blockchain_anchoring.png")


# =============================================================================
# DIAGRAM 13: API & Backend Architecture
# =============================================================================
def diag_13_api_backend_architecture():
    fig, ax = plt.subplots(figsize=(10.5, 5))
    ax.set_facecolor(C_LIGHT)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.5, 0.94, "FastAPI High-Performance Backend & Router Inventory", ha="center", va="center", color=C_NAVY, fontsize=12, fontweight="bold")
    ax.text(0.5, 0.88, "161 REST Endpoints across 7 Specialized Subsystems with Multi-Tier RBAC", ha="center", va="center", color=C_MUTED, fontsize=8)

    # Left: Gateway & Middleware
    draw_box(ax, 0.05, 0.28, 0.22, 0.52, "API Gateway & Security", "• SecurityHeadersMiddleware\n• OWASP HSTS / CSP / XFO\n• CORS Allow-Origins\n• Bcrypt Password Hashing\n• JWT Token Issuance\n• 3-Tier RBAC Enforcement", bg_color=C_WHITE, border_color=C_NAVY, lw=1.8)

    # Middle: Routers
    routers = [
        ("Core v1 Router (69 Endpoints)", "Graph, Attack Paths, Ingestion, Optimization, Governance, Ledger", 0.65),
        ("ML Pipeline Router (36 Endpoints)", "Datasets, Features, Cross-Validation, Training, Model Registry", 0.50),
        ("Calibration & Feedback (23 Endpoints)", "Platt Calibration, Cost Utility Grid, Shadow Evaluation", 0.35),
        ("Predictive & Threat Intel (33 Endpoints)", "Trajectory, Early Warning, Cluster Dossiers, CUSUM Breaks", 0.20),
    ]

    for title, sub, y in routers:
        draw_box(ax, 0.34, y, 0.40, 0.12, title, sub, bg_color=C_WHITE, border_color=C_BLUE, title_color=C_BLUE, lw=1.3)

    # Right: Handlers & Services
    draw_box(ax, 0.78, 0.28, 0.18, 0.52, "Engine Handlers", "• GraphEngine\n• BusinessTwin\n• CPSATOptimizer\n• EvidenceEngine\n• AuditLedger\n• ModelRegistry", bg_color=C_WHITE, border_color=C_SLATE, lw=1.5)

    draw_arrow(ax, 0.27, 0.54, 0.34, 0.54, color=C_NAVY)
    draw_arrow(ax, 0.74, 0.54, 0.78, 0.54, color=C_BLUE)

    ax.text(0.5, 0.08, "Total Verified Endpoints: 161 | Interactive Docs: /docs (Swagger UI) & /redoc (ReDoc)", ha="center", va="center", color=C_SLATE, fontsize=7.5, fontweight="bold")

    save_fig(fig, "13_api_backend_architecture.png")


# =============================================================================
# DIAGRAM 14: Database Storage Architecture
# =============================================================================
def diag_14_database_storage_architecture():
    fig, ax = plt.subplots(figsize=(10, 4.8))
    ax.set_facecolor(C_LIGHT)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.5, 0.94, "SafeContain AI — Multi-Tier Data Storage Architecture", ha="center", va="center", color=C_NAVY, fontsize=12, fontweight="bold")
    ax.text(0.5, 0.88, "Relational State, Persistent Graph, In-Memory Caches & Cryptographic Append-Only Files", ha="center", va="center", color=C_MUTED, fontsize=8)

    tiers = [
        ("Graph Database", "Neo4j AuraDB (Cloud)\n&\nNetworkX (In-Memory)\n120 Nodes / 142 Edges", 0.05, C_BLUE),
        ("State & RBAC", "SQLite / PostgreSQL\nUser Records, JWT State,\nApproval Workflows", 0.29, C_NAVY),
        ("Audit Evidence", "Append-Only JSONL\n(audit_ledger.jsonl)\nSHA-256 Hash Chain", 0.53, C_PURPLE),
        ("ML & Artifacts", "joblib Model Binaries,\nJSON Calibration Grids,\nIncident PDF Dossiers", 0.77, C_GREEN),
    ]

    for title, sub, x, col in tiers:
        draw_box(ax, x, 0.32, 0.20, 0.44, title, sub, bg_color=C_WHITE, border_color=col, title_color=col, lw=1.8)

    ax.text(0.5, 0.16, "Clear Separation of Concerns: Ephemeral Caches, Persistent Graph Topology, and Tamper-Proof Audit Files", ha="center", va="center", color=C_SLATE, fontsize=8, fontweight="bold")

    save_fig(fig, "14_database_storage_architecture.png")


# =============================================================================
# DIAGRAM 15: Single-URL Render Deployment
# =============================================================================
def diag_15_deployment_architecture():
    fig, ax = plt.subplots(figsize=(10.5, 5))
    ax.set_facecolor(C_LIGHT)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.5, 0.94, "Single-Service Single-URL Cloud Deployment Architecture", ha="center", va="center", color=C_NAVY, fontsize=12, fontweight="bold")
    ax.text(0.5, 0.88, "Unified Render Web Service Serving React/Vite SPA and FastAPI REST Backend under One Domain", ha="center", va="center", color=C_MUTED, fontsize=8)

    # Cloud Ingress
    draw_box(ax, 0.05, 0.38, 0.22, 0.38, "Public Ingress\nhttps://safecontain-ai.onrender.com", "• Render Edge CDN\n• TLS Termination (HTTPS)\n• Unified Domain\n• Zero CORS Overhead", bg_color=C_WHITE, border_color=C_NAVY, lw=1.8)

    # Container
    draw_box(ax, 0.35, 0.25, 0.32, 0.58, "Render Docker Web Service\n(Container Runtime)", "• Multi-Stage Docker Build\n• Python 3.11 + Node 20\n• Port $PORT Binding\n• Non-Root 'appuser'\n• Healthcheck: /api/v1/health", bg_color=C_WHITE, border_color=C_BLUE, title_color=C_BLUE, lw=1.8)

    # Routes
    draw_box(ax, 0.73, 0.54, 0.22, 0.26, "Frontend SPA Routes", "• / -> index.html\n• /topology-explorer\n• /optimizer\n• /assets/* Static Files", bg_color=C_WHITE, border_color=C_PURPLE, lw=1.5)
    draw_box(ax, 0.73, 0.22, 0.22, 0.26, "Backend API Routes", "• /api/v1/* REST APIs\n• /docs (Swagger UI)\n• /redoc (API Docs)\n• /status (Health Probe)", bg_color=C_WHITE, border_color=C_GREEN, lw=1.5)

    draw_arrow(ax, 0.27, 0.57, 0.35, 0.57, color=C_NAVY)
    draw_arrow(ax, 0.67, 0.65, 0.73, 0.65, color=C_PURPLE, label="GET /*")
    draw_arrow(ax, 0.67, 0.38, 0.73, 0.38, color=C_GREEN, label="API Req")

    ax.text(0.5, 0.10, "Eliminates Localhost Coupling: Production Client uses Relative '/api/v1' Endpoints Seamlessly", ha="center", va="center", color=C_SLATE, fontsize=7.5, fontweight="bold")

    save_fig(fig, "15_deployment_architecture.png")


# =============================================================================
# DIAGRAM 16: Complete Incident Decision Lifecycle
# =============================================================================
def diag_16_integrated_lifecycle():
    fig, ax = plt.subplots(figsize=(11, 5))
    ax.set_facecolor(C_LIGHT)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    ax.text(0.5, 0.94, "SafeContain AI — Complete Incident Decision Lifecycle", ha="center", va="center", color=C_NAVY, fontsize=12, fontweight="bold")
    ax.text(0.5, 0.88, "End-to-End Operational Lifecycle: Detection -> Graph Analysis -> Optimization -> Verified Action", ha="center", va="center", color=C_MUTED, fontsize=8)

    cycle_steps = [
        ("Phase 1: Ingest & Correlate", "SIEM/EDR Telemetry -> Graph Synchronization", 0.70),
        ("Phase 2: Risk & Attribution", "Balanced ML Score + SHAP Explanation + Trajectory", 0.54),
        ("Phase 3: Decision Optimization", "Business Continuity Twin + OR-Tools CP-SAT 0-1 ILP", 0.38),
        ("Phase 4: Governance & Proof", "Four-Eyes Approval + SHA-256 Chaining + Merkle Anchor", 0.22),
    ]

    for title, sub, y in cycle_steps:
        draw_box(ax, 0.12, y, 0.76, 0.12, title, sub, bg_color=C_WHITE, border_color=C_BLUE, title_color=C_NAVY, lw=1.5)

    draw_arrow(ax, 0.5, 0.68, 0.5, 0.66, color=C_CYAN, lw=2)
    draw_arrow(ax, 0.5, 0.52, 0.5, 0.50, color=C_CYAN, lw=2)
    draw_arrow(ax, 0.5, 0.36, 0.5, 0.34, color=C_CYAN, lw=2)

    ax.text(0.5, 0.08, "Mission: Transforming reactive, disruptive incident response into proactive, business-aware decision intelligence", ha="center", va="center", color=C_PURPLE, fontsize=8, fontweight="bold")

    save_fig(fig, "16_integrated_lifecycle.png")


def main():
    print("Generating 16 SafeContain AI Architecture Diagrams...")
    diag_01_system_architecture()
    diag_02_decision_workflow()
    diag_03_attack_path_graph()
    diag_04_dual_engine_architecture()
    diag_05_ml_pipeline()
    diag_06_shap_explainability()
    diag_07_predictive_intelligence()
    diag_08_business_continuity_twin()
    diag_09_cpsat_optimization()
    diag_10_audit_hash_chain()
    diag_11_merkle_tree_verification()
    diag_12_blockchain_anchoring()
    diag_13_api_backend_architecture()
    diag_14_database_storage_architecture()
    diag_15_deployment_architecture()
    diag_16_integrated_lifecycle()
    print("All 16 diagrams successfully generated in docs/rnd_diagrams/!")


if __name__ == "__main__":
    main()
