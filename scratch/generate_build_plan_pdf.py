import os
import sys
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
import pypdf

def build_pdf():
    pdf_path = "SAFECONTAIN_AI_FINAL_BUILD_PLAN.pdf"
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        rightMargin=26,
        leftMargin=26,
        topMargin=22,
        bottomMargin=22
    )

    styles = getSampleStyleSheet()

    # Executive Palette
    c_primary = colors.HexColor("#10233F")     # Deep Navy
    c_secondary = colors.HexColor("#0284C7")   # Sky Cyan
    c_slate = colors.HexColor("#334155")       # Slate
    c_light_bg = colors.HexColor("#F8FAFC")    # Clean Table Alt
    c_border = colors.HexColor("#CBD5E1")      # Slate 300
    c_callout_bg = colors.HexColor("#EFF6FF")  # Blue 50
    c_callout_border = colors.HexColor("#93C5FD")

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=16,
        textColor=c_primary,
        alignment=TA_LEFT,
        spaceAfter=1
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=10.5,
        textColor=c_secondary,
        alignment=TA_LEFT,
        spaceAfter=5
    )

    h2_style = ParagraphStyle(
        'H2Style',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=10.5,
        textColor=c_primary,
        spaceBefore=4,
        spaceAfter=2
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7,
        leading=8.8,
        textColor=c_slate
    )

    body_bold = ParagraphStyle(
        'BodyBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7,
        leading=8.8,
        textColor=c_primary
    )

    dod_style = ParagraphStyle(
        'DoD',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.2,
        leading=9.2,
        textColor=c_primary,
        alignment=TA_LEFT
    )

    table_header = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.2,
        leading=9,
        textColor=colors.white
    )

    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=6.8,
        leading=8.4,
        textColor=c_primary
    )

    table_cell_dim = ParagraphStyle(
        'TableCellDim',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=6.8,
        leading=8.4,
        textColor=c_slate
    )

    story = []

    # Title & Subtitle Header
    story.append(Paragraph("SAFECONTAIN AI — HACKATHON FINAL BUILD PLAN", title_style))
    story.append(Paragraph("AI-Powered Cyber Defense Decision Intelligence & Business-Aware Containment | IIIT Delhi Hackathon Grand Finale", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.2, color=c_secondary, spaceAfter=4, spaceBefore=0))

    # 1. WHERE WE ARE
    story.append(Paragraph("1. WHERE WE ARE (CURRENT PROTOTYPE AUDIT — 50,937 LOC | 269/272 TESTS PASSING)", h2_style))
    
    audit_data = [
        [
            Paragraph("Domain", table_header),
            Paragraph("Verified Working Implementation", table_header),
            Paragraph("Synthetic vs. Mocked Reality", table_header),
            Paragraph("Honest Operational Limits", table_header)
        ],
        [
            Paragraph("<b>Graph Intel</b>", table_cell),
            Paragraph("Dijkstra attack path traversal; NetworkX dual-engine in-memory; Cytoscape interactive graph with real IP hover copy.", table_cell),
            Paragraph("120-node enterprise topology loaded from synthetic CSV (real IPs, hostnames, crown jewels).", table_cell_dim),
            Paragraph("AuraDB active; falls back to NetworkX under TLS proxy interception.", table_cell_dim)
        ],
        [
            Paragraph("<b>AI/ML Risk</b>", table_cell),
            Paragraph("Balanced Logistic Regression; 13 leak-free features; closed-form LinearExplainer SHAP; Platt calibration (θ*=0.58).", table_cell),
            Paragraph("Telemetry sequences generated via deterministic scenario generator.", table_cell_dim),
            Paragraph("Retraining tested on holdout; streaming continuous learning out-of-scope.", table_cell_dim)
        ],
        [
            Paragraph("<b>CP-SAT Solver</b>", table_cell),
            Paragraph("Google OR-Tools 0-1 ILP solver; integer-cent budget; hard zero-outage SLA constraints on critical citizen workflows.", table_cell),
            Paragraph("None (mathematical solver evaluates real candidate actions and real SLA models).", table_cell_dim),
            Paragraph("Physical OS kernel drivers (iptables/eBPF) not deployed; advisory decision model.", table_cell_dim)
        ],
        [
            Paragraph("<b>Trust & Audit</b>", table_cell),
            Paragraph("SHA-256 JSONL append-only hash chain; Merkle tree root validation; pure-Python EVM client; Solidity contract.", table_cell),
            Paragraph("None (local cryptographic chaining and Merkle proofs are 100% genuine).", table_cell_dim),
            Paragraph("Sepolia EVM testnet anchoring defaults to local verification if RPC is unset.", table_cell_dim)
        ],
        [
            Paragraph("<b>UI/UX & RBAC</b>", table_cell),
            Paragraph("Light Workspace (#F4F7FB/#FFFFFF); Deep Navy Sidebar (#10233F); 27 views; 3-tier RBAC (Admin, Analyst, Viewer).", table_cell),
            Paragraph("None (all 27 views actively bind to live REST backend responses).", table_cell_dim),
            Paragraph("Monolithic App.tsx (10k LOC) requires post-hackathon component modularization.", table_cell_dim)
        ]
    ]

    t_audit = Table(audit_data, colWidths=[65, 195, 155, 145])
    t_audit.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_primary),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, c_border),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, c_light_bg]),
        ('TOPPADDING', (0, 0), (-1, -1), 1.8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1.8),
    ]))
    story.append(t_audit)

    # 2. DEFINITION OF DONE CALLOUT BOX
    story.append(Paragraph("2. DEFINITION OF DONE", h2_style))
    dod_text = (
        "<b>Single Sentence Standard:</b> <i>\"SafeContain AI is complete for the hackathon when an evaluator can follow an "
        "active lateral threat from initial graph detection through calibrated ML risk explanation and early-warning forecasting, "
        "receive a mathematically optimal, SLA-preserving containment recommendation via Google OR-Tools CP-SAT, simulate the "
        "residual risk delta, and cryptographically verify the integrity of the decision ledger through a stable, presentation-ready enterprise dashboard.\"</i>"
    )
    dod_table = Table([[Paragraph(dod_text, dod_style)]], colWidths=[560])
    dod_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_callout_bg),
        ('BORDER', (0, 0), (-1, -1), 0.8, c_callout_border),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(dod_table)

    # 3. TARGET USER SEGMENTS & TECHNOLOGY FOCUS
    story.append(Paragraph("3. TARGET USER SEGMENTS & TECHNOLOGY FOCUS", h2_style))

    segments_data = [
        [
            Paragraph("Segment", table_header),
            Paragraph("Operational Pain Point", table_header),
            Paragraph("SafeContain AI Differentiator & Value Metric", table_header)
        ],
        [
            Paragraph("<b>Primary: SOC Analysts</b>", table_cell),
            Paragraph("Alert fatigue and fear of severing critical servers during attacks.", table_cell),
            Paragraph("<b>Graph Path Traversal & SHAP Attribution:</b> Visualizes lateral route and gives mathematical rationale for exact isolation in &lt; 2 minutes.", table_cell)
        ],
        [
            Paragraph("<b>SecOps / IT Infra</b>", table_cell),
            Paragraph("Blunt EDR isolates hosts blindly, collapsing mission-critical services.", table_cell),
            Paragraph("<b>OR-Tools CP-SAT SLA Engine:</b> Guarantees zero outage for critical workflows (SSO, Payment Gateway) under strict budget caps.", table_cell)
        ],
        [
            Paragraph("<b>CISOs & Regulators</b>", table_cell),
            Paragraph("Inability to justify containment costs or prove evidence integrity.", table_cell),
            Paragraph("<b>Business Twin & Cryptographic Ledger:</b> Translates risk into dollars saved, disruption scores, and SHA-256 / Merkle tamper proofs.", table_cell)
        ]
    ]

    t_seg = Table(segments_data, colWidths=[105, 195, 260])
    t_seg.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_secondary),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, c_border),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, c_light_bg]),
        ('TOPPADDING', (0, 0), (-1, -1), 1.8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1.8),
    ]))
    story.append(t_seg)

    # Technology Choice text
    tech_text = (
        "<b>Core Technology Deepening: Neo4j AuraDB & Graph Intelligence.</b> Cybersecurity threats are inherently relational graphs of credentials, network hops, and permissions. We deepen Neo4j to store and query multi-hop attack routes with NetworkX dual-engine resilience. "
        "<b>Excluded:</b> <i>Arduino</i> rejected as physical hardware introduces zero value to cloud SecOps; <i>Sarvam AI</i> excluded as our innovation is discrete mathematical optimization, not Indic NLP translation."
    )
    story.append(Paragraph(tech_text, body_style))

    # 4. FINAL SPRINT ROADMAP
    story.append(Paragraph("4. FINAL SPRINT ROADMAP & DEMONSTRATION DISCIPLINE", h2_style))

    sprint_data = [
        [
            Paragraph("Sprint Window", table_header),
            Paragraph("Focus Area", table_header),
            Paragraph("Key Technical Deliverables & Judge Milestones", table_header)
        ],
        [
            Paragraph("<b>Hours 00 - 04</b>", table_cell),
            Paragraph("Freeze & Baseline", table_cell),
            Paragraph("Lock backend API endpoints; verify 269 passing automated tests; ensure NetworkX dual-mode fallback is rock-solid.", table_cell_dim)
        ],
        [
            Paragraph("<b>Hours 04 - 10</b>", table_cell),
            Paragraph("UI/UX Polish", table_cell),
            Paragraph("Verify Light Theme (#F4F7FB) across all 5 demo screens; confirm prominent monospace IP tooltips & 1-click clipboard copy.", table_cell_dim)
        ],
        [
            Paragraph("<b>Hours 10 - 18</b>", table_cell),
            Paragraph("Golden Demo Flow", table_cell),
            Paragraph("Pre-stage 'Operation Sovereign Gateway': alert &rarr; attack graph &rarr; SHAP explainability &rarr; CP-SAT solver &rarr; Merkle audit check.", table_cell_dim)
        ],
        [
            Paragraph("<b>Hours 18 - 24</b>", table_cell),
            Paragraph("Pitch & Defense", table_cell),
            Paragraph("Rehearse 4-minute demo pitch; harden judge Q&A on class imbalance (~69% CV balanced acc) and solver feasibility; lock final bundle.", table_cell_dim)
        ]
    ]

    t_sprint = Table(sprint_data, colWidths=[75, 95, 390])
    t_sprint.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_primary),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, c_border),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, c_light_bg]),
        ('TOPPADDING', (0, 0), (-1, -1), 1.8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1.8),
    ]))
    story.append(t_sprint)

    # What We Will NOT Do Footer
    footer_text = (
        "<b>Final Strategy:</b> Integrate &rarr; Validate &rarr; Polish &rarr; Demonstrate &rarr; Win. "
        "<b>Strict Scope Discipline:</b> No architectural refactors; no mock data presented as live telemetry; no unverified live blockchain claims; no feature creep. Stability and proof over speculation."
    )
    story.append(Paragraph(footer_text, body_bold))

    doc.build(story)
    
    reader = pypdf.PdfReader(pdf_path)
    print(f"PDF build complete: {pdf_path} | Total pages: {len(reader.pages)}")

if __name__ == "__main__":
    build_pdf()
