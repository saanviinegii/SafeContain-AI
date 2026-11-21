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
        rightMargin=24,
        leftMargin=24,
        topMargin=18,
        bottomMargin=18
    )

    styles = getSampleStyleSheet()

    # Brand Colors matching Hackathon Prompt & SafeContain AI
    c_magenta = colors.HexColor("#7E22CE")   # Step Zero Magenta/Purple from rubric
    c_primary = colors.HexColor("#10233F")   # Deep Navy
    c_secondary = colors.HexColor("#0284C7") # Sky Cyan
    c_slate = colors.HexColor("#334155")     # Slate 700
    c_muted = colors.HexColor("#64748B")     # Slate 500
    c_light_bg = colors.HexColor("#F8FAFC")  # Crisp Table Alternating Row
    c_border = colors.HexColor("#CBD5E1")    # Slate 300
    c_callout_bg = colors.HexColor("#F5F3FF")# Purple 50
    c_callout_border = colors.HexColor("#C084FC")
    c_blue_callout = colors.HexColor("#EFF6FF")
    c_blue_border = colors.HexColor("#93C5FD")

    # Typography Styles
    step_zero_style = ParagraphStyle(
        'StepZero',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=12,
        textColor=c_magenta,
        spaceAfter=1
    )

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=13.5,
        leading=15.5,
        textColor=c_primary,
        alignment=TA_LEFT,
        spaceAfter=1
    )

    meta_style = ParagraphStyle(
        'MetaStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7,
        leading=8.5,
        textColor=c_muted,
        spaceAfter=3
    )

    h2_style = ParagraphStyle(
        'H2Style',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=9.5,
        textColor=c_primary,
        spaceBefore=3,
        spaceAfter=1.5
    )

    table_header = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=6.8,
        leading=8.2,
        textColor=colors.white
    )

    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=6.5,
        leading=7.8,
        textColor=c_primary
    )

    table_cell_dim = ParagraphStyle(
        'TableCellDim',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=6.5,
        leading=7.8,
        textColor=c_slate
    )

    body_text = ParagraphStyle(
        'BodyText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=6.6,
        leading=8,
        textColor=c_slate
    )

    dod_style = ParagraphStyle(
        'DoDStyle',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=7,
        leading=8.8,
        textColor=c_primary
    )

    story = []

    # Title Banner (Explicitly Matching Hackathon Submission Prompt)
    story.append(Paragraph("STEP ZERO: PRODUCT AUDIT AND FINALE BUILD PLAN", step_zero_style))
    story.append(Paragraph("SafeContain AI — AI Cyber Defense Decision Intelligence & Business-Aware Containment", title_style))
    story.append(Paragraph("<b>Evaluation Yardstick:</b> Scored Rounds 1 & 2 | <b>Due:</b> 4 PM on 21 November | <b>Target Finale Delivery:</b> 12 PM on 22 November | <b>Codebase:</b> 50,937 LOC (269/272 Tests Passing)", meta_style))
    story.append(HRFlowable(width="100%", thickness=1.2, color=c_magenta, spaceAfter=3, spaceBefore=0))

    # =========================================================================
    # POINT 1: WHERE YOU ARE
    # =========================================================================
    story.append(Paragraph("1. WHERE YOU ARE: What Works in Prototype Today vs. Mocked, Hardcoded or Missing", h2_style))
    
    where_we_are_data = [
        [
            Paragraph("Core Subsystem", table_header),
            Paragraph("What Works in Prototype Today (Verified)", table_header),
            Paragraph("What is Synthetic vs. Mocked", table_header),
            Paragraph("What is Missing / Limitations", table_header)
        ],
        [
            Paragraph("<b>Graph Intelligence</b>", table_cell),
            Paragraph("Dijkstra attack traversal; NetworkX dual-engine in-memory; Cytoscape interactive graph with real IP hover copy.", table_cell),
            Paragraph("120-node enterprise topology loaded from synthetic CSV (real IPs, hostnames, crown jewels).", table_cell_dim),
            Paragraph("AuraDB active; falls back to NetworkX under corporate TLS proxy interception.", table_cell_dim)
        ],
        [
            Paragraph("<b>AI/ML Risk Intelligence</b>", table_cell),
            Paragraph("Balanced Logistic Regression; 13 leak-free features; closed-form LinearExplainer SHAP; Platt calibration (θ*=0.58).", table_cell),
            Paragraph("Telemetry event sequences generated via deterministic enterprise scenario loader.", table_cell_dim),
            Paragraph("Retraining tested on holdout; live continuous streaming online retraining out-of-scope.", table_cell_dim)
        ],
        [
            Paragraph("<b>Containment Solver</b>", table_cell),
            Paragraph("Google OR-Tools 0-1 ILP CP-SAT solver; exact integer-cent budget; hard zero-outage SLA constraints on critical workflows.", table_cell),
            Paragraph("None (mathematical solver optimizes real candidate actions and real SLA models).", table_cell_dim),
            Paragraph("Host OS kernel drivers (iptables/eBPF) not deployed; operates as decision advisory platform.", table_cell_dim)
        ],
        [
            Paragraph("<b>Trust & Audit Ledger</b>", table_cell),
            Paragraph("SHA-256 JSONL append-only hash chain; Merkle tree root validation; pure-Python EVM client; Solidity smart contract.", table_cell),
            Paragraph("None (local cryptographic chaining and Merkle verification are 100% genuine).", table_cell_dim),
            Paragraph("Sepolia EVM testnet anchoring defaults to local verification if RPC is unconfigured.", table_cell_dim)
        ],
        [
            Paragraph("<b>UI/UX & Security</b>", table_cell),
            Paragraph("Light Workspace (#F4F7FB/#FFFFFF); Deep Navy Sidebar (#10233F); 27 views; 3-tier RBAC (Admin, Analyst, Viewer).", table_cell),
            Paragraph("None (all 27 views actively bind to live REST backend responses).", table_cell_dim),
            Paragraph("Monolithic App.tsx (10k LOC) requires post-hackathon component modularization.", table_cell_dim)
        ]
    ]

    t_where = Table(where_we_are_data, colWidths=[70, 190, 155, 149])
    t_where.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_primary),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, c_border),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, c_light_bg]),
        ('TOPPADDING', (0, 0), (-1, -1), 1.2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1.2),
    ]))
    story.append(t_where)

    # =========================================================================
    # POINT 2: WHERE YOU WILL BE BY 12 PM ON 22 NOVEMBER
    # =========================================================================
    story.append(Paragraph("2. WHERE YOU WILL BE: Exact Features, Flows & Integrations Working by 12 PM on 22 November", h2_style))
    
    where_will_be_data = [
        [
            Paragraph("Delivery Pillar", table_header),
            Paragraph("Exact Working Deliverable by 12 PM on 22 November", table_header),
            Paragraph("Demonstration & Judge Verification Proof", table_header)
        ],
        [
            Paragraph("<b>Unified Golden Flow</b>", table_cell),
            Paragraph("End-to-end cyber containment: Alert &rarr; Graph traversal &rarr; SHAP attribution &rarr; CP-SAT solver &rarr; Merkle audit check.", table_cell),
            Paragraph("Complete walkthrough of 'Operation Sovereign Gateway' lateral breach scenario in &lt; 3 mins.", table_cell_dim)
        ],
        [
            Paragraph("<b>Zero-Fail Resilience</b>", table_cell),
            Paragraph("Dual-engine graph synchronization: live Neo4j AuraDB with seamless in-memory NetworkX failover.", table_cell),
            Paragraph("Zero demo crashes even if conference Wi-Fi disconnects or TLS proxy blocks Bolt port.", table_cell_dim)
        ],
        [
            Paragraph("<b>Enterprise UI/UX</b>", table_cell),
            Paragraph("Light SecOps workspace (#F4F7FB) with deep navy sidebar (#10233F) and interactive Cytoscape canvas.", table_cell),
            Paragraph("Live node hover tooltip displaying prominent monospace IP address with 1-click clipboard copy.", table_cell_dim)
        ],
        [
            Paragraph("<b>Evidence Anchoring</b>", table_cell),
            Paragraph("Deterministic SHA-256 ledger chaining with real-time Merkle proof verification and tamper detection.", table_cell),
            Paragraph("Interactive tamper demo showing hash invalidation upon unauthorized data modification.", table_cell_dim)
        ]
    ]

    t_will_be = Table(where_will_be_data, colWidths=[80, 240, 244])
    t_will_be.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_secondary),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, c_border),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, c_light_bg]),
        ('TOPPADDING', (0, 0), (-1, -1), 1.2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1.2),
    ]))
    story.append(t_will_be)

    # =========================================================================
    # POINT 3: YOUR USER SEGMENTS
    # =========================================================================
    story.append(Paragraph("3. YOUR USER SEGMENTS: Primary Segment Plus Two Additional Segments", h2_style))

    segments_data = [
        [
            Paragraph("User Segment", table_header),
            Paragraph("Critical Operational Pain Point", table_header),
            Paragraph("SafeContain AI Value Metric & Solution", table_header)
        ],
        [
            Paragraph("<b>PRIMARY:<br/>SOC Analysts & Triage</b>", table_cell),
            Paragraph("Alert fatigue & analysis paralysis: fear of taking down critical production servers during active lateral intrusions.", table_cell),
            Paragraph("<b>Attack Graph & SHAP Attribution:</b> Visualizes lateral route and gives exact mathematical rationale for isolation in &lt; 2 minutes.", table_cell)
        ],
        [
            Paragraph("<b>SECONDARY 1:<br/>IT & Infrastructure SecOps</b>", table_cell),
            Paragraph("Blunt EDR isolation breaks mission-critical dependencies, collapsing citizen services and violating strict SLAs.", table_cell),
            Paragraph("<b>OR-Tools CP-SAT SLA Engine:</b> Guarantees zero outage for critical workflows (Payment Gateway, SSO) under hard budget caps.", table_cell)
        ],
        [
            Paragraph("<b>SECONDARY 2:<br/>CISOs & Enterprise Risk</b>", table_cell),
            Paragraph("Inability to quantify financial risk reduction, justify response disruption costs, or prove regulatory audit compliance.", table_cell),
            Paragraph("<b>Business Twin & Cryptographic Ledger:</b> Translates risk into dollars saved, disruption scores, and immutable SHA-256 / Merkle proofs.", table_cell)
        ]
    ]

    t_seg = Table(segments_data, colWidths=[90, 220, 254])
    t_seg.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_primary),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, c_border),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, c_light_bg]),
        ('TOPPADDING', (0, 0), (-1, -1), 1.2),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1.2),
    ]))
    story.append(t_seg)

    # =========================================================================
    # POINT 4: YOUR PARTNER TECH CHOICE
    # =========================================================================
    story.append(Paragraph("4. YOUR PARTNER TECH CHOICE: Deepening Neo4j & Product Need Solved (vs. Exclusions)", h2_style))
    
    partner_text = (
        "• <b>Primary Partner Choice: Deepening Neo4j (Neo4j AuraDB & Graph Intelligence).</b> "
        "<b>Product Need Solved:</b> Cyber attacks are inherently relational graphs of compromised identities, credential reuse, and network hops. "
        "Tabular SQL databases cannot efficiently evaluate multi-hop transitive lateral movement. Neo4j powers our asset relationship mapping, "
        "Cypher graph traversals, and critical attack path synthesis, synchronized with an in-memory NetworkX engine for zero-fail resilience.<br/>"
        "• <b>Why We Do NOT Add Arduino:</b> SafeContain AI is a pure cloud/enterprise software decision platform. Introducing physical microcontrollers "
        "would be an artificial hackathon gimmick that adds hardware failure points without solving an enterprise cybersecurity problem.<br/>"
        "• <b>Why We Do NOT Add Sarvam AI:</b> Our core innovation is discrete mathematical optimization (0-1 ILP) and leak-free ML risk classification. "
        "Forcing Indic natural language translation would distract from our core decision-intelligence value proposition."
    )
    
    p_box = Table([[Paragraph(partner_text, body_text)]], colWidths=[564])
    p_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_callout_bg),
        ('BORDER', (0, 0), (-1, -1), 0.8, c_callout_border),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
    ]))
    story.append(p_box)

    # =========================================================================
    # POINT 5: YOUR DEFINITION OF DONE
    # =========================================================================
    story.append(Paragraph("5. YOUR DEFINITION OF DONE (One Powerful Sentence)", h2_style))
    
    dod_text = (
        "<b>\"SafeContain AI is complete for the hackathon when an evaluator can follow an active lateral threat from initial graph detection "
        "through calibrated ML risk explanation and early-warning forecasting, receive a mathematically optimal, SLA-preserving containment "
        "recommendation via Google OR-Tools CP-SAT, simulate the residual risk delta, and cryptographically verify the integrity of the decision "
        "ledger through a stable, presentation-ready enterprise dashboard.\"</b>"
    )
    
    dod_box = Table([[Paragraph(dod_text, dod_style)]], colWidths=[564])
    dod_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_blue_callout),
        ('BORDER', (0, 0), (-1, -1), 0.8, c_blue_border),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
    ]))
    story.append(dod_box)

    # Strategy Footer
    footer_text = (
        "<b>Execution Strategy:</b> Integrate &rarr; Validate &rarr; Polish &rarr; Demonstrate &rarr; Win. | "
        "<b>Strict Scope Discipline:</b> No architecture rewrites; no fake 99.9% accuracy claims; no unverified live blockchain claims. Stability and verified proof over speculation."
    )
    story.append(Spacer(1, 1))
    story.append(Paragraph(footer_text, ParagraphStyle('Foot', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=6.2, leading=7.5, textColor=c_primary)))

    doc.build(story)
    
    reader = pypdf.PdfReader(pdf_path)
    print(f"PDF build complete: {pdf_path} | Total pages: {len(reader.pages)}")

if __name__ == "__main__":
    build_pdf()
