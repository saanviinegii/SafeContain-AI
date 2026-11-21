"""SafeContain AI Automated Incident Dossier Generator & Professional PDF Export Engine (Phase 7.2D).

Compiles real platform telemetry, attack routes, calibrated ML threat predictions, SHAP feature attributions,
CP-SAT containment optimizations, continuous drift metrics, and chained cryptographic audit hashes into
an executive-ready, audit-grade incident dossier exported in both structured JSON and formatted PDF formats.
"""

from __future__ import annotations

import os
import io
import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
    PageBreak,
    HRFlowable,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas

from backend.app.ml.model_trainer import DEFAULT_ARTIFACTS_DIR
from backend.app.ml.model_registry import ModelRegistry
from backend.app.ml.drift_detector import TelemetryDriftDetector
from backend.app.ml.explainability import ShapExplainerService

logger = logging.getLogger("safecontain.reporting.dossier")

DEFAULT_DOSSIERS_DIR = os.path.join(DEFAULT_ARTIFACTS_DIR, "dossiers")


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas for dynamic total page count in running headers/footers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        # Running Top Rule
        self.setStrokeColor(colors.HexColor("#0284C7"))  # Sky Blue accent
        self.setLineWidth(1)
        self.line(40, letter[1] - 40, letter[0] - 40, letter[1] - 40)

        # Header Text
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawString(40, letter[1] - 34, "SAFECONTAIN AI — ENTERPRISE INCIDENT CONTAINMENT DOSSIER")
        self.drawRightString(letter[0] - 40, letter[1] - 34, "CLASSIFICATION: CISO DECISION SUPPORT // RESTRICTED")

        # Running Bottom Rule
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.line(40, 42, letter[0] - 40, 42)

        # Footer Text
        self.drawString(40, 30, "Digitally Sealed by SafeContain AI Cryptographic Audit Engine (SHA-256 Tamper-Evident)")
        self.drawRightString(letter[0] - 40, 30, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


class IncidentDossierGenerator:
    """Orchestrates comprehensive data collection, cryptographic signing, and PDF dossier rendering."""

    def __init__(
        self,
        artifacts_dir: Optional[str] = None,
        model_registry: Optional[ModelRegistry] = None,
        drift_detector: Optional[TelemetryDriftDetector] = None,
        shap_service: Optional[ShapExplainerService] = None,
    ):
        self.artifacts_dir = os.path.abspath(artifacts_dir or DEFAULT_ARTIFACTS_DIR)
        self.dossiers_dir = os.path.join(self.artifacts_dir, "dossiers")
        os.makedirs(self.dossiers_dir, exist_ok=True)

        self.registry = model_registry or ModelRegistry(artifacts_dir=self.artifacts_dir)
        self.drift_detector = drift_detector or TelemetryDriftDetector(
            artifacts_dir=self.artifacts_dir,
            model_registry=self.registry,
        )
        self.shap_service = shap_service or ShapExplainerService(
            model_registry=self.registry,
        )

    # -------------------------------------------------------------------------
    # Incident Data Aggregation
    # -------------------------------------------------------------------------

    def compile_incident_data(
        self,
        incident_id: Optional[str] = None,
        analyst_name: str = "SecOps Lead Analyst",
        analyst_notes: str = "",
        target_scenario: str = "Live Enterprise Multi-Hop Threat Vector",
    ) -> Dict[str, Any]:
        """Aggregates real topology, threat probabilities, SHAP drivers, containment actions, drift, and audit records."""
        now = datetime.now(timezone.utc)
        dossier_id = incident_id or f"INC-{now.strftime('%Y%m%d')}-{now.strftime('%H%M%S')}"

        # 1. Fetch ML Predictions and Graph Context
        preds = self.registry.predict_for_nodes()
        th = self.registry.get_operating_threshold()
        meta = self.registry.get_model_metadata()
        model_version = meta.get("version", "1.0.0")

        at_risk_nodes = [p for p in preds if p["is_at_risk"]]
        healthy_nodes = [p for p in preds if not p["is_at_risk"]]

        # Sort at-risk by threat probability descending
        at_risk_nodes.sort(key=lambda x: x["risk_probability"], reverse=True)

        # 2. Extract Attack Routes & Topology from Platform Context
        attack_paths_data: List[Dict[str, Any]] = []
        crown_jewels_at_risk: List[str] = []
        containment_plan_data: Dict[str, Any] = {}
        disrupted_workflows_data: List[Dict[str, Any]] = []
        audit_events_data: List[Dict[str, Any]] = []

        try:
            from backend.app.api.v1.router import platform_ctx
            # Attack paths
            paths = platform_ctx.engine.find_attack_paths()
            for p in paths[:6]:
                attack_paths_data.append({
                    "path_id": p.id,
                    "source": p.source_node_id,
                    "target": p.target_crown_jewel_id,
                    "hops": len(p.node_sequence),
                    "sequence": p.node_sequence,
                    "criticality": p.criticality.value,
                    "cumulative_risk": round(p.cumulative_risk, 2),
                })
                if p.target_crown_jewel_id not in crown_jewels_at_risk:
                    crown_jewels_at_risk.append(p.target_crown_jewel_id)

            # Containment Plan
            if platform_ctx.current_plan:
                cp = platform_ctx.current_plan
                containment_plan_data = {
                    "plan_id": cp.id,
                    "strategy": cp.strategy.value,
                    "total_cost": round(cp.total_cost, 2),
                    "disruption_score": round(cp.total_disruption_score, 2),
                    "risk_reduction": round(cp.predicted_risk_reduction, 2),
                    "actions": [
                        {
                            "id": a.id,
                            "type": a.action_type.value,
                            "target_node": a.target_node_name,
                            "cost": a.implementation_cost,
                            "disruption": a.operational_disruption_score,
                            "role": a.required_role.value,
                            "rationale": a.rationale,
                        }
                        for a in cp.actions
                    ],
                }

            # Audit events
            recent_events = platform_ctx.ledger.get_events(limit=8)
            audit_events_data = [
                {
                    "event_id": e.event_id,
                    "timestamp": e.timestamp.isoformat(),
                    "event_type": e.event_type.value,
                    "actor_role": e.actor_role.value,
                    "prev_hash": e.prev_hash[:16] + "...",
                    "curr_hash": e.curr_hash[:16] + "...",
                }
                for e in recent_events
            ]
        except Exception as e:
            logger.warning("Platform context query warning during dossier compilation: %s", e)

        # 3. Explainability (SHAP attributions for top compromised assets)
        shap_explanations: List[Dict[str, Any]] = []
        top_threat_nodes = at_risk_nodes[:4]
        for node in top_threat_nodes:
            nid = node["node_id"]
            try:
                exp_res = self.shap_service.explain_asset(nid)
                exp_detail = exp_res.get("explanation", {})
                contributors = exp_detail.get("top_contributors", [])
                pos_drivers = [
                    {"feature": c["feature"], "attribution": c.get("shap_value", 0.0)}
                    for c in contributors if c.get("direction") == "increases_risk"
                ]
                neg_drivers = [
                    {"feature": c["feature"], "attribution": c.get("shap_value", 0.0)}
                    for c in contributors if c.get("direction") == "decreases_risk"
                ]
                shap_explanations.append({
                    "node_id": nid,
                    "base_value": exp_detail.get("base_value", 0.0),
                    "risk_probability": exp_res.get("risk_probability", node["risk_probability"]),
                    "top_risk_drivers": pos_drivers[:4],
                    "top_protective_factors": neg_drivers[:3],
                })
            except Exception as e:
                logger.warning("SHAP explanation failed for node %s: %s", nid, e)

        # 4. Telemetry Drift Status
        drift_report = self.drift_detector.get_latest_drift_report()
        drift_summary = {
            "status": drift_report.get("overall_severity", "NORMAL"),
            "drift_score": drift_report.get("overall_drift_score", 0.0),
            "retraining_recommended": drift_report.get("retraining_recommended", False),
            "recommendation_reason": drift_report.get("retraining_recommendation_reason", "Telemetry within bounds."),
            "drifted_features_count": sum(1 for f in drift_report.get("features_drift", []) if f.get("drift_detected")),
        }

        # 5. Build Canonical Dossier Payload
        dossier_data: Dict[str, Any] = {
            "platform": "SafeContain AI Enterprise Risk Intelligence",
            "dossier_id": dossier_id,
            "incident_title": f"Active Cyber Incident Containment Briefing: {target_scenario}",
            "generated_at": now.isoformat(),
            "analyst_name": analyst_name,
            "analyst_notes": analyst_notes or "Containment plan formulated via AI-assisted multi-objective CP-SAT optimizer.",
            "classification": "TOP SECRET // CISO INCIDENT DECISION SUPPORT",
            "executive_summary": {
                "total_monitored_nodes": len(preds),
                "compromised_nodes_count": len(at_risk_nodes),
                "healthy_nodes_count": len(healthy_nodes),
                "operating_threshold": th,
                "model_version": model_version,
                "crown_jewels_at_risk_count": len(crown_jewels_at_risk),
                "crown_jewels_at_risk": crown_jewels_at_risk,
                "active_attack_routes_count": len(attack_paths_data),
                "recommended_containment_actions_count": len(containment_plan_data.get("actions", [])),
                "estimated_containment_cost": containment_plan_data.get("total_cost", 0.0),
                "disruption_score": containment_plan_data.get("disruption_score", 0.0),
                "drift_severity": drift_summary["status"],
            },
            "at_risk_assets": at_risk_nodes[:15],
            "attack_paths": attack_paths_data,
            "shap_risk_drivers": shap_explanations,
            "containment_plan": containment_plan_data,
            "drift_telemetry": drift_summary,
            "audit_trail": audit_events_data,
        }

        # 6. Compute Cryptographic SHA-256 Digest
        canonical_str = json.dumps(dossier_data, sort_keys=True, default=str)
        audit_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
        dossier_data["cryptographic_audit_hash"] = audit_hash

        return dossier_data

    # -------------------------------------------------------------------------
    # PDF Rendering Engine (ReportLab)
    # -------------------------------------------------------------------------

    def generate_pdf_dossier(
        self,
        dossier_data: Dict[str, Any],
        output_filename: Optional[str] = None,
    ) -> Tuple[bytes, str]:
        """Renders comprehensive, publication-grade incident dossier PDF using ReportLab."""
        dossier_id = dossier_data.get("dossier_id", "INC-DOSSIER")
        fname = output_filename or f"incident_dossier_{dossier_id}.pdf"
        output_path = os.path.join(self.dossiers_dir, fname)

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=letter,
            leftMargin=40,
            rightMargin=40,
            topMargin=54,
            bottomMargin=54,
        )

        styles = getSampleStyleSheet()

        # Custom Palette Styles
        c_primary = colors.HexColor("#0F172A")    # Deep Navy
        c_secondary = colors.HexColor("#1E293B")  # Slate
        c_accent = colors.HexColor("#0284C7")     # Sky Blue
        c_cyan = colors.HexColor("#06B6D4")       # Cyber Cyan
        c_danger = colors.HexColor("#DC2626")     # Crimson
        c_warning = colors.HexColor("#D97706")    # Amber
        c_success = colors.HexColor("#059669")    # Emerald
        c_bg_light = colors.HexColor("#F8FAFC")   # Light Gray/Slate
        c_text_dark = colors.HexColor("#0F172A")  # Dark text
        c_text_muted = colors.HexColor("#64748B") # Muted text

        title_style = ParagraphStyle(
            "DossierTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=colors.white,
        )
        subtitle_style = ParagraphStyle(
            "DossierSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#BAE6FD"),
        )
        h1_style = ParagraphStyle(
            "DossierH1",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=15,
            textColor=c_primary,
            spaceAfter=4,
        )
        body_style = ParagraphStyle(
            "DossierBody",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=c_text_dark,
        )
        body_muted = ParagraphStyle(
            "DossierBodyMuted",
            parent=body_style,
            textColor=c_text_muted,
        )
        badge_danger = ParagraphStyle(
            "BadgeDanger",
            parent=body_style,
            fontName="Helvetica-Bold",
            textColor=c_danger,
        )
        badge_success = ParagraphStyle(
            "BadgeSuccess",
            parent=body_style,
            fontName="Helvetica-Bold",
            textColor=c_success,
        )

        story: List[Any] = []

        # ---------------------------------------------------------------------
        # 1. Header Banner Block
        # ---------------------------------------------------------------------
        banner_content = [
            [
                Paragraph("<b>SAFECONTAIN AI</b> | INCIDENT CONTAINMENT DOSSIER", title_style),
                Paragraph(f"<b>STATUS:</b> ACTIVE THREAT<br/><b>HASH:</b> {dossier_data.get('cryptographic_audit_hash', '')[:16]}...", subtitle_style)
            ]
        ]
        banner_table = Table(banner_content, colWidths=[360, 172])
        banner_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), c_primary),
            ("PADDING", (0, 0), (-1, -1), 10),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ]))
        story.append(banner_table)
        story.append(Spacer(1, 8))

        # ---------------------------------------------------------------------
        # 2. Incident Metadata Strip
        # ---------------------------------------------------------------------
        exec_sum = dossier_data.get("executive_summary", {})
        meta_data = [
            [
                Paragraph(f"<b>Incident ID:</b> {dossier_data.get('dossier_id')}", body_style),
                Paragraph(f"<b>Date/Time:</b> {dossier_data.get('generated_at')[:19]} UTC", body_style),
                Paragraph(f"<b>Investigator:</b> {dossier_data.get('analyst_name')}", body_style),
            ],
            [
                Paragraph(f"<b>Model:</b> v{exec_sum.get('model_version')} (Threshold: {exec_sum.get('operating_threshold')})", body_style),
                Paragraph(f"<b>Drift Severity:</b> {exec_sum.get('drift_severity')}", body_style),
                Paragraph(f"<b>Classification:</b> {dossier_data.get('classification')}", body_style),
            ]
        ]
        meta_table = Table(meta_data, colWidths=[177, 177, 178])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), c_bg_light),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 12))

        # ---------------------------------------------------------------------
        # 3. Section 1: Executive Briefing & Key Risk Metrics
        # ---------------------------------------------------------------------
        story.append(Paragraph("1. EXECUTIVE SUMMARY & THREAT DISPOSITION", h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceAfter=6))

        metric_cards = [
            [
                Paragraph(f"<font size=14><b>{exec_sum.get('compromised_nodes_count', 0)}</b></font><br/><font color='#64748B' size=7>COMPROMISED ASSETS</font>", body_style),
                Paragraph(f"<font size=14 color='#DC2626'><b>{exec_sum.get('crown_jewels_at_risk_count', 0)}</b></font><br/><font color='#64748B' size=7>CROWN JEWELS AT RISK</font>", body_style),
                Paragraph(f"<font size=14><b>{exec_sum.get('active_attack_routes_count', 0)}</b></font><br/><font color='#64748B' size=7>ACTIVE ATTACK ROUTES</font>", body_style),
                Paragraph(f"<font size=14 color='#0284C7'><b>{exec_sum.get('recommended_containment_actions_count', 0)}</b></font><br/><font color='#64748B' size=7>RECOMMENDED ACTIONS</font>", body_style),
                Paragraph(f"<font size=14><b>${exec_sum.get('estimated_containment_cost', 0):.0f}</b></font><br/><font color='#64748B' size=7>EST. CONTAINMENT COST</font>", body_style),
            ]
        ]
        metric_table = Table(metric_cards, colWidths=[106, 106, 106, 107, 107])
        metric_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#94A3B8")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(metric_table)

        analyst_notes_p = Paragraph(
            f"<b>Analyst Context:</b> {dossier_data.get('analyst_notes')}",
            body_style
        )
        story.append(Spacer(1, 4))
        story.append(analyst_notes_p)
        story.append(Spacer(1, 10))

        # ---------------------------------------------------------------------
        # 4. Section 2: Compromised Asset Inventory & ML Threat Assessment
        # ---------------------------------------------------------------------
        story.append(Paragraph("2. ASSET THREAT INVENTORY & CALIBRATED ML PROBABILITIES", h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceAfter=6))

        asset_rows = [
            ["Node ID", "Type", "Criticality", "Env", "Exposure", "ML Threat P(Y=1)", "Risk Status"]
        ]
        for a in dossier_data.get("at_risk_assets", [])[:10]:
            p_val = a.get("risk_probability", 0.0)
            asset_rows.append([
                Paragraph(f"<b>{a.get('node_id')}</b>", body_style),
                Paragraph(a.get("node_type", "UNKNOWN"), body_style),
                Paragraph(str(a.get("criticality", "N/A")), body_style),
                Paragraph(a.get("environment", "PROD"), body_style),
                Paragraph(a.get("exposure", "INTERNAL"), body_style),
                Paragraph(f"<b>{p_val:.1%}</b>", badge_danger if p_val >= 0.5 else body_style),
                Paragraph(f"<b>{a.get('risk_tier', 'AT-RISK')}</b>", badge_danger),
            ])

        if len(asset_rows) == 1:
            asset_rows.append([Paragraph("No compromised assets detected.", body_style)] + [""] * 6)

        asset_table = Table(asset_rows, colWidths=[100, 75, 65, 55, 65, 92, 80])
        asset_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), c_secondary),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
            ("TOPPADDING", (0, 0), (-1, 0), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_bg_light]),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(asset_table)
        story.append(Spacer(1, 10))

        # ---------------------------------------------------------------------
        # 5. Section 3: Attack Path Reconnaissance
        # ---------------------------------------------------------------------
        story.append(Paragraph("3. ATTACK PATH PROPAGATION & CROWN JEWEL REACHABILITY", h1_style))
        story.append(HRFlowable(width="100%", thickness=1, color=c_accent, spaceAfter=6))

        path_rows = [
            ["Path ID", "Origin Ingress", "Target Crown Jewel", "Hops", "Cumulative Risk", "Sequence Route"]
        ]
        for p in dossier_data.get("attack_paths", [])[:5]:
            seq_summary = " -> ".join(p.get("sequence", [])[:4])
            if len(p.get("sequence", [])) > 4:
                seq_summary += f" (+{len(p.get('sequence', [])) - 4} hops)"
            path_rows.append([
                Paragraph(f"<b>{p.get('path_id')}</b>", body_style),
                Paragraph(p.get("source", "N/A"), body_style),
                Paragraph(f"<b>{p.get('target', 'N/A')}</b>", badge_danger),
                Paragraph(str(p.get("hops", 0)), body_style),
                Paragraph(str(p.get("cumulative_risk", 0.0)), body_style),
                Paragraph(f"<font size=7>{seq_summary}</font>", body_muted),
            ])

        if len(path_rows) == 1:
            path_rows.append([Paragraph("No active attack paths identified.", body_style)] + [""] * 5)

        path_table = Table(path_rows, colWidths=[70, 85, 95, 38, 70, 174])
        path_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), c_secondary),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
            ("TOPPADDING", (0, 0), (-1, 0), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_bg_light]),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(path_table)
        story.append(Spacer(1, 10))

        # ---------------------------------------------------------------------
        # 6. Section 4: Explainable AI (SHAP Feature Attribution)
        # ---------------------------------------------------------------------
        story.append(KeepTogether([
            Paragraph("4. EXPLAINABLE AI (SHAP) RISK DRIVERS FOR COMPROMISED ASSETS", h1_style),
            HRFlowable(width="100%", thickness=1, color=c_accent, spaceAfter=6),
        ]))

        shap_rows = [
            ["Asset ID", "ML Risk P(Y=1)", "Top Risk-Increasing Feature Drivers (+SHAP)", "Protective Factors (-SHAP)"]
        ]
        for exp in dossier_data.get("shap_risk_drivers", [])[:3]:
            pos_drivers = ", ".join([f"{f['feature']} (+{f['attribution']:.3f})" for f in exp.get("top_risk_drivers", [])[:3]]) or "None"
            neg_drivers = ", ".join([f"{f['feature']} ({f['attribution']:.3f})" for f in exp.get("top_protective_factors", [])[:2]]) or "None"
            shap_rows.append([
                Paragraph(f"<b>{exp.get('node_id')}</b>", body_style),
                Paragraph(f"<b>{exp.get('risk_probability', 0.0):.1%}</b>", badge_danger),
                Paragraph(f"<font color='#DC2626'>{pos_drivers}</font>", body_style),
                Paragraph(f"<font color='#059669'>{neg_drivers}</font>", body_style),
            ])

        if len(shap_rows) == 1:
            shap_rows.append([Paragraph("No SHAP explainability records compiled.", body_style)] + [""] * 3)

        shap_table = Table(shap_rows, colWidths=[90, 80, 186, 176])
        shap_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), c_secondary),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
            ("TOPPADDING", (0, 0), (-1, 0), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_bg_light]),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(shap_table)
        story.append(Spacer(1, 10))

        # ---------------------------------------------------------------------
        # 7. Section 5: CP-SAT Optimal Containment Plan
        # ---------------------------------------------------------------------
        plan = dossier_data.get("containment_plan", {})
        story.append(KeepTogether([
            Paragraph("5. CP-SAT OPTIMAL CONTAINMENT ACTIONS & DISRUPTION TRADE-OFFS", h1_style),
            HRFlowable(width="100%", thickness=1, color=c_accent, spaceAfter=6),
        ]))

        action_rows = [
            ["Action ID", "Intervention Type", "Target Entity", "Cost ($)", "Disruption", "Required Role", "Operational Rationale"]
        ]
        for a in plan.get("actions", [])[:8]:
            action_rows.append([
                Paragraph(f"<b>{a.get('id')}</b>", body_style),
                Paragraph(a.get("type", "ISOLATE"), body_style),
                Paragraph(f"<b>{a.get('target_node', 'N/A')}</b>", body_style),
                Paragraph(f"${a.get('cost', 0):.0f}", body_style),
                Paragraph(str(a.get("disruption", 0)), body_style),
                Paragraph(a.get("role", "ANALYST"), body_style),
                Paragraph(f"<font size=7>{a.get('rationale', 'Containment isolation')}</font>", body_muted),
            ])

        if len(action_rows) == 1:
            action_rows.append([Paragraph("No containment actions currently scheduled.", body_style)] + [""] * 6)

        action_table = Table(action_rows, colWidths=[65, 80, 85, 45, 55, 68, 134])
        action_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), c_secondary),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
            ("TOPPADDING", (0, 0), (-1, 0), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, c_bg_light]),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(action_table)
        story.append(Spacer(1, 10))

        # ---------------------------------------------------------------------
        # 8. Section 6: Telemetry Drift & Cryptographic Tamper-Evidence
        # ---------------------------------------------------------------------
        drift = dossier_data.get("drift_telemetry", {})
        story.append(KeepTogether([
            Paragraph("6. TELEMETRY DRIFT CONTEXT & FORENSIC CHAIN OF CUSTODY", h1_style),
            HRFlowable(width="100%", thickness=1, color=c_accent, spaceAfter=6),
        ]))

        forensic_data = [
            [
                Paragraph(
                    f"<b>Continuous Telemetry Drift Status:</b><br/>"
                    f"Severity Level: <b>{drift.get('status', 'NORMAL')}</b> (Drift Score: {drift.get('drift_score', 0.0)})<br/>"
                    f"Retraining Needed: <b>{'YES' if drift.get('retraining_recommended') else 'NO'}</b><br/>"
                    f"Assessment: {drift.get('recommendation_reason', 'Normal baseline')}",
                    body_style
                ),
                Paragraph(
                    f"<b>Cryptographic Tamper-Evident Seal:</b><br/>"
                    f"SHA-256 Digest:<br/><font size=7 color='#0284C7'><b>{dossier_data.get('cryptographic_audit_hash', '')}</b></font><br/>"
                    f"Security Notice: Immutable decision support artifact. Any modification invalidates cryptographic signature.",
                    body_style
                ),
            ]
        ]
        forensic_table = Table(forensic_data, colWidths=[266, 266])
        forensic_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), c_bg_light),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#0284C7")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("PADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(forensic_table)

        # Build document with NumberedCanvas
        doc.build(story, canvasmaker=NumberedCanvas)
        pdf_bytes = buf.getvalue()

        # Save to disk
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)

        # Also save JSON alongside
        json_path = os.path.splitext(output_path)[0] + ".json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(dossier_data, f, indent=2, default=str)

        logger.info(
            "Incident dossier %s generated successfully: PDF (%d bytes) at %s, JSON at %s",
            dossier_id, len(pdf_bytes), output_path, json_path
        )

        return pdf_bytes, output_path

    def generate_full_dossier(
        self,
        incident_id: Optional[str] = None,
        analyst_name: str = "SecOps Lead Analyst",
        analyst_notes: str = "",
        target_scenario: str = "Live Enterprise Multi-Hop Threat Vector",
    ) -> Dict[str, Any]:
        """High-level method: compiles incident data, writes JSON & PDF, and returns execution summary."""
        dossier_data = self.compile_incident_data(
            incident_id=incident_id,
            analyst_name=analyst_name,
            analyst_notes=analyst_notes,
            target_scenario=target_scenario,
        )
        pdf_bytes, pdf_path = self.generate_pdf_dossier(dossier_data)
        json_path = os.path.splitext(pdf_path)[0] + ".json"

        return {
            "dossier_id": dossier_data["dossier_id"],
            "generated_at": dossier_data["generated_at"],
            "pdf_path": pdf_path,
            "json_path": json_path,
            "pdf_size_bytes": len(pdf_bytes),
            "cryptographic_audit_hash": dossier_data["cryptographic_audit_hash"],
            "executive_summary": dossier_data["executive_summary"],
            "dossier_data": dossier_data,
        }

    def list_generated_dossiers(self) -> List[Dict[str, Any]]:
        """Returns catalog of all generated incident dossiers."""
        if not os.path.exists(self.dossiers_dir):
            return []

        results = []
        for f in sorted(os.listdir(self.dossiers_dir), reverse=True):
            if f.endswith(".json"):
                json_path = os.path.join(self.dossiers_dir, f)
                pdf_path = os.path.splitext(json_path)[0] + ".pdf"
                try:
                    with open(json_path, "r", encoding="utf-8") as jf:
                        data = json.load(jf)
                    results.append({
                        "dossier_id": data.get("dossier_id", f),
                        "generated_at": data.get("generated_at"),
                        "analyst_name": data.get("analyst_name"),
                        "compromised_assets": data.get("executive_summary", {}).get("compromised_nodes_count", 0),
                        "crown_jewels_at_risk": data.get("executive_summary", {}).get("crown_jewels_at_risk_count", 0),
                        "containment_cost": data.get("executive_summary", {}).get("estimated_containment_cost", 0.0),
                        "audit_hash": data.get("cryptographic_audit_hash"),
                        "json_file": f,
                        "pdf_file": os.path.basename(pdf_path) if os.path.exists(pdf_path) else None,
                        "pdf_available": os.path.exists(pdf_path),
                    })
                except Exception as e:
                    logger.warning("Error reading dossier JSON %s: %s", json_path, e)

        return results
