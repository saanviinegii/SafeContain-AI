"""SafeContain AI Report Generator and Export Services.

Produces reproducible incident analysis reports, strategy comparison audits,
and cryptographic evidence provenance packages in JSON, CSV, and formatted text.
"""

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from backend.app.models.domain import SimulationResult, ContainmentPlan, AuditEvent


class ReportExporter:
    """Generates verifiable and reproducible compliance reports."""

    @classmethod
    def generate_incident_json(
        cls,
        scenario_name: str,
        simulation: SimulationResult,
        plan: ContainmentPlan,
        audit_events: List[AuditEvent]
    ) -> str:
        """Produces a canonical JSON incident dossier."""
        dossier = {
            "platform": "SafeContain AI Enterprise",
            "report_type": "EXECUTIVE_INCIDENT_CONTAINMENT_DOSSIER",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scenario": scenario_name,
            "governance_status": plan.status.value,
            "simulation_audit_hash": simulation.audit_hash,
            "containment_summary": {
                "initial_risk": simulation.initial_risk_score,
                "residual_risk": simulation.residual_risk_score,
                "risk_reduction_achieved": simulation.risk_reduction_achieved,
                "residual_paths_remaining": simulation.residual_attack_path_count,
                "is_threat_contained": simulation.is_fully_contained,
                "unprotected_crown_jewels": simulation.unprotected_crown_jewels,
            },
            "selected_interventions": [a.model_dump(mode="json") for a in plan.actions],
            "workflow_impact": [w.model_dump(mode="json") for w in simulation.disrupted_workflows],
            "audit_trail_excerpt": [e.model_dump(mode="json") for e in audit_events[:10]],
        }
        return json.dumps(dossier, indent=2)

    @classmethod
    def generate_actions_csv(cls, plan: ContainmentPlan) -> str:
        """Exports containment actions into standard CSV format for operational teams."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Action ID", "Action Type", "Target Entity", "Risk Reduction",
            "Disruption Score", "Implementation Cost ($)", "Duration (min)", "Required Role", "Rationale"
        ])
        for a in plan.actions:
            writer.writerow([
                a.id, a.action_type.value, a.target_node_name,
                a.estimated_risk_reduction, a.operational_disruption_score,
                a.implementation_cost, a.estimated_duration_minutes,
                a.required_role.value, a.rationale
            ])
        return output.getvalue()

    @classmethod
    def generate_executive_text_summary(
        cls,
        scenario_name: str,
        simulation: SimulationResult,
        plan: ContainmentPlan
    ) -> str:
        """Produces a formal formatted text briefing suitable for leadership."""
        sep = "=" * 70
        sub_sep = "-" * 70
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines = [
            sep,
            " SAFECONTAIN AI — EXECUTIVE INCIDENT CONTAINMENT DOSSIER",
            " Classified Decision-Support & Business Continuity Intelligence",
            sep,
            f"Generated At       : {now_str}",
            f"Scenario Scope     : {scenario_name}",
            f"Governance State   : {plan.status.value}",
            f"Simulation Hash    : {simulation.audit_hash}",
            sub_sep,
            " 1. SECURITY & RESIDUAL RISK OUTCOME",
            sub_sep,
            f"Initial System Risk       : {simulation.initial_risk_score:.1f} / 100.0",
            f"Simulated Residual Risk   : {simulation.residual_risk_score:.1f} / 100.0",
            f"Net Risk Reduction        : -{simulation.risk_reduction_achieved:.1f} points",
            f"Initial Attack Routes     : {simulation.initial_attack_path_count}",
            f"Residual Routes Remaining : {simulation.residual_attack_path_count}",
            f"Containment Verification  : {'COMPLETE' if simulation.is_fully_contained else 'PARTIAL (Residual Paths Open)'}",
            sub_sep,
            " 2. BUSINESS CONTINUITY & CITIZEN SLA STATUS",
            sub_sep,
            f"Workflows Disrupted       : {len(simulation.disrupted_workflows)}",
            f"Total Disruption Score    : {plan.total_disruption_score:.1f}",
            f"Total Plan Cost           : ${plan.total_cost:.2f}",
            sub_sep,
            " 3. RECOMMENDED CONTAINMENT INTERVENTIONS",
            sub_sep,
        ]

        for i, a in enumerate(plan.actions, 1):
            lines.append(f" [{i}] {a.action_type.value} on '{a.target_node_name}'")
            lines.append(f"     Cost: ${a.implementation_cost:.2f} | Disruption: {a.operational_disruption_score:.1f} | Role: {a.required_role.value}")
            lines.append(f"     Rationale: {a.rationale}")

        lines.extend([
            sub_sep,
            " 4. MANDATORY GOVERNANCE NOTICE",
            sub_sep,
            " Decision Support Only. No destructive real-world interventions have been executed.",
            " Execution requires authorized human approval in compliance with CERT-In & ISO 27001.",
            sep,
        ])

        return "\n".join(lines)
