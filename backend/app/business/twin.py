"""SafeContain AI Business Continuity Digital Twin.

Models business operational workflows, maps infrastructure dependencies,
and calculates downtime, financial impact, and SLA violations for containment actions.
"""

from typing import Dict, List, Optional, Set
from backend.app.core.config import settings
from backend.app.models.domain import (
    BusinessWorkflow,
    ContainmentAction,
    GraphNode,
    NodeType,
    RelationshipType,
    SecurityActionType,
    WorkflowCriticality,
    WorkflowDisruptionAssessment,
)


class BusinessContinuityTwin:
    """Enterprise Business Continuity Digital Twin Engine."""

    def __init__(self):
        self._workflows: Dict[str, BusinessWorkflow] = {}

    def register_workflow(self, workflow: BusinessWorkflow) -> None:
        """Registers a critical business or citizen workflow in the twin model."""
        self._workflows[workflow.id] = workflow

    def get_workflow(self, workflow_id: str) -> Optional[BusinessWorkflow]:
        return self._workflows.get(workflow_id)

    def get_all_workflows(self) -> List[BusinessWorkflow]:
        return list(self._workflows.values())

    def discover_dependencies_from_graph(self, engine) -> None:
        """Scans the graph topology for workflow nodes and their supporting dependencies."""
        nodes = engine.get_all_nodes()
        edges = engine.get_all_edges()

        for node in nodes:
            if node.type == NodeType.BUSINESS_WORKFLOW:
                crit_str = node.properties.get("criticality_tier", WorkflowCriticality.TIER_2_BUSINESS_CRITICAL.value)
                crit = WorkflowCriticality(crit_str) if crit_str in WorkflowCriticality.__members__.values() else WorkflowCriticality.TIER_2_BUSINESS_CRITICAL
                citizen_facing = bool(node.properties.get("citizen_facing", False))
                cost = float(node.properties.get("hourly_downtime_cost", 25000.0))
                max_down = float(node.properties.get("max_allowable_downtime_hours", 0.0 if citizen_facing else 2.0))

                # Find all nodes that support this workflow
                supporting_assets: List[str] = [
                    e.source for e in edges
                    if e.target == node.id and e.type == RelationshipType.SUPPORTS_WORKFLOW
                ]

                wf = BusinessWorkflow(
                    id=node.id,
                    name=node.name,
                    criticality=crit,
                    citizen_facing=citizen_facing,
                    dependent_asset_ids=supporting_assets,
                    max_allowable_downtime_hours=max_down,
                    estimated_hourly_downtime_cost=cost,
                    active_incident_count=1 if any(engine.get_node(nid) and engine.get_node(nid).is_compromised for nid in supporting_assets) else 0,
                    operational_status="AT_RISK" if supporting_assets else "HEALTHY",
                )
                self.register_workflow(wf)

    def assess_action_disruption(
        self,
        action: ContainmentAction,
        engine
    ) -> List[WorkflowDisruptionAssessment]:
        """Calculates exact business disruption incurred if a specific action is executed."""
        assessments: List[WorkflowDisruptionAssessment] = []
        target_id = action.target_node_id

        # Determine severity and estimated downtime based on action type
        downtime_hours = 0.5 # Default brief impact
        if action.action_type in (SecurityActionType.ISOLATE_ENDPOINT, SecurityActionType.RESTRICT_NETWORK):
            downtime_hours = 4.0 # Endpoint / network isolation causes substantial downtime
        elif action.action_type in (SecurityActionType.DISABLE_ACCOUNT, SecurityActionType.REVOKE_SESSION):
            downtime_hours = 1.0 # Account lockout disruption
        elif action.action_type == SecurityActionType.PATCH_VULNERABILITY:
            downtime_hours = 0.25 # Rolling restart / patch window

        for wf in self._workflows.values():
            # Check direct dependency
            is_directly_dependent = target_id in wf.dependent_asset_ids

            # Check indirect dependency via connected servers / databases
            is_indirectly_dependent = False
            if not is_directly_dependent:
                for asset_id in wf.dependent_asset_ids:
                    if engine._nx_graph.has_edge(target_id, asset_id) or engine._nx_graph.has_edge(asset_id, target_id):
                        is_indirectly_dependent = True
                        break

            if is_directly_dependent or is_indirectly_dependent:
                fin_cost = round(downtime_hours * wf.estimated_hourly_downtime_cost, 2)
                violates_sla = downtime_hours > wf.max_allowable_downtime_hours

                assessments.append(WorkflowDisruptionAssessment(
                    workflow_id=wf.id,
                    workflow_name=wf.name,
                    criticality=wf.criticality,
                    is_disrupted=True,
                    estimated_downtime_hours=downtime_hours,
                    financial_impact=fin_cost,
                    violates_sla=violates_sla,
                    disrupting_action_ids=[action.id],
                ))

        return assessments

    def assess_plan_disruption(
        self,
        actions: List[ContainmentAction],
        engine
    ) -> List[WorkflowDisruptionAssessment]:
        """Computes aggregate workflow disruption across a multi-action containment plan."""
        disrupted_map: Dict[str, WorkflowDisruptionAssessment] = {}

        for action in actions:
            action_assessments = self.assess_action_disruption(action, engine)
            for ass in action_assessments:
                if ass.workflow_id not in disrupted_map:
                    disrupted_map[ass.workflow_id] = ass
                else:
                    curr = disrupted_map[ass.workflow_id]
                    curr.estimated_downtime_hours = max(curr.estimated_downtime_hours, ass.estimated_downtime_hours)
                    curr.financial_impact = max(curr.financial_impact, ass.financial_impact)
                    curr.violates_sla = curr.violates_sla or ass.violates_sla
                    if action.id not in curr.disrupting_action_ids:
                        curr.disrupting_action_ids.append(action.id)

        return list(disrupted_map.values())
