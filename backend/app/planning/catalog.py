"""SafeContain AI Response Action Catalog and Candidate Generator.

Formal model of 11+ cybersecurity containment interventions with preconditions,
financial cost, operational disruption, and reversibility attributes.
"""

from typing import Dict, List, Optional
from backend.app.models.domain import (
    AttackPath,
    ContainmentAction,
    GraphNode,
    NodeType,
    SecurityActionType,
    UserRole,
)


class ActionCatalog:
    """Generates candidate response interventions for compromised nodes and path choke-points."""

    @classmethod
    def generate_candidate_actions(
        cls,
        paths: List[AttackPath],
        nodes: Dict[str, GraphNode]
    ) -> List[ContainmentAction]:
        """Synthesizes valid candidate containment actions targeting active attack paths."""
        candidates: List[ContainmentAction] = []
        seen_targets: set = set()

        # Collect all active nodes across discovered attack paths
        traversed_node_ids = set()
        for p in paths:
            traversed_node_ids.update(p.node_sequence)

        for nid in traversed_node_ids:
            node = nodes.get(nid)
            if not node:
                continue

            # 1. Endpoints & Workstations -> ISOLATE_ENDPOINT
            if node.type in (NodeType.ENDPOINT, NodeType.HOST) and nid not in seen_targets:
                seen_targets.add(nid)
                candidates.append(ContainmentAction(
                    id=f"act-isolate-{nid}",
                    action_type=SecurityActionType.ISOLATE_ENDPOINT,
                    target_node_id=nid,
                    target_node_name=node.name,
                    estimated_risk_reduction=45.0 if node.is_compromised else 25.0,
                    operational_disruption_score=15.0,
                    implementation_cost=250.0,
                    estimated_duration_minutes=10,
                    reversibility=True,
                    required_role=UserRole.INCIDENT_RESPONDER,
                    preconditions=["EDR_AGENT_ONLINE", "VALID_DEVICE_CERTIFICATE"],
                    mitigated_path_ids=[p.id for p in paths if nid in p.node_sequence],
                    rationale=f"Sever network layer connectivity for endpoint '{node.name}' to halt lateral movement.",
                ))

            # 2. Privileged Identities & Users -> REVOKE_SESSION / DISABLE_ACCOUNT / ROTATE_CREDENTIALS
            elif node.type in (NodeType.USER, NodeType.PRIVILEGED_IDENTITY) and nid not in seen_targets:
                seen_targets.add(nid)
                # Revoke Session (Lower disruption)
                candidates.append(ContainmentAction(
                    id=f"act-revoke-{nid}",
                    action_type=SecurityActionType.REVOKE_SESSION,
                    target_node_id=nid,
                    target_node_name=node.name,
                    estimated_risk_reduction=35.0,
                    operational_disruption_score=10.0,
                    implementation_cost=100.0,
                    estimated_duration_minutes=5,
                    reversibility=True,
                    required_role=UserRole.SOC_ANALYST,
                    preconditions=["IAM_API_ONLINE"],
                    mitigated_path_ids=[p.id for p in paths if nid in p.node_sequence],
                    rationale=f"Immediately terminate active Kerberos/OAuth sessions for '{node.name}'.",
                ))
                # Disable Account (Higher disruption, higher risk reduction)
                candidates.append(ContainmentAction(
                    id=f"act-disable-{nid}",
                    action_type=SecurityActionType.DISABLE_ACCOUNT,
                    target_node_id=nid,
                    target_node_name=node.name,
                    estimated_risk_reduction=60.0,
                    operational_disruption_score=40.0,
                    implementation_cost=300.0,
                    estimated_duration_minutes=15,
                    reversibility=True,
                    required_role=UserRole.SECURITY_ADMIN,
                    preconditions=["IAM_API_ONLINE", "MANAGER_NOTIFICATION_DISPATCHED"],
                    mitigated_path_ids=[p.id for p in paths if nid in p.node_sequence],
                    rationale=f"Lock identity provider account for '{node.name}' to prevent authentication replay.",
                ))

            # 3. Servers & Gateways -> RESTRICT_NETWORK / APPLY_FIREWALL_RULE
            elif node.type in (NodeType.SERVER, NodeType.CLOUD_RESOURCE) and nid not in seen_targets:
                seen_targets.add(nid)
                # Network Microsegmentation Rule
                candidates.append(ContainmentAction(
                    id=f"act-firewall-{nid}",
                    action_type=SecurityActionType.APPLY_FIREWALL_RULE,
                    target_node_id=nid,
                    target_node_name=node.name,
                    estimated_risk_reduction=55.0,
                    operational_disruption_score=20.0,
                    implementation_cost=500.0,
                    estimated_duration_minutes=20,
                    reversibility=True,
                    required_role=UserRole.SECURITY_ADMIN,
                    preconditions=["SDN_CONTROLLER_SYNC", "FIREWALL_POLICY_VALIDATED"],
                    mitigated_path_ids=[p.id for p in paths if nid in p.node_sequence],
                    rationale=f"Deploy microsegmentation ACL blocking non-whitelisted lateral traffic into '{node.name}'.",
                ))

            # 4. Critical Database Target -> RESTRICT_RESOURCE_ACCESS
            elif node.type == NodeType.DATABASE and nid not in seen_targets:
                seen_targets.add(nid)
                candidates.append(ContainmentAction(
                    id=f"act-restrict-{nid}",
                    action_type=SecurityActionType.RESTRICT_RESOURCE_ACCESS,
                    target_node_id=nid,
                    target_node_name=node.name,
                    estimated_risk_reduction=70.0,
                    operational_disruption_score=60.0,
                    implementation_cost=1200.0,
                    estimated_duration_minutes=30,
                    reversibility=True,
                    required_role=UserRole.SECURITY_MANAGER,
                    preconditions=["DB_READONLY_MODE_READY", "DBA_ON_CALL_ENGAGED"],
                    mitigated_path_ids=[p.id for p in paths if nid in p.node_sequence],
                    rationale=f"Enforce strict read-only access and drop remote administrative connections to '{node.name}'.",
                ))

        return candidates
