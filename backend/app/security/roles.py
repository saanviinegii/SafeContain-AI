"""SafeContain AI Role-Based Access Control Definitions & Hierarchy.

Defines the three canonical application security roles (ADMIN, ANALYST, VIEWER)
and provides bidirectional mapping to enterprise governance UserRoles.
"""

from enum import Enum
from typing import Union
from backend.app.models.domain import UserRole


class AppRole(str, Enum):
    """Canonical application-level RBAC role tiers."""
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


# Role privilege hierarchy: ADMIN (3) > ANALYST (2) > VIEWER (1)
ROLE_HIERARCHY = {
    AppRole.ADMIN: 3,
    AppRole.ANALYST: 2,
    AppRole.VIEWER: 1,
}


def normalize_app_role(role_val: Union[str, AppRole, UserRole]) -> AppRole:
    """Normalizes any role input (string or enum) into canonical AppRole."""
    if isinstance(role_val, AppRole):
        return role_val

    val_str = str(role_val.value if hasattr(role_val, "value") else role_val).upper().strip()

    # Direct match
    if val_str in ("ADMIN", "PLATFORM_ADMIN", "SECURITY_ADMIN"):
        return AppRole.ADMIN
    elif val_str in (
        "ANALYST", "SOC_ANALYST", "INCIDENT_RESPONDER",
        "INCIDENT_COMMANDER", "SECURITY_MANAGER"
    ):
        return AppRole.ANALYST
    elif val_str in ("VIEWER", "READ_ONLY_VIEWER", "AUDITOR"):
        return AppRole.VIEWER

    # Fallback to VIEWER for unrecognized roles for safe least-privilege defaults
    return AppRole.VIEWER


def has_sufficient_privilege(user_role: Union[str, AppRole, UserRole], required_role: AppRole) -> bool:
    """Evaluates whether user_role satisfies the minimum privilege requirement of required_role."""
    norm_user = normalize_app_role(user_role)
    norm_req = normalize_app_role(required_role)
    return ROLE_HIERARCHY[norm_user] >= ROLE_HIERARCHY[norm_req]
