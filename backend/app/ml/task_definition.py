"""Task Definitions and Data Leakage Guards for SafeContain AI ML Pipeline.

Formally specifies the machine learning prediction tasks supported by the
enterprise cybersecurity data and establishes strict leakage guardrails.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Set


class MLTaskType(str, Enum):
    """Supported machine learning task types."""
    SUPERVISED_CLASSIFICATION = "supervised_classification"
    UNSUPERVISED_ANOMALY_DETECTION = "unsupervised_anomaly_detection"


# Columns that must NEVER be passed as model inputs to prevent target leakage
FORBIDDEN_LEAKAGE_COLUMNS: Set[str] = {
    "security_status",
    "target_is_at_risk",
    "target_status",
    "is_compromised",
    "is_at_risk",
    "label",
    "ground_truth",
}

# Features that belong strictly to graph topology and static asset attributes (100% leak-free)
TOPOLOGY_FEATURE_COLUMNS: List[str] = [
    "node_type",
    "environment",
    "exposure",
    "criticality",
    "business_value",
    "in_degree",
    "out_degree",
    "total_degree",
    "in_out_degree_ratio",
    "pagerank",
    "is_high_privilege_connected",
    "admin_edge_count",
    "has_asset_profile",
]

# Telemetry features representing observable security signals (alerts and vulnerability scans)
TELEMETRY_FEATURE_COLUMNS: List[str] = [
    "vuln_count",
    "max_cvss_score",
    "sum_cvss_score",
    "has_critical_vuln",
    "alert_src_count",
    "alert_dst_count",
    "total_alert_count",
    "max_alert_severity_weight",
    "evidence_count",
    "max_evidence_confidence",
]


@dataclass
class TaskDefinition:
    """Formal definition of a cybersecurity machine learning task."""
    task_id: str
    task_name: str
    task_type: MLTaskType
    description: str
    target_column: str
    primary_metrics: List[str]
    allowed_feature_subsets: List[str]
    leakage_risks: List[str]
    limitations: List[str]


# Task 1: Supervised Node Security Compromise Risk Classification
TASK_NODE_RISK_CLASSIFICATION = TaskDefinition(
    task_id="TASK_NODE_RISK_CLASSIFICATION",
    task_name="Supervised Node Security Compromise Risk Classification",
    task_type=MLTaskType.SUPERVISED_CLASSIFICATION,
    description=(
        "Predicts whether an enterprise graph entity is at elevated risk of security compromise "
        "(status non-HEALTHY) based on graph topology, exposure, asset value, and observable telemetry."
    ),
    target_column="target_is_at_risk",
    primary_metrics=["balanced_accuracy", "roc_auc", "average_precision", "f1", "recall", "precision"],
    allowed_feature_subsets=["topology_only", "full"],
    leakage_risks=[
        "Target leakage if 'security_status' is included in features.",
        "Contamination if train/test split does not isolate node entities.",
        "Alert leakage if alert description contains the ground truth status label.",
    ],
    limitations=[
        "Dataset size is constrained to 120 enterprise nodes.",
        "Class imbalance (approx 80.8% Healthy vs 19.2% At-Risk) requires Stratified K-Fold CV.",
        "High-capacity models (deep neural nets) risk severe overfitting; regularized linear or shallow trees required.",
    ],
)

# Task 2: Unsupervised Graph Node Intrusion & Topological Anomaly Detection
TASK_NODE_ANOMALY_DETECTION = TaskDefinition(
    task_id="TASK_NODE_ANOMALY_DETECTION",
    task_name="Unsupervised Graph Entity Anomaly & Outlier Detection",
    task_type=MLTaskType.UNSUPERVISED_ANOMALY_DETECTION,
    description=(
        "Detects structurally anomalous graph entities that exhibit unusual topological roles, "
        "unexpected privilege bridges, or anomalous combinations of exposure, criticality, and connectivity."
    ),
    target_column="",
    primary_metrics=["contamination_rate", "anomaly_score_distribution", "top_outlier_count"],
    allowed_feature_subsets=["topology_only", "full"],
    leakage_risks=[
        "None (Unsupervised; no target labels used during fitting).",
    ],
    limitations=[
        "Anomaly score measures structural deviation, NOT confirmed maliciousness.",
        "High-degree legitimate infrastructure (e.g., domain controllers, central proxies) may be flagged as outliers.",
        "Requires human analyst triage to confirm operational validity.",
    ],
)


def assert_no_target_leakage(feature_names: List[str]) -> None:
    """Verifies that no forbidden target-encoding columns exist in feature set.
    
    Raises:
        ValueError: If any forbidden column name is detected.
    """
    detected_leakage = [col for col in feature_names if col.lower() in FORBIDDEN_LEAKAGE_COLUMNS]
    if detected_leakage:
        raise ValueError(
            f"CRITICAL TARGET LEAKAGE DETECTED: Features contain forbidden target columns: {detected_leakage}. "
            f"These columns directly encode ground-truth outcomes and must be excluded."
        )
