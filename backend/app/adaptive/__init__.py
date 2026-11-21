"""SafeContain AI Phase 7.4 Adaptive Threat Intelligence & Predictive Feedback Loop Package."""

from backend.app.adaptive.evaluation_engine import TemporalEvaluationEngine
from backend.app.adaptive.feedback_engine import AdaptiveFeedbackEngine
from backend.app.adaptive.graph_sync import AdaptiveGraphSynchronizer
from backend.app.adaptive.intelligence_quality import ThreatIntelligenceQualityEngine
from backend.app.adaptive.metrics import AdaptiveMetricsCalculator
from backend.app.adaptive.models import (
    AdaptiveFeedbackInsights,
    AdaptiveSummary,
    GroundTruthOutcome,
    HorizonComparisonItem,
    ModelReliabilityReport,
    PredictionOutcomeStatus,
    PredictionRecord,
    PredictivePerformanceMetrics,
    ThreatIntelQualityMetrics,
)
from backend.app.adaptive.router import router as adaptive_router
from backend.app.adaptive.shap_analyzer import ExplanationQualityAnalyzer
from backend.app.adaptive.tracker import PredictionOutcomeTracker

__all__ = [
    "AdaptiveFeedbackEngine",
    "AdaptiveFeedbackInsights",
    "AdaptiveGraphSynchronizer",
    "AdaptiveMetricsCalculator",
    "AdaptiveSummary",
    "ExplanationQualityAnalyzer",
    "GroundTruthOutcome",
    "HorizonComparisonItem",
    "ModelReliabilityReport",
    "PredictionOutcomeStatus",
    "PredictionOutcomeTracker",
    "PredictionRecord",
    "PredictivePerformanceMetrics",
    "TemporalEvaluationEngine",
    "ThreatIntelQualityMetrics",
    "ThreatIntelligenceQualityEngine",
    "adaptive_router",
]
