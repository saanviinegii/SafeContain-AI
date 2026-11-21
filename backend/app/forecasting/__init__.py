"""SafeContain AI Phase 7.3: Temporal Threat Propagation Forecasting Engine.

Exports core forecasting models, temporal feature extractor, graph propagation engine,
and forecaster singleton facade.
"""

from backend.app.forecasting.forecaster import TemporalThreatForecaster
from backend.app.forecasting.models import (
    AssetRiskForecast,
    ForecastHorizon,
    ForecastingEvaluationResult,
    ForecastingSummary,
    PropagationHop,
    RiskTrend,
)
from backend.app.forecasting.propagation import GraphRiskPropagationEngine
from backend.app.forecasting.temporal_features import TemporalFeatureExtractor

__all__ = [
    "TemporalThreatForecaster",
    "TemporalFeatureExtractor",
    "GraphRiskPropagationEngine",
    "ForecastHorizon",
    "RiskTrend",
    "AssetRiskForecast",
    "ForecastingSummary",
    "ForecastingEvaluationResult",
    "PropagationHop",
]
