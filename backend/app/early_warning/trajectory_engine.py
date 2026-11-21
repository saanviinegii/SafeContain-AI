"""Module 7.6.2: Risk Trajectory Engine.

Analyzes chronological sequences of enterprise asset risk scores to calculate mathematical
derivatives: trend slope, acceleration, volatility, rolling moving averages, exponential
moving averages, CUSUM change-point breaks, and bounded horizon projections.
"""

from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from backend.app.early_warning.models import (
    DataSufficiency,
    RiskTrajectory,
    RiskTrajectoryPoint,
    TrajectoryDirection,
)

logger = logging.getLogger("safecontain.early_warning.trajectory_engine")


class RiskTrajectoryEngine:
    """Computes mathematically rigorous risk trajectory metrics from discrete historical telemetry observations."""

    def __init__(self, default_horizon_hours: float = 6.0):
        self.default_horizon_hours = default_horizon_hours

    def clean_and_sort_points(self, points: List[RiskTrajectoryPoint]) -> List[RiskTrajectoryPoint]:
        """Cleans, validates, deduplicates, and chronologically sorts risk observation points."""
        if not points:
            return []

        valid: List[RiskTrajectoryPoint] = []
        for p in points:
            # Filter out None, NaN, and Inf
            if p is None or p.timestamp is None or p.risk_score is None:
                continue
            if math.isnan(p.risk_score) or math.isinf(p.risk_score):
                continue
            # Clamp risk score to [0.0, 100.0]
            clamped_score = max(0.0, min(100.0, float(p.risk_score)))
            valid.append(
                RiskTrajectoryPoint(
                    timestamp=p.timestamp,
                    risk_score=clamped_score,
                    source=p.source or "ML_RISK_SCORE",
                )
            )

        if not valid:
            return []

        # Sort chronologically
        valid.sort(key=lambda x: x.timestamp)

        # Handle duplicate timestamps by averaging their risk scores
        deduped: List[RiskTrajectoryPoint] = []
        i = 0
        while i < len(valid):
            curr_ts = valid[i].timestamp
            same_ts_points = [valid[i]]
            j = i + 1
            while j < len(valid) and valid[j].timestamp == curr_ts:
                same_ts_points.append(valid[j])
                j += 1

            if len(same_ts_points) > 1:
                avg_score = sum(p.risk_score for p in same_ts_points) / len(same_ts_points)
                deduped.append(RiskTrajectoryPoint(timestamp=curr_ts, risk_score=avg_score, source=same_ts_points[0].source))
            else:
                deduped.append(same_ts_points[0])
            i = j

        return deduped

    def calculate_linear_regression_slope(self, points: List[RiskTrajectoryPoint]) -> float:
        """Calculates ordinary least squares linear regression slope (risk change per hour).

        Formula:
            m = sum((t_i - mean(t)) * (R_i - mean(R))) / sum((t_i - mean(t))^2)
        """
        n = len(points)
        if n < 2:
            return 0.0

        t0 = points[0].timestamp
        t_hours = [(p.timestamp - t0).total_seconds() / 3600.0 for p in points]
        r_vals = [p.risk_score for p in points]

        mean_t = sum(t_hours) / n
        mean_r = sum(r_vals) / n

        numerator = sum((t_hours[i] - mean_t) * (r_vals[i] - mean_r) for i in range(n))
        denominator = sum((t_hours[i] - mean_t) ** 2 for i in range(n))

        if denominator == 0.0:
            return 0.0

        return numerator / denominator

    def calculate_acceleration(self, points: List[RiskTrajectoryPoint]) -> float:
        """Calculates risk acceleration (d2R/dt2) as rate of slope change across chronological halves."""
        n = len(points)
        if n < 4:
            return 0.0

        mid = n // 2
        first_half = points[:mid]
        second_half = points[mid:]

        slope1 = self.calculate_linear_regression_slope(first_half)
        slope2 = self.calculate_linear_regression_slope(second_half)

        # Delta time between midpoints of the two halves
        t_mid1 = (first_half[-1].timestamp - first_half[0].timestamp).total_seconds() / 7200.0
        t_mid2 = (second_half[-1].timestamp - second_half[0].timestamp).total_seconds() / 7200.0
        dt = ((second_half[0].timestamp - first_half[0].timestamp).total_seconds() / 3600.0) + (t_mid2 - t_mid1)

        if dt <= 0.0:
            return 0.0

        return (slope2 - slope1) / dt

    def calculate_volatility(self, points: List[RiskTrajectoryPoint]) -> float:
        """Calculates sample standard deviation of historical risk values."""
        n = len(points)
        if n < 2:
            return 0.0

        r_vals = [p.risk_score for p in points]
        mean_r = sum(r_vals) / n
        variance = sum((r - mean_r) ** 2 for r in r_vals) / (n - 1)
        return math.sqrt(variance)

    def calculate_moving_average(self, points: List[RiskTrajectoryPoint], window: int = 5) -> float:
        """Calculates trailing arithmetic moving average over window points."""
        if not points:
            return 0.0
        k = min(window, len(points))
        trailing = points[-k:]
        return sum(p.risk_score for p in trailing) / k

    def calculate_ema(self, points: List[RiskTrajectoryPoint], window: int = 5) -> float:
        """Calculates Exponential Moving Average (EMA) with standard alpha = 2 / (k + 1)."""
        if not points:
            return 0.0
        k = min(window, len(points))
        alpha = 2.0 / (k + 1)
        ema = points[0].risk_score
        for p in points[1:]:
            ema = alpha * p.risk_score + (1.0 - alpha) * ema
        return ema

    def detect_cusum_change_point(
        self,
        points: List[RiskTrajectoryPoint],
        threshold: float = 12.0,
    ) -> Tuple[bool, Optional[str]]:
        """Detects structural change-point breaks using the Cumulative Sum (CUSUM) control chart.

        Formula:
            S_k = max(0, S_{k-1} + (R_k - mean(R_baseline) - slack))
        """
        n = len(points)
        if n < 4:
            return False, None

        # Baseline established on first 40% of observations
        baseline_len = max(2, int(n * 0.4))
        baseline_mean = sum(p.risk_score for p in points[:baseline_len]) / baseline_len

        s_pos = 0.0
        s_neg = 0.0
        slack = 2.0  # Allowable random variation slack

        for i in range(baseline_len, n):
            score = points[i].risk_score
            s_pos = max(0.0, s_pos + (score - baseline_mean - slack))
            s_neg = max(0.0, s_neg + (baseline_mean - score - slack))

            if s_pos >= threshold:
                return True, f"CUSUM Positive Break: Risk sharply escalated by +{s_pos:.1f} beyond baseline {baseline_mean:.1f} at {points[i].timestamp.isoformat()}."
            if s_neg >= threshold:
                return True, f"CUSUM Negative Break: Risk attenuated sharply by -{s_neg:.1f} below baseline {baseline_mean:.1f} at {points[i].timestamp.isoformat()}."

        return False, None

    def determine_trend_direction(
        self,
        slope: float,
        volatility: float,
        points: List[RiskTrajectoryPoint],
    ) -> TrajectoryDirection:
        """Classifies trajectory direction considering velocity, volatility, and score oscillation."""
        if len(points) < 2:
            return TrajectoryDirection.STABLE

        # High volatility dominance
        if volatility >= 18.0:
            return TrajectoryDirection.VOLATILE

        # Clear linear velocity
        if slope >= 0.5:
            return TrajectoryDirection.RISING
        elif slope <= -0.5:
            return TrajectoryDirection.FALLING

        # Check total range variation
        r_vals = [p.risk_score for p in points]
        if max(r_vals) - min(r_vals) >= 25.0 and volatility >= 10.0:
            return TrajectoryDirection.VOLATILE

        return TrajectoryDirection.STABLE

    def calculate_projected_risk(
        self,
        current_risk: float,
        slope: float,
        horizon_hours: float,
    ) -> float:
        """Projects risk forward over horizon H using damped linear extrapolation clamped to [0.0, 100.0]."""
        if horizon_hours <= 0:
            return current_risk

        # Damping factor lambda prevents unbounded runaway extrapolation for longer horizons
        damping_lambda = 0.08
        damped_hours = (1.0 - math.exp(-damping_lambda * horizon_hours)) / damping_lambda if damping_lambda > 0 else horizon_hours
        projected = current_risk + (slope * damped_hours)
        return max(0.0, min(100.0, projected))

    def evaluate_trajectory(
        self,
        asset_id: str,
        raw_points: List[RiskTrajectoryPoint],
        horizon_hours: Optional[float] = None,
    ) -> RiskTrajectory:
        """Executes full mathematical trajectory analysis on an asset's risk observation history."""
        horizon = horizon_hours if (horizon_hours is not None and horizon_hours > 0) else self.default_horizon_hours
        now = datetime.now(timezone.utc)
        points = self.clean_and_sort_points(raw_points)
        n = len(points)

        # ---------------------------------------------------------------------
        # Edge Case 1: No Data
        # ---------------------------------------------------------------------
        if n == 0:
            return RiskTrajectory(
                asset_id=asset_id,
                current_risk=0.0,
                historical_values=[],
                trend_direction=TrajectoryDirection.STABLE,
                slope=0.0,
                acceleration=0.0,
                volatility=0.0,
                moving_average=0.0,
                ema=0.0,
                change_point_detected=False,
                data_sufficiency=DataSufficiency.NO_DATA,
                forecast_horizon_hours=horizon,
                projected_risk=0.0,
                projection_confidence=0.0,
                generated_at=now,
                notes="No historical risk observations available for asset.",
            )

        current_risk = round(points[-1].risk_score, 2)

        # ---------------------------------------------------------------------
        # Edge Case 2: Single Observation (Insufficient)
        # ---------------------------------------------------------------------
        if n == 1:
            return RiskTrajectory(
                asset_id=asset_id,
                current_risk=current_risk,
                historical_values=points,
                trend_direction=TrajectoryDirection.STABLE,
                slope=0.0,
                acceleration=0.0,
                volatility=0.0,
                moving_average=current_risk,
                ema=current_risk,
                change_point_detected=False,
                data_sufficiency=DataSufficiency.INSUFFICIENT,
                forecast_horizon_hours=horizon,
                projected_risk=current_risk,
                projection_confidence=0.30,
                generated_at=now,
                notes="Single point observation: slope, volatility, and change-point math suppressed.",
            )

        # ---------------------------------------------------------------------
        # Edge Case 3: Two Observations (Sparse)
        # ---------------------------------------------------------------------
        if n == 2:
            slope = self.calculate_linear_regression_slope(points)
            volatility = self.calculate_volatility(points)
            direction = self.determine_trend_direction(slope, volatility, points)
            projected = self.calculate_projected_risk(current_risk, slope, horizon)
            return RiskTrajectory(
                asset_id=asset_id,
                current_risk=current_risk,
                historical_values=points,
                trend_direction=direction,
                slope=round(slope, 3),
                acceleration=0.0,
                volatility=round(volatility, 2),
                moving_average=round((points[0].risk_score + points[1].risk_score) / 2.0, 2),
                ema=round(self.calculate_ema(points), 2),
                change_point_detected=False,
                data_sufficiency=DataSufficiency.SPARSE,
                forecast_horizon_hours=horizon,
                projected_risk=round(projected, 2),
                projection_confidence=0.55,
                generated_at=now,
                notes="Sparse history (2 points): linear slope calculated, acceleration and CUSUM suppressed.",
            )

        # ---------------------------------------------------------------------
        # Full Calculation (N >= 3: Sufficient)
        # ---------------------------------------------------------------------
        slope = self.calculate_linear_regression_slope(points)
        acceleration = self.calculate_acceleration(points)
        volatility = self.calculate_volatility(points)
        moving_avg = self.calculate_moving_average(points)
        ema = self.calculate_ema(points)
        cp_detected, cp_desc = self.detect_cusum_change_point(points)
        direction = self.determine_trend_direction(slope, volatility, points)
        projected = self.calculate_projected_risk(current_risk, slope, horizon)

        # Confidence scales with sample size and inversely with volatility
        base_confidence = min(0.95, 0.60 + (n * 0.04))
        volatility_penalty = min(0.30, volatility * 0.01)
        confidence = round(max(0.40, min(0.98, base_confidence - volatility_penalty)), 2)

        return RiskTrajectory(
            asset_id=asset_id,
            current_risk=current_risk,
            historical_values=points,
            trend_direction=direction,
            slope=round(slope, 3),
            acceleration=round(acceleration, 4),
            volatility=round(volatility, 2),
            moving_average=round(moving_avg, 2),
            ema=round(ema, 2),
            change_point_detected=cp_detected,
            change_point_description=cp_desc,
            data_sufficiency=DataSufficiency.SUFFICIENT,
            forecast_horizon_hours=horizon,
            projected_risk=round(projected, 2),
            projection_confidence=confidence,
            generated_at=now,
            notes=f"Full trajectory math verified across {n} observations.",
        )

