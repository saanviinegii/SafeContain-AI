"""Module 7.6.1: Threat Signal Extraction Engine.

Extracts evidence-grounded anomaly and threat signals from real security telemetry,
historical risk sequences, alert streams, and vulnerability scans.
Guarantees deterministic, idempotent execution without fabricating synthetic telemetry.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.app.early_warning.models import (
    RiskTrajectoryPoint,
    SignalType,
    ThreatSeverity,
    ThreatSignal,
)

logger = logging.getLogger("safecontain.early_warning.signal_extractor")


class ThreatSignalExtractor:
    """Extracts behavioral threat signals from multi-source enterprise security telemetry."""

    def __init__(self):
        self._extracted_signals: Dict[str, ThreatSignal] = {}
        self._processed_hashes: Set[str] = set()

    def _generate_signal_id(self, asset_id: str, signal_type: SignalType, time_bucket: str, discriminator: str = "") -> str:
        """Generates a deterministic, collision-resistant signal identifier."""
        raw = f"{asset_id}:{signal_type.value}:{time_bucket}:{discriminator}"
        token = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
        return f"sig-{signal_type.value.lower()[:8]}-{token}"

    def extract_signals_from_telemetry(
        self,
        alerts: Optional[List[Dict[str, Any]]] = None,
        evidence: Optional[List[Dict[str, Any]]] = None,
        risk_history: Optional[Dict[str, List[RiskTrajectoryPoint]]] = None,
        vulnerabilities: Optional[List[Dict[str, Any]]] = None,
        clear_cache: bool = False,
    ) -> List[ThreatSignal]:
        """Extracts all threat signals from provided telemetry feeds idempotently."""
        if clear_cache:
            self._extracted_signals.clear()
            self._processed_hashes.clear()

        signals: List[ThreatSignal] = []

        # 1. Process chronological risk trajectory points for risk spikes & slope anomalies
        if risk_history:
            for asset_id, points in risk_history.items():
                risk_signals = self.extract_risk_signals(asset_id, points)
                signals.extend(risk_signals)

        # 2. Process security alerts
        if alerts:
            alert_signals = self.extract_alert_signals(alerts)
            signals.extend(alert_signals)

        # 3. Process forensic evidence
        if evidence:
            evidence_signals = self.extract_evidence_signals(evidence)
            signals.extend(evidence_signals)

        # 4. Process vulnerability surges
        if vulnerabilities:
            vuln_signals = self.extract_vulnerability_signals(vulnerabilities)
            signals.extend(vuln_signals)

        # Register signals in internal index
        for s in signals:
            self._extracted_signals[s.signal_id] = s

        return list(self._extracted_signals.values())

    def extract_risk_signals(
        self,
        asset_id: str,
        points: List[RiskTrajectoryPoint],
        baseline_risk: float = 25.0,
    ) -> List[ThreatSignal]:
        """Extracts rapid risk increase, deviation from baseline, and risk spike signals."""
        signals: List[ThreatSignal] = []
        if not points or len(points) < 2:
            return signals

        # Sort chronologically
        valid_points = [p for p in points if p.timestamp is not None and not (p.risk_score is None or p.risk_score != p.risk_score)]
        sorted_points = sorted(valid_points, key=lambda x: x.timestamp)
        if len(sorted_points) < 2:
            return signals

        # Calculate consecutive risk jumps
        for i in range(1, len(sorted_points)):
            prev = sorted_points[i - 1]
            curr = sorted_points[i]

            time_delta = (curr.timestamp - prev.timestamp).total_seconds() / 3600.0
            if time_delta <= 0:
                continue

            risk_delta = curr.risk_score - prev.risk_score
            rate_per_hour = risk_delta / time_delta if time_delta > 0 else 0.0

            # Signal 1: Risk Spike (sudden jump >= 15.0 risk points in short interval <= 6h)
            if risk_delta >= 15.0 and time_delta <= 6.0:
                time_bucket = curr.timestamp.strftime("%Y%m%d%H")
                sig_id = self._generate_signal_id(asset_id, SignalType.RISK_SPIKE, time_bucket, f"{prev.risk_score:.1f}-{curr.risk_score:.1f}")
                if sig_id not in self._extracted_signals:
                    severity = ThreatSeverity.CRITICAL if curr.risk_score >= 70.0 or risk_delta >= 30.0 else ThreatSeverity.HIGH
                    sig = ThreatSignal(
                        signal_id=sig_id,
                        asset_id=asset_id,
                        signal_type=SignalType.RISK_SPIKE,
                        severity=severity,
                        observed_value=round(curr.risk_score, 2),
                        baseline_value=round(prev.risk_score, 2),
                        deviation=round(risk_delta, 2),
                        timestamp=curr.timestamp,
                        source=curr.source or "RiskTrajectoryEngine",
                        evidence=f"Acute risk spike detected: Risk surged +{risk_delta:.1f} points (from {prev.risk_score:.1f} to {curr.risk_score:.1f}) in {time_delta:.2f} hours.",
                        confidence=0.92,
                        related_entities=[asset_id],
                        metadata={"rate_per_hour": round(rate_per_hour, 2), "interval_hours": round(time_delta, 2)},
                    )
                    signals.append(sig)
                    self._extracted_signals[sig_id] = sig

            # Signal 2: Rapid Risk Increase (continuous velocity >= 5.0 points/hour)
            if rate_per_hour >= 5.0 and risk_delta >= 10.0:
                time_bucket = curr.timestamp.strftime("%Y%m%d%H")
                sig_id = self._generate_signal_id(asset_id, SignalType.RAPID_RISK_INCREASE, time_bucket, f"{rate_per_hour:.1f}")
                if sig_id not in self._extracted_signals:
                    sig = ThreatSignal(
                        signal_id=sig_id,
                        asset_id=asset_id,
                        signal_type=SignalType.RAPID_RISK_INCREASE,
                        severity=ThreatSeverity.HIGH if rate_per_hour >= 10.0 else ThreatSeverity.MEDIUM,
                        observed_value=round(rate_per_hour, 2),
                        baseline_value=0.0,
                        deviation=round(rate_per_hour, 2),
                        timestamp=curr.timestamp,
                        source="RiskVelocityTracker",
                        evidence=f"High risk escalation velocity: Risk escalating at {rate_per_hour:.2f} points/hour (total surge: +{risk_delta:.1f} pts).",
                        confidence=0.88,
                        related_entities=[asset_id],
                        metadata={"time_delta_hours": round(time_delta, 2)},
                    )
                    signals.append(sig)
                    self._extracted_signals[sig_id] = sig

        # Signal 3: Significant Deviation from Historical Baseline
        latest = sorted_points[-1]
        deviation_from_base = latest.risk_score - baseline_risk
        if deviation_from_base >= 25.0:
            time_bucket = latest.timestamp.strftime("%Y%m%d%H")
            sig_id = self._generate_signal_id(asset_id, SignalType.DEVIATION_FROM_BASELINE, time_bucket, f"{latest.risk_score:.1f}")
            if sig_id not in self._extracted_signals:
                sig = ThreatSignal(
                    signal_id=sig_id,
                    asset_id=asset_id,
                    signal_type=SignalType.DEVIATION_FROM_BASELINE,
                    severity=ThreatSeverity.CRITICAL if latest.risk_score >= 70.0 else ThreatSeverity.HIGH,
                    observed_value=round(latest.risk_score, 2),
                    baseline_value=round(baseline_risk, 2),
                    deviation=round(deviation_from_base, 2),
                    timestamp=latest.timestamp,
                    source="BaselineDeviationDetector",
                    evidence=f"Severe baseline deviation: Current risk {latest.risk_score:.1f} exceeds baseline reference ({baseline_risk:.1f}) by +{deviation_from_base:.1f} points.",
                    confidence=0.90,
                    related_entities=[asset_id],
                )
                signals.append(sig)
                self._extracted_signals[sig_id] = sig

        return signals

    def extract_alert_signals(self, alerts: List[Dict[str, Any]]) -> List[ThreatSignal]:
        """Extracts repeated suspicious events, unusual event frequency, and severity escalations."""
        signals: List[ThreatSignal] = []
        if not alerts:
            return signals

        # Group alerts by target asset
        asset_alerts: Dict[str, List[Dict[str, Any]]] = {}
        for a in alerts:
            target_id = a.get("target_node_id") or a.get("source_node_id") or a.get("asset_id")
            if target_id:
                asset_alerts.setdefault(target_id, []).append(a)

        for asset_id, a_list in asset_alerts.items():
            # Parse timestamps
            parsed_alerts = []
            for a in a_list:
                ts_raw = a.get("timestamp")
                if ts_raw:
                    try:
                        if isinstance(ts_raw, str):
                            ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                        elif isinstance(ts_raw, datetime):
                            ts = ts_raw
                        else:
                            continue
                        parsed_alerts.append((ts, a))
                    except Exception:
                        continue

            if not parsed_alerts:
                continue

            parsed_alerts.sort(key=lambda x: x[0])

            # Signal 4: Repeated Suspicious Events (>= 3 alerts on same asset in 24h)
            window_start = parsed_alerts[0][0]
            recent_alerts = [a for ts, a in parsed_alerts if (ts - window_start).total_seconds() <= 86400.0]
            if len(recent_alerts) >= 3:
                latest_ts = parsed_alerts[-1][0]
                time_bucket = latest_ts.strftime("%Y%m%d%H")
                sig_id = self._generate_signal_id(asset_id, SignalType.REPEATED_SUSPICIOUS_EVENTS, time_bucket, str(len(recent_alerts)))
                if sig_id not in self._extracted_signals:
                    alert_types = list(set(a.get("alert_type", "UNKNOWN") for a in recent_alerts))
                    critical_count = sum(1 for a in recent_alerts if str(a.get("severity", "")).upper() == "CRITICAL")
                    severity = ThreatSeverity.CRITICAL if critical_count >= 1 else ThreatSeverity.HIGH

                    sig = ThreatSignal(
                        signal_id=sig_id,
                        asset_id=asset_id,
                        signal_type=SignalType.REPEATED_SUSPICIOUS_EVENTS,
                        severity=severity,
                        observed_value=float(len(recent_alerts)),
                        baseline_value=1.0,
                        deviation=float(len(recent_alerts) - 1),
                        timestamp=latest_ts,
                        source="AlertCorrelationSensor",
                        evidence=f"Concentrated anomalous event cluster: {len(recent_alerts)} suspicious alerts detected within 24h window. Categories: {', '.join(alert_types[:4])}.",
                        confidence=0.94,
                        related_entities=[a.get("alert_id") for a in recent_alerts if a.get("alert_id")],
                        metadata={"alert_types": alert_types, "critical_count": critical_count},
                    )
                    signals.append(sig)
                    self._extracted_signals[sig_id] = sig

            # Signal 5: Severity Escalation (shift from LOW/MEDIUM to HIGH/CRITICAL)
            severities = [str(a.get("severity", "LOW")).upper() for _, a in parsed_alerts]
            if len(severities) >= 2:
                early_sev = severities[0]
                late_sev = severities[-1]
                sev_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                if sev_order.get(late_sev, 0) > sev_order.get(early_sev, 0) and sev_order.get(late_sev, 0) >= 3:
                    latest_ts = parsed_alerts[-1][0]
                    time_bucket = latest_ts.strftime("%Y%m%d%H")
                    sig_id = self._generate_signal_id(asset_id, SignalType.SEVERITY_ESCALATION, time_bucket, f"{early_sev}->{late_sev}")
                    if sig_id not in self._extracted_signals:
                        sig = ThreatSignal(
                            signal_id=sig_id,
                            asset_id=asset_id,
                            signal_type=SignalType.SEVERITY_ESCALATION,
                            severity=ThreatSeverity.CRITICAL if late_sev == "CRITICAL" else ThreatSeverity.HIGH,
                            observed_value=float(sev_order.get(late_sev, 3)),
                            baseline_value=float(sev_order.get(early_sev, 1)),
                            deviation=float(sev_order.get(late_sev, 3) - sev_order.get(early_sev, 1)),
                            timestamp=latest_ts,
                            source="TelemetrySeverityAuditor",
                            evidence=f"Threat severity escalation: Alert posture escalated from {early_sev} to {late_sev} on asset.",
                            confidence=0.91,
                            related_entities=[asset_id],
                        )
                        signals.append(sig)
                        self._extracted_signals[sig_id] = sig

            # Signal 6: Unusual Event Frequency (burst of >= 5 events in 2h)
            for i in range(len(parsed_alerts)):
                t_i = parsed_alerts[i][0]
                burst = [a for ts, a in parsed_alerts[i:] if (ts - t_i).total_seconds() <= 7200.0]
                if len(burst) >= 5:
                    time_bucket = t_i.strftime("%Y%m%d%H")
                    sig_id = self._generate_signal_id(asset_id, SignalType.UNUSUAL_EVENT_FREQUENCY, time_bucket, str(len(burst)))
                    if sig_id not in self._extracted_signals:
                        sig = ThreatSignal(
                            signal_id=sig_id,
                            asset_id=asset_id,
                            signal_type=SignalType.UNUSUAL_EVENT_FREQUENCY,
                            severity=ThreatSeverity.CRITICAL if len(burst) >= 8 else ThreatSeverity.HIGH,
                            observed_value=float(len(burst)),
                            baseline_value=1.0,
                            deviation=float(len(burst) - 1),
                            timestamp=t_i,
                            source="EventFrequencyMonitor",
                            evidence=f"Unusual high-frequency alert burst: {len(burst)} security events fired within a 2-hour window.",
                            confidence=0.89,
                            related_entities=[a.get("alert_id") for a in burst if a.get("alert_id")],
                        )
                        signals.append(sig)
                        self._extracted_signals[sig_id] = sig
                    break

        return signals

    def extract_evidence_signals(self, evidence: List[Dict[str, Any]]) -> List[ThreatSignal]:
        """Extracts abnormal telemetry behavior and persistent suspicious activity from forensic evidence."""
        signals: List[ThreatSignal] = []
        if not evidence:
            return signals

        # Count evidence per node
        node_evidence: Dict[str, List[Dict[str, Any]]] = {}
        for ev in evidence:
            nid = ev.get("related_node_id") or ev.get("asset_id")
            if nid:
                node_evidence.setdefault(nid, []).append(ev)

        for asset_id, ev_list in node_evidence.items():
            confirmed_ev = [e for e in ev_list if str(e.get("evidence_status", "")).upper() == "CONFIRMED"]
            if len(confirmed_ev) >= 4:
                latest_ev = ev_list[-1]
                ts_raw = latest_ev.get("timestamp")
                ts = datetime.now(timezone.utc)
                if ts_raw:
                    try:
                        ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
                    except Exception:
                        pass

                time_bucket = ts.strftime("%Y%m%d%H")
                sig_id = self._generate_signal_id(asset_id, SignalType.PERSISTENT_SUSPICIOUS_ACTIVITY, time_bucket, str(len(confirmed_ev)))
                if sig_id not in self._extracted_signals:
                    sig = ThreatSignal(
                        signal_id=sig_id,
                        asset_id=asset_id,
                        signal_type=SignalType.PERSISTENT_SUSPICIOUS_ACTIVITY,
                        severity=ThreatSeverity.HIGH,
                        observed_value=float(len(confirmed_ev)),
                        baseline_value=1.0,
                        deviation=float(len(confirmed_ev) - 1),
                        timestamp=ts,
                        source="ForensicEvidenceEngine",
                        evidence=f"Persistent suspicious forensic trace: {len(confirmed_ev)} multi-source confirmed evidence items linked to asset.",
                        confidence=0.95,
                        related_entities=[e.get("evidence_id") for e in confirmed_ev if e.get("evidence_id")],
                    )
                    signals.append(sig)
                    self._extracted_signals[sig_id] = sig

        return signals

    def extract_vulnerability_signals(self, vulnerabilities: List[Dict[str, Any]]) -> List[ThreatSignal]:
        """Extracts vulnerability exposure surge signals on critical or unpatched assets."""
        signals: List[ThreatSignal] = []
        if not vulnerabilities:
            return signals

        # Group by asset
        asset_vulns: Dict[str, List[Dict[str, Any]]] = {}
        for v in vulnerabilities:
            aid = v.get("asset_id")
            if aid:
                asset_vulns.setdefault(aid, []).append(v)

        for asset_id, v_list in asset_vulns.items():
            critical_vulns = [v for v in v_list if str(v.get("severity", "")).upper() == "CRITICAL" or float(v.get("cvss_score") or 0.0) >= 9.0]
            if len(critical_vulns) >= 2:
                latest_v = v_list[-1]
                ts = datetime.now(timezone.utc)
                ts_raw = latest_v.get("discovered_at")
                if ts_raw:
                    try:
                        ts = datetime.fromisoformat(str(ts_raw).replace("Z", "+00:00"))
                    except Exception:
                        pass

                time_bucket = ts.strftime("%Y%m%d%H")
                sig_id = self._generate_signal_id(asset_id, SignalType.VULNERABILITY_EXPOSURE_SURGE, time_bucket, str(len(critical_vulns)))
                if sig_id not in self._extracted_signals:
                    cve_ids = [v.get("cve_id", "") for v in critical_vulns if v.get("cve_id")]
                    sig = ThreatSignal(
                        signal_id=sig_id,
                        asset_id=asset_id,
                        signal_type=SignalType.VULNERABILITY_EXPOSURE_SURGE,
                        severity=ThreatSeverity.CRITICAL,
                        observed_value=float(len(critical_vulns)),
                        baseline_value=0.0,
                        deviation=float(len(critical_vulns)),
                        timestamp=ts,
                        source="VulnerabilityScanFeed",
                        evidence=f"Critical vulnerability exposure surge: {len(critical_vulns)} CVSS >= 9.0 vulnerabilities open on asset. CVEs: {', '.join(cve_ids[:3])}.",
                        confidence=0.96,
                        related_entities=cve_ids,
                    )
                    signals.append(sig)
                    self._extracted_signals[sig_id] = sig

        return signals

    def get_all_signals(self) -> List[ThreatSignal]:
        """Returns all currently extracted signals."""
        return list(self._extracted_signals.values())

    def get_signals_for_asset(self, asset_id: str) -> List[ThreatSignal]:
        """Returns extracted signals associated with a specific asset."""
        return [s for s in self._extracted_signals.values() if s.asset_id == asset_id or asset_id in s.related_entities]
