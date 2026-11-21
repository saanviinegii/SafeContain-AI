"""Internal Telemetry Threat Intelligence Source Adapter (Phase 7.2E).

Extracts, normalizes, and deduplicates threat indicators from:
- Security Telemetry Alerts (SIEM/EDR alert types, communicating IPs, suspicious behaviors)
- Enterprise Vulnerability Registries (CVE IDs, CVSS scores, exploitability PoCs)
- Forensic Evidence Records (EDR process lines, network flows, forensic telemetry)
- Infrastructure Graph Nodes (Asset IPs, internal domains, compromised endpoints)
"""

from __future__ import annotations

import re
import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

import pandas as pd

from backend.app.ml.dataset_loader import DatasetLoader
from backend.app.threat_intel.models import (
    IndicatorType,
    ThreatIndicator,
    ThreatSeverity,
)
from backend.app.threat_intel.sources.base import BaseThreatIntelSource

logger = logging.getLogger("safecontain.threat_intel.internal")

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _map_severity(raw_sev: Any) -> ThreatSeverity:
    """Maps heterogeneous severity strings/numbers to standardized ThreatSeverity."""
    if isinstance(raw_sev, (int, float)):
        if raw_sev >= 9.0 or raw_sev >= 0.85:
            return ThreatSeverity.CRITICAL
        if raw_sev >= 7.0 or raw_sev >= 0.65:
            return ThreatSeverity.HIGH
        if raw_sev >= 4.0 or raw_sev >= 0.40:
            return ThreatSeverity.MEDIUM
        return ThreatSeverity.LOW

    s = str(raw_sev).strip().upper()
    if "CRIT" in s:
        return ThreatSeverity.CRITICAL
    if "HIGH" in s:
        return ThreatSeverity.HIGH
    if "MED" in s:
        return ThreatSeverity.MEDIUM
    return ThreatSeverity.LOW


class InternalTelemetrySource(BaseThreatIntelSource):
    """Source adapter extracting threat indicators from verified platform telemetry datasets."""

    def __init__(self, dataset_loader: Optional[DatasetLoader] = None):
        super().__init__(source_name="Internal_Enterprise_Telemetry", source_type="TELEMETRY", is_enabled=True)
        self.loader = dataset_loader or DatasetLoader()
        self._indicators_cache: Optional[List[ThreatIndicator]] = None
        self._lookup_map: Dict[str, ThreatIndicator] = {}

    def fetch_indicators(self, force_refresh: bool = False) -> List[ThreatIndicator]:
        """Extracts and normalizes indicators across alerts, evidence, vulnerabilities, and assets."""
        if not force_refresh and self._indicators_cache is not None:
            return self._indicators_cache

        indicators_by_key: Dict[str, ThreatIndicator] = {}

        def _upsert(
            ind_type: IndicatorType,
            raw_value: str,
            title: str,
            severity: ThreatSeverity,
            confidence: float,
            source: str,
            asset_ids: Optional[List[str]] = None,
            alert_ids: Optional[List[str]] = None,
            cves: Optional[List[str]] = None,
            desc: Optional[str] = None,
            timestamp: Optional[datetime] = None,
            metadata: Optional[Dict[str, Any]] = None,
        ) -> None:
            val_clean = raw_value.strip()
            if ind_type == IndicatorType.VULNERABILITY_CVE:
                val_clean = val_clean.upper()
            elif ind_type in (IndicatorType.IP_ADDRESS, IndicatorType.DOMAIN, IndicatorType.FILE_HASH):
                val_clean = val_clean.lower()

            if not val_clean:
                return

            dedup_key = f"{ind_type.value}::{val_clean}"
            ts = timestamp or datetime.now(timezone.utc)

            if dedup_key in indicators_by_key:
                existing = indicators_by_key[dedup_key]
                # Merge associated references
                if asset_ids:
                    existing.associated_asset_ids = sorted(list(set(existing.associated_asset_ids + asset_ids)))
                if alert_ids:
                    existing.associated_alert_ids = sorted(list(set(existing.associated_alert_ids + alert_ids)))
                if cves:
                    existing.associated_cves = sorted(list(set(existing.associated_cves + cves)))
                # Update confidence and severity to max observed
                existing.confidence = max(existing.confidence, confidence)
                if severity == ThreatSeverity.CRITICAL or (severity == ThreatSeverity.HIGH and existing.severity != ThreatSeverity.CRITICAL):
                    existing.severity = severity
                existing.last_seen = max(existing.last_seen, ts)
            else:
                digest = hashlib.md5(f"{ind_type.value}:{val_clean}".encode("utf-8")).hexdigest()[:10]
                ind_id = f"ind-{ind_type.value.lower()[:3]}-{digest}"
                new_ind = ThreatIndicator(
                    id=ind_id,
                    type=ind_type,
                    value=val_clean,
                    title=title or f"{ind_type.value}: {val_clean}",
                    severity=severity,
                    confidence=round(confidence, 2),
                    source=source,
                    first_seen=ts,
                    last_seen=ts,
                    associated_asset_ids=asset_ids or [],
                    associated_alert_ids=alert_ids or [],
                    associated_cves=cves or [],
                    description=desc,
                    metadata=metadata or {},
                )
                indicators_by_key[dedup_key] = new_ind

        # ---------------------------------------------------------------------
        # 1. Process Vulnerabilities (CVE Indicators)
        # ---------------------------------------------------------------------
        try:
            vulns_df = self.loader.load_table("vulnerabilities.csv")
            try:
                assets_df = self.loader.load_table("assets.csv")
                asset_to_node = dict(zip(assets_df["asset_id"], assets_df["node_id"]))
            except Exception:
                asset_to_node = {}

            for _, r in vulns_df.iterrows():
                cve = str(r.get("cve_id", "")).strip()
                if not cve or cve.lower() == "nan":
                    continue
                raw_ast = str(r.get("asset_id", ""))
                graph_node_id = asset_to_node.get(raw_ast, raw_ast)
                sev = _map_severity(r.get("severity", "MEDIUM"))
                cvss = float(r.get("cvss_score", 7.0))
                title = str(r.get("title", f"Vulnerability {cve}"))
                src = str(r.get("evidence_source", "Tenable_Nessus"))

                linked_nodes = [graph_node_id] if graph_node_id and graph_node_id.lower() != "nan" else []
                _upsert(
                    ind_type=IndicatorType.VULNERABILITY_CVE,
                    raw_value=cve,
                    title=title,
                    severity=sev,
                    confidence=min(1.0, cvss / 10.0),
                    source=src,
                    asset_ids=linked_nodes,
                    cves=[cve],
                    desc=str(r.get("description", "")),
                    metadata={"cvss_score": cvss, "exploitability": str(r.get("exploitability", "UNKNOWN")), "raw_asset_id": raw_ast},
                )
        except Exception as e:
            logger.warning("Error extracting vulnerability indicators: %s", e)

        # ---------------------------------------------------------------------
        # 2. Process Security Alerts (Behaviors, IP communications, Signatures)
        # ---------------------------------------------------------------------
        try:
            alerts_df = self.loader.load_table("security_alerts.csv")
            for _, r in alerts_df.iterrows():
                alert_id = str(r.get("alert_id", ""))
                alert_type = str(r.get("alert_type", "SUSPICIOUS_ACTIVITY")).strip()
                sev = _map_severity(r.get("severity", "HIGH"))
                conf = float(r.get("confidence", 0.85))
                src = str(r.get("detection_source", "Splunk_ES"))
                desc = str(r.get("description", ""))
                src_node = str(r.get("source_node_id", ""))
                tgt_node = str(r.get("target_node_id", ""))
                rel_cve = str(r.get("related_vulnerability_id", ""))
                rel_path = str(r.get("related_attack_path_id", ""))

                linked_assets = [n for n in (src_node, tgt_node) if n and n.lower() != "nan"]
                linked_cves = [rel_cve] if rel_cve and rel_cve.lower() != "nan" else []

                # Behavior Indicator
                _upsert(
                    ind_type=IndicatorType.SUSPICIOUS_BEHAVIOR,
                    raw_value=alert_type,
                    title=f"Behavior: {alert_type.replace('_', ' ').title()}",
                    severity=sev,
                    confidence=conf,
                    source=src,
                    asset_ids=linked_assets,
                    alert_ids=[alert_id],
                    cves=linked_cves,
                    desc=desc,
                    metadata={"attack_path_id": rel_path},
                )

                # Extract IP addresses in alert description if present
                found_ips = IP_REGEX.findall(desc)
                for ip in found_ips:
                    _upsert(
                        ind_type=IndicatorType.IP_ADDRESS,
                        raw_value=ip,
                        title=f"Suspicious IP: {ip}",
                        severity=sev,
                        confidence=conf,
                        source=src,
                        asset_ids=linked_assets,
                        alert_ids=[alert_id],
                        cves=linked_cves,
                        desc=f"Communicating IP observed in alert {alert_id}",
                    )
        except Exception as e:
            logger.warning("Error extracting alert indicators: %s", e)

        # ---------------------------------------------------------------------
        # 3. Process Evidence Records (EDR/Forensic Signatures)
        # ---------------------------------------------------------------------
        try:
            evid_df = self.loader.load_table("evidence.csv")
            for _, r in evid_df.iterrows():
                ev_type = str(r.get("evidence_type", "FORENSIC_TELEMETRY")).strip()
                node_id = str(r.get("related_node_id", ""))
                alert_id = str(r.get("related_alert_id", ""))
                cve_id = str(r.get("related_vulnerability_id", ""))
                src = str(r.get("source", "CrowdStrike_Sensor"))
                conf = float(r.get("confidence", 0.9))
                obs = str(r.get("observation", ""))

                _upsert(
                    ind_type=IndicatorType.THREAT_SIGNATURE,
                    raw_value=ev_type,
                    title=f"Forensic Signature: {ev_type.replace('_', ' ').title()}",
                    severity=ThreatSeverity.HIGH if "PROCESS" in ev_type or "FLOW" in ev_type else ThreatSeverity.MEDIUM,
                    confidence=conf,
                    source=src,
                    asset_ids=[node_id] if node_id else [],
                    alert_ids=[alert_id] if alert_id else [],
                    cves=[cve_id] if cve_id else [],
                    desc=obs,
                )
        except Exception as e:
            logger.warning("Error extracting evidence indicators: %s", e)

        # ---------------------------------------------------------------------
        # 4. Process Asset Graph Nodes (IPs and Hostnames of At-Risk Nodes)
        # ---------------------------------------------------------------------
        try:
            nodes_df = self.loader.load_table("nodes.csv")
            for _, r in nodes_df.iterrows():
                nid = str(r.get("node_id", ""))
                ip = str(r.get("ip_address", "")).strip()
                host = str(r.get("hostname", "")).strip()
                sec_status = str(r.get("security_status", "HEALTHY")).upper()
                is_at_risk = sec_status != "HEALTHY"

                if ip and ip.lower() != "nan" and is_at_risk:
                    _upsert(
                        ind_type=IndicatorType.IP_ADDRESS,
                        raw_value=ip,
                        title=f"Internal Asset IP: {ip} ({r.get('name', nid)})",
                        severity=ThreatSeverity.CRITICAL if sec_status == "COMPROMISED" else ThreatSeverity.HIGH,
                        confidence=0.95,
                        source="Enterprise_CMDB",
                        asset_ids=[nid],
                        desc=f"Network IP for compromised asset {nid}",
                    )

                if host and host.lower() != "nan" and is_at_risk:
                    _upsert(
                        ind_type=IndicatorType.DOMAIN,
                        raw_value=host,
                        title=f"Internal Domain: {host}",
                        severity=ThreatSeverity.HIGH,
                        confidence=0.90,
                        source="Enterprise_DNS",
                        asset_ids=[nid],
                        desc=f"Fully qualified domain for asset {nid}",
                    )
        except Exception as e:
            logger.warning("Error extracting node network indicators: %s", e)

        result_list = list(indicators_by_key.values())
        self._indicators_cache = result_list
        self._lookup_map = {ind.value.lower(): ind for ind in result_list}
        # Also index by id
        for ind in result_list:
            self._lookup_map[ind.id.lower()] = ind

        logger.info("Internal telemetry source extracted %d verified indicators.", len(result_list))
        return result_list

    def lookup_indicator(self, indicator_value: str) -> Optional[ThreatIndicator]:
        """Fast lookup by indicator value, ID, or CVE."""
        if not self._lookup_map:
            self.fetch_indicators()
        return self._lookup_map.get(indicator_value.strip().lower())
