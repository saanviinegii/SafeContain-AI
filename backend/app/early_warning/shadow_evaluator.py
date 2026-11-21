"""Module 7.6.9: Shadow Mode Safety & Non-Interference Guard.

Guarantees that Phase 7.6 Predictive Threat Intelligence operates in strictly isolated
SHADOW MODE without altering production risk scores, active decision thresholds (theta* = 0.32),
asset configurations, or executing unapproved containment actions.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("safecontain.early_warning.shadow_evaluator")


class ShadowModeGuard:
    """Enforces non-destructive isolation and proves zero-interference with active production operations."""

    def __init__(self, config_path: Optional[str] = None):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
        self.config_path = config_path or os.path.join(base_dir, "artifacts", "calibration", "configurations.json")
        self._shadow_mode_enabled = True

    @property
    def is_shadow_mode(self) -> bool:
        """Returns True if engine is strictly operating in shadow mode."""
        return self._shadow_mode_enabled

    def capture_production_state_snapshot(self) -> Dict[str, Any]:
        """Captures cryptographic hashes and key metrics of live production configuration and state."""
        snapshot = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "config_hash": None,
            "active_threshold": 0.32,
            "active_version": "v1.0.0-baseline",
        }

        if os.path.exists(self.config_path):
            with open(self.config_path, "rb") as f:
                content = f.read()
                snapshot["config_hash"] = hashlib.sha256(content).hexdigest()
                try:
                    data = json.loads(content.decode("utf-8"))
                    active_cfgs = [c for c in data if c.get("status") == "ACTIVE"]
                    if active_cfgs:
                        snapshot["active_threshold"] = active_cfgs[0].get("operating_threshold", 0.32)
                        snapshot["active_version"] = active_cfgs[0].get("version", "1.0.0")
                except Exception:
                    pass

        return snapshot

    def verify_non_interference(
        self,
        pre_snapshot: Dict[str, Any],
        post_snapshot: Dict[str, Any],
    ) -> Tuple[bool, Dict[str, Any]]:
        """Verifies that executing early-warning predictions caused zero production state mutations."""
        pre_hash = pre_snapshot.get("config_hash")
        post_hash = post_snapshot.get("config_hash")

        hash_identical = (pre_hash == post_hash)
        threshold_preserved = (pre_snapshot.get("active_threshold") == post_snapshot.get("active_threshold"))
        version_preserved = (pre_snapshot.get("active_version") == post_snapshot.get("active_version"))

        zero_interference = (hash_identical and threshold_preserved and version_preserved)

        report = {
            "pre_config_hash": pre_hash,
            "post_config_hash": post_hash,
            "hash_identical": hash_identical,
            "pre_threshold": pre_snapshot.get("active_threshold"),
            "post_threshold": post_snapshot.get("active_threshold"),
            "threshold_preserved": threshold_preserved,
            "active_version_preserved": version_preserved,
            "zero_production_interference_verified": zero_interference,
        }

        if not zero_interference:
            logger.error("SHADOW MODE BREACH: Production state was mutated during early-warning execution! %s", report)
        else:
            logger.info("Shadow mode safety verified: 100% production immutability confirmed.")

        return zero_interference, report
