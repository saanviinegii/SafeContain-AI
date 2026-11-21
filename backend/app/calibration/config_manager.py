"""Module 7.5.7: Configuration Versioning & Rollback Manager for SafeContain AI.

Manages the lifecycle, semantic versioning, audit trail, and rollback of risk threshold configurations.
Persists configuration history to artifacts/calibration/configurations.json.
Enforces RBAC workflow: Analyst stages/approves -> Administrator activates/rolls back.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.app.calibration.models import (
    ConfigurationStatus,
    ThresholdConfiguration,
    ThresholdTiers,
)
from backend.app.ml.model_trainer import DEFAULT_ARTIFACTS_DIR

logger = logging.getLogger("safecontain.calibration.config_manager")

DEFAULT_CALIB_DIR = os.path.join(DEFAULT_ARTIFACTS_DIR, "calibration")
DEFAULT_CONFIGS_FILE = os.path.join(DEFAULT_CALIB_DIR, "configurations.json")


class ConfigurationVersionManager:
    """Manages versioned risk threshold configurations with human-in-the-loop approval and rollback."""

    _instance: Optional["ConfigurationVersionManager"] = None
    _lock = threading.Lock()

    def __init__(self, storage_path: Optional[str] = None):
        self.storage_path = storage_path or DEFAULT_CONFIGS_FILE
        self._configs: Dict[str, ThresholdConfiguration] = {}
        self._ensure_storage()
        self._load()

    @classmethod
    def get_instance(cls) -> "ConfigurationVersionManager":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _ensure_storage(self) -> None:
        directory = os.path.dirname(self.storage_path)
        if directory and not os.path.exists(directory):
            try:
                os.makedirs(directory, exist_ok=True)
            except Exception as e:
                logger.warning("Could not create calibration directory '%s': %s", directory, e)

    def _load(self) -> None:
        with self._lock:
            if os.path.exists(self.storage_path):
                try:
                    with open(self.storage_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        for item in data:
                            cfg = ThresholdConfiguration(**item)
                            self._configs[cfg.config_id] = cfg
                    logger.info("Loaded %d configurations from '%s'", len(self._configs), self.storage_path)
                except Exception as e:
                    logger.error("Failed to load configurations from '%s': %s", self.storage_path, e)

            # Ensure default baseline configuration exists
            if not self._configs:
                self._create_default_baseline()

    def _save(self) -> None:
        self._ensure_storage()
        try:
            configs_list = [c.model_dump(mode="json") for c in self._configs.values()]
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(configs_list, f, indent=2, default=str)
        except Exception as e:
            logger.error("Failed to save configurations to '%s': %s", self.storage_path, e)

    def _create_default_baseline(self) -> ThresholdConfiguration:
        baseline_tiers = ThresholdTiers(
            low_cutoff=0.0,
            medium_cutoff=0.20,
            high_cutoff=0.32,
            critical_cutoff=0.70,
        )
        baseline_cfg = ThresholdConfiguration(
            config_id="cfg-v1.0.0-baseline",
            version="1.0.0",
            operating_threshold=0.32,
            tiers=baseline_tiers,
            status=ConfigurationStatus.ACTIVE,
            author_id="system-baseline",
            author_role="ADMIN",
            rationale="Initial baseline decision threshold theta*=0.32 calibrated in Phase 7.2B.",
            supporting_evidence={"source": "Phase 7.2B Cost-Sensitive Calibration", "recall": 0.90},
            activated_by="system-admin",
            activated_at=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc),
        )
        self._configs[baseline_cfg.config_id] = baseline_cfg
        self._save()
        return baseline_cfg

    def get_active_configuration(self) -> ThresholdConfiguration:
        """Returns the currently active threshold configuration."""
        with self._lock:
            for cfg in self._configs.values():
                if cfg.status == ConfigurationStatus.ACTIVE:
                    return cfg
            # Fallback if no configuration is explicitly ACTIVE
            return self._create_default_baseline()

    def list_configurations(self) -> List[ThresholdConfiguration]:
        """Returns all configurations sorted in reverse chronological order."""
        with self._lock:
            items = list(self._configs.values())
            items.sort(key=lambda x: x.created_at, reverse=True)
            return items

    def get_configuration(self, config_id: str) -> Optional[ThresholdConfiguration]:
        """Retrieves a configuration by its unique config_id."""
        with self._lock:
            return self._configs.get(config_id)

    def stage_candidate(self, config: ThresholdConfiguration) -> ThresholdConfiguration:
        """Stages a newly proposed candidate configuration in PENDING_APPROVAL status."""
        with self._lock:
            config.status = ConfigurationStatus.PENDING_APPROVAL
            self._configs[config.config_id] = config
            self._save()
            return config

    def approve_configuration(self, config_id: str, analyst_id: str) -> Optional[ThresholdConfiguration]:
        """Analyst sign-off: advances configuration from PENDING_APPROVAL to APPROVED."""
        with self._lock:
            cfg = self._configs.get(config_id)
            if not cfg:
                return None
            if cfg.status != ConfigurationStatus.PENDING_APPROVAL:
                logger.warning("Configuration '%s' cannot be approved from status '%s'", config_id, cfg.status)
                return cfg

            cfg.status = ConfigurationStatus.APPROVED
            cfg.approved_by = analyst_id
            cfg.approved_at = datetime.now(timezone.utc)
            self._save()
            return cfg

    def reject_configuration(self, config_id: str, user_id: str, reason: str) -> Optional[ThresholdConfiguration]:
        """Rejects a candidate configuration."""
        with self._lock:
            cfg = self._configs.get(config_id)
            if not cfg:
                return None

            cfg.status = ConfigurationStatus.REJECTED
            cfg.rationale = f"{cfg.rationale} [REJECTED by {user_id}: {reason}]"
            self._save()
            return cfg

    def activate_configuration(self, config_id: str, admin_id: str) -> Optional[ThresholdConfiguration]:
        """Administrator action: activates an approved configuration, superseding previous active."""
        with self._lock:
            target = self._configs.get(config_id)
            if not target:
                return None

            # Mark all currently active configurations as SUPERSEDED
            now = datetime.now(timezone.utc)
            for cfg in self._configs.values():
                if cfg.status == ConfigurationStatus.ACTIVE and cfg.config_id != config_id:
                    cfg.status = ConfigurationStatus.SUPERSEDED

            target.status = ConfigurationStatus.ACTIVE
            target.activated_by = admin_id
            target.activated_at = now
            self._save()
            return target

    def rollback_configuration(
        self,
        target_config_id: str,
        admin_id: str,
        reason: str,
    ) -> Optional[ThresholdConfiguration]:
        """Administrator action: rolls back active threshold to a previous configuration version."""
        with self._lock:
            target = self._configs.get(target_config_id)
            if not target:
                return None

            now = datetime.now(timezone.utc)
            for cfg in self._configs.values():
                if cfg.status == ConfigurationStatus.ACTIVE:
                    cfg.status = ConfigurationStatus.SUPERSEDED

            target.status = ConfigurationStatus.ACTIVE
            target.rationale = f"{target.rationale} [ROLLED BACK by {admin_id}: {reason}]"
            target.activated_by = admin_id
            target.activated_at = now
            self._save()
            return target

    def clear(self) -> None:
        """Clears configurations (primarily for test fixture teardowns)."""
        with self._lock:
            self._configs.clear()
            if os.path.exists(self.storage_path):
                try:
                    os.remove(self.storage_path)
                except Exception:
                    pass
