"""Base Threat Intelligence Source Adapter Interface (Phase 7.2E).

Provides standard interface for polling, normalizing, and querying threat intelligence sources.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from backend.app.threat_intel.models import ThreatIndicator


class BaseThreatIntelSource(ABC):
    """Abstract base class for all threat intelligence source adapters."""

    def __init__(self, source_name: str, source_type: str = "TELEMETRY", is_enabled: bool = True):
        self.source_name = source_name
        self.source_type = source_type
        self.is_enabled = is_enabled

    @abstractmethod
    def fetch_indicators(self) -> List[ThreatIndicator]:
        """Fetches and normalizes all available indicators from this source."""
        pass

    @abstractmethod
    def lookup_indicator(self, indicator_value: str) -> Optional[ThreatIndicator]:
        """Looks up a specific indicator value (e.g. IP, hash, CVE) within this source."""
        pass

    def get_source_metadata(self) -> Dict[str, Any]:
        """Returns metadata regarding this source adapter."""
        return {
            "source_name": self.source_name,
            "source_type": self.source_type,
            "is_enabled": self.is_enabled,
        }
