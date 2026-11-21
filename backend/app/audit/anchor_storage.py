"""SafeContain AI Anchor Manifest Storage.

Persists local cryptographic evidence anchor manifests, Merkle batch metadata,
and transaction receipts. Ensures anchor manifests can be enumerated, retrieved,
and independently verified across server restarts.
"""

import json
import logging
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.app.core.config import settings

logger = logging.getLogger(__name__)


class StoredAnchorManifest(BaseModel):
    """Full metadata manifest for an anchored batch of audit ledger records."""
    anchor_id: str
    merkle_root: str
    batch_id: str
    first_sequence: int
    last_sequence: int
    record_count: int
    first_event_id: str
    last_event_id: str
    leaves: List[str] = Field(default_factory=list)
    event_ids: List[str] = Field(default_factory=list)
    algorithm: str = "SHA-256-RFC6962-MerkleTree"
    transaction_hash: Optional[str] = None
    network: str = "Ethereum Sepolia Testnet"
    chain_id: int = 11155111
    contract_address: Optional[str] = None
    block_number: Optional[int] = None
    confirmation_status: str = Field(
        default="LOCAL_VERIFIED",
        description="CONFIRMED | PENDING | LOCAL_VERIFIED | FAILED"
    )
    verification_status: str = "VERIFIED"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    anchored_by: str = "system"


class AnchorStorage:
    """Thread-safe persistent storage for evidence anchor manifests."""

    def __init__(self, storage_path: Optional[str] = None):
        self.storage_path = storage_path or os.path.join("artifacts", "blockchain", "anchor_manifests.json")
        self._lock = threading.Lock()
        self._anchors: Dict[str, StoredAnchorManifest] = {}
        self._load()

    def _load(self) -> None:
        """Loads manifests from disk or initializes empty directory."""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data:
                        manifest = StoredAnchorManifest.model_validate(item)
                        self._anchors[manifest.anchor_id] = manifest
                logger.info("Loaded %d anchor manifests from %s", len(self._anchors), self.storage_path)
            except Exception as e:
                logger.warning("Could not load anchor storage: %s", e)

    def _save(self) -> None:
        """Saves manifests to disk."""
        try:
            parent = os.path.dirname(self.storage_path)
            if parent and not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)
            with open(self.storage_path, "w", encoding="utf-8") as f:
                json.dump(
                    [m.model_dump(mode="json") for m in self._anchors.values()],
                    f,
                    indent=2
                )
        except Exception as e:
            logger.error("Failed to save anchor manifests: %s", e)

    def save_manifest(self, manifest: StoredAnchorManifest) -> None:
        """Persists a new or updated anchor manifest."""
        with self._lock:
            self._anchors[manifest.anchor_id] = manifest
            self._save()

    def get_manifest(self, anchor_id: str) -> Optional[StoredAnchorManifest]:
        """Retrieves manifest by anchor ID."""
        with self._lock:
            return self._anchors.get(anchor_id)

    def get_all_manifests(self) -> List[StoredAnchorManifest]:
        """Returns all anchor manifests in reverse chronological order."""
        with self._lock:
            return sorted(
                list(self._anchors.values()),
                key=lambda m: m.created_at,
                reverse=True
            )

    def get_last_anchored_sequence(self) -> int:
        """Finds highest sequence number across all existing anchors."""
        with self._lock:
            if not self._anchors:
                return 0
            return max(m.last_sequence for m in self._anchors.values())
