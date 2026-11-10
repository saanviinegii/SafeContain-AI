"""SafeContain AI Blockchain Smart Contract & Permissioned Ledger Anchor.

Conforms strictly to SafeContain AI R&D Blueprint:
- Page 4: "Blockchain ledger / smart contract | Audit integrity | Record hashes, timestamps and minimal event metadata"
- Page 2: "On-chain: record ID, cryptographic hash, timestamp, event type and minimal approval reference."
- Page 2: "Off-chain: retain detailed logs, graph snapshots and sensitive evidence in controlled storage."
- Page 2: "Integrity check: recompute the off-chain record hash and compare it with the ledger entry."
- Page 2: "Limitation: blockchain provides tamper evidence, not truth; false input can still be recorded immutably."
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.app.models.domain import AuditEvent

logger = logging.getLogger(__name__)


class OnChainAuditRecord(BaseModel):
    """Minimal immutable audit tuple anchored on blockchain / permissioned ledger."""
    record_id: str = Field(description="Unique event ID (e.g. aud-000001-...)")
    cryptographic_hash: str = Field(description="SHA-256 hash of the off-chain canonical record")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: str = Field(description="EVIDENCE_SNAPSHOT | RECOMMENDATION | SIMULATION_SUMMARY | APPROVAL")
    approval_reference: Optional[str] = Field(default=None, description="Minimal approval reference / signature")
    block_number: int = Field(default=1, description="Ledger block height")
    transaction_hash: str = Field(description="Simulated or live EVM transaction receipt hash")
    network_id: str = Field(default="safecontain-permissioned-ledger-v1", description="Chain / network ID")


class BlockchainVerificationResult(BaseModel):
    """Result of recomputing off-chain record hash and verifying against blockchain ledger."""
    is_valid: bool
    record_id: str
    recomputed_off_chain_hash: str
    on_chain_hash: Optional[str] = None
    on_chain_timestamp: Optional[datetime] = None
    event_type: Optional[str] = None
    approval_reference: Optional[str] = None
    block_number: Optional[int] = None
    transaction_hash: Optional[str] = None
    verification_message: str
    tamper_detected: bool = False
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    limitation_notice: str = (
        "Cryptographic ledger provides tamper evidence, not truth; false input can still be recorded immutably."
    )


class BlockchainLedgerAnchor:
    """Smart contract anchor managing on-chain audit records & verification."""

    def __init__(self, network_id: str = "safecontain-evm-testnet"):
        self.network_id = network_id
        self._on_chain_store: Dict[str, OnChainAuditRecord] = {}
        self._current_block: int = 1000

    def anchor_event(self, event: AuditEvent) -> OnChainAuditRecord:
        """Anchors an off-chain AuditEvent onto the immutable ledger.
        
        Extracts only minimal on-chain fields:
        (record ID, cryptographic hash, timestamp, event type, minimal approval reference).
        """
        self._current_block += 1
        
        # Deterministic transaction hash from block and hash
        tx_data = f"{self._current_block}:{event.event_id}:{event.current_hash}:{datetime.now(timezone.utc).isoformat()}"
        tx_hash = "0x" + hashlib.sha256(tx_data.encode("utf-8")).hexdigest()

        record = OnChainAuditRecord(
            record_id=event.event_id,
            cryptographic_hash=event.current_hash,
            timestamp=event.timestamp,
            event_type=event.event_type or "DECISION_EVENT",
            approval_reference=event.approval_reference or "N/A",
            block_number=self._current_block,
            transaction_hash=tx_hash,
            network_id=self.network_id,
        )

        self._on_chain_store[event.event_id] = record
        logger.info(
            "Anchored event %s (Type: %s, Hash: %s) on block #%d (Tx: %s)",
            event.event_id,
            record.event_type,
            record.cryptographic_hash[:12] + "...",
            record.block_number,
            record.transaction_hash[:12] + "...",
        )
        return record

    def verify_event(self, event: AuditEvent, recomputed_hash: str) -> BlockchainVerificationResult:
        """Integrity check: recomputes the off-chain record hash and compares it with ledger entry."""
        on_chain = self._on_chain_store.get(event.event_id)

        if not on_chain:
            return BlockchainVerificationResult(
                is_valid=False,
                record_id=event.event_id,
                recomputed_off_chain_hash=recomputed_hash,
                verification_message="Record not found on blockchain ledger. Has not been anchored yet.",
                tamper_detected=False,
            )

        # Check if recomputed hash matches on-chain hash
        if on_chain.cryptographic_hash == recomputed_hash:
            return BlockchainVerificationResult(
                is_valid=True,
                record_id=event.event_id,
                recomputed_off_chain_hash=recomputed_hash,
                on_chain_hash=on_chain.cryptographic_hash,
                on_chain_timestamp=on_chain.timestamp,
                event_type=on_chain.event_type,
                approval_reference=on_chain.approval_reference,
                block_number=on_chain.block_number,
                transaction_hash=on_chain.transaction_hash,
                verification_message="On-chain hash match verified. Record is cryptographically authentic.",
                tamper_detected=False,
            )
        else:
            return BlockchainVerificationResult(
                is_valid=False,
                record_id=event.event_id,
                recomputed_off_chain_hash=recomputed_hash,
                on_chain_hash=on_chain.cryptographic_hash,
                on_chain_timestamp=on_chain.timestamp,
                event_type=on_chain.event_type,
                approval_reference=on_chain.approval_reference,
                block_number=on_chain.block_number,
                transaction_hash=on_chain.transaction_hash,
                verification_message=(
                    f"TAMPER DETECTED: Off-chain record hash ({recomputed_hash[:12]}...) "
                    f"does NOT match on-chain anchored hash ({on_chain.cryptographic_hash[:12]}...)."
                ),
                tamper_detected=True,
            )

    def get_anchored_record(self, record_id: str) -> Optional[OnChainAuditRecord]:
        """Retrieves on-chain record by ID."""
        return self._on_chain_store.get(record_id)

    def get_all_anchored_records(self) -> List[OnChainAuditRecord]:
        """Returns all records anchored on-chain."""
        return list(self._on_chain_store.values())

    def get_ledger_status(self) -> Dict[str, Any]:
        """Returns operational summary of the blockchain / smart contract anchor."""
        return {
            "network_id": self.network_id,
            "smart_contract_name": "SafeContainAuditLedger",
            "smart_contract_standard": "Solidity 0.8.20 / EVM Compatible",
            "total_anchored_records": len(self._on_chain_store),
            "current_block_height": self._current_block,
            "status": "ONLINE",
            "design_principles": {
                "on_chain_fields": ["record_id", "cryptographic_hash", "timestamp", "event_type", "approval_reference"],
                "off_chain_storage": "Detailed telemetry, payload metadata, graph snapshots",
                "integrity_verification": "recompute_off_chain_hash == on_chain_hash",
                "limitation": "Blockchain provides tamper evidence, not truth; false input can still be recorded immutably.",
            }
        }

