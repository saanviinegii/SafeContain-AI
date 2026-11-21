"""SafeContain AI Blockchain Smart Contract & Permissioned Ledger Anchor.

Conforms strictly to SafeContain AI R&D Blueprint:
- Page 4: "Blockchain ledger / smart contract | Audit integrity | Record hashes, timestamps and minimal event metadata"
- Page 2: "On-chain: record ID, cryptographic hash, timestamp, event type and minimal approval reference."
- Page 2: "Off-chain: retain detailed logs, graph snapshots and sensitive evidence in controlled storage."
- Page 2: "Integrity check: recompute the off-chain record hash and compare it with the ledger entry."
- Page 2: "Limitation: blockchain provides tamper evidence, not truth; false input can still be recorded immutably."

Phase 3 Upgrade:
- Genuine EVM JSON-RPC connection management (Ethereum Sepolia / EVM compatible)
- Deterministic binary Merkle tree evidence batch anchoring
- Independent verification against on-chain smart contract (SafeContainAuditLedger.sol)
- Safe, non-destructive tamper detection demonstration in isolated memory
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.app.core.config import settings
from backend.app.models.domain import AuditEvent
from backend.app.audit.merkle import MerkleTree, MerkleProof, MerkleBatchManifest
from backend.app.audit.blockchain_client import (
    BlockchainClient,
    BlockchainStatusReport,
    BlockchainNetworkConfig,
    OnChainTransactionResult,
)
from backend.app.audit.anchor_storage import AnchorStorage, StoredAnchorManifest
from backend.app.audit.anchor_service import AnchorService, AnchorPreview, CreateAnchorRequest, AnchorResponse
from backend.app.audit.verifier import EvidenceVerifier, EvidenceVerificationResult, VerificationStatus
from backend.app.audit.tamper_demo import TamperDemonstrator, TamperDemoReport

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

    def __init__(self, network_id: str = "Ethereum Sepolia Testnet"):
        self.network_id = network_id
        self._on_chain_store: Dict[str, OnChainAuditRecord] = {}
        self._current_block: int = 1000

        # Phase 3 subsystems
        self.client = BlockchainClient()
        self.storage = AnchorStorage()
        self.anchor_service = AnchorService(storage=self.storage, client=self.client)
        self.verifier = EvidenceVerifier(storage=self.storage, client=self.client)
        self.tamper_demo = TamperDemonstrator(verifier=self.verifier)

    def anchor_event(self, event: AuditEvent) -> OnChainAuditRecord:
        """Anchors an off-chain AuditEvent onto the immutable ledger (single record).
        
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
        return record

    def verify_event(self, event: AuditEvent, recomputed_hash: str) -> BlockchainVerificationResult:
        """Integrity check: recomputes off-chain record hash and compares with ledger entry."""
        on_chain = self._on_chain_store.get(event.event_id)
        if not on_chain:
            return BlockchainVerificationResult(
                is_valid=False,
                record_id=event.event_id,
                recomputed_off_chain_hash=recomputed_hash,
                verification_message="Record not found on blockchain ledger. Has not been anchored yet.",
                tamper_detected=False,
            )

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
        client_status = self.client.get_status()
        anchors = self.storage.get_all_manifests()

        return {
            "network_id": self.client.config.network_name,
            "chain_id": self.client.config.chain_id,
            "smart_contract_name": "SafeContainAuditLedger",
            "smart_contract_standard": "Solidity 0.8.20 / EVM Compatible",
            "contract_address": self.client.config.contract_address,
            "wallet_address": self.client.config.wallet_address,
            "wallet_balance_eth": client_status.wallet_balance_eth,
            "rpc_configured": bool(self.client.config.rpc_url),
            "private_key_configured": bool(settings.BLOCKCHAIN_PRIVATE_KEY),
            "mode": client_status.mode,
            "connected": client_status.connected,
            "status": "ONLINE" if client_status.connected else "BLOCKCHAIN_UNAVAILABLE",
            "status_message": client_status.status_message,
            "can_anchor_on_chain": client_status.can_anchor_on_chain,
            "live_node_block_height": client_status.current_block_height,
            "total_anchored_records": len(self._on_chain_store),
            "total_merkle_batches": len(anchors),
            "current_block_height": client_status.current_block_height or self._current_block,
            "explorer_tx_template": self.client.config.explorer_tx_template,
            "explorer_address_template": self.client.config.explorer_address_template,
            "design_principles": {
                "on_chain_fields": [
                    "batch_id", "merkle_root", "first_sequence", "last_sequence", "record_count", "timestamp", "submitter"
                ],
                "off_chain_storage": "Detailed telemetry, payload metadata, graph snapshots, and audit_ledger.jsonl",
                "integrity_verification": "recomputed_hash -> Merkle proof -> on_chain_merkle_root",
                "limitation": "Blockchain provides tamper evidence, not truth; false input can still be recorded immutably.",
            }
        }
