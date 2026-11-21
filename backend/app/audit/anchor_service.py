"""SafeContain AI Evidence Batch Anchoring Service.

Coordinates validation of audit ledger records, Merkle tree commitment,
on-chain smart contract submission, and persistent manifest storage.
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from backend.app.core.config import settings
from backend.app.models.domain import AuditEvent, UserRole
from backend.app.audit.merkle import MerkleTree, MerkleProof, MerkleBatchManifest
from backend.app.audit.anchor_storage import AnchorStorage, StoredAnchorManifest
from backend.app.audit.blockchain_client import BlockchainClient, OnChainTransactionResult

logger = logging.getLogger(__name__)


class AnchorPreview(BaseModel):
    """Preview of audit ledger records available for batch anchoring."""
    total_ledger_records: int
    last_anchored_sequence: int
    unanchored_count: int
    candidate_first_sequence: int
    candidate_last_sequence: int
    candidate_record_count: int
    candidate_events: List[Dict[str, Any]]
    ledger_intact: bool
    ledger_integrity_summary: str


class CreateAnchorRequest(BaseModel):
    """Request payload to create a new cryptographic evidence anchor."""
    first_sequence: Optional[int] = None
    last_sequence: Optional[int] = None
    max_records: int = 100
    submit_on_chain: bool = True
    notes: Optional[str] = None


class AnchorResponse(BaseModel):
    """Result of an anchor creation operation."""
    success: bool
    anchor_id: str
    merkle_root: str
    batch_id: str
    first_sequence: int
    last_sequence: int
    record_count: int
    confirmation_status: str
    transaction_hash: Optional[str] = None
    block_number: Optional[int] = None
    network: str
    chain_id: int
    contract_address: Optional[str] = None
    explorer_url: Optional[str] = None
    message: str
    created_at: datetime


class AnchorService:
    """Enterprise service managing audit batch commitment and on-chain anchoring."""

    def __init__(
        self,
        storage: Optional[AnchorStorage] = None,
        client: Optional[BlockchainClient] = None
    ):
        self.storage = storage or AnchorStorage()
        self.client = client or BlockchainClient()

    def get_preview(self, ledger_events: List[AuditEvent], max_records: int = 50) -> AnchorPreview:
        """Inspects ledger and generates candidate batch preview for anchoring."""
        total = len(ledger_events)
        last_seq = self.storage.get_last_anchored_sequence()

        # Eligible unanchored records are sequence > last_seq
        # Index in ledger_events is 0-based, so sequence is (idx + 1)
        eligible = ledger_events[last_seq:last_seq + max_records]
        unanchored_total = max(0, total - last_seq)

        candidate_first = (last_seq + 1) if eligible else total
        candidate_last = (last_seq + len(eligible)) if eligible else total

        # Check local chain continuity of eligible chunk
        intact = True
        summary = "Records are sequential and cryptographically chained."
        if eligible:
            for i in range(1, len(eligible)):
                if eligible[i].previous_hash != eligible[i - 1].current_hash:
                    intact = False
                    summary = f"Chain break detected between {eligible[i-1].event_id} and {eligible[i].event_id}."
                    break

        candidate_events = [
            {
                "sequence": last_seq + idx + 1,
                "event_id": e.event_id,
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type or "DECISION_EVENT",
                "action": e.action,
                "actor_id": e.actor_id,
                "current_hash": e.current_hash,
            }
            for idx, e in enumerate(eligible)
        ]

        return AnchorPreview(
            total_ledger_records=total,
            last_anchored_sequence=last_seq,
            unanchored_count=unanchored_total,
            candidate_first_sequence=candidate_first,
            candidate_last_sequence=candidate_last,
            candidate_record_count=len(eligible),
            candidate_events=candidate_events,
            ledger_intact=intact,
            ledger_integrity_summary=summary,
        )

    def create_anchor(
        self,
        ledger_events: List[AuditEvent],
        request: CreateAnchorRequest,
        actor_id: str = "admin"
    ) -> AnchorResponse:
        """Validates ledger records, builds Merkle tree, and anchors batch."""
        total = len(ledger_events)
        if total == 0:
            raise ValueError("Audit ledger is empty; nothing to anchor.")

        last_anchored = self.storage.get_last_anchored_sequence()
        first_seq = request.first_sequence if request.first_sequence is not None else (last_anchored + 1)
        last_seq = request.last_sequence if request.last_sequence is not None else min(total, first_seq + request.max_records - 1)

        if first_seq < 1 or last_seq > total or first_seq > last_seq:
            raise ValueError(f"Invalid sequence range: {first_seq}..{last_seq} (ledger total: {total})")

        # Extract selected events (1-based sequences)
        selected_events = ledger_events[first_seq - 1:last_seq]
        if not selected_events:
            raise ValueError("No records found in specified sequence range.")

        # 1. STEP 2: Strict Ledger Validation
        for i in range(len(selected_events)):
            ev = selected_events[i]
            # Check previous hash continuity
            if i > 0 and ev.previous_hash != selected_events[i - 1].current_hash:
                raise ValueError(
                    f"LEDGER INTEGRITY FAILED: Chain break between sequence {first_seq + i - 1} "
                    f"and {first_seq + i}. Aborting blockchain anchor."
                )

        # 2. STEP 3: Deterministic Merkle Root Generation
        record_hashes = [e.current_hash for e in selected_events]
        event_ids = [e.event_id for e in selected_events]
        tree = MerkleTree(record_hashes, event_ids)
        merkle_root_hex = tree.root_hex

        now = datetime.now(timezone.utc)
        batch_id = f"batch-{first_seq:06d}-{last_seq:06d}-{now.strftime('%Y%m%d%H%M%S')}"
        # Anchor ID is deterministic 32-byte hash: SHA-256(batch_id || merkle_root)
        anchor_id_bytes = hashlib.sha256(f"{batch_id}:{merkle_root_hex}".encode("utf-8")).digest()
        anchor_id_hex = "0x" + anchor_id_bytes.hex()
        evidence_root_32 = "0x" + merkle_root_hex

        # 3. STEP 4 & 5: Blockchain Submission (if requested & connected)
        tx_result: Optional[OnChainTransactionResult] = None
        explorer_url: Optional[str] = None
        confirmation_status = "LOCAL_VERIFIED"
        message = "Batch Merkle root calculated and verified locally."

        if request.submit_on_chain:
            status = self.client.get_status()
            if status.connected and status.can_anchor_on_chain:
                logger.info("Broadcasting anchorBatch to EVM testnet for %s...", batch_id)
                tx_result = self.client.anchor_batch_on_chain(
                    anchor_id_hex=anchor_id_hex,
                    evidence_root_hex=evidence_root_32,
                    first_sequence=first_seq,
                    last_sequence=last_seq,
                    record_count=len(selected_events)
                )
                if tx_result.success:
                    confirmation_status = tx_result.status
                    explorer_url = tx_result.explorer_url
                    message = (
                        f"Successfully anchored on-chain! Tx: {tx_result.tx_hash[:16]}... "
                        f"(Block #{tx_result.block_number or 'pending'})"
                    )
                else:
                    confirmation_status = "FAILED"
                    message = f"Blockchain submission failed: {tx_result.error_message}. Saved locally."
            else:
                confirmation_status = "LOCAL_VERIFIED"
                message = f"Saved locally. On-chain broadcast skipped: {status.status_message}"

        # 4. STEP 6: Persist Anchor Metadata Manifest
        manifest = StoredAnchorManifest(
            anchor_id=anchor_id_hex,
            merkle_root=merkle_root_hex,
            batch_id=batch_id,
            first_sequence=first_seq,
            last_sequence=last_seq,
            record_count=len(selected_events),
            first_event_id=selected_events[0].event_id,
            last_event_id=selected_events[-1].event_id,
            leaves=[leaf.hex() for leaf in tree.leaves],
            event_ids=event_ids,
            transaction_hash=tx_result.tx_hash if tx_result else None,
            network=self.client.config.network_name,
            chain_id=self.client.config.chain_id,
            contract_address=self.client.config.contract_address,
            block_number=tx_result.block_number if tx_result else None,
            confirmation_status=confirmation_status,
            verification_status="VERIFIED",
            created_at=now,
            anchored_by=actor_id,
        )
        self.storage.save_manifest(manifest)

        return AnchorResponse(
            success=True,
            anchor_id=anchor_id_hex,
            merkle_root=merkle_root_hex,
            batch_id=batch_id,
            first_sequence=first_seq,
            last_sequence=last_seq,
            record_count=len(selected_events),
            confirmation_status=confirmation_status,
            transaction_hash=tx_result.tx_hash if tx_result else None,
            block_number=tx_result.block_number if tx_result else None,
            network=self.client.config.network_name,
            chain_id=self.client.config.chain_id,
            contract_address=self.client.config.contract_address,
            explorer_url=explorer_url,
            message=message,
            created_at=now,
        )

    def get_merkle_proof(
        self,
        anchor_id: str,
        event_id: str,
        ledger_events: List[AuditEvent]
    ) -> Optional[MerkleProof]:
        """Generates Merkle proof for specific event within an anchored batch."""
        manifest = self.storage.get_manifest(anchor_id)
        if not manifest:
            return None

        if event_id not in manifest.event_ids:
            return None

        idx = manifest.event_ids.index(event_id)
        # Reconstruct tree from selected events in range
        batch_events = ledger_events[manifest.first_sequence - 1:manifest.last_sequence]
        record_hashes = [e.current_hash for e in batch_events]
        event_ids = [e.event_id for e in batch_events]
        tree = MerkleTree(record_hashes, event_ids)
        return tree.get_proof(idx)
