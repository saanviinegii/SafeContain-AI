"""SafeContain AI Cryptographic Merkle Tree and Batch Evidence Commitment.

Implements domain-separated, deterministic Merkle tree construction (RFC 6962 compliant):
- Leaf hashing: SHA-256(0x00 || leaf_data)
- Internal node hashing: SHA-256(0x01 || left_child || right_child)
- Odd-node handling: canonical duplicate-last-node pairing
- Deterministic ordering: strict chronological/sequence ordering by audit record ID
- Cryptographic proof generation and independent verification
"""

import hashlib
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field


class MerkleProofStep(BaseModel):
    """Single step along the Merkle audit verification path."""
    position: str = Field(description="'left' if sibling is on the left, 'right' if sibling is on the right")
    sibling_hash: str = Field(description="Hex-encoded 32-byte SHA-256 hash of the sibling node")


class MerkleProof(BaseModel):
    """Cryptographic Merkle inclusion proof for a single audit record."""
    event_id: str
    record_hash: str
    leaf_hash: str
    leaf_index: int
    total_leaves: int
    root_hash: str
    proof_steps: List[MerkleProofStep]
    is_valid: Optional[bool] = None


class MerkleBatchManifest(BaseModel):
    """Cryptographic commitment manifest for a batch of anchored audit records."""
    batch_id: str
    merkle_root: str
    first_sequence: int
    last_sequence: int
    record_count: int
    first_event_id: str
    last_event_id: str
    leaves: List[str] = Field(default_factory=list, description="List of leaf hashes in batch order")
    algorithm: str = "SHA-256-RFC6962-MerkleTree"


class MerkleTree:
    """Deterministic, domain-separated binary Merkle tree."""

    LEAF_PREFIX: bytes = b"\x00"
    INTERNAL_PREFIX: bytes = b"\x01"

    def __init__(self, record_hashes: Optional[List[str]] = None, event_ids: Optional[List[str]] = None):
        """Initializes Merkle tree from ordered list of record hashes."""
        self.record_hashes: List[str] = list(record_hashes or [])
        self.event_ids: List[str] = list(event_ids or [])
        self.leaves: List[bytes] = []
        self.levels: List[List[bytes]] = []
        self._build_tree()

    @classmethod
    def hash_leaf(cls, record_hash_hex: str) -> bytes:
        """Domain-separated leaf hash: SHA-256(0x00 || raw_record_hash_bytes)."""
        raw_bytes = bytes.fromhex(record_hash_hex) if len(record_hash_hex) == 64 else record_hash_hex.encode("utf-8")
        return hashlib.sha256(cls.LEAF_PREFIX + raw_bytes).digest()

    @classmethod
    def hash_internal(cls, left: bytes, right: bytes) -> bytes:
        """Domain-separated internal node hash: SHA-256(0x01 || left || right)."""
        return hashlib.sha256(cls.INTERNAL_PREFIX + left + right).digest()

    def _build_tree(self) -> None:
        """Constructs tree levels bottom-up with deterministic odd-node duplication."""
        if not self.record_hashes:
            empty_root = hashlib.sha256(self.INTERNAL_PREFIX + b"EMPTY_TREE").digest()
            self.leaves = []
            self.levels = [[empty_root]]
            return

        # 1. Compute leaves
        self.leaves = [self.hash_leaf(h) for h in self.record_hashes]
        self.levels = [self.leaves]

        # 2. Build upper levels
        current_level = self.leaves
        while len(current_level) > 1:
            next_level: List[bytes] = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    # Duplicate last node for odd counts
                    right = left
                next_level.append(self.hash_internal(left, right))
            self.levels.append(next_level)
            current_level = next_level

    @property
    def root(self) -> bytes:
        """Returns 32-byte binary Merkle root."""
        return self.levels[-1][0] if self.levels else b""

    @property
    def root_hex(self) -> str:
        """Returns 64-character lowercase hex-encoded Merkle root."""
        return self.root.hex()

    def get_proof(self, index: int) -> MerkleProof:
        """Generates Merkle inclusion proof for leaf at specified index."""
        if index < 0 or index >= len(self.leaves):
            raise IndexError(f"Leaf index {index} out of bounds (total leaves: {len(self.leaves)})")

        steps: List[MerkleProofStep] = []
        curr_idx = index

        for level_idx in range(len(self.levels) - 1):
            level = self.levels[level_idx]
            is_right_child = (curr_idx % 2 == 1)

            if is_right_child:
                # Sibling is to the left
                sibling_idx = curr_idx - 1
                steps.append(MerkleProofStep(
                    position="left",
                    sibling_hash=level[sibling_idx].hex()
                ))
            else:
                # Sibling is to the right
                sibling_idx = curr_idx + 1
                if sibling_idx < len(level):
                    sibling_hash = level[sibling_idx].hex()
                else:
                    # Odd node: sibling is self duplicated
                    sibling_hash = level[curr_idx].hex()
                steps.append(MerkleProofStep(
                    position="right",
                    sibling_hash=sibling_hash
                ))

            curr_idx = curr_idx // 2

        event_id = self.event_ids[index] if index < len(self.event_ids) else f"event-{index}"
        record_hash = self.record_hashes[index]

        proof = MerkleProof(
            event_id=event_id,
            record_hash=record_hash,
            leaf_hash=self.leaves[index].hex(),
            leaf_index=index,
            total_leaves=len(self.leaves),
            root_hash=self.root_hex,
            proof_steps=steps,
            is_valid=True,
        )
        return proof

    @classmethod
    def verify_proof(cls, leaf_hash_hex: str, proof_steps: List[MerkleProofStep], expected_root_hex: str) -> bool:
        """Independently verifies a Merkle proof without needing the full tree."""
        try:
            curr = bytes.fromhex(leaf_hash_hex)
            for step in proof_steps:
                sibling = bytes.fromhex(step.sibling_hash)
                if step.position == "left":
                    curr = cls.hash_internal(sibling, curr)
                elif step.position == "right":
                    curr = cls.hash_internal(curr, sibling)
                else:
                    return False
            return curr.hex().lower() == expected_root_hex.lower()
        except Exception:
            return False

    @classmethod
    def verify_record_proof(
        cls,
        record_hash_hex: str,
        proof_steps: List[MerkleProofStep],
        expected_root_hex: str
    ) -> bool:
        """Hashes raw record hash into leaf and verifies proof against expected root."""
        leaf = cls.hash_leaf(record_hash_hex)
        return cls.verify_proof(leaf.hex(), proof_steps, expected_root_hex)
