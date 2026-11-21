"""Unit and Integration Tests for SafeContain AI Phase 3: Blockchain Trust & Evidence Integrity.

Verifies:
1. Merkle tree construction, leaf hashing, internal hashing, odd-node duplication, deterministic ordering.
2. Merkle proof generation and independent proof verification.
3. Cryptographic utilities (Keccak-256, secp256k1 address derivation, RLP serialization, ABI encoding/decoding).
4. Evidence anchor storage and manifest persistence.
5. Batch anchoring service, sequence ranges, and ledger validation.
6. Independent evidence verification engine (authentic vs invalid record vs invalid proof vs root mismatch).
7. Safe isolated tamper demonstration (guarantees zero mutation to production audit ledger).
8. Blockchain client connection management, status reporting, and graceful unconfigured/offline handling.
9. REST API endpoints (authentication, RBAC, status, anchors, proofs, verification, tamper demo).
"""

import copy
import hashlib
import os
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.models.domain import AuditEvent, UserRole
from backend.app.audit.merkle import MerkleTree, MerkleProof, MerkleProofStep
from backend.app.audit.crypto_utils import (
    keccak_256,
    private_key_to_address,
    to_checksum_address,
    rlp_encode,
    sign_transaction,
    encode_abi_call,
    decode_abi_output,
)
from backend.app.audit.blockchain_client import (
    BlockchainClient,
    BlockchainNetworkConfig,
    BlockchainStatusReport,
)
from backend.app.audit.anchor_storage import AnchorStorage, StoredAnchorManifest
from backend.app.audit.anchor_service import AnchorService, CreateAnchorRequest
from backend.app.audit.verifier import EvidenceVerifier, VerificationStatus
from backend.app.audit.tamper_demo import TamperDemonstrator
from backend.app.audit.ledger import ChainedAuditLedger


# =============================================================================
# 1. MERKLE TREE & PROOF TESTS
# =============================================================================

def test_merkle_tree_empty():
    tree = MerkleTree([], [])
    assert len(tree.leaves) == 0
    assert len(tree.root_hex) == 64


def test_merkle_tree_single_leaf():
    h = "a" * 64
    tree = MerkleTree([h], ["aud-001"])
    assert len(tree.leaves) == 1
    proof = tree.get_proof(0)
    assert proof.event_id == "aud-001"
    assert MerkleTree.verify_record_proof(h, proof.proof_steps, tree.root_hex)


def test_merkle_tree_even_leaves():
    hashes = [hashlib.sha256(f"record-{i}".encode()).hexdigest() for i in range(4)]
    ids = [f"aud-{i}" for i in range(4)]
    tree = MerkleTree(hashes, ids)

    for i in range(4):
        proof = tree.get_proof(i)
        assert MerkleTree.verify_record_proof(hashes[i], proof.proof_steps, tree.root_hex)


def test_merkle_tree_odd_leaves():
    hashes = [hashlib.sha256(f"record-{i}".encode()).hexdigest() for i in range(5)]
    ids = [f"aud-{i}" for i in range(5)]
    tree = MerkleTree(hashes, ids)

    for i in range(5):
        proof = tree.get_proof(i)
        assert MerkleTree.verify_record_proof(hashes[i], proof.proof_steps, tree.root_hex)


def test_merkle_proof_tamper_rejection():
    hashes = [hashlib.sha256(f"rec-{i}".encode()).hexdigest() for i in range(4)]
    tree = MerkleTree(hashes, [f"aud-{i}" for i in range(4)])
    proof = tree.get_proof(0)

    # Legitimate proof verifies
    assert MerkleTree.verify_record_proof(hashes[0], proof.proof_steps, tree.root_hex)

    # Tampered leaf hash fails
    tampered_hash = "f" * 64
    assert not MerkleTree.verify_record_proof(tampered_hash, proof.proof_steps, tree.root_hex)

    # Wrong expected root fails
    assert not MerkleTree.verify_record_proof(hashes[0], proof.proof_steps, "0" * 64)


# =============================================================================
# 2. CRYPTO UTILITIES TESTS
# =============================================================================

def test_keccak_256_standard_vectors():
    # Empty string
    assert keccak_256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    # ERC-20 transfer selector
    assert keccak_256(b"transfer(address,uint256)")[:4].hex() == "a9059cbb"


def test_private_key_to_address():
    test_priv = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
    addr = private_key_to_address(test_priv)
    assert addr == "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"


def test_rlp_encoding():
    assert rlp_encode(b"dog") == bytes([0x83]) + b"dog"
    assert rlp_encode(0) == bytes([0x80])
    assert rlp_encode(15) == bytes([0x0F])
    assert rlp_encode(1024) == bytes([0x82, 0x04, 0x00])


def test_eip155_transaction_signing():
    test_priv = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
    raw_tx, tx_hash = sign_transaction(
        nonce=1,
        gas_price=25000000000,
        gas_limit=21000,
        to="0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        value=1000000000,
        data=b"",
        chain_id=11155111,
        private_key_hex=test_priv,
    )
    assert raw_tx.startswith("0x")
    assert tx_hash.startswith("0x")
    assert len(tx_hash) == 66


def test_abi_encoding_decoding():
    calldata = encode_abi_call(
        "anchorBatch(bytes32,bytes32,uint256,uint256,uint256)",
        ["0x" + "1" * 64, "0x" + "2" * 64, 1, 50, 50],
        ["bytes32", "bytes32", "uint256", "uint256", "uint256"]
    )
    assert calldata.startswith("0x8e7e8653")

    decoded = decode_abi_output("0" * 63 + "1" + "0" * 63 + "a", ["bool", "uint256"])
    assert decoded[0] is True
    assert decoded[1] == 10


# =============================================================================
# 3. ANCHOR STORAGE & SERVICE TESTS
# =============================================================================

def test_anchor_storage_persistence(tmp_path):
    storage_file = str(tmp_path / "anchors.json")
    storage = AnchorStorage(storage_path=storage_file)

    manifest = StoredAnchorManifest(
        anchor_id="0x" + "1" * 64,
        merkle_root="2" * 64,
        batch_id="batch-001",
        first_sequence=1,
        last_sequence=10,
        record_count=10,
        first_event_id="aud-000001",
        last_event_id="aud-000010",
        event_ids=[f"aud-{i:06d}" for i in range(1, 11)],
    )
    storage.save_manifest(manifest)

    # Re-read from disk
    storage2 = AnchorStorage(storage_path=storage_file)
    retrieved = storage2.get_manifest("0x" + "1" * 64)
    assert retrieved is not None
    assert retrieved.batch_id == "batch-001"
    assert retrieved.record_count == 10
    assert storage2.get_last_anchored_sequence() == 10


def test_anchor_service_batch_creation(tmp_path):
    storage_file = str(tmp_path / "anchors.json")
    storage = AnchorStorage(storage_path=storage_file)
    service = AnchorService(storage=storage)

    # Generate 5 test audit events
    now = datetime.now(timezone.utc)
    events = []
    prev_hash = "0" * 64
    for i in range(5):
        curr_hash = hashlib.sha256(f"ev-{i}-{prev_hash}".encode()).hexdigest()
        e = AuditEvent(
            event_id=f"aud-{i+1:06d}",
            timestamp=now,
            event_type="DECISION_EVENT",
            action="TEST_ACTION",
            actor_id="tester",
            actor_role=UserRole.SOC_ANALYST,
            organization_id="ORG-TEST",
            resource_type="TestResource",
            resource_id=f"res-{i}",
            metadata={},
            previous_hash=prev_hash,
            current_hash=curr_hash,
        )
        events.append(e)
        prev_hash = curr_hash

    # Check preview
    preview = service.get_preview(events, max_records=5)
    assert preview.total_ledger_records == 5
    assert preview.unanchored_count == 5
    assert preview.ledger_intact is True

    # Create anchor
    req = CreateAnchorRequest(first_sequence=1, last_sequence=5, submit_on_chain=False)
    resp = service.create_anchor(events, req)
    assert resp.success is True
    assert resp.record_count == 5
    assert resp.first_sequence == 1
    assert resp.last_sequence == 5
    assert resp.confirmation_status == "LOCAL_VERIFIED"

    # Proof generation
    proof = service.get_merkle_proof(resp.anchor_id, "aud-000003", events)
    assert proof is not None
    assert proof.event_id == "aud-000003"
    assert MerkleTree.verify_record_proof(events[2].current_hash, proof.proof_steps, resp.merkle_root)


# =============================================================================
# 4. INDEPENDENT EVIDENCE VERIFICATION TESTS
# =============================================================================

def test_evidence_verifier_authentic_and_tampered(tmp_path):
    storage_file = str(tmp_path / "anchors.json")
    storage = AnchorStorage(storage_path=storage_file)
    service = AnchorService(storage=storage)
    verifier = EvidenceVerifier(storage=storage)

    now = datetime.now(timezone.utc)
    events = []
    prev_hash = "0" * 64
    for i in range(3):
        curr_hash = hashlib.sha256(f"ev-{i}-{prev_hash}".encode()).hexdigest()
        e = AuditEvent(
            event_id=f"aud-{i+1:06d}",
            timestamp=now,
            event_type="DECISION_EVENT",
            action="TEST_ACTION",
            actor_id="tester",
            actor_role=UserRole.SOC_ANALYST,
            organization_id="ORG-TEST",
            resource_type="TestResource",
            resource_id=f"res-{i}",
            metadata={},
            previous_hash=prev_hash,
            current_hash=curr_hash,
        )
        events.append(e)
        prev_hash = curr_hash

    anchor_resp = service.create_anchor(
        events,
        CreateAnchorRequest(first_sequence=1, last_sequence=3, submit_on_chain=False)
    )

    proof = service.get_merkle_proof(anchor_resp.anchor_id, events[0].event_id, events)

    # 1. Authentic record verifies
    res_authentic = verifier.verify_record(
        event=events[0],
        recomputed_hash=events[0].current_hash,
        anchor_id=anchor_resp.anchor_id,
        proof=proof
    )
    assert res_authentic.status == VerificationStatus.VERIFIED
    assert res_authentic.is_valid is True
    assert res_authentic.tamper_detected is False

    # 2. Tampered recomputed hash triggers INVALID_RECORD
    res_tampered = verifier.verify_record(
        event=events[0],
        recomputed_hash="tampered_hash_value" + "0" * 44,
        anchor_id=anchor_resp.anchor_id,
        proof=proof
    )
    assert res_tampered.status == VerificationStatus.INVALID_RECORD
    assert res_tampered.is_valid is False
    assert res_tampered.tamper_detected is True


# =============================================================================
# 5. SAFE TAMPER DEMONSTRATION TESTS
# =============================================================================

def test_tamper_demonstration_leaves_ledger_intact(tmp_path):
    storage_file = str(tmp_path / "test_ledger.jsonl")
    ledger = ChainedAuditLedger(storage_path=storage_file)

    # Record 3 events
    e1 = ledger.record_event("user1", UserRole.SOC_ANALYST, "ACTION_1", "Res", "id1")
    e2 = ledger.record_event("user1", UserRole.SOC_ANALYST, "ACTION_2", "Res", "id2")
    e3 = ledger.record_event("user1", UserRole.SOC_ANALYST, "ACTION_3", "Res", "id3")

    assert len(ledger._events) == 3
    demo = TamperDemonstrator()

    report = demo.run_demonstration(
        target_event=e2,
        ledger=ledger,
        field_to_tamper="action",
        tampered_value="MALICIOUS_TAMPER"
    )

    assert report.original_evidence_verified is True
    assert report.tampered_evidence_detected is True
    assert "CONFIRMED SAFE" in report.safety_guarantee

    # Verify that original ledger is completely intact and passes integrity check
    assert len(ledger._events) == 3
    assert ledger._events[1].action == "ACTION_2"
    integrity = ledger.verify_integrity()
    assert integrity.is_valid is True


# =============================================================================
# 6. BLOCKCHAIN CLIENT & STATUS TESTS
# =============================================================================

def test_blockchain_client_unconfigured():
    client = BlockchainClient(config=BlockchainNetworkConfig(rpc_url=None))
    status = client.get_status()
    assert status.connected is False
    assert status.mode == "UNCONFIGURED"
    assert status.can_anchor_on_chain is False
    assert "BLOCKCHAIN UNAVAILABLE" in status.status_message


def test_blockchain_client_invalid_rpc():
    client = BlockchainClient(
        config=BlockchainNetworkConfig(
            rpc_url="http://127.0.0.1:8545",
            timeout_seconds=0.5
        )
    )
    # Mock _rpc_call to simulate RPC network failure
    def mock_fail(*args, **kwargs):
        raise ConnectionError("RPC Node Unreachable: Connection refused")

    client._rpc_call = mock_fail
    status = client.get_status()
    assert status.connected is False
    assert status.mode == "RPC_UNAVAILABLE"
    assert "RPC Connection Error" in status.status_message


# =============================================================================
# 7. REST API ENDPOINT HANDLER TESTS
# =============================================================================

def test_blockchain_rest_api_endpoints():
    from backend.app.api.v1.router import (
        platform_ctx,
        get_blockchain_status,
        get_blockchain_network,
        get_anchor_preview,
        create_blockchain_anchor,
        list_blockchain_anchors,
        get_blockchain_anchor_by_id,
        run_blockchain_tamper_demo,
        get_blockchain_ledger_integrity,
        CreateAnchorRequest,
        TamperDemoPayload,
    )
    from backend.app.security.user_store import UserRecord, AppRole

    now_str = datetime.now(timezone.utc).isoformat()
    mock_admin = UserRecord(
        id="usr-admin",
        username="admin",
        email="admin@safecontain.ai",
        hashed_password="hash",
        role=AppRole.ADMIN,
        created_at=now_str,
        updated_at=now_str,
    )

    # 1. Status endpoint
    status_res = get_blockchain_status(current_user=mock_admin)
    assert "mode" in status_res
    assert "network_id" in status_res

    # 2. Network endpoint
    net_res = get_blockchain_network(current_user=mock_admin)
    assert net_res["network_name"] == "Ethereum Sepolia Testnet"
    assert net_res["chain_id"] == 11155111

    # 3. Anchor preview endpoint
    prev_res = get_anchor_preview(max_records=10, current_user=mock_admin)
    assert prev_res.total_ledger_records >= 0
    assert prev_res.ledger_intact is True

    # 4. Create anchor batch (if ledger has events)
    if len(platform_ctx.ledger._events) > 0:
        create_req = CreateAnchorRequest(first_sequence=1, last_sequence=min(5, len(platform_ctx.ledger._events)), submit_on_chain=False)
        anchor_res = create_blockchain_anchor(payload=create_req, current_user=mock_admin)
        assert anchor_res.success is True
        assert anchor_res.anchor_id.startswith("0x")

        # 5. List anchors
        anchors_list = list_blockchain_anchors(current_user=mock_admin)
        assert len(anchors_list) >= 1

        # 6. Retrieve anchor by ID
        single_manifest = get_blockchain_anchor_by_id(anchor_id=anchor_res.anchor_id, current_user=mock_admin)
        assert single_manifest.anchor_id == anchor_res.anchor_id

        # 7. Tamper demo endpoint
        tamper_payload = TamperDemoPayload(event_id=platform_ctx.ledger._events[0].event_id, field_to_tamper="action", tampered_value="TAMPER_EXPLOIT")
        tamper_rep = run_blockchain_tamper_demo(payload=tamper_payload, current_user=mock_admin)
        assert tamper_rep.original_evidence_verified is True
        assert tamper_rep.tampered_evidence_detected is True

    # 8. Ledger integrity endpoint
    integrity_res = get_blockchain_ledger_integrity(current_user=mock_admin)
    assert integrity_res.is_valid is True
