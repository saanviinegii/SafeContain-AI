# SafeContain AI — Blockchain Smart Contract & Permissioned Ledger Setup

## 1. Compliance with SafeContain AI R&D Blueprint

The cryptographic audit architecture is designed strictly in accordance with **SafeContain AI Project Blueprint (Pages 2 & 4)**:

- **Page 4**: *"Blockchain ledger / smart contract | Audit integrity | Record hashes, timestamps and minimal event metadata"*
- **Page 2**: *"On-chain: record ID, cryptographic hash, timestamp, event type and minimal approval reference."*
- **Page 2**: *"Off-chain: retain detailed logs, graph snapshots and sensitive evidence in controlled storage."*
- **Page 2**: *"Integrity check: recompute the off-chain record hash and compare it with the ledger entry."*
- **Page 2**: *"Limitation: blockchain provides tamper evidence, not truth; false input can still be recorded immutably."*

---

## 2. Smart Contract Specification (`SafeContainAuditLedger.sol`)

The smart contract is written in standard Solidity 0.8.20 and is deployable to any EVM-compatible network (Ethereum Sepolia, Polygon Amoy, Arbitrum Sepolia, Hyperledger Besu):

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title SafeContainAuditLedger
 * @notice Anchors minimal immutable cryptographic audit events for SafeContain AI.
 * @dev Conforms strictly to R&D Blueprint Page 2 & 4 (minimal on-chain tuples).
 */
contract SafeContainAuditLedger {
    struct OnChainAuditRecord {
        string recordId;
        bytes32 cryptographicHash;
        uint256 timestamp;
        string eventType;
        string approvalReference;
        uint256 blockNumber;
    }

    address public incidentCommander;
    mapping(string => OnChainAuditRecord) private records;
    string[] private recordIds;

    event RecordAnchored(
        string indexed recordId,
        bytes32 indexed cryptographicHash,
        uint256 timestamp,
        string eventType,
        string approvalReference
    );

    constructor() {
        incidentCommander = msg.sender;
    }

    function anchorRecord(
        string calldata _recordId,
        bytes32 _cryptographicHash,
        string calldata _eventType,
        string calldata _approvalReference
    ) external {
        require(records[_recordId].timestamp == 0, "Record already anchored on-chain");

        OnChainAuditRecord memory rec = OnChainAuditRecord({
            recordId: _recordId,
            cryptographicHash: _cryptographicHash,
            timestamp: block.timestamp,
            eventType: _eventType,
            approvalReference: _approvalReference,
            blockNumber: block.number
        });

        records[_recordId] = rec;
        recordIds.push(_recordId);

        emit RecordAnchored(_recordId, _cryptographicHash, block.timestamp, _eventType, _approvalReference);
    }

    function getRecord(string calldata _recordId)
        external
        view
        returns (
            string memory recordId,
            bytes32 cryptographicHash,
            uint256 timestamp,
            string memory eventType,
            string memory approvalReference,
            uint256 blockNumber
        )
    {
        OnChainAuditRecord memory rec = records[_recordId];
        require(rec.timestamp != 0, "Record does not exist");
        return (
            rec.recordId,
            rec.cryptographicHash,
            rec.timestamp,
            rec.eventType,
            rec.approvalReference,
            rec.blockNumber
        );
    }

    function totalRecords() external view returns (uint256) {
        return recordIds.length;
    }
}
```

---

## 3. Environment Configuration

To connect SafeContain AI to an EVM testnet or permissioned Hyperledger Besu / Quorum node:

```bash
# Optional Live EVM Testnet RPC URL (e.g. Sepolia, Amoy, or local Geth/Anvil node)
BLOCKCHAIN_RPC_URL=https://rpc.sepolia.org

# Deployed Smart Contract Address
BLOCKCHAIN_CONTRACT_ADDRESS=0x742d35Cc6634C0532925a3b844Bc454e4438f44e

# Off-chain Local Hash-Chained Storage Path
AUDIT_LEDGER_STORAGE_PATH=audit_ledger.jsonl
VERIFY_AUDIT_INTEGRITY_ON_STARTUP=true
```

If `BLOCKCHAIN_RPC_URL` is omitted, SafeContain AI operates in **Deterministic Permissioned Anchor Mode**, maintaining the exact block height, deterministic transaction hashes, and on-chain record queries without external dependencies or gas costs.

---

## 4. Verification Workflow & API

### 4.1 Ledger Status

```http
GET /api/v1/audit/blockchain/status
```

**Response:**
```json
{
  "network_id": "safecontain-evm-testnet",
  "smart_contract_name": "SafeContainAuditLedger",
  "smart_contract_standard": "Solidity 0.8.20 / EVM Compatible",
  "contract_address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "rpc_configured": false,
  "total_anchored_records": 4,
  "current_block_height": 1004,
  "status": "ONLINE",
  "design_principles": {
    "on_chain_fields": ["record_id", "cryptographic_hash", "timestamp", "event_type", "approval_reference"],
    "off_chain_storage": "Detailed telemetry, payload metadata, graph snapshots",
    "integrity_verification": "recompute_off_chain_hash == on_chain_hash",
    "limitation": "Blockchain provides tamper evidence, not truth; false input can still be recorded immutably."
  }
}
```

### 4.2 On-Demand Verification Endpoint

```http
POST /api/v1/audit/blockchain/verify?event_id=aud-000001-f8e2
```

1. Retrieves off-chain canonical record from `audit_ledger.jsonl`.
2. Recomputes off-chain record SHA-256 hash across canonical fields.
3. Retrieves on-chain anchored hash from smart contract.
4. Compares hashes: returns `is_valid: true` if identical, or flags `tamper_detected: true` if mismatch detected.
