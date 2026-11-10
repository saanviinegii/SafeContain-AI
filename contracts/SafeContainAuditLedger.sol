// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title SafeContainAuditLedger
 * @notice Permissioned / public testnet smart contract anchoring cryptographic audit hashes.
 * @dev Conforms strictly to SafeContain AI R&D Blueprint Page 2 (Blockchain Design Principles):
 *      - On-chain: record ID, cryptographic hash, timestamp, event type, minimal approval reference.
 *      - Off-chain: retain detailed logs, graph snapshots and sensitive evidence in controlled storage.
 *      - Integrity check: recompute the off-chain record hash and compare it with the ledger entry.
 *      - Limitation: blockchain provides tamper evidence, not truth; false input can still be recorded immutably.
 */
contract SafeContainAuditLedger {
    struct AuditRecord {
        string eventId;
        bytes32 recordHash;
        uint256 timestamp;
        string eventType;
        string approvalReference;
        address recordedBy;
    }

    // Mapping from unique event ID to on-chain record
    mapping(string => AuditRecord) private records;
    string[] private eventRegistry;

    event RecordAnchored(
        string indexed eventId,
        bytes32 indexed recordHash,
        uint256 timestamp,
        string eventType,
        string approvalReference,
        address recordedBy
    );

    address public immutable owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "SafeContain: unauthorized anchor attempt");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Anchors an off-chain record's cryptographic SHA-256 hash onto the immutable ledger.
     */
    function recordEvent(
        string calldata eventId,
        bytes32 recordHash,
        string calldata eventType,
        string calldata approvalReference
    ) external {
        require(bytes(eventId).length > 0, "SafeContain: eventId cannot be empty");
        require(records[eventId].timestamp == 0, "SafeContain: record already anchored on-chain");

        records[eventId] = AuditRecord({
            eventId: eventId,
            recordHash: recordHash,
            timestamp: block.timestamp,
            eventType: eventType,
            approvalReference: approvalReference,
            recordedBy: msg.sender
        });

        eventRegistry.push(eventId);

        emit RecordAnchored(
            eventId,
            recordHash,
            block.timestamp,
            eventType,
            approvalReference,
            msg.sender
        );
    }

    /**
     * @notice Performs on-chain integrity check: compares given off-chain hash with anchored record.
     */
    function verifyRecord(
        string calldata eventId,
        bytes32 recomputedHash
    ) external view returns (bool isValid, uint256 timestamp, string memory eventType, string memory approvalReference) {
        AuditRecord memory rec = records[eventId];
        if (rec.timestamp == 0) {
            return (false, 0, "", "");
        }
        bool matches = (rec.recordHash == recomputedHash);
        return (matches, rec.timestamp, rec.eventType, rec.approvalReference);
    }

    /**
     * @notice Returns total number of anchored audit blocks.
     */
    function totalAnchoredRecords() external view returns (uint256) {
        return eventRegistry.length;
    }

    /**
     * @notice Retrieves record metadata for verification.
     */
    function getRecord(string calldata eventId) external view returns (
        bytes32 recordHash,
        uint256 timestamp,
        string memory eventType,
        string memory approvalReference,
        address recordedBy
    ) {
        AuditRecord memory rec = records[eventId];
        require(rec.timestamp > 0, "SafeContain: record not found");
        return (rec.recordHash, rec.timestamp, rec.eventType, rec.approvalReference, rec.recordedBy);
    }
}

