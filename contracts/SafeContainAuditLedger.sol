// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @title SafeContainAuditLedger
 * @notice Permissioned / public testnet smart contract anchoring cryptographic audit hashes and Merkle evidence roots.
 * @dev Conforms strictly to SafeContain AI R&D Blueprint:
 *      - On-chain: record ID, cryptographic hash, timestamp, event type, minimal approval reference.
 *      - Batch Merkle Root Anchoring: batch ID, Merkle root, sequence range, record count, timestamp.
 *      - Off-chain: retain detailed logs, graph snapshots and sensitive evidence in controlled storage.
 *      - Integrity check: recompute off-chain hash or Merkle proof and verify against on-chain root.
 *      - Limitation: blockchain provides tamper evidence, not truth; false input can still be recorded immutably.
 */
contract SafeContainAuditLedger {
    // Single event record (Phase 1 legacy & individual anchors)
    struct AuditRecord {
        string eventId;
        bytes32 recordHash;
        uint256 timestamp;
        string eventType;
        string approvalReference;
        address recordedBy;
    }

    // Batch Merkle Evidence Anchor (Phase 3 enterprise anchoring)
    struct EvidenceAnchor {
        bytes32 anchorId;
        bytes32 evidenceRoot;
        uint256 timestamp;
        uint256 firstSequence;
        uint256 lastSequence;
        uint256 recordCount;
        address submitter;
    }

    // State mappings
    mapping(string => AuditRecord) private records;
    string[] private eventRegistry;

    mapping(bytes32 => EvidenceAnchor) private anchors;
    bytes32[] private anchorRegistry;

    // Authorized anchorers mapping
    mapping(address => bool) public authorizedAnchorers;

    // Events
    event RecordAnchored(
        string indexed eventId,
        bytes32 indexed recordHash,
        uint256 timestamp,
        string eventType,
        string approvalReference,
        address recordedBy
    );

    event EvidenceAnchored(
        bytes32 indexed anchorId,
        bytes32 indexed evidenceRoot,
        uint256 firstSequence,
        uint256 lastSequence,
        uint256 recordCount,
        uint256 timestamp,
        address indexed submitter
    );

    event AnchorerAuthorized(address indexed account, bool authorized);

    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "SafeContain: caller is not the owner");
        _;
    }

    modifier onlyAuthorized() {
        require(
            msg.sender == owner || authorizedAnchorers[msg.sender],
            "SafeContain: unauthorized anchor submitter"
        );
        _;
    }

    constructor() {
        owner = msg.sender;
        authorizedAnchorers[msg.sender] = true;
    }

    function setAuthorizedAnchorer(address account, bool authorized) external onlyOwner {
        require(account != address(0), "SafeContain: zero address");
        authorizedAnchorers[account] = authorized;
        emit AnchorerAuthorized(account, authorized);
    }

    /**
     * @notice Anchors a cryptographic Merkle evidence root for a batch of audit ledger records.
     */
    function anchorBatch(
        bytes32 anchorId,
        bytes32 evidenceRoot,
        uint256 firstSequence,
        uint256 lastSequence,
        uint256 recordCount
    ) external onlyAuthorized {
        require(anchorId != bytes32(0), "SafeContain: anchorId cannot be empty");
        require(evidenceRoot != bytes32(0), "SafeContain: evidenceRoot cannot be empty");
        require(anchors[anchorId].timestamp == 0, "SafeContain: anchor already exists");
        require(recordCount > 0, "SafeContain: recordCount must be positive");
        require(lastSequence >= firstSequence, "SafeContain: invalid sequence range");

        anchors[anchorId] = EvidenceAnchor({
            anchorId: anchorId,
            evidenceRoot: evidenceRoot,
            timestamp: block.timestamp,
            firstSequence: firstSequence,
            lastSequence: lastSequence,
            recordCount: recordCount,
            submitter: msg.sender
        });

        anchorRegistry.push(anchorId);

        emit EvidenceAnchored(
            anchorId,
            evidenceRoot,
            firstSequence,
            lastSequence,
            recordCount,
            block.timestamp,
            msg.sender
        );
    }

    /**
     * @notice Retrieves batch anchor details by anchor ID.
     */
    function getAnchor(bytes32 anchorId) external view returns (
        bytes32 evidenceRoot,
        uint256 timestamp,
        uint256 firstSequence,
        uint256 lastSequence,
        uint256 recordCount,
        address submitter
    ) {
        EvidenceAnchor memory a = anchors[anchorId];
        require(a.timestamp > 0, "SafeContain: anchor not found");
        return (
            a.evidenceRoot,
            a.timestamp,
            a.firstSequence,
            a.lastSequence,
            a.recordCount,
            a.submitter
        );
    }

    /**
     * @notice Performs on-chain batch anchor verification against an expected Merkle root.
     */
    function verifyAnchor(
        bytes32 anchorId,
        bytes32 expectedRoot
    ) external view returns (bool isValid, uint256 timestamp, uint256 recordCount) {
        EvidenceAnchor memory a = anchors[anchorId];
        if (a.timestamp == 0) {
            return (false, 0, 0);
        }
        bool matches = (a.evidenceRoot == expectedRoot);
        return (matches, a.timestamp, a.recordCount);
    }

    /**
     * @notice Returns total number of anchored Merkle batches.
     */
    function totalAnchors() external view returns (uint256) {
        return anchorRegistry.length;
    }

    /**
     * @notice Retrieves anchor ID by registry index for enumeration.
     */
    function getAnchorByIndex(uint256 index) external view returns (bytes32) {
        require(index < anchorRegistry.length, "SafeContain: index out of bounds");
        return anchorRegistry[index];
    }

    // =========================================================================
    // Legacy individual record support (maintains backward compatibility)
    // =========================================================================

    /**
     * @notice Anchors an off-chain record's cryptographic SHA-256 hash onto the immutable ledger.
     */
    function recordEvent(
        string calldata eventId,
        bytes32 recordHash,
        string calldata eventType,
        string calldata approvalReference
    ) external onlyAuthorized {
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
     * @notice Returns total number of anchored individual audit records.
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
