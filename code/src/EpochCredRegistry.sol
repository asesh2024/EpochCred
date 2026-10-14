// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CredLib} from "./CredLib.sol";

/// @title EpochCredRegistry
/// @notice Quorum-endorsed (k-of-n independent ECDSA signatures), epoch-anchored credential registry.
///  * An accreditation authority registers an issuer (university) with n officer keys and a threshold k.
///  * Once per epoch, any relayer submits ONE transaction carrying k-of-n EIP-712 signatures over
///    (issuanceRoot, revocationRoot, count, prevHead). The registry stores a single 32-byte digest per
///    epoch (hash-chained to the previous one); full roots are emitted in an event (digest mode) or
///    additionally stored (full mode, used as an ablation).
///  * Revocations are folded into the same commitment as the root of a sparse Merkle tree keyed by
///    privacy-preserving nullifiers, so revocation cost is O(1) per epoch regardless of how many
///    credentials are revoked.
contract EpochCredRegistry {
    struct EpochRecord {
        bytes32 issuanceRoot;
        bytes32 revocationRoot;
        uint64 timestamp;
        uint32 count;
        bytes32 prevHead;
    }

    struct Issuer {
        uint64 epoch; // last committed epoch (0 = none)
        uint64 rotationNonce;
        uint8 threshold;
        bool active;
        bool frozen; // set by a successful revocation-removal fraud proof
        uint64 restoredAt; // epoch at which the accreditor last restored a frozen issuer (0 = never)
        bytes32 head; // digest of last committed epoch
    }

    bytes32 public constant EPOCH_TYPEHASH = keccak256(
        "EpochCommit(bytes32 issuerId,uint64 epoch,bytes32 issuanceRoot,bytes32 revocationRoot,uint32 count,bytes32 prevHead)"
    );
    bytes32 public constant ROTATE_TYPEHASH =
        keccak256("RotateOfficers(bytes32 issuerId,uint64 nonce,bytes32 officersHash,uint8 threshold)");

    address public immutable accreditor;
    bool public immutable storeFull;
    bytes32 public immutable DOMAIN_SEPARATOR;

    mapping(bytes32 => Issuer) public issuers;
    mapping(bytes32 => address[]) internal officers;
    mapping(bytes32 => mapping(address => bool)) public isOfficer;
    mapping(bytes32 => mapping(uint64 => bytes32)) public epochDigest;
    mapping(bytes32 => mapping(uint64 => EpochRecord)) internal fullRecords; // ablation only

    event IssuerRegistered(bytes32 indexed issuerId, address[] officers, uint8 threshold);
    event OfficersRotated(bytes32 indexed issuerId, address[] officers, uint8 threshold);
    event EpochCommitted(
        bytes32 indexed issuerId,
        uint64 indexed epoch,
        bytes32 issuanceRoot,
        bytes32 revocationRoot,
        uint64 timestamp,
        uint32 count,
        bytes32 prevHead,
        bytes32 digest
    );

    error NotAccreditor();
    error UnknownIssuer();
    error BadEpoch();
    error BadThreshold();
    error BadSignatures();
    error StaleHead();
    error Frozen();
    error BadFraudProof();

    event IssuerFrozen(bytes32 indexed issuerId, uint64 oldEpoch, uint64 newEpoch, bytes32 nullifier, address reporter);
    event IssuerRestored(bytes32 indexed issuerId, uint64 atEpoch);
    error NotFrozen();

    constructor(bool _storeFull) {
        accreditor = msg.sender;
        storeFull = _storeFull;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("EpochCred"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    // --------------------------------------------------------------------- governance
    function registerIssuer(bytes32 issuerId, address[] calldata _officers, uint8 threshold) external {
        if (msg.sender != accreditor) revert NotAccreditor();
        if (issuers[issuerId].active) revert BadEpoch();
        _setOfficers(issuerId, _officers, threshold);
        issuers[issuerId].active = true;
        emit IssuerRegistered(issuerId, _officers, threshold);
    }

    /// @notice k-of-n of the CURRENT officers authorise a new officer set (key rotation / recovery).
    function rotateOfficers(bytes32 issuerId, address[] calldata newOfficers, uint8 newThreshold, bytes calldata sigs)
        external
    {
        Issuer storage s = issuers[issuerId];
        if (!s.active) revert UnknownIssuer();
        bytes32 structHash = keccak256(
            abi.encode(ROTATE_TYPEHASH, issuerId, s.rotationNonce, keccak256(abi.encodePacked(newOfficers)), newThreshold)
        );
        _checkThreshold(issuerId, _digest712(structHash), sigs, s.threshold);
        s.rotationNonce++;
        address[] storage old = officers[issuerId];
        for (uint256 i = 0; i < old.length; ++i) isOfficer[issuerId][old[i]] = false;
        delete officers[issuerId];
        _setOfficers(issuerId, newOfficers, newThreshold);
        emit OfficersRotated(issuerId, newOfficers, newThreshold);
    }

    function _setOfficers(bytes32 issuerId, address[] calldata _officers, uint8 threshold) internal {
        if (threshold == 0 || threshold > _officers.length) revert BadThreshold();
        for (uint256 i = 0; i < _officers.length; ++i) {
            if (_officers[i] == address(0) || isOfficer[issuerId][_officers[i]]) revert BadThreshold();
            isOfficer[issuerId][_officers[i]] = true;
            officers[issuerId].push(_officers[i]);
        }
        issuers[issuerId].threshold = threshold;
    }

    function getOfficers(bytes32 issuerId) external view returns (address[] memory) {
        return officers[issuerId];
    }

    // --------------------------------------------------------------------- epoch commit
    function commitEpoch(
        bytes32 issuerId,
        uint64 epoch,
        bytes32 issuanceRoot,
        bytes32 revocationRoot,
        uint32 count,
        bytes calldata sigs
    ) external returns (bytes32 digest) {
        Issuer storage s = issuers[issuerId];
        if (!s.active) revert UnknownIssuer();
        if (s.frozen) revert Frozen();
        if (epoch != s.epoch + 1) revert BadEpoch();
        bytes32 prevHead = s.head;
        bytes32 structHash =
            keccak256(abi.encode(EPOCH_TYPEHASH, issuerId, epoch, issuanceRoot, revocationRoot, count, prevHead));
        _checkThreshold(issuerId, _digest712(structHash), sigs, s.threshold);

        uint64 ts = uint64(block.timestamp);
        digest = recordDigest(EpochRecord(issuanceRoot, revocationRoot, ts, count, prevHead));
        epochDigest[issuerId][epoch] = digest;
        s.epoch = epoch;
        s.head = digest;
        if (storeFull) fullRecords[issuerId][epoch] = EpochRecord(issuanceRoot, revocationRoot, ts, count, prevHead);
        emit EpochCommitted(issuerId, epoch, issuanceRoot, revocationRoot, ts, count, prevHead, digest);
    }

    function recordDigest(EpochRecord memory r) public pure returns (bytes32) {
        return keccak256(abi.encode(r.issuanceRoot, r.revocationRoot, r.timestamp, r.count, r.prevHead));
    }

    function getFullRecord(bytes32 issuerId, uint64 epoch) external view returns (EpochRecord memory) {
        return fullRecords[issuerId][epoch];
    }

    function _digest712(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    /// @dev signatures are 65-byte (r,s,v) blobs, concatenated, signers strictly ascending (no duplicates)
    function _checkThreshold(bytes32 issuerId, bytes32 digest, bytes calldata sigs, uint8 threshold) internal view {
        uint256 n = sigs.length / 65;
        if (sigs.length % 65 != 0 || n < threshold) revert BadSignatures();
        address last = address(0);
        for (uint256 i = 0; i < threshold; ++i) {
            bytes32 r;
            bytes32 s_;
            uint8 v;
            assembly {
                let off := add(sigs.offset, mul(i, 65))
                r := calldataload(off)
                s_ := calldataload(add(off, 32))
                v := byte(0, calldataload(add(off, 64)))
            }
            // reject malleable high-s signatures (EIP-2)
            if (uint256(s_) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) revert BadSignatures();
            address signer = ecrecover(digest, v, r, s_);
            if (signer <= last || !isOfficer[issuerId][signer]) revert BadSignatures();
            last = signer;
        }
    }

    // --------------------------------------------------------------------- append-only revocation
    /// @notice Fraud proof: anyone holding the published revocation sets can show that a nullifier present
    ///         under the revocation root of epoch `oldE` is absent under the root of a later epoch `newE`.
    ///         The registry then freezes the issuer: no further commits, and on-chain verification fails.
    ///         This makes "revocation is cumulative" enforceable instead of an assumption on officer honesty.
    function challengeRevocationRemoval(
        bytes32 issuerId,
        uint64 oldE,
        EpochRecord calldata oldRec,
        uint64 newE,
        EpochRecord calldata newRec,
        bytes32 nullifier,
        NonRevocation calldata memberProof,
        NonRevocation calldata absentProof
    ) external {
        Issuer storage s = issuers[issuerId];
        // newE > restoredAt: violations already adjudicated before a restoration cannot be replayed to re-freeze,
        // but a later epoch that again omits an earlier nullifier is a new, challengeable violation
        if (!s.active || s.frozen || newE <= oldE || newE <= s.restoredAt) revert BadFraudProof();
        if (recordDigest(oldRec) != epochDigest[issuerId][oldE]) revert BadFraudProof();
        if (recordDigest(newRec) != epochDigest[issuerId][newE]) revert BadFraudProof();
        if (CredLib.smtRoot(nullifier, CredLib.smtLeaf(nullifier), memberProof.bitmap, memberProof.siblings) != oldRec.revocationRoot) {
            revert BadFraudProof();
        }
        if (CredLib.smtRoot(nullifier, bytes32(0), absentProof.bitmap, absentProof.siblings) != newRec.revocationRoot) {
            revert BadFraudProof();
        }
        s.frozen = true;
        emit IssuerFrozen(issuerId, oldE, newE, nullifier, msg.sender);
    }

    /// @notice Accreditor-only restoration after a freeze (governance decision taken off-chain). The issuer's next
    ///         commit must again contain every previously committed nullifier, otherwise it is challengeable anew.
    function restoreIssuer(bytes32 issuerId) external {
        if (msg.sender != accreditor) revert NotAccreditor();
        Issuer storage s = issuers[issuerId];
        if (!s.frozen) revert NotFrozen();
        s.frozen = false;
        s.restoredAt = s.epoch;
        emit IssuerRestored(issuerId, s.epoch);
    }

    // --------------------------------------------------------------------- on-chain verification
    struct Disclosure {
        bytes key;
        bytes value;
        bytes32 salt;
        uint256 attrIndex;
        bytes32[] attrPath;
    }

    struct CredBody {
        address holder;
        bytes32 nullifier;
        uint64 validUntil;
        bytes32 schemaId;
        uint256 leafIndex;
        bytes32[] issuancePath;
    }

    struct NonRevocation {
        uint256 bitmap;
        bytes32[] siblings;
    }

    /// @notice Verifies one disclosed attribute of a credential issued in `issEpoch`, and that the
    ///         credential is not revoked according to the issuer's LATEST epoch, which must be at most
    ///         `maxStaleness` seconds old. Intended for smart-contract relying parties.
    function verifyAttribute(
        bytes32 issuerId,
        uint64 issEpoch,
        EpochRecord calldata issRec,
        EpochRecord calldata latestRec,
        Disclosure calldata d,
        CredBody calldata c,
        NonRevocation calldata nr,
        uint256 maxStaleness
    ) external view returns (bool) {
        Issuer storage s = issuers[issuerId];
        if (!s.active || s.frozen) return false;
        if (recordDigest(issRec) != epochDigest[issuerId][issEpoch]) return false;
        if (recordDigest(latestRec) != s.head) return false;
        if (block.timestamp > latestRec.timestamp + maxStaleness) return false;
        if (block.timestamp > c.validUntil) return false;
        if (c.leafIndex >= issRec.count) return false; // padding positions are not credentials

        bytes32 attrRoot = CredLib.merkleRoot(CredLib.attrLeaf(d.salt, d.key, d.value), d.attrIndex, d.attrPath);
        bytes32 leaf = CredLib.credLeaf(attrRoot, c.holder, c.nullifier, c.validUntil, c.schemaId);
        if (CredLib.merkleRoot(leaf, c.leafIndex, c.issuancePath) != issRec.issuanceRoot) return false;
        // non-membership: the SMT slot at `nullifier` must be empty under the latest revocation root
        if (CredLib.smtRoot(c.nullifier, bytes32(0), nr.bitmap, nr.siblings) != latestRec.revocationRoot) return false;
        return true;
    }
}
