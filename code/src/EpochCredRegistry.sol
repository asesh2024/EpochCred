// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./CredLib.sol";

contract EpochCredRegistry {
    struct Issuer {
        bool active;
        bool frozen;
        uint16 k;
        uint32 epoch;
        uint32 restoredAt;
        uint32 gen;
        uint32 rotNonce;
        uint32 obligationCount;
        bytes32 head;
    }

    struct Sig {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    struct EpochRecord {
        bytes32 rIss;
        bytes32 rRev;
        uint64 timestamp;
        uint32 batchSize;
        uint32 gen;
        bytes32 prevDigest;
    }

    address public immutable accreditor;
    bytes32 public immutable DOMAIN_SEPARATOR;

    bytes32 public constant EPOCH_TYPEHASH =
        keccak256("EpochCommit(bytes32 issuerId,uint32 epoch,bytes32 rIss,bytes32 rRev,uint32 batchSize,uint32 gen,uint64 sigDeadline,bytes32 prevHead)");
    bytes32 public constant ROTATE_TYPEHASH =
        keccak256("RotateOfficers(bytes32 issuerId,uint32 nonce,bytes32 newOfficersHash,uint16 newK)");
    bytes32 public constant REVACK_TYPEHASH =
        keccak256("RevAck(bytes32 issuerId,bytes32 nullifier,uint32 gen,uint64 deadline)");

    mapping(bytes32 => Issuer) public issuers;
    mapping(bytes32 => mapping(address => bool)) public isOfficer;
    mapping(bytes32 => address[]) private _currentOfficers;
    mapping(bytes32 => mapping(uint32 => bytes32)) public epochDigest;

    // Lifecycle Obligation Preservation & Idempotent Adjudication
    mapping(bytes32 => mapping(uint32 => bytes32)) public genOfficerRoot;
    mapping(bytes32 => bytes32) public obligationHead;
    mapping(bytes32 => mapping(bytes32 => bool)) public processedChallenges; // Idempotence check

    event IssuerRegistered(bytes32 indexed issuerId, uint256 n, uint16 k, uint32 gen);
    event EpochCommitted(
        bytes32 indexed issuerId,
        uint32 indexed epoch,
        bytes32 rIss,
        bytes32 rRev,
        uint64 timestamp,
        uint32 batchSize,
        uint32 gen,
        bytes32 prevDigest,
        bytes32 digest
    );
    event OfficersRotated(bytes32 indexed issuerId, uint32 oldGen, uint32 newGen, uint16 newK, bytes32 archivedRoot);
    event IssuerFrozen(bytes32 indexed issuerId, uint32 offendingEpoch, bytes32 nullifier, string reason);
    event IssuerRestored(bytes32 indexed issuerId, uint32 restoredAtEpoch, uint32 clearedObligations);

    constructor() {
        accreditor = msg.sender;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("EpochCredRegistry")),
                keccak256(bytes("2")),
                block.chainid,
                address(this)
            )
        );
    }

    function registerIssuer(
        bytes32 issuerId,
        address[] calldata officers,
        uint16 k
    ) external {
        require(msg.sender == accreditor, "Only accreditor");
        require(!issuers[issuerId].active, "Already registered");
        require(k > 0 && k <= officers.length, "Invalid quorum k");

        for (uint256 i = 0; i < officers.length; ++i) {
            address o = officers[i];
            require(o != address(0) && !isOfficer[issuerId][o], "Duplicate/zero officer");
            isOfficer[issuerId][o] = true;
            _currentOfficers[issuerId].push(o);
        }

        issuers[issuerId] = Issuer({
            active: true,
            frozen: false,
            k: k,
            epoch: 0,
            restoredAt: 0,
            gen: 1,
            rotNonce: 0,
            obligationCount: 0,
            head: bytes32(0)
        });

        emit IssuerRegistered(issuerId, officers.length, k, 1);
    }

    function commitEpoch(
        bytes32 issuerId,
        uint32 e,
        bytes32 rIss,
        bytes32 rRev,
        uint32 batchSize,
        uint32 gen,
        uint64 sigDeadline,
        Sig[] calldata sigs
    ) external {
        Issuer storage I = issuers[issuerId];
        require(I.active && !I.frozen, "Issuer inactive or frozen");
        require(e == I.epoch + 1, "Non-sequential epoch");
        require(gen == I.gen, "Generation mismatch");
        require(block.timestamp <= sigDeadline, "Endorsement expired");
        require(sigs.length >= I.k, "Insufficient signatures");

        bytes32 structHash = keccak256(
            abi.encode(EPOCH_TYPEHASH, issuerId, e, rIss, rRev, batchSize, gen, sigDeadline, I.head)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        _verifyCurrentQuorum(issuerId, digest, sigs, I.k);

        bytes32 prev = I.head;
        uint64 nowTs = uint64(block.timestamp);
        bytes32 D = keccak256(abi.encode(rIss, rRev, nowTs, batchSize, gen, prev));

        epochDigest[issuerId][e] = D;
        I.head = D;
        I.epoch = e;

        emit EpochCommitted(issuerId, e, rIss, rRev, nowTs, batchSize, gen, prev, D);
    }

    function rotateOfficers(
        bytes32 issuerId,
        uint32 nonce,
        address[] calldata newOfficers,
        uint16 newK,
        Sig[] calldata sigs
    ) external {
        Issuer storage I = issuers[issuerId];
        require(I.active, "Issuer inactive");
        require(nonce == I.rotNonce + 1, "Invalid rotation nonce");
        require(newK > 0 && newK <= newOfficers.length, "Invalid newK");

        bytes32 newOfficersHash = keccak256(abi.encodePacked(newOfficers));
        bytes32 structHash = keccak256(abi.encode(ROTATE_TYPEHASH, issuerId, nonce, newOfficersHash, newK));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        _verifyCurrentQuorum(issuerId, digest, sigs, I.k);

        uint32 oldGen = I.gen;
        bytes32 archivedRoot = keccak256(abi.encodePacked(_currentOfficers[issuerId], I.k));
        genOfficerRoot[issuerId][oldGen] = archivedRoot;

        address[] storage cur = _currentOfficers[issuerId];
        for (uint256 i = 0; i < cur.length; ++i) {
            isOfficer[issuerId][cur[i]] = false;
        }
        delete _currentOfficers[issuerId];

        for (uint256 i = 0; i < newOfficers.length; ++i) {
            address o = newOfficers[i];
            require(o != address(0) && !isOfficer[issuerId][o], "Duplicate/zero new officer");
            isOfficer[issuerId][o] = true;
            _currentOfficers[issuerId].push(o);
        }

        I.k = newK;
        I.rotNonce = nonce;
        I.gen = oldGen + 1;

        emit OfficersRotated(issuerId, oldGen, oldGen + 1, newK, archivedRoot);
    }

    function challengeRevocationRemoval(
        bytes32 issuerId,
        uint32 e1,
        uint32 e2,
        EpochRecord calldata rec1,
        EpochRecord calldata rec2,
        bytes32 nullifier,
        uint256 bitmap1,
        bytes32[] calldata sibs1,
        uint256 bitmap2,
        bytes32[] calldata sibs2
    ) external {
        Issuer storage I = issuers[issuerId];
        require(I.active, "Issuer inactive");
        bytes32 chalId = keccak256(abi.encodePacked("ROLLBACK", issuerId, nullifier, e1, e2));
        require(!processedChallenges[issuerId][chalId], "Challenge already processed");
        processedChallenges[issuerId][chalId] = true;

        require(e1 < e2, "Invalid epoch ordering");
        require(_hashRecord(rec1) == epochDigest[issuerId][e1], "rec1 digest mismatch");
        require(_hashRecord(rec2) == epochDigest[issuerId][e2], "rec2 digest mismatch");

        bytes32 leaf = CredLib.hashNullifierLeaf(nullifier);
        require(CredLib.smtRoot(nullifier, leaf, bitmap1, sibs1) == rec1.rRev, "Not member in e1");
        require(CredLib.smtRoot(nullifier, bytes32(0), bitmap2, sibs2) == rec2.rRev, "Not absent in e2");

        I.frozen = true;
        obligationHead[issuerId] = keccak256(abi.encodePacked(obligationHead[issuerId], nullifier));
        unchecked { ++I.obligationCount; }

        emit IssuerFrozen(issuerId, e2, nullifier, "REVOCATION_ROLLBACK");
    }

    /// @notice Idempotent challenge processing with obligation-specific adjudication (Reviewer Issue 2 & 3)
    function challengeMissedDeadline(
        bytes32 issuerId,
        bytes32 nullifier,
        uint32 ackGen,
        uint64 deadline,
        Sig[] calldata ackSigs,
        address[] calldata archivedOfficers,
        uint16 archivedK,
        uint32 eHead,
        EpochRecord calldata recHead,
        uint256 nrBitmap,
        bytes32[] calldata nrSibs
    ) external {
        Issuer storage I = issuers[issuerId];
        require(I.active, "Issuer inactive");
        bytes32 chalId = keccak256(abi.encodePacked("DEADLINE", issuerId, nullifier, deadline));
        require(!processedChallenges[issuerId][chalId], "Challenge already processed");
        processedChallenges[issuerId][chalId] = true;

        require(block.timestamp > deadline, "Deadline not yet passed");
        require(_hashRecord(recHead) == epochDigest[issuerId][eHead], "recHead digest mismatch");
        require(recHead.timestamp >= deadline || eHead == I.epoch, "Not post-deadline head");

        bytes32 structHash = keccak256(abi.encode(REVACK_TYPEHASH, issuerId, nullifier, ackGen, deadline));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        if (ackGen == I.gen) {
            _verifyCurrentQuorum(issuerId, digest, ackSigs, 1);
        } else {
            require(
                keccak256(abi.encodePacked(archivedOfficers, archivedK)) == genOfficerRoot[issuerId][ackGen],
                "Invalid archived officer set"
            );
            _verifyArchivedQuorum(archivedOfficers, digest, ackSigs, 1);
        }

        require(CredLib.smtRoot(nullifier, bytes32(0), nrBitmap, nrSibs) == recHead.rRev, "Nullifier is present");

        I.frozen = true;
        obligationHead[issuerId] = keccak256(abi.encodePacked(obligationHead[issuerId], nullifier));
        unchecked { ++I.obligationCount; }

        emit IssuerFrozen(issuerId, eHead, nullifier, "MISSED_REVACK_DEADLINE");
    }

    /// @notice Atomic remedial-fenced restoration enforcing sigDeadline (Reviewer Issue 3)
    function restoreAndRemediate(
        bytes32 issuerId,
        uint32 eNew,
        bytes32 rIss,
        bytes32 rRev,
        uint32 batchSize,
        uint64 sigDeadline,
        Sig[] calldata officerSigs,
        bytes32[] calldata obligatedNullifiers,
        uint256[] calldata memBitmaps,
        bytes32[][] calldata memSibs
    ) external {
        Issuer storage I = issuers[issuerId];
        require(msg.sender == accreditor, "Only accreditor");
        require(I.frozen, "Issuer not frozen");
        require(eNew == I.epoch + 1, "Must advance epoch");
        require(block.timestamp <= sigDeadline, "Remedial endorsement expired");
        require(obligatedNullifiers.length == I.obligationCount, "Obligation count mismatch");

        bytes32 structHash = keccak256(
            abi.encode(EPOCH_TYPEHASH, issuerId, eNew, rIss, rRev, batchSize, I.gen, sigDeadline, I.head)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        _verifyCurrentQuorum(issuerId, digest, officerSigs, I.k);

        bytes32 acc = bytes32(0);
        for (uint256 j = 0; j < obligatedNullifiers.length; ++j) {
            bytes32 nu = obligatedNullifiers[j];
            acc = keccak256(abi.encodePacked(acc, nu));
            bytes32 leaf = CredLib.hashNullifierLeaf(nu);
            require(
                CredLib.smtRoot(nu, leaf, memBitmaps[j], memSibs[j]) == rRev,
                "Obligated nullifier missing in remedial root"
            );
        }
        require(acc == obligationHead[issuerId], "Obligation accumulator mismatch");

        uint32 cleared = I.obligationCount;
        I.frozen = false;
        I.restoredAt = eNew; // Used only for tracking historical remediation boundaries, not blocking challenges
        I.obligationCount = 0;
        obligationHead[issuerId] = bytes32(0);

        uint64 nowTs = uint64(block.timestamp);
        bytes32 prev = I.head;
        bytes32 D = keccak256(abi.encode(rIss, rRev, nowTs, batchSize, I.gen, prev));
        epochDigest[issuerId][eNew] = D;
        I.head = D;
        I.epoch = eNew;

        emit IssuerRestored(issuerId, eNew, cleared);
        emit EpochCommitted(issuerId, eNew, rIss, rRev, nowTs, batchSize, I.gen, prev, D);
    }

    function _hashRecord(EpochRecord calldata rec) private pure returns (bytes32) {
        return keccak256(abi.encode(rec.rIss, rec.rRev, rec.timestamp, rec.batchSize, rec.gen, rec.prevDigest));
    }

    function _verifyCurrentQuorum(
        bytes32 issuerId,
        bytes32 digest,
        Sig[] calldata sigs,
        uint16 requiredSigs
    ) private view {
        address last = address(0);
        for (uint256 i = 0; i < requiredSigs; ++i) {
            address a = CredLib.recoverStrict(digest, sigs[i].v, sigs[i].r, sigs[i].s);
            require(a > last && isOfficer[issuerId][a], "Invalid or unsorted officer sig");
            last = a;
        }
    }

    function _verifyArchivedQuorum(
        address[] calldata archivedOfficers,
        bytes32 digest,
        Sig[] calldata sigs,
        uint16 requiredSigs
    ) private pure {
        address last = address(0);
        for (uint256 i = 0; i < requiredSigs; ++i) {
            address a = CredLib.recoverStrict(digest, sigs[i].v, sigs[i].r, sigs[i].s);
            require(a > last, "Unsorted archived sig");
            bool found = false;
            for (uint256 j = 0; j < archivedOfficers.length; ++j) {
                if (archivedOfficers[j] == a) {
                    found = true;
                    break;
                }
            }
            require(found, "Not an officer in archived generation");
            last = a;
        }
    }
}
