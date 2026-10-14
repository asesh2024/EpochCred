// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {CredLib} from "./CredLib.sol";

/// Baselines re-implemented in the SAME testbed so gas, proof size and latency are comparable.

/// B1 - per-credential hash registry (the design used by most prior academic-certificate systems,
///      including our earlier single-chain prototype): one storage slot per certificate hash,
///      a single authorised issuer key, revocation by flag.
contract PerCredentialRegistry {
    struct Rec {
        address issuer;
        uint64 issuedAt;
        bool revoked;
    }

    mapping(address => bool) public isIssuer;
    mapping(bytes32 => Rec) public records;

    constructor() {
        isIssuer[msg.sender] = true;
    }

    function addIssuer(address a) external {
        require(isIssuer[msg.sender], "auth");
        isIssuer[a] = true;
    }

    function issue(bytes32 h) external {
        require(isIssuer[msg.sender], "auth");
        require(records[h].issuedAt == 0, "dup");
        records[h] = Rec(msg.sender, uint64(block.timestamp), false);
    }

    function issueBatch(bytes32[] calldata hs) external {
        require(isIssuer[msg.sender], "auth");
        for (uint256 i = 0; i < hs.length; ++i) {
            require(records[hs[i]].issuedAt == 0, "dup");
            records[hs[i]] = Rec(msg.sender, uint64(block.timestamp), false);
        }
    }

    function revoke(bytes32 h) external {
        require(records[h].issuer == msg.sender, "auth");
        records[h].revoked = true;
    }

    function revokeBatch(bytes32[] calldata hs) external {
        for (uint256 i = 0; i < hs.length; ++i) {
            require(records[hs[i]].issuer == msg.sender, "auth");
            records[hs[i]].revoked = true;
        }
    }

    function isValid(bytes32 h) external view returns (bool) {
        Rec memory r = records[h];
        return r.issuedAt != 0 && !r.revoked && isIssuer[r.issuer];
    }
}

/// B2 - Blockcerts-style batch anchoring: one Merkle root per batch signed by a single key,
///      revocation through a per-credential on-chain list.
contract BatchMerkleRegistry {
    mapping(address => bool) public isIssuer;
    mapping(bytes32 => uint64) public anchoredAt;
    mapping(bytes32 => bool) public revoked;

    constructor() {
        isIssuer[msg.sender] = true;
    }

    function anchor(bytes32 root) external {
        require(isIssuer[msg.sender], "auth");
        require(anchoredAt[root] == 0, "dup");
        anchoredAt[root] = uint64(block.timestamp);
    }

    function revoke(bytes32 credId) external {
        require(isIssuer[msg.sender], "auth");
        revoked[credId] = true;
    }

    function revokeBatch(bytes32[] calldata ids) external {
        require(isIssuer[msg.sender], "auth");
        for (uint256 i = 0; i < ids.length; ++i) revoked[ids[i]] = true;
    }

    function verify(bytes32 docHash, uint256 index, bytes32[] calldata path, bytes32 root) external view returns (bool) {
        if (anchoredAt[root] == 0 || revoked[docHash]) return false;
        return CredLib.merkleRoot(docHash, index, path) == root;
    }
}

/// B3 - batch anchoring + on-chain bitstring status list (W3C Bitstring Status List style):
///      revocation flips bit `index` of the batch's status list (256 credentials per storage word).
contract StatusListRegistry {
    mapping(address => bool) public isIssuer;
    mapping(bytes32 => uint64) public anchoredAt;
    mapping(bytes32 => mapping(uint256 => uint256)) public statusWords; // root => word => bits

    constructor() {
        isIssuer[msg.sender] = true;
    }

    function anchor(bytes32 root) external {
        require(isIssuer[msg.sender], "auth");
        require(anchoredAt[root] == 0, "dup");
        anchoredAt[root] = uint64(block.timestamp);
    }

    function revoke(bytes32 root, uint256 index) external {
        require(isIssuer[msg.sender], "auth");
        statusWords[root][index >> 8] |= (1 << (index & 255));
    }

    function revokeBatch(bytes32 root, uint256[] calldata idx) external {
        require(isIssuer[msg.sender], "auth");
        for (uint256 i = 0; i < idx.length; ++i) statusWords[root][idx[i] >> 8] |= (1 << (idx[i] & 255));
    }

    /// optimised variant (reviewer request): revocations pre-grouped off-chain by storage word, one SSTORE per word
    function revokeWords(bytes32 root, uint256[] calldata wordIdx, uint256[] calldata masks) external {
        require(isIssuer[msg.sender], "auth");
        for (uint256 i = 0; i < wordIdx.length; ++i) statusWords[root][wordIdx[i]] |= masks[i];
    }

    function verify(bytes32 docHash, uint256 index, bytes32[] calldata path, bytes32 root) external view returns (bool) {
        if (anchoredAt[root] == 0) return false;
        if ((statusWords[root][index >> 8] >> (index & 255)) & 1 == 1) return false;
        return CredLib.merkleRoot(docHash, index, path) == root;
    }
}

/// B4 - single-signer ROOT registry: the same storage pattern as EpochCred (one hash-chained digest per epoch
///      binding an issuance root and a revocation root) but authorised by ONE key (msg.sender) instead of a
///      k-of-n quorum. Used with two off-chain revocation structures: EpochCred's nullifier SMT, and a
///      root-anchored bitstring status list (Merkle tree over 256-bit words). Isolates the cost of the quorum.
contract SingleSignerRootRegistry {
    mapping(address => bool) public isIssuer;
    uint64 public epoch;
    bytes32 public head;
    mapping(uint64 => bytes32) public epochDigest;

    // same data-availability event as EpochCred, so the comparison isolates the quorum only
    event EpochCommitted(uint64 indexed epoch, bytes32 issuanceRoot, bytes32 revocationRoot, uint64 timestamp, uint32 count, bytes32 prevHead, bytes32 digest);

    constructor() {
        isIssuer[msg.sender] = true;
    }

    function commit(bytes32 issuanceRoot, bytes32 revocationRoot, uint32 count) external returns (bytes32 d) {
        require(isIssuer[msg.sender], "auth");
        bytes32 prev = head;
        d = keccak256(abi.encode(issuanceRoot, revocationRoot, uint64(block.timestamp), count, prev));
        epoch += 1;
        epochDigest[epoch] = d;
        head = d;
        emit EpochCommitted(epoch, issuanceRoot, revocationRoot, uint64(block.timestamp), count, prev, d);
    }
}

/// Gas harness for the revocation CHECK alone (eth_estimateGas on these views; subtract the intrinsic 21000).
contract RevocationCheckHarness {
    /// EpochCred: nullifier absent from the SMT
    function smtNotRevoked(bytes32 nullifier, uint256 bitmap, bytes32[] calldata siblings, bytes32 root)
        external
        pure
        returns (bool)
    {
        return CredLib.smtRoot(nullifier, bytes32(0), bitmap, siblings) == root;
    }

    /// reference: the unoptimised 256-level SMT walk (before the lowest-set-bit shortcut), for the ablation
    function smtNotRevokedNaive(bytes32 nullifier, uint256 bitmap, bytes32[] calldata siblings, bytes32 root)
        external
        pure
        returns (bool)
    {
        bytes32 h;
        uint256 j = 0;
        for (uint256 i = 0; i < 256; ++i) {
            bytes32 s;
            if ((bitmap >> i) & 1 == 1) s = siblings[j++];
            if (h == bytes32(0) && s == bytes32(0)) continue;
            h = ((uint256(nullifier) >> i) & 1) == 0 ? CredLib.smtNode(h, s) : CredLib.smtNode(s, h);
        }
        return j == siblings.length && h == root;
    }

    /// root-anchored status list: the 256-bit word holding `index` is authenticated, and its bit is 0
    function statusNotRevoked(uint256 index, bytes32 word, bytes32[] calldata path, bytes32 root)
        external
        pure
        returns (bool)
    {
        bytes32 leaf = keccak256(abi.encodePacked(uint8(0x07), word));
        if (CredLib.merkleRoot(leaf, index >> 8, path) != root) return false;
        return (uint256(word) >> (index & 255)) & 1 == 0;
    }
}
