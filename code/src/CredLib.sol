// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title CredLib - domain-separated hashing, Merkle and sparse-Merkle verification
/// @notice All tags below MUST match offchain/lib/hash.js byte-for-byte.
///         0x00 attribute leaf | 0x01 binary-Merkle internal node | 0x02 credential leaf
///         0x03 nullifier       | 0x04 SMT occupied leaf          | 0x05 SMT internal node
library CredLib {
    uint256 internal constant SMT_DEPTH = 256;

    /// attribute leaf: H(0x00 || salt || H(key) || H(value))
    function attrLeaf(bytes32 salt, bytes memory key, bytes memory value) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(uint8(0x00), salt, keccak256(key), keccak256(value)));
    }

    function node(bytes32 l, bytes32 r) internal pure returns (bytes32 h) {
        assembly {
            let p := mload(0x40)
            mstore8(p, 0x01)
            mstore(add(p, 1), l)
            mstore(add(p, 33), r)
            h := keccak256(p, 65)
        }
    }

    /// credential leaf: H(0x02 || attrRoot || holder || nullifier || validUntil || schemaId)
    function credLeaf(bytes32 attrRoot, address holder, bytes32 nullifier, uint64 validUntil, bytes32 schemaId)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(uint8(0x02), attrRoot, holder, nullifier, validUntil, schemaId));
    }

    /// positional binary Merkle proof (index bits select left/right, LSB = leaf level)
    function merkleRoot(bytes32 leaf, uint256 index, bytes32[] calldata path) internal pure returns (bytes32 h) {
        h = leaf;
        for (uint256 i = 0; i < path.length; ++i) {
            h = ((index >> i) & 1) == 0 ? node(h, path[i]) : node(path[i], h);
        }
        // index must fit in the tree height, otherwise two indices could share a proof
        require(index >> path.length == 0, "index out of range");
    }

    function smtNode(bytes32 l, bytes32 r) internal pure returns (bytes32 h) {
        if (l == bytes32(0) && r == bytes32(0)) return bytes32(0);
        assembly {
            let p := mload(0x40)
            mstore8(p, 0x05)
            mstore(add(p, 1), l)
            mstore(add(p, 33), r)
            h := keccak256(p, 65)
        }
    }

    function smtLeaf(bytes32 key) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(uint8(0x04), key));
    }

    /// @notice Recompute a sparse-Merkle root from a leaf value at position `key`.
    /// @param bitmap bit h set  <=> sibling at height h is non-zero and present in `siblings`
    /// @dev For a non-membership proof (leafValue == 0) every level below the lowest non-zero sibling
    ///      hashes (0,0) -> 0, so the loop starts at that sibling: O(log r) iterations instead of 256.
    function smtRoot(bytes32 key, bytes32 leafValue, uint256 bitmap, bytes32[] calldata siblings)
        internal
        pure
        returns (bytes32 h)
    {
        h = leafValue;
        uint256 start = 0;
        if (leafValue == bytes32(0)) {
            if (bitmap == 0) {
                require(siblings.length == 0, "unused siblings");
                return bytes32(0);
            }
            start = lowestBit(bitmap);
        }
        uint256 k = uint256(key);
        uint256 j = 0;
        for (uint256 i = start; i < SMT_DEPTH; ++i) {
            bytes32 sib;
            if ((bitmap >> i) & 1 == 1) {
                sib = siblings[j++];
            }
            if (h == bytes32(0) && sib == bytes32(0)) continue; // empty subtree stays empty
            h = ((k >> i) & 1) == 0 ? smtNode(h, sib) : smtNode(sib, h);
        }
        require(j == siblings.length, "unused siblings");
    }

    /// index of the least-significant set bit (x != 0), by binary search
    function lowestBit(uint256 x) internal pure returns (uint256 r) {
        x = x & (~x + 1);
        if (x >= 1 << 128) { x >>= 128; r += 128; }
        if (x >= 1 << 64) { x >>= 64; r += 64; }
        if (x >= 1 << 32) { x >>= 32; r += 32; }
        if (x >= 1 << 16) { x >>= 16; r += 16; }
        if (x >= 1 << 8) { x >>= 8; r += 8; }
        if (x >= 1 << 4) { x >>= 4; r += 4; }
        if (x >= 1 << 2) { x >>= 2; r += 2; }
        if (x >= 1 << 1) { r += 1; }
    }
}
