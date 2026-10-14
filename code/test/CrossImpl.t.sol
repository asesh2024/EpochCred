// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {CredLib} from "../src/CredLib.sol";
import {EpochCredRegistry} from "../src/EpochCredRegistry.sol";

contract Harness {
    function merkleRoot(bytes32 leaf, uint256 index, bytes32[] calldata path) external pure returns (bytes32) {
        return CredLib.merkleRoot(leaf, index, path);
    }

    function smtRoot(bytes32 key, bytes32 leafValue, uint256 bitmap, bytes32[] calldata sib) external pure returns (bytes32) {
        return CredLib.smtRoot(key, leafValue, bitmap, sib);
    }

    /// reference: the unoptimised 256-level walk (specification semantics)
    function smtRootNaive(bytes32 key, bytes32 leafValue, uint256 bitmap, bytes32[] calldata sib)
        external
        pure
        returns (bytes32 h)
    {
        h = leafValue;
        uint256 j = 0;
        for (uint256 i = 0; i < 256; ++i) {
            bytes32 s;
            if ((bitmap >> i) & 1 == 1) s = sib[j++];
            h = ((uint256(key) >> i) & 1) == 0 ? CredLib.smtNode(h, s) : CredLib.smtNode(s, h);
        }
        require(j == sib.length, "unused siblings");
    }
}

/// JS reference implementation (offchain/lib) and Solidity (src/CredLib.sol) must agree bit-for-bit.
contract CrossImplTest is Test {
    Harness h;
    string json;

    function setUp() public {
        h = new Harness();
        json = vm.readFile("results/vectors.json");
    }

    function test_attributeLeafAndRoot() public view {
        bytes32 salt = vm.parseJsonBytes32(json, ".salt");
        string memory value = vm.parseJsonString(json, ".degreeValue");
        bytes32 leaf = CredLib.attrLeaf(salt, bytes("degree"), bytes(value));
        assertEq(leaf, vm.parseJsonBytes32(json, ".attrLeaf"));
        bytes32[] memory p = vm.parseJsonBytes32Array(json, ".attrPath");
        uint256 idx = vm.parseJsonUint(json, ".attrIndex");
        assertEq(h.merkleRoot(leaf, idx, p), vm.parseJsonBytes32(json, ".attrRoot"));
    }

    function test_credentialLeafAndIssuanceRoot() public view {
        bytes32 leaf = CredLib.credLeaf(
            vm.parseJsonBytes32(json, ".attrRoot"),
            vm.parseJsonAddress(json, ".holder"),
            vm.parseJsonBytes32(json, ".nullifier"),
            uint64(vm.parseJsonUint(json, ".validUntil")),
            vm.parseJsonBytes32(json, ".schemaId")
        );
        assertEq(leaf, vm.parseJsonBytes32(json, ".credLeaf"));
        bytes32[] memory p = vm.parseJsonBytes32Array(json, ".issuancePath");
        assertEq(h.merkleRoot(leaf, 0, p), vm.parseJsonBytes32(json, ".issuanceRoot"));
    }

    function test_smtNonMembershipAndMembership() public view {
        bytes32 root = vm.parseJsonBytes32(json, ".smtRoot");
        bytes32 nul = vm.parseJsonBytes32(json, ".nullifier");
        uint256 bm = uint256(vm.parseJsonBytes32(json, ".nonMemBitmap"));
        assertEq(h.smtRoot(nul, bytes32(0), bm, vm.parseJsonBytes32Array(json, ".nonMemSiblings")), root);
        bytes32 key = vm.parseJsonBytes32(json, ".memKey");
        uint256 bm2 = uint256(vm.parseJsonBytes32(json, ".memBitmap"));
        bytes32[] memory sib = vm.parseJsonBytes32Array(json, ".memSiblings");
        assertEq(h.smtRoot(key, CredLib.smtLeaf(key), bm2, sib), root);
        // a member key can never produce a valid NON-membership proof with its own path
        assertTrue(h.smtRoot(key, bytes32(0), bm2, sib) != root);
    }

    function testFuzz_indexOutOfRangeReverts(bytes32 leaf, uint8 len, uint256 index) public {
        len = uint8(bound(len, 0, 20));
        index = bound(index, uint256(1) << len, type(uint128).max);
        bytes32[] memory p = new bytes32[](len);
        vm.expectRevert(bytes("index out of range"));
        h.merkleRoot(leaf, index, p);
    }

    function testFuzz_emptySmtAcceptsAnyNonMembership(bytes32 key) public view {
        bytes32[] memory none = new bytes32[](0);
        assertEq(h.smtRoot(key, bytes32(0), 0, none), bytes32(0));
    }

    function testFuzz_singleKeySmt(bytes32 key, bytes32 other) public view {
        vm.assume(key != other);
        // root of a tree holding only `key`, computed by hashing up 256 levels with empty siblings
        bytes32[] memory none = new bytes32[](0);
        bytes32 root = h.smtRoot(key, CredLib.smtLeaf(key), 0, none);
        assertTrue(root != bytes32(0));
        // `other` is absent: its non-membership path has exactly one non-empty sibling (the subtree of `key`)
        assertTrue(h.smtRoot(other, bytes32(0), 0, none) != root);
    }

    function _sig(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _digest(EpochCredRegistry reg, bytes32 id) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(reg.EPOCH_TYPEHASH(), id, uint64(1), bytes32(uint256(1)), bytes32(0), uint32(1), bytes32(0))
        );
        return keccak256(abi.encodePacked("\x19\x01", reg.DOMAIN_SEPARATOR(), structHash));
    }

    /// the lowest-set-bit shortcut must preserve the specified root semantics for any proof
    function testFuzz_smtShortcutMatchesNaive(bytes32 key, uint256 bitmap, bytes32 seed, bool member) public view {
        bitmap = bitmap & ((uint256(1) << 24) - 1) | (bitmap >> 232 << 232); // keep it to <= 48 siblings
        uint256 n = 0;
        for (uint256 i = 0; i < 256; ++i) if ((bitmap >> i) & 1 == 1) n++;
        bytes32[] memory sib = new bytes32[](n);
        for (uint256 i = 0; i < n; ++i) sib[i] = keccak256(abi.encode(seed, i));
        bytes32 leaf = member ? CredLib.smtLeaf(key) : bytes32(0);
        assertEq(h.smtRoot(key, leaf, bitmap, sib), h.smtRootNaive(key, leaf, bitmap, sib));
    }

    function test_thresholdRejectsUnsortedSigners() public {
        EpochCredRegistry reg = new EpochCredRegistry(false);
        uint256 pkA = 0xA11CE;
        uint256 pkB = 0xB0B;
        address[] memory off = new address[](3);
        off[0] = vm.addr(pkA);
        off[1] = vm.addr(pkB);
        off[2] = vm.addr(0xCA11);
        bytes32 id = keccak256("uni");
        reg.registerIssuer(id, off, 2);
        bytes32 digest = _digest(reg, id);
        (bytes memory first, bytes memory second) =
            off[0] < off[1] ? (_sig(pkA, digest), _sig(pkB, digest)) : (_sig(pkB, digest), _sig(pkA, digest));
        vm.expectRevert(EpochCredRegistry.BadSignatures.selector);
        reg.commitEpoch(id, 1, bytes32(uint256(1)), bytes32(0), 1, bytes.concat(second, first));
        reg.commitEpoch(id, 1, bytes32(uint256(1)), bytes32(0), 1, bytes.concat(first, second));
        (uint64 ep,,,,,,) = reg.issuers(id);
        assertEq(ep, 1);
    }
}
