'use strict';
// EpochCred protocol: issuer (epoch building + threshold endorsement), holder (selective-disclosure
// presentation bound to a verifier challenge), verifier (pure verification against on-chain digests).
const crypto = require('crypto');
const ethers = require('../vendor/ethers.umd.min.js');
const H = require('./hash');
const { MerkleTree, rootFromProof, rootFromMultiproof } = require('./merkle');
const { SparseMerkleTree, smtRootFromProof } = require('./smt');

const SCHEMA_NAME = 'AcademicDegree-v1';
const SCHEMA_KEYS = [
  'institution', 'studentName', 'studentId', 'dateOfBirth', 'program', 'degree', 'major', 'cgpa',
  'classification', 'admissionYear', 'graduationYear', 'transcriptHash', 'issueDate', 'convocationNo',
  'nationality', 'email',
];
const SCHEMA_ID = H.keccak256(H.toBytes(SCHEMA_NAME));

const { rand32 } = require('./rng');
/** per-attribute salt derived from a single per-credential seed (holder stores 32 bytes, not n salts) */
function deriveSalt(seed, j) {
  const b = new Uint8Array(37);
  b[0] = 0x06;
  b.set(seed, 1);
  new DataView(b.buffer).setUint32(33, j);
  return H.keccak256(b);
}

function attrTree(attrs, seed, keys = SCHEMA_KEYS) {
  const leaves = keys.map((k, j) => H.attrLeaf(deriveSalt(seed, j), k, String(attrs[k] ?? '')));
  return new MerkleTree(leaves);
}

/** keccak(abi.encode(issuanceRoot, revocationRoot, uint64 ts, uint32 count, prevHead)) */
function recordDigest(rec) {
  const b = new Uint8Array(160);
  b.set(H.hexToBytes(rec.issuanceRoot), 0);
  b.set(H.hexToBytes(rec.revocationRoot), 32);
  const dv = new DataView(b.buffer);
  dv.setBigUint64(88, BigInt(rec.timestamp));
  dv.setUint32(124, Number(rec.count));
  b.set(H.hexToBytes(rec.prevHead), 128);
  return H.bytesToHex(H.keccak256(b));
}

function eip712Domain(chainId, verifyingContract) {
  return { name: 'EpochCred', version: '1', chainId, verifyingContract };
}
const EPOCH_TYPES = {
  EpochCommit: [
    { name: 'issuerId', type: 'bytes32' }, { name: 'epoch', type: 'uint64' },
    { name: 'issuanceRoot', type: 'bytes32' }, { name: 'revocationRoot', type: 'bytes32' },
    { name: 'count', type: 'uint32' }, { name: 'prevHead', type: 'bytes32' },
  ],
};
const ROTATE_TYPES = {
  RotateOfficers: [
    { name: 'issuerId', type: 'bytes32' }, { name: 'nonce', type: 'uint64' },
    { name: 'officersHash', type: 'bytes32' }, { name: 'threshold', type: 'uint8' },
  ],
};

/** k signatures from wallets, ordered by ascending signer address, concatenated (65 bytes each) */
function signThreshold(wallets, domain, types, value) {
  const sorted = [...wallets].sort((a, b) => (BigInt(a.address) < BigInt(b.address) ? -1 : 1));
  const sigs = sorted.map((w) => ethers.Signature.from(w.signingKey.sign(ethers.TypedDataEncoder.hash(domain, types, value))).serialized);
  return ethers.concat(sigs);
}

class Issuer {
  constructor({ issuerId, officers, threshold, chainId, registry }) {
    this.issuerId = issuerId;
    this.officers = officers; // ethers.Wallet[]
    this.threshold = threshold;
    this.domain = eip712Domain(chainId, registry);
    this.epoch = 0;
    this.head = ethers.ZeroHash;
    this.revoked = new SparseMerkleTree();
    this.pendingRevocations = [];
  }
  revoke(nullifierBytes) {
    this.pendingRevocations.push(nullifierBytes);
  }
  /**
   * Build the next epoch from credential requests [{attrs, holder, validUntil}] and pending revocations.
   * Returns { commit (on-chain call args), wallets (one per credential, for holders) }.
   */
  buildEpoch(requests, signers = this.officers.slice(0, this.threshold)) {
    const epoch = this.epoch + 1;
    const wallets = [];
    const leaves = requests.map((r) => {
      const seed = rand32();
      const credSecret = rand32();
      const nul = H.nullifier(credSecret);
      const at = attrTree(r.attrs, seed);
      const leaf = H.credLeaf(at.root, r.holder, nul, r.validUntil, SCHEMA_ID);
      wallets.push({ issuerId: this.issuerId, epoch, attrs: r.attrs, seed, credSecret, nullifier: nul, holder: r.holder, validUntil: r.validUntil, schemaId: SCHEMA_ID, leaf });
      return leaf;
    });
    const tree = leaves.length ? new MerkleTree(leaves) : null;
    wallets.forEach((w, i) => { w.leafIndex = i; w.issuancePath = tree.proof(i); });
    if (this.pendingRevocations.length) {
      this.revoked.insertMany(this.pendingRevocations);
      this.pendingRevocations = [];
    }
    const value = {
      issuerId: this.issuerId,
      epoch,
      issuanceRoot: tree ? H.bytesToHex(tree.root) : ethers.ZeroHash,
      revocationRoot: H.bytesToHex(this.revoked.root),
      count: leaves.length,
      prevHead: this.head,
    };
    const sigs = signThreshold(signers, this.domain, EPOCH_TYPES, value);
    return { value, sigs, wallets, tree };
  }
  /** call after the commit is mined, with the block timestamp, to advance the local hash chain */
  confirm(value, timestamp) {
    const rec = { issuanceRoot: value.issuanceRoot, revocationRoot: value.revocationRoot, timestamp, count: value.count, prevHead: value.prevHead };
    this.epoch = value.epoch;
    this.head = recordDigest(rec);
    return rec;
  }
}

// --------------------------------------------------------------------------------- holder
function presentationCoreHash(p) {
  // binds everything the verifier will rely on; ordered, length-prefixed JSON is sufficient here
  const core = JSON.stringify({
    i: p.issuerId, e: p.epoch, d: p.disclosed.map((x) => [x.index, x.key, x.value, H.bytesToHex(x.salt)]),
    h: p.holder, n: H.bytesToHex(p.nullifier), v: String(p.validUntil), s: H.bytesToHex(p.schemaId), li: p.leafIndex,
  });
  return H.keccak256(H.toBytes(core));
}

/**
 * Build a presentation disclosing `keys`, with a non-revocation proof against `revTree`
 * (the issuer's public revocation set at the latest epoch), signed over the verifier's challenge.
 */
function present(wallet, holderWallet, keys, revTree, challenge) {
  const at = attrTree(wallet.attrs, wallet.seed);
  const idx = keys.map((k) => SCHEMA_KEYS.indexOf(k)).sort((a, b) => a - b);
  const disclosed = idx.map((j) => ({ index: j, key: SCHEMA_KEYS[j], value: String(wallet.attrs[SCHEMA_KEYS[j]]), salt: deriveSalt(wallet.seed, j) }));
  const p = {
    issuerId: wallet.issuerId, epoch: wallet.epoch, disclosed, attrProof: at.multiproof(idx), attrHeight: at.height,
    holder: wallet.holder, nullifier: wallet.nullifier, validUntil: wallet.validUntil, schemaId: wallet.schemaId,
    leafIndex: wallet.leafIndex, issuancePath: wallet.issuancePath, nonRevocation: revTree.proof(wallet.nullifier),
  };
  const msg = ethers.concat([presentationCoreHash(p), H.toBytes(challenge)]);
  p.holderSig = holderWallet.signingKey.sign(ethers.hashMessage(msg)).serialized;
  return p;
}

function presentationSize(p) {
  let n = 0;
  for (const d of p.disclosed) n += 1 + H.toBytes(d.key).length + H.toBytes(d.value).length + 32; // index, key, value, salt
  n += 32 * p.attrProof.length + 1;
  n += 32 + 8 + 20 + 32 + 8 + 32 + 4; // issuerId, epoch, holder, nullifier, validUntil, schemaId, leafIndex
  n += 32 * p.issuancePath.length + 1;
  n += 32 + 32 * p.nonRevocation.siblings.length; // bitmap + siblings
  n += 65; // holder signature
  return n;
}

// --------------------------------------------------------------------------------- verifier
/**
 * Pure verification. `chain` supplies what the verifier read from the registry:
 *   { issRec, issDigest, latestRec, head, now, frozen }  (records as emitted in EpochCommitted)
 * Returns {ok, reason}.
 */
function verify(p, chain, challenge, { maxStaleness = 86400 } = {}) {
  if (chain.frozen) return { ok: false, reason: 'issuer frozen by revocation-removal fraud proof' };
  if (recordDigest(chain.issRec) !== chain.issDigest) return { ok: false, reason: 'issuance record mismatch' };
  if (recordDigest(chain.latestRec) !== chain.head) return { ok: false, reason: 'latest record mismatch' };
  if (chain.now > Number(chain.latestRec.timestamp) + maxStaleness) return { ok: false, reason: 'stale revocation root' };
  if (chain.now > Number(p.validUntil)) return { ok: false, reason: 'expired' };
  if (!Number.isInteger(p.leafIndex) || p.leafIndex < 0 || p.leafIndex >= Number(chain.issRec.count)) return { ok: false, reason: 'leaf index outside the committed batch' };
  if (!Array.isArray(p.nonRevocation?.siblings) || typeof p.nonRevocation.bitmap !== 'bigint') return { ok: false, reason: 'malformed non-revocation proof' };
  const leaves = new Map(p.disclosed.map((d) => [d.index, H.attrLeaf(d.salt, d.key, d.value)]));
  for (const d of p.disclosed) if (SCHEMA_KEYS[d.index] !== d.key) return { ok: false, reason: 'schema mismatch' };
  let attrRoot;
  try { attrRoot = rootFromMultiproof(leaves, p.attrHeight, p.attrProof); } catch (e) { return { ok: false, reason: 'bad attribute proof' }; }
  const leaf = H.credLeaf(attrRoot, p.holder, p.nullifier, p.validUntil, p.schemaId);
  let r;
  try { r = rootFromProof(leaf, p.leafIndex, p.issuancePath); } catch (e) { return { ok: false, reason: 'bad issuance proof' }; }
  if (H.bytesToHex(r) !== chain.issRec.issuanceRoot) return { ok: false, reason: 'not issued' };
  let rr;
  try { rr = smtRootFromProof(p.nullifier, H.ZERO, p.nonRevocation); } catch (e) { return { ok: false, reason: 'bad revocation proof' }; }
  if (H.bytesToHex(rr) !== chain.latestRec.revocationRoot) return { ok: false, reason: 'revoked or bad non-revocation proof' };
  const msg = ethers.concat([presentationCoreHash(p), H.toBytes(challenge)]);
  const signer = ethers.recoverAddress(ethers.hashMessage(msg), p.holderSig);
  if (signer.toLowerCase() !== p.holder.toLowerCase()) return { ok: false, reason: 'holder binding failed' };
  return { ok: true, reason: 'valid' };
}

module.exports = {
  SCHEMA_KEYS, SCHEMA_ID, SCHEMA_NAME, Issuer, present, verify, presentationSize, recordDigest,
  attrTree, deriveSalt, signThreshold, eip712Domain, EPOCH_TYPES, ROTATE_TYPES, rand32,
};
