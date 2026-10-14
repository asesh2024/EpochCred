'use strict';
// Adversarial test-suite (security evaluation, Section 6). Requires a running anvil node.
const fs = require('fs');
const path = require('path');
const { ethers, provider, devWallet, deploy, randomWallet } = require('../offchain/lib/chain');
const C = require('../offchain/lib/credential');
const H = require('../offchain/lib/hash');
const { makeRecords } = require('../offchain/lib/data');
const { setupRegistry, commitEpoch, chainView } = require('../offchain/lib/setup');

const results = [];
function record(id, name, threat, expected, observed) {
  const pass = expected === observed;
  results.push({ id, name, threat, expected, observed, pass });
  console.log(`${pass ? 'PASS' : 'FAIL'} ${id} ${name}: expected=${expected} observed=${observed}`);
}
async function reverts(p) {
  try { const tx = await p; await tx.wait(); return 'accepted'; } catch (e) { return 'reverted'; }
}
const deepCopy = (p) => ({ ...p, disclosed: p.disclosed.map((d) => ({ ...d })), issuancePath: [...p.issuancePath], attrProof: [...p.attrProof] });

function onchainArgs(fx, p, issRec, latestRec, discIdx = 0) {
  const at = C.attrTree(p._wallet.attrs, p._wallet.seed);
  const d = p.disclosed[discIdx];
  return [
    fx.issuer.issuerId, p.epoch, issRec, latestRec,
    { key: ethers.toUtf8Bytes(d.key), value: ethers.toUtf8Bytes(d.value), salt: H.bytesToHex(d.salt), attrIndex: d.index, attrPath: at.proof(d.index).map(H.bytesToHex) },
    { holder: p.holder, nullifier: H.bytesToHex(p.nullifier), validUntil: p.validUntil, schemaId: H.bytesToHex(p.schemaId), leafIndex: p.leafIndex, issuancePath: p.issuancePath.map(H.bytesToHex) },
    { bitmap: p.nonRevocation.bitmap, siblings: p.nonRevocation.siblings.map(H.bytesToHex) },
    86400,
  ];
}

(async () => {
  const prov = provider();
  const fx = await setupRegistry({ n: 5, k: 3, prov });
  const recs = {};
  const holders = Array.from({ length: 16 }, () => randomWallet());
  const now = (await prov.getBlock('latest')).timestamp;
  const reqs = makeRecords(16, 7).map((attrs, i) => ({ attrs, holder: holders[i].address, validUntil: now + 10 * 365 * 86400 }));
  const e1 = await commitEpoch(fx, reqs);
  recs[1] = e1.rec;
  const w = e1.wallets[3];
  const challenge = 'verifier:acme-corp|nonce:' + ethers.hexlify(ethers.randomBytes(16));
  const p = C.present(w, holders[3], ['degree', 'major', 'graduationYear'], fx.issuer.revoked, challenge);
  p._wallet = w;
  let cv = await chainView(fx, 1, recs);

  record('T1', 'Valid presentation (off-chain)', 'correctness', 'accept', C.verify(p, cv, challenge).ok ? 'accept' : 'reject');
  const onOk = await fx.reg.verifyAttribute(...onchainArgs(fx, p, recs[1], recs[1]));
  record('T2', 'Valid presentation (on-chain verifyAttribute)', 'correctness', 'accept', onOk ? 'accept' : 'reject');

  const t = deepCopy(p); t.disclosed[0].value = 'Ph.D';
  record('T3', 'Tampered disclosed attribute value', 'credential alteration', 'reject', C.verify(t, cv, challenge).ok ? 'accept' : 'reject');

  const t2 = deepCopy(p); t2.disclosed[0].key = 'major'; // claim degree value under another schema key
  record('T4', 'Attribute re-labelled under another schema key', 'semantic confusion', 'reject', C.verify(t2, cv, challenge).ok ? 'accept' : 'reject');

  // forged credential: adversary fabricates a credential for itself and reuses a valid path
  const mallory = randomWallet();
  const fakeW = { ...w, holder: mallory.address, attrs: { ...w.attrs, cgpa: '9.99' } };
  const f = C.present(fakeW, mallory, ['cgpa'], fx.issuer.revoked, challenge);
  record('T5', 'Fabricated credential with borrowed Merkle path', 'forgery', 'reject', C.verify(f, cv, challenge).ok ? 'accept' : 'reject');

  const t3 = deepCopy(p); t3.leafIndex = 4;
  record('T6', 'Leaf-index substitution', 'proof manipulation', 'reject', C.verify(t3, cv, challenge).ok ? 'accept' : 'reject');

  record('T7', 'Replay of presentation to another verifier/nonce', 'replay', 'reject', C.verify(p, cv, challenge + 'x').ok ? 'accept' : 'reject');

  const t4 = deepCopy(p); t4.holderSig = mallory.signingKey.sign(ethers.hashMessage(ethers.concat([ethers.ZeroHash]))).serialized;
  record('T8', 'Presentation re-signed with a key other than the holder key', 'holder-key binding', 'reject', C.verify(t4, cv, challenge).ok ? 'accept' : 'reject');

  const { _wallet, ...pubP } = p;
  const serialized = JSON.stringify(pubP, (k, v) => (typeof v === 'bigint' ? v.toString() : v instanceof Uint8Array ? H.bytesToHex(v) : v));
  const leaked = ['studentName', 'dateOfBirth', 'cgpa', 'email', 'studentId'].filter((k) => serialized.includes(String(w.attrs[k])));
  record('T9', 'Undisclosed attributes absent from presentation', 'over-disclosure', 'none-leaked', leaked.length ? 'leaked:' + leaked.join(',') : 'none-leaked');

  // ---- threshold / governance attacks
  const v2 = { issuerId: fx.issuer.issuerId, epoch: 2, issuanceRoot: ethers.id('evil'), revocationRoot: H.bytesToHex(fx.issuer.revoked.root), count: 1, prevHead: fx.issuer.head };
  const sigK1 = C.signThreshold(fx.officers.slice(0, 2), fx.issuer.domain, C.EPOCH_TYPES, v2);
  record('T10', 'Commit with k-1 compromised officers', 'insider forgery', 'reverted', await reverts(fx.regRelayer.commitEpoch(v2.issuerId, 2, v2.issuanceRoot, v2.revocationRoot, 1, sigK1)));
  const one = C.signThreshold([fx.officers[0]], fx.issuer.domain, C.EPOCH_TYPES, v2);
  record('T11', 'Same officer signature repeated k times', 'threshold bypass', 'reverted', await reverts(fx.regRelayer.commitEpoch(v2.issuerId, 2, v2.issuanceRoot, v2.revocationRoot, 1, ethers.concat([one, one, one]))));
  const outsiders = Array.from({ length: 3 }, () => randomWallet());
  record('T12', 'Signatures by non-officers', 'unauthorised issuer', 'reverted', await reverts(fx.regRelayer.commitEpoch(v2.issuerId, 2, v2.issuanceRoot, v2.revocationRoot, 1, C.signThreshold(outsiders, fx.issuer.domain, C.EPOCH_TYPES, v2))));
  const vOld = { ...v2, epoch: 1 };
  record('T13', 'Re-commit / rewrite an already committed epoch', 'history rewriting', 'reverted', await reverts(fx.regRelayer.commitEpoch(v2.issuerId, 1, v2.issuanceRoot, v2.revocationRoot, 1, C.signThreshold(fx.officers.slice(0, 3), fx.issuer.domain, C.EPOCH_TYPES, vOld))));
  const vSkip = { ...v2, epoch: 3 };
  record('T14', 'Skip epoch number (gap)', 'log forking', 'reverted', await reverts(fx.regRelayer.commitEpoch(v2.issuerId, 3, v2.issuanceRoot, v2.revocationRoot, 1, C.signThreshold(fx.officers.slice(0, 3), fx.issuer.domain, C.EPOCH_TYPES, vSkip))));
  const vBadPrev = { ...v2, prevHead: ethers.id('fork') };
  record('T15', 'Valid k signatures over wrong prevHead (fork)', 'equivocation', 'reverted', await reverts(fx.regRelayer.commitEpoch(v2.issuerId, 2, v2.issuanceRoot, v2.revocationRoot, 1, C.signThreshold(fx.officers.slice(0, 3), fx.issuer.domain, C.EPOCH_TYPES, vBadPrev))));
  // cross-registry replay
  const fx2 = await setupRegistry({ n: 5, k: 3, prov });
  const { contract: reg2 } = { contract: fx2.regRelayer };
  const goodSigs = C.signThreshold(fx.officers.slice(0, 3), fx.issuer.domain, C.EPOCH_TYPES, v2);
  record('T16', 'Replay endorsement on another registry deployment', 'cross-domain replay', 'reverted', await reverts(reg2.commitEpoch(v2.issuerId, 2, v2.issuanceRoot, v2.revocationRoot, 1, goodSigs)));
  // high-s malleability
  const sigs = ethers.getBytes(goodSigs);
  const N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
  const mall = new Uint8Array(sigs);
  const s0 = BigInt(ethers.hexlify(mall.slice(32, 64)));
  mall.set(ethers.getBytes(ethers.toBeHex(N - s0, 32)), 32);
  mall[64] = mall[64] === 27 ? 28 : 27;
  record('T17', 'Malleated (high-s) officer signature', 'signature malleability', 'reverted', await reverts(fx.regRelayer.commitEpoch(v2.issuerId, 2, v2.issuanceRoot, v2.revocationRoot, 1, mall)));

  // ---- revocation
  fx.issuer.revoke(w.nullifier);
  const e2 = await commitEpoch(fx, []); // revocation-only epoch
  recs[2] = e2.rec;
  cv = await chainView(fx, 1, recs);
  const pr = C.present(w, holders[3], ['degree'], fx.issuer.revoked, challenge);
  record('T18', 'Revoked credential (off-chain)', 'use after revocation', 'reject', C.verify(pr, cv, challenge).ok ? 'accept' : 'reject');
  pr._wallet = w;
  const onRev = await fx.reg.verifyAttribute(...onchainArgs(fx, pr, recs[1], recs[2]));
  record('T19', 'Revoked credential (on-chain)', 'use after revocation', 'reject', onRev ? 'accept' : 'reject');
  // old proof against old revocation root, presented after the revocation epoch
  record('T20', 'Pre-revocation proof replayed after revocation', 'stale-proof replay', 'reject', C.verify(p, cv, challenge).ok ? 'accept' : 'reject');
  const w5 = e1.wallets[5];
  const p5 = C.present(w5, holders[5], ['degree'], fx.issuer.revoked, challenge);
  record('T21', 'Non-revoked sibling credential still valid', 'revocation collateral damage', 'accept', C.verify(p5, cv, challenge).ok ? 'accept' : 'reject');

  // ---- freshness: advance time beyond Delta with no new epoch
  // advance the clock by 2 days (evm_setNextBlockTimestamp also works when the node runs with a fixed block interval)
  const tNow = (await prov.getBlock('latest')).timestamp;
  await prov.send('evm_setNextBlockTimestamp', [tNow + 2 * 86400]);
  await prov.send('evm_mine', []);
  cv = await chainView(fx, 1, recs);
  record('T22', 'Revocation root older than staleness bound', 'freshness / withheld update', 'reject', C.verify(p5, cv, challenge, { maxStaleness: 86400 }).ok ? 'accept' : 'reject');

  // ---- expiry
  const cvFuture = { ...cv, now: w5.validUntil + 1 };
  record('T23', 'Expired credential', 'expiry', 'reject', C.verify(p5, cvFuture, challenge, { maxStaleness: 1e12 }).ok ? 'accept' : 'reject');

  // ---- key rotation
  const newOff = Array.from({ length: 4 }, () => randomWallet());
  const rotVal = { issuerId: fx.issuer.issuerId, nonce: 0, officersHash: ethers.keccak256(ethers.concat(newOff.map((o) => ethers.zeroPadValue(o.address, 32)))) /* abi.encodePacked(address[]) pads elements */, threshold: 2 };
  const rotSigs = C.signThreshold(fx.officers.slice(1, 4), fx.issuer.domain, C.ROTATE_TYPES, rotVal);
  record('T24', 'Officer-set rotation by k current officers', 'key compromise recovery', 'accepted', await reverts(fx.regRelayer.rotateOfficers(fx.issuer.issuerId, newOff.map((o) => o.address), 2, rotSigs)));
  const v3 = { issuerId: fx.issuer.issuerId, epoch: 3, issuanceRoot: ethers.id('x'), revocationRoot: H.bytesToHex(fx.issuer.revoked.root), count: 1, prevHead: fx.issuer.head };
  record('T25', 'Old (rotated-out) officers attempt commit', 'post-rotation misuse', 'reverted', await reverts(fx.regRelayer.commitEpoch(v3.issuerId, 3, v3.issuanceRoot, v3.revocationRoot, 1, C.signThreshold(fx.officers.slice(0, 3), fx.issuer.domain, C.EPOCH_TYPES, v3))));
  record('T26', 'New officers commit after rotation', 'liveness after rotation', 'accepted', await reverts(fx.regRelayer.commitEpoch(v3.issuerId, 3, v3.issuanceRoot, v3.revocationRoot, 1, C.signThreshold(newOff.slice(0, 2), fx.issuer.domain, C.EPOCH_TYPES, v3))));

  const accreditorOnly = await reverts(fx.regRelayer.registerIssuer(ethers.id('rogue'), [mallory.address], 1));
  record('T27', 'Non-accreditor registers a rogue issuer', 'unaccredited issuer', 'reverted', accreditorOnly);

  // ---- enforceable append-only revocation (fraud proof) -------------------------------------------
  const fz = await setupRegistry({ n: 5, k: 3, prov });
  const fzRecs = {};
  const fzNow = (await prov.getBlock('latest')).timestamp;
  const fzReq = makeRecords(4, 9).map((attrs, i) => ({ attrs, holder: holders[i].address, validUntil: fzNow + 3e8 }));
  const f1 = await commitEpoch(fz, fzReq);
  fzRecs[1] = f1.rec;
  const victimW = f1.wallets[0];
  fz.issuer.revoke(victimW.nullifier);
  fz.issuer.revoke(C.rand32());
  const f2 = await commitEpoch(fz, []);
  fzRecs[2] = f2.rec;
  const memberP = fz.issuer.revoked.proof(victimW.nullifier);
  const encP = (pp) => ({ bitmap: pp.bitmap, siblings: pp.siblings.map(H.bytesToHex) });
  // bogus challenge first: a nullifier that was never revoked cannot produce a membership proof
  const never = f1.wallets[1].nullifier;
  record('T28', 'Fraud proof with a never-revoked nullifier', 'false accusation / griefing', 'reverted',
    await reverts(fz.regRelayer.challengeRevocationRemoval(fz.issuer.issuerId, 1, fzRecs[1], 2, fzRecs[2], H.bytesToHex(never), encP(fz.issuer.revoked.proof(never)), encP(fz.issuer.revoked.proof(never)))));
  // a k-officer coalition (or a buggy tool) drops the victim's nullifier in epoch 3
  const { SparseMerkleTree } = require('../offchain/lib/smt');
  fz.issuer.revoked = new SparseMerkleTree([...fz.issuer.revoked.keySet.keys()].filter((k) => k !== H.bytesToHex(victimW.nullifier)).map(H.hexToBytes));
  const f3 = await commitEpoch(fz, []);
  fzRecs[3] = f3.rec;
  const cvFz = await chainView(fz, 1, fzRecs);
  const pVictim = C.present(victimW, holders[0], ['degree'], fz.issuer.revoked, challenge);
  record('T29', 'Revoked credential re-validated by dropping its nullifier (before challenge)', 'revocation rollback', 'accept',
    C.verify(pVictim, cvFz, challenge).ok ? 'accept' : 'reject');
  const absentP = fz.issuer.revoked.proof(victimW.nullifier);
  record('T30', 'Anyone submits fraud proof (member in epoch 2, absent in epoch 3)', 'revocation rollback', 'accepted',
    await reverts(fz.regRelayer.challengeRevocationRemoval(fz.issuer.issuerId, 2, fzRecs[2], 3, fzRecs[3], H.bytesToHex(victimW.nullifier), encP(memberP), encP(absentP))));
  pVictim._wallet = victimW;
  const onFrozen = await fz.reg.verifyAttribute(...onchainArgs(fz, pVictim, fzRecs[1], fzRecs[3]));
  const offFrozen = C.verify(pVictim, await chainView(fz, 1, fzRecs), challenge).ok;
  record('T31', 'Verification (on- and off-chain) after issuer is frozen', 'revocation rollback', 'reject', onFrozen || offFrozen ? 'accept' : 'reject');
  const vF = { issuerId: fz.issuer.issuerId, epoch: 4, issuanceRoot: ethers.ZeroHash, revocationRoot: H.bytesToHex(fz.issuer.revoked.root), count: 0, prevHead: fz.issuer.head };
  record('T32', 'Frozen issuer attempts a further commit', 'continued operation after fraud', 'reverted',
    await reverts(fz.regRelayer.commitEpoch(vF.issuerId, 4, vF.issuanceRoot, vF.revocationRoot, 0, C.signThreshold(fz.officers.slice(0, 3), fz.issuer.domain, C.EPOCH_TYPES, vF))));


  // ---- withholding taxonomy -------------------------------------------------------------------------
  const fw = await setupRegistry({ n: 5, k: 3, prov });
  const fwRecs = {};
  const fwNow = (await prov.getBlock('latest')).timestamp;
  const w1 = await commitEpoch(fw, makeRecords(4, 10).map((attrs, i) => ({ attrs, holder: holders[i].address, validUntil: fwNow + 3e8 })));
  fwRecs[1] = w1.rec;
  const cached = C.present(w1.wallets[2], holders[2], ['degree'], fw.issuer.revoked, challenge); // proof cached by holder
  const w2 = await commitEpoch(fw, []); // fresh epoch, unchanged revocation root
  fwRecs[2] = w2.rec;
  record('T33', 'Cached proof after a fresh epoch with unchanged revocation root', 'documented behaviour (no new revocations)', 'accept',
    C.verify(cached, await chainView(fw, 1, fwRecs), challenge).ok ? 'accept' : 'reject');
  fw.issuer.revoke(C.rand32()); // some other credential revoked; issuer withholds the new list
  const w3 = await commitEpoch(fw, []);
  fwRecs[3] = w3.rec;
  record('T34', 'Cached proof after root changed while issuer withholds the new list', 'witness withholding', 'reject',
    C.verify(cached, await chainView(fw, 1, fwRecs), challenge).ok ? 'accept' : 'reject');

  // ---- restoration after a freeze (accreditor governance) --------------------------------------------
  const notAcc = fz.reg.connect(fz.relayer);
  record('T35', 'Non-accreditor attempts to restore a frozen issuer', 'governance bypass', 'reverted', await reverts(notAcc.restoreIssuer(fz.issuer.issuerId)));
  record('T36', 'Accreditor restores the frozen issuer', 'recovery liveness', 'accepted', await reverts(fz.reg.restoreIssuer(fz.issuer.issuerId)));
  record('T37', 'Replay of the already-adjudicated fraud proof after restoration', 'griefing by historical evidence', 'reverted',
    await reverts(fz.regRelayer.challengeRevocationRemoval(fz.issuer.issuerId, 2, fzRecs[2], 3, fzRecs[3], H.bytesToHex(victimW.nullifier), encP(memberP), encP(absentP))));
  const f4 = await commitEpoch(fz, []); // issuer still omits the victim's nullifier after restoration
  fzRecs[4] = f4.rec;
  record('T38', 'Post-restoration epoch that still omits a committed nullifier is challengeable', 'repeated rollback', 'accepted',
    await reverts(fz.regRelayer.challengeRevocationRemoval(fz.issuer.issuerId, 2, fzRecs[2], 4, fzRecs[4], H.bytesToHex(victimW.nullifier), encP(memberP), encP(fz.issuer.revoked.proof(victimW.nullifier)))));

  // ---- governance edge cases --------------------------------------------------------------------------
  const ga = await setupRegistry({ n: 5, k: 3, prov });
  const gb = await setupRegistry({ n: 5, k: 3, prov });
  const vX = { issuerId: gb.issuer.issuerId, epoch: 1, issuanceRoot: ethers.id('x'), revocationRoot: ethers.ZeroHash, count: 1, prevHead: ethers.ZeroHash };
  record('T39', "Issuer A's officers endorse an epoch of issuer B", 'cross-issuer authority', 'reverted',
    await reverts(gb.regRelayer.commitEpoch(vX.issuerId, 1, vX.issuanceRoot, vX.revocationRoot, 1, C.signThreshold(ga.officers.slice(0, 3), gb.issuer.domain, C.EPOCH_TYPES, vX))));
  const rotSig = (fxx, list, k, nonce) => C.signThreshold(fxx.officers.slice(0, fxx.issuer.threshold), fxx.issuer.domain, C.ROTATE_TYPES,
    { issuerId: fxx.issuer.issuerId, nonce, officersHash: ethers.keccak256(ethers.concat(list.map((a) => ethers.zeroPadValue(a, 32)))), threshold: k });
  const nA = randomWallet().address, nB = randomWallet().address;
  record('T40', 'Rotation to a set containing a duplicate address', 'quorum inflation', 'reverted',
    await reverts(ga.regRelayer.rotateOfficers(ga.issuer.issuerId, [nA, nA, nB], 2, rotSig(ga, [nA, nA, nB], 2, 0))));
  record('T41', 'Rotation with quorum k > n', 'unusable officer set', 'reverted',
    await reverts(ga.regRelayer.rotateOfficers(ga.issuer.issuerId, [nA, nB], 3, rotSig(ga, [nA, nB], 3, 0))));
  record('T42', 'Rotation with quorum k = 0', 'quorum removal', 'reverted',
    await reverts(ga.regRelayer.rotateOfficers(ga.issuer.issuerId, [nA, nB], 0, rotSig(ga, [nA, nB], 0, 0))));
  const goodRot = rotSig(ga, [nA, nB], 2, 0);
  await (await ga.regRelayer.rotateOfficers(ga.issuer.issuerId, [nA, nB], 2, goodRot)).wait();
  record('T43', 'Replay of a consumed rotation authorisation (same nonce)', 'stale authorisation replay', 'reverted',
    await reverts(ga.regRelayer.rotateOfficers(ga.issuer.issuerId, [nA, nB], 2, goodRot)));

  // ---- malformed proofs and batch bounds ----------------------------------------------------------------
  const pW = C.present(w1.wallets[1], holders[1], ['degree', 'major'], fw.issuer.revoked, challenge);
  const pm = deepCopy(pW); pm.attrProof = [...pW.attrProof, pW.attrProof[0]];
  cv = await chainView(fw, 1, fwRecs);
  record('T44', 'Attribute multiproof with an extra sibling', 'malformed proof', 'reject', C.verify(pm, cv, challenge, { maxStaleness: 1e12 }).ok ? 'accept' : 'reject');
  record('T45', 'Well-formed presentation in the same setting (control)', 'correctness', 'accept', C.verify(pW, cv, challenge, { maxStaleness: 1e12 }).ok ? 'accept' : 'reject');
  const pn = deepCopy(pW); pn.nonRevocation = { bitmap: pW.nonRevocation.bitmap, siblings: [...pW.nonRevocation.siblings, ethers.getBytes(ethers.id('junk'))] };
  record('T46', 'Non-revocation proof whose sibling list does not match its bitmap', 'malformed proof', 'reject', C.verify(pn, cv, challenge, { maxStaleness: 1e12 }).ok ? 'accept' : 'reject');
  const pb = deepCopy(pW); pb.leafIndex = Number(fwRecs[1].count);
  record('T47', 'Leaf index pointing into the zero padding of the batch', 'batch-length confusion', 'reject', C.verify(pb, cv, challenge, { maxStaleness: 1e12 }).ok ? 'accept' : 'reject');

  // ---- delayed submission of endorsed epochs ---------------------------------------------------------------
  const fd = await setupRegistry({ n: 5, k: 3, prov });
  const late = fd.issuer.buildEpoch(makeRecords(2, 12).map((attrs, i) => ({ attrs, holder: holders[i].address, validUntil: fzNow + 3e8 })));
  const tL = (await prov.getBlock('latest')).timestamp;
  await prov.send('evm_setNextBlockTimestamp', [tL + 7 * 86400]); await prov.send('evm_mine', []);
  record('T48', 'Endorsed epoch relayed one week late (still the successor)', 'documented behaviour: endorsements do not expire', 'accepted',
    await reverts(fd.regRelayer.commitEpoch(late.value.issuerId, 1, late.value.issuanceRoot, late.value.revocationRoot, late.value.count, late.sigs)));
  fd.issuer.confirm(late.value, (await prov.getBlock('latest')).timestamp);
  const alt = { ...late.value, issuanceRoot: ethers.id('alt') }; // a competing endorsement for the same epoch number
  record('T49', 'Competing endorsement for an epoch number already taken', 'stale endorsement replay', 'reverted',
    await reverts(fd.regRelayer.commitEpoch(alt.issuerId, 1, alt.issuanceRoot, alt.revocationRoot, alt.count, C.signThreshold(fd.officers.slice(0, 3), fd.issuer.domain, C.EPOCH_TYPES, alt))));


  const VALID = new Set(['T1', 'T2', 'T21', 'T24', 'T26', 'T29', 'T33', 'T36', 'T45', 'T48']);
  for (const r of results) r.kind = VALID.has(r.id) ? 'correctness / documented behaviour' : 'attack';
  const out = path.join(__dirname, '..', 'results', 'security_tests.json');
  fs.writeFileSync(out, JSON.stringify(results, null, 2));
  const nPass = results.filter((r) => r.pass).length;
  console.log(`\n${nPass}/${results.length} security tests passed -> ${out}`);
  process.exit(nPass === results.length ? 0 : 1);
})().catch((e) => { console.error(e); process.exit(2); });
