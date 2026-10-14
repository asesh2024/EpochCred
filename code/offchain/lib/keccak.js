'use strict';
// Dependency-free Keccak-256 (the Ethereum variant, padding 0x01) on Uint8Array.
// ~5x faster than the generic hex-string API for the 33..161-byte inputs used here.
// Cross-checked against ethers.keccak256 in offchain/test/selftest.js.

const RC = [
  [0x00000000, 0x00000001], [0x00000000, 0x00008082], [0x80000000, 0x0000808a], [0x80000000, 0x80008000],
  [0x00000000, 0x0000808b], [0x00000000, 0x80000001], [0x80000000, 0x80008081], [0x80000000, 0x00008009],
  [0x00000000, 0x0000008a], [0x00000000, 0x00000088], [0x00000000, 0x80008009], [0x00000000, 0x8000000a],
  [0x00000000, 0x8000808b], [0x80000000, 0x0000008b], [0x80000000, 0x00008089], [0x80000000, 0x00008003],
  [0x80000000, 0x00008002], [0x80000000, 0x00000080], [0x00000000, 0x0000800a], [0x80000000, 0x8000000a],
  [0x80000000, 0x80008081], [0x80000000, 0x00008080], [0x00000000, 0x80000001], [0x80000000, 0x80008008],
];
const RHO = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]];
// precompute (source lane, dest lane, rotation)
const PI_SRC = new Int32Array(25), PI_DST = new Int32Array(25), PI_ROT = new Int32Array(25);
{ let i = 0; for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) { PI_SRC[i] = 2 * (x + 5 * y); PI_DST[i] = 2 * (y + 5 * ((2 * x + 3 * y) % 5)); PI_ROT[i] = RHO[x][y]; i++; } }
const RC_HI = new Uint32Array(RC.map((r) => r[0])), RC_LO = new Uint32Array(RC.map((r) => r[1]));

const s = new Uint32Array(50); // lane i: lo = s[2i], hi = s[2i+1]
const B = new Uint32Array(50);
const C = new Uint32Array(10);

function keccakF() {
  for (let round = 0; round < 24; round++) {
    for (let x = 0; x < 5; x++) {
      C[2 * x] = s[2 * x] ^ s[2 * x + 10] ^ s[2 * x + 20] ^ s[2 * x + 30] ^ s[2 * x + 40];
      C[2 * x + 1] = s[2 * x + 1] ^ s[2 * x + 11] ^ s[2 * x + 21] ^ s[2 * x + 31] ^ s[2 * x + 41];
    }
    for (let x = 0; x < 5; x++) {
      const p = (x + 4) % 5, q = (x + 1) % 5;
      const qlo = C[2 * q], qhi = C[2 * q + 1];
      const dlo = C[2 * p] ^ ((qlo << 1) | (qhi >>> 31));
      const dhi = C[2 * p + 1] ^ ((qhi << 1) | (qlo >>> 31));
      for (let y = 0; y < 25; y += 5) { s[2 * (x + y)] ^= dlo; s[2 * (x + y) + 1] ^= dhi; }
    }
    for (let i = 0; i < 25; i++) {
      const src = PI_SRC[i], dst = PI_DST[i], n = PI_ROT[i];
      const lo = s[src], hi = s[src + 1];
      if (n === 0) { B[dst] = lo; B[dst + 1] = hi; }
      else if (n < 32) { B[dst] = (lo << n) | (hi >>> (32 - n)); B[dst + 1] = (hi << n) | (lo >>> (32 - n)); }
      else if (n === 32) { B[dst] = hi; B[dst + 1] = lo; }
      else { const m = n - 32; B[dst] = (hi << m) | (lo >>> (32 - m)); B[dst + 1] = (lo << m) | (hi >>> (32 - m)); }
    }
    for (let y = 0; y < 50; y += 10) {
      const b0 = B[y], b1 = B[y + 1], b2 = B[y + 2], b3 = B[y + 3], b4 = B[y + 4], b5 = B[y + 5],
        b6 = B[y + 6], b7 = B[y + 7], b8 = B[y + 8], b9 = B[y + 9];
      s[y] = b0 ^ (~b2 & b4); s[y + 1] = b1 ^ (~b3 & b5);
      s[y + 2] = b2 ^ (~b4 & b6); s[y + 3] = b3 ^ (~b5 & b7);
      s[y + 4] = b4 ^ (~b6 & b8); s[y + 5] = b5 ^ (~b7 & b9);
      s[y + 6] = b6 ^ (~b8 & b0); s[y + 7] = b7 ^ (~b9 & b1);
      s[y + 8] = b8 ^ (~b0 & b2); s[y + 9] = b9 ^ (~b1 & b3);
    }
    s[0] ^= RC_LO[round];
    s[1] ^= RC_HI[round];
  }
}

const RATE = 136;
const block = new Uint8Array(RATE);

function absorb(blk) {
  for (let i = 0; i < RATE / 8; i++) {
    const o = 8 * i;
    s[2 * i] ^= blk[o] | (blk[o + 1] << 8) | (blk[o + 2] << 16) | (blk[o + 3] << 24);
    s[2 * i + 1] ^= blk[o + 4] | (blk[o + 5] << 8) | (blk[o + 6] << 16) | (blk[o + 7] << 24);
  }
  keccakF();
}

/** keccak256(data: Uint8Array) -> Uint8Array(32) */
function keccak256(data) {
  s.fill(0);
  let off = 0;
  while (data.length - off >= RATE) { absorb(data.subarray(off, off + RATE)); off += RATE; }
  block.fill(0);
  block.set(data.subarray(off));
  block[data.length - off] ^= 0x01;
  block[RATE - 1] ^= 0x80;
  absorb(block);
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) {
    const lo = s[2 * i], hi = s[2 * i + 1];
    out[8 * i] = lo; out[8 * i + 1] = lo >>> 8; out[8 * i + 2] = lo >>> 16; out[8 * i + 3] = lo >>> 24;
    out[8 * i + 4] = hi; out[8 * i + 5] = hi >>> 8; out[8 * i + 6] = hi >>> 16; out[8 * i + 7] = hi >>> 24;
  }
  return out;
}

module.exports = { keccak256 };
