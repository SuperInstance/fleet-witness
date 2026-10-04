'use strict';
// RFC 6962 Merkle tree hash over leaf payloads (WAL rows).
// Pure, zero-dep. Mirrors fleet five-opcode WAL semantics from the
// witnessing study (memory/study/witnessing-study-2026-10-04.md):
// L0 fnv1a-64 prev-chain is tamper-LOUD but clean suffix truncation
// verifies clean; this L1 layer binds size+root so truncation fails.

const crypto = require('crypto');

function sha256(buf) { return crypto.createHash('sha256').update(buf).digest(); }
function leafHash(data) { return sha256(Buffer.concat([Buffer.from([0x00]), data])); }
function nodeHash(l, r) { return sha256(Buffer.concat([Buffer.from([0x01]), l, r])); }

// split point per RFC 6962 §2.1.1: largest power of two < n (n >= 2)
function split(n) {
  let k = 1 << (31 - Math.clz32(n));
  if (k === n) k >>= 1;
  return k;
}

// MTH({}) = SHA-256("") ; MTH({d}) = SHA-256(0x00 || d) ; else node.
function root(leaves) {
  const n = leaves.length;
  if (n === 0) return sha256(Buffer.alloc(0));
  if (n === 1) return leafHash(Buffer.from(leaves[0]));
  const k = split(n);
  return nodeHash(root(leaves.slice(0, k)), root(leaves.slice(k, n)));
}

// consistency proof: first m leaves against tree of all n leaves
// (RFC 6962 §2.1.2). Returns array of node hashes, in generation order.
function consistencyProof(m, leaves) {
  const n = leaves.length;
  if (m === 0) return [root(leaves)];
  const out = [];
  (function gen(mm, d0) {
    const nn = d0.length;
    if (mm === nn) return;
    const kk = split(nn);
    if (mm <= kk) {
      out.push(root(d0.slice(kk)));
      gen(mm, d0.slice(0, kk));
    } else {
      out.push(root(d0.slice(0, kk)));
      gen(mm - kk, d0.slice(kk));
    }
  })(m, leaves);
  return out;
}

// v0 verification = audit-by-recompute (honest limit, docs/WITNESSING.md):
// the proof is regenerated from the presented leaves and compared; the
// old root is recomputed over the first m presented leaves. A truncated
// ledger either fails the recompute (rows gone) or, if the truncated set
// is presented as-is with an old checkpoint, fails the root compare.
// Streaming (data-free) verification is deferred to extraction #4.
function verifyConsistency(m, oldRoot, leaves, proof) {
  const n = leaves.length;
  if (m < 0 || m > n) return false;
  if (!oldRoot.equals(root(leaves.slice(0, m)))) return false;
  const expected = consistencyProof(m, leaves);
  if (expected.length !== proof.length) return false;
  return expected.every((p, i) => p.equals(proof[i]));
}

module.exports = { sha256, leafHash, nodeHash, split, root, consistencyProof, verifyConsistency };
