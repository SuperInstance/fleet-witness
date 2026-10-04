'use strict';
// L3 witness quorum — CLIENT-SIDE check (policy + cosig verification + quorum).
// Built per docs/L3-QUORUM.md; witness service daemons are still gated (the
// design's build gate: extraction #4 + two always-on hosts). This module is
// the mechanism half only — per the Nous-lang v5.67 erratum adopted in the
// design doc, nothing here claims a witness network until a real external
// cosig exists on disk. Persist-before-cosign atomicity lives in the witness
// service; the client-side mirror is that quorum() re-seals the caller's OWN
// ledger rows and refuses any quorum that does not attest that local seal.
//
// Cosig note format: the documented signer seam in src/checkpoint.js v0.1
// (note body + "sig:<base64>\n"); the witness NAME travels out of band in the
// {name, signedNote} pair (the design doc's "— name sig" sketch is superseded
// by the already-pinned seam; the name is bound to the key by the policy, and
// body bytes bind the cosig to the checkpoint). Conflict semantics per C2SP
// tlog-witness v1.0.0, classes named not wire-claimed (RFC 9162 lesson):
//   conflict  — valid cosigs disagree on root at same size (their 409 class)
//   malformed — unparsable note or size disagreement (their 422 class)
//   unrecognized-key — a verified cosig from a key not in the policy is
//     refused outright (fail-closed per design), not merely uncounted.

const cp = require('./checkpoint.js');

// Strict-majority bound (transparency.dev 2026, no monitors): split-view
// resistance against m malicious witnesses needs t >= ceil((n+m+1)/2).
// requiredCosigners(n, 0) is the floor ANY policy must meet; m > 0 raises it.
function requiredCosigners(n, m) {
  return Math.ceil((n + m + 1) / 2);
}

// Policy file: C2SP tlog-policy shape, client-side, named per deployment
// (Sigsum convention). Shape per docs/L3-QUORUM.md:
//   { name, origin, log: { ed25519: <PEM> }, witnesses: [{ name, ed25519: <PEM> }],
//     quorum: { kind: 'k-of-n', k, n } }
// The policy's k is CHECKED against the strict-majority floor, not trusted.
function loadPolicy(obj) {
  if (!obj || typeof obj !== 'object') throw new Error('policy: not an object');
  if (typeof obj.name !== 'string' || obj.name.length === 0) throw new Error('policy: name required');
  if (obj.origin !== cp.ORIGIN) throw new Error('policy: origin mismatch: ' + obj.origin);
  if (obj.log && !obj.log.ed25519) throw new Error('policy: log key required when log present');
  const witnesses = obj.witnesses;
  if (!Array.isArray(witnesses) || witnesses.length === 0) throw new Error('policy: witnesses required');
  const names = new Set(witnesses.map((w) => w && w.name));
  if (names.size !== witnesses.length) throw new Error('policy: duplicate witness name');
  for (const w of witnesses) {
    if (!w.name || typeof w.name !== 'string') throw new Error('policy: witness name required');
    if (!w.ed25519 || !w.ed25519.includes('PUBLIC KEY')) throw new Error('policy: witness ' + w.name + ' ed25519 PEM required');
  }
  const q = obj.quorum || {};
  if (q.kind !== 'k-of-n') throw new Error('policy: quorum.kind must be k-of-n: ' + q.kind);
  const n = witnesses.length;
  if (!Number.isSafeInteger(q.n) || q.n !== n) throw new Error(`policy: quorum.n ${q.n} != witness count ${n}`);
  if (!Number.isSafeInteger(q.k) || q.k < 1 || q.k > n) throw new Error('policy: bad k: ' + q.k);
  const floor = requiredCosigners(n, 0);
  if (q.k < floor) throw new Error(`policy: k=${q.k} below strict-majority floor ${floor} for n=${n}`);
  return {
    name: obj.name, origin: obj.origin,
    logPubPem: obj.log ? obj.log.ed25519 : null,
    witnesses: witnesses.map((w) => ({ name: w.name, pubPem: w.ed25519 })),
    n, k: q.k,
  };
}

// Client-side quorum check.
//   rows        — the caller's OWN ledger rows (persist-before-cosign mirror:
//                 the local re-seal is the checkpoint the quorum must attest)
//   operatorNote— checkpoint.sign(size, root, operatorKey) output, or the raw
//                 unsigned note (refused unless the policy names no log key)
//   cosigs      — [{ name, signedNote }] from the witness hosts, out of band
//   policy      — loaded policy (or raw object; loaded if needed)
// Verdict object, never throws on cosig content (named refusal, fail-closed).
function quorum(rows, operatorNote, cosigs, policy) {
  const p = policy.witnesses ? policy : loadPolicy(policy);
  let local;
  try { local = cp.seal(rows); } catch (e) { return { ok: false, reason: 'seal-failed', detail: e.message }; }

  // operator note must parse and attest the caller's local seal
  let op;
  try { op = cp.parse(operatorNote); } catch (e) { return { ok: false, reason: 'malformed', detail: 'operator note: ' + e.message }; }
  if (op.size !== local.size || !op.root.equals(local.root)) {
    return { ok: false, reason: 'conflict', detail: 'operator note does not attest locally re-sealed checkpoint' };
  }
  if (p.logPubPem) {
    const ov = cp.verify(operatorNote, p.logPubPem);
    if (!ov.ok) return { ok: false, reason: ov.signed ? 'bad-operator-signature' : 'unsigned-operator' };
  }

  const byName = new Map(p.witnesses.map((w) => [w.name, w.pubPem]));
  const valid = new Map(); // witness name -> root (first valid cosig per witness)
  const problems = [];
  for (const c of cosigs || []) {
    const pub = byName.get(c.name);
    if (!pub) { problems.push({ name: c.name, reason: 'unrecognized-key' }); continue; }
    let v;
    try { v = cp.verify(c.signedNote, pub); } catch (e) { problems.push({ name: c.name, reason: 'malformed', detail: e.message }); continue; }
    if (!v.ok) { problems.push({ name: c.name, reason: v.signed ? 'bad-signature' : 'unsigned' }); continue; }
    if (v.size !== local.size) { problems.push({ name: c.name, reason: 'malformed', detail: `size ${v.size} != ${local.size}` }); continue; }
    if (valid.has(c.name)) continue; // duplicate submission: first valid wins, counted once
    valid.set(c.name, v.root);
  }

  // fork evidence: valid cosigs disagreeing on the root at the same size
  const roots = new Set([...valid.values()].map((r) => r.toString('hex')));
  if (roots.size > 1) {
    return { ok: false, reason: 'conflict', detail: `fork: ${roots.size} distinct roots across ${valid.size} valid cosigs`, valid: valid.size, k: p.k };
  }
  const root = valid.size ? [...valid.values()][0] : null;
  if (valid.size >= p.k && !root.equals(local.root)) {
    return { ok: false, reason: 'conflict', detail: 'quorum attests a root the local ledger does not re-seal to', valid: valid.size, k: p.k };
  }
  if (valid.size < p.k) {
    return { ok: false, reason: 'insufficient', detail: `${valid.size}/${p.k} required cosigners`, valid: valid.size, k: p.k, problems };
  }
  return { ok: true, reason: 'quorum', valid: valid.size, k: p.k, size: local.size, root: local.root, digest: local.digest };
}

module.exports = { requiredCosigners, loadPolicy, quorum };
