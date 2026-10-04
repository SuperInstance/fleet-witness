'use strict';
// truncate-demo.js — the sales artifact for the witnessing study's core claim:
//
//   "L0 (fnv1a-64 append chain, fleet WAL idiom) verifies CLEAN on a
//    truncated ledger. L1 (Merkle checkpoint) catches it."
//
// Three honest cases, all live, no staging:
//   1. TRUNCATION  — drop the last 3 rows; L0 chain verifies; checkpoint audit CATCHES.
//   2. TAMPER      — flip one byte in place; L0 catches it (L0 is not useless).
//   3. RE-SEAL     — tamper AND rebuild the L0 chain (byte-stable forgery);
//                    L0 verifies again; checkpoint root mismatch CATCHES it.
//
// Run: node demo/truncate-demo.js

const tree = require('../src/tree.js');
const cp = require('../src/checkpoint.js');

// L0 fleet-WAL idiom: fnv1a-64 chain over row strings ("row|prevhex").
function fnv1a64(str) {
  let h = 0xcbf29ce484222325n;
  for (let i = 0; i < str.length; i++) {
    h ^= BigInt(str.charCodeAt(i));
    h = (h * 0x100000001b3n) & 0xffffffffffffffffn;
  }
  return h;
}
function l0Chain(rows) {
  let prev = 'genesis';
  return rows.map((r) => (prev = fnv1a64(r + '|' + prev).toString(16).padStart(16, '0')));
}
function l0Verify(rows, chain) {
  if (rows.length !== chain.length) return false;
  return l0Chain(rows).every((h, i) => h === chain[i]);
}

// audit: does the checkpoint note match this ledger's L1 seal?
function audit(rows, noteText) {
  const n = cp.parse(noteText);
  if (n.size !== rows.length) return { ok: false, why: `size mismatch: note ${n.size}, ledger ${rows.length}` };
  const root = tree.root(rows);
  if (!root.equals(n.root)) return { ok: false, why: 'root mismatch' };
  return { ok: true, why: 'match' };
}

function runDemo() {
  const rows = [
    'BIND|fleet-wal-demo|seed 7',
    'EFFECT|search gen 1',
    'EFFECT|search gen 2',
    'EFFECT|search gen 3',
    'TICK|champion minted',
    'PROOF|witness ledger sealed',
  ];

  const fullChain = l0Chain(rows);
  const checkpoint = cp.seal(rows); // honest operator sealed the FULL ledger

  // Case 1: truncation (the silent disaster)
  const truncated = rows.slice(0, 3);
  const c1 = {
    l0: l0Verify(truncated, fullChain.slice(0, 3)),
    audit: audit(truncated, checkpoint.note),
  };

  // Case 2: in-place tamper (L0's honest win)
  const tampered = rows.slice();
  tampered[2] = tampered[2].replace('gen 2', 'gen 2 FORGED');
  const c2 = { l0: l0Verify(tampered, fullChain) };

  // Case 3: tamper + re-seal the L0 chain (byte-stable forgery)
  const resealed = l0Chain(tampered);
  const c3 = {
    l0: l0Verify(tampered, resealed),
    audit: audit(tampered, checkpoint.note),
  };

  return { rows, checkpoint, c1, c2, c3 };
}

function main() {
  const d = runDemo();
  console.log(`ledger: ${d.rows.length} rows, checkpoint root ${d.checkpoint.root.toString('hex').slice(0, 16)}…`);
  console.log(`CASE 1 truncation (3 rows dropped):  L0 verify = ${d.c1.l0} (PASSES — silent loss)`);
  console.log(`                                    checkpoint audit = ${d.c1.audit.ok ? 'PASS' : 'CATCH — ' + d.c1.audit.why}`);
  console.log(`CASE 2 in-place tamper:              L0 verify = ${d.c2.l0 ? 'PASS' : 'CATCH (L0 honest here)'}`);
  console.log(`CASE 3 tamper + L0 re-seal:          L0 verify = ${d.c3.l0} (forgery verifies clean)`);
  console.log(`                                    checkpoint audit = ${d.c3.audit.ok ? 'PASS' : 'CATCH — ' + d.c3.audit.why}`);
  if (!(!d.c1.l0 === false && d.c1.audit.ok === false)) process.exitCode = 1;
}

if (require.main === module) main();
module.exports = { fnv1a64, l0Chain, l0Verify, audit, runDemo };
