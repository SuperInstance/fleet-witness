'use strict';
// Zero-dep test runner + pins. Run: node test/run.js
// FAIL-first doctrine: every pin must be capable of tripping; pins were
// verified against an independent Python hashlib pass at authoring time
// (vectors below), not copied between implementations unchecked.

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const tree = require('../src/tree.js');
const cp = require('../src/checkpoint.js');
const anchor = require('../src/anchor.js');
const demo = require('../demo/truncate-demo.js');

let pass = 0, fail = 0;
function pin(name, fn) {
  try { fn(); pass++; console.log(`ok - ${name}`); }
  catch (e) { fail++; console.log(`FAIL - ${name}: ${e.message}`); }
}
const hex = (b) => b.toString('hex');

// --- RFC 6962 vectors (independent python hashlib pass, /tmp/rfc6962-vectors.py) ---
pin('MTH empty = SHA-256 of empty', () => {
  assert.strictEqual(hex(tree.root([])), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
});
pin('MTH single leaf "a"', () => {
  assert.strictEqual(hex(tree.root(['a'])), '022a6979e6dab7aa5ae4c3e5e45f7e977112a7e63593820dbec1ec738a24f93c');
});
pin('MTH a,b', () => {
  assert.strictEqual(hex(tree.root(['a', 'b'])), 'b137985ff484fb600db93107c77b0365c80d78f5b429ded0fd97361d077999eb');
});
pin('MTH a,b,c', () => {
  assert.strictEqual(hex(tree.root(['a', 'b', 'c'])), '36642e73c2540ab121e3a6bf9545b0a24982cd830eb13d3cd19de3ce6c021ec1');
});
pin('MTH a..d', () => {
  assert.strictEqual(hex(tree.root(['a', 'b', 'c', 'd'])), '33376a3bd63e9993708a84ddfe6c28ae58b83505dd1fed711bd924ec5a6239f0');
});
pin('MTH a..g (unbalanced, split at 4)', () => {
  assert.strictEqual(hex(tree.root(['a', 'b', 'c', 'd', 'e', 'f', 'g'])), '4ae191939f548d9934740b88dea2c5cb89bb8870fc4505cd79dec6bbfaaee9cb');
});

// --- consistency proof vectors (same python pass) ---
pin('consistency 2->3 proof node', () => {
  const p = tree.consistencyProof(2, ['a', 'b', 'c']);
  assert.strictEqual(p.map(hex).join(','), '597fcb31282d34654c200d3418fca5705c648ebf326ec73d8ddef11841f876d8');
});
pin('consistency 1->3 proof nodes', () => {
  const p = tree.consistencyProof(1, ['a', 'b', 'c']);
  assert.strictEqual(p.length, 2);
});
pin('consistency 3->7 proof nodes', () => {
  const p = tree.consistencyProof(3, ['a', 'b', 'c', 'd', 'e', 'f', 'g']);
  assert.strictEqual(p.length, 3);
});
pin('verifyConsistency accepts genuine append 3->7', () => {
  const leaves = ['a', 'b', 'c', 'd', 'e', 'f', 'g'];
  const m = 3;
  assert.ok(tree.verifyConsistency(m, tree.root(leaves.slice(0, m)), leaves, tree.consistencyProof(m, leaves)));
});

// --- the threat: clean suffix truncation ---
// L0-style fnv1a-64 prev chain sim (fleet shape): chain verifies after
// truncation; anchored checkpoint must NOT.
function fnv1a64(str) {
  let h = 0xcbf29ce484222325n;
  for (const b of Buffer.from(str)) { h ^= BigInt(b); h = (h * 0x100000001b3n) & 0xffffffffffffffffn; }
  return h.toString(16).padStart(16, '0');
}
function l0chain(rows) {
  let prev = '0'.repeat(16);
  return rows.map((r) => { prev = fnv1a64(prev + r); return prev; });
}
function l0verify(rows, heads) {
  return l0chain(rows).every((h, i) => h === heads[i]);
}

const full = ['BIND genesis', 'LINK step one', 'LINK step two', 'VIEW snapshot', 'LINK step three'];
const heads = l0chain(full);
const s5 = cp.seal(full); // checkpoint anchored at size 5

pin('L0 chain verifies on FULL ledger', () => {
  assert.ok(l0verify(full, heads));
});
pin('L0 chain verifies on TRUNCATED ledger (the gap, by construction)', () => {
  const t = full.slice(0, 3);
  assert.ok(l0verify(t, heads.slice(0, 3))); // clean truncation verifies clean
});
pin('checkpoint audit CATCHES truncation (size mismatch)', () => {
  const t = full.slice(0, 3);
  const rt = cp.seal(t); // truncated ledger seals fine...
  assert.ok(!rt.digest.equals(s5.digest)); // ...but digest disagrees with anchored s5
  assert.strictEqual(rt.size, 3);
  assert.strictEqual(s5.size, 5);
});
pin('checkpoint audit CATCHES same-size tamper', () => {
  const tampered = full.slice(); tampered[2] = 'LINK step TWO (forged)';
  assert.ok(!cp.seal(tampered).digest.equals(s5.digest));
});
pin('checkpoint re-seal of identical ledger is byte-stable', () => {
  const again = cp.seal(full);
  assert.strictEqual(again.note, s5.note);
  assert.ok(again.digest.equals(s5.digest));
});
pin('parse round-trips sealed checkpoint', () => {
  const p = cp.parse(s5.note);
  assert.strictEqual(p.size, 5);
  assert.ok(p.root.equals(s5.root));
  assert.strictEqual(p.origin, cp.ORIGIN);
});
pin('parse rejects foreign origin', () => {
  assert.throws(() => cp.parse('evil-origin\n5\nAAAA\n'));
});
pin('digest == SHA-256 of note body (anchor channel invariant)', () => {
  const d = require('crypto').createHash('sha256').update(s5.note).digest();
  assert.ok(d.equals(s5.digest));
});

// --- L2 anchor channel: witness-repo git anchoring (window 2) ---
function freshWitnessRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fw-witness-'));
  execFileSync('git', ['init', '-q', dir]);
  const run = (args) => execFileSync('git', ['-C', dir, ...args], { stdio: 'pipe' });
  run(['-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-q', '--allow-empty', '-m', 'init']);
  return dir;
}
pin('anchor: fresh anchor verifies from git history', () => {
  const repo = freshWitnessRepo();
  anchor.anchor(repo, 'demo', cp.seal(full).note);
  const v = anchor.audit(repo, 'demo', 5, cp.seal(full).root);
  assert.ok(v.ok, JSON.stringify(v));
});
pin('anchor: truncation to 3 CAUGHT (size pin)', () => {
  const repo = freshWitnessRepo();
  anchor.anchor(repo, 'demo', cp.seal(full).note);
  const t = full.slice(0, 3);
  assert.ok(!anchor.audit(repo, 'demo', 3, cp.seal(t).root).ok);
});
pin('anchor: ROLLBACK to old valid state CAUGHT (chains fine at L0, size pin rejects)', () => {
  const grown = full.concat(['LINK step SIX', 'LINK step SEVEN']);
  const repo = freshWitnessRepo();
  anchor.anchor(repo, 'demo', cp.seal(full).note);
  anchor.anchor(repo, 'demo', cp.seal(grown).note);
  const v7 = anchor.audit(repo, 'demo', 7, cp.seal(grown).root);
  assert.ok(v7.ok, JSON.stringify(v7));
  // attacker presents the OLD full-5 state: valid rows, valid L0 chain, wrong era
  assert.ok(!anchor.audit(repo, 'demo', 5, cp.seal(full).root).ok);
});
pin('anchor: forged LATEST CAUGHT (root mismatch)', () => {
  const repo = freshWitnessRepo();
  anchor.anchor(repo, 'demo', cp.seal(full).note);
  const forged = cp.note(5, Buffer.alloc(32, 0x41));
  fs.writeFileSync(path.join(repo, 'checkpoints', 'demo', 'LATEST'), forged);
  assert.ok(!anchor.audit(repo, 'demo', 5, cp.seal(full).root).ok);
});
pin('anchor: notes.log is append-only across re-anchors', () => {
  const repo = freshWitnessRepo();
  anchor.anchor(repo, 'demo', cp.seal(full).note);
  anchor.anchor(repo, 'demo', cp.seal(full.concat(['X'])).note);
  const log = fs.readFileSync(path.join(repo, 'checkpoints', 'demo', 'notes.log'), 'utf8');
  assert.strictEqual((log.match(/superinstance\/fleet-wal\/v1/g) || []).length, 2);
});

// --- truncate-demo pins (the sales artifact: L0 silent, L1 catches) ---
pin('demo: runDemo returns all three cases', () => {
  const d = demo.runDemo();
  assert.strictEqual(d.c1.l0, true, 'truncated ledger MUST verify at L0 (silent-loss premise)');
  assert.strictEqual(d.c1.audit.ok, false, 'checkpoint MUST catch truncation');
  assert.strictEqual(d.c2.l0, false, 'in-place tamper MUST break L0');
  assert.strictEqual(d.c3.l0, true, 're-sealed forgery MUST verify at L0');
  assert.strictEqual(d.c3.audit.ok, false, 'checkpoint MUST catch re-sealed forgery');
});
pin('demo: CLI exits 0 and prints CATCH lines', () => {
  const out = execFileSync(process.execPath, [path.join(__dirname, '..', 'demo', 'truncate-demo.js')]).toString();
  assert.ok(/CASE 1 truncation/.test(out) && /CATCH — size mismatch/.test(out), 'truncation catch line missing');
  assert.ok(/CASE 3 tamper \+ L0 re-seal/.test(out) && /CATCH — root mismatch/.test(out), 're-seal catch line missing');
});
pin('demo: audit size-mismatch reason names both sizes', () => {
  const d = demo.runDemo();
  assert.ok(/note 6, ledger 3/.test(d.c1.audit.why), 'honest reason: ' + d.c1.audit.why);
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
