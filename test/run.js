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
const emb = require('../src/embedding.js');

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

// --- channel (b): sibling-seal digest embedding ---
const embedRow = emb.embedRow(s5);

pin('embedRow shape: BIND witness-anchor origin size digest, one line', () => {
  assert.ok(!embedRow.includes('\n'));
  assert.ok(embedRow.startsWith('BIND witness-anchor origin=superinstance/fleet-wal/v1 size=5 digest='));
  assert.strictEqual(embedRow.length, 'BIND witness-anchor origin=superinstance/fleet-wal/v1 size=5 digest='.length + 64);
});
pin('embedRow digest = independent SHA-256 of note body', () => {
  const d = require('crypto').createHash('sha256').update(s5.note).digest('hex');
  assert.ok(embedRow.endsWith(d));
});
pin('verifyRow accepts genuine (row, note) pair', () => {
  const v = emb.verifyRow(embedRow, s5.note);
  assert.ok(v.ok);
  assert.strictEqual(v.size, 5);
});
pin('verifyRow CATCHES truncated sibling (row binds size 5, note says 3)', () => {
  const t = cp.seal(full.slice(0, 3));
  const v = emb.verifyRow(embedRow, t.note);
  assert.ok(!v.ok);
  assert.strictEqual(v.reason, 'size-mismatch');
});
pin('verifyRow CATCHES forged note with row digest kept (digest-mismatch)', () => {
  const tampered = cp.seal(full.slice().map((r, i) => (i === 1 ? r + ' (forged)' : r)));
  const v = emb.verifyRow(embedRow, tampered.note);
  assert.ok(!v.ok);
  assert.strictEqual(v.reason, 'digest-mismatch');
});
pin('parseRow rejects foreign origin', () => {
  assert.throws(() => emb.parseRow('BIND witness-anchor origin=evil size=5 digest=' + 'ab'.repeat(32)));
});
pin('parseRow rejects uppercase digest hex (strict lowercase)', () => {
  assert.throws(() => emb.parseRow('BIND witness-anchor origin=superinstance/fleet-wal/v1 size=5 digest=' + 'AB'.repeat(32)));
});
pin('parseRow rejects multi-line row (WAL row injection guard)', () => {
  assert.throws(() => emb.parseRow(embedRow + '\nLINK injected'));
});
pin('embedRow works on empty ledger (size 0 edge)', () => {
  const s0 = cp.seal([]);
  const r = emb.embedRow(s0);
  const v = emb.verifyRow(r, s0.note);
  assert.ok(v.ok);
  assert.strictEqual(v.size, 0);
});
pin('embedding row is an ordinary WAL row (extends L0 chain, byte-stable)', () => {
  const withEmb = full.concat([embedRow]);
  const h1 = l0chain(withEmb);
  const h2 = l0chain(withEmb);
  assert.deepStrictEqual(h1, h2); // fnv1a chain deterministic over embedded row
  assert.ok(l0verify(withEmb, h1));
});
pin('verifyRow ACCEPTS signed witness note (sig line never enters the anchored digest)', () => {
  // channel (b) consumers will receive signed notes once the signer seam is
  // filled; the row digest anchors the note BODY, so the sig line must not
  // break the recompute. Sig shape faked locally — no signer dependency here.
  // (Byte-drift beyond the sig seam is cp.parse's strict-shape job, not
  // verifyRow's — notes are byte-canonical per the signer-seam branch.)
  const signedNote = s5.note + 'sig:' + Buffer.alloc(64, 0x41).toString('base64') + '\n';
  const v = emb.verifyRow(embedRow, signedNote);
  assert.ok(v.ok, 'signed note must verify: ' + JSON.stringify(v));
});
pin('parseRow rejects unknown extra fields (strict shape, no drift)', () => {
  assert.throws(() => emb.parseRow(embedRow + ' attackernote=x'));
});
pin('parseRow rejects duplicate fields (no last-wins ambiguity)', () => {
  assert.throws(() => emb.parseRow(embedRow.replace('size=5', 'size=99 size=5')));
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
pin('anchor: stray untracked file in witness repo is NOT swept into the anchor commit', () => {
  const repo = freshWitnessRepo();
  fs.writeFileSync(path.join(repo, 'editor-temp.txt'), 'stray');
  anchor.anchor(repo, 'demo', cp.seal(full).note);
  const status = execFileSync('git', ['-C', repo, 'status', '--porcelain'], { encoding: 'utf8' });
  assert.ok(/^\?\? editor-temp\.txt$/m.test(status), 'stray file must remain untracked, got: ' + status.trim());
  const files = execFileSync('git', ['-C', repo, 'ls-files'], { encoding: 'utf8' });
  assert.ok(!/editor-temp\.txt/.test(files), 'stray file must not be committed');
});

// --- L3 quorum design pins (doc-text pins, FAIL-first: all red on main where the doc is absent) ---
const l3doc = fs.readFileSync(path.join(__dirname, '..', 'docs', 'L3-QUORUM.md'), 'utf8');
pin('L3-QUORUM.md design doc exists', () => {
  assert.ok(l3doc.length > 2000);
});
pin('L3 operating point recorded: n=3 witnesses, k=2 cosigs', () => {
  assert.match(l3doc, /n = 3 witnesses across 3 trust domains/);
  assert.match(l3doc, /k = 2 cosigs required/);
});
pin('L3 strict-majority bound recorded, not simple majority', () => {
  assert.match(l3doc, /t ≥ ⌈\(n \+ m \+ 1\) \/ 2⌉/);
  assert.match(l3doc, /not a simple majority|NOT a simple majority/i);
});
pin('L3 policy file shape: origin + log key + witness keys + quorum', () => {
  for (const field of ['"origin"', '"log"', '"witnesses"', '"quorum"', '"k-of-n"']) {
    assert.ok(l3doc.includes(field), `policy shape missing ${field}`);
  }
});
pin('L3 Nous honesty rule: no witnessing claim without on-disk cosig', () => {
  assert.match(l3doc, /mechanism ≠ witnessing/);
  assert.match(l3doc, /Nous/);
});
pin('L4 TSA rejection recorded (study verdict kept)', () => {
  assert.match(l3doc, /L4 TSA.*?: rejected|Trusted time \(L4 TSA\): rejected/s);
});
pin('L3 fail-closed semantics stated (freezing, not convergence)', () => {
  assert.match(l3doc, /fail closed/);
  assert.match(l3doc, /freezing/, 'split-view without monitors is freezing, not convergence');
});
pin('L3 build gate stated (extraction #4 + two always-on hosts)', () => {
  assert.match(l3doc, /extraction #4/);
  assert.match(l3doc, /always-on daemons/);
});


// --- Ed25519 signer seam (v0.1) ---
// Keys generated in-test (never the fleet key — CI must not depend on
// ~/.config/fleet-witness); PEM shape matches the fleet keypair exactly.
const kp = require('crypto').generateKeyPairSync('ed25519');
const privPem = kp.privateKey.export({ type: 'pkcs8', format: 'pem' });
const pubPem = kp.publicKey.export({ type: 'spki', format: 'pem' });
const kp2 = require('crypto').generateKeyPairSync('ed25519');
const pubPem2 = kp2.publicKey.export({ type: 'spki', format: 'pem' });

const signed = cp.sign(s5.size, s5.root, privPem);

pin('sign appends sig line after the body', () => {
  const lines = signed.split('\n');
  assert.strictEqual(lines[3].slice(0, 4), 'sig:');
  assert.strictEqual(lines.length, 5);
  assert.strictEqual(signed.slice(0, s5.note.length), s5.note); // body untouched
});
pin('signed note parses as signed with extracted sig', () => {
  const p = cp.parse(signed);
  assert.strictEqual(p.signed, true);
  assert.strictEqual(p.size, 5);
  assert.ok(p.root.equals(s5.root));
  assert.ok(p.sig.length === 64); // raw Ed25519
  assert.strictEqual(p.body, s5.note);
});
pin('unsigned note parses signed:false (honest, not an error)', () => {
  assert.strictEqual(cp.parse(s5.note).signed, false);
});
pin('verify ACCEPTS genuine signed note', () => {
  const v = cp.verify(signed, pubPem);
  assert.strictEqual(v.ok, true);
  assert.strictEqual(v.size, 5);
});
pin('verify REJECTS body tamper under valid sig', () => {
  const lines = signed.split('\n');
  lines[1] = '999'; // size lie, sig untouched
  assert.strictEqual(cp.verify(lines.join('\n'), pubPem).ok, false);
});
pin('verify REJECTES sig from a different key', () => {
  assert.strictEqual(cp.verify(signed, pubPem2).ok, false);
});
pin('sig line never enters the anchored digest (channel invariant)', () => {
  const p = cp.parse(signed);
  const bodyDigest = require('crypto').createHash('sha256').update(p.body).digest();
  assert.ok(bodyDigest.equals(s5.digest)); // anchor binds body only
});
pin('verify(unsigned) reports ok:false reason unsigned', () => {
  const v = cp.verify(s5.note, pubPem);
  assert.strictEqual(v.ok, false);
  assert.strictEqual(v.reason, 'unsigned');
});
pin('parse rejects junk line after sig line (strict shape)', () => {
  assert.throws(() => cp.parse(signed + 'THIS IS JUNK\n'));
});
pin('parse rejects extra line in unsigned note (strict shape)', () => {
  assert.throws(() => cp.parse(s5.note + 'extra line\n'));
});
pin('parse rejects junk-before-sig shapes (sig is line 4, nothing between)', () => {
  const sigLine = signed.split('\n')[3];
  assert.throws(() => cp.parse(s5.note + 'junkline\n' + sigLine + '\n'));
});
pin('verify still catches junk-after-sig (via strict parse, not sig check)', () => {
  assert.throws(() => cp.verify(signed + 'JUNK\n', pubPem));
});


// --- L3 witness quorum (C2SP-shaped, this window) ---
// Client-side check per docs/L3-QUORUM.md: named policy, strict-majority
// bound, operator note + witness cosigs over the v0.1 signer seam. Witness
// daemons remain design-gated; these pins exercise the mechanism only.
const qu = require('../src/quorum.js');

const pem = (kp) => kp.publicKey.export({ type: 'spki', format: 'pem' });
const priv = (kp) => kp.privateKey.export({ type: 'pkcs8', format: 'pem' });
const kpW2 = require('crypto').generateKeyPairSync('ed25519');
const kpW3 = require('crypto').generateKeyPairSync('ed25519');
const kpOp = require('crypto').generateKeyPairSync('ed25519');
const policy3 = qu.loadPolicy({
  name: 'fleet-wal-prod', origin: cp.ORIGIN,
  log: { ed25519: pem(kpOp) },
  witnesses: [
    { name: 'kimi1', ed25519: pubPem },
    { name: 'z-worker', ed25519: pem(kpW2) },
    { name: 'casey', ed25519: pem(kpW3) },
  ],
  quorum: { kind: 'k-of-n', k: 2, n: 3 },
});
const opNote = cp.sign(s5.size, s5.root, priv(kpOp));
const cosig = (name, key) => ({ name, signedNote: cp.sign(s5.size, s5.root, key) });
const C1 = cosig('kimi1', privPem);
const C2 = cosig('z-worker', priv(kpW2));
const C3 = cosig('casey', priv(kpW3));

pin('strict-majority bound: n=3,m=0 -> k=2; n=3,m=1 -> k=3', () => {
  assert.strictEqual(qu.requiredCosigners(3, 0), 2);
  assert.strictEqual(qu.requiredCosigners(3, 1), 3);
  assert.strictEqual(qu.requiredCosigners(7, 2), 5);
  assert.strictEqual(policy3.k, 2);
});
pin('loadPolicy accepts the design-doc policy shape', () => {
  assert.strictEqual(policy3.name, 'fleet-wal-prod');
  assert.strictEqual(policy3.n, 3);
  assert.strictEqual(policy3.logPubPem, pem(kpOp));
});
pin('loadPolicy REFUSES k below the strict-majority floor (not trusted)', () => {
  assert.throws(() => qu.loadPolicy({
    name: 'p', origin: cp.ORIGIN,
    witnesses: [
      { name: 'a', ed25519: pubPem }, { name: 'b', ed25519: pem(kpW2) },
      { name: 'c', ed25519: pem(kpW3) }, { name: 'd', ed25519: pem(kpOp) }, { name: 'e', ed25519: pubPem2 },
    ],
    quorum: { kind: 'k-of-n', k: 2, n: 5 }, // floor for n=5 is 3
  }), /floor/);
});
pin('loadPolicy REFUSES duplicate witness names', () => {
  assert.throws(() => qu.loadPolicy({
    name: 'p', origin: cp.ORIGIN,
    witnesses: [{ name: 'x', ed25519: pubPem }, { name: 'x', ed25519: pem(kpW2) }],
    quorum: { kind: 'k-of-n', k: 2, n: 2 }, // floor for n=2 is 2
  }), /duplicate/);
});
pin('loadPolicy REFUSES foreign origin', () => {
  assert.throws(() => qu.loadPolicy({
    name: 'p', origin: 'evil/origin', witnesses: [{ name: 'x', ed25519: pubPem }],
    quorum: { kind: 'k-of-n', k: 1, n: 1 },
  }), /origin/);
});
pin('loadPolicy REFUSES quorum.n diverging from witness count', () => {
  assert.throws(() => qu.loadPolicy({
    name: 'p', origin: cp.ORIGIN,
    witnesses: [{ name: 'x', ed25519: pubPem }, { name: 'y', ed25519: pem(kpW2) }],
    quorum: { kind: 'k-of-n', k: 2, n: 3 },
  }), /!= witness count/);
});
pin('quorum ACCEPTS 2-of-3 valid distinct cosigs + operator sig', () => {
  const v = qu.quorum(full, opNote, [C1, C2], policy3);
  assert.strictEqual(v.ok, true);
  assert.strictEqual(v.reason, 'quorum');
  assert.strictEqual(v.valid, 2);
  assert.strictEqual(v.k, 2);
  assert.ok(v.digest.equals(s5.digest));
});
pin('quorum REFUSES 1-of-3 (below strict majority), names the gap', () => {
  const v = qu.quorum(full, opNote, [C1], policy3);
  assert.strictEqual(v.ok, false);
  assert.strictEqual(v.reason, 'insufficient');
  assert.strictEqual(v.valid, 1);
  assert.strictEqual(v.k, 2);
});
pin('quorum counts a witness ONCE (duplicate submissions never a quorum)', () => {
  const v = qu.quorum(full, opNote, [C1, C1, C1], policy3);
  assert.strictEqual(v.ok, false);
  assert.strictEqual(v.valid, 1);
});
pin('quorum fail-closed on unrecognized-key (verified cosig NOT in policy)', () => {
  const kpRogue = require('crypto').generateKeyPairSync('ed25519');
  const rogue = cosig('rogue', priv(kpRogue));
  const v = qu.quorum(full, opNote, [C1, rogue], policy3);
  assert.strictEqual(v.ok, false);
  assert.strictEqual(v.valid, 1);
  assert.ok(v.problems.some((p) => p.name === 'rogue' && p.reason === 'unrecognized-key'));
});
pin('quorum REFUSES unsigned witness notes (never counted toward k)', () => {
  const v = qu.quorum(full, opNote, [C1, { name: 'z-worker', signedNote: s5.note }], policy3);
  assert.strictEqual(v.ok, false);
  assert.strictEqual(v.valid, 1);
  assert.ok(v.problems.some((p) => p.reason === 'unsigned'));
});
pin('quorum REFUSES unsigned operator note when policy names a log key', () => {
  const v = qu.quorum(full, s5.note, [C1, C2], policy3);
  assert.strictEqual(v.ok, false);
  assert.strictEqual(v.reason, 'unsigned-operator');
});
pin('quorum REFUSES operator note signed by the wrong key', () => {
  const wrongKey = cp.sign(s5.size, s5.root, privPem); // not the policy log key
  const v = qu.quorum(full, wrongKey, [C1, C2], policy3);
  assert.strictEqual(v.ok, false);
  assert.strictEqual(v.reason, 'bad-operator-signature');
});
pin('FORK: two valid cosigs over different roots at same size -> conflict (409-class)', () => {
  const tampered = full.slice(); tampered[2] = 'LINK step TWO (forked)';
  const forkSeal = cp.seal(tampered);
  assert.strictEqual(forkSeal.size, s5.size); // premise: same size, different root
  const forkSigned = cp.sign(forkSeal.size, forkSeal.root, priv(kpW2));
  const v = qu.quorum(full, opNote, [C1, { name: 'z-worker', signedNote: forkSigned }], policy3);
  assert.strictEqual(v.ok, false);
  assert.strictEqual(v.reason, 'conflict');
});
pin('quorum attesting a root the local ledger does not re-seal -> conflict (persist-before-cosign mirror)', () => {
  // witnesses honestly cosign a SAME-SIZE forked ledger; caller presents the real rows
  const forked = full.slice(); forked[2] = 'LINK step TWO (forked ledger)';
  const fSeal = cp.seal(forked);
  assert.strictEqual(fSeal.size, s5.size);
  const honest = [
    { name: 'kimi1', signedNote: cp.sign(fSeal.size, fSeal.root, privPem) },
    { name: 'z-worker', signedNote: cp.sign(fSeal.size, fSeal.root, priv(kpW2)) },
  ];
  const v = qu.quorum(full, opNote, honest, policy3);
  assert.strictEqual(v.ok, false);
  assert.strictEqual(v.reason, 'conflict');
});
pin('operator note not attesting local seal -> conflict (caller lied about its own ledger)', () => {
  const forked = full.slice(); forked[2] = 'LINK step TWO (forked ledger)';
  const fSeal = cp.seal(forked);
  const opLie = cp.sign(fSeal.size, fSeal.root, priv(kpOp));
  const v = qu.quorum(full, opLie, [C1, C2], policy3);
  assert.strictEqual(v.ok, false);
  assert.strictEqual(v.reason, 'conflict');
});
pin('size disagreement from a witness -> malformed (422-class), named', () => {
  const wrongSize = cp.sign(3, cp.seal(full.slice(0, 3)).root, priv(kpW2));
  const v = qu.quorum(full, opNote, [C1, { name: 'z-worker', signedNote: wrongSize }], policy3);
  assert.strictEqual(v.ok, false);
  assert.ok(v.problems.some((p) => p.name === 'z-worker' && p.reason === 'malformed'));
});
pin('3-of-3 (k=3,n=3) policy ACCEPTS only when all three agree', () => {
  const pol = qu.loadPolicy({
    name: 'fleet-wal-strict', origin: cp.ORIGIN,
    log: { ed25519: pem(kpOp) },
    witnesses: [
      { name: 'kimi1', ed25519: pubPem },
      { name: 'z-worker', ed25519: pem(kpW2) },
      { name: 'casey', ed25519: pem(kpW3) },
    ],
    quorum: { kind: 'k-of-n', k: 3, n: 3 },
  });
  assert.strictEqual(qu.quorum(full, opNote, [C1, C2], pol).ok, false);
  const v = qu.quorum(full, opNote, [C1, C2, C3], pol);
  assert.strictEqual(v.ok, true);
  assert.strictEqual(v.valid, 3);
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);