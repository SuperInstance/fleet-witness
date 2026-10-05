'use strict';
// Truncate-demo: standalone sales artifact driving the whole witnessing
// story (witnessing study build order item 4, "after anchor"). One command:
//
//   node src/truncate-demo.js
//
// Story, in five beats:
//   1. A fleet WAL grows to 5 rows and gets anchored in a witness repo.
//   2. An attacker deletes the last two rows. The L0 fnv1a-64 prev chain —
//      the fleet's tamper-loud edit/insert protection — STILL VERIFIES.
//      (That's the hole this repo exists to close.)
//   3. The anchored checkpoint refuses to agree: size pin fires.
//   4. Variants: rollback to an old valid state, and same-size forgery —
//      both caught by the same compare.
//   5. Honest limits restated (anchor every seal; git-as-broadcast).
//
// The demo builds everything in a temp dir; nothing outside is touched.
// It exits 0 only if every attack is caught — a demo that can't fail is
// marketing, not evidence (FAIL-first doctrine applies to demos too).

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const cp = require('./checkpoint.js');
const anchor = require('./anchor.js');

function fnv1a64(str) {
  let h = 0xcbf29ce484222325n;
  for (const b of Buffer.from(str)) { h ^= BigInt(b); h = (h * 0x100000001b3n) & 0xffffffffffffffffn; }
  return h.toString(16).padStart(16, '0');
}
function l0chain(rows) {
  let prev = '0'.repeat(16);
  return rows.map((r) => { prev = fnv1a64(prev + r); return prev; });
}
const l0ok = (rows, heads) => l0chain(rows).every((h, i) => h === heads[i]);

const say = (n, msg) => console.log(`\n[${n}] ${msg}`);
const verdict = (caught, what) =>
  console.log(`    -> ${caught ? 'CAUGHT' : 'NOT CAUGHT (!!)'} — ${what}`);

const wal = ['BIND genesis', 'LINK step one', 'LINK step two', 'VIEW snapshot', 'LINK step three'];
const heads = l0chain(wal);
const grown = wal.concat(['LINK step six', 'LINK step seven']);

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fw-demo-'));
const witnessDir = path.join(dir, 'witness-repo');
execFileSync('git', ['init', '-q', witnessDir]);
const git = (args) => execFileSync('git', ['-C', witnessDir, ...args], { stdio: 'pipe' });
git(['-c', 'user.name=demo', '-c', 'user.email=demo@demo', 'commit', '-q', '--allow-empty', '-m', 'init']);

let failed = 0;
function expectCaught(caught, what) { verdict(caught, what); if (!caught) failed++; }

say(1, `a fleet WAL grows to ${wal.length} rows: ${wal.map((r) => JSON.stringify(r)).join(', ')}`);
const s5 = cp.seal(wal);
console.log(`    L0 chain head: ${heads[heads.length - 1]}`);
console.log(`    Merkle root:   ${s5.root.toString('hex').slice(0, 16)}…  size=${s5.size}`);

say(2, `operator anchors the size-${s5.size} checkpoint in a witness repo (one git commit, another trust domain)`);
anchor.anchor(witnessDir, 'demo-ledger', s5.note, { name: 'demo', email: 'demo@demo' });
console.log(`    witness repo: ${path.join('checkpoints', 'demo-ledger', 'LATEST')}`);

say(3, `ATTACK — clean suffix truncation: delete the last two rows`);
const trunc = wal.slice(0, 3);
const l0still = l0ok(trunc, heads.slice(0, 3));
console.log(`    L0 fnv1a-64 chain over the truncated ledger: ${l0still ? 'VERIFIES CLEAN (the hole)' : 'broken'}`);
const a1 = anchor.audit(witnessDir, 'demo-ledger', cp.seal(trunc).size, cp.seal(trunc).root);
expectCaught(!a1.ok, `anchored checkpoint audit: ${a1.reason}`);

say(4, `VARIANT — rollback: operator grows the ledger to ${grown.length} and re-anchors; attacker presents the old valid size-5 state`);
anchor.anchor(witnessDir, 'demo-ledger', cp.seal(grown).note, { name: 'demo', email: 'demo@demo' });
const grownOk = anchor.audit(witnessDir, 'demo-ledger', 7, cp.seal(grown).root);
console.log(`    honest size-7 presentation: ${grownOk.ok ? 'verifies' : 'rejected?! ' + grownOk.reason}`);
const a2 = anchor.audit(witnessDir, 'demo-ledger', 5, cp.seal(wal).root);
expectCaught(!a2.ok, `rolled-back size-5 presentation (valid rows, valid chain, wrong era): ${a2.reason}`);

say(5, `VARIANT — same-size forgery: rewrite row 3 in place, keep the size`);
const forged = wal.slice(); forged[2] = 'LINK step TWO (forged)';
const a3 = anchor.audit(witnessDir, 'demo-ledger', 7, cp.seal(forged.concat(grown.slice(5))).root);
expectCaught(!a3.ok, `forged presentation: ${a3.reason}`);

say('∞', 'honest limits (study, kept loud)');
console.log('    - truncation between two anchors is invisible — anchor every seal (one git commit).');
console.log('    - git-as-broadcast protects retainers, not newcomers; split-view waits for L3.');
console.log("    - witnesses are content-blind; content honesty stays the receipts' job.");

fs.rmSync(dir, { recursive: true, force: true });

console.log(`\n${failed === 0 ? 'DEMO PASS' : 'DEMO FAIL'} — ${failed === 0 ? 'every attack caught' : failed + ' attack(s) NOT caught'}`);
process.exit(failed ? 1 : 0);
