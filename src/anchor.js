'use strict';
// L2 anchor channel: checkpoint notes committed into a WITNESS REPO's git
// history (different trust domain than the ledger: tampering with the ledger
// can't rewrite an already-committed note). From the witnessing study's
// window-2 plan; consume-don't-rival — this repo is the canonical core.
//
// Layout inside the witness repo:
//   checkpoints/<ledger-slug>/notes.log   — append-only note history
//   checkpoints/<ledger-slug>/LATEST      — copy of the newest note
//
// Audit rule: LATEST pins the newest (size, root). A presented ledger that
// chains fine at layer 0 but is SHORTER than the anchor (rollback to an old
// valid state) or reseals differently (truncation + rewrite) both FAIL here —
// two attack classes layer 0 cannot see. Honest limit (study): git-as-broadcast
// protects retainers, not newcomers; split-view resistance waits for L3.

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const cp = require('./checkpoint.js');

function slugify(name) {
  return name.replace(/[^a-zA-Z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'ledger';
}

// Append a sealed checkpoint's note to the witness repo and commit.
// opts.git identity: pass {name, email} if the repo has no global identity.
function anchor(witnessRepoDir, ledgerName, noteText, opts = {}) {
  const dir = path.join(witnessRepoDir, 'checkpoints', slugify(ledgerName));
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'notes.log'), noteText, { flag: 'a' });
  fs.writeFileSync(path.join(dir, 'LATEST'), noteText);
  const run = (args) => execFileSync('git', ['-C', witnessRepoDir, ...args], { stdio: 'pipe' });
  run(['add', '.']);
  const idArgs = opts.name ? ['-c', `user.name=${opts.name}`, '-c', `user.email=${opts.email}`] : [];
  run([...idArgs, 'commit', '-m', `anchor: ${slugify(ledgerName)} checkpoint`]);
  return path.join(dir, 'LATEST');
}

// Returns {ok, reason, anchorSize, presentedSize}.
// presentedRoot: Buffer (32B) from cp.seal(presentedRows).
function audit(witnessRepoDir, ledgerName, presentedSize, presentedRoot) {
  const latest = path.join(witnessRepoDir, 'checkpoints', slugify(ledgerName), 'LATEST');
  if (!fs.existsSync(latest)) return { ok: false, reason: 'no anchor present' };
  let anchor;
  try {
    anchor = cp.parse(fs.readFileSync(latest, 'utf8'));
  } catch (e) {
    return { ok: false, reason: `anchor unparsable: ${e.message}` };
  }
  if (anchor.size !== presentedSize) {
    return {
      ok: false,
      reason: `size mismatch: anchor pins ${anchor.size}, presented ${presentedSize}`,
      anchorSize: anchor.size, presentedSize,
    };
  }
  if (!anchor.root.equals(presentedRoot)) {
    return {
      ok: false,
      reason: 'root mismatch: presented ledger does not match anchored checkpoint',
      anchorSize: anchor.size, presentedSize,
    };
  }
  return { ok: true, anchorSize: anchor.size, presentedSize };
}

module.exports = { slugify, anchor, audit };
