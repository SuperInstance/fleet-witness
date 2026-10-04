'use strict';
// C2SP-shaped checkpoint note over a WAL's L1 Merkle root.
// Study decision: L1+L2 now; note format is OURS (do not claim C2SP
// wire-compat until byte-tested, per RFC 9162 lesson in the study).
// v0 emits the note body + anchor digest; the Ed25519 signature line is
// a documented seam (fleet signing key lives outside this repo).

const crypto = require('crypto');
const tree = require('./tree.js');

const ORIGIN = 'superinstance/fleet-wal/v1';

// body: "origin\nsize\nbase64root\n" — sig line appended by signer seam.
function note(size, root) {
  return `${ORIGIN}\n${size}\n${root.toString('base64')}\n`;
}

function digest(size, root) {
  return crypto.createHash('sha256').update(note(size, root)).digest();
}

// parse a note body (unsigned or with sig line present); strict shape.
function parse(text) {
  const lines = text.split('\n');
  if (lines[0] !== ORIGIN) throw new Error('origin mismatch: ' + lines[0]);
  const size = Number(lines[1]);
  if (!Number.isSafeInteger(size) || size < 0) throw new Error('bad size: ' + lines[1]);
  const root = Buffer.from(lines[2], 'base64');
  if (root.length !== 32) throw new Error('bad root len: ' + root.length);
  return { origin: lines[0], size, root, signed: lines.length > 4 && lines[3].startsWith('sig:') };
}

// seal a WAL (array of row strings) -> checkpoint record.
function seal(rows) {
  const r = tree.root(rows);
  return { size: rows.length, root: r, note: note(rows.length, r), digest: digest(rows.length, r) };
}

module.exports = { ORIGIN, note, digest, parse, seal };
