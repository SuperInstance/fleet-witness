'use strict';
// C2SP-shaped checkpoint note over a WAL's L1 Merkle root.
// Study decision: L1+L2 now; note format is OURS (do not claim C2SP
// wire-compat until byte-tested, per RFC 9162 lesson in the study).
// v0 emits the note body + anchor digest; v0.1 fills the documented
// signer seam: Ed25519 over the exact note-body bytes (the same bytes
// digest() anchors), sig line appended as "sig:<base64>\n". The fleet
// signing key lives outside this repo; sign/verify take PEM keys so any
// holder can sign and anyone with the .pub can verify offline.

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
// Signed note = body + "sig:<base64>\n"; the sig line never enters the
// anchored digest (channel invariant, pinned).
function parse(text) {
  const lines = text.split('\n');
  if (lines[0] !== ORIGIN) throw new Error('origin mismatch: ' + lines[0]);
  const size = Number(lines[1]);
  if (!Number.isSafeInteger(size) || size < 0) throw new Error('bad size: ' + lines[1]);
  const root = Buffer.from(lines[2], 'base64');
  if (root.length !== 32) throw new Error('bad root len: ' + root.length);
  // strict tail: either exactly ["", ] (trailing newline of the unsigned
  // body) or exactly ["sig:<b64>", ""]. Junk lines before/after the sig
  // line and extra trailing lines are shape drift and throw — a verified
  // note must be byte-canonical apart from the sig seam.
  const tail = lines.slice(3);
  let sig = null;
  if (tail.length >= 1 && tail[0].startsWith('sig:')) {
    if (tail.length !== 2 || tail[1] !== '') throw new Error('junk after sig line');
    sig = Buffer.from(tail[0].slice(4), 'base64');
  } else {
    if (tail.length !== 1 || tail[0] !== '') throw new Error('unexpected trailing line: ' + JSON.stringify(tail[0]));
  }
  return {
    origin: lines[0], size, root,
    signed: sig !== null,
    sig,
    body: lines.slice(0, 3).join('\n') + '\n',
  };
}

// seal a WAL (array of row strings) -> checkpoint record.
function seal(rows) {
  const r = tree.root(rows);
  return { size: rows.length, root: r, note: note(rows.length, r), digest: digest(rows.length, r) };
}

// signer seam (v0.1): Ed25519 over the exact note-body bytes.
// privPem: PKCS8 PEM (fleet key at ~/.config/fleet-witness/key.pem, 0600).
function sign(size, root, privPem) {
  const body = note(size, root);
  const sig = crypto.sign(null, Buffer.from(body), privPem);
  return body + 'sig:' + sig.toString('base64') + '\n';
}

// verify a signed note against a PEM/SPKI public key.
// Returns the parsed fields + ok; throws on malformed shape. A missing
// sig line verifies ok:false (unsigned notes stay verifiable, honest).
function verify(text, pubPem) {
  const p = parse(text);
  if (!p.signed) return { ...p, ok: false, reason: 'unsigned' };
  const ok = crypto.verify(null, Buffer.from(p.body), pubPem, p.sig);
  return { ...p, ok };
}

module.exports = { ORIGIN, note, digest, parse, seal, sign, verify };
