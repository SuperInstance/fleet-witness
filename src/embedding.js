'use strict';
// Channel (b): sibling-seal digest embedding.
// A sibling ledger (any fleet repo sealing its own WAL) can append ONE row
// binding its ledger to an anchored fleet-witness checkpoint. Anyone holding
// the witness note (from the witness-repo anchor channel) can then verify,
// from the sibling ledger alone, WHICH checkpoint the ledger claimed — and
// truncation of the sibling after that row fails against the anchored size.
//
// Honest limits (kept loud, per study honesty rules):
// - The embedding binds the sibling to a checkpoint; it proves nothing about
//   the witness note's provenance. Provenance = channel (a), the witness-repo
//   git anchor. Embedding + anchor together = the L2 channel pair.
// - Embedding a digest is NOT "witnessing". No external cosig exists yet;
//   the Nous v5.67 erratum rule stands.
// - The row is an ordinary WAL row: it extends the sibling's L0 chain like
//   any other row. It adds no trust by itself — only cross-repo binding.

const cp = require('./checkpoint.js');
const crypto = require('crypto');

const ROW_PREFIX = 'BIND witness-anchor';

// Build the embedding row for a sealed checkpoint.
// Shape (single line, fleet row style):
//   BIND witness-anchor origin=superinstance/fleet-wal/v1 size=<n> digest=<64 lowercase hex>
function embedRow(sealed) {
  if (!sealed || !Buffer.isBuffer(sealed.digest)) throw new Error('seal first: pass checkpoint.seal(rows)');
  if (!Number.isSafeInteger(sealed.size) || sealed.size < 0) throw new Error('bad seal size');
  return `${ROW_PREFIX} origin=${cp.ORIGIN} size=${sealed.size} digest=${sealed.digest.toString('hex')}`;
}

// Strict parse of an embedding row; throws on any shape drift.
function parseRow(row) {
  if (typeof row !== 'string' || row.includes('\n')) throw new Error('row must be one line');
  const parts = row.split(' ');
  if (parts[0] !== 'BIND' || parts[1] !== 'witness-anchor') throw new Error('not an embedding row');
  const fields = {};
  for (const f of parts.slice(2)) {
    const eq = f.indexOf('=');
    if (eq < 1) throw new Error('bad field: ' + f);
    fields[f.slice(0, eq)] = f.slice(eq + 1);
  }
  if (fields.origin !== cp.ORIGIN) throw new Error('origin mismatch: ' + fields.origin);
  const size = Number(fields.size);
  if (!Number.isSafeInteger(size) || size < 0) throw new Error('bad size: ' + fields.size);
  if (!/^[0-9a-f]{64}$/.test(fields.digest || '')) throw new Error('bad digest hex');
  return { origin: fields.origin, size, digest: fields.digest };
}

// Verify an embedding row against a PRESENTED witness note (the note body,
// fetched from wherever the verifier trusts — normally the witness-repo
// anchor channel). Recomputes the digest from the note; never trusts the
// row's digest field alone.
function verifyRow(row, noteText) {
  const f = parseRow(row);
  const n = cp.parse(noteText); // strict note shape; throws on drift
  if (n.size !== f.size) return { ok: false, reason: 'size-mismatch', rowSize: f.size, noteSize: n.size };
  const recomputed = crypto.createHash('sha256').update(noteText).digest('hex');
  if (recomputed !== f.digest) return { ok: false, reason: 'digest-mismatch' };
  return { ok: true, size: f.size, digest: f.digest };
}

module.exports = { ROW_PREFIX, embedRow, parseRow, verifyRow };
