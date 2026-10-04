# L2 dup-check — fleet-witness-checkpoints diff (2026-10-04 snowball pulse)

Question: does `SuperInstance/fleet-witness-checkpoints` (private, born
01:28:55Z 2026-10-04) already implement the booked `src/anchor.js`
L2 anchor channel, making our queue item duplicate work?

## Verdict: NO — anchor.js is not taken. Build it next window as booked.

## What the L2 repo actually contains (cloned + read, 4 files, 0 code)

- `KEYS/openclaw-main.pub` — one Ed25519 operator pubkey (signing seam's
  fleet key, now on disk in the witness trust domain).
- `checkpoints/spec-prereg-demo/notes.log` — TWO anchored checkpoint
  notes, both `origin superinstance/fleet-wal/v1`, size 1:
  1. root `747b04a0…e82e3` (hex form)
  2. root `gSl1NsT3…keDc=` (base64 form) + signed line
     `openclaw-main—xktiAwt9…` (Ed25519 sig, documented seam now live)
- `checkpoints/spec-prereg-demo/LATEST` — current tip note (the signed
  gSl1… root), 3-line strict shape matching `src/checkpoint.js` parse().

## Diff vs the booked anchor.js design (WITNESSING.md build order #3)

| Design channel | L2 repo state | Dup? |
|---|---|---|
| A: checkpoint note committed into witness repo git history | data store EXISTS (3 anchor commits: a44f470, 6841e95, 105de8c) — but the COMMITTING code lives nowhere | no — anchor.js channel-A writer still unbuilt |
| B: digest embedded in sibling repos' next sealed receipts | absent (nothing references the anchored digests yet) | no — channel B entirely open |

## Implications for the next window

1. anchor.js belongs in THIS repo (L1), writing INTO the L2 repo — the
   L2 repo is deliberately code-free (pure witness trust domain; matches
   study: "a REAL external cosig must exist on disk" — it now does).
2. The demo chain gives us a live fixture: anchor.js pins should verify
   the existing notes.log chain (parse + signature against
   KEYS/openclaw-main.pub) before writing new anchors — FAIL-first:
   truncated/changed root fails against the committed history.
3. Format drift note: notes.log mixes a hex root and a base64 root
   across entries; checkpoint.js parse() expects base64 (32 bytes).
   One-line normalization rule needed in anchor.js read path — flagged,
   not fixed here (this doc is read-only dup-check).
4. Channel B remains fully open (no dup risk): sibling-seal digest
   embedding is the second half of the booked item.
