# fleet-witness

Fleet WAL **completeness** layer. The fleet's layer-0 receipt ledger (five-opcode,
fnv1a-64, prev-link) is tamper-loud for edit/insert — but **clean suffix truncation
verifies clean**: delete the last N rows and the chain still checks out. fleet-witness
closes that gap with RFC 6962 Merkle checkpoints that bind *size + root* at every seal.

Built per the witnessing study (`memory/study/witnessing-study-2026-10-04.md`,
process-refinement R7): **L1+L2 adopted now, L3 designed-not-built, L4 rejected.**
Zero-dep stdlib Node, standalone-extraction style (mirrors SuperInstance/coev).

## What ships in v0

- `src/tree.js` — RFC 6962 §2.1 Merkle tree hash (`MTH`) over WAL rows + §2.1.2
  consistency proofs. Pinned against an independent Python `hashlib` vector pass
  (empty/single/multi/unbalanced trees; 2→3, 1→3, 3→7 proofs).
- `src/checkpoint.js` — C2SP-*shaped* checkpoint note
  (`origin / size / base64root`) + anchor digest (`SHA-256` of the note body).
  Origin is `superinstance/fleet-wal/v1`. The Ed25519 signature line is a
  documented seam — the fleet signing key lives outside this repo; **no
  "witnessing" is claimed until a real external cosig exists on disk**
  (Nous v5.67 erratum, adopted as an honesty rule in the study).

## The demo in one breath

Anchored checkpoint at size 5. Delete rows 4–5: the L0 fnv1a chain still verifies
clean (that's the hole); the sealed checkpoint at size 5 refuses to agree with a
re-seal of the truncated ledger. See `test/run.js` — the truncation catch is
pinned, not narrated.

## Honest limits (from the study, kept loud)

- Truncation is caught only against *anchored* checkpoints; rows written and
  truncated between two anchors are invisible (anchor every seal — it costs one
  git commit).
- v0 `verifyConsistency` is audit-by-recompute: it needs the presented rows.
  Streaming (data-free) proof verification is deferred to extraction #4.
- Git-as-broadcast (L2 anchor channel, next window) protects retainers, not
  newcomers; split-view resistance waits for L3 witness quorum (k=2-of-3,
  strict-majority bound from transparency.dev 2026).
- Witnesses are content-blind; content honesty stays the receipts' job.

## Run

```
node test/run.js
```

## Status

v0.1.0 — tree + checkpoint core, 16 pins green. Anchor channels (witness-repo git
commit + sibling-seal digest embedding) are the next window. L3 policy file
designed in the study, not built.
