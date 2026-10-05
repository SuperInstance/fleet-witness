# ONBOARDING — fleet-witness

> Seed doc (fleet handoff 2026-10-06). Read with `README.md` (v0 + honest
> limits), `docs/WITNESSING.md` (the L0–L4 study), `docs/L3-QUORUM.md`.
> Mesh context: `SuperInstance/fleet-seeds` → `docs/handoff-2026-10-06/ORG-MESH.md`.

## 1. What this repo is now

The fleet WAL **completeness** layer. The org's layer-0 receipt ledger
(five-opcode, fnv1a-64, prev-link) is tamper-loud for edit/insert — but clean
**suffix truncation verifies clean**: delete the last N rows and the chain
still checks out. fleet-witness closes that hole with RFC 6962 Merkle
checkpoints binding **size + root** at every seal. Zero-dep stdlib Node,
standalone-extraction style (mirrors `SuperInstance/coev`).

What ships: `src/tree.js` (RFC 6962 §2.1 MTH + consistency proofs, pinned
against an independent Python hashlib pass), `src/checkpoint.js` (C2SP-shaped
note + anchor digest; Ed25519 sig line is a documented seam), `src/embedding.js`
(channel (b): a sibling ledger appends one ordinary WAL row binding its ledger
to an anchored checkpoint), `src/quorum.js` (L3 client-side mechanism, in PR #7),
`src/truncate-demo.js` (live-narrated sales artifact, in PR #8). Suite 59/59
(post-#8) / 75/75 (post-#7); pin command is **`node test/run.js`** — there is
no package.json test script.

**Open at handoff:** PRs #7 (L3 quorum mechanism: named-policy loader,
witness-cosig verify over the checkpoint.js v0.1 signer seam, dedup, conflict
classes fork=409/malformed=422/unrecognized-key fail-closed, persist-before-
cosign mirror) and #8 (truncate-demo). Both carry committed pristine-audit
receipts.

## 2. How it got here (the momentum)

1. **The study first** (`memory/study/witnessing-study-2026-10-04.md`,
   process-refinement R7): L1+L2 adopted now, L3 designed-not-built, L4
   rejected. The repo exists because the study said exactly what to build and
   what not to.
2. **Honesty rule adopted before code.** Nous v5.67 erratum: **no "witnessing"
   is claimed until a real external cosig exists on disk.** The Ed25519 line
   is a seam, not a promise. This is why the README's honest limits are loud.
3. **L1 → L2 → seam → L3 mechanism.** Truncation/rollback/forgery detection
   (L1); git anchoring of checkpoints to the witness-checkpoints repo via
   `src/anchor.js` (L2, receipted live); the signer seam (#5, merged); the L3
   quorum *mechanism* (#7) — client-side policy + cosig verification, built so
   that a witness network could exist without trusting the witnesses.
4. **The demo as proof.** truncate-demo (#8) narrates the whole attack story
   live and exits 0 only if every attack is caught — a sales artifact that is
   also a pin.

## 3. The vision

*Completeness, not just consistency.* Tamper-evidence is cheap; **deletion
evidence** is the hard half of trust. The fleet's receipts are only as strong
as the ledger that survived. fleet-witness's stance: a witness is a mechanism
anyone can run, a checkpoint is a claim anyone can verify, and nothing is
"witnessed" until an external cosig says so on disk. Mechanism, not network —
the network is deliberately gated (below).

## 4. Roadmaps (several directions)

**Going now:** merge #7 + #8; then the L3 witness *service* remains the
designed-not-built item — **gated on extraction #4 (receipt/WAL generic
subset from the fleet formats) + two always-on hosts**. Do not build daemons
before those land.

**Sketched futures:**
- **Quorum verification loop.** Once #7 merges, a scheduled lane could
  cross-check checkpoint cosigs org-wide (the twin-notary pattern already
  prototyped with Cloudflare anchors).
- **Consistency-proof serving.** `src/tree.js` already computes RFC 6962
  consistency proofs; exposing them (CLI → small server) makes the checkpoints
  repo independently auditable without cloning everything.
- **TMA-NM alignment.** The June-2026 Louck result (write-time origin binding
  is *necessary*, 68% laundering ASR otherwise) is the academic proof of this
  repo's doctrine — a docs node citing it strengthens the moat claim
  "enforcement-gate witnessing has zero competitors."
- **stone-v1 adjacency.** If Casey's `zero-msg-test` lane opens, sealing
  wake-cycle decision chains through quilt-stone would mint a VERIFIED edge
  here (cite-not-build until then).

## 5. How it meshes

- Anchors live in **`SuperInstance/fleet-witness-checkpoints`** (private);
  the Ed25519 fleet key pubkey is committed there (`KEYS/openclaw-main.pub`).
- Doctrine shared with: the fleet WAL (five-opcode, fnv1a-64 — same idiom as
  MicroMoth cell ledgers and quilt-jev-toolkit organs), `quilt-tools`
  (fresh-audit receipts, referral-graph edges #31–#32 witness-flavored),
  `doubt-ledger` (coverage = what trust lets through; witnessing = what
  deletion let through).
- The referral-graph upgrade edge exoj→pincher (#29, flip in quilt-tools#50)
  was verified the same way this repo verifies everything: cited BY NAME in a
  merged target-repo PR.
- Org state: `fleet-seeds` → `docs/handoff-2026-10-06/HANDOFF.md`.
