# L3 witness quorum — design + client-side mechanism (witness service still gated)

Source: `memory/study/witnessing-study-2026-10-04.md` (R7, sealed ~08:20 GMT+8).
Status per study verdict: **L1+L2 adopted now, L3 designed-not-built, L4 rejected.**
This document is the design record named in the study ("L3 = design doc only this
quarter"). Nothing in this repo performs witnessing until a real external cosig
exists on disk (Nous-lang v5.67 erratum, adopted as a fleet honesty rule).

## Why L3 exists

L1 catches truncation *against anchored checkpoints*. L2 anchors those
checkpoints into two trust domains we already operate (witness-repo git history;
sibling-seal digest embedding). Both channels are **operator-run**. Git-as-broadcast
protects *retainers* (anyone holding a clone can detect force-push rewrites); a
*newcomer* with no prior state can be shown a rewritten history and cannot tell.

L3 closes the newcomer hole: **split-view resistance** — the log operator must
not be able to maintain two inconsistent ledger views without a witness
equivocating too.

## Roles

- **Log operator** (the sealer): runs `src/checkpoint.js` at every seal, keeps
  the checkpoint note current, serves it and consistency proofs.
- **Witness**: a small always-on service in a *different trust domain* that
  keeps only the latest checkpoint per origin, verifies the consistency proof
  (old size → new size) before cosigning, and persists the checkpoint before
  publishing its cosignature (persist-before-cosign atomicity, C2SP tlog-witness
  v1.0.0). Refusal semantics per C2SP: inconsistent = refuse (409-class), stale
  or malformed = refuse (422-class).
- **Client / auditor**: fetches the operator checkpoint plus witness cosigs,
  applies the policy file, advances only on quorum.

## Cosignature note format

Extends the L1 C2SP-*shaped* note; the signature line that is a documented seam
in `src/checkpoint.js` becomes real here:

```
origin\nsize\nbase64root\n
— <witness-name> <ed25519-sig-of-note-body>\n
```

The Ed25519 keypair per witness lives on the witness host, never in this repo
(fleet-witness operator key convention: `~/.config/fleet-witness/`, 0600,
pubkey under `KEYS/` in the anchor repo).

## Quorum rule

Operating point: **n = 3 witnesses across 3 trust domains (kimi1 host, z-worker
host, Casey host), k = 2 cosigs required.**

Scaling rule from transparency.dev 2026 (no monitors): split-view resistance
against m malicious witnesses requires a strict-majority threshold

```
t ≥ ⌈(n + m + 1) / 2⌉
```

— deliberately not a simple majority. Worked points:

| n | tolerated m (no monitors) | min t |
|---|---|---|
| 3 | 0 | 2 |
| 5 | 1 | 4 |
| 7 | 2 | 5 |

The study records both the bound and the n=3/k=2 takeaway; the operating point
is chosen for the fleet's three existing trust domains, and the bound is the
rule for *scaling* n — any future decision to tolerate a malicious witness must
recompute t from the formula, not pick a majority by feel.

## Fail-closed semantics (what k=2-of-3 buys, honestly)

With k=2 and at most one malicious witness, an equivocating operator can get
quorum on **at most one** view: the other view attracts ≤1 witness and clients
on it **fail closed** — they refuse to advance, they are not lied to. Split-view
resistance without monitors is *freezing*, not *convergence*. Cosigned-checkpoint
gossip between witnesses (a monitor in the transparency.dev sense) is the future
upgrade that relaxes the bound; it is out of scope for this design.

## Policy file (C2SP tlog-policy shape)

Client-side, named per deployment (Sigsum named-policy convention — log key +
witness keys + quorum rule, all client-held):

```json
{
  "name": "fleet-wal-prod",
  "origin": "superinstance/fleet-wal/v1",
  "log": { "ed25519": "<operator pubkey, KEYS/openclaw-main.pub>" },
  "witnesses": [
    { "name": "kimi1",     "ed25519": "<pubkey>" },
    { "name": "z-worker",  "ed25519": "<pubkey>" },
    { "name": "casey",     "ed25519": "<pubkey>" }
  ],
  "quorum": { "kind": "k-of-n", "k": 2, "n": 3 }
}
```

Clients verify: checkpoint signature (operator), each cosig against the named
witness key in *their* policy file, and quorum per `kind`. A checkpoint cosigned
by a key not in the policy is not merely insufficient — it is refused
(unrecognized-key fail-closed, mirroring C2SP 422-class).

## Non-goals (kept loud)

- **Content honesty**: witnesses are content-blind. A consistently fabricated
  ledger cosigns fine; content honesty stays the receipts' job, unchanged.
- **Trusted time (L4 TSA)**: rejected in the study — fleet receipts don't need
  third-party wall-clock; the moat is append-only proof, not trusted time.
- **Claiming "witnessing" before an artifact exists**: the Nous v5.67 erratum —
  mechanism ≠ witnessing. Until a cosig from a different trust domain exists on
  disk, this repo ships an anchoring mechanism, not a witness network.

## Build status (updated 2026-10-05 pulse)

Per the study, L3 is not a witness network until **(1)** extraction #4 lands (receipt/WAL
generic subset — fleet formats stabilizing) and **(2)** at least two of the three hosts
run always-on daemons. The client-side half shipped in v0.2 (this window):
`src/quorum.js` — policy-file loader (design-doc shape; policy k is CHECKED against
the strict-majority floor, never trusted), operator-note + witness-cosig verification
over the checkpoint.js v0.1 signer seam, duplicate-witness dedup,
fork=conflict (409-class) / unparsable-or-size-mismatch=malformed (422-class) /
verified-but-unlisted-key=unrecognized-key (fail-closed), and the
persist-before-cosign mirror: a quorum must attest the caller's OWN local re-seal.
20 pins in test/run.js; FAIL-first verified against pristine main (import dies —
quorum.js absent). Nous v5.67 still binds: with no real cosig from another trust
domain on disk, this repo ships an anchoring mechanism + a quorum checker, not a
witness network.

Remaining build order: witness service (fetch → consistency-verify → persist →
cosign, one file per origin) → cross-host drill: freeze one witness, verify the
remaining two keep quorum live and the frozen one's clients fail closed.

## Pristine-run receipt (fresh-audit v0, canonical tool quilt-tools#45)

- 2026-10-05 07:56 CST snowball pulse: `node tools/fresh-audit/fresh-audit.mjs SuperInstance/fleet-witness 7`
  → fresh clone of head `l3-quorum` (c21cb39): runner test/run.js PASS — 75 passed, 0 failed;
  verdict: all discovered runners GREEN in fresh clone. No phantom-RED class on this PR.
