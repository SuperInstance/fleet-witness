# Witnessing layer design (condensed from the study)

Full source: `memory/study/witnessing-study-2026-10-04.md` (sealed 2026-10-04 ~08:20 GMT+8).
Lane: study → build. Author: snowball pulse.

## Layers

| Layer | Status | Mechanism |
|---|---|---|
| L1 Merkleize | **built (this repo, v0)** | RFC 6962 root over WAL rows; checkpoint binds size+root |
| L2 anchor | build next window | checkpoint note committed into a witness repo's git history + digest embedded in sibling repos' next sealed receipts — two trust-domain channels we already operate |
| L3 witness quorum | **mechanism built (this repo, v0.2)** — client-side check only; witness daemons still design-gated | n=3 witnesses across 3 trust domains (kimi1 host, z-worker, Casey), k=2 per strict-majority bound t ≥ ⌈(n+m+1)/2⌉ (transparency.dev 2026); C2SP tlog-policy-shaped policy file |
| L4 TSA | rejected | fleet receipts don't need third-party wall-clock; moat is append-only proof, not trusted time |

## Key external readings

- C2SP tlog-witness v1.0.0 (Mar 2026): persist-before-cosign atomicity; 409/422 semantics.
- Sigsum named policies: log key + witness keys + quorum rule, client-side — reusable shape.
- Calybris-core (edge-watch flag): Ed25519 decision receipts + anchored WAL detecting
  clean suffix truncation — closest external kin; validates L1+L2 as product, not research.
- Nous-lang v5.67 erratum: mechanism ≠ witnessing; a REAL external cosig must exist on disk.
- RFC 9162 (CT v2): reuse Merkle algorithms, don't claim wire-compat. Our checkpoint note
  is our own format until byte-tested against C2SP.

## Build order (cheapest-first, named in the study)

1. `src/tree.js` — RFC 6962 root + consistency proofs, pinned vs vectors ✅ (this window)
2. `src/checkpoint.js` — C2SP-shaped note + Ed25519 sig seam ✅ (this window, sig seam documented)
3. `src/anchor.js` \— git witness-repo channel + sibling-seal digest channel \✅ (merged #6/#1/#3); FAIL-first: truncated WAL passes L0, fails anchored-checkpoint compare
4. `src/quorum.js` \— L3 witness quorum: client-side named policy, strict-majority bound, persist-before-cosign, fork=conflict (409-class) \✅ (this window)
5. `src/truncate-demo.js` \— standalone sales artifact driving the whole story \✅ (this window)
6. Pins: vectors, truncation catch, cross-channel agree \← vectors + truncation landed
