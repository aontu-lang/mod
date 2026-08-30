# `@aontu-lang/mod`

The transparency-log **client** for the [Aontu](https://github.com/aontu-lang/aontu)
module system: a TypeScript port of the verifying half of
`golang.org/x/mod/sumdb/tlog`, held to upstream's own output by golden
vectors that upstream generated.

This is [G10](https://github.com/aontu-lang/aontu/blob/main/docs/capability-review/g10-transparency.md)
phase 2. It is useful with no log running: it verifies checkpoints and
proofs that a lockfile already carries.

## What is here

| | |
|---|---|
| `src/hash.ts` | leaf and node hashing, with RFC 6962 domain separation |
| `src/tree.ts` | stored-hash addressing and tree roots |
| `src/proof.ts` | **the two verifiers** — inclusion and consistency |
| `src/tile.ts` | tile coordinates, paths and hash extraction |
| `src/note.ts` | signed checkpoints: key ids, Ed25519 verification, tree heads |
| `goref/` | the Go program that links real upstream and emits the vectors |
| `vectors/` | the golden vectors, committed |

## What is deliberately not here

**The proving half.** No `ProveRecord`, no `ProveTree`, no signing. A
client checks; a log proves. See `src/proof.ts`.

**The service.** Rate limits, quotas, key custody and deploy live in
`aontu-lang/system`. Nothing a client relies on to verify may live
there — a log whose auditor cannot be rebuilt from public code is a
database with extra steps.

## The differential gate

```sh
npm run vectors   # regenerate from pinned upstream Go
npm test          # check this port against them
```

689 proof vectors, of which **374 expect rejection**. A verifier that
returned `true` unconditionally would pass every positive case and fail
those. That asymmetry is the point: see `test/vectors.test.ts`.

Read [`UPSTREAM_GO_MOD.md`](UPSTREAM_GO_MOD.md) before changing
anything in `src/`.

## Licence

MIT, except the material derived from `golang.org/x/mod`, which is
BSD-3-Clause — see [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
