# Upstream: `golang.org/x/mod`

**Pinned version: `v0.32.0`.**

This repository carries a TypeScript translation of the *verifying*
half of Go's transparency-log implementation, plus a Go program that
links the real thing and emits the vectors the translation is held to.

## Why this version, and not the latest

`x/mod` raised its own minimum Go version to **1.25.0 at v0.34.0**.
Aontu's Go port declares `go 1.24.7` and its CI matrix runs
`go-version: ['1.24', 'stable']`, so importing v0.34.0 or later from
`aontu/go` would break the 1.24 job. **v0.32.0 is the newest release
that still declares `go 1.24.0`**, and it is therefore the pin until
Aontu itself moves off 1.24 — which is a compatibility decision for
the language, not one to make by accident through a dependency bump.

Verified at pin time:

| x/mod | declares |
|-------|----------|
| v0.29.0 – v0.32.0 | `go 1.24.0` |
| v0.34.0 and later | `go 1.25.0` |

## Derived components

| This repository | Upstream |
|---|---|
| `src/hash.ts` | `sumdb/tlog/tlog.go` — `RecordHash`, `NodeHash`, hash encoding |
| `src/tree.ts` | `sumdb/tlog/tlog.go` — `StoredHashIndex`, `SplitStoredHashIndex`, `StoredHashCount`, `TreeHash`, `maxpow2` |
| `src/proof.ts` | `sumdb/tlog/tlog.go` — `CheckRecord`, `CheckTree` and their runners |
| `src/tile.ts` | `sumdb/tlog/tile.go` — `TileForIndex`, `HashFromTile`, `NewTiles`, `Tile.Path`, `ParseTilePath` |
| `src/note.ts` | `sumdb/note/note.go` (`Open`, key parsing, key hash) and `sumdb/tlog/note.go` (`ParseTree`) |
| `goref/main.go` | links `sumdb/tlog` and `sumdb/note` directly |

## Intentional divergences

1. **Only the verifying half is ported.** `ProveRecord`, `ProveTree`,
   `StoredHashes`, `ReadTileData`, `TileHashReader` and note *signing*
   are absent. A client checks; a log proves. Porting the proving half
   would put the serving code inside the component that must not trust
   it, and none of it would be reachable from a client.

2. **No 32-bit bitwise arithmetic.** Upstream uses `<<`, `>>` and `&`
   on `int64`. JavaScript's bitwise operators coerce to 32 bits, so a
   direct transliteration is correct for small trees and silently wrong
   past 2^31. Every shift is written as multiplication or division and
   every power-of-two mask as a modulus, exact to 2^53. **The rule for
   editors: no `<<`, `>>`, `&` or `|` on a tree index, ever.**

3. **Errors are `undefined` returns or thrown `Error`s**, not Go
   `error` values, and the two proof checkers return `boolean` rather
   than `error` — a checker whose failure mode is a falsy value cannot
   be accidentally treated as success by an unchecked call.

4. **Upstream `panic`s become thrown `Error`s** at the same places,
   marked `c8 ignore` where the surrounding bounds make them
   unreachable. They are kept rather than deleted so the translation
   stays line-comparable with upstream.

5. **`openNote` returns the list of verifiers that signed**, where
   upstream returns a `Note` with verified and unverified signature
   lists. The list is deliberately not reduced to a boolean: a caller
   must decide whether the set of signers is sufficient, which is what
   a K-of-N witness policy is.

## Changing any of this

1. Read the upstream diff for `sumdb/tlog` and `sumdb/note`.
2. Identify security fixes and behavioural changes.
3. Move the pin here and in `goref/go.mod`.
4. **Regenerate the vectors** (`npm run vectors`) and read the diff.
   A vector diff on an unchanged pin means the generator moved; a
   vector diff on a moved pin is upstream's behaviour changing and
   must be understood before it is accepted.
5. Port the applicable changes.
6. `npm test` — the differential suite is the gate.
7. Record any new divergence above.
