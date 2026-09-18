# Upstream: `golang.org/x/mod`

**Pinned version: `v0.32.0`.**

This repository carries a TypeScript translation of the *verifying*
half of Go's transparency-log implementation, plus a Go program that
links the real thing and emits the vectors the translation is held to.

## Why this version, and not the latest

`x/mod` raised its own minimum Go version to **1.25.0 at v0.34.0**, and
again to **1.26.0 at v0.41.0**. aontu's Go port declares `go 1.24.7` and
its CI matrix runs `go-version: ['1.24', 'stable']`, so importing
v0.34.0 or later from `aontu/go` would break the 1.24 job. The ceiling
that constraint sets is **v0.33.0, the newest release that still
declares `go 1.24.0`**, so the pin is one release short of it. Closing
that gap is a compatibility decision with a vectors regeneration behind
it; going past it is a decision for the language, and neither is one to
make by accident through a dependency bump.

Derived from `proxy.golang.org` on 2026-09-13:

| x/mod | declares |
|-------|----------|
| v0.28.0 – v0.33.0 | `go 1.24.0` |
| v0.34.0 – v0.40.0 | `go 1.25.0` |
| v0.41.0 | `go 1.26.0` |

## Derived components

| This repository | Upstream |
|---|---|
| `src/hash.ts` | `sumdb/tlog/tlog.go`: `RecordHash`, `NodeHash`, hash encoding |
| `src/tree.ts` | `sumdb/tlog/tlog.go`: `StoredHashIndex`, `SplitStoredHashIndex`, `StoredHashCount`, `TreeHash`, `maxpow2` |
| `src/proof.ts` | `sumdb/tlog/tlog.go`: `CheckRecord`, `CheckTree` and their runners |
| `src/tile.ts` | `sumdb/tlog/tile.go`: `TileForIndex`, `HashFromTile`, `NewTiles`, `Tile.Path`, `ParseTilePath` |
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
   than `error`: a checker whose failure mode is a falsy value cannot
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

6. **Base64 must round-trip, which refuses two kinds of spelling
   upstream accepts.** Upstream reads `data, err := base64.StdEncoding
   .DecodeString(s)` and refuses on `err`. Node's `Buffer` has no
   `err`: it skips non-alphabet bytes, accepts missing padding and
   accepts the base64url alphabet, so a length check alone lets one
   hash, one signature or one key have unboundedly many spellings. Each
   decode site therefore requires the bytes to re-encode to exactly the
   input. That closes the accepting direction, and costs two kinds of
   input upstream would take: a value with an embedded `\n` or `\r`,
   which Go's decoder skips, and a value whose final character carries
   non-zero spare bits, which `StdEncoding` tolerates because it is not
   `StdEncoding.Strict()`. **The refusals are the point rather than a
   side effect**: admitting either would put the extra spellings
   straight back, and a checkpoint is compared as TEXT between
   witnesses, so a second spelling is a second checkpoint. No encoder
   produces either.

7. **`openNote` takes a string, so two UTF-8 questions are settled
   before it is called.** Upstream takes `[]byte` and distinguishes a
   DECODE ERROR from a legitimately encoded U+FFFD (`r ==
   utf8.RuneError && size == 1`); it also requires `utf8.ValidString`
   on a signer name. A JavaScript string has already been decoded, and
   a decode error has already become U+FFFD, so neither test can be
   made here. This port refuses U+FFFD outright, which refuses a note
   whose text legitimately contains one — the availability direction,
   and the only one available to it.

## Changing any of this

1. Read the upstream diff for `sumdb/tlog` and `sumdb/note`.
2. Identify security fixes and behavioural changes.
3. Move the pin here and in `goref/go.mod`.
4. **Regenerate the vectors** (`npm run vectors`) and read the diff.
   A vector diff on an unchanged pin means the generator moved; a
   vector diff on a moved pin is upstream's behaviour changing and
   must be understood before it is accepted.
5. Port the applicable changes.
6. `npm test`: the differential suite is the gate.
7. Record any new divergence above.
