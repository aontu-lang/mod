# How the verifier is built

The reasoning behind the shape of `src/`, `test/` and `goref/`: the
rules a change has to keep, and why each one holds. What the port
derives from upstream, and where it diverges, is in
[UPSTREAM_GO_MOD.md](../../UPSTREAM_GO_MOD.md); what a client verifies
is in [PROOF-CONTRACT.md](../../PROOF-CONTRACT.md). Read both first.

## Only the verifying half

A client checks; a log proves. `ProveRecord`, `ProveTree`, the append
side and note signing are absent, and stay absent: each would put the
serving code inside the component that must not trust it, and none of
it is reachable from a client. The same holds for the key proof, whose
key `aontu pkg keygen` mints and whose signature `aontu publish` makes.

Nothing here fetches anything. `HashReader` is injected rather than
imported, as it is upstream, so where the hashes come from (memory,
tiles, a file) stays the caller's business and the verifier has no
transport in it.

## Hashing

- **Domain separation is the point of `src/hash.ts`.** A leaf is
  hashed under a `0x00` prefix and an interior node under `0x01`
  (RFC 6962, section 2.1), so no leaf encoding can be read as a node.
  Dropping the prefix, or applying it to the wrong side, is the
  second-preimage hole in a Merkle tree.
- **A hash is a `Uint8Array` of 32 bytes**, because every use is byte
  concatenation. `formatHash` and `parseHash` are the boundary.
- **`formatHash` writes standard base64 with padding**, as Go's
  `Hash.String()` does. The canonical package hash elsewhere in aontu
  is base64url, and confusing the two gives a string that looks right
  and compares wrong.
- **`hashEqual` has no early return.** The hashes are public, so timing
  reveals nothing, but a comparison that cannot short-circuit is one
  nobody has to reason about.

## Arithmetic

Upstream is `int64` arithmetic with `<<`, `>>` and `&`. JavaScript's
bitwise operators work on 32 bits, so a direct transliteration is right
for small trees and silently wrong past 2^31 stored hashes, which a
real log reaches. Every shift in `src/tree.ts` and `src/tile.ts` is
written as multiplication or division and every mask as a modulus,
exact to 2^53. No `<<`, `>>`, `&` or `|` is ever applied to a tree
index.

- `shr` in `src/tile.ts` answers 0 for a shift count past 53, which is
  what the arithmetic means; JavaScript's `>>` masks the count to five
  bits, so `x >> 64` is `x >> 0`.
- `keyHash` reads the key hash with `readUInt32BE`, because a bitwise
  shift would sign it.

## Proofs

- **Both checkers reject by default.** Every path that is not a
  completed, length-exact, root-matching verification returns `false`.
  A verifier whose failure mode is `true` passes every positive test,
  which is why most vectors are rejections.
- **The bounds are part of the check.** A proof for a record outside
  the tree returns `false` rather than throwing: the numbers come off
  the wire, and a throw would turn a hostile response into a crash.
- **A proof with hashes left over is refused**, not trimmed. Accepting
  the surplus would let one proof stand for several tree shapes.
- **`checkTree` compares both roots.** Checking only the new root
  accepts a proof that rebuilds the right tree from the wrong history,
  which is the rewrite the check exists to detect.
- **Upstream's `panic`s stay as thrown errors**, excluded from coverage
  where the surrounding bounds make them unreachable, so the
  translation stays line-comparable with upstream.

## Tiles and their paths

A tile is a fixed-height block of the log's hashes at a stable path,
which is what lets a log be served as static files. A client that
computes a different path fetches a 404 and reads it as a missing tile,
so both encodings are held exactly.

- **`src/c2sp.ts` is the encoding this package commits to**: C2SP
  `tlog-tiles`, which Rekor v2 serves. `tile/<L>/<N>`, a partial tile
  as `tile/<L>/<N>.p/<W>` with W from 1 to 255, and entry bundles as
  `tile/entries/<N>`. N is written in groups of three digits, every
  group but the last prefixed with `x`: 1234067 is `x001/x234/067`. The
  height, 8, is not in the path.
- **`src/tile.ts` keeps Go sumdb's encoding** for the differential
  vectors only: `tile/<H>/<L>/<N>`, with the height in the path and
  level -1 spelled `data`. A C2SP path is malformed there.
- **Each parser formats the parsed tile again and requires the same
  path back.** That refuses every second spelling of one tile (a
  leading zero, a redundant `x000/`) for the whole path at once. Without
  it a tile has more than one name, and a cache keyed by path holds it
  twice.
- **`intOf` accepts leading zeros**, and must: `000` is the ordinary
  spelling of a zero group, and Go's `strconv.Atoi("000")` is 0. The
  round trip above refuses the spellings a leading zero could add.
- **`hashFromTile` refuses rather than reads past**: a tile shorter
  than its width, or a tile that does not hold the index asked for,
  stops a server answering one tile's request with the bytes of another.

## Signed notes

A checkpoint travels in a signed note: text, a blank line, then one or
more signature lines, each `— <name> <base64(keyhash || signature)>`.
A signature line names its key by server name and a 32-bit key hash, so
one note can carry the log's signature beside any number of witness
cosignatures, and a client finds the ones it trusts without
understanding the rest.

- **The key hash covers the algorithm byte.** It is the first four
  bytes, big-endian, of SHA-256 over the name, a newline and the
  encoded key, and the encoded key begins with the algorithm byte.
  Hashing the bare key gives an id no other implementation agrees with,
  which shows up only as an unknown verifier.
- **A name holds no whitespace and no `+`**, the field separator of a
  verifier key. Whitespace is Go's `unicode.IsSpace` set, written out as
  code points in `GO_SPACE`: JavaScript's `\s` differs in both
  directions (it omits U+0085 and includes U+FEFF), and U+2028 inside a
  regular expression literal ends the literal.
- **An unknown signer is skipped; a bad signature by a known key is an
  error.** Skipping strangers is what lets a note gather cosignatures
  without breaking older clients. A known key's signature that does not
  verify is an attack, not a stranger.
- **A note no known key signed is refused**, as upstream's
  `UnverifiedNoteError` refuses it, not opened with an empty list. A
  usable checkpoint always carries the log's own signature, which the
  client knows, so the refusal costs the witness protocol nothing.
- **`openNote` returns the verifiers that signed**, not a boolean, so
  that a caller decides whether the set is enough: a K-of-N witness
  policy is a predicate over that list. A key that signed twice is
  listed once.
- **Control characters, other than newline, are refused**, so a note
  cannot print a second apparent note inside itself, and a note with
  more than `MAX_SIGS` signature lines is refused before any signature
  is checked, since the work is per signature and the sender would
  otherwise choose it.
- **Every base64 field must re-encode to itself.** Node's `Buffer`
  skips junk, accepts missing padding and the base64url alphabet, so
  without the round trip one key or signature has many spellings.
  UPSTREAM_GO_MOD.md records what this costs.
- **A checkpoint's tree size has one spelling.** `parseTree` refuses
  `007`, `+7` and ` 7`, because witnesses compare checkpoints as text,
  and two spellings are two checkpoints. Lines after the root hash are
  ignored, as upstream ignores them, so a later format can add lines.

## The key proof

[PROOF-CONTRACT.md](../../PROOF-CONTRACT.md) states the encoding.
Beyond it:

- **A signer id is exact.** Forty-three base64url characters carry two
  more bits than a 32-byte key, so four ids decode to one key. The id
  must re-encode to itself, which leaves one.
- **A key of small order is refused before the signature is read**, as
  is a key whose encoding is not canonical: a signature under a
  small-order point verifies for any message.
- **Node has no raw Ed25519 key import**, so a key is wrapped in the
  fixed SPKI DER prefix for id-Ed25519 (RFC 8410).

## The vectors

`goref/main.go` links the pinned upstream and writes
`vectors/tlog.json`; `test/vectors.test.ts` holds the port to it.
A port that passes only tests its author wrote agrees with its author,
which is the thing in doubt; the vectors check it against the code Go's
checksum database runs.

- **The output is deterministic.** Record i is the bytes of
  `record <i>`, and the note key comes from a fixed seed, so a rerun on
  the same pin writes the same file and a diff means something moved.
  The seed is test material, published so that anyone can re-derive
  the file.
- **Upstream's stored-hash array ships in the vectors**, so `treeHash`
  is checked against upstream's hashes rather than against a second
  append side, which the client does not have and whose errors could
  cancel against the port's.
- **Tree sizes are chosen for shape**: the degenerate trees of one and
  two records, the ragged ones where `maxpow2` splits unevenly, the
  perfect ones, and sizes that reach past one tile.
- **Indexes past 2^31 are generated, never written by hand**: a
  hand-written expectation for arithmetic that large is a guess.
- **Most proof cases are rejections**: one bit flipped in a sibling, a
  proof for the wrong leaf, the right proof against the wrong root.
  Flipping one bit is the smallest corruption a verifier must catch.
- **An empty proof is `[]`, never `null`**: it is a real case, and the
  JSON must not blur it.
- `test/guards.test.ts` holds the refusals the vectors cannot reach,
  because upstream's generator never produces the input.

## Coverage

`src/index.ts` ends with a line after its last export. Without one,
source-mapped coverage reports two uncovered lines at the end of the
file, an artefact of the source map rather than a gap; a coverage
directive cannot answer it, because it covers the lines that follow it.
