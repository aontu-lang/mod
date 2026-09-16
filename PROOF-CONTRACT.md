# The proof contract

A published package carries a **proof**: evidence that a named identity
signed the manifest a consumer is about to trust. The contract is
[ADR-024](https://github.com/aontu-lang/aontu/blob/main/ADR.md) of the
engine repository, and this package holds the client half of it. What a
client verifies never changes with the provider; which object it fetches
and how the signature is encoded does.

## What a client verifies

Three clauses, in order, for every package acquired from a repository:

1. **A signature over the manifest**, by an identity the proof names.
   The signed bytes are derived from the manifest's digest, never from
   the manifest itself, so the manifest can be checked byte for byte
   against the archive before the signature is looked at.
2. **That the client's trust configuration accepts that identity for
   the package's name.** The `repo.trust` block of the consumer's
   `pkg.aon` maps a pattern (`corp.example/*`) to a signer and an
   inclusion requirement. A proof by a signer the entry does not name is
   refused before a byte of the archive is read.
3. **Where the entry requires it, inclusion of the signed manifest in a
   transparency log** whose checkpoint key the client trusts. The log
   is served as C2SP `tlog-tiles`; `checkRecord`, `checkTree`,
   `openNote` and `parseTree` in this package verify it, and
   `c2spTilePath` names the tiles to fetch.

The contract names no provider. A provider is one encoding of the three
clauses, and a change in a provider's terms is answered by another
provider under the same contract, never by a change to what the client
checks.

## The two encodings

| Provider | Object | Encoding | Identity | Log |
|---|---|---|---|---|
| **key** | `<version>.sig` | `aontu-signature/v1` (below) | a named Ed25519 key, `ed25519:<base64url public key>` | none in v1 |
| **sigstore** | `<version>.sigstore.json` | `sigstore-bundle/v0.3`, stored verbatim | a Fulcio certificate carrying the forge's OIDC claims | Rekor v2, C2SP `tlog-tiles` |

The key provider is the minimal one: what `aontu pkg serve` serves, what
a private package carries, and what proved the seam before the first
third-party publish. `aontu pkg keygen <file>` mints its key once and
prints the signer id a consumer names. The Sigstore provider is the
default for public tier-A packages, and its verifier is not in this
package yet; a client that meets a trust entry naming `forge` refuses
by name rather than failing open.

## The key proof

The object `<version>.sig` is an aontu document, one line, canonical:

```
{"encoding":"aontu-signature/v1","kind":"key","over":"sha256:…","signature":"…","signer":"ed25519:…"}
```

- `over` is the manifest's digest, `sha256:` and 64 hex characters.
- `signer` is `ed25519:` followed by the base64url (unpadded, RFC 4648
  §5) of the 32-byte public key. `signerId` and `parseSignerId` convert.
- `signature` is the base64url of the 64-byte Ed25519 signature over
  the bytes `signedBytes(over)` returns:

  ```
  aontu-signature/v1\n
  sha256:…\n
  ```

  The encoding name frames the digest so a signature over one digest
  cannot be replayed as a signature over a prefix of another.

`verifyKeyProof(proof, over, signer)` checks all of it and answers the
reason it does not hold, or `undefined` when it does:

```ts
import { verifyKeyProof } from '@aontu/mod'

const why = verifyKeyProof(proof, manifestDigest, trustEntry.signer)
if (undefined !== why) {
  refuse('proof_invalid', why)
}
```

Every path that is not a completed, signer-matching, digest-matching
verification is a refusal, and the reasons are the ones the engine's
own client prints, so a consumer sees the same sentence whichever side
of the seam it is on.

## What is not here

Signing. A client verifies; whoever holds the key signs, and the engine's
`aontu publish --key <file>` is where that happens. Porting a signer into
the verifying package would be putting the half that must not be trusted
beside the half that does the trusting.
