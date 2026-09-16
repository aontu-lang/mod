/* Copyright (c) 2026 aontu-lang, MIT License */

// THE KEY PROVIDER'S PROOF (ADR-024 part 4, ADR-039 part 10): a
// signature over a manifest's digest by a named Ed25519 key. It is the
// minimal provider under the proof contract -- what a local registry
// serves and what a private package carries -- and the one encoding
// this package verifies today; the Sigstore bundle is the other, and
// is refused by name until its verifier exists.
//
//   message   = "aontu-signature/v1\n" + <digest> + "\n"
//   signer    = "ed25519:" + base64url(the 32-byte public key)
//   signature = base64url(the 64-byte Ed25519 signature)
//
// ONLY VERIFICATION IS HERE, as in note.ts: signing lives with whoever
// holds the key, and `aontu pkg keygen` mints it.

import { createPublicKey, verify as cryptoVerify } from 'node:crypto'


export const SIGNATURE_ENCODING = 'aontu-signature/v1'

// The proof object, as <version>.sig serves it.
export type KeyProof = {
  kind: 'key'
  encoding: typeof SIGNATURE_ENCODING
  over: string
  signer: string
  signature: string
}

const KEY_ID_RE = /^ed25519:[A-Za-z0-9_-]{43}$/
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/

// Node has no raw-Ed25519 key import, so the 32 key bytes are wrapped
// in the fixed SPKI DER prefix for id-Ed25519 (RFC 8410).
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')


// The bytes a key proof signs: the encoding name, the digest, each
// followed by a newline, so a signature over one digest cannot be
// replayed as a signature over a prefix of another.
export function signedBytes(over: string): Uint8Array {
  return new Uint8Array(Buffer.from(SIGNATURE_ENCODING + '\n' + over + '\n', 'utf8'))
}


// The signer id of a public key: what a trust entry names.
export function signerId(publicKey: Uint8Array): string {
  if (32 !== publicKey.length) {
    throw new Error('keyproof: an Ed25519 public key is 32 bytes, not ' + publicKey.length)
  }
  return 'ed25519:' + Buffer.from(publicKey).toString('base64url')
}


// The public key a signer id names. Refuses anything but the exact
// shape: a tampered id is refused here rather than silently failing to
// match later. Forty-three base64url characters are exactly 32 bytes,
// so the shape check is the length check.
export function parseSignerId(id: string): Uint8Array {
  if (!KEY_ID_RE.test(id)) {
    throw new Error('keyproof: malformed signer id')
  }
  return new Uint8Array(Buffer.from(id.slice('ed25519:'.length), 'base64url'))
}


// Verify a key proof against the digest it must sign and the signer the
// trust entry accepts. Answers the reason it does not hold, or
// undefined when it does. Every path that is not a completed,
// signer-matching, digest-matching verification is a refusal.
export function verifyKeyProof(
  proof: unknown, over: string, signer: string,
): string | undefined {
  const p = proof as Partial<KeyProof> | null | undefined
  if (null == p || 'key' !== p.kind || SIGNATURE_ENCODING !== p.encoding ||
    'string' !== typeof p.signature || !KEY_ID_RE.test(p.signer ?? '')) {
    return 'the proof is not an ' + SIGNATURE_ENCODING + ' key proof'
  }
  if (!DIGEST_RE.test(over) || p.over !== over) {
    return 'the proof signs ' + p.over + ', not this manifest'
  }
  if (p.signer !== signer) {
    return 'signed by ' + p.signer + '; the trust entry accepts ' + signer
  }
  const raw = Buffer.from((p.signer as string).slice('ed25519:'.length), 'base64url')
  const sig = Buffer.from(p.signature, 'base64url')
  if (32 !== raw.length || 64 !== sig.length) {
    return 'the proof carries a malformed key or signature'
  }
  const key = createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: 'der', type: 'spki',
  })
  return cryptoVerify(null, Buffer.from(signedBytes(over)), key, sig) ?
    undefined : 'the signature does not verify'
}
