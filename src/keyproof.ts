/* Copyright (c) 2026 aontu-lang, MIT License */

// The key provider's proof, encoded as PROOF-CONTRACT.md states.

import { createPublicKey, verify as cryptoVerify } from 'node:crypto'


export const SIGNATURE_ENCODING = 'aontu-signature/v1'

export type KeyProof = {
  kind: 'key'
  encoding: typeof SIGNATURE_ENCODING
  over: string
  signer: string
  signature: string
}

const KEY_ID_RE = /^ed25519:[A-Za-z0-9_-]{43}$/
const SIG_RE = /^[A-Za-z0-9_-]{86}$/
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/

// Small-order points by y, sign bit cleared; the last is p, the first non-canonical y.
const SMALL_ORDER_Y = new Set([
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
])

// Node has no raw Ed25519 key import: this prefix wraps a key as SPKI DER.
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')


export function signedBytes(over: string): Uint8Array {
  return new Uint8Array(Buffer.from(SIGNATURE_ENCODING + '\n' + over + '\n', 'utf8'))
}


export function signerId(publicKey: Uint8Array): string {
  if (32 !== publicKey.length) {
    throw new Error('keyproof: an Ed25519 public key is 32 bytes, not ' + publicKey.length)
  }
  return 'ed25519:' + Buffer.from(publicKey).toString('base64url')
}


// The regex leaves the last character's spare bits free; the re-encode in
// canonicalBase64url is what gives one key one id.
export function parseSignerId(id: string): Uint8Array {
  const raw = KEY_ID_RE.test(id)
    ? canonicalBase64url(id.slice('ed25519:'.length), 32)
    : undefined
  if (undefined === raw) {
    throw new Error('keyproof: malformed signer id')
  }
  return new Uint8Array(raw)
}


// A small-order point, or a non-canonical encoding: any signature verifies.
export function smallOrderKey(publicKey: Uint8Array): boolean {
  const y = Buffer.from(publicKey)
  y[31] &= 0x7f
  const hex = y.toString('hex')
  return SMALL_ORDER_Y.has(hex) || (hex.endsWith('ff'.repeat(30) + '7f') && 0xed <= y[0])
}


// Buffer ignores spare trailing bits, so only the re-encode gives one spelling.
function canonicalBase64url(text: string, length: number): Buffer | undefined {
  const bytes = Buffer.from(text, 'base64url')
  return length === bytes.length && bytes.toString('base64url') === text ? bytes : undefined
}


// The reason the proof does not hold, or undefined when it does.
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
  const raw = canonicalBase64url((p.signer as string).slice('ed25519:'.length), 32)
  const sig = SIG_RE.test(p.signature) ? canonicalBase64url(p.signature, 64) : undefined
  if (undefined === raw || undefined === sig) {
    return 'the proof carries a malformed key or signature'
  }
  if (smallOrderKey(raw)) {
    return 'the signer is a key of small order'
  }
  const key = createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: 'der', type: 'spki',
  })
  return cryptoVerify(null, Buffer.from(signedBytes(over)), key, sig) ?
    undefined : 'the signature does not verify'
}
