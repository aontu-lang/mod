/* Copyright (c) 2026 aontu-lang, MIT License */

// THE KEY PROVIDER'S PROOF, verified against signatures made here with
// node's own Ed25519: the port has no signer, so the test is the
// signer. As with the tlog vectors, the refusals are the point: a
// verifier whose failure mode is "holds" passes every positive case.

import { describe, test } from 'node:test'
import * as Assert from 'node:assert'
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto'

import {
  SIGNATURE_ENCODING, signedBytes, signerId, parseSignerId, verifyKeyProof,
} from '../dist/index'
import type { KeyProof } from '../dist/index'


const DIGEST = 'sha256:' + 'ab'.repeat(32)
const OTHER = 'sha256:' + 'cd'.repeat(32)

function keypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const raw = new Uint8Array(publicKey.export({ format: 'jwk' }).x
    ? Buffer.from(publicKey.export({ format: 'jwk' }).x as string, 'base64url') : [])
  return { privateKey, raw, id: signerId(raw) }
}

function proofOver(over: string, k = keypair()): { proof: KeyProof, id: string } {
  const sig = cryptoSign(null, Buffer.from(signedBytes(over)), k.privateKey)
  return {
    proof: {
      kind: 'key', encoding: SIGNATURE_ENCODING, over,
      signer: k.id, signature: Buffer.from(sig).toString('base64url'),
    },
    id: k.id,
  }
}


describe('keyproof', () => {

  test('signed-bytes-frame-the-digest', () => {
    Assert.equal(Buffer.from(signedBytes(DIGEST)).toString('utf8'),
      'aontu-signature/v1\n' + DIGEST + '\n')
  })


  test('signer-id-round-trips-and-refuses-other-shapes', () => {
    const k = keypair()
    Assert.match(k.id, /^ed25519:[A-Za-z0-9_-]{43}$/)
    Assert.deepEqual(parseSignerId(k.id), k.raw)
    Assert.throws(() => signerId(new Uint8Array(31)), /32 bytes, not 31/)
    for (const bad of ['', 'ed25519:', 'rsa:' + 'A'.repeat(43), k.id + 'A',
      'ed25519:' + 'A'.repeat(42), 'ed25519:' + '='.repeat(43)]) {
      Assert.throws(() => parseSignerId(bad), /malformed signer id/, bad)
    }
    Assert.equal(parseSignerId('ed25519:' + 'A'.repeat(43)).length, 32)
  })


  test('a-proof-by-the-accepted-signer-over-this-digest-holds', () => {
    const { proof, id } = proofOver(DIGEST)
    Assert.equal(verifyKeyProof(proof, DIGEST, id), undefined)
  })


  test('every-other-shape-is-refused-with-its-reason', () => {
    const { proof, id } = proofOver(DIGEST)
    const other = keypair()

    // Not a key proof at all.
    for (const bad of [null, undefined, 1, {}, { ...proof, kind: 'sigstore' },
      { ...proof, encoding: 'aontu-signature/v2' }, { ...proof, signature: 5 },
      { ...proof, signer: 'forge' }, (({ signer, ...rest }) => rest)(proof)]) {
      Assert.match(verifyKeyProof(bad, DIGEST, id) as string, /not an aontu-signature\/v1 key proof/)
    }
    // Signs another digest, or the digest asked for is not a digest.
    Assert.equal(verifyKeyProof(proof, OTHER, id),
      'the proof signs ' + DIGEST + ', not this manifest')
    Assert.equal(verifyKeyProof({ ...proof, over: 'nope' }, 'nope', id),
      'the proof signs nope, not this manifest')
    // Signed by a key the trust entry does not accept.
    Assert.equal(verifyKeyProof(proof, DIGEST, other.id),
      'signed by ' + id + '; the trust entry accepts ' + other.id)
    // A signature of the wrong length, or a key of the wrong length.
    Assert.equal(verifyKeyProof({ ...proof, signature: 'AAAA' }, DIGEST, id),
      'the proof carries a malformed key or signature')
    const short = 'ed25519:' + 'A'.repeat(43)
    Assert.equal(verifyKeyProof({ ...proof, signer: short }, DIGEST, short) === undefined, false)
    // The right shape, the wrong bits.
    const flipped = ('A' === proof.signature[0] ? 'B' : 'A') + proof.signature.slice(1)
    Assert.equal(verifyKeyProof({ ...proof, signature: flipped }, DIGEST, id),
      'the signature does not verify')
    // Signed by another key but claiming this signer.
    const forged = proofOver(DIGEST, other).proof
    Assert.equal(verifyKeyProof({ ...forged, signer: id }, DIGEST, id),
      'the signature does not verify')
  })
})
