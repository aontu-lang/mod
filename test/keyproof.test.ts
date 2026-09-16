/* Copyright (c) 2026 aontu-lang, MIT License */

// THE KEY PROVIDER'S PROOF, verified against signatures made here with
// node's own Ed25519: the port has no signer, so the test is the
// signer. As with the tlog vectors, the refusals are the point: a
// verifier whose failure mode is "holds" passes every positive case.

import { describe, test } from 'node:test'
import * as Assert from 'node:assert'
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto'

import {
  SIGNATURE_ENCODING, signedBytes, signerId, parseSignerId, verifyKeyProof, smallOrderKey,
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
    // A key of small order, or one whose encoding is not canonical:
    // any signature verifies under the first, so both are refused
    // before the signature is looked at.
    const keyOf = (hex: string) => 'ed25519:' + Buffer.from(hex, 'hex').toString('base64url')
    for (const hex of ['00'.repeat(32), '01' + '00'.repeat(31), '01' + '00'.repeat(30) + '80',
      'ec' + 'ff'.repeat(30) + '7f', 'ed' + 'ff'.repeat(30) + '7f', 'ee' + 'ff'.repeat(30) + 'ff',
      '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
      'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa']) {
      Assert.equal(smallOrderKey(Buffer.from(hex, 'hex')), true, hex)
      Assert.equal(verifyKeyProof({ ...proof, signer: keyOf(hex) }, DIGEST, keyOf(hex)),
        'the signer is a key of small order', hex)
    }
    Assert.equal(smallOrderKey(Buffer.from('02' + 'ff'.repeat(30) + '7f', 'hex')), false)
    Assert.equal(smallOrderKey(Buffer.from('ed' + 'ff'.repeat(29) + 'fe7f', 'hex')), false)
    Assert.equal(smallOrderKey(other.raw), false)
    // Base64url with one spelling: trailing bits set, or padding, are
    // malformed even where Buffer would decode them to the same bytes.
    const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
    const slack = (text: string) => text.slice(0, -1) + B64[B64.indexOf(text[text.length - 1]) | 1]
    Assert.equal(verifyKeyProof({ ...proof, signature: slack(proof.signature) }, DIGEST, id),
      'the proof carries a malformed key or signature')
    Assert.equal(verifyKeyProof({ ...proof, signer: slack(id) }, DIGEST, slack(id)),
      'the proof carries a malformed key or signature')
    Assert.equal(verifyKeyProof({ ...proof, signature: proof.signature.slice(0, 85) + '=' }, DIGEST, id),
      'the proof carries a malformed key or signature')
    Assert.equal(verifyKeyProof({ ...proof, signature: proof.signature + 'AA' }, DIGEST, id),
      'the proof carries a malformed key or signature')
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
