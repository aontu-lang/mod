/* Copyright (c) 2026 aontu-lang, MIT License */

// Derived from golang.org/x/mod/sumdb/note and sumdb/tlog/note.go.
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style licence; see
// LICENSES/BSD-3-Clause-Go.txt and THIRD_PARTY_NOTICES.md.
//
// SIGNED NOTES: the envelope a checkpoint travels in. A note is text
// followed by a blank line and one or more signature lines:
//
//   aontu transparency log
//   1834921
//   nND/nri/U0xuHUrYSy0HtMeal2vzD9V4k/BO79C+QeI=
//
//   — aontu.example +4d9d0f2b BASE64SIG
//
// A signature line names the key by SERVER NAME and a 32-bit key hash,
// so one note can carry the log's own signature and any number of
// witness cosignatures side by side, and a client can find the ones it
// trusts without understanding the others. That is what makes the
// witness protocol additive rather than a format change -- G10 phase 6
// depends on this file having been right in phase 2.
//
// ONLY VERIFICATION IS HERE. Signing lives with whoever holds the key,
// which is not a client. See proof.ts for the same rule applied to
// proofs.

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto'
import { parseHash } from './hash'
import type { Hash } from './hash'


// The one signature algorithm this format defines, as its first byte.
const ALG_ED25519 = 1

// A signature line opens with an em dash and a space. Two bytes of
// UTF-8 punctuation carrying structural meaning, which is upstream's
// choice and must be matched exactly.
const SIG_PREFIX = '— '

// A note with an implausible number of signatures is refused rather
// than parsed, upstream's bound: verification is per-signature work an
// attacker would otherwise choose the amount of.
const MAX_SIGS = 100


// A verifier key: `<name>+<hash8>+<base64(alg || key)>`.
export type Verifier = {
  name: string
  keyHash: number
  publicKey: Uint8Array
}


// The 32-bit key hash: the first four bytes, big-endian, of
// SHA-256(name || "\n" || encodedKey) -- where encodedKey INCLUDES the
// leading algorithm byte. Hashing the bare key instead is the error
// this comment exists to prevent; it produces an id that disagrees with
// every other implementation and only shows up as "unknown verifier".
export function keyHash(name: string, encodedKey: Uint8Array): number {
  const h = createHash('sha256')
  h.update(Buffer.from(name, 'utf8'))
  h.update(Buffer.from('\n', 'utf8'))
  h.update(encodedKey)
  const sum = h.digest()
  // Unsigned: readUInt32BE, not a bitwise shift, which would sign it.
  return sum.readUInt32BE(0)
}


// Parse a verifier key, checking that its embedded hash is the hash the
// name and key actually produce -- so a key whose id was tampered with
// is refused here rather than silently failing to match later.
export function parseVerifierKey(vkey: string): Verifier {
  const plus1 = vkey.indexOf('+')
  if (0 >= plus1) {
    throw new Error('note: malformed verifier id')
  }
  const name = vkey.slice(0, plus1)
  const plus2 = vkey.indexOf('+', plus1 + 1)
  if (0 > plus2) {
    throw new Error('note: malformed verifier id')
  }
  const hash16 = vkey.slice(plus1 + 1, plus2)
  const key64 = vkey.slice(plus2 + 1)

  if (!isValidName(name) || !/^[0-9a-f]{8}$/.test(hash16)) {
    throw new Error('note: malformed verifier id')
  }

  const encoded = new Uint8Array(Buffer.from(key64, 'base64'))
  if (0 === encoded.length) {
    throw new Error('note: malformed verifier id')
  }
  if (ALG_ED25519 !== encoded[0] || 1 + 32 !== encoded.length) {
    throw new Error('note: unknown verifier algorithm')
  }
  if (parseInt(hash16, 16) !== keyHash(name, encoded)) {
    throw new Error('note: invalid verifier hash')
  }

  return { name, keyHash: keyHash(name, encoded), publicKey: encoded.slice(1) }
}


// A name may not be empty, hold whitespace, or hold `+` -- the last
// because `+` is the field separator in a verifier key, so a name
// containing one could spell a different key.
function isValidName(name: string): boolean {
  return '' !== name && !/\s/.test(name) && !name.includes('+')
}


// A note, once opened.
export type Note = {
  text: string
  // The verifiers whose signatures were present AND checked out.
  // NEVER EMPTY -- see openNote. A signature by an unknown key is not
  // an error and is not here: a witness this client does not know is a
  // normal thing to meet, provided somebody it DOES know also signed.
  verified: Verifier[]
}


// Open a note, verifying every signature made by a known verifier.
//
// THE RETURN IS NOT A BOOLEAN, and that matters: a caller must ask
// WHICH verifiers signed and decide whether that set is enough. The
// K-of-N witness policy G10 phase 6 describes is a predicate over this
// list, which is why it is a list.
//
// A NOTE NOBODY KNOWN SIGNED IS REFUSED, not opened with an empty
// list. The first draft of this file did the latter and left the
// caller to notice, which put it at odds with upstream's
// UnverifiedNoteError -- and a disagreement about whether a signature
// check passed is the worst class of parity breach there is. The Go
// side found it (go/tlog_test.go in aontu-lang/aontu), and upstream's
// line is the right one: an error forces handling where a doc comment
// does not, and it costs the witness story nothing, because a
// checkpoint always carries the LOG's own signature -- which the
// client knows by construction -- so a usable note always has at least
// one verified signer. The zero case only arises for a note the client
// could not act on anyway.
//
// Unknown signers ALONGSIDE a known one are still skipped, which is
// what actually makes cosignatures additive.
export function openNote(msg: string, known: Verifier[]): Note {
  // Valid UTF-8 with no ASCII control characters but newline. Refusing
  // control characters keeps a note from carrying a second apparent
  // note inside itself when printed.
  for (const ch of msg) {
    const c = ch.codePointAt(0) as number
    if ((0x20 > c && 0x0a !== c) || 0xfffd === c) {
      throw new Error('note: malformed note')
    }
  }

  // Text, blank line, then the signature block.
  const split = msg.lastIndexOf('\n\n')
  if (0 > split) {
    throw new Error('note: malformed note')
  }
  const text = msg.slice(0, split + 1)
  const sigBlock = msg.slice(split + 2)
  if ('' === sigBlock || !sigBlock.endsWith('\n')) {
    throw new Error('note: malformed note')
  }

  const textBytes = Buffer.from(text, 'utf8')
  const verified: Verifier[] = []
  const seen = new Set<string>()

  const lines = sigBlock.slice(0, sigBlock.length - 1).split('\n')
  if (MAX_SIGS < lines.length) {
    throw new Error('note: malformed note')
  }

  for (const line of lines) {
    if (!line.startsWith(SIG_PREFIX)) {
      throw new Error('note: malformed note')
    }
    const rest = line.slice(SIG_PREFIX.length)
    const sp = rest.indexOf(' ')
    if (0 > sp) {
      throw new Error('note: malformed note')
    }
    const name = rest.slice(0, sp)
    const b64 = rest.slice(sp + 1)
    const sig = new Uint8Array(Buffer.from(b64, 'base64'))
    if (!isValidName(name) || '' === b64 || 5 > sig.length) {
      throw new Error('note: malformed note')
    }

    const hash = Buffer.from(sig).readUInt32BE(0)
    const raw = sig.slice(4)

    const v = known.find((k) => k.name === name && k.keyHash === hash)
    if (undefined === v) {
      // An unknown signer is not a failure. Skipping it here is what
      // lets a note gather witness cosignatures over time without
      // breaking clients that predate them.
      continue
    }
    // A repeated signature by one key is counted once, so a note padded
    // with duplicates cannot look better-witnessed than it is.
    const id = v.name + '+' + v.keyHash
    if (seen.has(id)) {
      continue
    }
    if (ed25519Verify(v.publicKey, textBytes, raw)) {
      seen.add(id)
      verified.push(v)
    }
    else {
      // A BAD signature by a KNOWN key is an attack, not an unknown
      // witness, and must not be quietly skipped the way an unknown
      // signer is.
      throw new Error('note: invalid signature for key ' + v.name)
    }
  }

  if (0 === verified.length) {
    throw new Error('note: no verifiable signatures')
  }

  return { text, verified }
}


// Node has no raw-Ed25519 key import, so wrap the 32 key bytes in the
// fixed SPKI DER prefix for id-Ed25519 (RFC 8410). The prefix is
// constant because the algorithm and key length are.
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex')

function ed25519Verify(
  pub: Uint8Array, data: Buffer, sig: Uint8Array,
): boolean {
  if (64 !== sig.length) {
    return false
  }
  const key = createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(pub)]),
    format: 'der',
    type: 'spki',
  })
  return cryptoVerify(null, data, key, Buffer.from(sig))
}


// A tree head, as a checkpoint's body states it.
export type Tree = {
  origin: string
  n: number
  hash: Hash
}


// Parse a checkpoint body: an origin line, a decimal size, a base64
// root, then anything else, which is IGNORED for forwards
// compatibility -- that is upstream's rule and it is what lets a later
// version add lines without invalidating today's clients.
export function parseTree(text: string, origin: string): Tree {
  const prefix = origin + '\n'
  if (!text.startsWith(prefix) || 3 > countNewlines(text) || 1e6 < text.length) {
    throw new Error('note: malformed tree note')
  }
  const lines = text.split('\n')

  // `lines[1] !== String(n)` is the check that matters: it refuses
  // `007`, `+7` and ` 7`, which parse as 7 and would give one tree size
  // several spellings -- and a checkpoint is compared as TEXT by
  // witnesses and gossip, so two spellings would be two checkpoints.
  const n = Number(lines[1])
  if (!Number.isSafeInteger(n) || 0 > n || lines[1] !== String(n)) {
    throw new Error('note: malformed tree note')
  }

  let hash: Hash
  try {
    hash = parseHash(lines[2])
  }
  catch {
    throw new Error('note: malformed tree note')
  }
  // No length check here: parseHash refuses anything that is not
  // exactly HASH_SIZE, so a second check would be unreachable code --
  // which ADR-002 asks to be deleted rather than excluded.

  return { origin, n, hash }
}


function countNewlines(s: string): number {
  let c = 0
  for (const ch of s) {
    if ('\n' === ch) {
      c++
    }
  }
  return c
}
