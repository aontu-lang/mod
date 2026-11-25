/* Copyright (c) 2026 aontu-lang, MIT License */

// Copyright 2019 The Go Authors. All rights reserved. Derived from golang.org/x/mod/sumdb/note and sumdb/tlog/note.go; use of this source code is governed by a BSD-style licence, see LICENSES/BSD-3-Clause-Go.txt and THIRD_PARTY_NOTICES.md.

// The note format, and why each refusal: docs/contributing/verifier.md, "Signed notes".

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto'
import { parseHash } from './hash'
import type { Hash } from './hash'


const ALG_ED25519 = 1

const SIG_PREFIX = '— '

// Upstream's bound: the sender would otherwise choose the verification work.
const MAX_SIGS = 100


// A verifier key: `<name>+<hash8>+<base64(alg || key)>`.
export type Verifier = {
  name: string
  keyHash: number
  publicKey: Uint8Array
}


// `encodedKey` includes the leading algorithm byte; the bare key gives a wrong id.
export function keyHash(name: string, encodedKey: Uint8Array): number {
  const h = createHash('sha256')
  h.update(Buffer.from(name, 'utf8'))
  h.update(Buffer.from('\n', 'utf8'))
  h.update(encodedKey)
  const sum = h.digest()
  return sum.readUInt32BE(0)
}


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

  const encodedBuf = canonicalBase64(key64)
  if (undefined === encodedBuf) {
    throw new Error('note: malformed verifier id')
  }
  const encoded = new Uint8Array(encodedBuf)
  if (ALG_ED25519 !== encoded[0] || 1 + 32 !== encoded.length) {
    throw new Error('note: unknown verifier algorithm')
  }
  if (parseInt(hash16, 16) !== keyHash(name, encoded)) {
    throw new Error('note: invalid verifier hash')
  }

  return { name, keyHash: keyHash(name, encoded), publicKey: encoded.slice(1) }
}


// Buffer accepts junk, missing padding and base64url, so only the re-encode
// gives a key or signature one spelling.
function canonicalBase64(text: string): Buffer | undefined {
  const bytes = Buffer.from(text, 'base64')
  return 0 < bytes.length && bytes.toString('base64') === text ? bytes : undefined
}


// Go's unicode.IsSpace, as code points: JavaScript's `\s` is a different set,
// and U+2028 would end a regular expression literal.
const GO_SPACE = new Set([
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0,
  0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
])


function isValidName(name: string): boolean {
  if ('' === name || name.includes('+')) {
    return false
  }
  for (const ch of name) {
    const c = ch.codePointAt(0) as number
    if (GO_SPACE.has(c) || (0x2000 <= c && 0x200a >= c)) {
      return false
    }
  }
  return true
}


// A note, once opened.
export type Note = {
  text: string
  // Never empty: a note no known key signed is refused.
  verified: Verifier[]
}


// Returns which known verifiers signed, so the caller decides whether that is enough.
export function openNote(msg: string, known: Verifier[]): Note {
  for (const ch of msg) {
    const c = ch.codePointAt(0) as number
    if ((0x20 > c && 0x0a !== c) || 0xfffd === c) {
      throw new Error('note: malformed note')
    }
  }

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
    const sigBuf = canonicalBase64(b64)
    if (!isValidName(name) || undefined === sigBuf || 5 > sigBuf.length) {
      throw new Error('note: malformed note')
    }
    const sig = new Uint8Array(sigBuf)

    const hash = Buffer.from(sig).readUInt32BE(0)
    const raw = sig.slice(4)

    const v = known.find((k) => k.name === name && k.keyHash === hash)
    if (undefined === v) {
      // An unknown signer is skipped, so cosignatures can accumulate.
      continue
    }
    const id = v.name + '+' + v.keyHash
    if (seen.has(id)) {
      continue
    }
    if (ed25519Verify(v.publicKey, textBytes, raw)) {
      seen.add(id)
      verified.push(v)
    }
    else {
      // A bad signature by a known key is an attack, not a stranger.
      throw new Error('note: invalid signature for key ' + v.name)
    }
  }

  if (0 === verified.length) {
    throw new Error('note: no verifiable signatures')
  }

  return { text, verified }
}


// Node has no raw Ed25519 key import: this prefix wraps a key as SPKI DER.
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


// Lines after the root hash are ignored, as upstream ignores them.
export function parseTree(text: string, origin: string): Tree {
  const prefix = origin + '\n'
  if (!text.startsWith(prefix) || 3 > countNewlines(text) || 1e6 < text.length) {
    throw new Error('note: malformed tree note')
  }
  const lines = text.split('\n')

  // The comparison with String(n) refuses `007`, `+7` and ` 7`: one size, one spelling.
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
