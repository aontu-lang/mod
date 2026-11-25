/* Copyright (c) 2026 aontu-lang, MIT License */

// Copyright 2019 The Go Authors. All rights reserved. Derived from golang.org/x/mod/sumdb/tlog (tlog.go); use of this source code is governed by a BSD-style licence, see LICENSES/BSD-3-Clause-Go.txt and THIRD_PARTY_NOTICES.md.

// Why the prefixes matter: docs/contributing/verifier.md, "Hashing".

import { createHash } from 'node:crypto'


export const HASH_SIZE = 32

export type Hash = Uint8Array


// SHA-256(0x00 || data). RFC 6962 §2.1.
export function recordHash(data: Uint8Array): Hash {
  const h = createHash('sha256')
  h.update(LEAF_PREFIX)
  h.update(data)
  return new Uint8Array(h.digest())
}


// SHA-256(0x01 || left || right). RFC 6962 §2.1.
export function nodeHash(left: Hash, right: Hash): Hash {
  const buf = new Uint8Array(1 + HASH_SIZE + HASH_SIZE)
  buf[0] = 0x01
  buf.set(left, 1)
  buf.set(right, 1 + HASH_SIZE)
  return new Uint8Array(createHash('sha256').update(buf).digest())
}


const LEAF_PREFIX = new Uint8Array([0x00])


// Standard base64 with padding, as Go's Hash.String() writes it: not base64url.
export function formatHash(h: Hash): string {
  return Buffer.from(h).toString('base64')
}


// The re-encode is the real check: Buffer decodes junk, missing padding and
// base64url without complaint, so only the round trip gives a hash one spelling.
export function parseHash(s: string): Hash {
  const b = Buffer.from(s, 'base64')
  if (HASH_SIZE !== b.length || b.toString('base64') !== s) {
    throw new Error('tlog: malformed hash')
  }
  return new Uint8Array(b)
}


export function hashEqual(a: Hash, b: Hash): boolean {
  if (a.length !== b.length) {
    return false
  }
  let diff = 0
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i]
  }
  return 0 === diff
}
