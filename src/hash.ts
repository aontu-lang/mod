/* Copyright (c) 2026 aontu-lang, MIT License */

// Derived from golang.org/x/mod/sumdb/tlog (tlog.go).
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style licence; see
// LICENSES/BSD-3-Clause-Go.txt and THIRD_PARTY_NOTICES.md.
//
// LEAF AND NODE HASHING, with the domain separation RFC 6962 specifies
// and Go's checksum database implements: a leaf is hashed under a 0x00
// prefix and an interior node under 0x01, so no leaf encoding can ever
// be mistaken for a node encoding. Removing that prefix byte -- or
// applying it to the wrong one -- is the classic second-preimage hole
// in a Merkle tree, and it is why these two functions are three lines
// each and still have their own file.

import { createHash } from 'node:crypto'


// A hash is 32 bytes, always. Modelled as a Uint8Array rather than a
// string because every use is byte concatenation, and a base64 string
// that has to be decoded before every node hash is a decode step to get
// wrong. `formatHash`/`parseHash` are the boundary.
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


// The base64 form upstream prints and the tile protocol carries.
// STANDARD base64 with padding, matching Go's Hash.String() -- not
// base64url, which is what the canon-hash uses. Two encodings live in
// this ecosystem and confusing them produces a string that looks right
// and compares wrong.
export function formatHash(h: Hash): string {
  return Buffer.from(h).toString('base64')
}


// The inverse, refusing anything that is not exactly 32 bytes. A
// truncated hash that silently became a short array would compare
// unequal to everything, which reads as a proof failure rather than as
// the malformed input it is.
export function parseHash(s: string): Hash {
  const b = Buffer.from(s, 'base64')
  if (HASH_SIZE !== b.length) {
    throw new Error('tlog: malformed hash')
  }
  return new Uint8Array(b)
}


// Constant-time-ish equality. Not a secret comparison -- these are
// public hashes and a timing side channel reveals nothing an attacker
// does not already hold -- but written without an early return anyway,
// because a hash comparison that short-circuits is the shape a reviewer
// has to think about, and this way they do not.
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
