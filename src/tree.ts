/* Copyright (c) 2026 aontu-lang, MIT License */

// Derived from golang.org/x/mod/sumdb/tlog (tlog.go).
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style licence; see
// LICENSES/BSD-3-Clause-Go.txt and THIRD_PARTY_NOTICES.md.
//
// STORED-HASH ADDRESSING AND TREE ROOTS. The dense linear ordering is
// Crosby and Wallach's (§3.3 of "Efficient Data Structures for
// Tamper-Evident Logging"), which is what lets a log append in O(log n)
// and serve any historical root without recomputing the tree.
//
// THE PORTING HAZARD THIS FILE EXISTS TO CONTAIN. Upstream is `int64`
// arithmetic using `<<`, `>>` and `&`. JavaScript's bitwise operators
// coerce to *32 bits*, so a direct transliteration is correct for small
// trees and silently wrong past 2^31 -- roughly two billion stored
// hashes, which a real log reaches. Every shift here is therefore
// written as multiplication or division, and every mask as a modulus,
// which keeps the arithmetic exact to Number.MAX_SAFE_INTEGER (2^53)
// and makes the 32-bit trap unreachable rather than merely avoided.
// The rule for anyone editing this file: NO `<<`, `>>`, `&` or `|` on a
// tree index, ever.


// The maximum power of two strictly below n, and its log. Upstream's
// maxpow2, with the shift written out.
export function maxpow2(n: number): { k: number, l: number } {
  let l = 0
  while (Math.pow(2, l + 1) < n) {
    l++
  }
  return { k: Math.pow(2, l), l }
}


// The number of trailing zero bits of n, for n >= 0. Upstream calls
// bits.TrailingZeros64; written as a division loop for the reason at
// the top of this file.
export function trailingZeros(n: number): number {
  if (0 === n) {
    return 64
  }
  let z = 0
  while (0 === n % 2) {
    n = n / 2
    z++
  }
  return z
}


// The dense storage index of level L's n'th hash.
export function storedHashIndex(level: number, n: number): number {
  // Level L's n'th hash is written right after level L+1's 2n+1'th, so
  // work down to the level-0 ordering and add the level back at the end.
  for (let l = level; 0 < l; l--) {
    n = 2 * n + 1
  }

  // Level 0's n'th hash is written at n + n/2 + n/4 + …
  let i = 0
  for (; 0 < n; n = Math.floor(n / 2)) {
    i += n
  }

  return i + level
}


// The inverse of storedHashIndex.
export function splitStoredHashIndex(index: number):
  { level: number, n: number } {
  // storedHashIndex(0, n) < 2n, so the n wanted is in
  // [index/2, index/2 + log2(index)].
  let n = Math.floor(index / 2)
  let indexN = storedHashIndex(0, n)
  // upstream panics here; unreachable by the bound above
  /* node:coverage ignore next 3 */
  if (indexN > index) {
    throw new Error('tlog: bad math in splitStoredHashIndex')
  }
  for (; ;) {
    // Each new record n adds 1 + trailingZeros(n+1) hashes.
    const x = indexN + 1 + trailingZeros(n + 1)
    if (x > index) {
      break
    }
    n++
    indexN = x
  }
  // The hash wanted was committed with record n, so it is one of
  // (0, n), (1, n/2), (2, n/4), …
  const level = index - indexN
  return { level, n: Math.floor(n / Math.pow(2, level)) }
}


// How many stored hashes a tree of n records has.
export function storedHashCount(n: number): number {
  if (0 === n) {
    return 0
  }
  // Every hash up to the last leaf hash …
  let numHash = storedHashIndex(0, n - 1) + 1
  // … plus any subtree that leaf completed.
  for (let i = n - 1; 0 !== i % 2; i = Math.floor(i / 2)) {
    numHash++
  }
  return numHash
}


// What a caller must supply to read stored hashes by index. The reader
// is injected rather than imported for the reason it is upstream: where
// the hashes come from -- memory, tiles, a file -- is the caller's
// business, and a verifier that knew would be a verifier with a
// transport in it.
export type HashReader = (indexes: number[]) => Uint8Array[]


// SHA-256 of the empty string: the root of a tree with no records.
const EMPTY_HASH = new Uint8Array([
  0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
  0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
  0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
  0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
])


// The root hash of the tree with n records.
export function treeHash(n: number, r: HashReader): Uint8Array {
  if (0 === n) {
    return EMPTY_HASH
  }
  const indexes = subTreeIndex(0, n, [])
  const hashes = r(indexes)
  if (hashes.length !== indexes.length) {
    throw new Error('tlog: reader returned ' + hashes.length +
      ' hashes for ' + indexes.length + ' indexes')
  }
  const out = subTreeHash(0, n, hashes)
  // upstream panics here; unreachable when the reader agrees
  /* node:coverage ignore next 3 */
  if (0 !== out.rest.length) {
    throw new Error('tlog: bad index math in treeHash')
  }
  return out.hash
}


// The storage indexes needed to compute the hash of records [lo, hi).
function subTreeIndex(lo: number, hi: number, need: number[]): number[] {
  for (; lo < hi;) {
    const { k, l } = maxpow2(hi - lo + 1)
    // upstream panics here; lo is always k-aligned
    /* node:coverage ignore next 3 */
    if (0 !== lo % k) {
      throw new Error('tlog: bad math in subTreeIndex')
    }
    need.push(storedHashIndex(l, lo / Math.pow(2, l)))
    lo += k
  }
  return need
}


// The hash of records [lo, hi) from the hashes subTreeIndex asked for,
// with whatever is left over.
function subTreeHash(lo: number, hi: number, hashes: Uint8Array[]):
  { hash: Uint8Array, rest: Uint8Array[] } {
  // Repeatedly split off the largest power-of-two left side, whose hash
  // is stored directly; the right side is the fringe and needs more.
  let numTree = 0
  for (; lo < hi;) {
    const { k } = maxpow2(hi - lo + 1)
    // upstream panics here; lo is always k-aligned
    /* node:coverage ignore next 3 */
    if (0 !== lo % k) {
      throw new Error('tlog: bad math in subTreeHash')
    }
    numTree++
    lo += k
  }

  // upstream panics here; treeHash checked the count
  /* node:coverage ignore next 3 */
  if (hashes.length < numTree) {
    throw new Error('tlog: bad index math in subTreeHash')
  }

  let h = hashes[numTree - 1]
  for (let i = numTree - 2; 0 <= i; i--) {
    h = nodeHashOf(hashes[i], h)
  }
  return { hash: h, rest: hashes.slice(numTree) }
}


// Imported late to keep the dependency one-way: hashing knows nothing
// about tree shape.
import { nodeHash as nodeHashOf } from './hash'
