/* Copyright (c) 2026 aontu-lang, MIT License */

// Copyright 2019 The Go Authors. All rights reserved. Derived from golang.org/x/mod/sumdb/tlog (tlog.go); use of this source code is governed by a BSD-style licence, see LICENSES/BSD-3-Clause-Go.txt and THIRD_PARTY_NOTICES.md.

// No `<<`, `>>`, `&` or `|` on a tree index: docs/contributing/verifier.md.


// The maximum power of two strictly below n, and its log.
export function maxpow2(n: number): { k: number, l: number } {
  let l = 0
  while (Math.pow(2, l + 1) < n) {
    l++
  }
  return { k: Math.pow(2, l), l }
}


// Go's bits.TrailingZeros64, for n >= 0.
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


export function storedHashIndex(level: number, n: number): number {
  // Level L's n'th hash follows level L+1's 2n+1'th.
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


export function splitStoredHashIndex(index: number):
  { level: number, n: number } {
  let n = Math.floor(index / 2)
  let indexN = storedHashIndex(0, n)
  // Upstream panics here; storedHashIndex(0, n) < 2n bounds it.
  /* node:coverage ignore next 3 */
  if (indexN > index) {
    throw new Error('tlog: bad math in splitStoredHashIndex')
  }
  for (; ;) {
    const x = indexN + 1 + trailingZeros(n + 1)
    if (x > index) {
      break
    }
    n++
    indexN = x
  }
  const level = index - indexN
  return { level, n: Math.floor(n / Math.pow(2, level)) }
}


export function storedHashCount(n: number): number {
  if (0 === n) {
    return 0
  }
  let numHash = storedHashIndex(0, n - 1) + 1
  for (let i = n - 1; 0 !== i % 2; i = Math.floor(i / 2)) {
    numHash++
  }
  return numHash
}


export type HashReader = (indexes: number[]) => Uint8Array[]


// SHA-256 of the empty string: the root of a tree with no records.
const EMPTY_HASH = new Uint8Array([
  0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
  0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
  0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
  0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
])


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
  // Upstream panics here; the reader's count was checked above.
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
    // Upstream panics here; lo is always k-aligned.
    /* node:coverage ignore next 3 */
    if (0 !== lo % k) {
      throw new Error('tlog: bad math in subTreeIndex')
    }
    need.push(storedHashIndex(l, lo / Math.pow(2, l)))
    lo += k
  }
  return need
}


// The hash of records [lo, hi), and the hashes left over.
function subTreeHash(lo: number, hi: number, hashes: Uint8Array[]):
  { hash: Uint8Array, rest: Uint8Array[] } {
  let numTree = 0
  for (; lo < hi;) {
    const { k } = maxpow2(hi - lo + 1)
    // Upstream panics here; lo is always k-aligned.
    /* node:coverage ignore next 3 */
    if (0 !== lo % k) {
      throw new Error('tlog: bad math in subTreeHash')
    }
    numTree++
    lo += k
  }

  // Upstream panics here; treeHash checked the count.
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


import { nodeHash as nodeHashOf } from './hash'
