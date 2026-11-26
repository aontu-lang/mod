/* Copyright (c) 2026 aontu-lang, MIT License */

// Copyright 2019 The Go Authors. All rights reserved. Derived from golang.org/x/mod/sumdb/tlog (tlog.go); use of this source code is governed by a BSD-style licence, see LICENSES/BSD-3-Clause-Go.txt and THIRD_PARTY_NOTICES.md.

import { nodeHash, hashEqual } from './hash'
import { maxpow2 } from './tree'
import type { Hash } from './hash'


export type RecordProof = Hash[]

export type TreeProof = Hash[]


// Is p a valid proof that the tree of size t with root th has an n'th
// record whose leaf hash is h?
export function checkRecord(
  p: RecordProof, t: number, th: Hash, n: number, h: Hash,
): boolean {
  // Out of bounds is a rejection, not an error: the numbers come off the wire.
  if (t < 0 || n < 0 || n >= t) {
    return false
  }
  const th2 = runRecordProof(p, 0, t, n, h)
  return null != th2 && hashEqual(th2, th)
}


function runRecordProof(
  p: RecordProof, lo: number, hi: number, n: number, leafHash: Hash,
): Hash | undefined {
  // Upstream panics here; checkRecord's bounds hold it.
  /* node:coverage ignore next 3 */
  if (!(lo <= n && n < hi)) {
    throw new Error('tlog: bad math in runRecordProof')
  }

  if (lo + 1 === hi) {
    // Hashes left over mean the proof describes another tree shape.
    return 0 === p.length ? leafHash : undefined
  }

  if (0 === p.length) {
    return undefined
  }

  const { k } = maxpow2(hi - lo)
  const last = p[p.length - 1]
  const rest = p.slice(0, p.length - 1)

  if (n < lo + k) {
    const th = runRecordProof(rest, lo, lo + k, n, leafHash)
    return null == th ? undefined : nodeHash(th, last)
  }
  const th = runRecordProof(rest, lo + k, hi, n, leafHash)
  return null == th ? undefined : nodeHash(last, th)
}


// Is p a valid proof that the tree of size t with root th contains, as
// a prefix, the tree of size n with root h?
export function checkTree(
  p: TreeProof, t: number, th: Hash, n: number, h: Hash,
): boolean {
  if (t < 1 || n < 1 || n > t) {
    return false
  }
  const out = runTreeProof(p, 0, t, n, h)
  if (null == out) {
    return false
  }
  // Both roots must match, or the right tree over a rewritten prefix passes.
  return hashEqual(out.th, th) && hashEqual(out.oh, h)
}


function runTreeProof(
  p: TreeProof, lo: number, hi: number, n: number, old: Hash,
): { oh: Hash, th: Hash } | undefined {
  // Upstream panics here; checkTree's bounds hold it.
  /* node:coverage ignore next 3 */
  if (!(lo < n && n <= hi)) {
    throw new Error('tlog: bad math in runTreeProof')
  }

  if (n === hi) {
    if (0 === lo) {
      return 0 === p.length ? { oh: old, th: old } : undefined
    }
    return 1 === p.length ? { oh: p[0], th: p[0] } : undefined
  }

  if (0 === p.length) {
    return undefined
  }

  const { k } = maxpow2(hi - lo)
  const last = p[p.length - 1]
  const rest = p.slice(0, p.length - 1)

  if (n <= lo + k) {
    const out = runTreeProof(rest, lo, lo + k, n, old)
    return null == out ? undefined
      : { oh: out.oh, th: nodeHash(out.th, last) }
  }
  const out = runTreeProof(rest, lo + k, hi, n, old)
  return null == out ? undefined
    : { oh: nodeHash(last, out.oh), th: nodeHash(last, out.th) }
}
