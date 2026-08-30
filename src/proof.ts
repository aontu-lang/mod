/* Copyright (c) 2026 aontu-lang, MIT License */

// Derived from golang.org/x/mod/sumdb/tlog (tlog.go).
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style licence; see
// LICENSES/BSD-3-Clause-Go.txt and THIRD_PARTY_NOTICES.md.
//
// THE TWO VERIFIERS. Everything else in this package exists so that
// these two functions can be called: `checkRecord` answers "is this
// record really in the tree that root commits to", and `checkTree`
// answers "is this tree really an append-only extension of that one".
// The first is what makes a lookup trustworthy; the second is what
// makes the log's history un-rewritable.
//
// ONLY THE CHECKERS ARE HERE, not the provers. A client verifies; a log
// proves. Porting `ProveRecord`/`ProveTree` would be porting the
// serving half into the half that must not trust it, and every line of
// it would be unreachable from a client -- dead weight in the place
// where dead weight is most expensive to review.
//
// BOTH REJECT BY DEFAULT. Every path that is not a completed,
// length-exact, root-matching verification returns false. That matters
// more than it looks: a verifier whose failure mode is "true" passes
// every positive test anyone writes, which is why the golden vectors
// carry four rejections for every acceptance.

import { nodeHash, hashEqual } from './hash'
import { maxpow2 } from './tree'
import type { Hash } from './hash'


// A record proof: the sibling hashes from a leaf up to the root.
export type RecordProof = Hash[]

// A tree proof: RFC 6962's Merkle consistency proof.
export type TreeProof = Hash[]


// Is p a valid proof that the tree of size t with root th has an n'th
// record whose leaf hash is h?
export function checkRecord(
  p: RecordProof, t: number, th: Hash, n: number, h: Hash,
): boolean {
  // The bounds are part of the check, not a precondition on the caller:
  // a proof for record 7 of a 3-record tree is a rejection, not a
  // programming error, because the numbers came off the wire.
  if (t < 0 || n < 0 || n >= t) {
    return false
  }
  const th2 = runRecordProof(p, 0, t, n, h)
  return null != th2 && hashEqual(th2, th)
}


// The implied root of the subtree covering [lo, hi), or undefined when
// the proof does not run. Upstream returns an error; undefined is the
// same statement in a language that has one.
function runRecordProof(
  p: RecordProof, lo: number, hi: number, n: number, leafHash: Hash,
): Hash | undefined {
  // upstream panics here; checkRecord's bounds hold it
  /* node:coverage ignore next 3 */
  if (!(lo <= n && n < hi)) {
    throw new Error('tlog: bad math in runRecordProof')
  }

  if (lo + 1 === hi) {
    // The leaf. A proof with anything left over is REFUSED rather than
    // ignored: unused hashes mean the proof does not describe this
    // tree, and accepting the surplus would let one proof stand for
    // several shapes.
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
  // BOTH roots must match. Checking only the new root would accept a
  // proof that reconstructs the right tree from the WRONG history,
  // which is exactly the rewrite this function exists to detect.
  return hashEqual(out.th, th) && hashEqual(out.oh, h)
}


// The implied old and new roots of the subtree covering [lo, hi).
function runTreeProof(
  p: TreeProof, lo: number, hi: number, n: number, old: Hash,
): { oh: Hash, th: Hash } | undefined {
  // upstream panics here; checkTree's bounds hold it
  /* node:coverage ignore next 3 */
  if (!(lo < n && n <= hi)) {
    throw new Error('tlog: bad math in runTreeProof')
  }

  if (n === hi) {
    // Common ground.
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
