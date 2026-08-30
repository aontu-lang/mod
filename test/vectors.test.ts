/* Copyright (c) 2026 aontu-lang, MIT License */

// THE DIFFERENTIAL GATE. Every case here was produced by running the
// PINNED upstream `golang.org/x/mod/sumdb/tlog` (see ../goref), so a
// disagreement is a bug in this port and not a difference of opinion.
//
// This file is the reason the port is allowed to exist at all. A
// cryptographic implementation that passes only tests written by
// whoever wrote it has been checked against its author's understanding,
// which is exactly the thing in doubt. The vectors check it against the
// implementation Go's own checksum database runs.
//
// THE REJECTIONS ARE THE POINT. 214 of the 268 inclusion cases and 160
// of the 200 consistency cases expect `false`. A verifier that returned
// true unconditionally would pass every positive case in this file and
// fail 374 others, which is the asymmetry a proof checker's test suite
// has to have.

import { describe, test } from 'node:test'
import * as Assert from 'node:assert'
import * as Fs from 'node:fs'
import * as Path from 'node:path'

import {
  recordHash, nodeHash, formatHash, parseHash,
  storedHashIndex, splitStoredHashIndex, storedHashCount, treeHash,
  checkRecord, checkTree,
  tileForIndex, tilePath, parseTilePath,
  keyHash, parseVerifierKey, openNote, parseTree,
} from '../dist/index'


type Vectors = {
  upstream: string
  corpus: string
  recordHash: { data: string, hash: string }[]
  nodeHash: { left: string, right: string, hash: string }[]
  storedHashIndex: { level: number, n: number, index: number }[]
  storedHashCount: { n: number, count: number }[]
  storedHashes: string[]
  treeHash: { n: number, root: string }[]
  checkRecord: {
    name: string, t: number, th: string, n: number, h: string,
    proof: string[], want: boolean,
  }[]
  checkTree: {
    name: string, t: number, th: string, n: number, h: string,
    proof: string[], want: boolean,
  }[]
  tilePath: { h: number, l: number, n: number, w: number, path: string }[]
  tileForIndex: {
    h: number, index: number, tileL: number, tileN: number, tileW: number,
    path: string,
  }[]
  note: {
    verifierKey: string
    name: string
    keyHash: number
    signed: { name: string, text: string, msg: string, want: boolean }[]
    trees: {
      text: string, origin: string, n: number, hash: string, want: boolean,
    }[]
    malformed: { name: string, msg: string }[]
  }
}


const V: Vectors = JSON.parse(Fs.readFileSync(
  Path.join(__dirname, '..', 'vectors', 'tlog.json'), 'utf8'))


// The corpus the vectors were generated over, reproduced here. If this
// disagrees with goref/main.go the vectors are being read against the
// wrong records, and every hash case below fails -- which is the
// intended failure, loudly, rather than a silent re-baseline.
function record(i: number): Uint8Array {
  return new TextEncoder().encode('record ' + i)
}


// The dense stored-hash array AS UPSTREAM BUILT IT. Shipped in the
// vectors rather than reconstructed here, deliberately: reconstructing
// it would mean implementing the append side, which the client half
// does not have and must not grow, and a re-implementation could carry
// an error that cancelled against a matching one in `storedHashIndex`.
// Read from upstream's array, `treeHash` is checked against upstream's
// roots over upstream's hashes, and only the tree walk is under test.
const STORE: Uint8Array[] = V.storedHashes.map(parseHash)

const reader = (indexes: number[]): Uint8Array[] =>
  indexes.map((i) => {
    const h = STORE[i]
    if (undefined === h) {
      throw new Error('index ' + i + ' out of range')
    }
    return h
  })


describe('vectors', () => {

  test('the-vector-file-names-its-upstream', () => {
    // A vector set that does not say what produced it cannot be
    // re-derived, and a stale one would be indistinguishable from a
    // fresh one. UPSTREAM_GO_MOD.md carries the same string.
    Assert.equal(V.upstream, 'golang.org/x/mod@v0.32.0 sumdb/tlog')
    Assert.ok(0 < V.corpus.length)
  })


  test('record-hash', () => {
    Assert.ok(0 < V.recordHash.length)
    for (const c of V.recordHash) {
      const data = new Uint8Array(Buffer.from(c.data, 'base64'))
      Assert.equal(formatHash(recordHash(data)), c.hash,
        'recordHash of ' + JSON.stringify(c.data))
    }
    // And the corpus itself agrees: record 0's leaf hash is the first
    // entry of upstream's stored-hash array, which ties the records
    // this file builds to the array the vectors carry. Without this the
    // two halves could describe different logs and every test still pass.
    Assert.equal(formatHash(recordHash(record(0))), V.storedHashes[0])
  })


  test('node-hash', () => {
    Assert.ok(0 < V.nodeHash.length)
    for (const c of V.nodeHash) {
      Assert.equal(
        formatHash(nodeHash(parseHash(c.left), parseHash(c.right))), c.hash)
    }
  })


  test('stored-hash-index-and-its-inverse', () => {
    Assert.ok(0 < V.storedHashIndex.length)
    for (const c of V.storedHashIndex) {
      Assert.equal(storedHashIndex(c.level, c.n), c.index,
        'storedHashIndex(' + c.level + ', ' + c.n + ')')
      // The inverse is asserted against the SAME vector rather than
      // against itself, so a pair of mutually consistent errors cannot
      // pass: upstream fixed the index, and split must land back on
      // upstream's coordinates.
      const back = splitStoredHashIndex(c.index)
      Assert.deepEqual({ level: back.level, n: back.n },
        { level: c.level, n: c.n },
        'splitStoredHashIndex(' + c.index + ')')
    }
  })


  test('stored-hash-count', () => {
    for (const c of V.storedHashCount) {
      Assert.equal(storedHashCount(c.n), c.count, 'storedHashCount(' + c.n + ')')
    }
  })


  test('tree-hash', () => {
    Assert.ok(0 < V.treeHash.length)
    for (const c of V.treeHash) {
      Assert.equal(formatHash(treeHash(c.n, reader)), c.root,
        'treeHash(' + c.n + ')')
    }
    // The empty tree is SHA-256 of nothing, and is not in the vector
    // set because upstream's TreeHash short-circuits before reading.
    Assert.equal(formatHash(treeHash(0, reader)),
      '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=')
  })


  test('check-record', () => {
    Assert.ok(200 < V.checkRecord.length)
    let accepted = 0
    let rejected = 0
    for (const c of V.checkRecord) {
      const got = checkRecord(
        c.proof.map(parseHash), c.t, parseHash(c.th), c.n, parseHash(c.h))
      Assert.equal(got, c.want, 'checkRecord ' + c.name)
      c.want ? accepted++ : rejected++
    }
    // The balance is itself the assertion: a suite that drifted to all
    // acceptances would stop testing the thing that matters.
    Assert.ok(0 < accepted, 'no accepting inclusion vectors')
    Assert.ok(accepted * 2 < rejected, 'too few rejecting inclusion vectors')
  })


  test('check-tree', () => {
    Assert.ok(150 < V.checkTree.length)
    let accepted = 0
    let rejected = 0
    for (const c of V.checkTree) {
      const got = checkTree(
        c.proof.map(parseHash), c.t, parseHash(c.th), c.n, parseHash(c.h))
      Assert.equal(got, c.want, 'checkTree ' + c.name)
      c.want ? accepted++ : rejected++
    }
    Assert.ok(0 < accepted, 'no accepting consistency vectors')
    Assert.ok(accepted * 2 < rejected, 'too few rejecting consistency vectors')
  })


  test('tile-path-and-its-inverse', () => {
    Assert.ok(0 < V.tilePath.length)
    for (const c of V.tilePath) {
      const t = { h: c.h, l: c.l, n: c.n, w: c.w }
      Assert.equal(tilePath(t), c.path)
      Assert.deepEqual(parseTilePath(c.path), t, 'parseTilePath ' + c.path)
    }
  })


  test('tile-for-index', () => {
    Assert.ok(0 < V.tileForIndex.length)
    for (const c of V.tileForIndex) {
      const t = tileForIndex(c.h, c.index)
      Assert.deepEqual(t, { h: c.h, l: c.tileL, n: c.tileN, w: c.tileW },
        'tileForIndex(' + c.h + ', ' + c.index + ')')
      Assert.equal(tilePath(t), c.path)
    }
  })

})


// SIGNED NOTES. The key, its 32-bit id and every signature below were
// produced by upstream's own signer from a fixed seed, so this checks
// the port against Go's construction rather than against a second
// reading of the specification.
describe('note', () => {

  const N = V.note

  test('the-key-id-is-over-the-encoded-key', () => {
    const v = parseVerifierKey(N.verifierKey)
    Assert.equal(v.name, N.name)
    Assert.equal(v.keyHash, N.keyHash)
    Assert.equal(v.publicKey.length, 32)
    // Hashing the BARE key instead of the algorithm-prefixed encoding
    // is the classic error here, and it produces an id that disagrees
    // with every other implementation. Pinned against upstream's.
    Assert.equal(
      keyHash(N.name, new Uint8Array([1, ...v.publicKey])), N.keyHash)
  })


  test('a-verifier-key-whose-id-was-tampered-with-is-refused', () => {
    // Split on the FIRST TWO plus signs only. Standard base64 includes
    // `+` in its alphabet, so a naive split('+') shreds the key and
    // this test would pass for the wrong reason -- which is exactly why
    // the key is the last field and a name may not contain a plus.
    const p1 = N.verifierKey.indexOf('+')
    const p2 = N.verifierKey.indexOf('+', p1 + 1)
    const name = N.verifierKey.slice(0, p1)
    const hash = N.verifierKey.slice(p1 + 1, p2)
    const key = N.verifierKey.slice(p2 + 1)
    const wrong = hash.replace(/^./, (c: string) => '0' === c ? '1' : '0')
    Assert.throws(() => parseVerifierKey(name + '+' + wrong + '+' + key),
      /invalid verifier hash/)
  })


  test('signed-notes', () => {
    const known = [parseVerifierKey(N.verifierKey)]
    for (const c of N.signed) {
      if (c.want) {
        const note = openNote(c.msg, known)
        Assert.equal(note.text, c.text, c.name)
        Assert.equal(note.verified.length, 1, c.name)
        Assert.equal(note.verified[0].name, N.name, c.name)
      }
      else {
        // A BAD signature by a KNOWN key must throw, not open with an
        // empty verified list -- the difference between "nobody I know
        // signed this" and "someone I know signed something else".
        Assert.throws(() => openNote(c.msg, known), c.name)
      }
    }
  })


  test('an-unknown-signer-is-not-a-failure', () => {
    // The whole witness story depends on this: a note gathering
    // cosignatures a client does not recognise must still open, with
    // those signatures simply absent from `verified`.
    const note = openNote(N.signed[0].msg, [])
    Assert.equal(note.text, N.signed[0].text)
    Assert.deepEqual(note.verified, [])
  })


  test('malformed-notes-are-refused', () => {
    const known = [parseVerifierKey(N.verifierKey)]
    for (const c of N.malformed) {
      Assert.throws(() => openNote(c.msg, known), c.name)
    }
  })


  test('checkpoint-bodies', () => {
    for (const c of N.trees) {
      if (c.want) {
        const t = parseTree(c.text, c.origin)
        Assert.equal(t.n, c.n)
        Assert.equal(formatHash(t.hash), c.hash)
      }
      else {
        Assert.throws(() => parseTree(c.text, c.origin),
          /malformed tree note/, JSON.stringify(c.text))
      }
    }
  })

})
