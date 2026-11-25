/* Copyright (c) 2026 aontu-lang, MIT License */

// Every expectation here came from the pinned upstream, by goref/main.go:
// a disagreement is a defect in the port. See docs/contributing/verifier.md.

import { describe, test } from 'node:test'
import * as Assert from 'node:assert'
import * as Fs from 'node:fs'
import * as Path from 'node:path'

import {
  recordHash, nodeHash, formatHash, parseHash,
  storedHashIndex, splitStoredHashIndex, storedHashCount, treeHash,
  checkRecord, checkTree,
  tileForIndex,
  keyHash, parseVerifierKey, openNote, parseTree,
} from '../dist/index'

// The sumdb path functions are not exported from the package.
import { tilePath, parseTilePath } from '../dist/tile'


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


// Must match `record` in goref/main.go.
function record(i: number): Uint8Array {
  return new TextEncoder().encode('record ' + i)
}


// Upstream's own stored-hash array, so only the tree walk is under test.
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
    // UPSTREAM_GO_MOD.md names the same pin.
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
    // Ties this file's records to the array the vectors carry.
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
      // Against upstream's coordinates, so a pair of matching errors cannot pass.
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
    // Not in the vectors: upstream's TreeHash answers it before reading.
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


// The key, its id and every signature came from upstream's signer.
describe('note', () => {

  const N = V.note

  test('the-key-id-is-over-the-encoded-key', () => {
    const v = parseVerifierKey(N.verifierKey)
    Assert.equal(v.name, N.name)
    Assert.equal(v.keyHash, N.keyHash)
    Assert.equal(v.publicKey.length, 32)
    Assert.equal(
      keyHash(N.name, new Uint8Array([1, ...v.publicKey])), N.keyHash)
  })


  test('a-verifier-key-whose-id-was-tampered-with-is-refused', () => {
    // Split on the leading plus signs only: base64 has `+` in its alphabet.
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
        Assert.throws(() => openNote(c.msg, known), c.name)
      }
    }
  })


  test('a-note-no-known-key-signed-is-refused', () => {
    // As upstream's UnverifiedNoteError refuses it.
    Assert.throws(() => openNote(N.signed[0].msg, []),
      /no verifiable signatures/)
  })


  test('an-unknown-signer-alongside-a-known-one-is-skipped', () => {
    const known = [parseVerifierKey(N.verifierKey)]
    const good = N.signed[0].msg
    const split = good.lastIndexOf('\n\n')
    const stranger = '— other.example ' +
      Buffer.alloc(68).toString('base64') + '\n'
    const note = openNote(good + stranger, known)
    Assert.equal(note.text, N.signed[0].text)
    Assert.equal(note.verified.length, 1)
    Assert.equal(note.verified[0].name, N.name)
    Assert.ok(0 < split)
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
