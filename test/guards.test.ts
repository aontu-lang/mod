/* Copyright (c) 2026 aontu-lang, MIT License */

// The refusals the vectors cannot reach: input a hostile server could send.

import { describe, test } from 'node:test'
import * as Assert from 'node:assert'
import * as Fs from 'node:fs'
import * as Path from 'node:path'

import {
  HASH_SIZE, recordHash, nodeHash, formatHash, parseHash, hashEqual,
  maxpow2, trailingZeros, storedHashIndex, storedHashCount, treeHash,
  checkRecord, checkTree,
  tileForIndex, hashFromTile, newTiles,
  keyHash, parseVerifierKey, openNote, parseTree,
} from '../dist/index'
import type { Tile } from '../dist/index'

// The sumdb path functions are not exported from the package.
import { tilePath, parseTilePath } from '../dist/tile'


const V = JSON.parse(Fs.readFileSync(
  Path.join(__dirname, '..', 'vectors', 'tlog.json'), 'utf8'))

const STORE: Uint8Array[] = V.storedHashes.map((s: string) => parseHash(s))
const reader = (indexes: number[]) => indexes.map((i) => STORE[i])

const H0 = recordHash(new TextEncoder().encode('record 0'))
const H1 = recordHash(new TextEncoder().encode('record 1'))


describe('hash guards', () => {

  test('a-hash-that-is-not-32-bytes-is-refused', () => {
    Assert.throws(() => parseHash(''), /malformed hash/)
    Assert.throws(() => parseHash('AAAA'), /malformed hash/)
    // Longer, not shorter: a length check written with `<` passes this one.
    Assert.throws(() => parseHash(Buffer.alloc(33).toString('base64')),
      /malformed hash/)
    Assert.equal(parseHash(formatHash(H0)).length, HASH_SIZE)
  })

  test('a-hash-with-a-non-canonical-spelling-is-refused', () => {
    // Each decodes to the same bytes, and is still refused.
    const good = formatHash(H0)
    for (const bad of [
      good + '!!!!',                                    // trailing junk
      '!!!!' + good,                                    // leading junk
      good.replace(/\+/g, '-').replace(/\//g, '_'),     // base64url
      good.slice(0, -1),                                // unpadded
      good + '=',                                       // over-padded
      good.slice(0, 10) + ' ' + good.slice(10),         // embedded space
      good.slice(0, 10) + '\n' + good.slice(10),        // embedded newline
      ' ' + good,                                       // leading space
    ]) {
      Assert.throws(() => parseHash(bad), /malformed hash/, JSON.stringify(bad))
    }
    // A guard that refused everything would also pass the loop above.
    Assert.ok(hashEqual(parseHash(good), H0))
  })

  test('hash-equality-is-length-aware', () => {
    Assert.equal(hashEqual(H0, H0), true)
    Assert.equal(hashEqual(H0, H1), false)
    Assert.equal(hashEqual(H0, H0.slice(0, 16)), false)
  })

  test('domain-separation-is-real', () => {
    const pair = new Uint8Array(HASH_SIZE * 2)
    pair.set(H0, 0)
    pair.set(H1, HASH_SIZE)
    Assert.equal(hashEqual(recordHash(pair), nodeHash(H0, H1)), false)
  })

})


describe('tree guards', () => {

  test('maxpow2-and-trailing-zeros-at-their-edges', () => {
    Assert.deepEqual(maxpow2(1), { k: 1, l: 0 })
    Assert.deepEqual(maxpow2(2), { k: 1, l: 0 })
    Assert.deepEqual(maxpow2(3), { k: 2, l: 1 })
    Assert.deepEqual(maxpow2(9), { k: 8, l: 3 })
    // Upstream answers 64 for zero, and splitStoredHashIndex depends on it.
    Assert.equal(trailingZeros(0), 64)
    Assert.equal(trailingZeros(1), 0)
    Assert.equal(trailingZeros(8), 3)
  })

  test('the-empty-tree-has-no-stored-hashes', () => {
    Assert.equal(storedHashCount(0), 0)
    Assert.equal(storedHashIndex(0, 0), 0)
  })

  test('a-reader-that-answers-the-wrong-number-of-hashes-is-refused', () => {
    Assert.throws(() => treeHash(13, () => []),
      /reader returned 0 hashes for 3 indexes/)
    Assert.throws(() => treeHash(13, (ix) => reader(ix).concat([H0])),
      /reader returned 4 hashes for 3 indexes/)
  })

  test('arithmetic-stays-exact-past-32-bits', () => {
    // The expected values come from the vectors: hand-written ones are guesses.
    const big = V.storedHashIndex.filter((c: any) => 2 ** 31 <= c.n)
    Assert.ok(0 < big.length, 'no past-32-bit index vectors')
    for (const c of big) {
      Assert.equal(storedHashIndex(c.level, c.n), c.index,
        'storedHashIndex(' + c.level + ', ' + c.n + ')')
      Assert.ok(Number.isSafeInteger(c.index))
    }
    const bigCount = V.storedHashCount.filter((c: any) => 2 ** 31 <= c.n)
    Assert.ok(0 < bigCount.length)
    for (const c of bigCount) {
      Assert.equal(storedHashCount(c.n), c.count)
    }
  })

})


describe('proof guards', () => {

  test('a-record-outside-the-tree-is-refused', () => {
    Assert.equal(checkRecord([], 0, H0, 0, H0), false)
    Assert.equal(checkRecord([], 3, H0, 3, H0), false)
    Assert.equal(checkRecord([], 3, H0, -1, H0), false)
    Assert.equal(checkRecord([], -1, H0, 0, H0), false)
  })

  test('a-tree-outside-its-own-bounds-is-refused', () => {
    Assert.equal(checkTree([], 0, H0, 0, H0), false)
    Assert.equal(checkTree([], 3, H0, 4, H0), false)
    Assert.equal(checkTree([], 3, H0, 0, H0), false)
  })

  test('a-one-record-tree-takes-an-empty-proof-and-nothing-else', () => {
    const th = treeHash(1, reader)
    Assert.equal(checkRecord([], 1, th, 0, H0), true)
    Assert.equal(checkRecord([H1], 1, th, 0, H0), false)
  })

  test('a-consistency-proof-to-the-same-size-is-empty', () => {
    const th = treeHash(13, reader)
    Assert.equal(checkTree([], 13, th, 13, th), true)
    Assert.equal(checkTree([H1], 13, th, 13, th), false)
    Assert.equal(checkTree([], 13, th, 8, treeHash(8, reader)), false)
  })

})


describe('tile guards', () => {

  const dataFor = (t: Tile): Uint8Array => {
    const out = new Uint8Array(t.w * HASH_SIZE)
    for (let i = 0; i < t.w; i++) {
      out.set(STORE[storedHashIndex(t.l * t.h, t.n * Math.pow(2, t.h) + i)],
        i * HASH_SIZE)
    }
    return out
  }

  test('a-hash-can-be-read-out-of-its-tile', () => {
    const t = tileForIndex(2, storedHashIndex(0, 5))
    const full: Tile = { ...t, w: Math.pow(2, t.h) }
    const got = hashFromTile(full, dataFor(full), storedHashIndex(0, 5))
    Assert.equal(formatHash(got), formatHash(STORE[storedHashIndex(0, 5)]))
  })

  test('a-hash-above-the-leaf-level-is-recomputed-from-the-tile', () => {
    // Recomputed from the leaves under it, which reading a leaf never exercises.
    const index = storedHashIndex(1, 0)
    const t = tileForIndex(2, index)
    const full: Tile = { ...t, w: Math.pow(2, t.h) }
    const got = hashFromTile(full, dataFor(full), index)
    Assert.equal(formatHash(got), formatHash(STORE[index]))
  })

  test('a-tile-that-is-too-short-for-its-width-is-refused', () => {
    const t: Tile = { h: 2, l: 0, n: 0, w: 4 }
    Assert.throws(() => hashFromTile(t, new Uint8Array(3 * HASH_SIZE), 0),
      /too short for tile/)
  })

  test('an-index-that-is-not-in-this-tile-is-refused', () => {
    const t: Tile = { h: 2, l: 0, n: 0, w: 4 }
    Assert.throws(() => hashFromTile(t, dataFor(t), storedHashIndex(0, 500)),
      /is in .* not /)
  })

  test('an-impossible-tile-is-refused', () => {
    const data = new Uint8Array(64 * HASH_SIZE)
    for (const bad of [
      { h: 0, l: 0, n: 0, w: 1 },
      { h: 31, l: 0, n: 0, w: 1 },
      { h: 2, l: -1, n: 0, w: 1 },
      { h: 2, l: 64, n: 0, w: 1 },
      { h: 2, l: 0, n: 0, w: 0 },
      { h: 2, l: 0, n: 0, w: 5 },
    ] as Tile[]) {
      Assert.throws(() => hashFromTile(bad, data, 0), /invalid tile|malformed/,
        JSON.stringify(bad))
    }
  })

  test('tile-height-must-be-positive', () => {
    Assert.throws(() => tileForIndex(0, 0), /invalid height/)
    Assert.throws(() => newTiles(0, 0, 1), /invalid height/)
  })

  test('new-tiles-cover-a-growing-tree', () => {
    Assert.deepEqual(newTiles(2, 0, 0), [])
    Assert.deepEqual(newTiles(2, 8, 8), [])
    const tiles = newTiles(2, 0, 8)
    Assert.ok(0 < tiles.length)
    for (const t of tiles) {
      Assert.equal(t.h, 2)
      Assert.ok(0 < t.w && t.w <= 4)
      Assert.deepEqual(parseTilePath(tilePath(t)), t)
    }
    Assert.ok(newTiles(2, 0, 7).some((t) => 4 > t.w))
  })

  test('a-malformed-tile-path-is-refused', () => {
    for (const bad of [
      '', 'tile', 'tile/2/0', 'notatile/2/0/000',
      'tile/x/0/000', 'tile/0/0/000', 'tile/31/0/000', 'tile/2/-1/000',
      'tile/2/0/00', 'tile/2/0/0000', 'tile/2/0/x000/000',
      'tile/2/0/000.p/0', 'tile/2/0/000.p/4', 'tile/2/0/000.p/x',
      'tile/2/0/abc',
    ]) {
      Assert.throws(() => parseTilePath(bad), /malformed tile path/,
        JSON.stringify(bad))
    }
  })

  test('the-data-level-round-trips', () => {
    const t: Tile = { h: 2, l: -1, n: 7, w: 4 }
    Assert.equal(tilePath(t), 'tile/2/data/007')
    Assert.deepEqual(parseTilePath('tile/2/data/007'), t)
  })

})


describe('note guards', () => {

  const known = [parseVerifierKey(V.note.verifierKey)]

  test('a-malformed-verifier-key-is-refused', () => {
    for (const bad of [
      '', 'noplus', '+missing+name', 'name+notahex+AAAA',
      'name+0000000+AAAA', 'na me+00000000+AAAA', 'name+00000000+',
      // One plus only: no key field at all.
      'name+00000000',
    ]) {
      Assert.throws(() => parseVerifierKey(bad), /note:/, JSON.stringify(bad))
    }
  })

  test('a-key-of-the-wrong-algorithm-or-length-is-refused', () => {
    const name = 'x.example'
    for (const key of [
      new Uint8Array([2, ...new Uint8Array(32)]),   // wrong algorithm
      new Uint8Array([1, ...new Uint8Array(16)]),   // wrong length
    ]) {
      const kh = keyHash(name, key)
      const vkey = name + '+' + kh.toString(16).padStart(8, '0') + '+' +
        Buffer.from(key).toString('base64')
      Assert.throws(() => parseVerifierKey(vkey), /unknown verifier algorithm/)
    }
  })

  test('a-signature-line-that-is-not-one-is-refused', () => {
    for (const bad of [
      'text\n\n— name\n',            // no space, so no signature
      'text\n\nnot-a-sig-line\n',
      'text\n\n—  AAAAAAA=\n',       // empty name
      'text\n\n— name \n',           // empty signature
      'text\n\n— name AA==\n',       // signature too short for a key id
    ]) {
      Assert.throws(() => openNote(bad, known), /malformed note/,
        JSON.stringify(bad))
    }
  })

  test('a-signature-whose-base64-is-not-canonical-is-refused', () => {
    // Every spelling decodes to the same valid signature bytes.
    const good = V.note.signed[0].msg as string
    const line = good.slice(good.lastIndexOf('\n', good.length - 2) + 1)
    const head = good.slice(0, good.length - line.length)
    const b64 = line.slice(line.lastIndexOf(' ') + 1).replace(/\n$/, '')
    const prefix = line.slice(0, line.length - b64.length - 1)

    Assert.equal(openNote(good, known).verified.length, 1)

    for (const bad of [
      b64 + '!!!!',
      b64.replace(/=+$/, ''),
      b64.replace(/\+/g, '-').replace(/\//g, '_'),
      b64.slice(0, 8) + ' ' + b64.slice(8),
    ]) {
      Assert.throws(() => openNote(head + prefix + ' ' + bad + '\n', known),
        /malformed note/, JSON.stringify(bad))
    }
  })

  test('a-verifier-key-whose-base64-is-not-canonical-is-refused', () => {
    const vkey = V.note.verifierKey as string
    const plus2 = vkey.lastIndexOf('+')
    const head = vkey.slice(0, plus2 + 1)
    const key64 = vkey.slice(plus2 + 1)
    for (const bad of [key64 + '!!!!', ' ' + key64, key64.slice(0, 4) + ' ' + key64.slice(4)]) {
      Assert.throws(() => parseVerifierKey(head + bad),
        /malformed verifier id/, JSON.stringify(bad))
    }
    Assert.equal(parseVerifierKey(vkey).name, V.note.name)
  })

  test('a-name-is-scanned-with-gos-space-set-not-javascripts', () => {
    const key = V.note.verifierKey.slice(V.note.verifierKey.indexOf('+'))
    for (const cp of [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0,
      0x1680, 0x2000, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000]) {
      const name = 'x' + String.fromCodePoint(cp) + 'example'
      Assert.throws(() => parseVerifierKey(name + key),
        /malformed verifier id/, 'U+' + cp.toString(16))
    }
    // Not spaces to Go: these reach the hash check instead.
    for (const cp of [0xfeff, 0x200b, 0x180e]) {
      const name = 'x' + String.fromCodePoint(cp) + 'example'
      Assert.throws(() => parseVerifierKey(name + key),
        /invalid verifier hash/, 'U+' + cp.toString(16))
    }
  })

  test('a-note-with-too-many-signature-lines-is-refused', () => {
    const line = '— name ' + Buffer.alloc(40).toString('base64') + '\n'
    Assert.throws(() => openNote('text\n\n' + line.repeat(101), known),
      /malformed note/)
  })

  test('a-duplicated-signature-counts-once', () => {
    const good = V.note.signed[0].msg as string
    const split = good.lastIndexOf('\n\n')
    const sig = good.slice(split + 2)
    const doubled = good.slice(0, split + 2) + sig + sig
    const note = openNote(doubled, known)
    Assert.equal(note.verified.length, 1)
  })

  test('a-short-signature-by-a-known-key-is-refused', () => {
    // Long enough to carry a key id, too short to be a signature: refused, not skipped.
    const sig = Buffer.alloc(10)
    sig.writeUInt32BE(V.note.keyHash, 0)
    const msg = 'text\n\n— ' + V.note.name + ' ' +
      sig.toString('base64') + '\n'
    Assert.throws(() => openNote(msg, known), /invalid signature for key/)
  })

  test('a-checkpoint-body-with-a-short-hash-is-refused', () => {
    Assert.throws(
      () => parseTree(V.note.name + '\n13\nAAAA\n', V.note.name),
      /malformed tree note/)
  })

  test('a-checkpoint-body-that-is-absurdly-long-is-refused', () => {
    const huge = V.note.name + '\n13\n' + formatHash(H0) + '\n' +
      'x'.repeat(1000001)
    Assert.throws(() => parseTree(huge, V.note.name), /malformed tree note/)
  })

  test('extra-checkpoint-lines-are-ignored-for-forwards-compatibility', () => {
    const text = V.note.name + '\n13\n' + formatHash(H0) + '\nextra\nmore\n'
    const t = parseTree(text, V.note.name)
    Assert.equal(t.n, 13)
    Assert.equal(formatHash(t.hash), formatHash(H0))
  })

})
