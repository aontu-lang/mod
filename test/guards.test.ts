/* Copyright (c) 2026 aontu-lang, MIT License */

// THE REFUSALS THE VECTORS DO NOT REACH. The golden vectors in
// vectors.test.ts prove this port agrees with upstream on well-formed
// input and on corrupted proofs. They cannot reach the guards that
// refuse input upstream's own generator would never produce: a
// malformed hash, a tile that is too short for its own width, a proof
// for a record outside the tree.
//
// Those guards are the ones that face the network. Every case here is
// input a hostile server could send, and the assertion is always that
// it is REFUSED -- never that it is handled gracefully, which for a
// verifier is the same thing as accepted.

import { describe, test } from 'node:test'
import * as Assert from 'node:assert'
import * as Fs from 'node:fs'
import * as Path from 'node:path'

import {
  HASH_SIZE, recordHash, nodeHash, formatHash, parseHash, hashEqual,
  maxpow2, trailingZeros, storedHashIndex, storedHashCount, treeHash,
  checkRecord, checkTree,
  tileForIndex, hashFromTile, newTiles, tilePath, parseTilePath,
  keyHash, parseVerifierKey, openNote, parseTree,
} from '../dist/index'
import type { Tile } from '../dist/index'


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
    // 33 bytes: longer, not shorter, because a length check written as
    // `<` instead of `!==` passes this one.
    Assert.throws(() => parseHash(Buffer.alloc(33).toString('base64')),
      /malformed hash/)
    Assert.equal(parseHash(formatHash(H0)).length, HASH_SIZE)
  })

  test('hash-equality-is-length-aware', () => {
    Assert.equal(hashEqual(H0, H0), true)
    Assert.equal(hashEqual(H0, H1), false)
    // A short array must not compare equal to a prefix of a long one.
    Assert.equal(hashEqual(H0, H0.slice(0, 16)), false)
  })

  test('domain-separation-is-real', () => {
    // The whole point of the 0x00/0x01 prefixes: a leaf and a node can
    // never collide, so a 64-byte record cannot be passed off as an
    // interior node. Pinned rather than assumed.
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
    // Zero has no trailing-zero count; upstream answers 64 and so must
    // this, because splitStoredHashIndex's loop depends on it.
    Assert.equal(trailingZeros(0), 64)
    Assert.equal(trailingZeros(1), 0)
    Assert.equal(trailingZeros(8), 3)
  })

  test('the-empty-tree-has-no-stored-hashes', () => {
    Assert.equal(storedHashCount(0), 0)
    Assert.equal(storedHashIndex(0, 0), 0)
  })

  test('a-reader-that-answers-the-wrong-number-of-hashes-is-refused', () => {
    // A tile server that returns short data must not be able to make
    // treeHash compute a root out of whatever it did send.
    Assert.throws(() => treeHash(13, () => []),
      /reader returned 0 hashes for 3 indexes/)
    Assert.throws(() => treeHash(13, (ix) => reader(ix).concat([H0])),
      /reader returned 4 hashes for 3 indexes/)
  })

  test('arithmetic-stays-exact-past-32-bits', () => {
    // The trap this port is written to avoid: JavaScript's `<<` and
    // `>>` coerce to 32 bits, so an index past 2^31 would wrap.
    //
    // The EXPECTED VALUES ARE IN THE VECTORS, not written here. The
    // first draft of this test transcribed them by hand and got
    // storedHashIndex(1, 2^31) wrong -- the port was right and the test
    // was not, which is the exact failure mode a hand-written
    // expectation for large arithmetic has.
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
    // Out of bounds is a REJECTION, not a thrown error: the numbers
    // came off the wire, so refusing is the answer, and a throw here
    // would turn a hostile response into a crash.
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
    // A surplus hash must be refused rather than ignored: accepting it
    // would let one proof stand for more than one tree shape.
    Assert.equal(checkRecord([H1], 1, th, 0, H0), false)
  })

  test('a-consistency-proof-to-the-same-size-is-empty', () => {
    const th = treeHash(13, reader)
    Assert.equal(checkTree([], 13, th, 13, th), true)
    Assert.equal(checkTree([H1], 13, th, 13, th), false)
    // And a non-empty prefix at n < t needs a real proof.
    Assert.equal(checkTree([], 13, th, 8, treeHash(8, reader)), false)
  })

})


describe('tile guards', () => {

  const dataFor = (t: Tile): Uint8Array => {
    // The tile's hashes, laid out as its data: w hashes end to end.
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
    // A level-1 hash inside a tile is NOT stored in the tile directly:
    // it is recomputed from the leaves under it, which is the recursive
    // half of tileHash and the reason a tile of 2^H leaves serves every
    // level within it. Reading only leaf hashes never exercises it.
    const index = storedHashIndex(1, 0)
    const t = tileForIndex(2, index)
    const full: Tile = { ...t, w: Math.pow(2, t.h) }
    const got = hashFromTile(full, dataFor(full), index)
    // And the recomputed value is the stored one: the tile's own
    // arithmetic must agree with the log's.
    Assert.equal(formatHash(got), formatHash(STORE[index]))
  })

  test('a-tile-that-is-too-short-for-its-width-is-refused', () => {
    const t: Tile = { h: 2, l: 0, n: 0, w: 4 }
    Assert.throws(() => hashFromTile(t, new Uint8Array(3 * HASH_SIZE), 0),
      /too short for tile/)
  })

  test('an-index-that-is-not-in-this-tile-is-refused', () => {
    // The check that stops a server answering one tile's request with
    // another tile's bytes.
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
    // Nothing to publish for an empty tree, and nothing for a tree that
    // did not grow.
    Assert.deepEqual(newTiles(2, 0, 0), [])
    Assert.deepEqual(newTiles(2, 8, 8), [])
    // Growing from nothing to 8 records at height 2 publishes the
    // level-0 tiles plus the level-1 tile above them.
    const tiles = newTiles(2, 0, 8)
    Assert.ok(0 < tiles.length)
    for (const t of tiles) {
      Assert.equal(t.h, 2)
      Assert.ok(0 < t.w && t.w <= 4)
      // Every published tile must have a well-formed path that parses
      // back to itself -- otherwise a publisher writes objects no
      // client can name.
      Assert.deepEqual(parseTilePath(tilePath(t)), t)
    }
    // A partial tile appears when the tree does not fill one.
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
    // Level -1 is spelled `data` and is how raw records are addressed.
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
      // Exactly ONE plus: a name and something, with no key field at
      // all. Distinct from the no-plus case, and a separate arm.
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
      'text\n\n— name AA==\n',       // signature under five bytes
    ]) {
      Assert.throws(() => openNote(bad, known), /malformed note/,
        JSON.stringify(bad))
    }
  })

  test('a-note-with-too-many-signature-lines-is-refused', () => {
    const line = '— name ' + Buffer.alloc(40).toString('base64') + '\n'
    Assert.throws(() => openNote('text\n\n' + line.repeat(101), known),
      /malformed note/)
  })

  test('a-duplicated-signature-counts-once', () => {
    // A note padded with the same good signature repeated must not look
    // better-witnessed than a note carrying it once.
    const good = V.note.signed[0].msg as string
    const split = good.lastIndexOf('\n\n')
    const sig = good.slice(split + 2)
    const doubled = good.slice(0, split + 2) + sig + sig
    const note = openNote(doubled, known)
    Assert.equal(note.verified.length, 1)
  })

  test('a-short-signature-by-a-known-key-is-refused', () => {
    // Five bytes is enough to carry a key id and pass the length gate,
    // but not enough to be an Ed25519 signature. A verifier that fed it
    // to the crypto layer and took the exception as "unverified" would
    // turn a malformed signature into a silently skipped one, which is
    // how a known key's signature goes missing without anyone noticing.
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
    // A later version adding lines must not invalidate today's clients:
    // that is the rule that lets the format grow at all.
    const text = V.note.name + '\n13\n' + formatHash(H0) + '\nextra\nmore\n'
    const t = parseTree(text, V.note.name)
    Assert.equal(t.n, 13)
    Assert.equal(formatHash(t.hash), formatHash(H0))
  })

})
