/* Copyright (c) 2026 aontu-lang, MIT License */

// Derived from golang.org/x/mod/sumdb/tlog (tile.go).
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style licence; see
// LICENSES/BSD-3-Clause-Go.txt and THIRD_PARTY_NOTICES.md.
//
// TILES: the log's hashes cut into fixed-height blocks, each a single
// immutable object at a stable path. This is what makes a log servable
// as static files behind a CDN with no request-shaped computation --
// the C2SP `tlog-tiles` shape, and the direction Certificate
// Transparency and Sigstore both converged on after starting with
// parameterised proof endpoints.
//
// The path encoding chunks N three digits at a time (`x123/x456/789`)
// so no directory holds more than a few thousand entries. That is an
// operational detail of the FORMAT, not of any one server, which is why
// it is here and must match upstream exactly: a client that computes a
// different path fetches a 404 and calls it a missing tile.
//
// The same no-bitwise-arithmetic rule as tree.ts applies, and harder:
// `n << level >> H` is three shifts deep in one expression upstream,
// and every one of them is a silent 32-bit truncation in JavaScript.

import { HASH_SIZE, nodeHash } from './hash'
import { splitStoredHashIndex } from './tree'
import type { Hash } from './hash'


// A tile of hashes. H is its height, L its level in the tiling, N its
// number within that level, and W its width -- W < 2^H is a partial
// tile, which is how the newest, still-growing tile is published.
export type Tile = {
  h: number
  l: number
  n: number
  w: number
}


// Right shift, as division. Tolerates a shift count past 53 by
// answering 0, which is what the arithmetic means and what a real
// `>>` would NOT do in JavaScript (it masks the count to 5 bits, so
// `x >> 64` is `x >> 0` -- the exact trap this avoids).
function shr(n: number, bits: number): number {
  return Math.floor(n / Math.pow(2, bits))
}

// Left shift, as multiplication.
function shl(n: number, bits: number): number {
  return n * Math.pow(2, bits)
}


// The tile of height h holding the given stored-hash index, together
// with the byte range within that tile's data.
function tileForIndexRange(h: number, index: number):
  { tile: Tile, start: number, end: number } {
  const split = splitStoredHashIndex(index)
  let level = split.level
  let n = split.n

  const l = Math.floor(level / h)
  level -= l * h                      // level within the tile
  const tn = shr(shl(n, level), h)
  n -= shr(shl(tn, h), level)         // n within the tile, at that level
  const w = shl(n + 1, level)

  return {
    tile: { h, l, n: tn, w },
    start: shl(n, level) * HASH_SIZE,
    end: shl(n + 1, level) * HASH_SIZE,
  }
}


// The tile of height h and least width holding the given index.
export function tileForIndex(h: number, index: number): Tile {
  if (h <= 0) {
    throw new Error('tileForIndex: invalid height ' + h)
  }
  return tileForIndexRange(h, index).tile
}


// The hash at `index`, read out of tile t's data.
//
// Every one of these guards is a rejection of untrusted input rather
// than an assertion about the caller: tile bytes come off the network,
// and a tile that is too short, or is not the tile the index lives in,
// must be refused rather than read past.
export function hashFromTile(t: Tile, data: Uint8Array, index: number): Hash {
  if (t.h < 1 || t.h > 30 || t.l < 0 || t.l >= 64 ||
    t.w < 1 || t.w > Math.pow(2, t.h)) {
    throw new Error('tlog: invalid tile ' + tilePath(t))
  }
  if (data.length < t.w * HASH_SIZE) {
    throw new Error('tlog: data len ' + data.length +
      ' too short for tile ' + tilePath(t))
  }
  const got = tileForIndexRange(t.h, index)
  if (t.l !== got.tile.l || t.n !== got.tile.n || t.w < got.tile.w) {
    throw new Error('tlog: index ' + index + ' is in ' +
      tilePath(got.tile) + ' not ' + tilePath(t))
  }
  return tileHash(data.subarray(got.start, got.end))
}


// The subtree hash of the (2^K)-1 hashes in data.
function tileHash(data: Uint8Array): Hash {
  // Upstream panics here. Unreachable through hashFromTile, whose
  // computed range is always at least one hash wide, and kept so the
  // translation stays line-comparable with upstream.
  /* node:coverage ignore next 3 */
  if (0 === data.length) {
    throw new Error('tlog: bad math in tileHash')
  }
  if (HASH_SIZE === data.length) {
    return new Uint8Array(data)
  }
  const n = Math.floor(data.length / 2)
  return nodeHash(tileHash(data.subarray(0, n)), tileHash(data.subarray(n)))
}


// The tiles that must be published when the tree grows from oldTreeSize
// to newTreeSize.
export function newTiles(
  h: number, oldTreeSize: number, newTreeSize: number,
): Tile[] {
  if (h <= 0) {
    throw new Error('newTiles: invalid height ' + h)
  }
  const tiles: Tile[] = []
  for (let level = 0; 0 < shr(newTreeSize, h * level); level++) {
    const oldN = shr(oldTreeSize, h * level)
    const newN = shr(newTreeSize, h * level)
    if (oldN === newN) {
      continue
    }
    for (let n = shr(oldN, h); n < shr(newN, h); n++) {
      tiles.push({ h, l: level, n, w: Math.pow(2, h) })
    }
    const n = shr(newN, h)
    const w = newN - shl(n, h)
    if (0 < w) {
      tiles.push({ h, l: level, n, w })
    }
  }
  return tiles
}


// Three digits at a time, so no directory grows unbounded.
const PATH_BASE = 1000


// The path describing t: `tile/<h>/<l>/<nnn>` with `.p/<w>` appended
// for a partial tile, and level -1 spelled `data`.
export function tilePath(t: Tile): string {
  let n = t.n
  let nStr = pad3(n % PATH_BASE)
  for (; PATH_BASE <= n;) {
    n = Math.floor(n / PATH_BASE)
    nStr = 'x' + pad3(n % PATH_BASE) + '/' + nStr
  }
  const pStr = t.w !== Math.pow(2, t.h) ? '.p/' + t.w : ''
  const l = -1 === t.l ? 'data' : String(t.l)
  return 'tile/' + t.h + '/' + l + '/' + nStr + pStr
}


function pad3(n: number): string {
  return String(n).padStart(3, '0')
}


// The inverse of tilePath.
//
// THE LAST LINE IS THE WHOLE CHECK. Upstream re-renders the parsed tile
// and refuses anything that does not round-trip, which is how a path
// with a leading zero, a redundant `x000/`, or any other second
// spelling of the same coordinates is rejected. Without it a tile would
// have more than one name, and a cache keyed by path would hold the
// same tile twice under names a client could not tell apart.
export function parseTilePath(path: string): Tile {
  const f = path.split('/')
  if (f.length < 4 || 'tile' !== f[0]) {
    throw new Error('tlog: malformed tile path "' + path + '"')
  }
  const h = intOf(f[1])
  const isData = 'data' === f[2]
  const l = isData ? 0 : intOf(f[2])
  if (null == h || null == l || h < 1 || l < 0 || h > 30) {
    throw new Error('tlog: malformed tile path "' + path + '"')
  }

  let w = Math.pow(2, h)
  let rest = f.slice(3)
  const dotP = f[f.length - 2]
  if (dotP.endsWith('.p')) {
    const ww = intOf(f[f.length - 1])
    if (null == ww || ww <= 0 || ww >= w) {
      throw new Error('tlog: malformed tile path "' + path + '"')
    }
    w = ww
    rest = f.slice(3, f.length - 1)
    rest[rest.length - 1] = dotP.slice(0, dotP.length - '.p'.length)
  }

  let n = 0
  for (const s of rest) {
    const nn = intOf(s.startsWith('x') ? s.slice(1) : s)
    if (null == nn || nn < 0 || nn >= PATH_BASE) {
      throw new Error('tlog: malformed tile path "' + path + '"')
    }
    n = n * PATH_BASE + nn
  }

  const t: Tile = { h, l: isData ? -1 : l, n, w }
  if (path !== tilePath(t)) {
    throw new Error('tlog: malformed tile path "' + path + '"')
  }
  return t
}


// Go's strconv.Atoi, near enough: digits and nothing else.
// `Number('')` is 0 and `Number('1e3')` is 1000, so neither is usable
// here -- a path element that is not plainly digits is malformed.
//
// LEADING ZEROS ARE ACCEPTED, and must be: the path encodes N in
// zero-padded three-digit groups (`x001/x234/067`), so `000` is the
// ordinary spelling of nought and a stricter rule rejects a
// well-formed path. Refusing them here also duplicates a check that
// already exists in a stronger form -- `parseTilePath` re-renders the
// tile and compares, which rejects every alternate spelling including
// `0000` and `x000/000`, and does it for the whole path rather than
// one element at a time. (A stricter rule here is exactly what the
// differential vectors caught: upstream's `strconv.Atoi("000")` is 0,
// and this port refused it.)
function intOf(s: string): number | undefined {
  if (!/^[0-9]+$/.test(s)) {
    return undefined
  }
  return Number(s)
}
