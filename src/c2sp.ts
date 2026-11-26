/* Copyright (c) 2026 aontu-lang, MIT License */

// C2SP tlog-tiles addressing (https://c2sp.org/tlog-tiles); the encoding is
// described in docs/contributing/verifier.md, "Tiles and their paths".

export const C2SP_TILE_HEIGHT = 8

// A tile address. `entries` is the data level; `width` is present for a
// partial tile only.
export type C2spTile = {
  level: number | 'entries'
  index: number
  width?: number
}

const MAX_LEVEL = 63
const FULL_WIDTH = Math.pow(2, C2SP_TILE_HEIGHT)


function indexPath(n: number): string {
  const digits = String(n)
  const groups: string[] = []
  let rest = digits.length % 3 === 0 ? digits : '0'.repeat(3 - digits.length % 3) + digits
  for (; 0 < rest.length; rest = rest.slice(3)) {
    groups.push(rest.slice(0, 3))
  }
  return groups.map((g, i) => i < groups.length - 1 ? 'x' + g : g).join('/')
}


// The path of a tile.
export function c2spTilePath(t: C2spTile): string {
  if (!Number.isSafeInteger(t.index) || 0 > t.index) {
    throw new Error('c2sp: invalid tile index ' + t.index)
  }
  if ('entries' !== t.level && (!Number.isInteger(t.level) || 0 > t.level || MAX_LEVEL < t.level)) {
    throw new Error('c2sp: invalid tile level ' + t.level)
  }
  if (undefined !== t.width && (!Number.isInteger(t.width) || 1 > t.width || FULL_WIDTH <= t.width)) {
    throw new Error('c2sp: invalid partial tile width ' + t.width)
  }
  return 'tile/' + t.level + '/' + indexPath(t.index) +
    (undefined === t.width ? '' : '.p/' + t.width)
}


// The tile a path names. A path that does not format back to itself is refused.
export function parseC2spTilePath(path: string): C2spTile {
  const m = /^tile\/(entries|0|[1-9][0-9]?)\/((?:x[0-9]{3}\/)*[0-9]{3})(?:\.p\/(0|[1-9][0-9]{0,2}))?$/.exec(path)
  if (null == m) {
    throw new Error('c2sp: malformed tile path ' + JSON.stringify(path))
  }
  const level = 'entries' === m[1] ? 'entries' : Number(m[1])
  if ('entries' !== level && MAX_LEVEL < level) {
    throw new Error('c2sp: invalid tile level ' + m[1])
  }
  const digits = m[2].replace(/x|\//g, '').replace(/^0+(?=.)/, '')
  const index = Number(digits)
  if (!Number.isSafeInteger(index)) {
    throw new Error('c2sp: invalid tile index ' + digits)
  }
  const t: C2spTile = { level, index }
  if (undefined !== m[3]) {
    const width = Number(m[3])
    if (1 > width || FULL_WIDTH <= width) {
      throw new Error('c2sp: invalid partial tile width ' + m[3])
    }
    t.width = width
  }
  if (c2spTilePath(t) !== path) {
    throw new Error('c2sp: malformed tile path ' + JSON.stringify(path))
  }
  return t
}
