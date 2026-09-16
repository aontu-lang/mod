/* Copyright (c) 2026 aontu-lang, MIT License */

// C2SP tlog-tiles paths, held to the encoding the specification gives:
// digits in groups of three, x on every group but the last, .p/<W> for
// a partial tile, entries for the data level.

import { describe, test } from 'node:test'
import * as Assert from 'node:assert'

import { C2SP_TILE_HEIGHT, c2spTilePath, parseC2spTilePath } from '../dist/index'
import type { C2spTile } from '../dist/index'


describe('c2sp', () => {

  test('paths-follow-the-specification', () => {
    Assert.equal(C2SP_TILE_HEIGHT, 8)
    const cases: [C2spTile, string][] = [
      [{ level: 0, index: 0 }, 'tile/0/000'],
      [{ level: 0, index: 5 }, 'tile/0/005'],
      [{ level: 1, index: 999 }, 'tile/1/999'],
      [{ level: 2, index: 1000 }, 'tile/2/x001/000'],
      [{ level: 3, index: 1234067 }, 'tile/3/x001/x234/067'],
      [{ level: 63, index: 12, width: 1 }, 'tile/63/012.p/1'],
      [{ level: 0, index: 1234, width: 255 }, 'tile/0/x001/234.p/255'],
      [{ level: 'entries', index: 42 }, 'tile/entries/042'],
      [{ level: 'entries', index: 4200, width: 17 }, 'tile/entries/x004/200.p/17'],
    ]
    for (const [tile, path] of cases) {
      Assert.equal(c2spTilePath(tile), path)
      Assert.deepEqual(parseC2spTilePath(path), tile)
    }
  })


  test('formatting-refuses-a-tile-that-cannot-exist', () => {
    Assert.throws(() => c2spTilePath({ level: 0, index: -1 }), /invalid tile index/)
    Assert.throws(() => c2spTilePath({ level: 0, index: 1.5 }), /invalid tile index/)
    Assert.throws(() => c2spTilePath({ level: 0, index: Number.MAX_SAFE_INTEGER + 2 }), /invalid tile index/)
    Assert.throws(() => c2spTilePath({ level: -1, index: 0 }), /invalid tile level/)
    Assert.throws(() => c2spTilePath({ level: 64, index: 0 }), /invalid tile level/)
    Assert.throws(() => c2spTilePath({ level: 0.5, index: 0 }), /invalid tile level/)
    Assert.throws(() => c2spTilePath({ level: 0, index: 0, width: 0 }), /invalid partial tile width/)
    Assert.throws(() => c2spTilePath({ level: 0, index: 0, width: 256 }), /invalid partial tile width/)
    Assert.throws(() => c2spTilePath({ level: 0, index: 0, width: 2.5 }), /invalid partial tile width/)
  })


  test('parsing-refuses-anything-but-the-exact-encoding', () => {
    for (const bad of ['', 'tile', 'tile/0', 'tile/0/', 'tile/0/5', 'tile/0/0005',
      'tile/0/x001', 'tile/0/001/000', 'tile/0/x001/x000', 'tile/00/000', 'tile/01/000',
      'tile/a/000', 'tile/0/000/', 'tile/0/000.p', 'tile/0/000.p/', 'tile/0/000.p/x',
      'tile/0/000.p/01', 'tile/0/000.p/1000', '/tile/0/000', 'tile/0/000 ', 'tiles/0/000',
      'tile/0/x000/001', 'tile/0/x000/x000/001', 'tile/entries/x000/000']) {
      Assert.throws(() => parseC2spTilePath(bad), /malformed tile path/, bad)
    }
    Assert.equal(parseC2spTilePath('tile/0/x009/x007/x199/x254/x740/991').index, 9007199254740991)
    Assert.throws(() => parseC2spTilePath('tile/0/x009/x007/x199/x254/x740/992'), /invalid tile index 9007199254740992/)
    Assert.throws(() => parseC2spTilePath('tile/0/x001/x000/x000/x000/x000/x000/000'), /invalid tile index 1000000000000000000/)
    Assert.throws(() => parseC2spTilePath('tile/0/x000/x000/x000/x000/x000/x000/000'), /malformed tile path/)
    Assert.throws(() => parseC2spTilePath('tile/64/000'), /invalid tile level 64/)
    Assert.throws(() => parseC2spTilePath('tile/0/000.p/0'), /invalid partial tile width 0/)
    Assert.throws(() => parseC2spTilePath('tile/0/000.p/256'), /invalid partial tile width 256/)
  })
})
