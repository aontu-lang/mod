/* Copyright (c) 2026 aontu-lang, MIT License */

export { HASH_SIZE, recordHash, nodeHash, formatHash, parseHash, hashEqual }
  from './hash'
export type { Hash } from './hash'

export {
  maxpow2, trailingZeros, storedHashIndex, splitStoredHashIndex,
  storedHashCount, treeHash,
} from './tree'
export type { HashReader } from './tree'

export { checkRecord, checkTree } from './proof'
export type { RecordProof, TreeProof } from './proof'

// Only C2SP tile paths are exported; sumdb's stay internal, for the vectors.
export { tileForIndex, hashFromTile, newTiles } from './tile'
export type { Tile } from './tile'
export { C2SP_TILE_HEIGHT, c2spTilePath, parseC2spTilePath } from './c2sp'
export type { C2spTile } from './c2sp'

export { SIGNATURE_ENCODING, signedBytes, signerId, parseSignerId, verifyKeyProof, smallOrderKey }
  from './keyproof'
export type { KeyProof } from './keyproof'

export { keyHash, parseVerifierKey, openNote, parseTree } from './note'
export type { Verifier, Note, Tree } from './note'

// Keep a line here, after the last export: docs/contributing/verifier.md, "Coverage".
