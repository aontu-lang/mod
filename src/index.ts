/* Copyright (c) 2026 aontu-lang, MIT License */

// THE TRANSPARENCY-LOG CLIENT for the Aontu module system: the
// VERIFYING half of golang.org/x/mod/sumdb/tlog, ported to TypeScript
// and held to upstream's own output by the golden vectors in
// ../vectors/ (see ../UPSTREAM_GO_MOD.md).
//
// Only the client half is here. A log proves; a client checks. See
// proof.ts for why the provers are deliberately absent.

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

export {
  tileForIndex, hashFromTile, newTiles, tilePath, parseTilePath,
} from './tile'
export type { Tile } from './tile'

export { keyHash, parseVerifierKey, openNote, parseTree } from './note'
export type { Verifier, Note, Tree } from './note'

// The export block alone, which the emitted JavaScript wraps in
// accessor definitions no test can drive -- ADR-002's standing
// exclusion in the canonical port, for the same reason.
/* node:coverage ignore next 3 */
