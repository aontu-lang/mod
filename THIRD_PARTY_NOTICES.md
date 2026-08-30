# Third-party notices

## golang.org/x/mod — BSD-3-Clause

`src/hash.ts`, `src/tree.ts`, `src/proof.ts`, `src/tile.ts` and
`src/note.ts` are **mechanical translations** of
`golang.org/x/mod/sumdb/tlog` and `golang.org/x/mod/sumdb/note`,
pinned at **v0.32.0**. `goref/main.go` links the same packages
directly.

Copyright 2019 The Go Authors. All rights reserved.
Licensed under the BSD-3-Clause licence, reproduced verbatim in
[`LICENSES/BSD-3-Clause-Go.txt`](LICENSES/BSD-3-Clause-Go.txt).

Every derived file carries the attribution and the licence pointer in
its own header, because a notice that lives only in this file is a
notice that goes missing the first time someone copies one file out.

The remainder of this repository is MIT (see [`LICENSE`](LICENSE)).
The BSD-3 notice and disclaimer above apply to the derived material
regardless of that.

### Intentional divergences

Documented in [`UPSTREAM_GO_MOD.md`](UPSTREAM_GO_MOD.md), which is the
file to read before changing anything in `src/`.
