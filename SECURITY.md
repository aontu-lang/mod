# Security policy

This package verifies transparency-log evidence: checkpoints, inclusion
and consistency proofs, and the signatures over them. It is the half of
the module system that decides whether a recorded pin can be believed,
so a defect that makes it believe something false is a vulnerability and
not an ordinary bug.

## Supported versions

There is nothing published. `0.1.0` has never been released to npm, so
there is no version range to report against: report against `main`,
which is what the first release will ship.

## Reporting a vulnerability

**Do not open a public issue for an exploitable defect.** Use GitHub's
private vulnerability reporting on the engine repository, where this
project's advisories are published:

- <https://github.com/aontu-lang/aontu/security/advisories/new>

A report is most useful as a failing case: the bytes (checkpoint, note,
tile or proof), the call that accepted them, and what upstream
`golang.org/x/mod/sumdb/tlog` does with the same input. The vectors in
`vectors/tlog.json` and the refusals in `test/guards.test.ts` show the
shape of one.

## Scope: acceptance is the surface

**In scope**, because each one lets a client believe evidence it should
have refused:

- **A proof, checkpoint or note accepted that upstream refuses.** This
  port is held to upstream's own output by the golden vectors, and an
  acceptance upstream does not make is a divergence in the direction
  that costs something.
- **A tile-path or stored-hash divergence from the pin.** Addressing and
  index arithmetic decide which bytes get hashed, so computing a
  different one verifies a different record without saying so. The
  no-32-bit-arithmetic rule in
  [UPSTREAM_GO_MOD.md](UPSTREAM_GO_MOD.md) exists for exactly this, and
  a tree index past 2^31 is the case to try.
- **A signature-verification bypass in `src/note.ts`.** A note opened
  for a key that did not sign it, a key hash computed over the bare key
  rather than the algorithm byte and the key, a bad signature by a known
  key treated as an unknown signer, or a duplicate counted twice.
- Malicious-input crashes in any of the parsers. A client parses what a
  log or a lockfile hands it, and neither is trusted.

**Out of scope, but still worth an issue.** A refusal this port makes
where upstream accepts costs availability rather than integrity, so
report it publicly as a correctness defect. The absent proving half is
deliberate, as is the absence of any fetching code: this package
verifies evidence it is handed, and
[UPSTREAM_GO_MOD.md](UPSTREAM_GO_MOD.md) records both under "Intentional
divergences".

## Response expectations

Best effort for a pre-1.0 project with one maintainer, not an SLA.
Acknowledgement within 7 days of a private report; an assessment of
scope and severity with it or shortly after; a fix pinned by a vector or
a guard case before the advisory is published. There is no bug bounty.
Credit is given in the advisory unless you ask otherwise.
