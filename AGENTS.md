# @aontu/mod: agent and contributor guide

`@aontu/mod` is the client half of the aontu package system's proof
contract. It is a TypeScript port of the verifying half of Go's
`golang.org/x/mod/sumdb/tlog` and `sumdb/note`, held to upstream by
golden vectors that a Go program generates from the pinned upstream,
with C2SP `tlog-tiles` addressing and the key provider's proof beside
it. It verifies bytes it is handed; it fetches nothing and signs
nothing.

Read [DEV-PROCESS.md](DEV-PROCESS.md) first: it says how work is done
here (the prompt log, testing, documentation, code comments, and what
each folder holds). This file holds what is particular to this
repository.

## Where the detail lives

| Page | What it carries |
|------|-----------------|
| [DEV-PROCESS.md](DEV-PROCESS.md) | how work is done; read first |
| [STYLE-GUIDE.md](STYLE-GUIDE.md) | how documentation is written; normative for every published page |
| [ADR.md](ADR.md) | the decision record, and who may add to it |
| [UPSTREAM_GO_MOD.md](UPSTREAM_GO_MOD.md) | the pin, what is derived from where, the intentional divergences; read before changing `src/` |
| [docs/contributing/verifier.md](docs/contributing/verifier.md) | why the port is shaped as it is: the rules a change keeps |
| [PROOF-CONTRACT.md](PROOF-CONTRACT.md) | what a client verifies, and the key proof's encoding |
| [SECURITY.md](SECURITY.md) | the security policy and what is in scope |
| [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | the BSD-3-Clause notice for the derived files |
| [patch/README.md](patch/README.md) | workflow changes waiting for a push with the `workflow` scope |

## Repository layout

```
.
├── AGENTS.md          # this file; CLAUDE.md links to it
├── ADR.md             # the decision record
├── DEV-PROCESS.md     # how work is done
├── STYLE-GUIDE.md     # how documentation is written
├── src/               # the TypeScript port (published)
├── test/              # the node:test suites, compiled to dist-test/
├── vectors/tlog.json  # golden vectors, generated, never edited by hand
├── goref/             # the Go program that generates the vectors
├── docs/contributing/ # contributor documentation
├── admin/scripts/     # the comment and prose gates, and vale-counts
├── patch/             # pending workflow changes, as patches
├── sketch/            # working files and the prompt log, to be ignored
└── .githooks/         # the pre-push hook running the comment gate
```

`dist/` and `dist-test/` are build output and are not committed. The
published tarball is what `files` in `package.json` lists: `dist/`,
`src/`, `vectors/` and the top-level notices. It never takes `admin/`,
`sketch/`, `docs/` or `goref/`.

## Build and test

Node 22 or later. There are no npm lifecycle hooks, and `.npmrc` sets
`ignore-scripts`; a script that needs the build runs it.

```sh
npm ci              # install the toolchain
npm test            # the gates, then build, then the suites against the vectors
npm run gates       # the comment gate and the prose gate alone
npm run vale        # Vale over the gated pages, then the recorded counts
npm run test-cov-check   # the suites under the 100 % coverage floor
npm run vectors     # regenerate vectors/tlog.json from the pinned upstream Go
```

`npm run vectors` needs Go and network access; the regenerated file
must equal the committed one, and CI checks that it does. `npm run
vale` needs [Vale](https://vale.sh) on the path, at the version CI
pins; it runs `vale sync` first, which fetches the Google package that
`.vale.ini` pins by URL.

### Before you push

The quick check, well inside two minutes:

```sh
npm test
```

That runs the comment gate (`node admin/scripts/comment-gate.cjs`),
the prose gate (`node admin/scripts/prose-gate.cjs`), the build and
every suite. Where a page changed, run `npm run vale` too. Where
`goref/` or the pin changed, run `npm run vectors` and read the diff.

`git config core.hooksPath .githooks` points git at the pre-push hook,
which runs the comment gate. It is a convenience: `npm test` in CI is
the enforcement.

### The gates

- **The comment gate** reads `src/`, `test/`, `goref/` and
  `admin/scripts/`, as `admin/scripts/comment-gate.json` sets it, and
  leaves out `vectors/`, `dist/`, `dist-test/` and `node_modules`. A
  file derived from upstream carries the Go copyright notice on one
  line, which the gate reads as a licence header.
- **The prose gate** reads the published pages (README.md,
  PROOF-CONTRACT.md, SECURITY.md, UPSTREAM_GO_MOD.md,
  THIRD_PARTY_NOTICES.md) and `docs/`, as
  `admin/scripts/prose-gate.json` lists them, and checks the links of
  every markdown file outside `sketch/`. `--list` prints the pages Vale
  reads.
- **Vale** runs at error level over the same pages, and
  `node admin/scripts/vale-counts.cjs` checks every count `.vale.ini`
  records. `--write` re-measures them, with the Vale version CI pins.

## Releasing

Releases publish over npm's OIDC trusted publishing, by dispatching
`publish.yml` from `main`, or on a pushed `v*` tag, which publishes
without tagging. The version is the one in `package.json` on the
branch: the bump is a reviewed commit, and the release is a button.
Never publish from a local token, which bypasses the OIDC exchange and
carries no provenance attestation.

## The rules that are easy to get wrong

- **No `<<`, `>>`, `&` or `|` on a tree index.** JavaScript's bitwise
  operators truncate to 32 bits; see
  [docs/contributing/verifier.md](docs/contributing/verifier.md#arithmetic).
- **The vectors are derived, never authored.** A change to an expected
  value comes from `npm run vectors` on the pin, not from an edit.
- **A refusal stays a refusal.** A change that makes the port accept
  what upstream refuses is a security defect; see
  [SECURITY.md](SECURITY.md).
- **Only the verifying half is ported.** No prover, no signer, no
  fetching code.
- **A derived file keeps its one-line Go copyright notice.**
- **Only the maintainer adds a decision to [ADR.md](ADR.md).** An agent
  may propose one.
- **A change under `.github/workflows/` travels as a patch** in
  `patch/` when the pushing credential lacks the `workflow` scope.
- **Every prompt is logged** in `sketch/PROMPT-LOG.md` before the work
  starts, as [DEV-PROCESS.md](DEV-PROCESS.md#the-prompt-log) says.
