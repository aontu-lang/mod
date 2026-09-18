# Patches awaiting a push with the `workflow` scope

A change under `.github/workflows/` can only be pushed by a credential
that holds GitHub's `workflow` scope. When a writing session does not
have that scope, the change travels here instead as a patch against
`main`, for a maintainer to apply and push.

Remove the patch in the same change that applies it, so this folder
holds only what is still pending. `git am` keeps the patch's author and
records you as committer, so `user.name` and `user.email` must be set;
add `--reset-author` to the amend below to take the commit as your own.

## Pending patches

- **`engines-floor-matrix.patch`** — adds `22.x` to `build.yml`'s
  `node-version` matrix, so the floor `package.json` declares is the
  lowest version CI actually runs. Nothing depends on it; apply it
  whenever.
- **`provenance-explicit.patch`** — passes `--provenance` to the
  `npm publish` in `publish.yml`. npm's own auto-enable is conditional
  and fails quietly; the flag makes a missing attestation fail the
  release instead. **Apply before the first release** if the
  attestation is meant to be a guarantee rather than a default.

Both apply with `git am --3way` against `main` and are independent of
each other.
