# Patches awaiting a push with the `workflow` scope

A change under `.github/workflows/` can only be pushed by a credential
that holds GitHub's `workflow` scope. When a writing session does not
have that scope, the change travels here instead as a patch against
`main`, for a maintainer to apply and push.

Remove the patch in the same change that applies it, so this folder
holds only what is still pending. `git am` keeps the patch's author and
records you as committer, so `user.name` and `user.email` must be set.
Fold the patch's removal into its commit with `git commit --amend`, and
add `--reset-author` to take the commit as your own.

## Pending patches

- [`0001-ci-vale.patch`](0001-ci-vale.patch) adds a `vale` job to
  `build.yml`: it installs Vale 3.14.0, the version the aontu
  repository pins, and runs `npm run vale`. The comment and prose gates
  need no workflow change, since `npm test` runs them. Apply it with
  `git am patch/0001-ci-vale.patch`, remove the patch and this entry,
  and fold the removal in with `git commit --amend`.
