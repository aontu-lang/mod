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

- **`npm-pin.patch`** — replaces `npm install -g npm@latest` in
  `publish.yml` with `npm@^11.5.1`. The job that floats onto whatever
  npm shipped that morning is the one holding the publish credential,
  and the upgrade is not needed for its stated reason: Node 24.x already
  bundles an npm above the trusted-publishing floor.

It applies with `git am --3way` against `main`; that is checked, not
assumed.
