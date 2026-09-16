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

### `publish-workflow.patch`

Adds `.github/workflows/publish.yml`, the release workflow: `npm
publish` over OIDC trusted publishing from a `workflow_dispatch` on
`main` (with an optional `expect_sha` guard) or a `v*` tag, then the
tag. Two jobs with different privileges, so no dependency lifecycle
script ever holds a repository-write credential. It reads the version
from `package.json` and publishes exactly that; nothing here commits.

npm keys the trusted publisher to this workflow's filename, so
register it as `publish.yml` and have this file on `main` before the
first dispatch (`docs/manual-tasks.md` §2 in `aontu-lang/system`).

Apply it with:

```sh
git am patch/publish-workflow.patch
```

Then delete the patch, replace everything under `## Pending patches`
with `None.`, drop the one sentence in `README.md` that says the
workflow waits here (the registration sentence before it stays), and
fold all of it into the applied commit with `git commit --amend`. The
folder and this file stay when they are empty, as in `aontu-lang/aontu`.
