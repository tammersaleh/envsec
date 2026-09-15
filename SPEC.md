# envsec

`envsec` exports 1Password secrets as environment variables. 1Password is the
only manifest. The macOS login keychain is a local cache so that shells start
without calling `op`. Written for one user's laptops; agent-first output.

## Design principles

- **1Password is the manifest.** An item opts in with a tag. Which vars it
  yields is read from its fields. No config file, no list in the code.
- **Nothing environment-specific in the binary.** Accounts come from `op account
  list`. Vaults are whatever the tag search returns.
- **Shells never call `op`.** `op` is slow and prompts. Only `sync` and `check`
  touch it. `env` and `list` read the keychain only.
- **Thin wrapper.** Shell out to `op` and `/usr/bin/security`; parse their JSON
  and text. No Security.framework, no 1Password SDK.
- **Resolve everything, then write.** `sync` never leaves the keychain half
  updated because of a 1Password failure.

## The 1Password contract

An item is in scope when it carries the tag `shell-env`, in any signed-in
account, any vault the user can read.

Within an in-scope item, every field with type `CONCEALED` whose label matches
`^[A-Z][A-Z0-9_]*$` and is not denylisted is exported under that label. Other
fields are ignored, so an item can keep `username`, notes, and URLs. One item
may yield several vars. A denylisted label is a `sync` error naming the item.

Denylist (decided 2026-09-14): exact names `PATH HOME USER LOGNAME SHELL TMPDIR
UID EUID IFS FPATH ZDOTDIR ENV SHLVL TERM LANG NODE_OPTIONS GIT_SSH_COMMAND`
and prefixes `LC_ DYLD_ LD_ ENVSEC_`.

Two in-scope fields with the same label, in one account or across accounts, are
a conflict. `sync` and `check` report both items and write nothing.

## The keychain contract

Login keychain, `~/Library/Keychains/login.keychain-db`, always named
explicitly. All access through `/usr/bin/security`. Decided 2026-09-14 after
Codex review: one bundle item, not per-var items.

| Item | Service | Account | Value |
|---|---|---|---|
| bundle | `envsec` | `bundle` | base64 of the JSON below |

```json
{
  "schema": 1,
  "generated_at": "2026-09-14T17:02:11Z",
  "vars": [
    {
      "name": "GRAFANA_TOKEN",
      "value": "…",
      "account_uuid": "…",
      "user_uuid": "…",
      "account_url": "my.1password.com",
      "item_id": "…",
      "field_id": "…"
    }
  ]
}
```

Created with `-T /usr/bin/security` so reads never prompt; replaced with
`add-generic-password -U`. Replacement is a single item write, so a shell sees
either the old bundle or the new one, never a mix. There is nothing to prune.
`env` and `list` read this one item with one `security` call. `account_url` is
for display; identity is `account_uuid` plus `user_uuid`.

Migration from v1 (`secrets-sync.*` items and the manifest): not
handled by envsec. The v1 cleanup in the private brain plan deletes them by hand.

## Commands

### `envsec sync`

For every account: list items tagged `shell-env`, fetch each, select fields.
Validate every value: nonempty, no CR or LF. Detect conflicts. If anything
failed, print the failures and exit 1 with the keychain untouched. Otherwise
build the new bundle in memory, write it in one keychain replacement. One
Touch ID prompt per account. Output: one row per var
`{"var":"GRAFANA_TOKEN","account":"my.1password.com","status":"added"|"unchanged"|"changed"|"removed"}`
(diffed against the previous bundle) and a `_meta` trailer with `error_count`.
Never prints a value.

### `envsec env`

Read the bundle with one `security find-generic-password`, decode, and print
`builtin export -- VAR='value'` per line to stdout, single-quoted with `'\''`
escaping.
Overwrites inherited values. See "Hardening rules for `env`" for rejection,
`unset`, and the managed-vars sentinel. Exit 0 when every var exported, 1 when
any was rejected, 4 when the keychain or bundle is unreadable. Never calls
`op`. Shell usage:

```zsh
(( $+commands[envsec] )) && eval "$(envsec env)"
```

### `envsec check`

Resolve from 1Password as `sync` does, read the bundle, compare in memory.
One row per var with `status` of `ok`, `missing` (in 1Password, not in
bundle), `different`, or `stale` (in bundle, not in 1Password). Conflicts
are reported as rows with `status: conflict`. No writes. Exit 1 if anything is
not `ok`. Prints no values and no hashes.

### `envsec list`

Print the bundle's provenance: `{"var":"...","account":"...","item_id":"...","field_id":"..."}`
per row plus `generated_at` in `_meta`. No values, no `op`.

### `envsec version`

`{"version":"x.y.z"}` then the trailer.

## Output and errors

JSONL rows to stdout ending in `{"_meta":{"has_more":false}}` (plus
`error_count` on `sync` and `check`). `env` is the exception: plain shell on
stdout. Fatal errors are one JSON object on stderr: `error` (stable snake_case
code), `detail`, `hint` (a concrete recovery command such as `op signin`).

Exit codes: `0` success; `1` general or partial failure; `2` 1Password not
signed in or locked past its prompt; `4` keychain unavailable (locked, missing
file, `security` failure).

## Hardening rules for `env`

From the Codex review, adopted:

- Assemble all output before writing any of it. Emit `builtin export -- VAR='...'` lines.
- Reject values containing NUL, CR, LF, invalid UTF-8, or other C0/DEL control bytes. A rejected var produces `unset VAR` so a stale inherited value does not survive.
- Also export `ENVSEC_MANAGED_VARS` (space-separated names). A following run unsets any inherited name in that list that is no longer managed. `ENVSEC_*` labels are refused at `sync`.
- The denylist (see "The 1Password contract") is enforced again in `env` on the decoded bundle; a bundle written by a future buggy `sync` must not export `PATH`.
- Unreadable keychain or bundle (missing item, bad base64, bad JSON, unknown `schema`): emit nothing, one warning, exit 4. Otherwise one aggregated warning line for all problems, exit 1.
- `eval "$(envsec env)"` masks the exit status; stderr is the only shell-start signal. Never run the loader under xtrace.

## Hardening rules for `sync`

- Per-user lock file; a second `sync` waits or fails, never interleaves.
- All accounts and all items must resolve before any keychain write. One failure aborts with the keychain unchanged, exit 2 for authorization, 1 otherwise.
- An account present in the current bundle but absent from `op account list` is not dropped without `--forget-account <uuid>`; without the flag `sync` aborts naming the account. Zero in-scope items across all accounts requires `--prune-all`.
- Provenance records `account_uuid`, `user_uuid`, item ID, field ID. Account URL is display only.

## Global flags

- `--tag <name>` - override `shell-env`. Default is the only thing about the
  contract that is configurable, and only per invocation.
- `--keychain <path>` - override the login keychain path. For tests.
- `--timeout <duration>` - per external command. Default 60s for `op`
  (Touch ID), 10s for `security`.

## Distribution

Homebrew cask from `tammersaleh/homebrew-tap` (decided 2026-09-14, matching the
sibling CLIs). The keychain ACL trusts `/usr/bin/security`, so the binary's
signing state is irrelevant to keychain access.

## Implementation status

Scaffold only. See `docs/plan.md` for the build order and the Codex review.
