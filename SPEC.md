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
UID EUID IFS FPATH ZDOTDIR ENV SHLVL TERM LANG NODE_OPTIONS GIT_SSH_COMMAND
PROMPT PS1 PS2 PS3 PS4 RPROMPT RPS1 RPS2 PROMPT2 PROMPT3 PROMPT4 SPROMPT PPID
LINENO RANDOM SECONDS COLUMNS LINES HISTSIZE SAVEHIST HISTFILE GID EGID
USERNAME RPROMPT2 KEYTIMEOUT FUNCNEST LISTMAX MAILCHECK OPTIND TRY_BLOCK_ERROR
TRY_BLOCK_INTERRUPT ARGC HISTCMD TTYIDLE` and prefixes `LC_ DYLD_ LD_ ENVSEC_
OP_ ZSH_`. The zsh names are special parameters that re-expand their values,
change shell behavior, or are read-only; `OP_*` reconfigures the `op` child
`sync` runs; `ZSH_*` is the shell's own namespace.

Two in-scope fields with the same label are a conflict: two fields in one
item, two items in one account, or items across accounts. Conflict identity is
`(account_uuid, user_uuid, item_id, field_id)`; `account_url` is display only,
so one field seen under two URLs is one source. `sync` and `check` report
every source and write nothing.

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
one line per var to stdout:

```zsh
[[ ${(t)VAR} != *readonly* ]] && builtin unset -- VAR && builtin export -- VAR='value'
```

The value is single-quoted with `'\''` escaping. The `unset` runs before the
`export` so a parameter the shell already typed (`typeset -i`, an array)
cannot reinterpret the value: an integer parameter would evaluate
`path[$(cmd)]` as arithmetic. The readonly guard comes first because `unset`
is a special builtin: its failure aborts the rest of the enclosing `eval`, so
without the guard one readonly parameter in the caller's shell would skip
every later line. With it the readonly var is left as is and the rest of the
output runs. envsec cannot see the caller's shell, so a skipped readonly is
not reported and stays listed in `ENVSEC_MANAGED_VARS`; the guarded `unset` a
later run emits for it is a no-op. The standalone `unset` lines and
`ENVSEC_MANAGED_VARS` use the same guard. Overwrites inherited values. See "Hardening rules for `env`" for rejection,
`unset`, and the managed-vars sentinel. Exit 0 when every var exported, 1 when
any was rejected, 4 when the keychain or bundle is unreadable. Never calls
`op`. Shell usage:

```zsh
(( $+commands[envsec] )) && eval "$(envsec env)"
```

### `envsec check`

Resolve from 1Password as `sync` does, read the bundle, compare in memory.
Exactly one row per var name with `status` of `ok`, `missing` (in 1Password,
not in bundle), `different`, `stale` (in bundle, not in 1Password),
`conflict`, or `error` (a source validation failure such as a denylisted label
or an empty value). `conflict` wins over `error` when a name has both; the
row's `detail` joins every problem with `; `. A name with a `conflict` or
`error` row is excluded from the ok/missing/different/stale comparison on both
sides, so it is never also reported `stale` or `missing`. No writes. Exit 1 if
anything is not `ok`. Prints no values and no hashes.

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
signed in or locked past its prompt, including `op account list` returning
zero accounts and any `op` command hitting the `--timeout` deadline (an
unanswered prompt is indistinguishable from a lock); `4` keychain unavailable
(locked, missing file, `security` failure).

## Hardening rules for `env`

From the Codex review, adopted:

- Assemble all output before writing any of it. Emit the guarded `unset && export` line from "envsec env" for every var.
- Reject values containing NUL, CR, LF, invalid UTF-8, or other C0/DEL control bytes. A rejected var produces a guarded `builtin unset -- VAR` so a stale inherited value does not survive.
- Also export `ENVSEC_MANAGED_VARS` (space-separated names). A following run emits a guarded `builtin unset -- VAR` for any inherited name in that list that is no longer managed. `ENVSEC_*` labels are refused at `sync`.
- The denylist (see "The 1Password contract") is enforced again in `env` on the decoded bundle; a bundle written by a future buggy `sync` must not export `PATH`.
- Unreadable keychain or bundle (missing item, bad base64, bad JSON, unknown
  `schema`): emit nothing, one warning, exit 4. Bad JSON includes invalid UTF-8
  in the decoded document, a missing or zero `generated_at`, a missing or
  null `vars`, a null entry in `vars`, a var with a missing or null `value`,
  a var with an empty `name`, `account_uuid`, `user_uuid`, `account_url`,
  `item_id`, or `field_id`, and two vars with the same `name`; all are
  `bundle_invalid`. `sync` refuses to encode a bundle `env` would reject.
  Otherwise one aggregated warning line for all problems, exit 1.
- `eval "$(envsec env)"` masks the exit status; stderr is the only shell-start signal. Never run the loader under xtrace.

## Hardening rules for `sync`

- Per-user lock file; a second `sync` waits or fails, never interleaves.
- All accounts and all items must resolve before any keychain write. One failure aborts with the keychain unchanged, exit 2 for authorization, 1 otherwise.
- An account present in the current bundle but absent from `op account list` is not dropped without `--forget-account <account_uuid>`; without the flag `sync` aborts naming the account. Identity is `(account_uuid, user_uuid)`; the flag forgets every old identity under that account UUID.
- Zero in-scope items across all accounts requires `--prune-all`. This applies always, including the first run and an empty old bundle. An in-scope item is one that was fetched and still carries the tag, regardless of how many vars it yields.
- Provenance records `account_uuid`, `user_uuid`, item ID, field ID. Account URL is display only.

## Global flags

- `--tag <name>` - override `shell-env`. Default is the only thing about the
  contract that is configurable, and only per invocation.
- `--keychain <path>` - override the login keychain path. For tests.
- `--timeout <duration>` - per external command. Default 60s for `op`
  (Touch ID), 10s for `security`.
- `--verbose` - forward raw `op` stderr for `account list` and `item list`
  only. `item get` stderr is never forwarded or stored: the item is fetched
  with `--reveal` and `op` could echo a value.

## Distribution

Homebrew cask from `tammersaleh/homebrew-tap` (decided 2026-09-14, matching the
sibling CLIs). The keychain ACL trusts `/usr/bin/security`, so the binary's
signing state is irrelevant to keychain access.

## Implementation status

Implemented; see `docs/implementation.md` for outstanding verification against
the real `op` CLI. `docs/plan.md` holds the build order and the Codex review.
