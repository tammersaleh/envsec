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
`^[A-Z][A-Z0-9_]*$` is exported under that label. Other fields are ignored, so
an item can keep `username`, notes, and URLs. One item may yield several vars.

Two in-scope fields with the same label, in one account or across accounts, are
a conflict. `sync` and `check` report both items and write nothing.

## The keychain contract

Login keychain, `~/Library/Keychains/login.keychain-db`, always named
explicitly. All access through `/usr/bin/security`.

| Item | Service | Account | Value |
|---|---|---|---|
| value | `envsec.<VAR>` | 1Password account URL, e.g. `my.1password.com` | the secret |
| index | `envsec` | `index` | lines of `<VAR>\t<account URL>\t<item id>` |

Value items are created with `-T /usr/bin/security` so reads never prompt, and
updated with `add-generic-password -U`. The index is rewritten last, after all
value writes succeed, and is the only thing `env` and `list` enumerate from.
Items in the keychain whose var is no longer in 1Password are deleted by `sync`
and reported.

## Commands

### `envsec sync`

For every account: list items tagged `shell-env`, fetch each, select fields.
Validate every value: nonempty, no CR or LF. Detect conflicts. If anything
failed, print the failures and exit 1 with the keychain untouched. Otherwise
write every value, delete stale value items, rewrite the index. One Touch ID
prompt per account. Output: one row per var `{"var":"GRAFANA_TOKEN","account":"...","status":"written"|"unchanged"|"deleted"}` and a `_meta` trailer with `error_count`. Never prints a value.

### `envsec env`

Read the index, then every value in a single `security -i` process. Print
`export VAR='value'` per line to stdout, single-quoted with `'\''` escaping.
Overwrites inherited values. A value containing a newline is not printed; a
warning names it on stderr. A missing keychain item is a warning naming it on
stderr; the rest still print. Exit 0 when all present, 1 when any missing or
refused, 4 when the keychain is unavailable. Never calls `op`. Shell usage:

```zsh
(( $+commands[envsec] )) && eval "$(envsec env)"
```

### `envsec check`

Resolve from 1Password as `sync` does, read the keychain, compare in memory.
One row per var with `status` of `ok`, `missing` (in 1Password, not in
keychain), `different`, or `stale` (in keychain, not in 1Password). Conflicts
are reported as rows with `status: conflict`. No writes. Exit 1 if anything is
not `ok`. Prints no values and no hashes.

### `envsec list`

Print the index: `{"var":"...","account":"...","item_id":"..."}` per row. No
values, no `op`.

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

## Global flags

- `--tag <name>` - override `shell-env`. Default is the only thing about the
  contract that is configurable, and only per invocation.
- `--keychain <path>` - override the login keychain path. For tests.
- `--timeout <duration>` - per external command. Default 60s for `op`
  (Touch ID), 10s for `security`.

## Implementation status

Scaffold only. See `docs/plan.md` for the build order.
