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
TRY_BLOCK_INTERRUPT ARGC HISTCMD TTYIDLE BASH_ENV MAILPATH PROMPT_EOL_MARK` and
prefixes `LC_ DYLD_ LD_ ENVSEC_ OP_ ZSH_ GIT_CONFIG_`. The zsh names are
special parameters that re-expand their values, change shell behavior, or are
read-only; `OP_*` reconfigures the `op` child `sync` runs; `ZSH_*` is the
shell's own namespace. `BASH_ENV` is expanded and sourced by every
non-interactive bash. `GIT_CONFIG_*` (`GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`,
`GIT_CONFIG_VALUE_<n>`, `GIT_CONFIG_PARAMETERS`) injects git config, and keys
such as `core.fsmonitor` run a command.

Two in-scope fields with the same label are a conflict: two fields in one
item, two items in one account, or items across accounts. Conflict identity is
`(account_uuid, user_uuid, item_id, field_id)`; `account_url` is display only,
so one field seen under two URLs is one source. `sync` and `check` report
every source and write nothing. Conflicts are detected among trusted sources
only (see "Trust").

### Trust

A selected field is a source, identified by `(account_uuid, user_uuid,
vault_id, item_id, field_id, name)`. `name` is the field label. A source is
stored as a var only when that exact tuple is in the bundle's
`trusted_sources`. A change to any part of the tuple, including the label, is
a new source and needs trust again. A value change is not. Trust is local to
one Mac's keychain.

The source id shown to the user is derived, never stored: `src_` plus
lowercase base32 without padding of the first 16 bytes of SHA-256 over
`"envsec-source-v1\x00"` followed by the six fields in the order above, each
prefixed with its byte length as a 4-byte big-endian integer.

Problems are judged by trust. A conflict or a validation error among trusted
sources aborts with no write. A problem that involves only untrusted sources
never blocks the write: an untrusted source that shares a name with a trusted
var is `untrusted`, and a denylisted or invalid untrusted source is an `error`
row that cannot be trusted. Anyone who can write a tagged item to a readable
vault can therefore add rows and force exit 1, and nothing more.

Not covered: someone who can edit a trusted field can change its value.

## The keychain contract

Login keychain, `~/Library/Keychains/login.keychain-db`, always named
explicitly. All access through `/usr/bin/security`. Decided 2026-09-14 after
Codex review: one bundle item, not per-var items.

| Item | Service | Account | Value |
|---|---|---|---|
| bundle | `envsec` | `bundle` | base64 of the JSON below |

```json
{
  "schema": 2,
  "generated_at": "2026-09-14T17:02:11Z",
  "trusted_sources": [
    {
      "account_uuid": "…",
      "user_uuid": "…",
      "vault_id": "…",
      "item_id": "…",
      "field_id": "…",
      "name": "GRAFANA_TOKEN"
    }
  ],
  "vars": [
    {
      "name": "GRAFANA_TOKEN",
      "value": "…",
      "account_uuid": "…",
      "user_uuid": "…",
      "account_url": "my.1password.com",
      "vault_id": "…",
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

`trusted_sources` is separate from `vars`. A trusted source that is absent
from 1Password loses its var and keeps its trust. Every var must match a
trusted source, or the bundle is `bundle_invalid`. Deleting the keychain item
deletes every trust decision.

Schema 1 (no `trusted_sources`, no `vault_id`) predates trust. `env` and
`list` refuse it: nothing on stdout, exit 4, hint `envsec sync`. `sync`,
`trust`, and `check` read it as a bundle whose sources are all untrusted.

Migration from v1 (`secrets-sync.*` items and the manifest): not
handled by envsec. The v1 cleanup in the private brain plan deletes them by hand.

## Commands

### `envsec sync`

For every account: list items tagged `shell-env`, fetch each, select fields.
Validate every value: nonempty, valid UTF-8, no C0 control bytes (0x00-0x1F,
which covers tab, CR, LF, and NUL), no DEL (0x7F). This is the rule `env`
enforces, so `sync` never stores a value `env` would reject. A rejected value
is an `error` row naming the item and the reason (the control byte, or that
the value is not valid UTF-8), never the value. Split the sources into trusted
and untrusted, then detect conflicts among the trusted. If a trusted source
failed, print the failures and exit 1 with the keychain untouched. Otherwise
build the new bundle in memory from the trusted sources, write it in one
keychain replacement. One Touch ID prompt per account. Output: one row per var
`{"var":"GRAFANA_TOKEN","account":"my.1password.com","status":"added"|"unchanged"|"changed"|"removed"}`
(diffed against the previous bundle) and a `_meta` trailer with `error_count`.
Never prints a value.

An untrusted source is left out of the bundle and reported:

```json
{"var":"GITHUB_TOKEN","account":"my.1password.com","vault":"Private","vault_id":"…","item":"CI","item_id":"…","field_id":"…","source_id":"src_…","status":"untrusted","detail":"source is not trusted"}
```

plus one warning line on stderr naming the vars and `envsec trust`. Each
`untrusted` or `error` row counts in `error_count` and makes the exit 1. The
trusted vars are still written. One row per var name, in the order `conflict`,
`error`, `untrusted`, then the diff status. `detail` joins every problem with
`; `. A row that stands for several sources drops the provenance fields and
names each source id in `detail`. Rows and the warning are printed after the
keychain write, so a failed write never reports a sync.

When `trusted_sources` is empty (no bundle, a schema 1 bundle, or an empty
list, judged after `--forget-account`) and a terminal is present, `sync` opens the picker
described under `envsec trust`, with nothing checked, and continues with the
confirmed selection. Confirming with nothing checked writes nothing, prints
the `untrusted` rows, and exits 1. Without a terminal it does the same with no
picker. The one write in that case is a `--forget-account` removal. With no
valid source to offer there is no picker and `sync` writes a bundle with no
vars. Cancelling is `trust_cancelled`, nothing written.

A terminal is present when stdin and stderr are both terminals and `TERM` is
not `dumb`. The picker draws on stderr, so `envsec sync >file` still opens it.

### `envsec trust`

Resolve from 1Password as `sync` does, change `trusted_sources`, and write the
bundle in the same run, with `sync`'s rows and trailer. It takes `sync`'s lock
and runs `sync`'s guards, without `--forget-account` or `--prune-all`.

With no arguments and a terminal: a checkbox list on stderr, one line per
valid source (var, account, vault, item title), trusted sources checked. Space
toggles, enter confirms. The new list is the checked sources plus every
trusted source absent from 1Password. Unchecking revokes. A trusted source
that now fails validation cannot be shown and is revoked on confirm.
Confirming with nothing checked revokes every source shown. Two checked sources
with the same name are refused. Account, vault, and item strings are escaped
to one line with no control characters before display. Cancelling (Ctrl-C,
EOF, a terminal error) is `trust_cancelled`, exit 1, nothing written. With no
arguments and no terminal: `no_terminal`, exit 1, hint
`envsec trust <source-id>`.

`envsec trust <source-id>...` trusts exactly those ids and revokes nothing.
`envsec trust --revoke <source-id>...` revokes. No picker in either form. All
ids apply or none: a malformed id (`invalid_source_id`), a repeated id
(`duplicate_source_id`), an unknown id (`unknown_source_id`), an id naming an
invalid source (`source_invalid`), or a new conflict (`trust_conflict`) writes
nothing and exits 1. Errors name the argument position or the id, never other
input. A trust id must name a valid source in this run's resolution. Trusting
a source that is already trusted changes nothing. A revoke id must be in the
stored list, present in 1Password or not. `envsec list` shows those ids.
Revokes apply before the guards, so a source whose account or item is gone
can still be revoked.

A source revoked in this run gets a `revoked` row in place of `removed`, loses
its var, and is not an error. When the name keeps a row for another reason,
the revoke is appended to that row's `detail`. A later `sync` reports it `untrusted` while it stays tagged.

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
`conflict`, `error` (a source validation failure such as a denylisted label
or an empty value), or `untrusted` (a valid source not in `trusted_sources`,
with the row shape `sync` prints). With no bundle every valid source is
`untrusted`. `conflict` wins over `error`, and both win over `untrusted`; the
row's `detail` joins every problem with `; `. A name with a `conflict`,
`error`, or `untrusted` row is excluded from the ok/missing/different/stale comparison on both
sides, so it is never also reported `stale` or `missing`. No writes. Exit 1 if
anything is not `ok`. Prints no values and no hashes.

### `envsec list`

Print the bundle's provenance: `{"var":"...","account":"...","vault_id":"...","item_id":"...","field_id":"...","source_id":"src_..."}`
per row plus `generated_at` in `_meta`. No values, no `op`. After the var rows,
one row per trusted source with no var:
`{"var":"...","account_uuid":"...","vault_id":"...","item_id":"...","field_id":"...","source_id":"src_...","status":"absent"}`.

### `envsec version`

`{"version":"x.y.z"}` then the trailer.

## Output and errors

JSONL rows to stdout ending in `{"_meta":{"has_more":false}}` (plus
`error_count` on `sync`, `trust`, and `check`). `env` is the exception: plain shell on
stdout. Fatal errors are one JSON object on stderr: `error` (stable snake_case
code), `detail`, `hint` (a concrete recovery command such as `op signin`).

Exit codes: `0` success; `1` general or partial failure; `2` 1Password not
signed in or locked past its prompt, including `op account list` returning
zero accounts and any `op` command hitting the `--timeout` deadline (an
unanswered prompt is indistinguishable from a lock); `4` keychain unavailable
(missing file, `security` failure, or locked). A locked keychain that
`security` cannot prompt to unlock (exit 36, the normal state over ssh, where
the session has no UI) is `keychain_locked` with hint
`security unlock-keychain <path>`; `envsec sync` fails the same way, so it is
never the hint.

## Hardening rules for `env`

From the Codex review, adopted:

- Assemble all output before writing any of it. Emit the guarded `unset && export` line from "envsec env" for every var.
- Reject empty values and values containing NUL, CR, LF, invalid UTF-8, or other C0/DEL control bytes. `sync` applies the same rule, so this fires only for a bundle written by an older release or by hand. A rejected var produces a guarded `builtin unset -- VAR` so a stale inherited value does not survive.
- Also export `ENVSEC_MANAGED_VARS` (space-separated names). A following run emits a guarded `builtin unset -- VAR` for any inherited name in that list that is no longer managed. `ENVSEC_*` labels are refused at `sync`.
- The denylist (see "The 1Password contract") is enforced again in `env` on the decoded bundle; a bundle written by a future buggy `sync` must not export `PATH`.
- Unreadable keychain or bundle (missing item, bad base64, bad JSON, unknown
  `schema`): emit nothing, one warning, exit 4. Bad JSON includes invalid UTF-8
  in the decoded document, a missing or zero `generated_at`, a missing or
  null `vars`, a null entry in `vars`, a var with a missing or null `value`,
  a var with an empty `name`, `account_uuid`, `user_uuid`, `account_url`,
  `vault_id`, `item_id`, or `field_id`, two vars with the same `name`, a
  missing or null `trusted_sources`, a trusted source with an empty field, a
  repeated trusted source, and a var with no matching trusted source; all are
  `bundle_invalid`. A schema 1 bundle is `bundle_untrusted`, exit 4, hint
  `envsec sync`. `sync` refuses to encode a bundle `env` would reject.
  Otherwise one aggregated warning line for all problems, exit 1.
- `eval "$(envsec env)"` masks the exit status; stderr is the only shell-start signal. Never run the loader under xtrace.

## Hardening rules for `sync`

- Per-user lock file; a second `sync` waits or fails, never interleaves.
- All accounts and all items must resolve before any keychain write. One failure aborts with the keychain unchanged, exit 2 for authorization, 1 otherwise.
- An account present in the current bundle (in `vars` or `trusted_sources`) but absent from `op account list` is not dropped without `--forget-account <account_uuid>`; without the flag `sync` aborts naming the account. Identity is `(account_uuid, user_uuid)`; the flag forgets every old identity under that account UUID, its trusted sources included.
- Zero in-scope items across all accounts requires `--prune-all`. This applies always, including the first run and an empty old bundle. An in-scope item is one that was fetched and still carries the tag, regardless of how many vars it yields. `--prune-all` empties `vars` and keeps `trusted_sources`.
- Provenance records `account_uuid`, `user_uuid`, vault ID, item ID, field ID. Account URL is display only.

## Global flags

- `--tag <name>` - override `shell-env`. Default is the only thing about the
  contract that is configurable, and only per invocation.
- `--keychain <path>` - override the login keychain path. For tests.
- `--timeout <duration>` - per external command. Default 60s for `op`
  (Touch ID), 10s for `security`.
- `--verbose` - forward raw `op` stderr for `account list` and `item list`
  only. `item get` stderr is never forwarded or stored: the item is fetched
  with `--reveal` and `op` could echo a value.

## Dependencies

Kong for flags. `charm.land/huh/v2` for the trust picker, locked at v2.0.3:
Dependabot ignores it and it is bumped by hand. It is imported only by
`internal/trustpicker`. Nothing else beyond the standard library.

## Distribution

Homebrew cask from `tammersaleh/homebrew-tap` (decided 2026-09-14, matching the
sibling CLIs). The keychain ACL trusts `/usr/bin/security`, so the binary's
signing state is irrelevant to keychain access.

## Implementation status

Implemented; see `docs/implementation.md` for outstanding verification against
the real `op` CLI. `docs/plan.md` holds the build order and the Codex review.
