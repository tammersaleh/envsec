# Implementation plan

Working plan for turning `SPEC.md` into code. `docs/plan.md` holds the design
and the Codex review; this file holds build order, decisions made while
coding, and status. Update inline as work lands.

## Package layout

```
cmd/envsec/main.go          Kong entry, exit-code mapping
internal/cli/               commands: version, env, list, sync, check; output helpers
internal/export/            pure functions: label rule, denylist, field selection, conflicts, quoting
internal/onepass/           Client interface, real `op` impl, fake, fixtures
internal/keychain/          Store interface, real `security` impl, fake, integration test
internal/bundle/            bundle JSON schema, encode/decode, diff
```

Package dependencies flow downward: `cli` -> `export`, `onepass`, `keychain`,
`bundle`. `export` and `bundle` import only stdlib.

## Phases

Each phase is one or more sub-agents with disjoint file sets. The main
session commits after each phase, reviews before push.

### Phase 1 (parallel, three agents)

- [x] `internal/export` and `internal/bundle`. Label regex, denylist, field
  selection from a decoded item, conflict detection, shell quoting with
  control-byte rejection, bundle encode/decode/diff.
- [x] `internal/onepass`. `Client` interface, real impl over `op`, in-memory
  fake, scrubbed fixtures written from the documented `op` 2.38 JSON shape.
- [x] `internal/keychain`. `Store` interface (`ReadBundle`, `WriteBundle`),
  real impl over `/usr/bin/security`, in-memory fake, integration test on the
  `envsec-test.*` namespace.

### Phase 2 (one agent)

- [x] Kong root with global flags, `version`, `env`, `list`. Exit-code mapping
  in `main.go`. Fatal error JSON on stderr. `env` round-trip test through real
  `zsh`.

### Phase 3 (one agent)

- [x] `sync` and `check`, including the lock file, `--forget-account`,
  `--prune-all`, exit 2 on authorization failure.

### Phase 4 (main session)

- [x] Code review sub-agent, fix findings, re-review.
- [ ] Commit, push, wait for release, `brew upgrade`, verify installed binary.
- [ ] Verify against real `op` (needs Touch ID, see below).

## Decisions made while coding

- `op item get` is called with `--reveal` (op 2.38 redacts concealed values in
  `--format json` without it).
- Fake `op` output is generated from the documented JSON shape, not captured,
  because 1Password was locked during the build. Field names used:
  `id`, `title`, `tags`, `vault.{id,name}`, `fields[].{id,type,label,value}`.
- Lock file lives at `os.UserCacheDir()/envsec/sync.lock`, `flock` with
  `LOCK_NB`; a held lock is a fatal error `sync_locked`, exit 1.
- Interface methods take `context.Context` so `--timeout` applies per call.
- `op` authorization failures are detected by exit code plus a case-insensitive
  stderr substring from: `not signed in`, `not currently signed in`, `session
  expired`, `authorization`, `authentication required`, `unlock`, `locked`,
  `touch id`, `no accounts configured`; those map to exit 2. For `item get`,
  a not-found marker wins over an auth marker. Anything else is exit 1.
- Bundle `value` is base64 of the JSON on the wire, and the keychain item is
  created with `-T /usr/bin/security` and replaced with `-U`.
- Denylist adds the zsh prompt and special parameters (`PROMPT PS1..PS4
  RPROMPT RPS1 RPS2 PROMPT2..PROMPT4 SPROMPT PPID LINENO RANDOM SECONDS
  COLUMNS LINES HISTSIZE SAVEHIST HISTFILE GID EGID USERNAME`) and the `OP_`
  prefix, which would reconfigure the `op` child. Second review added
  `RPROMPT2 KEYTIMEOUT FUNCNEST LISTMAX MAILCHECK OPTIND TRY_BLOCK_ERROR
  TRY_BLOCK_INTERRUPT ARGC HISTCMD TTYIDLE` and the `ZSH_` prefix.
- `env` clears rejected and stale vars with `builtin unset -- VAR`, never bare
  `unset`.
- Every export line is `[[ ${(t)VAR} != *readonly* ]] && builtin unset --
  VAR && builtin export -- VAR='v'`, and every standalone unset carries the
  same guard. Measured in zsh 5.9: with `typeset -i VAR` predeclared, the
  old bare `export` evaluated `path[$(touch M)]` as arithmetic and ran the
  command; with `typeset -a`/`-A` it failed with "inconsistent type". The
  unset first fixes all three. A readonly parameter made the unset fail,
  and unset is a special builtin, so the failure aborted the rest of the
  enclosing `eval` including the sentinel. The `(t)` guard skips that line
  instead; `${(t)X}` is empty for an unset parameter and contains
  `readonly` for every readonly type. A skipped readonly is not detectable
  from Go, so it is not counted as rejected and stays in the sentinel.
- A label repeated within one item is no longer a `Select` error. Both vars
  are returned and `DetectConflicts` reports them as one conflict naming the
  field IDs. Conflict identity is `(account_uuid, user_uuid, item_id,
  field_id)`; `account_url` never enters the key, so one field seen under
  two URLs is one source.
- Conflict detail names field IDs when item IDs collide and account/user
  UUIDs when two identities share a URL, so the text always distinguishes
  the sources.
- Bundle decode also rejects null `vars` entries, a missing or null `value`,
  an empty `name`/`account_uuid`/`user_uuid`/`account_url`/`item_id`/`field_id`,
  and duplicate names (all `bundle_invalid`, exit 4). `Encode` runs the same
  validation plus a zero `generated_at` check and returns an error rather
  than write a bundle `Decode` would reject.
- `op` stdout must be valid UTF-8 before unmarshal (malformed otherwise). A
  fetched item must carry `tags` and `fields` as present, non-null arrays
  (explicit `[]` allowed) and every field a nonempty `id`; accounts need a
  nonempty `url` and unique `(account_uuid, user_uuid)`; summaries need
  unique `id`s. The `fields: null` case is the regression that would have
  silently dropped an item's vars from the bundle.
- `--verbose` forwards raw `op` stderr for `account list` and `item list`
  only. Every `item get` failure uses fixed text: stderr is read for
  classification (not-found, auth) and then discarded, and a runner error is
  reported as "op item get could not run" rather than wrapped.
- The default `op` runner hands the child `os.Environ()` minus
  `ENVSEC_MANAGED_VARS` and minus every name it lists that matches the label
  pattern and is not denylisted, so shell-loaded secrets never reach `op`.
  Denylisted names are skipped on purpose: envsec never exported them, and a
  tampered sentinel must not strip `PATH` or `HOME` from the child. Tested by
  re-executing the test binary as the child.
- `keychain.run` returns the raw context or runner error; `Read` and `Write`
  classify it and choose the text, so the Write path never builds an error
  from runner text (argv holds the value). Write's timeout error unwraps to
  `context.DeadlineExceeded`. The integration test's cleanup sets `WaitDelay`.
- `check` prints exactly one row per var name. Problems are folded by name:
  `conflict` wins over `error`, details join with `; ` (conflicts first, then
  selection failures, in resolve order), and a name with any problem is
  removed from both sides of the comparison so it is never also `stale`,
  `missing`, or `ok`. A cached var whose source is now empty is one `error`
  row.
- Status rows always carry `account`: the item's account URL on selection
  error rows, empty on conflict rows (a conflict may span accounts).
- The fatal `onepassword_unauthorized` detail includes `AuthError.Detail`
  when non-empty, so the timeout explanation reaches the user.
- `sync` requires `--prune-all` whenever zero in-scope items were found, first
  run and empty old bundle included. An in-scope item is fetched and still
  tagged; one with no exportable fields still counts.
- `--forget-account` and the vanished-account guard key on `(account_uuid,
  user_uuid)`; the flag takes an account UUID and forgets every user under it.
- An `op` command that hits `--timeout` is exit 2 (`AuthError` wrapping
  `ErrTimeout`): an unanswered prompt is indistinguishable from a lock. So is
  `op account list` returning zero accounts.
- `op` output is decoded strictly: blank or `null` stdout is malformed, not
  empty; accounts need `account_uuid` and `user_uuid`, summaries need `id`,
  and a fetched item must carry the requested `id`. `item get` failures never
  carry stderr (the item was fetched with `--reveal`). See the second-review
  entries below for the stricter shape checks.
- Bundle decode is strict: invalid UTF-8, a missing or zero `generated_at`,
  or a missing or null `vars` is `bundle_invalid`. Decode error text never
  quotes the underlying json or time error because those echo content.
- `security add-generic-password` failures report only the exit code or a
  fixed phrase, never stderr or the runner error, because a wrapper could echo
  argv containing `-w <value>`. `find-generic-password` keeps the first stderr
  line.
- Selection and conflict failures are typed (`export.SelectError`,
  `export.ConflictError`); sync and check rows carry the label or var name in
  `var`, and conflicts use `status: conflict` in both commands. `check`
  aggregation is described below.

## Outstanding

- Codex suggested a migration path for names newly denylisted after a
  release; not needed for v0 since no release ever exported them. Revisit if
  the denylist grows after 1.0.

- The `op` 2.38 checks listed under "Verify against `op` 2.38" in
  `docs/plan.md` were not run: the account was locked and the Touch ID prompt
  timed out. Run `envsec check` against real items once signed in and fix the
  parser if the shape differs.
- Plan step 2 (tag the items in 1Password) is outside this repo.
- Phase 1 integration test on the real keychain: first write and read-back
  passed, the `-U` overwrite timed out because an MDM agent had the login
  keychain locked behind a password dialog. Rerun
  `go test -tags=integration -run TestIntegrationLoginKeychain -v ./internal/keychain/`
  once the dialog is dismissed. `security` exits 44 for a missing keychain
  file too, so the store stats the path first and returns exit 4.
