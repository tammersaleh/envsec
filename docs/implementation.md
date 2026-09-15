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

- [ ] Code review sub-agent, fix findings, re-review.
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
- `op` authorization failures are detected by exit code plus stderr matching
  `not signed in`, `authorization`, `session expired`, or `Touch ID`; those map
  to exit 2. Anything else is exit 1.
- Bundle `value` is base64 of the JSON on the wire, and the keychain item is
  created with `-T /usr/bin/security` and replaced with `-U`.

## Outstanding

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
