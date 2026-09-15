# envsec

Go CLI that exports 1Password secrets as environment variables through the
macOS login keychain. `SPEC.md` is the source of truth for behavior; this file
is how to work in the repo. Sibling repos with the same conventions:
`slack-cli`, `confluence-cli`.

## What it does

1Password items tagged `shell-env` (in every account `op` is signed in to)
carry CONCEALED fields whose labels are env var names. `envsec sync` copies
those into the login keychain. `envsec env` prints `export` lines from the
keychain for the shell to `eval`. Shells never call `op`. See `SPEC.md` and
`docs/plan.md`.

## Design constraints

- **Nothing account-, vault-, or employer-specific in the code.** Accounts come
  from `op account list`. The tag and the field-label pattern are the whole
  contract.
- **Keychain access goes through `/usr/bin/security`, not Security.framework.**
  Decision and measurements in `docs/plan.md` ("Design decision"). Rethink if
  shell startup becomes a problem or the var count grows past a few dozen; the
  switch is contained to `internal/keychain`.
- **No secret values in argv you control, logs, test fixtures, or this repo.**
  `security add-generic-password -w` puts a value in argv briefly; that one is
  accepted and documented. Everything the binary prints is names and status,
  except `env`'s stdout, which is the point. Fixtures under `internal/*/testdata`
  are scrubbed captures; item titles and IDs there are synthetic.
- **This repo is public.** No real item IDs, account URLs beyond the 1Password
  public domains, or env var values. Env var *names* are fine.

## Workflow

Work is driven by `SPEC.md`. Every change - feature, bug fix, refactor -
follows the same workflow. No shortcuts for "small" fixes:

1. Read `SPEC.md` for the relevant command/feature.
2. Work on main (personal project, no PRs) or a short branch merged locally.
3. Red-green-refactor: write failing tests first, then implement, then clean up.
4. Run `mise run check` (test + lint + build) after every change. Gate on its
   exit code directly; piping it to `grep` masks a nonzero exit.
5. Keep commits small and conventional. Commit type drives releases - see
   "Release versioning".
6. **MANDATORY code review before push** (code changes only; docs-only Markdown
   edits are exempt): spawn a `feature-dev:code-reviewer` sub-agent on the
   pending diff. Tell it to scrutinize tests for ones that don't test what they
   claim, useless tests, and missing coverage. Address every important or
   critical finding, then re-run the reviewer to confirm clean. Never push code
   without a clean review pass.
7. Push. The pre-push hook runs `mise run check`; never bypass with `--no-verify`.
8. **Not done until installed and verified locally.** After a release-cutting
   push, poll in a background `Bash` loop (`run_in_background`): `gh release view
   vX.Y.Z` with `sleep 90` until the tag cuts, then the tap's raw
   `Casks/envsec.rb` until `version "X.Y.Z"` appears (the cask lags the tag by
   minutes), then `brew upgrade --cask tammersaleh/tap/envsec`, confirm `envsec
   version`, and exercise the new behavior with the installed binary. A
   general-purpose sub-agent is a poor poller; use the Bash loop.
   `chore:`/`docs:`/`test:`/`refactor:` cut no release. Never report a change
   "done" off a push alone.
9. Retrospective: update this file with anything that would help a future
   session.

Never ask permission to run this workflow. Committing, pushing to main, and
waiting out the release are the documented process, not a decision point.

## Bug reports and todos

`todo/` and `bugs/` are gitignored scratch space holding work orders, not
artifacts. Delete the file when the work is done - don't archive it or append a
resolution section. Findings belong in CLAUDE.md, SPEC.md, and the commit body.

- `bugs/` - something is broken now. Verify, fix, delete.
- `todo/` - work deferred out of the current change, usually a separate design
  decision. Write it for a session starting cold: what was measured and how,
  the proposed approach, and what to verify rather than assume. `todo/README.md`
  is the index.

Verify before fixing, and verify the whole report: a report can be right about
the symptom and wrong about the cause. Say which claims held.

## Release versioning

Releases are fully automated via release-please + GoReleaser. Release-please
watches main; a version-bumping commit opens a release PR that auto-merges once
CI passes. The merge cuts a tag and GitHub Release; GoReleaser builds the
binary and pushes an updated **cask** to `tammersaleh/homebrew-tap`
(`Casks/envsec.rb`, not `Formula/`). Nobody runs `git tag` by hand, nobody
clicks Merge on the release PR.

Commit type is the release trigger, chosen by user-facing impact, not diff size:

- `feat:` - minor bump. New commands, flags, outputs.
- `fix:` - patch bump. Promised behavior that was broken.
- `feat!:` / `BREAKING CHANGE:` footer - anything that breaks a caller: removed
  or renamed flags, changed output shape, exit codes, keychain layout.
- `chore:`, `docs:`, `test:`, `refactor:`, `perf:`, `style:` - no release.

Rules: one type per commit (split mixed intent); dependency bumps are `fix:`
only if they reach users; never downgrade a type to avoid a release or upgrade
one to force it; imperative subject under ~70 chars; body text shows in release
notes. **The version number is never a reason to ask.** Pick the type, say in
one line why, push.

## Autonomy

Work through features independently. Never stop to ask "should I continue?" -
the answer is always yes. Only escalate when a design decision isn't covered by
`SPEC.md`, or something feels wrong (scope creep, a `security` or `op`
limitation). Neither exception covers releases. If the turn ends with work
sitting uncommitted or unpushed pending an answer, the rule was broken.

## Testing

```bash
mise run check         # test + lint + build (use this by default)
mise run test          # unit tests only
mise run lint          # golangci-lint v2
mise run test:race     # with race detector
mise run test:int      # integration tests (build tag)
mise run test:cover    # coverage report
```

Tests live next to the code (`foo_test.go`), table-driven. `internal/onepass`
and `internal/keychain` are interfaces with in-memory fakes; commands are tested
against the fakes. The real keychain implementation has one integration test
(`-tags=integration`) that uses a throwaway `envsec-test.*` namespace on the
login keychain and cleans up after itself. Nothing in the test suite calls the
real `op`. Fixtures are scrubbed JSON captured once from the real CLI.

golangci-lint is v2 (v1 predates Go 1.25 and emits false positives). `errcheck`
is off for `_test.go` only. See `.golangci.yml`.

## Output and error contract

Same as the sibling CLIs. Full detail in `SPEC.md`.

- Status rows: JSONL to stdout, one object per line, `snake_case` fields, ending
  with a `_meta` trailer `{"_meta":{"has_more":false}}` (with `error_count` on
  bulk commands).
- `envsec env` is the exception: stdout is shell source, not JSONL, because it
  is `eval`'d. Warnings go to stderr.
- Fatal errors: one JSON object on stderr with `error` (stable snake_case code),
  `detail`, `hint`.
- Exit codes: `0` success, `1` general or partial failure, `2` authentication
  (1Password locked or not signed in), `4` keychain unavailable.

## Git

Personal project. Commit on main, push. Don't open pull requests; the only PR
is release-please's. Commits are GPG-signed.

The SSH remote key is fingerprint-gated, so a non-interactive `git push` over
SSH stalls. Push over HTTPS with the gh credential helper: `gh auth setup-git`
once, then `git push https://github.com/tammersaleh/envsec.git main:main`.
Exception: `.github/workflows/` changes need a `workflow`-scoped token; push
those over SSH with the fingerprint. Because release-please's merge advances
remote main, fetch and rebase before each subsequent push:

```bash
git fetch https://github.com/tammersaleh/envsec.git main && git rebase FETCH_HEAD
```

## Sandbox

GPG-signed commits and `mise run` need `dangerouslyDisableSandbox: true` (Go
build cache and GPG keyring access).

## Dependencies and Go version

Kong for CLI parsing (`github.com/alecthomas/kong`), nothing else beyond
stdlib unless SPEC says so. Go 1.25.

## Notes for future sessions

- `op read` rejects `(` in a secret reference. Reference items by ID, never title.
- `security find-generic-password -w` with an empty or non-matching `-s` falls
  back to prompting per item. Always pass exact `-a` and `-s`.
- Every `op` process is a new CLI session and may Touch ID prompt. A run that
  starts while a prompt is unanswered hangs until answered. From an agent,
  wrap `op` and `security` calls in `timeout`.
- Killed `security` processes leave their dialogs on screen.
- zsh: `local x` inside a loop re-declares an existing parameter and prints its
  value. Irrelevant now that the loader is Go, kept as a warning for the
  one-liner in `~/.zsh/d/secrets.zsh`.
