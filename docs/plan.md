# Plan v2: `envsec`, a Go binary replacing the manifest and the zsh loader

Decided 2026-09-14 after Tammer's review of v1 (`plan.md`). v1 works and stays in place until v2 replaces it. Name `envsec` is a placeholder; no PATH collision on this Mac.

## Why v2

v1 buried the manifest in `~/.config/secrets-sync/manifest` and put the loading logic in an untested zsh function. Tammer's requirements:

- 1Password is the manifest. Nothing else lists which secrets exist.
- The binary encodes nothing about the employer, accounts, or vaults. It applies one pattern across every account `op` is signed in to.
- Logic lives in Go with tests. zsh does one `eval`.

## Design

### 1Password side

An item joins the set by carrying the tag `shell-env`. Within a tagged item, every field of type CONCEALED whose label matches `^[A-Z][A-Z0-9_]*$` is exported under that label. One item can yield several vars (Salesforce: `SALESFORCE_PASSWORD`, `SALESFORCE_SECURITY_TOKEN`). Fields that don't match are ignored, so an item can keep `username`, notes, URLs.

Discovery per account: `op item list --tags shell-env --format json`, then `op item get <id> --format json` per item. Accounts come from `op account list --format json`. All accounts, every run.

Conflicts: the same label from two items, in one account or across accounts, is an error naming both items. `sync` writes nothing.

### Keychain side

Login keychain, `~/Library/Keychains/login.keychain-db`, through `/usr/bin/security`, never Security.framework. Decision recorded below.

Per var: generic password, service `envsec.<VAR>`, account `<1Password account URL>` (e.g. `example.1password.com`), ACL `-T /usr/bin/security`. Written with `add-generic-password -U`.

Index item: service `envsec`, account `index`, value is the var list, one `VAR<TAB>account-url` per line. `env` reads the index first, then every value, in a single `security -i` process. `sync` rewrites the index last, after all values succeed; `sync` also deletes keychain items for vars no longer in 1Password (and says so).

### Commands

- `envsec sync` - all accounts, resolve everything, validate (nonempty, no CR/LF), detect conflicts, then write values, prune, write index. One Touch ID prompt per account. Nonzero exit on any failure with the list of what failed; reruns idempotent. Prints names and status only.
- `envsec env` - read index and values from the keychain, print `export VAR='value'` lines, single-quoted with `'\''` escaping. A value with a newline is refused with a stderr warning and no export line. Missing items: warn on stderr naming them, still print the rest, exit 1. Nothing from `op`.
- `envsec check` - resolve from 1Password and compare with keychain; print `ok`/`missing`/`different`/`stale` per var; no writes; no hashes.
- `envsec list` - print var names and source account from the keychain index. No values.

### Shell

`public/.zsh/d/secrets.zsh` becomes:

```zsh
(( $+commands[envsec] )) && eval "$(envsec env)"
```

Inherited values: `env` overwrites. Simpler than v1's skip-if-set, and a rotated value propagates to subshells. Cost: one process, about 40ms (measured floor for any process on this Mac is ~40ms).

### Repo and distribution

Own repo `github.com/tammersaleh/envsec`, mirroring slack-cli and confluence-cli. Tammer (2026-09-14): copy the agent operating instructions from both repos (`CLAUDE.md`, `todo/README.md`, release conventions) into the new repo rather than inventing new ones. Layout: `cmd/envsec`, `internal/`, `todo/README.md`, `CLAUDE.md`, goreleaser with `homebrew_casks` into `tammersaleh/homebrew-tap`, release-please, CI workflow. Brewfile line `cask 'tammersaleh/tap/envsec'`. Fresh-install README step becomes `op signin` per account, then `envsec sync`.

### Testability

- `internal/onepass`: interface with `Accounts()`, `ListTagged(account, tag)`, `GetItem(account, id)`. Real impl shells to `op`. Fake returns canned JSON captured from the real CLI with values scrubbed.
- `internal/keychain`: interface with `Get`, `Set`, `Delete`, `GetIndex`, `SetIndex`, plus `BatchGet` for `env`. Real impl shells to `security`. In-memory fake. One integration test against the real login keychain on a throwaway namespace, gated by an env var.
- `internal/export`: pure functions. `SelectFields(item) []Var`, `Quote(value) (string, error)`, `DetectConflicts([]Var) error`.
- Tests: table-driven field selection; quoting for `'`, space, `$`, backtick, newline (refusal); conflicts within and across accounts; `sync`/`env`/`check` against both fakes; `env` output byte-exact.

## Design decision: `/usr/bin/security` over Security.framework

Measured 2026-09-14 on Tammer's Mac:

| Path | Keychain work | Wall |
|---|---|---|
| `security -i` batch, 9 reads | one child process | 40ms |
| Native Security.framework, enumerate + 9 reads | in-process | 13ms |
| Process launch floor (`/usr/bin/true`) | none | 40ms |

Native saves ~25ms per shell start out of ~700ms. Against that, a native binary is the trusted app on each keychain item, and every rebuild (ad-hoc signature changes) re-prompts once per item unless the binary is signed with a persistent identity on every machine, which a cask release can't do. `/usr/bin/security` keeps a stable trusted app and costs an index item for enumeration.

**Rethink if** shell startup becomes a problem or the var count grows past a few dozen. The switch is contained to `internal/keychain`: implement the interface with Security.framework (cgo) and solve signing (self-signed identity plus a post-install `codesign` step, or a Developer ID). Record this in the envsec repo's `CLAUDE.md` when the repo exists.

## Steps

1. [ ] Codex review of this plan.
2. [ ] Tag the nine items `shell-env` and relabel their concealed fields to the env var names (Grafana TARS `credential` -> `GRAFANA_TOKEN`, etc.). Via `op item edit` with label renames only (no values in argv), one Bash call.
3. [ ] Scaffold repo, `internal/export` with tests first.
4. [ ] `internal/onepass` and `internal/keychain` with fakes and tests; capture scrubbed fixtures.
5. [ ] Commands. `envsec sync` for real, then `envsec check`, then `envsec env` diffed against v1's exports (same names, same values).
6. [ ] Swap `secrets.zsh` to the one-liner. Fresh-shell acceptance as in v1 step 3. Tool auth checks as in v1 step 4.
7. [ ] Remove v1: `secrets-sync`, the manifest, `~/.config/secrets-sync`, the v1 keychain items (`secrets-sync.*`). Update private `CLAUDE.md` and public `README.md`.
8. [ ] goreleaser, release-please, tap cask, Brewfile line. First tagged release; `brew bundle` installs it; remove the locally built binary.
9. [ ] Rotation (v1 step 6) still outstanding; unchanged by v2.

v1 (the manifest plus zsh loader this replaces) is documented in the private brain repo at `projects/dotfiles-secrets/plan.md`; it holds real item IDs and stays out of this public repo.
