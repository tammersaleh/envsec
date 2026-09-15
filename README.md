# envsec

Export 1Password secrets as environment variables, cached in the macOS login
keychain so shells start without calling `op`.

## Install

```bash
brew install --cask tammersaleh/tap/envsec
```

## Use

Tag a 1Password item `shell-env`. Give it a concealed field whose label is the
env var name, for example `GRAFANA_TOKEN`. Then:

```bash
op signin
envsec sync
```

In `.zshrc`:

```zsh
(( $+commands[envsec] )) && eval "$(envsec env)"
```

After rotating a credential, update the 1Password item and run `envsec sync`
again. `envsec check` compares keychain to 1Password without writing.

Full contract in `SPEC.md`.
