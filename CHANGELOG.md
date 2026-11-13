# Changelog

## [2.0.0](https://github.com/tammersaleh/envsec/compare/v1.0.4...v2.0.0) (2026-11-13)


### ⚠ BREAKING CHANGES

* the keychain bundle schema, the `sync` and `check` row statuses, and first-run behavior changed. Existing bundles export nothing until `envsec sync` is run and sources are trusted.

### Features

* export only 1Password fields the user trusted ([82897e6](https://github.com/tammersaleh/envsec/commit/82897e617f420107ee0eecf35ee399219d105810))


### Bug Fixes

* env rejects an empty value ([d8f6242](https://github.com/tammersaleh/envsec/commit/d8f6242ecc86a72c477d87e5ad79ec11d8276486))

## [1.0.4](https://github.com/tammersaleh/envsec/compare/v1.0.3...v1.0.4) (2026-11-13)


### Bug Fixes

* **deps:** bump github.com/alecthomas/kong ([#5](https://github.com/tammersaleh/envsec/issues/5)) ([da3aa4c](https://github.com/tammersaleh/envsec/commit/da3aa4ce3d9ac6c0ff9c4bde06609c6252941e14))
* item get decode errors no longer quote the response ([6266fbb](https://github.com/tammersaleh/envsec/commit/6266fbbd5c7432a8b8917fc1912c43b91a7da92f))

## [1.0.3](https://github.com/tammersaleh/envsec/compare/v1.0.2...v1.0.3) (2026-11-12)


### Bug Fixes

* deny BASH_ENV, MAILPATH, PROMPT_EOL_MARK, and GIT_CONFIG_* ([fbf8e31](https://github.com/tammersaleh/envsec/commit/fbf8e31284e72b46ad47af69f38253985a687188))
* reject control bytes and invalid UTF-8 at sync, not only at env ([d43b81e](https://github.com/tammersaleh/envsec/commit/d43b81e45d95271e7ff720b621a958bcb372b9a2))

## [1.0.2](https://github.com/tammersaleh/envsec/compare/v1.0.1...v1.0.2) (2026-11-05)


### Bug Fixes

* **release:** migrate cask post-install hook to install_steps ([0955fba](https://github.com/tammersaleh/envsec/commit/0955fbad8d14b4028b990581a543652b81b64e80))

## [1.0.1](https://github.com/tammersaleh/envsec/compare/v1.0.0...v1.0.1) (2026-09-28)


### Bug Fixes

* report a locked keychain as keychain_locked with the unlock command ([358e986](https://github.com/tammersaleh/envsec/commit/358e98641348ce0e8f8d4dd87ee98f6e013d69ae))

## 1.0.0 (2026-09-15)


### Features

* add export and bundle packages ([3c92585](https://github.com/tammersaleh/envsec/commit/3c925855a73828a9f556b682ff2e0c85196e5375))
* add keychain store over /usr/bin/security with fake ([adbd107](https://github.com/tammersaleh/envsec/commit/adbd1072ade81f47503b5de74e6b769806a9c2b0))
* add Kong CLI with env and list commands ([d04709c](https://github.com/tammersaleh/envsec/commit/d04709c797d1442596d7c5ce8b695065070ef9da))
* add onepass client over op with fake and fixtures ([bfe1f47](https://github.com/tammersaleh/envsec/commit/bfe1f47c19ea99b2778c2dadb067fa42a0793bd7))
* add sync and check commands ([d240828](https://github.com/tammersaleh/envsec/commit/d24082818321aa625daaab59e483e6a17741e060))


### Bug Fixes

* harden against review findings ([b19aab7](https://github.com/tammersaleh/envsec/commit/b19aab77c1c43e2f26451685e869d0ff69cee035))

## Changelog
