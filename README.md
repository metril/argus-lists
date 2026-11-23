# argus-lists

Curated "do not decrypt" host lists for [Argus](https://github.com/metril/argus), published as
signed release assets. Argus subscribes to them by default and verifies every file against a
compiled-in public key before using it.

## Layout

* `lists/<category>/manual.txt` (hand-curated) and `generated.txt` (machine-written by `generator/`) -- `build.py` merges them into the published `<category>.txt`. One host or `*.suffix` per line;
  covers the domain and its subdomains; `*.suffix` covers subdomains only.
* `meta.json` — `id`, `name`, `description` and `default_mode` (`no_decrypt` or `full`) of each
  category. The release copy also carries `version` and each list's `sha256` and host count.
* `scripts/validate.py` — syntax, lowercase, duplicates, no bare-TLD or public-suffix wildcards
  (unless listed in `scripts/allowed-wildcards.txt`, e.g. `*.gov`), and a DNS check that only
  warns.
* `scripts/build.py` — builds `dist/` with the versioned `meta.json`.

Categories: `banking_finance`, `payments`, `health`, `government`, `password_managers`,
`os_updates`, `pinned_apps`.

## Release

`.github/workflows/release.yml` runs on every push to `main` that touches the lists: it validates,
builds the version `vYYYY.MM.DD` (`vYYYY.MM.DD.N` for further releases the same day), signs each
file with the Ed25519 key in the repository secret `ARGUS_LISTS_SIGNING_KEY` (minisign format) and
publishes `<id>.txt`, `<id>.txt.minisig`, `meta.json` and `meta.json.minisig` as release assets of
`metril/argus-lists`. Argus reads them from
`https://github.com/metril/argus-lists/releases/latest/download/<file>`.

## Catalogues

`catalog/filters.json` (`{"schema":1,"entries":[{id,name,description,url,format,category,licence,homepage,region?}]}`,
`format` is `abp|ubo|adguard|hosts|domains|ips`) and `catalog/userscripts.json` (`{"schema":1,"entries":[{id,name,
description,install_url,homepage,sites,category,licence,needs_gm,connect}]}`, `needs_gm` is `none|basic|xhr`,
`licence` may be null) are copied into the release and signed like the lists (`filters.json`, `userscripts.json`
plus `.minisig`). They only point at third-party lists and scripts; nothing is mirrored. `scripts/validate.py` checks
schema, unique ids, https, formats, categories and `.user.js` URLs; `validate.py --net` fetches every URL, checks
userscript headers (`@name`, `@updateURL`/`@downloadURL`) and flags entries not modified for 2 years.
`.github/workflows/catalog-check.yml` runs it weekly and opens or updates a "Catalog check failing" issue.

## Signing key

Generate an unencrypted key pair once, keep the secret key only in the repository secret, and put
the public key into Argus (`ARGUS_LISTS_PUBLIC_KEY` in `crates/common/src/bypass.rs`):

```sh
minisign -G -W -p argus-lists.pub -s argus-lists.key
gh secret set ARGUS_LISTS_SIGNING_KEY < argus-lists.key
```

Argus never installs a list older than the one it already has.

## Generated lists

`generator/generate.py` (weekly via `.github/workflows/generate.yml`, as a pull request) grows
`lists/<category>/generated.txt` from Wikidata, FDIC BankFind and CISA dotgov-data; see
`SOURCES.md` for licences and `generator/config.toml` / `generator/deny.txt` for what is pulled and
dropped. `generated/provenance.jsonl` records where each domain came from (not published).

## TLS root store

`roots/roots.json` is the approved Mozilla root set (Websites trust bit, restricted to the Chrome Root
Store) that Argus uses for certificate verification and chain display, with Chrome's per-root
`sct_not_after` / `permitted_dns_names` constraints and the Google-signed CT log list as `ct_logs`
(RFC 6962 and tiled logs, `"type":"rfc6962"|"static"`; the signature is verified against a pinned key
when fetched). `generator/rootstore.py` builds it from the CCADB "Mozilla included CA certificates" CSV,
cross-checked against NSS `certdata.txt`; the job fails if they differ by more than 3 roots. Roots absent
from the Chrome Root Store are dropped; Chrome-only roots are never added. Unknown Chrome fields fail the
job rather than being ignored, and `min_version`/`max_version_exclusive` blocks are evaluated against Chrome's
current stable version (VersionHistory API; the job fails if it cannot be read).

`.github/workflows/roots.yml` runs daily in two jobs: a read-only `generate` job (regenerate, validate,
split) and a `publish` job that only commits files, opens the PR.

* Stricter changes (removals, new or earlier `distrust_after`/`sct_not_after`, narrower DNS lists, logs
  removed or retired) are committed straight to `main` (which triggers `release.yml`), even while a
  loosening is waiting.
* Anything that loosens trust (an addition, a removed or later date, a widened constraint) goes on top of
  that into the rolling `roots/auto` PR (never auto-merged). The branch is rebuilt on the current `main`
  every run, left alone when only `serial`/`generated_at` would change, and the PR is closed (branch
  deleted) when nothing is left to review, so a stale PR cannot reintroduce a removed root.
* A root listed in `roots/rejected.txt` (sha256 per line, `#` reason) is never published, so a rejected
  root does not reopen the PR every day; reject one with a normal reviewed PR to `main`; if the root is already published, that PR must also remove
  it from `roots/roots.json` with a serial bump (validation fails otherwise).
* `publish` checks out exactly the `main` commit that `generate` saw; if `main` moved meanwhile the push is
  non-fast-forward and the run is skipped (the next run redoes it).
* `release.yml` runs only on `main`, validates (`scripts/validate_roots.py`), refuses a serial that is not greater than the
  published one, fails on any error fetching the published file other than 404, and refuses a loosening
  unless some commit since the last published release (the release tag points at the published commit)
  came from a merged PR into `main` and the head does not loosen that commit's `roots.json`. It publishes `roots.json` and
  `roots.json.minisig` next to the lists.

Repository settings the workflows rely on: Actions may create pull requests. `main` is protected by a
ruleset requiring a pull request with 1 approval and dismissing stale approvals; only the admin role and
deploy keys may bypass it. The `GITHUB_TOKEN` bot cannot bypass on a personal repo, so the `publish` job
pushes over SSH with a write deploy key stored in the repo secret `ROOTS_DEPLOY_KEY` (checkout `ssh-key`).
Unlike `GITHUB_TOKEN` pushes, deploy-key pushes trigger workflows: the push to `main` runs `release.yml`
and the force-push to `roots/auto` updates the PR and runs `test.yml`. `gh` still uses `GITHUB_TOKEN` for
the PR (`contents: write`, `pull-requests: write`).

Dependencies are pinned by hash (`requirements.txt`, `requirements-dev.txt`, compiled from the `.in`
files with `uv pip compile --universal --generate-hashes`; install with `--require-hashes`) and actions by
commit SHA. Tests: `pip install --require-hashes -r requirements-dev.txt && pytest -n auto tests`.
