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

`roots/roots.json` is the approved Mozilla root set (Websites trust bit, further restricted to the Chrome Root Store) that Argus uses for
certificate verification and chain display. `generator/rootstore.py` builds it from the CCADB
"Mozilla included CA certificates" PEM CSV report, cross-checked against NSS `certdata.txt`
(server-auth trusted delegators); the set is the intersection by SHA-256 and the job fails if the
sources differ by more than 3 roots. Roots absent from the Chrome Root Store (`root_store.textproto`) are dropped
(Chrome-only roots are never added); Chrome's `sct_not_after` and `permitted_dns_names` constraints are
carried per root, and the Google-signed CT log list (verified against a pinned key) is carried as `ct_logs`.
Anything that loosens trust (an addition, a removed or later date or constraint) goes through the PR. `.github/workflows/roots.yml` runs daily: removals and
new or earlier `distrust_after` dates are committed to `main`; any addition, or a removed or
later distrust date, opens/updates the rolling `roots/auto` PR (never auto-merged). After an auto-commit it dispatches `release.yml` itself (a push made with
`GITHUB_TOKEN` does not trigger workflows; needs `actions: write`). Branch protection on `main` must
allow `github-actions[bot]` to push. The release
workflow validates (`scripts/validate_roots.py`) and publishes `roots.json` and `roots.json.minisig`
next to the lists. Tests: `pip install -r requirements-dev.txt && pytest -n auto tests`.
