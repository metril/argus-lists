# argus-lists

Curated "do not decrypt" host lists for [Argus](https://github.com/metril/argus), published as
signed release assets. Argus subscribes to them by default and verifies every file against a
compiled-in public key before using it.

## Layout

* `lists/<category>.txt` — one host or `*.suffix` per line; `#` starts a comment. A bare domain
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
