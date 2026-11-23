# Sources and licences

`lists/<category>/generated.txt` is derived only from the openly licensed data below. Argus is
proprietary, so nothing under a share-alike or non-commercial licence is used. Only facts (domain
names) are extracted. `generated/provenance.jsonl` records the source and entity id of every domain.

| Source | Used for | Licence | Attribution |
|---|---|---|---|
| [Wikidata](https://www.wikidata.org) SPARQL (`P856` official website) | all five generated categories | CC0 1.0 | Not required; credited here: "Data from Wikidata". |
| [FDIC BankFind Suite API](https://banks.data.fdic.gov/docs/) (`WEBADDR` of active institutions) | banking_finance | US government work, public domain | Not required; credited here: "Source: FDIC". |
| [CISA dotgov-data](https://github.com/cisagov/dotgov-data) `current-full.csv` | government | US government work, public domain (CC0 dedication in the repository) | Not required. Every row is a `.gov` name already covered by the manual `*.gov` wildcard, so it currently adds nothing. |
| [Public Suffix List](https://publicsuffix.org/list/) (vendored, `generator/data/public_suffix_list.dat`, version 2026-11-21, commit 87a2c1b) | reducing URLs to registrable domains | MPL 2.0 (the data file is kept unmodified, with its notice) | Mozilla Foundation and contributors. |
| [CCADB Mozilla included roots](https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV) | `roots/roots.json` (Websites trust bit, distrust-after dates) | CCADB public data (as used by rustls/webpki-roots) | Common CA Database. |
| [NSS certdata.txt](https://github.com/mozilla-firefox/firefox/blob/main/security/nss/lib/ckfw/builtins/certdata.txt) (mozilla-central, now git; `hg.mozilla.org` no longer serves it) | cross-check of server-auth trust | MPL 2.0 (facts only; no file is redistributed) | Mozilla Foundation. |
| [Chrome Root Store](https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.textproto) | restricts `roots/roots.json`; SCT and DNS constraints | BSD-3-Clause (Chromium; facts only) | The Chromium Authors. |
| [CT log list v3](https://www.gstatic.com/ct/log_list/v3/log_list.json) (signature checked against Google's published `log_list_pubkey.pem`, pinned) | `ct_logs` | CC-BY 4.0-style public data (facts only) | Google. |

## Not used

* **NCUA credit unions:** the NCUA call-report and credit-union data (public domain) carries names
  and street addresses but no website field, so there is no machine-readable source of websites.
* **GOV.UK / other Open Government Licence domain lists:** `*.gov.uk` and the other national
  government namespaces are already covered by wildcards in `lists/government/manual.txt`, so a
  list would add nothing; no OGL data is included and no attribution file is needed.

## Catalogues

`catalog/filters.json` and `catalog/userscripts.json` are hand-curated indexes of third-party filter lists
(EasyList, uBlock Origin, AdGuard, Fanboy, regional lists, hosts/domain/IP feeds) and Greasy Fork userscripts.
Only metadata (name, URL, licence as stated by the publisher) is stored; no list or script content is
redistributed, and each entry's `licence` field records the upstream licence. Paywall-bypass scripts and video
downloaders are excluded. The userscript entries were filled from the `@name`, `@license`, `@match`, `@grant` and
`@connect` headers.
