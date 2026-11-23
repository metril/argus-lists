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

## Not used

* **NCUA credit unions:** the NCUA call-report and credit-union data (public domain) carries names
  and street addresses but no website field, so there is no machine-readable source of websites.
* **GOV.UK / other Open Government Licence domain lists:** `*.gov.uk` and the other national
  government namespaces are already covered by wildcards in `lists/government/manual.txt`, so a
  list would add nothing; no OGL data is included and no attribution file is needed.
