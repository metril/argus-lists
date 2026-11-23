import copy, datetime as dt, email.utils, json, pathlib, sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import catalog  # noqa: E402

NOW = dt.datetime(2026, 11, 23, tzinfo=dt.timezone.utc)
FILTER = dict(id="easylist", name="EasyList", description="d", url="https://example.com/a.txt", format="abp",
              category="ads", licence="GPL-3.0", homepage="https://example.com/")
SCRIPT = dict(id="gf-1", name="S", description="d", install_url="https://update.greasyfork.org/scripts/1/s.user.js",
              homepage="https://greasyfork.org/scripts/1", sites=["*"], category="ads", licence=None,
              needs_gm="none", connect=[])
HEADER = "// ==UserScript==\n// @name S\n// @downloadURL https://x/s.user.js\n// ==/UserScript==\nbody"


def doc(*entries):
    return {"schema": 1, "entries": [copy.deepcopy(e) for e in entries]}


def lm(days):
    return {"Last-Modified": email.utils.format_datetime(NOW - dt.timedelta(days=days))}


def test_committed_catalogs_are_valid():
    docs, errs = catalog.load()
    assert errs == []
    assert len(docs["filters"]["entries"]) >= 30 and len(docs["userscripts"]["entries"]) == 31


def test_valid_docs():
    assert catalog.check_doc(doc(FILTER), "filters") == []
    assert catalog.check_doc(doc(SCRIPT), "userscripts") == []


@pytest.mark.parametrize("mut,frag", [
    (lambda e: e.update(url="http://example.com/a.txt"), "https"),
    (lambda e: e.update(format="xml"), "format"),
    (lambda e: e.update(category="nope"), "category"),
    (lambda e: e.update(id="Bad Id"), "id must"),
    (lambda e: e.pop("name"), "name"),
    (lambda e: e.update(homepage="ftp://x"), "homepage"),
])
def test_filter_errors(mut, frag):
    e = copy.deepcopy(FILTER)
    mut(e)
    assert any(frag in m for m in catalog.check_doc(doc(e), "filters"))


@pytest.mark.parametrize("mut,frag", [
    (lambda e: e.update(install_url="https://x/s.js"), ".user.js"),
    (lambda e: e.update(install_url="http://x/s.user.js"), "https"),
    (lambda e: e.update(needs_gm="all"), "needs_gm"),
    (lambda e: e.update(sites=[]), "sites"),
    (lambda e: e.update(connect="x"), "connect"),
    (lambda e: e.pop("licence"), "licence"),
    (lambda e: e.update(category="paywall"), "category"),
])
def test_script_errors(mut, frag):
    e = copy.deepcopy(SCRIPT)
    mut(e)
    assert any(frag in m for m in catalog.check_doc(doc(e), "userscripts"))


def test_duplicate_ids_and_bad_schema():
    assert any("duplicate" in m for m in catalog.check_doc(doc(FILTER, FILTER), "filters"))
    assert catalog.check_doc({"schema": 2, "entries": []}, "filters")
    assert catalog.check_doc([], "filters")


def test_load_reports_missing_and_invalid(tmp_path):
    (tmp_path / "catalog").mkdir()
    (tmp_path / "catalog" / "filters.json").write_text("{")
    _, errs = catalog.load(tmp_path)
    assert len(errs) == 2


def run_net(kind, entry, status=200, headers=None, body="! list\n||x^"):
    return catalog.check_entry_net(kind, entry, lambda u: (status, headers or {}, body), NOW)


def test_net_ok_and_failures():
    assert run_net("filters", FILTER) == []
    assert any("404" in m for m in run_net("filters", FILTER, status=404))
    assert any("network error" in m for m in run_net("filters", FILTER, status=0))
    assert any("does not serve" in m for m in run_net("filters", FILTER, body="<!DOCTYPE html><html>"))
    assert any("does not serve" in m for m in run_net("filters", FILTER, body=""))


def test_net_userscript_header():
    assert run_net("userscripts", SCRIPT, body=HEADER) == []
    assert any("metadata" in m for m in run_net("userscripts", SCRIPT, body="nothing"))
    assert any("@name" in m for m in run_net("userscripts", SCRIPT, body=HEADER.replace("@name S", "@x S")))
    assert any("@updateURL" in m for m in run_net("userscripts", SCRIPT, body=HEADER.replace("@downloadURL", "@x")))
    assert run_net("userscripts", SCRIPT, body=HEADER.replace("@downloadURL", "@updateURL")) == []


def test_net_staleness():
    assert run_net("filters", FILTER, headers=lm(100)) == []
    assert any("stale" in m for m in run_net("filters", FILTER, headers=lm(800)))
    assert run_net("filters", FILTER, headers={"Last-Modified": "garbage"}) == []


def test_check_net_aggregates():
    docs = {"filters": doc(FILTER), "userscripts": doc(SCRIPT)}
    fake = lambda u: (404, {}, "") if u.endswith(".txt") else (200, {}, HEADER)
    errs = catalog.check_net(docs, fetcher=fake, now=NOW)
    assert len(errs) == 1 and "easylist" in errs[0]
