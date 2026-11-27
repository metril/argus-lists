import copy, datetime as dt, email.utils, json, pathlib, subprocess, sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import catalog  # noqa: E402

NOW = dt.datetime(2026, 11, 23, tzinfo=dt.timezone.utc)
FILTER = dict(id="easylist", name="EasyList", description="d", url="https://example.com/a.txt", format="abp",
              category="ads", licence="GPL-3.0", homepage="https://example.com/")
SCRIPT = dict(id="gf-1", name="S", description="d", install_url="https://update.greasyfork.org/scripts/1/s.user.js",
              homepage="https://greasyfork.org/scripts/1", sites=["*"], category="ads", licence=None,
              needs_gm="none", connect=[], requires=[])
HEADER = "// ==UserScript==\n// @name S\n// @downloadURL https://x/s.user.js\n// ==/UserScript==\nbody"


def doc(*entries, kind=None):
    return {"schema": 1, "kind": kind or ("userscripts" if "install_url" in entries[0] else "filters"), "entries": [copy.deepcopy(e) for e in entries]}


def lm(days):
    return {"Last-Modified": email.utils.format_datetime(NOW - dt.timedelta(days=days))}


def test_committed_catalogs_are_valid():
    docs, errs = catalog.load()
    assert errs == []
    assert len(docs["filters"]["entries"]) >= 30 and len(docs["userscripts"]["entries"]) >= 30


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
    (lambda e: e.update(trusted="yes"), "trusted"),
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
    (lambda e: e.update(needs_gm="xhr", connect=[]), "xhr"),
    (lambda e: e.update(sites=["invidious instances"]), "not a host"),
    (lambda e: e.update(connect=["http://x"]), "not a host"),
    (lambda e: e.update(requires=["http://x/a.js"]), "requires"),
    (lambda e: e.update(licence="free for personal use"), "SPDX"),
])
def test_script_errors(mut, frag):
    e = copy.deepcopy(SCRIPT)
    mut(e)
    assert any(frag in m for m in catalog.check_doc(doc(e), "userscripts"))


@pytest.mark.parametrize("cat", ["reddit", "wikipedia", "stackexchange", "media", "amp"])
def test_script_new_categories_allowed(cat):
    e = copy.deepcopy(SCRIPT)
    e["category"] = cat
    assert catalog.check_doc(doc(e), "userscripts") == []


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


def test_valid_host_globs_and_xhr():
    e = copy.deepcopy(SCRIPT)
    e.update(sites=["*", "*.google.*", "example.com", "*.example.com"], needs_gm="xhr", connect=["*", "self", "api.x.io"])
    assert catalog.check_doc(doc(e), "userscripts") == []


def test_kind_must_match():
    d = doc(FILTER)
    d["kind"] = "userscripts"
    assert any("kind" in m for m in catalog.check_doc(d, "filters"))
    d.pop("kind")
    assert any("kind" in m for m in catalog.check_doc(d, "filters"))


def test_naive_last_modified_is_utc():
    assert catalog.stale({"Last-Modified": "Mon, 01 Jan 2018 00:00:00 -0000"}, NOW)
    assert not catalog.stale({"Last-Modified": "Mon, 16 Nov 2026 00:00:00 -0000"}, NOW)


def test_header_regex_limited_to_metadata_block():
    body = "// ==UserScript==\n// @name S\n// ==/UserScript==\n// @downloadURL https://x/y"
    assert any("@updateURL" in m for m in run_net("userscripts", SCRIPT, body=body))


def test_build_puts_catalogues_in_dist(tmp_path):
    out = tmp_path / "repo"
    (out / "scripts").mkdir(parents=True)
    for f in ("build.py", "allowed-wildcards.txt"):
        (out / "scripts" / f).write_bytes((ROOT / "scripts" / f).read_bytes())
    (out / "lists" / "a").mkdir(parents=True)
    (out / "lists" / "a" / "manual.txt").write_text("example.com\n")
    (out / "meta.json").write_text(json.dumps({"categories": [{"id": "a"}]}))
    (out / "catalog").mkdir()
    for k in catalog.FILES:
        (out / "catalog" / f"{k}.json").write_bytes((ROOT / "catalog" / f"{k}.json").read_bytes())
    (out / "catalog" / "other.json").write_text("{}")
    subprocess.run([sys.executable, str(out / "scripts" / "build.py"), "vtest"], check=True, capture_output=True)
    dist = out / "dist"
    assert (dist / "filters.json").exists() and (dist / "userscripts.json").exists()
    assert not (dist / "other.json").exists()
    meta = json.loads((dist / "meta.json").read_text())
    import hashlib
    assert {c["kind"]: c["sha256"] for c in meta["catalogues"]} == {
        k: hashlib.sha256((dist / f"{k}.json").read_bytes()).hexdigest() for k in catalog.FILES}


def test_main_net_rejects_malformed_before_network(tmp_path, monkeypatch):
    import runpy
    (tmp_path / "catalog").mkdir()
    (tmp_path / "catalog" / "filters.json").write_text(json.dumps({"schema": 1, "kind": "filters", "entries": [{"id": "x"}]}))
    (tmp_path / "catalog" / "userscripts.json").write_text(json.dumps(doc(SCRIPT)))
    monkeypatch.setattr(catalog, "ROOT", tmp_path)
    called = []
    monkeypatch.setattr(catalog, "check_net", lambda *a, **k: called.append(1) or [])
    orig = catalog.load
    monkeypatch.setattr(catalog, "load", lambda root=tmp_path: orig(root))
    monkeypatch.setattr(sys, "argv", ["validate.py", "--net"])
    sys.modules.pop("validate", None)
    sys.path.insert(0, str(ROOT / "scripts"))
    mod = runpy.run_path(str(ROOT / "scripts" / "validate.py"), run_name="validate_test")
    with pytest.raises(SystemExit) as ex:
        mod["main_net"]()
    assert ex.value.code == 1 and not called


def test_unpinned_urls():
    for u in ("https://cdn.jsdelivr.net/gh/o/r@dev/a.js", "https://cdn.jsdelivr.net/gh/o/r/a.js",
              "https://raw.githubusercontent.com/o/r/main/a.js", "https://github.com/o/r/raw/master/a.js",
              "https://example.com/lib.js"):
        assert catalog.unpinned(u), u
    for u in ("https://cdn.jsdelivr.net/npm/x@1.2.3/a.js", "https://cdn.jsdelivr.net/gh/o/r@22af192175b5e1707f49c57de7ce942d4d4ad480/a.js",
              "https://raw.githubusercontent.com/o/r/22af192/a.js", "https://code.jquery.com/jquery-3.3.1.min.js",
              "https://update.greasyfork.org/scripts/528923/1588272/M.js"):
        assert not catalog.unpinned(u), u


def test_net_warns_on_unpinned_require():
    body = HEADER.replace("// ==/UserScript==", "// @require https://cdn.jsdelivr.net/gh/o/r@dev/a.js\n// ==/UserScript==")
    warns = []
    st = lambda u: (200, {}, body)
    assert catalog.check_entry_net("userscripts", dict(SCRIPT), st, NOW, warns) == []
    assert len(warns) == 1 and "not pinned" in warns[0]


def test_github_date_fallback():
    url = "https://raw.githubusercontent.com/o/r/main/a.user.js"
    old, new = NOW - dt.timedelta(days=900), NOW - dt.timedelta(days=5)
    assert catalog.stale({}, NOW, lambda u: old, url)
    assert not catalog.stale({}, NOW, lambda u: new, url)
    w = []
    assert not catalog.stale({}, NOW, lambda u: None, url, w, "x")
    assert len(w) == 1
    assert not catalog.stale({}, NOW, lambda u: old, "https://example.com/a.user.js")
    e = dict(SCRIPT, install_url=url)
    errs = catalog.check_entry_net("userscripts", e, lambda u: (200, {}, HEADER), NOW, [], lambda u: old)
    assert any("stale" in m for m in errs)
