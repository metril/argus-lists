"""Checks for catalog/filters.json and catalog/userscripts.json (offline schema + optional network)."""
import datetime as dt, email.utils, json, pathlib, re, urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parent.parent
FORMATS = {"abp", "ubo", "adguard", "hosts", "domains", "ips"}
FILTER_CATEGORIES = {"ads", "privacy", "annoyances", "social", "malware", "phishing", "unbreak",
                     "ads+tracking", "ads+malware", "ads+tracking+malware"}
SCRIPT_CATEGORIES = {"ads", "shortlinks", "link-cleaning", "google-ai-overview", "youtube", "social",
                     "github", "cookie-banners"}
GM = {"none", "basic", "xhr"}
ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")
STALE_DAYS = 730
MAX_READ = 256 * 1024
UA = "argus-lists-validator"


def _str(e, k, errs, where, optional=False):
    v = e.get(k)
    if v is None and optional:
        return
    if not isinstance(v, str) or not v.strip():
        errs.append(f"{where}: {k} must be a non-empty string")


def _https(e, k, errs, where):
    v = e.get(k)
    if not isinstance(v, str) or not v.startswith("https://") or " " in v:
        errs.append(f"{where}: {k} must be an https:// URL")


def check_doc(doc, kind):
    """kind: 'filters' or 'userscripts'. Returns a list of error strings."""
    errs = []
    if not isinstance(doc, dict) or doc.get("schema") != 1 or not isinstance(doc.get("entries"), list):
        return [f"{kind}: must be an object with schema=1 and an entries list"]
    seen = set()
    for i, e in enumerate(doc["entries"]):
        where = f"{kind}[{i}]"
        if not isinstance(e, dict):
            errs.append(f"{where}: must be an object")
            continue
        if not isinstance(e.get("id"), str) or not ID.match(e["id"]):
            errs.append(f"{where}: id must match {ID.pattern}")
        elif e["id"] in seen:
            errs.append(f"{where}: duplicate id {e['id']!r}")
        else:
            seen.add(e["id"])
        where = f"{kind}:{e.get('id', i)}"
        for k in ("name", "description", "category"):
            _str(e, k, errs, where)
        _https(e, "homepage", errs, where)
        if kind == "filters":
            _https(e, "url", errs, where)
            _str(e, "licence", errs, where)
            _str(e, "region", errs, where, optional=True)
            if e.get("format") not in FORMATS:
                errs.append(f"{where}: format must be one of {sorted(FORMATS)}")
            if e.get("category") not in FILTER_CATEGORIES:
                errs.append(f"{where}: unknown category {e.get('category')!r}")
        else:
            _https(e, "install_url", errs, where)
            u = e.get("install_url")
            if isinstance(u, str) and not u.split("?", 1)[0].endswith(".user.js"):
                errs.append(f"{where}: install_url must end in .user.js")
            if e.get("licence") is not None:
                _str(e, "licence", errs, where)
            if "licence" not in e:
                errs.append(f"{where}: licence is required (string or null)")
            if e.get("category") not in SCRIPT_CATEGORIES:
                errs.append(f"{where}: unknown category {e.get('category')!r}")
            if e.get("needs_gm") not in GM:
                errs.append(f"{where}: needs_gm must be one of {sorted(GM)}")
            for k in ("sites", "connect"):
                v = e.get(k)
                if not isinstance(v, list) or not all(isinstance(s, str) and s for s in v):
                    errs.append(f"{where}: {k} must be a list of strings")
            if not e.get("sites"):
                errs.append(f"{where}: sites must not be empty")
    return errs


def load(root=ROOT):
    errs, docs = [], {}
    for kind in ("filters", "userscripts"):
        p = pathlib.Path(root) / "catalog" / f"{kind}.json"
        try:
            docs[kind] = json.loads(p.read_text())
        except (OSError, ValueError) as ex:
            errs.append(f"catalog/{kind}.json: {ex}")
            continue
        errs += check_doc(docs[kind], kind)
    return docs, errs


def fetch(url):
    """GET url, reading at most MAX_READ bytes. Returns (status, headers, text); status 0 on failure."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.headers, r.read(MAX_READ).decode("utf-8", "replace")
    except urllib.error.HTTPError as ex:
        return ex.code, ex.headers, ""
    except Exception as ex:  # noqa: BLE001 -- any network failure is a finding
        return 0, {}, str(ex)


def stale(headers, now):
    lm = headers.get("Last-Modified") if headers else None
    if not lm:
        return False
    try:
        t = email.utils.parsedate_to_datetime(lm)
    except (TypeError, ValueError):
        return False
    return (now - t).days > STALE_DAYS


def check_entry_net(kind, e, fetcher, now):
    url = e["url"] if kind == "filters" else e["install_url"]
    where = f"{kind}:{e['id']}"
    status, headers, body = fetcher(url)
    if status != 200:
        return [f"{where}: {url} returned {status or 'a network error'}"]
    errs = []
    if kind == "userscripts":
        head = body[: body.find("==/UserScript==")] if "==/UserScript==" in body else ""
        if "==UserScript==" not in head and "==UserScript==" not in body:
            errs.append(f"{where}: no userscript metadata block")
        else:
            if not re.search(r"^//\s*@name\s+\S", body, re.M):
                errs.append(f"{where}: header lacks @name")
            if not re.search(r"^//\s*@(updateURL|downloadURL)\s+\S", body, re.M):
                errs.append(f"{where}: header lacks @updateURL/@downloadURL")
    elif not body.strip() or re.match(r"\s*<(!doctype|html)", body, re.I):
        errs.append(f"{where}: {url} does not serve a list")
    if stale(headers, now):
        errs.append(f"{where}: stale, Last-Modified is older than {STALE_DAYS} days")
    return errs


def check_net(docs, fetcher=fetch, now=None, workers=8):
    now = now or dt.datetime.now(dt.timezone.utc)
    jobs = [(k, e) for k in ("filters", "userscripts") for e in docs.get(k, {}).get("entries", [])]
    with ThreadPoolExecutor(workers) as ex:
        results = ex.map(lambda j: check_entry_net(j[0], j[1], fetcher, now), jobs)
    return [m for r in results for m in r]
