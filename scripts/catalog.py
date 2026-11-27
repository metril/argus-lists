"""Checks for catalog/filters.json and catalog/userscripts.json (offline schema + optional network)."""
import datetime as dt, email.utils, json, os, pathlib, re, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parent.parent
FORMATS = {"abp", "ubo", "adguard", "hosts", "domains", "ips"}
FILTER_CATEGORIES = {"ads", "privacy", "annoyances", "social", "malware", "phishing", "unbreak",
                     "ads+tracking", "ads+malware", "ads+tracking+malware"}
SCRIPT_CATEGORIES = {"ads", "shortlinks", "link-cleaning", "google-ai-overview", "youtube", "social",
                     "github", "cookie-banners", "reddit", "wikipedia", "stackexchange", "media",
                     "amp"}
GM = {"none", "basic", "xhr"}
ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")
STALE_DAYS = 730
MAX_READ = 256 * 1024
UA = "argus-lists-validator"
FILES = ("filters", "userscripts")
HOST = re.compile(r"^(\*|(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(\.\*)?)$")
SPDX = re.compile(r"^[A-Za-z0-9.+-]+( (OR|AND|WITH) [A-Za-z0-9.+-]+)*$")


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
    if doc.get("kind") != kind:
        return [f"{kind}: top-level kind must be {kind!r} (got {doc.get('kind')!r})"]
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
            _str(e, "licence_note", errs, where, optional=True)
            if "noncommercial" in e and not isinstance(e["noncommercial"], bool):
                errs.append(f"{where}: noncommercial must be a boolean")
            if "trusted" in e and not isinstance(e["trusted"], bool):
                errs.append(f"{where}: trusted must be a boolean")
            if isinstance(e.get("licence"), str) and not SPDX.match(e["licence"]):
                errs.append(f"{where}: licence must be an SPDX id or expression (use licence_note for free text)")
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
            if isinstance(e.get("licence"), str) and not SPDX.match(e["licence"]):
                errs.append(f"{where}: licence must be an SPDX id or expression")
            for k in ("sites", "connect"):
                v = e.get(k)
                if not isinstance(v, list) or not all(isinstance(s, str) and s for s in v):
                    errs.append(f"{where}: {k} must be a list of strings")
                else:
                    errs += [f"{where}: {k} entry {s!r} is not a host, *.host or *" for s in v
                             if not HOST.match(s) and not (k == "connect" and s == "self")]
            r = e.get("requires")
            if not isinstance(r, list) or not all(isinstance(s, str) and s.startswith("https://") for s in r):
                errs.append(f"{where}: requires must be a list of https URLs")
            if e.get("needs_gm") == "xhr" and not e.get("connect"):
                errs.append(f"{where}: needs_gm xhr requires a non-empty connect list")
            if not e.get("sites"):
                errs.append(f"{where}: sites must not be empty")
    return errs


def load(root=ROOT):
    errs, docs = [], {}
    for kind in FILES:
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


def _lm(headers):
    lm = headers.get("Last-Modified") if headers else None
    if not lm:
        return None
    try:
        t = email.utils.parsedate_to_datetime(lm)
    except (TypeError, ValueError):
        return None
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


def stale(headers, now, gh_date=None, url=None, warns=None, where=""):
    """True when older than STALE_DAYS. Without Last-Modified, raw.githubusercontent.com URLs use gh_date(url)
    (last commit date for the path); if that is unavailable a warning is added to warns."""
    t = _lm(headers)
    if t is None and url and url.startswith("https://raw.githubusercontent.com/"):
        t = (gh_date or github_date)(url)
        if t is None and warns is not None:
            warns.append(f"{where}: no Last-Modified and GitHub commit date unavailable, staleness not checked")
    return t is not None and (now - t).days > STALE_DAYS


def github_date(url):
    """Last commit date of a raw.githubusercontent.com file via the GitHub API, or None."""
    parts = url.split("?", 1)[0].split("/")[3:]
    if len(parts) < 4:
        return None
    owner, repo, ref, path = parts[0], parts[1], parts[2], "/".join(parts[3:])
    api = f"https://api.github.com/repos/{owner}/{repo}/commits?per_page=1&sha={ref}&path={path}"
    hdr = {"User-Agent": UA, "Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        hdr["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    try:
        with urllib.request.urlopen(urllib.request.Request(api, headers=hdr), timeout=30) as r:
            return dt.datetime.fromisoformat(json.load(r)[0]["commit"]["committer"]["date"].replace("Z", "+00:00"))
    except Exception:  # noqa: BLE001
        return None


BRANCHES = {"dev", "develop", "master", "main", "latest", "head", "trunk"}


def unpinned(url):
    """True when a @require/@resource URL is not pinned to a commit, version or hash."""
    u = urllib.parse.urlsplit(url)
    parts = [x for x in u.path.split("/") if x]
    ref = None
    if u.netloc == "raw.githubusercontent.com" and len(parts) > 2:
        ref = parts[2]
    elif u.netloc == "github.com" and len(parts) > 3 and parts[2] == "raw":
        ref = parts[3]
    elif re.search(r"[^/]@[^/]+", u.path):
        ref = re.search(r"[^/]@([^/]+)", u.path).group(1)
    elif u.netloc in ("cdn.jsdelivr.net", "unpkg.com"):
        return True
    if ref is not None:
        return ref.lower() in BRANCHES or not (re.fullmatch(r"[0-9a-f]{7,40}", ref) or re.match(r"v?\d", ref))
    if "sha256=" in u.fragment or "sha384=" in u.fragment:
        return False
    return not re.search(r"\d+\.\d+|/\d{3,}/|[0-9a-f]{32,}|version=\d", url)


def check_entry_net(kind, e, fetcher, now, warns=None, gh_date=None):
    url = e["url"] if kind == "filters" else e["install_url"]
    where = f"{kind}:{e['id']}"
    status, headers, body = fetcher(url)
    if status != 200:
        return [f"{where}: {url} returned {status or 'a network error'}"]
    errs = []
    if kind == "userscripts":
        m = re.search(r"==UserScript==(.*?)==/UserScript==", body, re.S)
        if not m:
            errs.append(f"{where}: no userscript metadata block")
        else:
            meta = m.group(1)
            if not re.search(r"^//\s*@name\s+\S", meta, re.M):
                errs.append(f"{where}: header lacks @name")
            if not re.search(r"^//\s*@(updateURL|downloadURL)\s+\S", meta, re.M):
                errs.append(f"{where}: header lacks @updateURL/@downloadURL")
            if warns is not None:
                for u in re.findall(r"^//\s*@(?:require|resource\s+\S+)\s+(https?://\S+)", meta, re.M):
                    if unpinned(u):
                        warns.append(f"{where}: {u} is not pinned to a commit, version or hash")
    elif not body.strip() or re.match(r"\s*<(!doctype|html)", body, re.I):
        errs.append(f"{where}: {url} does not serve a list")
    if stale(headers, now, gh_date, url, warns, where):
        errs.append(f"{where}: stale, Last-Modified is older than {STALE_DAYS} days")
    return errs


def check_net(docs, fetcher=fetch, now=None, workers=8, warns=None, gh_date=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    jobs = [(k, e) for k in FILES for e in docs.get(k, {}).get("entries", [])]
    with ThreadPoolExecutor(workers) as ex:
        results = ex.map(lambda j: check_entry_net(j[0], j[1], fetcher, now, warns, gh_date), jobs)
    return [m for r in results for m in r]
