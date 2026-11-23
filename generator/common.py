"""Shared helpers: HTTP, cached fetch, Public Suffix List and URL -> domain normalisation."""
import ipaddress, json, pathlib, re, time, urllib.request, urllib.error
from urllib.parse import urlsplit

ROOT = pathlib.Path(__file__).resolve().parent.parent
CACHE = ROOT / ".cache"
UA = "argus-lists-generator/1.0 (+https://github.com/metril/argus-lists)"
LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def http_get(url, data=None, headers=None, retries=4, timeout=120):
    h = {"User-Agent": UA, **(headers or {})}
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, data=data, headers=h)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code in (429, 502, 503, 504) and attempt < retries - 1:
                time.sleep(min(int(e.headers.get("Retry-After", 0) or 0) or 10 * (attempt + 1), 90))
                continue
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if attempt == retries - 1:
                raise
            time.sleep(5 * (attempt + 1))


def cached(name, fetch, refresh=False):
    """Cache a fetcher's JSON-serialisable result under .cache/ (reruns do not re-hit the sources)."""
    CACHE.mkdir(exist_ok=True)
    p = CACHE / name
    if p.exists() and not refresh:
        return json.loads(p.read_text())
    val = fetch()
    p.write_text(json.dumps(val))
    return val


class PSL:
    """Registrable domain from the vendored Public Suffix List (ICANN section only; private
    platform suffixes such as github.io are handled by deny.txt instead)."""

    def __init__(self, path):
        self.rules, self.wild, self.exc = set(), set(), set()
        for line in path.read_text(encoding="utf-8").splitlines():
            if "===END ICANN DOMAINS===" in line:
                break
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            if line.startswith("!"):
                self.exc.add(line[1:])
            elif line.startswith("*."):
                self.wild.add(line[2:])
            else:
                self.rules.add(line)

    def suffix_len(self, labels):
        n = len(labels)
        for i in range(n):
            cand = ".".join(labels[i:])
            if cand in self.exc:
                return n - i - 1
            if cand in self.rules or ".".join(labels[i + 1:]) in self.wild and i + 1 < n:
                return n - i
        return 1

    def registrable(self, host):
        labels = host.split(".")
        k = self.suffix_len(labels)
        if len(labels) <= k:
            return None  # host is itself a public suffix
        return ".".join(labels[-(k + 1):])


def host_of(url):
    """Lowercase ASCII hostname of an http(s) URL (or bare host), without www/port/path; else None."""
    url = url.strip()
    if not url:
        return None
    if "://" not in url:
        url = "http://" + url
    try:
        u = urlsplit(url)
        if u.scheme not in ("http", "https"):
            return None
        host = (u.hostname or "").strip(".").lower()
        host = host.encode("idna").decode("ascii") if host else ""
    except (ValueError, UnicodeError):
        return None
    if not host or "." not in host:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    host = re.sub(r"^www\d*\.", "", host)
    if "." not in host or not all(LABEL.match(l) for l in host.split(".")):
        return None
    return host
