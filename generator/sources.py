"""Source fetchers. Each returns a list of (category, url_or_host, source, entity_id)."""
import csv, hashlib, io, json, sys, time
from urllib.parse import urlencode
from common import http_get, cached


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def wikidata(cfg, refresh):
    w = cfg["wikidata"]
    out = []
    for cat, classes in w["classes"].items():
        for qid, spec in classes.items():
            spec = {"label": spec} if isinstance(spec, str) else spec
            label = spec["label"]
            # direct = instances only (no subclass closure); exclude = MINUS items of these classes.
            path = "wdt:P31" if spec.get("direct") else "wdt:P31/wdt:P279*"
            minus = "".join(f" MINUS {{ ?item wdt:P31/wdt:P279* wd:{x} }}" for x in spec.get("exclude", []))

            def fetch(qid=qid, label=label, path=path, minus=minus):
                rows, offset, size = [], 0, w["page_size"]
                while True:
                    q = (f"SELECT ?item ?url ?end WHERE {{ ?item {path} wd:{qid} . ?item wdt:P856 ?url .{minus} "
                         f"OPTIONAL {{ ?item wdt:P576 ?end }} }} ORDER BY ?item LIMIT {size} OFFSET {offset}")
                    body = http_get(w["endpoint"], data=urlencode({"query": q}).encode(),
                                    headers={"Accept": "application/sparql-results+json",
                                             "Content-Type": "application/x-www-form-urlencoded"})
                    res = json.loads(body, strict=False)["results"]["bindings"]
                    # Dissolved entities (P576) are dropped here: a FILTER NOT EXISTS makes WDQS time out.
                    rows += [[b["item"]["value"].rsplit("/", 1)[1], b["url"]["value"]] for b in res
                             if "end" not in b]
                    log(f"wikidata {qid} {label}: {offset + len(res)} fetched, {len(rows)} kept")
                    if len(res) < size:
                        return rows
                    offset += size
                    time.sleep(1)
            rows = cached(f"wikidata_{qid}_{hashlib.md5((path + minus).encode()).hexdigest()[:6]}.json", fetch, refresh)
            out += [(cat, url, f"wikidata:{qid}", item) for item, url in rows]
    return out


def fdic(cfg, refresh):
    c = cfg["fdic"]

    def fetch():
        rows, offset = [], 0
        while True:
            qs = urlencode({"filters": "ACTIVE:1", "fields": "CERT,WEBADDR", "limit": 1000,
                            "offset": offset, "sort_by": "CERT", "sort_order": "ASC"})
            d = json.loads(http_get(f"{c['url']}?{qs}"))
            page = [x["data"] for x in d["data"]]
            rows += [[str(x["CERT"]), x.get("WEBADDR") or ""] for x in page]
            log(f"fdic: {len(rows)}/{d['meta']['total']}")
            if len(page) < 1000:
                return rows
            offset += 1000
    return [(c["category"], url, "fdic", f"cert:{cert}") for cert, url in cached("fdic.json", fetch, refresh)]


def cisa(cfg, refresh):
    c = cfg["cisa"]
    raw = cached("cisa.json", lambda: http_get(c["url"]).decode("utf-8-sig"), refresh)
    return [(c["category"], r["Domain name"], "cisa-dotgov", r["Domain name"].lower())
            for r in csv.DictReader(io.StringIO(raw)) if r.get("Domain name")]
