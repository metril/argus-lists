#!/usr/bin/env python3
"""Grow lists/<cat>/generated.txt from openly licensed sources. See SOURCES.md.

    python generator/generate.py [--refresh] [--no-dns] [--allow-size-change]
"""
import argparse, collections, json, pathlib, socket, sys, time, tomllib
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from common import ROOT, CACHE, PSL, host_of, cached  # noqa: E402
import sources  # noqa: E402

GEN = pathlib.Path(__file__).resolve().parent
HEADER = """# {name} - GENERATED, do not edit (edit lists/{cat}/manual.txt for hand-curated entries).
# Sources: {srcs}. See SOURCES.md for licences. Written by generator/generate.py.
# One host per line; each covers the host and its subdomains.
"""
NAMES = {"banking_finance": "Banking and finance", "payments": "Payments", "health": "Health",
         "government": "Government", "password_managers": "Password managers"}


def read_list(path):
    if not path.exists():
        return []
    return [l.split("#", 1)[0].strip() for l in path.read_text().splitlines() if l.split("#", 1)[0].strip()]


def suffixes(d):
    p = d.split(".")
    return [".".join(p[i:]) for i in range(len(p))]


def dns_filter(domains, cfg, log):
    """Drop names that definitively do not exist (NXDOMAIN-style); timeouts/errors keep the name."""
    d = cfg["dns"]
    path = CACHE / "dns.json"
    cache = json.loads(path.read_text()) if path.exists() else {}
    now, ttl = time.time(), d["cache_ttl_days"] * 86400
    todo = [x for x in domains if x not in cache or now - cache[x][0] > ttl]
    deadline = now + d["max_seconds"]
    socket.setdefaulttimeout(4)

    def check(x):
        if time.time() > deadline:
            return x, None
        verdict = False
        for h in (x, "www." + x):
            try:
                socket.getaddrinfo(h, 443)
                return x, True
            except socket.gaierror as e:
                if e.errno not in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)):
                    verdict = True  # temporary failure: keep
            except OSError:
                verdict = True
        return x, verdict

    with ThreadPoolExecutor(d["workers"]) as ex:
        for x, ok in ex.map(check, todo):
            if ok is not None:
                cache[x] = [time.time(), ok]
    CACHE.mkdir(exist_ok=True)
    path.write_text(json.dumps(cache))
    unchecked = sum(1 for x in domains if x not in cache)
    dead = {x for x in domains if x in cache and cache[x][1] is False}
    log(f"dns: {len(dead)} dead, {unchecked} unchecked (cap), {len(todo)} looked up")
    return dead


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--refresh", action="store_true", help="ignore the .cache/ of fetched source data")
    ap.add_argument("--no-dns", action="store_true")
    ap.add_argument("--allow-size-change", action="store_true", help="override the size guard")
    args = ap.parse_args()
    cfg = tomllib.loads((GEN / "config.toml").read_text())
    log = sources.log
    psl = PSL(GEN / "data" / "public_suffix_list.dat")
    full_psl = PSL(GEN / "data" / "public_suffix_list.dat", private=True)  # Argus rejects any PSL suffix
    deny = set(read_list(GEN / "deny.txt"))
    order = cfg["output"]["category_order"]
    lists = ROOT / "lists"

    # Manual entries of every category: generated output must not repeat or be covered by them.
    m_exact, m_wild = set(), set()
    manual_count = {}
    for p in sorted(lists.glob("*/manual.txt")):
        entries = read_list(p)
        manual_count[p.parent.name] = len(entries)
        for e in entries:
            (m_wild if e.startswith("*.") else m_exact).add(e[2:] if e.startswith("*.") else e)

    # Allowed wildcards (scripts/allowed-wildcards.txt) cover their namespace; never emit a bare suffix
    # (rejected by the full-PSL check below) that one of them expresses.
    for l in read_list(ROOT / "scripts" / "allowed-wildcards.txt"):
        m_wild.add(l[2:])

    def covered(d):
        s = suffixes(d)
        return any(x in m_exact for x in s) or any(x in m_wild for x in s[1:])

    def denied(d):
        return any(x in deny for x in suffixes(d))

    recs = []
    for fn in (sources.wikidata, sources.fdic, sources.cisa):
        recs += fn(cfg, args.refresh)
    log(f"raw records: {len(recs)}")

    # Normalise. Keep the registrable domain, unless the entity lives on a subdomain of a domain that
    # no entity uses as its own site (e.g. a hospital at med.university.edu): then keep that host.
    stats = collections.Counter()
    parsed = []
    for cat, url, src, ent in recs:
        h = host_of(url)
        if not h:
            stats["unparsable/ip/tld"] += 1
            continue
        reg = psl.registrable(h)
        if not reg:
            stats["public suffix"] += 1
            continue
        parsed.append((cat, h, reg, src, ent))
    apex = {reg for _, h, reg, _, _ in parsed if h == reg}
    entities = collections.defaultdict(set)
    cand = []
    for cat, h, reg, src, ent in parsed:
        d = reg if reg in apex else h
        if full_psl.is_suffix(d):
            stats["public suffix (incl. private)"] += 1
            continue
        if denied(d) or denied(reg):
            stats["deny.txt"] += 1
            continue
        if covered(d):
            stats["covered by manual"] += 1
            continue
        entities[d].add(ent)
        cand.append((cat, d, src, ent))
    crowded = {d for d, e in entities.items() if len(e) > cfg["output"]["max_entities_per_domain"]}
    stats["shared by too many entities"] = sum(1 for c in cand if c[1] in crowded)
    cand = [c for c in cand if c[1] not in crowded]
    log(f"dropped: {dict(stats)}; crowded domains: {sorted(crowded)[:20]}")

    # Dedupe across categories by priority; within category by set.
    owner = {}
    for cat, d, _, _ in sorted(cand, key=lambda c: (order.index(c[0]), c[1])):
        owner.setdefault(d, cat)
    final = collections.defaultdict(set)
    for d, cat in owner.items():
        final[cat].add(d)

    if cfg["dns"]["enabled"] and not args.no_dns:
        dead = dns_filter(sorted(owner), cfg, lambda m: log(m))
        for cat in final:
            final[cat] -= dead
        owner = {d: c for d, c in owner.items() if d not in dead}

    # Size guard against the previous generated.txt.
    problems, summary = [], {}
    for cat in order:
        old = set(read_list(lists / cat / "generated.txt"))
        new = final[cat]
        summary[cat] = dict(manual=manual_count.get(cat, 0), before=len(old), after=len(new),
                            added=sorted(new - old), removed=sorted(old - new))
        if old and len(new) < len(old) * (1 - cfg["guard"]["max_shrink"]):
            problems.append(f"{cat}: shrank {len(old)} -> {len(new)}")
        if old and len(new) > len(old) * cfg["guard"]["max_growth_factor"]:
            problems.append(f"{cat}: grew {len(old)} -> {len(new)}")
    if problems and not args.allow_size_change:
        sys.exit("size guard tripped (rerun with --allow-size-change if intended):\n  " + "\n  ".join(problems))

    srcs = {}
    for cat, d, src, ent in cand:
        if owner.get(d) == cat or False:
            srcs.setdefault(cat, set()).add(src.split(":")[0])
    for cat in order:
        used = ", ".join({"wikidata": "Wikidata (CC0)", "fdic": "FDIC BankFind (public domain)",
                          "cisa-dotgov": "CISA dotgov-data (public domain)"}[s] for s in sorted(srcs.get(cat, [])))
        (lists / cat).mkdir(exist_ok=True)
        (lists / cat / "generated.txt").write_text(
            HEADER.format(name=NAMES[cat], cat=cat, srcs=used or "none") + "\n".join(sorted(final[cat])) + "\n")

    out = ROOT / "generated"
    out.mkdir(exist_ok=True)
    seen = set()
    with (out / "provenance.jsonl").open("w") as f:
        for cat, d, src, ent in sorted(cand, key=lambda c: (c[1], c[2], c[3])):
            if owner.get(d) == cat and (d, src, ent) not in seen:
                seen.add((d, src, ent))
                f.write(json.dumps({"domain": d, "category": cat, "source": src, "entity": ent}) + "\n")
    CACHE.mkdir(exist_ok=True)
    (CACHE / "summary.json").write_text(json.dumps(summary, indent=1))
    print(f"{'category':20}{'manual':>8}{'before':>8}{'after':>8}{'+':>7}{'-':>7}")
    for cat, s in summary.items():
        print(f"{cat:20}{s['manual']:>8}{s['before']:>8}{s['after']:>8}{len(s['added']):>7}{len(s['removed']):>7}")


main()
