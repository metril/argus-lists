#!/usr/bin/env python3
"""Validate lists/*.txt, meta.json and catalog/*.json. Errors fail the build; DNS problems only warn.

--net checks the catalog URLs over the network (and skips the list checks); used by the scheduled job."""
import json, re, socket, sys, pathlib
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "generator"))
sys.path.insert(0, str(ROOT / "scripts"))
import catalog  # noqa: E402
from common import PSL, LABEL  # noqa: E402  (ASCII/punycode hostname labels)

# Argus skips single-label names, anything that is itself a public suffix (full PSL, private section
# included) and non-ASCII/punycode names; scripts/allowed-wildcards.txt exempts listed *.suffix lines.
FULL_PSL = PSL(ROOT / "generator" / "data" / "public_suffix_list.dat", private=True)
ALLOW = {l.strip() for l in (ROOT / "scripts" / "allowed-wildcards.txt").read_text().splitlines()
         if l.strip() and not l.startswith("#")}
errors, warnings = [], []


def valid_host(h):
    return 0 < len(h) <= 253 and all(LABEL.match(l) for l in h.split("."))


def check_list(path, allow_empty=False):
    seen = {}
    hosts = []
    for n, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        where = f"{path.parent.name}/{path.name}:{n}"
        if line != line.lower():
            errors.append(f"{where}: {line!r} must be lowercase")
            continue
        if line.startswith("*."):
            suffix = line[2:]
            if not valid_host(suffix):
                errors.append(f"{where}: invalid wildcard {line!r}")
                continue
            if FULL_PSL.is_suffix(suffix) and line not in ALLOW:
                errors.append(f"{where}: {line!r} is a bare TLD / public-suffix wildcard "
                              f"(add it to scripts/allowed-wildcards.txt if intended)")
        elif not valid_host(line):
            errors.append(f"{where}: invalid host {line!r}")
            continue
        elif FULL_PSL.is_suffix(line):
            errors.append(f"{where}: {line!r} is a single label or public suffix (Argus skips it)")
            continue
        if line in seen:
            errors.append(f"{where}: duplicate of line {seen[line]}")
        seen[line] = n
        hosts.append(line)
    if not hosts and not allow_empty:
        errors.append(f"{path.parent.name}/{path.name}: empty list")
    return hosts


def resolves(host):
    try:
        socket.setdefaulttimeout(3)
        socket.getaddrinfo(host, 443)
        return True
    except OSError:
        return False


def main_net():
    warns = []
    docs, errs = catalog.load()
    if not errs:
        errs = catalog.check_net(docs, warns=warns)
    for w in warns:
        print(f"::warning::{w}")
    for e in errs:
        print(f"::error::{e}")
    print(f"{sum(len(d.get('entries', [])) for d in docs.values())} catalog entries checked, {len(errs)} errors")
    sys.exit(1 if errs else 0)


def main():
    if "--net" in sys.argv[1:]:
        main_net()
    meta = json.loads((ROOT / "meta.json").read_text())
    ids = [c["id"] for c in meta["categories"]]
    for c in meta["categories"]:
        for k in ("id", "name", "description", "default_mode"):
            if not c.get(k):
                errors.append(f"meta.json: category {c.get('id')!r} lacks {k}")
        if c.get("default_mode") not in ("no_decrypt", "full"):
            errors.append(f"meta.json: {c['id']}: default_mode must be no_decrypt or full")
    dirs = sorted(p for p in (ROOT / "lists").iterdir() if p.is_dir())
    if sorted(p.name for p in dirs) != sorted(ids):
        errors.append(f"lists/ and meta.json disagree: {[p.name for p in dirs]} vs {ids}")
    files = []
    exact = []
    for d in dirs:
        if not (d / "manual.txt").exists():
            errors.append(f"{d.name}: manual.txt missing")
        extra = {p.name for p in d.iterdir()} - {"manual.txt", "generated.txt"}
        if extra:
            errors.append(f"{d.name}: unexpected files {sorted(extra)}")
        merged = {}
        for name in ("manual.txt", "generated.txt"):
            p = d / name
            if not p.exists():
                continue
            files.append(p)
            for h in check_list(p, allow_empty=name == "generated.txt"):
                if h in merged:
                    errors.append(f"{d.name}/{name}: {h!r} already in {merged[h]}")
                merged[h] = name
        # DNS only for hand-curated hosts; generated ones are checked (cached) by the generator.
        exact += [h for h, n in merged.items() if n == "manual.txt" and not h.startswith("*.")]
    # DNS: warn only (hosts come and go; a dead name is not an error).
    sample = sorted(set(exact))
    with ThreadPoolExecutor(16) as ex:
        for host, ok in zip(sample, ex.map(resolves, sample)):
            if not ok:
                warnings.append(f"{host} does not resolve")
    errors.extend(catalog.load()[1])
    for w in warnings:
        print(f"::warning::{w}")
    for e in errors:
        print(f"::error::{e}")
    print(f"{len(files)} lists, {len(sample)} exact hosts checked, {len(warnings)} warnings, {len(errors)} errors")
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
