#!/usr/bin/env python3
"""Validate lists/*.txt and meta.json. Errors fail the build; DNS problems only warn."""
import json, re, socket, sys, pathlib
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parent.parent
LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
# Second-level registries that behave like public suffixes (co.uk, com.au, gov.uk ...).
REGISTRY = {"co", "com", "org", "net", "gov", "gouv", "gv", "gob", "edu", "ac", "or", "ne", "mil"}
ALLOW = {l.strip() for l in (ROOT / "scripts" / "allowed-wildcards.txt").read_text().splitlines()
         if l.strip() and not l.startswith("#")}
errors, warnings = [], []


def valid_host(h):
    return 0 < len(h) <= 253 and all(LABEL.match(l) for l in h.split("."))


def public_suffix_like(suffix):
    labels = suffix.split(".")
    if len(labels) == 1:
        return True
    return len(labels) == 2 and labels[0] in REGISTRY and len(labels[1]) == 2


def check_list(path):
    seen = {}
    hosts = []
    for n, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        where = f"{path.name}:{n}"
        if line != line.lower():
            errors.append(f"{where}: {line!r} must be lowercase")
            continue
        if line.startswith("*."):
            suffix = line[2:]
            if not valid_host(suffix):
                errors.append(f"{where}: invalid wildcard {line!r}")
                continue
            if public_suffix_like(suffix) and line not in ALLOW:
                errors.append(f"{where}: {line!r} is a bare TLD / public-suffix wildcard "
                              f"(add it to scripts/allowed-wildcards.txt if intended)")
        elif not valid_host(line):
            errors.append(f"{where}: invalid host {line!r}")
            continue
        elif "." not in line:
            errors.append(f"{where}: {line!r} is a bare TLD")
            continue
        if line in seen:
            errors.append(f"{where}: duplicate of line {seen[line]}")
        seen[line] = n
        hosts.append(line)
    if not hosts:
        errors.append(f"{path.name}: empty list")
    return hosts


def resolves(host):
    try:
        socket.setdefaulttimeout(3)
        socket.getaddrinfo(host, 443)
        return True
    except OSError:
        return False


def main():
    meta = json.loads((ROOT / "meta.json").read_text())
    ids = [c["id"] for c in meta["categories"]]
    for c in meta["categories"]:
        for k in ("id", "name", "description", "default_mode"):
            if not c.get(k):
                errors.append(f"meta.json: category {c.get('id')!r} lacks {k}")
        if c.get("default_mode") not in ("no_decrypt", "full"):
            errors.append(f"meta.json: {c['id']}: default_mode must be no_decrypt or full")
    files = sorted((ROOT / "lists").glob("*.txt"))
    if sorted(p.stem for p in files) != sorted(ids):
        errors.append(f"lists/ and meta.json disagree: {[p.stem for p in files]} vs {ids}")
    exact = []
    for p in files:
        exact += [h for h in check_list(p) if not h.startswith("*.")]
    # DNS: warn only (hosts come and go; a dead name is not an error).
    sample = sorted(set(exact))
    with ThreadPoolExecutor(16) as ex:
        for host, ok in zip(sample, ex.map(resolves, sample)):
            if not ok:
                warnings.append(f"{host} does not resolve")
    for w in warnings:
        print(f"::warning::{w}")
    for e in errors:
        print(f"::error::{e}")
    print(f"{len(files)} lists, {len(sample)} exact hosts checked, {len(warnings)} warnings, {len(errors)} errors")
    sys.exit(1 if errors else 0)


main()
