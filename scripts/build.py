#!/usr/bin/env python3
"""Build dist/: every list, plus meta.json carrying the version and each file's sha256."""
import hashlib, json, pathlib, shutil, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
version = sys.argv[1]


def entries(path):
    return [l for l in path.read_text().splitlines() if l.split("#", 1)[0].strip()] if path.exists() else []


def merged(cat):
    """manual.txt (header and comments kept verbatim) + generated.txt entries, deduplicated."""
    d = ROOT / "lists" / cat
    text = (d / "manual.txt").read_text()
    seen = {l.split("#", 1)[0].strip() for l in entries(d / "manual.txt")}
    extra = []
    for l in entries(d / "generated.txt"):
        h = l.split("#", 1)[0].strip()
        if h not in seen:
            seen.add(h)
            extra.append(h)
    if extra:
        text = text.rstrip("\n") + "\n\n# Generated (see SOURCES.md)\n" + "\n".join(extra) + "\n"
    return text


dist = ROOT / "dist"
shutil.rmtree(dist, ignore_errors=True)
dist.mkdir()
meta = json.loads((ROOT / "meta.json").read_text())
for c in meta["categories"]:
    text = merged(c["id"]).encode()
    (dist / f"{c['id']}.txt").write_bytes(text)
    c["sha256"] = hashlib.sha256(text).hexdigest()
    c["hosts"] = sum(1 for l in text.decode().splitlines() if l.split("#", 1)[0].strip())
meta["version"] = version
(dist / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
print(f"built {version}: {len(meta['categories'])} lists")
