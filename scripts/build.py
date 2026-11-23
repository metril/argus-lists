#!/usr/bin/env python3
"""Build dist/: every list, plus meta.json carrying the version and each file's sha256."""
import hashlib, json, pathlib, shutil, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
version = sys.argv[1]
dist = ROOT / "dist"
shutil.rmtree(dist, ignore_errors=True)
dist.mkdir()
meta = json.loads((ROOT / "meta.json").read_text())
for c in meta["categories"]:
    text = (ROOT / "lists" / f"{c['id']}.txt").read_bytes()
    (dist / f"{c['id']}.txt").write_bytes(text)
    c["sha256"] = hashlib.sha256(text).hexdigest()
    c["hosts"] = sum(1 for l in text.decode().splitlines() if l.split("#", 1)[0].strip())
meta["version"] = version
(dist / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
print(f"built {version}: {len(meta['categories'])} lists")
