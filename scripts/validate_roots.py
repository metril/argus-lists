#!/usr/bin/env python3
"""Validate roots/roots.json before signing.

    python scripts/validate_roots.py [--previous PATH_TO_PUBLISHED_roots.json]

Serial must exceed the previously published one (equal is allowed only for an identical file)."""
import argparse, json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "generator"))
import rootstore  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--previous", type=pathlib.Path)
ap.add_argument("path", nargs="?", type=pathlib.Path, default=ROOT / "roots" / "roots.json")
a = ap.parse_args()
try:
    doc = json.loads(a.path.read_text())
    prev = None
    if a.previous and a.previous.exists():
        if a.previous.read_bytes() == a.path.read_bytes():
            prev = doc["serial"] - 1  # unchanged since the last release
        else:
            prev = json.loads(a.previous.read_text())["serial"]
    rootstore.validate(doc, prev)
except (rootstore.RootError, ValueError, KeyError) as e:
    print(f"::error::roots.json invalid: {e}")
    sys.exit(1)
print(f"roots.json OK: serial {doc['serial']}, {len(doc['roots'])} roots")
