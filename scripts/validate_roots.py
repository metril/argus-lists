#!/usr/bin/env python3
"""Validate roots/roots.json before signing.

    python scripts/validate_roots.py [--previous PATH_TO_PUBLISHED_roots.json] [--require-approval]

Serial must exceed the previously published one (equal is allowed only for an identical file).
--require-approval: if the change against --previous loosens trust (see rootstore.classify), the
head commit ($GITHUB_SHA in $GITHUB_REPOSITORY) must belong to a merged pull request into main
(checked with `gh api`); otherwise the release fails."""
import argparse, json, os, pathlib, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "generator"))
import rootstore  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--previous", type=pathlib.Path)
ap.add_argument("--require-approval", action="store_true")
ap.add_argument("path", nargs="?", type=pathlib.Path, default=ROOT / "roots" / "roots.json")
a = ap.parse_args()
try:
    doc = json.loads(a.path.read_text())
    prev = None
    prev_doc = None
    if a.previous and a.previous.exists():
        prev_doc = json.loads(a.previous.read_text())
        if a.previous.read_bytes() == a.path.read_bytes():
            prev = doc["serial"] - 1  # unchanged since the last release
        else:
            prev = prev_doc["serial"]
    rootstore.validate(doc, prev)
    if a.require_approval and prev_doc is not None:
        status, added = rootstore.classify(prev_doc, doc)
        if status == "review":
            out = subprocess.run(["gh", "api", f"repos/{os.environ['GITHUB_REPOSITORY']}/commits/{os.environ['GITHUB_SHA']}/pulls"],
                                 capture_output=True, text=True)
            if out.returncode != 0:
                raise rootstore.RootError(f"cannot check the approving pull request: {out.stderr.strip()}")
            if not rootstore.merged_pr_ok(json.loads(out.stdout)):
                raise rootstore.RootError(
                    f"this change loosens trust ({len(added)} added roots or constraint/log loosening) but the head "
                    "commit is not part of a merged pull request into main")
            print("loosening change approved via a merged pull request")
except (rootstore.RootError, ValueError, KeyError) as e:
    print(f"::error::roots.json invalid: {e}")
    sys.exit(1)
print(f"roots.json OK: serial {doc['serial']}, {len(doc['roots'])} roots")
