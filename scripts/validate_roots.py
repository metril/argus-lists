#!/usr/bin/env python3
"""Validate roots/roots.json before signing.

    python scripts/validate_roots.py [--previous PATH_TO_PUBLISHED_roots.json]
                                     [--require-approval [--prev-commit SHA]]

Serial must exceed the previously published one (equal is allowed only for an identical file).
--require-approval: if the change against --previous loosens trust (see rootstore.classify), some
commit on main's first-parent history in <prev-commit>..$GITHUB_SHA that touched roots.json must belong
to a merged pull request into main, and $GITHUB_SHA must not loosen the roots.json of that commit
(so one failed release cannot block later, stricter ones). Without --prev-commit only $GITHUB_SHA is
considered. Roots listed in roots/rejected.txt fail validation."""
import argparse, json, os, pathlib, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "generator"))
import rootstore  # noqa: E402


def run(*cmd):
    out = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0:
        raise rootstore.RootError(f"{' '.join(cmd[:3])} failed: {out.stderr.strip()}")
    return out.stdout


def candidates(prev_commit):
    head = os.environ["GITHUB_SHA"]
    shas = ([head] if not prev_commit else
            run("git", "rev-list", "--first-parent", "--reverse", f"{prev_commit}..{head}", "--", "roots/roots.json").split())
    for sha in shas:
        pulls = json.loads(run("gh", "api", f"repos/{os.environ['GITHUB_REPOSITORY']}/commits/{sha}/pulls"))
        if rootstore.merged_pr_ok(pulls):
            yield True, json.loads(run("git", "show", f"{sha}:roots/roots.json"))


ap = argparse.ArgumentParser()
ap.add_argument("--previous", type=pathlib.Path)
ap.add_argument("--require-approval", action="store_true")
ap.add_argument("--prev-commit")
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
    rootstore.validate(doc, prev, rejected=rootstore.load_rejected())
    if a.require_approval and prev_doc is not None:
        if not rootstore.approved(prev_doc, doc, candidates(a.prev_commit)):
            _, added = rootstore.classify(prev_doc, doc)
            raise rootstore.RootError(
                f"this change loosens trust ({len(added)} added roots or constraint/log loosening) and no commit since "
                "the last release comes from a merged pull request into main that approves it")
        print("no unapproved loosening")
except (rootstore.RootError, ValueError, KeyError) as e:
    print(f"::error::roots.json invalid: {e}")
    sys.exit(1)
print(f"roots.json OK: serial {doc['serial']}, {len(doc['roots'])} roots")
