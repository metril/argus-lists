#!/usr/bin/env python3
"""Render .cache/summary.json (written by generate.py) as a PR body: counts table and sample diffs."""
import json, pathlib, random

root = pathlib.Path(__file__).resolve().parent.parent
s = json.loads((root / ".cache" / "summary.json").read_text())
rnd = random.Random(0)
out = ["Automated refresh of `lists/*/generated.txt` (see SOURCES.md). Review the sample diffs; "
       "`generated/provenance.jsonl` has the source of every domain.", "",
       "| category | manual | generated before | generated after | added | removed | published total |",
       "|---|---:|---:|---:|---:|---:|---:|"]
for c, v in s.items():
    out.append(f"| {c} | {v['manual']} | {v['before']} | {v['after']} | +{len(v['added'])} | -{len(v['removed'])} "
               f"| {v['manual'] + v['after']} |")
for c, v in s.items():
    for k, sign in (("added", "+"), ("removed", "-")):
        if v[k]:
            sample = rnd.sample(v[k], min(15, len(v[k])))
            out += ["", f"<details><summary>{c}: sample of {k} ({len(v[k])})</summary>", "", "```diff"]
            out += [f"{sign}{d}" for d in sorted(sample)] + ["```", "</details>"]
print("\n".join(out))
