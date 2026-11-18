#!/usr/bin/env python3
"""Blind-test leak gate for analysis artifacts, L5 candidates, and the compiled prompt pack.

Runs on the host only. Reports `leak_in_prompt: false` only when every scanned surface is free
of truth-set tokens (CVE ids, CWE ids, P2IM Table 5 references).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys

PATTERN = re.compile(r"(CVE-\d{4}-\d+|CWE-\d+|Table\s*5|Table5)", re.IGNORECASE)
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_PROMPT_SOURCE = os.path.join(REPO_ROOT, "dist", "src", "campaign", "mcu-runtime.js")
ALT_PROMPT_SOURCE = os.path.join(REPO_ROOT, "src", "campaign", "mcu-runtime.ts")


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan(text: str, where: str) -> dict:
    hits = [match.group(0) for match in PATTERN.finditer(text)]
    return {"where": where, "bytes": len(text.encode("utf-8")), "hits": hits[:5], "hit_count": len(hits)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan model-facing mcu-p2im surfaces for truth-set token leaks.")
    parser.add_argument("--work-dir", help="Target work directory containing analysis/{sources,paths}.json")
    parser.add_argument("--candidates", help="Path to run out l5-candidates.json")
    parser.add_argument("--prompt-source", default="", help="Path to compiled mcu-runtime.js (or mcu-runtime.ts)")
    parser.add_argument("--extra", action="append", default=[], help="Additional artifact files to scan")
    parser.add_argument("--out", help="Optional output JSON report path")
    args = parser.parse_args()

    artifacts = []
    if args.work_dir:
        artifacts.append(os.path.join(args.work_dir, "analysis", "sources.json"))
        artifacts.append(os.path.join(args.work_dir, "analysis", "paths.json"))
    if args.candidates:
        artifacts.append(args.candidates)
    artifacts.extend(args.extra)

    surfaces = []
    for path in artifacts:
        if not os.path.exists(path):
            surfaces.append({"where": path, "missing": True, "hit_count": None})
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            surfaces.append(scan(handle.read(), path))

    prompt_path = args.prompt_source
    if not prompt_path:
        prompt_path = DEFAULT_PROMPT_SOURCE if os.path.exists(DEFAULT_PROMPT_SOURCE) else ALT_PROMPT_SOURCE
    if os.path.exists(prompt_path):
        with open(prompt_path, "r", encoding="utf-8", errors="replace") as handle:
            surfaces.append(scan(handle.read(), prompt_path + "#prompts"))
    else:
        surfaces.append({"where": prompt_path, "missing": True, "hit_count": None})

    total_hits = sum(item.get("hit_count") or 0 for item in surfaces)
    missing = [item["where"] for item in surfaces if item.get("missing")]
    result = {
        "schema": "mcu-p2im/leak-check-0.2",
        "leak_in_prompt": total_hits > 0,
        "pattern": PATTERN.pattern,
        "surfaces": surfaces,
        "missing": missing,
        "prompt_pack_sha256": sha256_file(prompt_path) if os.path.exists(prompt_path) else None,
    }
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(result, handle, indent=2)
            handle.write("\n")
    print(json.dumps({
        "leak_in_prompt": result["leak_in_prompt"],
        "total_hits": total_hits,
        "surfaces": len(surfaces),
        "missing": missing,
    }, indent=2))
    return 0 if (total_hits == 0 and not missing) else 1


if __name__ == "__main__":
    sys.exit(main())
