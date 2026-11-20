#!/usr/bin/env python3
"""Generate the 10 target mcu-p2im campaign configs from docs/P2IM_10_UNPATCHED_MANIFEST.json."""

from __future__ import annotations

import argparse
import json
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_MANIFEST = os.path.join(REPO_ROOT, "docs", "P2IM_10_UNPATCHED_MANIFEST.json")


def expand_path(template: str, p2im_root: str, hoedur_root: str) -> str:
    return (
        template.replace("${P2IM_ROOT}", p2im_root.rstrip("/"))
        .replace("${HOEDUR_EXPERIMENTS_ROOT}", hoedur_root.rstrip("/"))
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate portable configs/m3/*.json for all 10 P2IM targets.")
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--p2im-root", default=os.environ.get("P2IM_ROOT", os.path.expanduser("~/deps/p2im")))
    parser.add_argument("--hoedur-root", default=os.environ.get("HOEDUR_EXPERIMENTS_ROOT", os.path.expanduser("~/deps/hoedur-experiments")))
    parser.add_argument("--work-root", default=os.environ.get("P2IM_WORK_ROOT", "/tmp/fa-p2im"))
    parser.add_argument("--oracle", default=os.path.join(REPO_ROOT, "tools", "p2im_oracle.py"))
    parser.add_argument("--out-dir", default=os.path.join(REPO_ROOT, "configs", "m3"))
    parser.add_argument("--segment-seconds", type=int, default=300)
    parser.add_argument("--fuzz-hard-cap-s", type=int, default=300)
    parser.add_argument("--fuzz-budget-s", type=int, default=None)
    parser.add_argument("--max-execs", type=int, default=None)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--max-segments", type=int, default=2)
    parser.add_argument("--collect-coverage", action="store_true")
    parser.add_argument("--gdb-watch", action="store_true")
    args = parser.parse_args()

    with open(args.manifest, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)

    effective_hard_cap = max(args.fuzz_hard_cap_s, args.fuzz_budget_s or 0)
    if args.segment_seconds > effective_hard_cap:
        print(json.dumps({"ok": False, "error": "segment-seconds exceeds fuzz-hard-cap-s"}), file=sys.stderr)
        return 3

    p2im_root = os.path.abspath(os.path.expanduser(args.p2im_root))
    hoedur_root = os.path.abspath(os.path.expanduser(args.hoedur_root))
    work_root = os.path.abspath(os.path.expanduser(args.work_root))
    oracle_path = os.path.abspath(os.path.expanduser(args.oracle))
    os.makedirs(args.out_dir, exist_ok=True)

    # Check P2IM AFL -c (< 100 byte) limit on longest target slug + longest round model filename.
    max_slug = max((t["target"].lower().replace("_", "-") for t in manifest["targets"]), key=len)
    longest_model_path = os.path.join(work_root, max_slug, "0.seed-random.10", "peripheral_model.json")
    if len(longest_model_path.encode("utf-8")) >= 100:
        print(json.dumps({
            "ok": False,
            "error": "work-root exceeds P2IM AFL -c <100 byte limit",
            "example_path": longest_model_path,
            "bytes": len(longest_model_path.encode("utf-8")),
        }), file=sys.stderr)
        return 3

    written = []
    for entry in manifest["targets"]:
        target = entry["target"]
        slug = target.lower().replace("_", "-")
        elf = expand_path(entry["path"], p2im_root, hoedur_root)
        cfg = {
            "schema_version": 1,
            "target": target,
            "elf": elf,
            "elf_sha256": entry["sha256"],
            "board": entry["board"]["qemu_board"],
            "mcu": entry["board"]["mcu"],
            "work_root": work_root,
            "oracle": oracle_path,
            "runner": "",
            "python": "python3",
            "wsl_distro": None,
            "fuzz_hard_cap_s": effective_hard_cap,
            "segment_seconds": args.segment_seconds,
            "max_segments": args.max_segments,
            "fuzz_budget_s": args.fuzz_budget_s,
            "max_execs": args.max_execs,
            "trial_seed": args.seed,
            "replay_repeat": 3,
            "contrast_budget": 1,
            "max_contrast_replays": 40,
            "auto_forkserver_pc": entry.get("auto_forkserver_pc") or None,
            "gdb_watch": bool(args.gdb_watch),
            "collect_coverage": bool(args.collect_coverage),
        }
        out_path = os.path.join(args.out_dir, f"{slug}.json")
        with open(out_path, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(cfg, handle, indent=2)
            handle.write("\n")
        written.append(out_path)

    print(json.dumps({"ok": True, "configs": len(written), "out_dir": args.out_dir, "work_root": work_root}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
