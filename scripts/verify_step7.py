#!/usr/bin/env python3
"""Read-only health verifier for manual Step 7 p2im_oracle.py workspaces.

Inspects meta.json, ELF SHA256, QEMU shim & target binary executability, inputs/,
smoke.json, me-round.json, segments/*.json, analysis/paths.json, crashes/replays/contrast,
and optionally checks /proc/*/cmdline scoped strictly to each work_root.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys

DEFAULT_WORK_ROOT = os.environ.get("P2IM_WORK_ROOT", "/tmp/fa-p2im")


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json_safe(path: str):
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return json.load(handle)


def parse_shim_target(shim_path: str) -> tuple[bool, str | None, bool]:
    if not os.path.isfile(shim_path):
        return False, None, False
    with open(shim_path, "r", encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    has_unset = "unset LD_LIBRARY_PATH" in text
    match = re.search(r'^exec\s+"([^"]+)"\s+"\$@"\s*$', text, re.M)
    target = match.group(1) if match else None
    target_ok = bool(target and os.path.isfile(target) and os.access(target, os.X_OK))
    return has_unset, target, target_ok


def find_scoped_procs(work_root: str) -> list[dict]:
    """Return processes in /proc whose cmdline references this exact work_root."""
    marker = os.path.abspath(work_root).encode("utf-8")
    me = os.getpid()
    found: list[dict] = []
    if not os.path.isdir("/proc"):
        return found
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid == me:
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as handle:
                raw = handle.read()
        except OSError:
            continue
        if marker not in raw:
            continue
        cmd = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        found.append({"pid": pid, "cmdline": cmd[:240]})
    return found


def inspect_target(work_root: str, slug: str) -> dict:
    work_dir = os.path.join(work_root, slug)
    meta_path = os.path.join(work_dir, "meta.json")
    meta = read_json_safe(meta_path)
    issues: list[str] = []
    notes: list[str] = []

    if not isinstance(meta, dict):
        return {
            "slug": slug,
            "work_dir": work_dir,
            "ok": False,
            "issues": ["missing or unreadable meta.json"],
            "notes": [],
        }

    target_name = meta.get("target") or slug
    elf_info = meta.get("elf") or {}
    elf_path = elf_info.get("path") or os.path.join(work_dir, f"{target_name}.elf")
    expected_sha = elf_info.get("sha256")
    actual_sha = sha256_file(elf_path) if os.path.isfile(elf_path) else None
    elf_sha_ok = bool(expected_sha and actual_sha == expected_sha)
    if not elf_sha_ok:
        issues.append(f"ELF SHA256 mismatch or missing ({elf_path})")

    longest_model_path = os.path.join(work_dir, "0.seed-random.10", "peripheral_model.json")
    path_bytes = len(longest_model_path.encode("utf-8"))
    if path_bytes >= 100:
        issues.append(f"longest model path >= 100 bytes ({path_bytes}B)")

    shim_path = os.path.join(work_root, "bin", "qemu-system-gnuarmeclipse")
    shim_exec = os.path.isfile(shim_path) and os.access(shim_path, os.X_OK)
    shim_unset, qemu_target, qemu_ok = parse_shim_target(shim_path)
    if not shim_exec or not shim_unset or not qemu_ok:
        issues.append(f"QEMU shim/binary unhealthy (shim_exec={shim_exec}, unset={shim_unset}, qemu_ok={qemu_ok})")

    inputs_dir = os.path.join(work_dir, "inputs")
    input_names = sorted(os.listdir(inputs_dir)) if os.path.isdir(inputs_dir) else []
    has_random = "seed-random" in input_names
    has_short = "seed-short" in input_names
    if not (has_random and has_short):
        notes.append(f"inputs incomplete: {input_names}")

    evidence_dir = os.path.join(work_dir, "evidence")
    smoke = read_json_safe(os.path.join(evidence_dir, "smoke.json"))
    smoke_log_path = os.path.join(evidence_dir, "smoke.log")
    smoke_forkserver_seen = False
    if os.path.isfile(smoke_log_path):
        with open(smoke_log_path, "r", encoding="utf-8", errors="replace") as handle:
            smoke_forkserver_seen = "start up afl forkserver!" in handle.read()
    if isinstance(smoke, dict):
        if smoke.get("outcome") == "error" or smoke.get("exit_code") in (126, 127):
            issues.append(f"smoke failed (outcome={smoke.get('outcome')}, rc={smoke.get('exit_code')})")
        if meta.get("auto_forkserver_pc") and not smoke_forkserver_seen:
            issues.append("auto_forkserver_pc configured but smoke.log lacks forkserver marker")

    me_round = read_json_safe(os.path.join(evidence_dir, "me-round.json"))
    me_summary = None
    if isinstance(me_round, dict):
        model = me_round.get("model") or {}
        me_summary = {
            "round": me_round.get("round"),
            "exit_code": me_round.get("exit_code"),
            "peripheral_count": model.get("peripheral_count", 0),
            "dr_count": len(model.get("dr_registers") or []),
        }
        if me_summary["peripheral_count"] == 0 or me_summary["dr_count"] == 0:
            issues.append("me round produced 0 peripherals or 0 DR registers")

    seg_dir = os.path.join(work_dir, "segments")
    segments = []
    if os.path.isdir(seg_dir):
        for fname in sorted(os.listdir(seg_dir)):
            if re.match(r"^s\d+\.json$", fname):
                seg = read_json_safe(os.path.join(seg_dir, fname))
                if not isinstance(seg, dict):
                    continue
                seg_name = seg.get("segment") or fname[:-5]
                fuzz_log = os.path.join(evidence_dir, f"fuzz-{seg_name}.log")
                program_abort = False
                if os.path.isfile(fuzz_log):
                    with open(fuzz_log, "r", encoding="utf-8", errors="replace") as handle:
                        program_abort = "PROGRAM ABORT" in handle.read()
                if program_abort:
                    issues.append(f"{seg_name}: PROGRAM ABORT in fuzz log")
                if int(seg.get("execs_done") or 0) == 0:
                    issues.append(f"{seg_name}: execs_done=0")
                segments.append({
                    "segment": seg_name,
                    "duration_s": seg.get("duration_s", 0),
                    "execs_done": seg.get("execs_done", 0),
                    "paths_total": seg.get("paths_total", 0),
                    "crash_files": seg.get("crash_files", 0),
                    "proposed_seeds": seg.get("proposed_seeds", 0),
                    "inherit_queue": seg.get("inherit_queue"),
                    "inherited_queue_files": seg.get("inherited_queue_files", 0),
                    "program_abort": program_abort,
                })

    paths_doc = read_json_safe(os.path.join(work_dir, "analysis", "paths.json"))
    paths_summary = None
    if isinstance(paths_doc, dict):
        shared = paths_doc.get("shared_globals") or []
        indexed_reach_items = sum(len(g.get("indexed_reach") or []) for g in shared if isinstance(g, dict))
        bad_call_edges = sum(
            1 for g in shared if isinstance(g, dict) and (
                g.get("call_edge") is not False
                or any(r.get("call_edge") is not False for r in (g.get("indexed_reach") or []) if isinstance(r, dict))
            )
        )
        if bad_call_edges > 0:
            issues.append(f"paths.json has {bad_call_edges} shared_globals entries without call_edge=False")
        paths_summary = {
            "counts": paths_doc.get("counts") or {},
            "indexed_reach_links": indexed_reach_items,
            "call_edge_all_false": bad_call_edges == 0,
        }

    crash_index = read_json_safe(os.path.join(evidence_dir, "crash-index.json"))
    replays_path = os.path.join(evidence_dir, "replays.jsonl")
    replay_rows = []
    if os.path.isfile(replays_path):
        with open(replays_path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.strip():
                    try:
                        replay_rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    contrast = read_json_safe(os.path.join(evidence_dir, "contrast.json"))

    raw_crashes = sum(int(s.get("crash_files") or 0) for s in segments)
    if segments and raw_crashes == 0:
        notes.append("0 crashes in recorded segments (normal for short 60s demo; extend window or inspect Step 8)")

    return {
        "target": target_name,
        "slug": slug,
        "work_dir": work_dir,
        "ok": len(issues) == 0,
        "issues": issues,
        "notes": notes,
        "elf_sha256_ok": elf_sha_ok,
        "longest_model_path_bytes": path_bytes,
        "qemu": {"shim_exec": shim_exec, "unset_ld": shim_unset, "target": qemu_target, "target_ok": qemu_ok},
        "inputs": {"has_random": has_random, "has_short": has_short, "count": len(input_names)},
        "smoke": {
            "present": isinstance(smoke, dict),
            "outcome": smoke.get("outcome") if isinstance(smoke, dict) else None,
            "exit_code": smoke.get("exit_code") if isinstance(smoke, dict) else None,
            "forkserver_seen": smoke_forkserver_seen,
        },
        "me": me_summary,
        "segments": segments,
        "paths": paths_summary,
        "crashes": {
            "raw_files": crash_index.get("raw_files") if isinstance(crash_index, dict) else raw_crashes,
            "unique": crash_index.get("unique") if isinstance(crash_index, dict) else None,
            "replays_logged": len(replay_rows),
            "contrast_confirmed": contrast.get("contrast_confirmed") if isinstance(contrast, dict) else None,
        },
    }


def verify_work_roots(work_roots: list[str], target_filter: str = "", check_procs: bool = False) -> dict:
    reports: list[dict] = []
    procs: list[dict] = []
    want = target_filter.lower().replace("_", "-") if target_filter else ""
    for raw_root in work_roots:
        root = os.path.abspath(os.path.expanduser(raw_root))
        if check_procs:
            for row in find_scoped_procs(root):
                row["work_root"] = root
                procs.append(row)
        if not os.path.isdir(root):
            reports.append({
                "slug": want or "(root)",
                "work_dir": root,
                "ok": False,
                "issues": [f"work_root does not exist: {root}"],
                "notes": [],
            })
            continue
        slugs = []
        for entry in sorted(os.listdir(root)):
            if entry == "bin":
                continue
            if os.path.isfile(os.path.join(root, entry, "meta.json")):
                if not want or entry == want:
                    slugs.append(entry)
        if not slugs:
            reports.append({
                "slug": want or "(none)",
                "work_dir": root,
                "ok": False,
                "issues": [f"no prepared targets found under {root}"],
                "notes": [],
            })
            continue
        for slug in slugs:
            reports.append(inspect_target(root, slug))
    if procs:
        for report in reports:
            report.setdefault("notes", [])
    overall_ok = bool(reports) and all(r.get("ok") for r in reports) and not procs
    return {"schema": "mcu-p2im/verify-step7-0.1", "ok": overall_ok, "targets": reports, "scoped_processes": procs}


def format_table(summary: dict) -> str:
    lines = [
        "TARGET            SHA  QEMU  SMOKE      ME(P/DR)   SEGMENTS(execs/paths/crash)          SLICE(idx/no-call)  L3/L4      STATUS",
        "-" * 118,
    ]
    for row in summary["targets"]:
        name = str(row.get("target") or row.get("slug"))[:16]
        if "qemu" not in row:
            lines.append(f"{name:17s} FAIL: {'; '.join(row.get('issues') or [])}")
            continue
        sha_s = "OK" if row["elf_sha256_ok"] else "BAD"
        qemu_s = "OK" if row["qemu"]["target_ok"] else "BAD"
        sm = row["smoke"]
        smoke_s = f"{sm['outcome']}({sm['exit_code']})" if sm["present"] else "-"
        me = row["me"]
        me_s = f"{me['peripheral_count']}/{me['dr_count']}" if me else "-"
        segs = row["segments"]
        seg_s = ",".join(
            f"{s['segment']}:{s['execs_done']}/{s['paths_total']}/{s['crash_files']}"
            + (f"+q{s['inherited_queue_files']}" if s.get("inherited_queue_files") else "")
            + (f"+p{s['proposed_seeds']}" if s.get("proposed_seeds") else "")
            for s in segs
        ) or "-"
        pt = row["paths"]
        slice_s = f"{pt['indexed_reach_links']}/{'OK' if pt['call_edge_all_false'] else 'BAD'}" if pt else "-"
        cr = row["crashes"]
        l34_s = f"r{cr['replays_logged']}/c={cr['contrast_confirmed']}"
        st_s = "PASS" if row["ok"] else "FAIL"
        lines.append(
            f"{name:17s} {sha_s:4s} {qemu_s:5s} {smoke_s:10s} {me_s:10s} {seg_s:36s} {slice_s:19s} {l34_s:10s} {st_s}"
        )
        for issue in row.get("issues") or []:
            lines.append(f"  [ISSUE] {issue}")
        for note in row.get("notes") or []:
            lines.append(f"  [NOTE]  {note}")
    if summary["scoped_processes"]:
        lines.append("[PROCS] Active processes matched to checked work_root(s):")
        for proc in summary["scoped_processes"]:
            lines.append(f"  pid={proc['pid']} {proc['cmdline']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only Step 7 verification dashboard for p2im_oracle workspaces.")
    parser.add_argument("--work-root", action="append", default=[], help="Work root directory (repeatable; defaults to $P2IM_WORK_ROOT or /tmp/fa-p2im)")
    parser.add_argument("--target", default="", help="Optional target name filter (e.g. PLC)")
    parser.add_argument("--check-procs", action="store_true", help="Check /proc for lingering processes scoped strictly to --work-root")
    parser.add_argument("--json", action="store_true", help="Print JSON output instead of summary table")
    args = parser.parse_args(argv)

    roots = args.work_root or [DEFAULT_WORK_ROOT]
    summary = verify_work_roots(roots, target_filter=args.target, check_procs=args.check_procs)
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(format_table(summary))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
