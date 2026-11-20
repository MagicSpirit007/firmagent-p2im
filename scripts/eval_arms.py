#!/usr/bin/env python3
"""Post-hoc offline evaluator and three-arm comparator (B0 vs offline vs real).

Host-only offline tool. Reads completed run directories (`score-owned.json`, `state.json`,
`account.json`, `l5-candidates.json`, `l5-candidates-bare.json`, optional `bbl-coverage.json`)
and optionally invokes `scripts/score_l5.py` in a separate process when `--notes` is supplied.

Strictly separates:
1. Stock P2IM bare crash attribution (`bare_without_sram_slice`) vs
   B0 + offline shared-SRAM slice attribution (`with_shared_sram_slice`),
2. Equal end-to-end wall clock vs equal `execs_done` budget views,
3. Raw per-run values alongside median and min/max spread across multi-seed trials.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCORE_L5 = os.path.join(REPO_ROOT, "scripts", "score_l5.py")
ORACLE = os.path.join(REPO_ROOT, "tools", "p2im_oracle.py")


def read_json(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return json.load(handle)


def write_json(path: str, payload) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def run_score_l5_subprocess(notes: str, candidates_path: str, target: str, paper_text: str | None = None) -> dict:
    cmd = [sys.executable, SCORE_L5, "--notes", notes, "--candidates", candidates_path, "--target", target, "--summary-only"]
    if paper_text:
        cmd.extend(["--paper-text", paper_text])
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"score_l5.py failed ({proc.returncode}): {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def summarize_l5_counts(l5_payload: dict | None) -> dict:
    if not isinstance(l5_payload, dict):
        return {
            "present": False,
            "candidates": 0,
            "known_p2im_bug_direct": 0,
            "known_p2im_bug_downstream": 0,
            "unmatched_verified_candidate": 0,
            "matched_total": 0,
            "matched_bug_ids": [],
            "candidate_hits_total": 0,
        }
    counts = l5_payload.get("counts") or {}
    cand_direct = int(counts.get("known_p2im_bug_direct") or 0)
    cand_downstream = int(counts.get("known_p2im_bug_downstream") or 0)
    cand_unmatched = int(counts.get("unmatched_verified_candidate") or 0)
    unique_bugs = l5_payload.get("unique_bugs")
    if isinstance(unique_bugs, dict):
        direct = int(unique_bugs.get("unique_known_bugs_direct") or 0)
        downstream = int(unique_bugs.get("unique_known_bugs_downstream") or 0)
        matched_total = int(
            unique_bugs.get("unique_known_bugs_total")
            if unique_bugs.get("unique_known_bugs_total") is not None
            else (direct + downstream)
        )
        unmatched = int(
            unique_bugs.get("unique_unmatched_fingerprints")
            if unique_bugs.get("unique_unmatched_fingerprints") is not None
            else cand_unmatched
        )
        matched_bug_ids = list(unique_bugs.get("matched_bug_ids") or [])
    else:
        direct = cand_direct
        downstream = cand_downstream
        matched_total = cand_direct + cand_downstream
        unmatched = cand_unmatched
        matched_bug_ids = []
    return {
        "present": True,
        "candidates": int(counts.get("candidates") or 0),
        "known_p2im_bug_direct": direct,
        "known_p2im_bug_downstream": downstream,
        "unmatched_verified_candidate": unmatched,
        "matched_total": matched_total,
        "matched_bug_ids": matched_bug_ids,
        "candidate_hits_total": cand_direct + cand_downstream,
    }


def _safe_rate(numerator: float, denominator: float, scale: float) -> float | None:
    if denominator <= 0:
        return None
    return round((numerator / denominator) * scale, 4)


def score_arm(
    run_dir: str,
    notes: str | None = None,
    paper_text: str | None = None,
    bbl_coverage_path: str | None = None,
    run_bbl_coverage: bool = False,
    work_root_override: str | None = None,
    tools_root_override: str | None = None,
    arm_label: str | None = None,
) -> dict:
    run_abs = os.path.abspath(run_dir)
    state_path = os.path.join(run_abs, "state.json")
    score_path = os.path.join(run_abs, "score-owned.json")
    if not os.path.isfile(score_path):
        raise FileNotFoundError(f"missing score-owned.json under {run_abs}")
    score_owned = read_json(score_path)
    state = read_json(state_path) if os.path.isfile(state_path) else {}
    account = read_json(os.path.join(run_abs, "account.json")) if os.path.isfile(os.path.join(run_abs, "account.json")) else {}

    target = str(score_owned.get("target") or state.get("target") or "")
    elf_sha256 = str(score_owned.get("elf_sha256") or state.get("elf_sha256") or "")
    mode = str(score_owned.get("mode") or state.get("mode") or "unknown")
    work_root = work_root_override or score_owned.get("work_root") or state.get("work_root") or ""
    work_dir = score_owned.get("work_dir") or state.get("work_dir") or (
        os.path.join(work_root, target.lower().replace("_", "-")) if work_root and target else ""
    )

    if run_bbl_coverage:
        if not work_root or not target:
            raise ValueError("cannot run bbl-coverage without work_root and target")
        cmd = [sys.executable, ORACLE, "bbl-coverage", "--target", target, "--work-root", work_root]
        if tools_root_override:
            cmd.extend(["--tools-root", tools_root_override])
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"p2im_oracle.py bbl-coverage failed ({proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}")

    cov_path = bbl_coverage_path or (os.path.join(work_dir, "analysis", "bbl-coverage.json") if work_dir else "")
    cov_doc = read_json(cov_path) if cov_path and os.path.isfile(cov_path) else None

    segments = score_owned.get("segments") or state.get("segments") or []
    total_execs_done = int(
        score_owned.get("total_execs_done")
        if score_owned.get("total_execs_done") is not None
        else sum(int(s.get("execs_done") or 0) for s in segments)
    )

    stage_wall = score_owned.get("stage_wall_ms") or state.get("stage_wall_ms") or {}
    wall_clock = score_owned.get("wall_clock") or {}
    eval_cov_wall_ms = int(wall_clock.get("eval_coverage_wall_ms") or 0)
    e2e_wall_ms = int(
        wall_clock.get("end_to_end_wall_ms")
        or (state.get("totals") or {}).get("wall_ms")
        or account.get("active_ms")
        or round(sum(float(s.get("duration_s") or 0.0) * 1000 for s in segments))
    )
    fuzz_wall_ms = int(
        wall_clock.get("fuzz_wall_ms")
        if wall_clock.get("fuzz_wall_ms") is not None
        else (
            int(stage_wall.get("discover_seg1") or 0) + int(stage_wall.get("discover_seg2") or 0)
            if stage_wall
            else round(sum(float(s.get("duration_s") or 0.0) * 1000 for s in segments))
        )
    )
    slice_wall_ms = int(wall_clock.get("slice_wall_ms") or stage_wall.get("slice") or 0)
    llm_wall_ms = int(wall_clock.get("llm_wall_ms") or stage_wall.get("analyze_and_propose") or 0)
    triage_wall_ms = int(wall_clock.get("triage_wall_ms") or stage_wall.get("triage_and_verify") or 0)
    discovery_guidance_wall_ms = int(
        wall_clock.get("discovery_guidance_wall_ms")
        if wall_clock.get("discovery_guidance_wall_ms") is not None
        else (fuzz_wall_ms if mode == "b0" else (fuzz_wall_ms + slice_wall_ms + llm_wall_ms))
    )
    trial_seed = score_owned.get("trial_seed") if score_owned.get("trial_seed") is not None else state.get("trial_seed")
    cumulative_cost = score_owned.get("cumulative_cost") if isinstance(score_owned.get("cumulative_cost"), dict) else None

    cand_path = os.path.join(run_abs, "l5-candidates.json")
    bare_path = os.path.join(run_abs, "l5-candidates-bare.json")
    l5_with_slice = None
    l5_bare = None
    if notes:
        if os.path.isfile(cand_path):
            l5_with_slice = run_score_l5_subprocess(notes, cand_path, target, paper_text=paper_text)
        if os.path.isfile(bare_path):
            l5_bare = run_score_l5_subprocess(notes, bare_path, target, paper_text=paper_text)
    else:
        existing_l5 = os.path.join(run_abs, "l5.json")
        if os.path.isfile(existing_l5):
            l5_with_slice = read_json(existing_l5)

    slice_summary = summarize_l5_counts(l5_with_slice)
    if l5_bare is not None:
        bare_summary = summarize_l5_counts(l5_bare)
    elif isinstance(l5_with_slice, dict) and isinstance(l5_with_slice.get("attribution_split"), dict):
        split_bare = l5_with_slice["attribution_split"].get("bare_without_sram_slice") or {}
        bare_ub = split_bare.get("unique_bugs") if isinstance(split_bare.get("unique_bugs"), dict) else None
        bare_summary = {
            "present": True,
            "candidates": int(split_bare.get("candidates") or 0),
            "known_p2im_bug_direct": int(bare_ub.get("unique_known_bugs_direct") if bare_ub else (split_bare.get("known_p2im_bug_direct") or 0)),
            "known_p2im_bug_downstream": 0,
            "unmatched_verified_candidate": int(bare_ub.get("unique_unmatched_fingerprints") if bare_ub else (split_bare.get("unmatched_verified_candidate") or 0)),
            "matched_total": int(bare_ub.get("unique_known_bugs_total") if bare_ub else (split_bare.get("matched_total") or 0)),
            "matched_bug_ids": list(bare_ub.get("matched_bug_ids") or []) if bare_ub else [],
            "candidate_hits_total": int(split_bare.get("matched_total") or 0),
        }
    elif slice_summary["present"]:
        bare_summary = {
            "present": True,
            "candidates": slice_summary["candidates"],
            "known_p2im_bug_direct": slice_summary["known_p2im_bug_direct"],
            "known_p2im_bug_downstream": 0,
            "unmatched_verified_candidate": max(0, slice_summary["candidates"] - slice_summary["known_p2im_bug_direct"]),
            "matched_total": slice_summary["known_p2im_bug_direct"],
            "matched_bug_ids": [],
            "candidate_hits_total": slice_summary["known_p2im_bug_direct"],
        }
    else:
        bare_summary = summarize_l5_counts(None)

    net_gain = max(0, slice_summary["matched_total"] - bare_summary["matched_total"]) if slice_summary["present"] else 0

    layers = score_owned.get("layers") or state.get("layers") or {"l1": 0, "l2": 0, "l3": 0, "l4": 0}
    model_diag = score_owned.get("model_diagnostics") or state.get("model_diagnostics") or {}
    warnings = list(score_owned.get("warnings") or state.get("warnings") or [])

    union_bbls = None
    union_funcs = None
    cov_segments = {}
    bbl_set_path = None
    if isinstance(cov_doc, dict):
        union = cov_doc.get("union") or {}
        union_bbls = int(union.get("unique_bbls") or 0)
        union_funcs = int(union.get("unique_functions") or 0)
        cov_segments = cov_doc.get("segments") or {}
        if isinstance(cov_doc.get("unique_bbls_list"), list):
            bbl_set_path = cov_path
    elif isinstance(score_owned.get("coverage"), dict):
        union = score_owned["coverage"].get("union") or {}
        if "unique_bbls" in union:
            union_bbls = int(union.get("unique_bbls") or 0)
            union_funcs = int(union.get("unique_functions") or 0)
            cov_segments = score_owned["coverage"].get("segments") or {}

    e2e_minutes = e2e_wall_ms / 60000.0 if e2e_wall_ms > 0 else 0.0
    l4 = int(layers.get("l4") or 0)

    effective_requests = int(cumulative_cost["total_model_requests"]) if cumulative_cost and cumulative_cost.get("total_model_requests") is not None else int(score_owned.get("model_requests") or 0)
    effective_tokens = int(cumulative_cost["total_tokens"]) if cumulative_cost and cumulative_cost.get("total_tokens") is not None else int(score_owned.get("tokens") or 0)

    return {
        "schema": "mcu-p2im/arm-summary-0.2",
        "run_dir": run_abs,
        "identity": {
            "target": target,
            "elf_sha256": elf_sha256,
            "mode": mode,
            "arm_label": arm_label or mode,
            "trial_seed": trial_seed,
            "status": state.get("status") or "completed",
            "work_root": work_root,
            "work_dir": work_dir,
        },
        "wall_clock": {
            "end_to_end_wall_ms": e2e_wall_ms,
            "discovery_guidance_wall_ms": discovery_guidance_wall_ms,
            "fuzz_wall_ms": fuzz_wall_ms,
            "slice_wall_ms": slice_wall_ms,
            "llm_wall_ms": llm_wall_ms,
            "triage_wall_ms": triage_wall_ms,
            "eval_coverage_wall_ms": eval_cov_wall_ms,
        },
        "target_executions": {
            "total_execs_done": total_execs_done,
            "segments": segments,
        },
        "model_cost": {
            "provider": model_diag.get("provider"),
            "model": model_diag.get("model"),
            "thinking": model_diag.get("thinking"),
            "model_requests": effective_requests,
            "tokens": effective_tokens,
            "attempt_model_requests": int(score_owned.get("model_requests") or 0),
            "attempt_tokens": int(score_owned.get("tokens") or 0),
            "cumulative_cost": cumulative_cost,
            "cost_usd": None,
            "stop_reasons": model_diag.get("stop_reasons") or {},
            "analyze_length_truncations": int(model_diag.get("analyze_length_truncations") or 0),
            "warnings": warnings,
        },
        "bbl_coverage": {
            "present": union_bbls is not None,
            "unique_bbls_union": union_bbls,
            "unique_functions_union": union_funcs,
            "per_segment": cov_segments,
            "bbls_per_1k_execs": _safe_rate(union_bbls, total_execs_done, 1000.0) if union_bbls is not None else None,
            "bbls_per_minute_e2e": round(union_bbls / e2e_minutes, 4) if (union_bbls is not None and e2e_minutes > 0) else None,
            "bbl_set_path": bbl_set_path,
        },
        "layers_l1_l4": {
            "l1": int(layers.get("l1") or 0),
            "l2": int(layers.get("l2") or 0),
            "l3": int(layers.get("l3") or 0),
            "l4": l4,
        },
        "l5_bare_without_sram_slice": bare_summary,
        "l5_with_shared_sram_slice": slice_summary,
        "l5_sram_slice_net_gain": {
            "additional_unique_bugs": net_gain,
            "additional_matched_candidates": max(
                0,
                int(slice_summary.get("candidate_hits_total") or 0) - int(bare_summary.get("candidate_hits_total") or 0),
            ) if slice_summary["present"] else 0,
            "downstream_attributed": slice_summary["known_p2im_bug_downstream"] if slice_summary["present"] else 0,
        },
        "efficiency": {
            "l4_per_1k_execs": _safe_rate(l4, total_execs_done, 1000.0),
            "l4_per_minute_e2e": round(l4 / e2e_minutes, 4) if e2e_minutes > 0 else None,
            "l5_direct_per_1k_execs": _safe_rate(slice_summary["known_p2im_bug_direct"], total_execs_done, 1000.0) if slice_summary["present"] else None,
            "l5_total_per_1k_execs": _safe_rate(slice_summary["matched_total"], total_execs_done, 1000.0) if slice_summary["present"] else None,
        },
        "instruction_authority": "none",
    }


def _stat_distribution(values: list[float | int | None]) -> dict:
    clean = [v for v in values if v is not None]
    if not clean:
        return {"n": 0, "raw": [], "median": None, "min": None, "max": None, "spread": None}
    return {
        "n": len(clean),
        "raw": clean,
        "median": statistics.median(clean),
        "min": min(clean),
        "max": max(clean),
        "spread": round(max(clean) - min(clean), 6) if any(isinstance(v, float) for v in clean) else (max(clean) - min(clean)),
    }


def _load_bbl_set(summary: dict) -> set[str] | None:
    path = (summary.get("bbl_coverage") or {}).get("bbl_set_path")
    if not path or not os.path.isfile(path):
        return None
    doc = read_json(path)
    items = doc.get("unique_bbls_list")
    return set(items) if isinstance(items, list) else None


def compare_arms(
    arm_specs: list[tuple[str, str]],
    notes: str | None = None,
    paper_text: str | None = None,
) -> dict:
    summaries: list[dict] = []
    grouped: dict[str, list[dict]] = {}
    for label, run_dir in arm_specs:
        summary = score_arm(run_dir, notes=notes, paper_text=paper_text, arm_label=label)
        summaries.append(summary)
        grouped.setdefault(label, []).append(summary)

    targets = {s["identity"]["target"] for s in summaries}
    hashes = {s["identity"]["elf_sha256"] for s in summaries if s["identity"]["elf_sha256"]}
    if len(targets) > 1 or len(hashes) > 1:
        raise ValueError(f"Cross-target comparison refused: targets={sorted(targets)}, elf_sha256={sorted(hashes)}")

    target = next(iter(targets)) if targets else ""
    elf_sha256 = next(iter(hashes)) if hashes else ""

    arms_agg: dict[str, dict] = {}
    baseline_execs = None
    first_label = next(iter(grouped), None)
    if "b0" in grouped:
        baseline_execs = _stat_distribution([r["target_executions"]["total_execs_done"] for r in grouped["b0"]])["median"]
    elif first_label:
        baseline_execs = _stat_distribution([r["target_executions"]["total_execs_done"] for r in grouped[first_label]])["median"]

    for label, rows in grouped.items():
        execs_dist = _stat_distribution([r["target_executions"]["total_execs_done"] for r in rows])
        execs_ratio = None
        if baseline_execs and baseline_execs > 0 and execs_dist["median"] is not None:
            execs_ratio = round(execs_dist["median"] / baseline_execs, 4)
        arms_agg[label] = {
            "runs": len(rows),
            "end_to_end_wall_ms": _stat_distribution([r["wall_clock"]["end_to_end_wall_ms"] for r in rows]),
            "discovery_guidance_wall_ms": _stat_distribution([r["wall_clock"]["discovery_guidance_wall_ms"] for r in rows]),
            "fuzz_wall_ms": _stat_distribution([r["wall_clock"]["fuzz_wall_ms"] for r in rows]),
            "llm_wall_ms": _stat_distribution([r["wall_clock"]["llm_wall_ms"] for r in rows]),
            "total_execs_done": execs_dist,
            "execs_ratio_vs_baseline": execs_ratio,
            "unique_bbls_union": _stat_distribution([r["bbl_coverage"]["unique_bbls_union"] for r in rows]),
            "bbls_per_1k_execs": _stat_distribution([r["bbl_coverage"]["bbls_per_1k_execs"] for r in rows]),
            "l1": _stat_distribution([r["layers_l1_l4"]["l1"] for r in rows]),
            "l2": _stat_distribution([r["layers_l1_l4"]["l2"] for r in rows]),
            "l3": _stat_distribution([r["layers_l1_l4"]["l3"] for r in rows]),
            "l4": _stat_distribution([r["layers_l1_l4"]["l4"] for r in rows]),
            "l4_per_1k_execs": _stat_distribution([r["efficiency"]["l4_per_1k_execs"] for r in rows]),
            "l5_bare_matched": _stat_distribution([r["l5_bare_without_sram_slice"]["matched_total"] for r in rows if r["l5_bare_without_sram_slice"]["present"]]),
            "l5_slice_direct": _stat_distribution([r["l5_with_shared_sram_slice"]["known_p2im_bug_direct"] for r in rows if r["l5_with_shared_sram_slice"]["present"]]),
            "l5_slice_downstream": _stat_distribution([r["l5_with_shared_sram_slice"]["known_p2im_bug_downstream"] for r in rows if r["l5_with_shared_sram_slice"]["present"]]),
            "l5_slice_matched": _stat_distribution([r["l5_with_shared_sram_slice"]["matched_total"] for r in rows if r["l5_with_shared_sram_slice"]["present"]]),
            "model_requests": _stat_distribution([r["model_cost"]["model_requests"] for r in rows]),
            "tokens": _stat_distribution([r["model_cost"]["tokens"] for r in rows]),
        }

    attribution_4way = []
    if "b0" in arms_agg:
        b0 = arms_agg["b0"]
        attribution_4way.append({
            "label": "b0_bare_stock_p2im",
            "sram_slice": False,
            "llm": False,
            "matched_l5": b0["l5_bare_matched"],
            "direct_l5": b0["l5_slice_direct"],
            "downstream_l5": _stat_distribution([0] * b0["l5_bare_matched"]["n"]),
        })
        attribution_4way.append({
            "label": "b0_plus_offline_sram_slice",
            "sram_slice": True,
            "llm": False,
            "matched_l5": b0["l5_slice_matched"],
            "direct_l5": b0["l5_slice_direct"],
            "downstream_l5": b0["l5_slice_downstream"],
        })
    for label in grouped:
        if label == "b0":
            continue
        arm = arms_agg[label]
        attribution_4way.append({
            "label": label,
            "sram_slice": True,
            "llm": label == "real" or (arm["model_requests"]["median"] or 0) > 0,
            "matched_l5": arm["l5_slice_matched"],
            "direct_l5": arm["l5_slice_direct"],
            "downstream_l5": arm["l5_slice_downstream"],
        })

    pooled_bbls: dict[str, set[str]] = {}
    for label, rows in grouped.items():
        merged: set[str] = set()
        any_present = False
        for row in rows:
            s = _load_bbl_set(row)
            if s is not None:
                any_present = True
                merged |= s
        if any_present:
            pooled_bbls[label] = merged

    pairwise_bbl_diff = []
    labels_with_bbls = list(pooled_bbls.keys())
    for i, left in enumerate(labels_with_bbls):
        for right in labels_with_bbls[i + 1:]:
            a = pooled_bbls[left]
            b = pooled_bbls[right]
            pairwise_bbl_diff.append({
                "left": left,
                "right": right,
                "left_unique_bbls": len(a),
                "right_unique_bbls": len(b),
                "left_only": len(a - b),
                "right_only": len(b - a),
                "intersection": len(a & b),
                "union": len(a | b),
            })

    return {
        "schema": "mcu-p2im/compare-0.1",
        "target": target,
        "elf_sha256": elf_sha256,
        "arms": arms_agg,
        "attribution_separation_4way": attribution_4way,
        "pairwise_bbl_diff": pairwise_bbl_diff,
        "runs": summaries,
        "instruction_authority": "none",
    }


def render_markdown(report: dict) -> str:
    lines = [
        f"# Evaluation Comparison: `{report['target']}` (`{report['elf_sha256'][:12]}...`)",
        "",
        "## 1. Equal End-to-End Wall Clock View (Unique Deduplicated Bugs)",
        "",
        "| Arm | Runs | E2E Wall (ms, med [min..max]) | Discovery+Guidance Wall (ms, med) | LLM Wall (ms, med) | BBL Union (med) | L3 / L4 (med) | Unique Known Bugs: Bare vs +SRAM Slice (med) |",
        "|---|---:|---|---:|---:|---:|---|---|",
    ]
    def fmt_med(dist: dict) -> str:
        if not dist or dist.get("median") is None:
            return "-"
        return f"{dist['median']} [{dist['min']}..{dist['max']}]"

    for label, arm in report["arms"].items():
        l34 = f"{arm['l3']['median']} / {arm['l4']['median']}"
        l5 = f"{arm['l5_bare_matched']['median']} vs {arm['l5_slice_matched']['median']} (direct={arm['l5_slice_direct']['median']}, down={arm['l5_slice_downstream']['median']})"
        lines.append(
            f"| `{label}` | {arm['runs']} | {fmt_med(arm['end_to_end_wall_ms'])} | {arm['discovery_guidance_wall_ms']['median']} | {arm['llm_wall_ms']['median']} | {fmt_med(arm['unique_bbls_union'])} | {l34} | {l5} |"
        )
    lines.extend([
        "",
        "## 2. Target Execution Budget & Exec-Normalized Throughput View",
        "",
        "> Note: Strict equal-execution comparisons require running all arms with `--max-execs N`; on wall-clock-bounded runs, per-1k-exec rates reflect execution-normalized efficiency only.",
        "",
        "| Arm | `execs_done` (med [min..max]) | Ratio vs Baseline | BBL / 1k execs (med) | L4 / 1k execs (med) | Model Calls / Tokens (med) |",
        "|---|---|---:|---:|---:|---|",
    ])
    for label, arm in report["arms"].items():
        lines.append(
            f"| `{label}` | {fmt_med(arm['total_execs_done'])} | {arm['execs_ratio_vs_baseline']} | {arm['bbls_per_1k_execs']['median']} | {arm['l4_per_1k_execs']['median']} | {arm['model_requests']['median']} / {arm['tokens']['median']} |"
        )
    lines.extend([
        "",
        "## 3. Four-Way Attribution Separation",
        "",
        "| Condition | SRAM Slice | LLM | Matched L5 (med [min..max]) | Direct L5 (med) | Downstream L5 (med) |",
        "|---|---:|---:|---|---:|---:|",
    ])
    for row in report["attribution_separation_4way"]:
        lines.append(
            f"| `{row['label']}` | {row['sram_slice']} | {row['llm']} | {fmt_med(row['matched_l5'])} | {row['direct_l5']['median']} | {row['downstream_l5']['median']} |"
        )
    if report["pairwise_bbl_diff"]:
        lines.extend([
            "",
            "## 4. Pairwise Unique BBL Set Differences",
            "",
            "| Left | Right | `|Left|` | `|Right|` | `|Left \\ Right|` | `|Right \\ Left|` | `|Intersection|` | `|Union|` |",
            "|---|---|---:|---:|---:|---:|---:|---:|",
        ])
        for row in report["pairwise_bbl_diff"]:
            lines.append(
                f"| `{row['left']}` | `{row['right']}` | {row['left_unique_bbls']} | {row['right_unique_bbls']} | {row['left_only']} | {row['right_only']} | {row['intersection']} | {row['union']} |"
            )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Post-hoc L3/L4/L5/BBL evaluation and multi-arm comparison.")
    sub = parser.add_subparsers(dest="command", required=True)

    s_arm = sub.add_parser("score-arm")
    s_arm.add_argument("--run-dir", required=True)
    s_arm.add_argument("--arm-label")
    s_arm.add_argument("--notes")
    s_arm.add_argument("--paper-text")
    s_arm.add_argument("--bbl-coverage")
    s_arm.add_argument("--run-bbl-coverage", action="store_true")
    s_arm.add_argument("--work-root")
    s_arm.add_argument("--tools-root")
    s_arm.add_argument("--out")

    cmp_p = sub.add_parser("compare")
    cmp_p.add_argument("--arm", action="append", required=True, metavar="LABEL=RUN_DIR")
    cmp_p.add_argument("--notes")
    cmp_p.add_argument("--paper-text")
    cmp_p.add_argument("--out")
    cmp_p.add_argument("--markdown")

    args = parser.parse_args(argv)
    try:
        if args.command == "score-arm":
            summary = score_arm(
                args.run_dir,
                notes=args.notes,
                paper_text=args.paper_text,
                bbl_coverage_path=args.bbl_coverage,
                run_bbl_coverage=args.run_bbl_coverage,
                work_root_override=args.work_root,
                tools_root_override=args.tools_root,
                arm_label=args.arm_label,
            )
            out_path = args.out or os.path.join(os.path.abspath(args.run_dir), "arm-summary.json")
            write_json(out_path, summary)
            print(json.dumps(summary, indent=2))
            return 0

        arm_specs: list[tuple[str, str]] = []
        for item in args.arm:
            if "=" not in item:
                print(json.dumps({"ok": False, "error": f"expected LABEL=RUN_DIR, got {item}"}), file=sys.stderr)
                return 3
            label, run_dir = item.split("=", 1)
            arm_specs.append((label.strip(), run_dir.strip()))
        report = compare_arms(arm_specs, notes=args.notes, paper_text=args.paper_text)
        if args.out:
            write_json(args.out, report)
        if args.markdown:
            os.makedirs(os.path.dirname(os.path.abspath(args.markdown)), exist_ok=True)
            with open(args.markdown, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(render_markdown(report))
        print(json.dumps(report, indent=2))
        return 0
    except ValueError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
