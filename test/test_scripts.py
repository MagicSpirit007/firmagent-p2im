#!/usr/bin/env python3
"""Unit tests for privacy_audit.py (#3), verify_step7.py (#8), leak_check.py (#9), and eval_arms.py (#13)."""

import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest

SCRIPTS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
sys.path.insert(0, SCRIPTS)
import eval_arms  # noqa: E402
import privacy_audit  # noqa: E402
import verify_step7  # noqa: E402


class PrivacyAuditTest(unittest.TestCase):
    def test_prunes_node_modules_and_supports_ignore_build_artifacts(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "src"), exist_ok=True)
            with open(os.path.join(root, "src", "app.ts"), "w", encoding="utf-8") as handle:
                handle.write("export const x = 1;\n")
            nm_nested = os.path.join(root, "node_modules", "pkg", "dist", "__pycache__")
            os.makedirs(nm_nested, exist_ok=True)
            with open(os.path.join(nm_nested, "deep.js"), "w", encoding="utf-8") as handle:
                handle.write("console.log('ok');\n")
            os.makedirs(os.path.join(root, "dist"), exist_ok=True)
            with open(os.path.join(root, "dist", "index.js"), "w", encoding="utf-8") as handle:
                handle.write("export {};\n")

            hits = privacy_audit.audit_repo(root, ignore_build_artifacts=False)
            self.assertEqual(
                sorted(item["path"] for item in hits),
                ["dist", "node_modules"],
                "must prune inside node_modules/dist rather than emitting nested hits",
            )
            self.assertEqual(privacy_audit.audit_repo(root, ignore_build_artifacts=True), [])

            # Secret regex must still be flagged even when build artifacts are ignored.
            fake_secret = "sk-" + "1234567890abcdef"
            with open(os.path.join(root, "src", "leak.ts"), "w", encoding="utf-8") as handle:
                handle.write(f"const k = '{fake_secret}';\n")
            secret_hits = privacy_audit.audit_repo(root, ignore_build_artifacts=True)
            self.assertEqual(len(secret_hits), 1)
            self.assertIn("forbidden_regex", secret_hits[0]["reason"])


class VerifyStep7Test(unittest.TestCase):
    def _write_json(self, path: str, data):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)

    def test_reports_healthy_0crash_and_flags_smoke_error_rc127(self):
        with tempfile.TemporaryDirectory() as root:
            work_dir = os.path.join(root, "plc")
            os.makedirs(os.path.join(work_dir, "inputs"), exist_ok=True)
            elf = os.path.join(work_dir, "PLC.elf")
            with open(elf, "wb") as handle:
                handle.write(b"\x7fELF")
            sha = hashlib.sha256(b"\x7fELF").hexdigest()
            self._write_json(os.path.join(work_dir, "meta.json"), {
                "target": "PLC", "elf": {"path": elf, "sha256": sha}, "auto_forkserver_pc": None,
            })
            fake_qemu = os.path.join(root, "qemu-bin")
            with open(fake_qemu, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nexit 0\n")
            os.chmod(fake_qemu, 0o755)
            shim = os.path.join(root, "bin", "qemu-system-gnuarmeclipse")
            os.makedirs(os.path.dirname(shim), exist_ok=True)
            with open(shim, "w", encoding="utf-8") as handle:
                handle.write(f'#!/bin/sh\nunset LD_LIBRARY_PATH\nexec "{fake_qemu}" "$@"\n')
            os.chmod(shim, 0o755)
            for name in ("seed-random", "seed-short"):
                with open(os.path.join(work_dir, "inputs", name), "wb") as handle:
                    handle.write(b"abcd")
            self._write_json(os.path.join(work_dir, "evidence", "smoke.json"), {"outcome": "ok", "exit_code": 64})
            self._write_json(os.path.join(work_dir, "evidence", "me-round.json"), {
                "round": "0", "exit_code": 0, "model": {"peripheral_count": 5, "dr_registers": [1, 2]},
            })
            self._write_json(os.path.join(work_dir, "segments", "s1.json"), {
                "segment": "s1", "duration_s": 60.0, "execs_done": 1200, "paths_total": 40, "crash_files": 0,
            })
            self._write_json(os.path.join(work_dir, "analysis", "paths.json"), {
                "counts": {"paths": 2},
                "shared_globals": [{"symbol": "rx_callback", "call_edge": False, "indexed_reach": [{"call_edge": False}]}],
            })
            self._write_json(os.path.join(work_dir, "evidence", "crash-index.json"), {"raw_files": 0, "unique": 0, "crashes": []})

            healthy = verify_step7.verify_work_roots([root], check_procs=False)
            self.assertTrue(healthy["ok"])
            self.assertIn("0 crashes", " ".join(healthy["targets"][0]["notes"]))
            self.assertIn("PASS", verify_step7.format_table(healthy))

            self._write_json(os.path.join(work_dir, "evidence", "smoke.json"), {"outcome": "error", "exit_code": 127})
            broken = verify_step7.verify_work_roots([root], check_procs=False)
            self.assertFalse(broken["ok"])
            self.assertIn("smoke failed", " ".join(broken["targets"][0]["issues"]))


class LeakCheckWorkDirTest(unittest.TestCase):
    def test_leak_check_infers_work_dir_from_candidates_when_omitted(self):
        with tempfile.TemporaryDirectory() as root:
            work_dir = os.path.join(root, "work", "plc")
            os.makedirs(os.path.join(work_dir, "analysis"), exist_ok=True)
            for fname in ("sources.json", "paths.json"):
                with open(os.path.join(work_dir, "analysis", fname), "w", encoding="utf-8") as handle:
                    json.dump({"ok": True}, handle)
            cand_path = os.path.join(root, "l5-candidates.json")
            with open(cand_path, "w", encoding="utf-8") as handle:
                json.dump({"work_dir": work_dir, "candidates": []}, handle)
            prompt_src = os.path.join(root, "prompt.ts")
            with open(prompt_src, "w", encoding="utf-8") as handle:
                handle.write("const clean = true;\n")
            leak_script = os.path.join(SCRIPTS, "leak_check.py")
            import subprocess
            proc = subprocess.run(
                [sys.executable, leak_script, "--candidates", cand_path, "--prompt-source", prompt_src],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(out["work_dir"], work_dir)
            self.assertEqual(out["surfaces"], 4)
            self.assertFalse(out["leak_in_prompt"])

            # Sibling ledger.jsonl is auto-scanned when present, and mismatched --work-dir is refused.
            with open(os.path.join(root, "ledger.jsonl"), "w", encoding="utf-8") as handle:
                handle.write('{"seq":1,"kind":"prompt"}\n')
            proc2 = subprocess.run(
                [sys.executable, leak_script, "--candidates", cand_path, "--prompt-source", prompt_src],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(proc2.returncode, 0, proc2.stderr)
            self.assertEqual(json.loads(proc2.stdout)["surfaces"], 5)

            proc_mismatch = subprocess.run(
                [sys.executable, leak_script, "--work-dir", os.path.join(root, "other-work"), "--candidates", cand_path],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(proc_mismatch.returncode, 2)
            self.assertIn("work_dir_mismatch", proc_mismatch.stderr)


class EvalArmsTest(unittest.TestCase):
    def _make_run(self, root: str, name: str, mode: str, execs: int, wall_ms: int, bbls: list[str],
                  upstream: list[str], target: str = "PLC", sha: str = "a" * 64) -> str:
        run_dir = os.path.join(root, "runs", name)
        work_dir = os.path.join(root, "work", name, target.lower())
        os.makedirs(run_dir, exist_ok=True)
        os.makedirs(os.path.join(work_dir, "analysis"), exist_ok=True)
        with open(os.path.join(work_dir, "analysis", "bbl-coverage.json"), "w", encoding="utf-8") as handle:
            json.dump({
                "schema": "mcu-p2im/bbl-coverage-0.1",
                "segments": {"s1": {"unique_bbls": len(bbls), "new_bbls_over_prior": len(bbls), "cumulative_unique_bbls": len(bbls)}},
                "union": {"unique_bbls": len(bbls), "unique_functions": 2},
                "unique_bbls_list": bbls,
            }, handle)
        with open(os.path.join(run_dir, "state.json"), "w", encoding="utf-8") as handle:
            json.dump({
                "target": target, "elf_sha256": sha, "mode": mode, "status": "completed",
                "work_root": os.path.join(root, "work", name), "work_dir": work_dir,
                "totals": {"wall_ms": wall_ms}, "layers": {"l1": 1, "l2": 1, "l3": 1, "l4": 1},
            }, handle)
        with open(os.path.join(run_dir, "score-owned.json"), "w", encoding="utf-8") as handle:
            json.dump({
                "schema": "mcu-p2im/score-owned-0.2", "target": target, "elf_sha256": sha, "mode": mode,
                "work_root": os.path.join(root, "work", name), "work_dir": work_dir,
                "model_requests": 5 if mode == "real" else 0, "tokens": 70000 if mode == "real" else 0,
                "total_execs_done": execs,
                "wall_clock": {"end_to_end_wall_ms": wall_ms, "fuzz_wall_ms": 600000, "slice_wall_ms": 2000, "llm_wall_ms": 40000 if mode == "real" else 0, "triage_wall_ms": 5000},
                "model_diagnostics": {"provider": "deepseek" if mode == "real" else None, "model": "deepseek-v4-flash" if mode == "real" else None,
                                      "thinking": "low" if mode == "real" else None, "stop_reasons": {"stop": 5} if mode == "real" else {},
                                      "analyze_length_truncations": 0},
                "segments": [{"segment": "s1", "execs_done": execs, "duration_s": 600.0}],
                "layers": {"l1": 1, "l2": 1, "l3": 1, "l4": 1},
            }, handle)
        cand = [{"target": target, "function": "HAL_UART_RxCpltCallback", "addresses": ["0x8003f30"],
                 "upstream_functions": upstream, "via_shared_global": "rx_callback" if upstream else None}]
        bare_cand = [{"target": target, "function": "HAL_UART_RxCpltCallback", "addresses": ["0x8003f30"],
                      "upstream_functions": [], "via_shared_global": None}]
        with open(os.path.join(run_dir, "l5-candidates.json"), "w", encoding="utf-8") as handle:
            json.dump({"target": target, "work_dir": work_dir, "candidates": cand}, handle)
        with open(os.path.join(run_dir, "l5-candidates-bare.json"), "w", encoding="utf-8") as handle:
            json.dump({"target": target, "work_dir": work_dir, "candidates": bare_cand}, handle)
        return run_dir

    def test_compare_separates_bare_vs_sram_slice_and_computes_median_and_bbl_diff(self):
        with tempfile.TemporaryDirectory() as root:
            notes = os.path.join(root, "notes.md")
            with open(notes, "w", encoding="utf-8") as handle:
                handle.write("## PLC\n### Bug 1: OOB\nAffected function:\n```\nint8_t Modbus::process_FC1(uint16_t *r, uint8_t s)\n```\n")
            b0 = self._make_run(root, "b0-1", "b0", 10000, 610000, ["0x1..0x2", "0x3..0x4"], ["Modbus::process_FC1"])
            off = self._make_run(root, "off-1", "offline", 11000, 620000, ["0x1..0x2", "0x5..0x6"], ["Modbus::process_FC1"])
            r1 = self._make_run(root, "real-1", "real", 11200, 640000, ["0x1..0x2", "0x5..0x6", "0x7..0x8"], ["Modbus::process_FC1"])
            r2 = self._make_run(root, "real-2", "real", 11600, 650000, ["0x1..0x2", "0x7..0x8", "0x9..0xa"], ["Modbus::process_FC1"])
            # Duplicate second witness hitting the same Bug 1 in real-1 must NOT inflate unique known bugs above 1!
            r1_cand_path = os.path.join(r1, "l5-candidates.json")
            with open(r1_cand_path, encoding="utf-8") as handle:
                r1_cand = json.load(handle)
            r1_cand["candidates"].append({
                "target": "PLC", "function": "Modbus::process_FC1", "addresses": ["0x8000952"],
                "upstream_functions": [], "via_shared_global": None,
            })
            with open(r1_cand_path, "w", encoding="utf-8") as handle:
                json.dump(r1_cand, handle)

            report = eval_arms.compare_arms([("b0", b0), ("offline", off), ("real", r1), ("real", r2)], notes=notes)
            self.assertEqual(report["arms"]["real"]["total_execs_done"]["raw"], [11200, 11600])
            self.assertEqual(report["arms"]["real"]["total_execs_done"]["median"], 11400)
            self.assertEqual(report["arms"]["real"]["total_execs_done"]["spread"], 400)
            self.assertEqual(report["arms"]["b0"]["l5_bare_matched"]["median"], 0)
            self.assertEqual(report["arms"]["b0"]["l5_slice_matched"]["median"], 1)
            self.assertEqual(report["arms"]["real"]["l5_slice_matched"]["raw"], [1, 1],
                             "two candidates hitting Bug 1 must count as 1 unique known bug")

            sep = {row["label"]: row for row in report["attribution_separation_4way"]}
            self.assertFalse(sep["b0_bare_stock_p2im"]["sram_slice"])
            self.assertEqual(sep["b0_bare_stock_p2im"]["matched_l5"]["median"], 0)
            self.assertTrue(sep["b0_plus_offline_sram_slice"]["sram_slice"])
            self.assertEqual(sep["b0_plus_offline_sram_slice"]["downstream_l5"]["median"], 1)

            diffs = {(d["left"], d["right"]): d for d in report["pairwise_bbl_diff"]}
            b0_real = diffs[("b0", "real")]
            self.assertEqual(b0_real["left_only"], 1)   # 0x3..0x4
            self.assertEqual(b0_real["right_only"], 3)  # 0x5..0x6, 0x7..0x8, 0x9..0xa
            self.assertEqual(b0_real["union"], 5)
            md = eval_arms.render_markdown(report)
            self.assertIn("Four-Way Attribution Separation", md)

    def test_compare_refuses_cross_target_comparison(self):
        with tempfile.TemporaryDirectory() as root:
            r_plc = self._make_run(root, "p", "b0", 100, 1000, [], [], target="PLC", sha="a" * 64)
            r_cnc = self._make_run(root, "c", "b0", 100, 1000, [], [], target="CNC", sha="b" * 64)
            with self.assertRaises(ValueError):
                eval_arms.compare_arms([("b0", r_plc), ("b0", r_cnc)])


if __name__ == "__main__":
    unittest.main()
