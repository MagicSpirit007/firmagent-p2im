#!/usr/bin/env python3
"""L5 scorer tests. The truth text stays inside this process."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts")))
import score_l5  # noqa: E402

NOTES = """# patching notes

## Gateway

Affected function:
```
void Gateway::handle(void)
{
}
```
address: 0x08001000

## PLC

### Bug 1: OOB write

Affected function:
```
int8_t Modbus::process_FC1( uint16_t *regs, uint8_t u8size )
{
}
```

address: 0x08000952

## Heat_Press

no plc here
"""

PAPER = """## 附录 A 漏洞分析与 PoC：PLC 固件

process_FC3 is named in the appendix.
HAL_UART_RxCpltCallback is only the observed crash site.
"""


class ScoreL5Test(unittest.TestCase):
    def test_level2_heading_is_kept_and_classes_are_split(self):
        result = score_l5.score(NOTES, PAPER, [
            {"target": "PLC", "function": "Modbus::process_FC1", "addresses": ["0x08000952"]},
            {"target": "PLC", "function": "HAL_UART_RxCpltCallback", "addresses": ["0x8003f30"],
             "upstream_functions": ["Modbus::process_FC1"], "via_shared_global": "rx_callback",
             "adjacent_global": "au8Buffer"},
            {"target": "PLC", "function": "unrelated", "addresses": ["0x08001000"]},
        ], "PLC")
        self.assertGreater(result["diagnostics"]["rows_mentioning_target"], 0)
        self.assertGreaterEqual(result["diagnostics"]["known_functions"], 2)
        self.assertEqual(result["diagnostics"]["notes_sections_matched"], ["PLC"])
        self.assertEqual(result["diagnostics"]["paper_sections_matched"], 1)
        statuses = {item["candidate"]["function"]: item["status"] for item in result["results"]}
        self.assertEqual(statuses["Modbus::process_FC1"], "known_p2im_bug_direct")
        self.assertEqual(statuses["HAL_UART_RxCpltCallback"], "known_p2im_bug_downstream")
        self.assertEqual(statuses["unrelated"], "unmatched_verified_candidate")
        # The Gateway patch address must not count as a PLC direct hit.
        self.assertNotIn("0x8001000", json.dumps(result["results"][0]["match"]))
        self.assertFalse(result["raw_text_emitted"])
        split = result["attribution_split"]
        self.assertEqual(split["bare_without_sram_slice"]["known_p2im_bug_direct"], 1)
        self.assertEqual(split["bare_without_sram_slice"]["known_p2im_bug_downstream"], 0)
        self.assertEqual(split["bare_without_sram_slice"]["matched_total"], 1)
        self.assertEqual(split["with_shared_sram_slice"]["known_p2im_bug_downstream"], 1)
        self.assertEqual(split["with_shared_sram_slice"]["matched_total"], 2)
        self.assertEqual(split["sram_slice_net_gain"]["additional_matched_candidates"], 1)

    def test_real_notes_plc_section_when_mounted(self):
        path = os.environ.get("P2IM_NOTES", "")
        if not path or not os.path.isfile(path):
            self.skipTest("P2IM_NOTES is not set or patching notes are not mounted")
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        result = score_l5.score(text, "", [
            {"target": "PLC", "function": "Modbus::process_FC1", "addresses": ["0x08000952"]},
            {"target": "PLC", "function": "HAL_UART_RxCpltCallback", "addresses": ["0x8003f30"],
             "upstream_functions": ["Modbus::process_FC1"], "via_shared_global": "rx_callback"},
        ], "PLC")
        self.assertGreater(result["diagnostics"]["rows_mentioning_target"], 0)
        self.assertGreaterEqual(result["diagnostics"]["known_functions"], 4)
        self.assertGreater(result["diagnostics"]["patch_addresses"], 0)
        statuses = {item["candidate"]["function"]: item["status"] for item in result["results"]}
        self.assertEqual(statuses["Modbus::process_FC1"], "known_p2im_bug_direct")
        self.assertEqual(statuses["HAL_UART_RxCpltCallback"], "known_p2im_bug_downstream")
        # The old heading-skip left this at 0. The heading itself is the anchor.
        self.assertIn("PLC", result["diagnostics"]["notes_sections_matched"])

    def test_bug_deduplication_and_bbl_range_matching(self):
        result = score_l5.score(NOTES, PAPER, [
            {"target": "PLC", "function": "Modbus::process_FC1", "addresses": ["0x08000952"]},
            {"target": "PLC", "function": "HAL_UART_RxCpltCallback", "addresses": ["0x8003f30"],
             "upstream_functions": ["Modbus::process_FC1"], "via_shared_global": "rx_callback"},
            {"target": "PLC", "function": "", "addresses": ["0x8000948"],
             "bbl_range": ["0x8000948", "0x8000958"]},
        ], "PLC")
        self.assertEqual(result["counts"]["candidates"], 3)
        self.assertEqual(result["counts"]["known_p2im_bug_direct"], 2)
        self.assertEqual(result["counts"]["known_p2im_bug_downstream"], 1)
        ub = result["unique_bugs"]
        self.assertEqual(ub["unique_known_bugs_total"], 1, "multiple witnesses of Bug 1 must deduplicate to 1 unique bug")
        self.assertEqual(ub["matched_bug_ids"], ["PLC#bug1"])

    def test_all_five_patched_targets_and_elf_symbol_lookup_when_mounted(self):
        notes_path = os.environ.get("P2IM_NOTES", "")
        if not notes_path or not os.path.isfile(notes_path):
            self.skipTest("P2IM_NOTES is not set or patching notes are not mounted")
        with open(notes_path, encoding="utf-8", errors="replace") as handle:
            notes_text = handle.read()
        manifest_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docs", "P2IM_10_UNPATCHED_MANIFEST.json"))
        with open(manifest_path, encoding="utf-8") as handle:
            manifest = json.load(handle)
        p2im_root = os.environ.get("P2IM_ROOT", os.path.expanduser("~/deps/p2im")).rstrip("/")
        hoedur_root = os.environ.get("HOEDUR_EXPERIMENTS_ROOT", os.path.expanduser("~/deps/hoedur-experiments")).rstrip("/")
        elf_by_target = {
            row["target"]: row["path"].replace("${P2IM_ROOT}", p2im_root).replace("${HOEDUR_EXPERIMENTS_ROOT}", hoedur_root)
            for row in manifest["targets"]
        }
        expected = {
            "CNC": (1, "printFloat", "protocol_execute_startup", []),
            "Gateway": (3, "I2C_ITError", "blinkVersion", ["0x80019b4"]),
            "PLC": (4, "Modbus::process_FC1", "__swrite", ["0x8005658"]),
            "Heat_Press": (1, "Modbus::get_FC3", "Modbus::validateAnswer", ["0x80218", "0x8025e"]),
            "Soldering_Iron": (3, "OLED::drawHeatSymbol", None, []),
        }
        for target, (bug_count, must_have, cave_exclude, excluded_addrs) in expected.items():
            elf_path = elf_by_target[target]
            if not os.path.isfile(elf_path):
                self.skipTest(f"ELF for {target} is not mounted at {elf_path}")
            res = score_l5.score(notes_text, "", [
                {"target": target, "function": must_have, "addresses": []},
            ], target, elf_path=elf_path)
            self.assertEqual(res["diagnostics"]["known_bugs"], bug_count, target)
            self.assertGreaterEqual(res["diagnostics"]["known_functions"], 1, target)
            self.assertEqual(res["unique_bugs"]["unique_known_bugs_direct"], 1, target)
            if cave_exclude or excluded_addrs:
                probe = score_l5.score(notes_text, "", [
                    {"target": target, "function": cave_exclude or "unrelated_fn", "addresses": excluded_addrs},
                ], target, elf_path=elf_path)
                self.assertEqual(probe["unique_bugs"]["unique_known_bugs_total"], 0,
                                 f"code-cave donor {cave_exclude}/{excluded_addrs} must not match on {target}")


if __name__ == "__main__":
    unittest.main()
