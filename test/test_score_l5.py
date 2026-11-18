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

    def test_real_notes_plc_section_when_mounted(self):
        path = os.environ.get("P2IM_NOTES", "")
        if not path or not os.path.isfile(path):
            self.skipTest("P2IM_NOTES is not set or patching notes are not mounted")
        text = open(path, encoding="utf-8", errors="replace").read()
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


if __name__ == "__main__":
    unittest.main()
