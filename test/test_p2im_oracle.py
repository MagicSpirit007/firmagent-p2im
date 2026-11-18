#!/usr/bin/env python3
"""Contract tests for tools/p2im_oracle.py.

Pure host-side: no QEMU, no AFL, no firmware execution. The ELF-dependent checks are skipped
when the P2IM tree is not mounted, so the suite stays meaningful on a bare checkout.

Run: python3 -m unittest discover -s test -p 'test_p2im_oracle.py' -v
"""

import io
import json
import os
import sys
import tempfile
import unittest

TOOLS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tools"))
sys.path.insert(0, TOOLS)
import p2im_oracle as oracle  # noqa: E402

PLC = os.path.join(
    os.environ.get("P2IM_ROOT", os.path.expanduser("~/deps/p2im")),
    "externals", "p2im-real_firmware", "binary", "PLC",
)


class FuzzerStatsTest(unittest.TestCase):
    def test_parses_typed_values(self):
        with tempfile.NamedTemporaryFile("w", suffix=".stats", delete=False) as handle:
            handle.write("start_time     : 1794834240\nbitmap_cvg     : 0.02%\nexecs_done     : 16416\n"
                         "execs_per_sec  : 51.94\nafl_banner     : PLC_0\n")
            path = handle.name
        try:
            stats = oracle.parse_fuzzer_stats(path)
        finally:
            os.unlink(path)
        self.assertEqual(stats["execs_done"], 16416)
        self.assertAlmostEqual(stats["execs_per_sec"], 51.94)
        self.assertEqual(stats["bitmap_cvg"], "0.02%")
        self.assertEqual(stats["afl_banner"], "PLC_0")

    def test_missing_file_is_empty(self):
        self.assertEqual(oracle.parse_fuzzer_stats("/nonexistent/fuzzer_stats"), {})


class CrashListingTest(unittest.TestCase):
    def test_crash_id_ret_v_and_sha(self):
        with tempfile.TemporaryDirectory() as root:
            crashes = os.path.join(root, "crashes")
            os.makedirs(crashes)
            open(os.path.join(crashes, "README.txt"), "w").write("x")
            body = b"\x01\x02\x03"
            open(os.path.join(crashes, "id:000000,ret_v:0xff,src:000000,op:havoc,rep:64"), "wb").write(body)
            rows = oracle.crash_files(root)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ret_v"], "0xff")
        self.assertEqual(rows[0]["bytes"], 3)
        self.assertEqual(rows[0]["sha256"], oracle.sha256_bytes(body))


class LogParsersTest(unittest.TestCase):
    def test_reg_acc_line(self):
        line = ("(0x40004804, 2, r, e15e) in BBL (0x8002f82, 0x8002f9a) "
                "[HAL_UART_IRQHandler]\n")
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as handle:
            handle.write(line)
            path = handle.name
        try:
            rows = oracle.parse_reg_acc(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["address"], "0x40004804")
        self.assertEqual(rows[0]["op"], "r")
        self.assertEqual(rows[0]["function"], "HAL_UART_IRQHandler")
        self.assertEqual(rows[0]["line"], 1)

    def test_trace_and_demangle(self):
        with tempfile.NamedTemporaryFile("w", suffix=".trace", delete=False) as handle:
            handle.write("BBL (0x80042ac, 0x80042b2) [_ZN14HardwareSerial16_rx_complete_irqEP8serial_s]\n"
                         "BBL (0x80042b2, 0x80042b6) [uart_getc]\n")
            path = handle.name
        try:
            rows = oracle.parse_trace(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["function"], "HardwareSerial::_rx_complete_irq(serial_s*)")
        self.assertEqual(rows[1]["function"], "uart_getc")

    def test_fault_parse(self):
        log = ("[8003f30, 8003f3e] illegal read at 0xfffc0004\n")
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as handle:
            handle.write(log)
            path = handle.name
        try:
            fault = oracle.parse_fault(path)
        finally:
            os.unlink(path)
        self.assertEqual(fault["fault"]["kind"], "read")
        self.assertEqual(fault["fault"]["address"], "0xfffc0004")
        self.assertEqual(fault["bbl"]["start"], "0x8003f30")


class ModelSummaryTest(unittest.TestCase):
    def test_dr_and_cr_slots(self):
        model = {"model": {"0x40004800": {"reg_size": 4, "DR_bytes_num": 2,
                                          "regs": [{"type": 2}, {"type": 3}, {"type": 3}, {"type": 1}],
                                          "events": {}}},
                 "interrupts": [{"excp_num": 55, "enabled": 1}],
                 "access_to_unmodeled_peri": {"aup_func": "HAL_UART_RxCpltCallback"}}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(model, handle)
            path = handle.name
        try:
            summary = oracle.read_model_summary(path)
        finally:
            os.unlink(path)
        self.assertEqual([entry["register"] for entry in summary["dr_registers"]],
                         ["0x40004804", "0x40004808"])
        self.assertEqual([entry["register"] for entry in summary["cr_registers"]], ["0x4000480c"])
        self.assertEqual(summary["aup"]["aup_func"], "HAL_UART_RxCpltCallback")

    def test_register_stride_follows_reg_size(self):
        model = {"model": {"0x4006a000": {"reg_size": 1, "regs": [{"type": 3}, {"type": 3}]}},
                 "interrupts": []}
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(model, handle)
            path = handle.name
        try:
            summary = oracle.read_model_summary(path)
        finally:
            os.unlink(path)
        self.assertEqual([entry["register"] for entry in summary["dr_registers"]],
                         ["0x4006a000", "0x4006a001"])


class ResolveInputTest(unittest.TestCase):
    def test_outputs_crashes_are_found_by_bare_name(self):
        with tempfile.TemporaryDirectory() as root:
            work = oracle.Work(root, "PLC")
            work.dir = os.path.join(root, "plc")
            os.makedirs(os.path.join(work.dir, "outputs-s1", "crashes"), exist_ok=True)
            name = "id:000001,ret_v:0xff,src:000000"
            path = os.path.join(work.dir, "outputs-s1", "crashes", name)
            open(path, "wb").write(b"\x00")
            self.assertEqual(oracle.resolve_input(work, name), path)
            self.assertIsNone(oracle.resolve_input(work, "id:missing"))


class ManifestTest(unittest.TestCase):
    def test_identify_plc_when_tree_mounted(self):
        if not os.path.exists(PLC):
            self.skipTest("P2IM firmware tree is not mounted")
        image = oracle.ElfImage(PLC)
        base, sp, reset = image.vector_table()
        self.assertEqual(base, 0x08000000)
        self.assertTrue(0x1FFF0000 <= sp < 0x40000000)
        self.assertTrue(0x08000000 <= reset < 0x08200000)
        self.assertEqual(image.family_scores()["stm32f4"] > 0, True)
        self.assertEqual(image.e_machine, 40)

    def test_board_table_covers_ten_targets(self):
        self.assertEqual(len(oracle.BOARD_FOR_TARGET), 10)
        self.assertEqual(oracle.BOARD_FOR_TARGET["Soldering_Iron"][0], "NUCLEO-F103RB")
        self.assertEqual(oracle.BOARD_FOR_TARGET["CNC"][0], "STM32F429I-Discovery")
        self.assertEqual(oracle.BOARD_FOR_TARGET["CNC"][1], "STM32F429ZI")


class SharedGlobalTest(unittest.TestCase):
    def test_thumb_literal_and_pc_relative_parse(self):
        self.assertEqual(oracle.thumb_literal_addr(0x08003F30, 12), 0x08003F40)
        self.assertEqual(oracle.pc_relative_load("ldr", "r3, [pc, #12]"), ("pool", 12))
        self.assertEqual(oracle.pc_relative_load("ldr.w", "r3, [pc, #0x10]"), ("pool", 16))
        self.assertIsNone(oracle.pc_relative_load("ldr", "r3, [r0, #4]"))
        self.assertEqual(oracle.pc_relative_load("ldr", "r0, =0x20001000"), ("abs", 0x20001000))

    def test_shared_global_is_not_a_call_edge(self):
        xrefs = [
            {"function": "UART_Receive_IT", "insn": 0x8001000, "loaded": 0x20001000},
            {"function": "Modbus::poll", "insn": 0x8002000, "loaded": 0x20001020},
        ]
        objects = [
            {"name": "rx_buffer", "addr": 0x20001000, "size": 64},
            {"name": "rx_callback", "addr": 0x20001040, "size": 16},
        ]
        links = oracle.link_shared_globals(
            xrefs, objects, source_side={"UART_Receive_IT"}, sink_side={"Modbus::poll"})
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["kind"], "via_shared_global")
        self.assertFalse(links[0]["call_edge"])
        self.assertEqual(links[0]["interrupt_write_side"], ["UART_Receive_IT"])
        self.assertEqual(links[0]["main_consume_side"], ["Modbus::poll"])
        self.assertIn("rx_callback", [item["symbol"] for item in links[0]["adjacent"]])

    def test_adjacent_callback_keeps_its_own_referencers(self):
        xrefs = [
            {"function": "HAL_UART_RxCpltCallback", "insn": 0x8003F30, "loaded": 0x20001040},
            {"function": "Modbus::process_FC1", "insn": 0x800094C, "loaded": 0x20001000},
            {"function": "Modbus::poll", "insn": 0x8000900, "loaded": 0x20001008},
        ]
        objects = [
            {"name": "au8Buffer", "addr": 0x20001000, "size": 64},
            {"name": "rx_callback", "addr": 0x20001040, "size": 16},
        ]
        links = oracle.link_shared_globals(
            xrefs, objects,
            source_side={"HAL_UART_RxCpltCallback"},
            sink_side={"Modbus::process_FC1", "Modbus::poll"})
        by_name = {item["symbol"]: item for item in links}
        self.assertIn("rx_callback", by_name)
        self.assertIn("au8Buffer", by_name)
        self.assertFalse(by_name["rx_callback"]["call_edge"])
        self.assertIn("au8Buffer", [item["symbol"] for item in by_name["rx_callback"]["adjacent"]])

    def test_mapping_symbol_does_not_steal_the_named_object(self):
        xrefs = [
            {"function": "HAL_UART_RxCpltCallback", "insn": 0x8003F30, "loaded": 0x20001040},
            {"function": "Modbus::process_FC1", "insn": 0x800094C, "loaded": 0x20001000},
        ]
        objects = [
            {"name": "$d", "addr": 0x20001000, "size": 4},
            {"name": "au8Buffer", "addr": 0x20001000, "size": 64},
            {"name": "$d", "addr": 0x20001040, "size": 4},
            {"name": "rx_callback", "addr": 0x20001040, "size": 16},
        ]
        links = oracle.link_shared_globals(
            xrefs, objects,
            source_side={"HAL_UART_RxCpltCallback"},
            sink_side={"Modbus::process_FC1"})
        names = [item["symbol"] for item in links]
        self.assertNotIn("$d", names)
        self.assertIn("rx_callback", names)
        self.assertIn("au8Buffer", names)

    def test_objdump_keeps_a_three_letter_add_mnemonic(self):
        parsed = oracle.parse_objdump_line(" 80006fe:\tadd\tr5, r4\n")
        self.assertEqual(parsed, (0x080006FE, "add", "r5, r4"))
        with_bytes = oracle.parse_objdump_line(" 80006fe:\t4415\tadd\tr5, r4\n")
        self.assertEqual(with_bytes[1:], ("add", "r5, r4"))

    def _owner(self, addr):
        spans = (
            (0x1000, 0x1800, "setup"),
            (0x2000, 0x2800, "poll"),
            (0x3000, 0x3800, "Modbus::process_FC3(unsigned short*, unsigned char)"),
            (0x4000, 0x4800, "Modbus::getRxBuffer()"),
        )
        for start, end, name in spans:
            if start <= addr < end:
                return {"addr": start, "size": end - start, "name": name}
        return None

    def test_indexed_member_store_reaches_a_later_object_without_a_call_edge(self):
        slave = {"name": "slave", "addr": 0x20000100, "size": 0x30}
        callback = {"name": "rx_callback", "addr": 0x20000140, "size": 0x10}
        objects = [slave, callback]
        insns = {
            0x1000: ("ldr", "r0, =0x20000100"),
            0x1004: ("bl", "2000 <poll>"),
            0x2000: ("mov", "r4, r0"),
            0x2004: ("mov", "r0, r4"),
            0x2008: ("bl", "3000 <Modbus::process_FC3>"),
            0x3000: ("mov", "r4, r0"),
            0x3004: ("ldrb.w", "r3, [r4, #16]"),
            0x3008: ("adds", "r7, r4, r3"),
            0x300C: ("strb", "r1, [r7, #8]"),
        }
        sites = oracle.indexed_member_sites(insns, self._owner, objects, None)
        matched = [site for site in sites if site["function"].startswith("Modbus::process_FC3")]
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["max_index"], 255)
        self.assertEqual(matched[0]["member_offset"], 8)
        self.assertLessEqual(callback["addr"], matched[0]["reach_hi"])
        links = [{
            "symbol": "rx_callback", "address": "0x20000140", "kind": "via_shared_global",
            "call_edge": False, "referencers": [{"function": "HAL_UART_RxCpltCallback", "sites": ["0x1"]}],
            "interrupt_write_side": ["HAL_UART_RxCpltCallback"], "main_consume_side": [], "adjacent": [],
        }]
        merged = oracle.merge_indexed_reach(links, matched, objects)
        names = [item["function"] for item in merged[0]["referencers"]]
        self.assertIn("Modbus::process_FC3(unsigned short*, unsigned char)", names)
        self.assertFalse(merged[0]["call_edge"])
        self.assertFalse(merged[0]["indexed_reach"][0]["call_edge"])
        self.assertEqual(merged[0]["indexed_reach"][0]["base_symbol"], "slave")

    def test_a_small_index_compare_does_not_reach_past_the_object(self):
        slave = {"name": "slave", "addr": 0x20000100, "size": 0x80}
        callback = {"name": "rx_callback", "addr": 0x20000214, "size": 0x28}
        objects = [slave, callback]
        insns = {
            0x1000: ("ldr", "r0, =0x20000100"),
            0x1004: ("bl", "4000 <getRxBuffer>"),
            0x4000: ("mov", "r4, r0"),
            0x4004: ("ldrb.w", "r5, [r4, #73]"),
            0x4008: ("add", "r5, r4"),
            0x400C: ("strb", "r0, [r5, #9]"),
            0x4010: ("ldrb.w", "r3, [r4, #73]"),
            0x4014: ("adds", "r3, #1"),
            0x4018: ("uxtb", "r3, r3"),
            0x401C: ("cmp", "r3, #63"),
        }
        sites = oracle.indexed_member_sites(insns, self._owner, objects, None)
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0]["max_index"], 63)
        self.assertLess(sites[0]["reach_hi"], callback["addr"])
        links = [{
            "symbol": "rx_callback", "address": "0x20000214", "kind": "via_shared_global",
            "call_edge": False, "referencers": [{"function": "HAL_UART_RxCpltCallback", "sites": ["0x1"]}],
            "adjacent": [],
        }]
        merged = oracle.merge_indexed_reach(links, sites, objects)
        self.assertEqual([item["function"] for item in merged[0]["referencers"]], ["HAL_UART_RxCpltCallback"])
        self.assertNotIn("indexed_reach", merged[0])

    def test_modbus_crc16_accepts_a_known_vector_and_rejects_a_bad_tail(self):
        body = b"123456789"
        crc = oracle.crc16_modbus(body)
        self.assertEqual(crc, 0x4B37)
        good = body + bytes((crc & 0xFF, (crc >> 8) & 0xFF))
        self.assertIsNone(oracle.validate_proposed_seed(good, "modbus_rtu"))
        self.assertEqual(oracle.validate_proposed_seed(good[:-1] + b"\x00", "modbus_rtu"), "crc16")
        self.assertIsNone(oracle.validate_proposed_seed(b"\x01\x02", "raw"))
        self.assertEqual(oracle.validate_proposed_seed(b"", "raw"), "length")

    def test_prepare_keeps_a_short_seed_beside_the_random_seed(self):
        with tempfile.TemporaryDirectory() as root:
            seed_path, short_path = oracle.write_initial_seeds(root, "ab" * 32, 256)
            self.assertEqual(os.path.getsize(seed_path), 256)
            self.assertEqual(open(short_path, "rb").read(), oracle.SHORT_SEED)
            oracle.write_initial_seeds(root, "cd" * 32, 32)
            self.assertEqual(os.path.getsize(seed_path), 256)

    def test_reg_acc_collection_does_not_stop_at_the_first_file(self):
        with tempfile.TemporaryDirectory() as root:
            work = oracle.Work(root, "Reflow_Oven")
            base = os.path.join(work.dir, "0")
            nested = os.path.join(base, "depth:2,stage:2.0")
            os.makedirs(nested)
            open(os.path.join(base, "reg_acc-depth:1,stage:1.0"), "w").write("early\n")
            open(os.path.join(nested, "reg_acc-depth:2,stage:2.0"), "w").write("late\n")
            found = oracle.find_round_artifacts(work, "0", "reg_acc")
            self.assertEqual(
                {os.path.basename(path) for path in found},
                {"reg_acc-depth:1,stage:1.0", "reg_acc-depth:2,stage:2.0"},
            )


class SweepTest(unittest.TestCase):
    def test_sweep_never_matches_this_process(self):
        with tempfile.TemporaryDirectory() as root:
            work = oracle.Work(root, "PLC")
            work.dir = os.path.join(root, "plc")
            os.makedirs(work.dir, exist_ok=True)
            work.meta = {"elf": {"path": os.path.join(work.dir, "PLC.elf")}, "board": {"qemu_board": "x", "mcu": "y"}}
            self.assertEqual(oracle.sweep_work(work), [])


if __name__ == "__main__":
    unittest.main()
