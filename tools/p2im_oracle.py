#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""p2im_oracle.py - host-owned execution and evidence helper for the mcu-p2im campaign.

This tool is the only component that touches the P2IM toolchain.  It runs inside the
Linux (WSL2) guest, keeps every runtime directory on a native short path, and never
edits a firmware image: the ELF is copied byte-for-byte and its SHA256 is recorded in
every artifact that refers to it.

Design rules that the TypeScript layer relies on:

* every subcommand prints exactly one JSON object on stdout and exits 0 on success,
  3 on a refused precondition, 4 on a tool failure, 5 on a timeout whose partial
  evidence was still written;
* free text never carries instruction authority; every artifact says
  ``instruction_authority: "none"``;
* processes are started in their own session, recorded in ``<work>/run/owned.json``
  before they can spawn children, and the whole group is signalled on timeout;
* strings that belong to the blind-test truth set (CVE ids, CWE ids, P2IM Table 5)
  are rejected rather than passed through.

Subcommands: identify, identify-all, prepare, smoke, me, fuzz, status, crashes, replay, contrast,
extract-sources, slice-paths, admit-seed, gdb-watch, cleanup, bbl-coverage, aggregate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time
import uuid

VERSION = "0.2.0"
SCHEMA = "mcu-p2im/oracle-0.2"

DEFAULT_WORK_ROOT = os.environ.get("P2IM_WORK_ROOT", "/tmp/fa-p2im")
DEFAULT_TOOLS_ROOT = os.environ.get("P2IM_TOOLS_ROOT", os.path.expanduser("~/p2im-tools"))
DEFAULT_P2IM_ROOT = os.environ.get("P2IM_ROOT", os.path.expanduser("~/deps/p2im"))
DEFAULT_HOEDUR_ROOT = os.environ.get("HOEDUR_EXPERIMENTS_ROOT", os.path.expanduser("~/deps/hoedur-experiments"))
DEFAULT_OBJDUMP = os.environ.get("ARM_OBJDUMP", "/usr/bin/arm-none-eabi-objdump")
DEFAULT_NM = os.environ.get("ARM_NM", "/usr/bin/arm-none-eabi-nm")
DEFAULT_READELF = os.environ.get("ARM_READELF", "/usr/bin/arm-none-eabi-readelf")

# The four QEMU board/MCU pairs the P2IM toolchain ships.  The firmware build files
# (externals/p2im-real_firmware/<target>/README.md) select the pair; identify()
# cross-checks the family against MMIO bases actually present in the image.
BOARD_FOR_TARGET = {
    "PLC": ("STM32F429I-Discovery", "STM32F429ZI", "stm32f4"),
    "CNC": ("STM32F429I-Discovery", "STM32F429ZI", "stm32f4"),
    "Gateway": ("NUCLEO-F103RB", "STM32F103RB", "stm32f1"),
    "Reflow_Oven": ("NUCLEO-F103RB", "STM32F103RB", "stm32f1"),
    "Robot": ("NUCLEO-F103RB", "STM32F103RB", "stm32f1"),
    "Drone": ("NUCLEO-F103RB", "STM32F103RB", "stm32f1"),
    "Console": ("FRDM-K64F", "MK64FN1M0VLL12", "k64"),
    "Heat_Press": ("Arduino-Due", "SAM3X8E", "sam3x"),
    "Steering_Control": ("Arduino-Due", "SAM3X8E", "sam3x"),
    "Soldering_Iron": ("NUCLEO-F103RB", "STM32F103RB", "stm32f1"),
}

FAMILY_MARKERS = {
    "stm32f4": (0x40023800, 0x40020000, 0x40004800, 0x40004400, 0x40023C00),
    "stm32f1": (0x40021000, 0x40010800, 0x40013800, 0x40005400, 0x40010000),
    "sam3x": (0x400E0600, 0x400E0E00, 0x400E0800, 0x400E1200, 0x400E1000),
    "k64": (0x40047000, 0x400FF000, 0x4006A000, 0x4006C000, 0x40048000),
}

# Copy/format sinks plus the libc aliases newlib emits.  Command execution sinks are
# deliberately absent: a bare-metal MCU image has no shell to inject into.
SINK_SYMBOLS = {
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "snprintf", "vsprintf", "vsnprintf", "sscanf", "vsscanf",
    "__aeabi_memcpy", "__aeabi_memcpy4", "__aeabi_memcpy8", "__aeabi_memmove",
    "__aeabi_memset", "__aeabi_memset4", "_memcpy", "_strcpy",
}

# Truth-set tokens that must never enter an Agent prompt or an artifact bound for it.
LEAK_PATTERN = re.compile(r"(CVE-\d{4}-\d+|CWE-\d+|Table\s*5|Table5)", re.IGNORECASE)

EXIT_OK = 0
EXIT_REFUSED = 3
EXIT_FAILED = 4
EXIT_TIMEOUT = 5


# --------------------------------------------------------------------------- io

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path: str, value) -> str:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    body = json.dumps(value, indent=2, sort_keys=False) + "\n"
    fd, tmp = tempfile.mkstemp(dir=directory or ".", prefix=".tmp-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(body)
    os.replace(tmp, path)
    return sha256_bytes(body.encode("utf-8"))


def read_json(path: str):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def append_jsonl(path: str, value) -> str:
    body = json.dumps(value, sort_keys=True) + "\n"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(body)
    return sha256_bytes(body.encode("utf-8"))


def fail(code: int, message: str, **extra):
    payload = {"schema": SCHEMA, "ok": False, "error": message, **extra}
    print(json.dumps(payload, indent=2))
    sys.exit(code)


def ok(**fields):
    payload = {"schema": SCHEMA, "ok": True, "tool_version": VERSION, **fields}
    print(json.dumps(payload, indent=2))
    sys.exit(EXIT_OK)


# ------------------------------------------------------------------------ ELF

class ElfImage:
    """Minimal little-endian ELF32 reader: sections, segments, symbols, strings."""

    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    PT_LOAD = 1
    STT_FUNC = 2

    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        with open(self.path, "rb") as handle:
            self.data = handle.read()
        if self.data[:4] != b"\x7fELF":
            raise ValueError("not an ELF image: %s" % self.path)
        if self.data[4] != 1:
            raise ValueError("only ELF32 images are supported")
        self.endian = "<" if self.data[5] == 1 else ">"
        (self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff, self.e_shoff,
         self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum, self.e_shentsize,
         self.e_shnum, self.e_shstrndx) = struct.unpack_from(self.endian + "HHIIIIIHHHHHH", self.data, 16)
        self._sections = None
        self._segments = None
        self._symbols = None

    # -- raw tables -------------------------------------------------------
    @property
    def sections(self):
        if self._sections is None:
            shstr = b""
            raw = []
            for index in range(self.e_shnum):
                base = self.e_shoff + index * self.e_shentsize
                fields = struct.unpack_from(self.endian + "IIIIIIIIII", self.data, base)
                raw.append({"name_off": fields[0], "type": fields[1], "flags": fields[2],
                            "addr": fields[3], "offset": fields[4], "size": fields[5],
                            "link": fields[6], "info": fields[7], "addralign": fields[8],
                            "entsize": fields[9]})
            if self.e_shstrndx < len(raw):
                shstr = self._slice(raw[self.e_shstrndx])
            for entry in raw:
                entry["name"] = self._cstring(shstr, entry["name_off"])
            self._sections = raw
        return self._sections

    @property
    def segments(self):
        if self._segments is None:
            out = []
            for index in range(self.e_phnum):
                base = self.e_phoff + index * self.e_phentsize
                fields = struct.unpack_from(self.endian + "IIIIIIII", self.data, base)
                out.append({"type": fields[0], "offset": fields[1], "vaddr": fields[2],
                            "paddr": fields[3], "filesz": fields[4], "memsz": fields[5],
                            "flags": fields[6], "align": fields[7]})
            self._segments = out
        return self._segments

    def _slice(self, section) -> bytes:
        start = section["offset"]
        return self.data[start:start + section["size"]]

    @staticmethod
    def _cstring(blob: bytes, offset: int) -> str:
        if offset < 0 or offset >= len(blob):
            return ""
        end = blob.find(b"\x00", offset)
        if end < 0:
            end = len(blob)
        return blob[offset:end].decode("utf-8", "replace")

    def section(self, name: str):
        for entry in self.sections:
            if entry["name"] == name:
                return entry
        return None

    @property
    def symbols(self):
        if self._symbols is None:
            out = []
            for section in self.sections:
                if section["type"] != self.SHT_SYMTAB:
                    continue
                if section["link"] >= len(self.sections):
                    continue
                strings = self._slice(self.sections[section["link"]])
                blob = self._slice(section)
                entry_size = section["entsize"] or 16
                for offset in range(0, len(blob) - entry_size + 1, entry_size):
                    name_off, value, size, info, other, shndx = struct.unpack_from(
                        self.endian + "IIIBBH", blob, offset)
                    out.append({"name": self._cstring(strings, name_off), "value": value,
                                "size": size, "info": info, "shndx": shndx,
                                "type": info & 0xF, "bind": info >> 4})
            self._symbols = out
        return self._symbols

    # -- derived facts ----------------------------------------------------
    def vaddr_to_offset(self, vaddr: int):
        for segment in self.segments:
            if segment["type"] == self.PT_LOAD and segment["vaddr"] <= vaddr < segment["vaddr"] + segment["filesz"]:
                return segment["offset"] + (vaddr - segment["vaddr"])
        return None

    def read_vaddr(self, vaddr: int, size: int) -> bytes:
        offset = self.vaddr_to_offset(vaddr)
        if offset is None:
            raise ValueError("vaddr 0x%x is not file-backed" % vaddr)
        return self.data[offset:offset + size]

    def word_at(self, vaddr: int) -> int:
        return struct.unpack_from(self.endian + "I", self.read_vaddr(vaddr, 4))[0]

    def alloc_sections(self):
        return [entry for entry in self.sections if entry["flags"] & 0x2 and entry["size"] > 0]

    def flash_base(self) -> int:
        """Lowest loadable address: the Cortex-M vector table is usually not SHF_EXECINSTR."""
        alloc = [entry for entry in self.alloc_sections() if entry["type"] != 8]
        if not alloc:
            return 0
        return min(entry["addr"] for entry in alloc)

    def ram_base(self) -> int:
        writable = [entry for entry in self.alloc_sections() if entry["flags"] & 0x1]
        if not writable:
            return 0
        return min(entry["addr"] for entry in writable)

    def vector_table(self):
        """(base, initial_sp, reset_handler) for the first plausible Cortex-M vector table.

        A candidate must start with a stack pointer inside 0x20000000..0x3fffffff and a
        reset word whose thumb address lands inside an executable section.  Scanning the
        loadable sections keeps this independent of linker-script naming.
        """
        exec_ranges = [(entry["addr"], entry["addr"] + entry["size"])
                       for entry in self.alloc_sections() if entry["flags"] & 0x4]
        candidates = sorted({entry["addr"] for entry in self.alloc_sections() if entry["type"] != 8})
        for base in candidates:
            try:
                sp = self.word_at(base)
                reset = self.word_at(base + 4)
            except ValueError:
                continue
            thumb = reset & ~1
            if not (0x1FFF0000 <= sp < 0x40000000):
                continue
            if any(start <= thumb < end for start, end in exec_ranges):
                return base, sp, thumb
        return None, None, None

    def family_scores(self):
        blob = b""
        for name in (".text", ".rodata", ".data", ".isr_vector"):
            section = self.section(name)
            if section is not None and section["type"] != 8:  # not NOBITS
                blob += self._slice(section)
        scores = {}
        for family, markers in FAMILY_MARKERS.items():
            scores[family] = sum(blob.count(struct.pack(self.endian + "I", marker)) for marker in markers)
        return scores


# ----------------------------------------------------------------- process control

class OwnedRuns:
    """Process groups started by this tool, persisted so a later cleanup can sweep them."""

    def __init__(self, work: str):
        self.work = work
        self.path = os.path.join(work, "run", "owned.json")
        self.entries = []
        if os.path.exists(self.path):
            try:
                self.entries = read_json(self.path)
            except Exception:
                self.entries = []

    def flush(self):
        write_json(self.path, self.entries)

    def register(self, pgid: int, label: str, command):
        self.entries.append({"pgid": pgid, "label": label, "started_at": time.time(),
                             "command": [str(part) for part in command]})
        self.flush()

    def forget(self, pgid: int):
        self.entries = [entry for entry in self.entries if entry.get("pgid") != pgid]
        self.flush()


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _signal_group(pgid: int, sig: int) -> bool:
    try:
        os.killpg(pgid, sig)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return False


def spawn_bounded(command, cwd, env, timeout_s, output_path, owned=None, label="run", stop_when=None):
    """Run one command in its own session; on timeout or stop_when signal the whole group.

    Returns (rc, timed_out, duration_s).  rc is None when the command never started.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    started = time.monotonic()
    with open(output_path, "wb") as handle:
        try:
            proc = subprocess.Popen(command, cwd=cwd, env=env, stdout=handle, stderr=subprocess.STDOUT,
                                    start_new_session=True, stdin=subprocess.DEVNULL)
        except OSError as exc:
            handle.write(("spawn failed: %s\n" % exc).encode("utf-8"))
            return None, False, 0.0
        pgid = os.getpgid(proc.pid)
        if owned is not None:
            owned.register(pgid, label, command)
        timed_out = False
        stopped_early = False
        if stop_when is None:
            try:
                proc.wait(timeout=timeout_s)
            except subprocess.TimeoutExpired:
                timed_out = True
        else:
            deadline = started + max(0.1, float(timeout_s))
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                try:
                    proc.wait(timeout=min(0.5, remaining))
                    break
                except subprocess.TimeoutExpired:
                    if stop_when():
                        stopped_early = True
                        break
        if timed_out or stopped_early:
            _signal_group(pgid, signal.SIGINT)
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                _signal_group(pgid, signal.SIGKILL)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
        rc = proc.returncode
        # A surviving child that ignored SIGINT would still hold the group; sweep it.
        if _alive(pgid):
            _signal_group(pgid, signal.SIGKILL)
        if owned is not None:
            owned.forget(pgid)
    return rc, timed_out, round(time.monotonic() - started, 3)


def tool_env(extra=None):
    env = dict(os.environ)
    env.update({
        "AFL_SKIP_CPUFREQ": "1",
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
        "AFL_NO_AFFINITY": "1",
        "AFL_SKIP_CRASHES": "1",
        "AFL_NO_FORKSRV": "",
        "PYTHONUNBUFFERED": "1",
    })
    # The QEMU shim drops this; AFL itself never needs the bundled 2017 libs.
    env.pop("LD_LIBRARY_PATH", None)
    if extra:
        env.update(extra)
    return env


# ------------------------------------------------------------------- workspace

class Work:
    def __init__(self, root: str, target: str):
        self.root = os.path.abspath(root)
        self.target = target
        self.slug = target.lower().replace("_", "-")
        self.dir = os.path.join(self.root, self.slug)
        self.meta_path = os.path.join(self.dir, "meta.json")
        self.meta = read_json(self.meta_path) if os.path.exists(self.meta_path) else None

    @property
    def elf(self):
        return self.meta["elf"]["path"] if self.meta else os.path.join(self.dir, self.target + ".elf")

    @property
    def board(self):
        return self.meta["board"]["qemu_board"]

    @property
    def mcu(self):
        return self.meta["board"]["mcu"]

    @property
    def cfg_dir(self):
        return os.path.join(self.dir, "cfg")

    @property
    def owned(self):
        os.makedirs(os.path.join(self.dir, "run"), exist_ok=True)
        return OwnedRuns(self.dir)

    def require(self):
        if not self.meta or not os.path.exists(self.elf):
            fail(EXIT_REFUSED, "target %s is not prepared under %s" % (self.target, self.dir),
                 hint="run: p2im_oracle.py prepare --target %s --elf <path>" % self.target)
        return self.meta

    def cfg_path(self, name: str) -> str:
        return os.path.join(self.cfg_dir, name + ".cfg")

    def execution_env(self):
        """QEMU environment for this target. The forkserver PC is opt-in and never logged."""
        extra = {}
        pc = (self.meta or {}).get("auto_forkserver_pc")
        if pc:
            extra["P2IM_AUTO_FORKSERVER_PC"] = str(pc)
        return tool_env(extra)

    def write_fuzz_cfg(self, name: str, output_dir: str, afl_bin: str, base: str, input_dir: str | None = None, tools_root: str = DEFAULT_TOOLS_ROOT) -> str:
        inputs = input_dir or os.path.join(self.dir, "inputs")
        body = f"""[DEFAULT]
base        = {base}
program     = {self.target}
run         = 0
working_dir = {self.dir}

[afl]
bin         = {afl_bin}
timeout     = 150+
input       = {inputs}
output      = {output_dir}

[cov]
count_hang  = True
bbl_cov_read_sz = 20000000
timeout     = 1

[qemu]
bin         = {self.qemu_shim()}
log         = unimp,guest_errors,int

[program]
board       = {self.board}
mcu         = {self.mcu}
img         = {self.elf}

[model]
retry_num   = 3
peri_addr_range = 512
objdump     = {DEFAULT_OBJDUMP}
bin         = {os.path.join(tools_root, "scripts", "me")}
log_file    = {self.dir}/me.log
"""
        os.makedirs(self.cfg_dir, exist_ok=True)
        path = self.cfg_path(name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(body)
        return path

    def qemu_shim(self) -> str:
        return os.path.join(self.root, "bin", "qemu-system-gnuarmeclipse")

    def qemu_target(self) -> str | None:
        shim = self.qemu_shim()
        if not os.path.isfile(shim):
            return None
        with open(shim, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        match = re.search(r'^exec\s+"([^"]+)"\s+"\$@"\s*$', text, re.M)
        return match.group(1) if match else None

    def require_qemu(self, tools_root: str | None = None) -> str:
        shim = self.qemu_shim()
        if not os.path.isfile(shim) or not os.access(shim, os.X_OK):
            fail(EXIT_REFUSED, "QEMU shim is missing or not executable: %s" % shim,
                 shim=shim, hint="run: p2im_oracle.py prepare --target %s --elf <path>" % self.target)
        real_qemu = self.qemu_target()
        if not real_qemu and tools_root:
            real_qemu = os.path.join(tools_root, "qemu", "qemu-system-gnuarmeclipse")
        if not real_qemu or not os.path.isfile(real_qemu) or not os.access(real_qemu, os.X_OK):
            fail(EXIT_REFUSED, "QEMU binary is missing or not executable: %s" % (real_qemu or shim),
                 shim=shim, qemu=real_qemu,
                 hint="build and install qemu-system-gnuarmeclipse into $P2IM_TOOLS_ROOT/qemu/")
        return real_qemu

    def install_shim(self, real_qemu: str) -> str:
        shim = self.qemu_shim()
        os.makedirs(os.path.dirname(shim), exist_ok=True)
        body = (
            "#!/bin/sh\n"
            "# P2IM QEMU shim written by p2im_oracle.py.\n"
            "# The p2im-tools/qemu directory still ships a 2017 glib that predates the\n"
            "# rebuilt qemu-system-gnuarmeclipse; loading it breaks with\n"
            "# 'undefined symbol: g_string_free_and_steal'.  Drop the path for QEMU only.\n"
            "unset LD_LIBRARY_PATH\n"
            'exec "%s" "$@"\n' % real_qemu
        )
        existing = None
        if os.path.exists(shim):
            with open(shim, "r", encoding="utf-8", errors="replace") as handle:
                existing = handle.read()
        if existing != body:
            with open(shim, "w", encoding="utf-8") as handle:
                handle.write(body)
            os.chmod(shim, 0o755)
        return shim

    def round_dirs(self):
        if not os.path.isdir(self.dir):
            return []
        out = []
        for name in os.listdir(self.dir):
            full = os.path.join(self.dir, name)
            if os.path.isdir(full) and re.match(r"^\d+(\.|$)", name) and \
                    os.path.exists(os.path.join(full, "peripheral_model.json")):
                out.append(name)
        def sort_key(name):
            head = name.split(".")
            major = int(head[0])
            if major == 0 and len(head) > 1:
                try:
                    mtime = os.stat(os.path.join(self.dir, name, "peripheral_model.json")).st_mtime_ns
                except OSError:
                    mtime = 0
                return (0, 1, mtime, name)
            return (major, 0, 0, name)
        return sorted(out, key=sort_key)

    def latest_round(self):
        rounds = self.round_dirs()
        return rounds[-1] if rounds else None

    def model_path(self, round_name: str) -> str:
        return os.path.join(self.dir, round_name, "peripheral_model.json")

    def segments_dir(self):
        path = os.path.join(self.dir, "segments")
        os.makedirs(path, exist_ok=True)
        return path

    def evidence_dir(self):
        path = os.path.join(self.dir, "evidence")
        os.makedirs(path, exist_ok=True)
        return path

    def analysis_dir(self):
        path = os.path.join(self.dir, "analysis")
        os.makedirs(path, exist_ok=True)
        return path

    def last_segment(self):
        directory = self.segments_dir()
        segs = sorted(name for name in os.listdir(directory) if re.match(r"^s\d+\.json$", name))
        return segs[-1][:-5] if segs else None


# ------------------------------------------------------------------- P2IM bits

def parse_fuzzer_stats(path: str):
    stats = {}
    if not os.path.exists(path):
        return stats
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if re.match(r"^-?\d+$", value):
                stats[key] = int(value)
            elif re.match(r"^-?\d+\.\d+$", value):
                stats[key] = float(value)
            else:
                stats[key] = value
    return stats


def crash_files(output_dir: str):
    directory = os.path.join(output_dir, "crashes")
    if not os.path.isdir(directory):
        return []
    out = []
    for name in sorted(os.listdir(directory)):
        if name == "README.txt" or name.startswith("."):
            continue
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        match = re.search(r"ret_v:(0x[0-9a-fA-F]+)", name)
        out.append({"id": name, "path": path, "bytes": os.path.getsize(path),
                    "sha256": sha256_file(path), "ret_v": match.group(1) if match else None})
    return out


def queue_files(output_dir: str):
    directory = os.path.join(output_dir, "queue")
    if not os.path.isdir(directory):
        return []
    return [os.path.join(directory, name) for name in sorted(os.listdir(directory))
            if os.path.isfile(os.path.join(directory, name)) and not name.startswith(".")]


def read_model_summary(path: str):
    model = read_json(path)
    body = model.get("model", {})
    peripherals = []
    dr_registers = []
    cr_registers = []
    for base_hex, entry in sorted(body.items()):
        base = int(base_hex, 16)
        regs = entry.get("regs", [])
        dr_slots = [index for index, reg in enumerate(regs) if reg.get("type") == 3]
        cr_slots = [index for index, reg in enumerate(regs) if reg.get("type") in (1, 4)]
        reg_size = register_stride(entry.get("reg_size", 4))
        peripherals.append({"base": base_hex, "reg_size": reg_size,
                            "registers": len(regs), "dr_slots": dr_slots, "events": len(entry.get("events", {}))})
        for index in dr_slots:
            dr_registers.append({"peripheral_base": base_hex, "register": "0x%08x" % (base + index * reg_size),
                                 "slot": index, "reg_size": reg_size, "dr_bytes": entry.get("DR_bytes_num", 2)})
        for index in cr_slots:
            cr_registers.append({"peripheral_base": base_hex, "register": "0x%08x" % (base + index * reg_size),
                                 "slot": index, "reg_size": reg_size, "type": regs[index].get("type")})
    return {
        "path": path,
        "sha256": sha256_file(path),
        "peripheral_count": len(body),
        "peripherals": peripherals,
        "dr_registers": dr_registers,
        "cr_registers": cr_registers,
        "interrupts": model.get("interrupts", []),
        "aup": model.get("access_to_unmodeled_peri"),
    }


REG_ACC_RE = re.compile(r"^\((0x[0-9a-fA-F]+), (\d+), ([rw]), ([0-9a-fA-Fx]+)\) in BBL \((0x[0-9a-fA-F]+), (0x[0-9a-fA-F]+)\) \[(.+)\]$")
TRACE_RE = re.compile(r"^BBL \((0x[0-9a-fA-F]+), (0x[0-9a-fA-F]+)\) \[(.+)\]$")


def parse_reg_acc(path: str):
    entries = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for lineno, line in enumerate(handle, 1):
            match = REG_ACC_RE.match(line.strip())
            if not match:
                continue
            entries.append({"address": match.group(1).lower(), "size": int(match.group(2)),
                            "op": match.group(3), "value": match.group(4),
                            "bbl_start": match.group(5).lower(), "bbl_end": match.group(6).lower(),
                            "function": match.group(7), "line": lineno})
    return entries


def parse_trace(path: str):
    entries = []
    if not os.path.exists(path):
        return entries
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = TRACE_RE.match(line.strip())
            if match:
                entries.append({"start": match.group(1).lower(), "end": match.group(2).lower(),
                                "function": match.group(3)})
    names = demangle({entry["function"] for entry in entries})
    for entry in entries:
        entry["function"] = names.get(entry["function"], entry["function"])
    return entries


def demangle(names):
    """QEMU prints the raw symbol table, nm -C prints demangled names; align them with c++filt."""
    unique = sorted({name for name in names if name})
    if not unique:
        return {}
    try:
        result = subprocess.run(["/usr/bin/c++filt"], input="\n".join(unique) + "\n",
                                capture_output=True, text=True, timeout=60)
        lines = result.stdout.splitlines()
        if len(lines) == len(unique):
            return dict(zip(unique, lines))
    except (OSError, subprocess.SubprocessError):
        pass
    return {name: name for name in unique}


def register_stride(value) -> int:
    """Model reg_size is the address step. K64 UART slots are 1 byte; a hardcoded 4 skips them."""
    try:
        stride = int(value)
    except (TypeError, ValueError):
        return 4
    return stride if stride > 0 else 4


def find_round_artifacts(work: Work, round_name: str, prefix: str):
    """Every file under the round (or archived rounds) whose name starts with prefix, including depth:*."""
    roots = [os.path.join(work.dir, round_name)]
    archive_root = os.path.join(work.dir, "rounds-archive")
    if os.path.isdir(archive_root):
        for snap in sorted(os.listdir(archive_root)):
            cand = os.path.join(archive_root, snap, round_name)
            if os.path.isdir(cand):
                roots.append(cand)
    found = []
    for directory in roots:
        if not os.path.isdir(directory):
            continue
        for root, dirs, files in os.walk(directory):
            dirs.sort()
            for name in files:
                if name.startswith(prefix):
                    found.append(os.path.join(root, name))
    return sorted(set(found))


def find_round_artifact(work: Work, round_name: str, prefix: str):
    found = find_round_artifacts(work, round_name, prefix)
    return found[0] if found else None


# ------------------------------------------------------------------ analysis

FUNC_LINE_RE = re.compile(r"^([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s+([A-Za-z])\s+(.*)$")
DISASM_PARSER_VERSION = 3
OBJDUMP_LABEL_RE = re.compile(r"^([0-9a-fA-F]+) <(.+)>:$")
# A raw instruction word is at least four hex digits. Three-letter mnemonics such as
# "add" are entirely hex characters and must not be discarded as a byte column.
_RAW_INSN_WORD = re.compile(r"[0-9a-fA-F]{4,8}")


def nm_functions(nm_bin: str, elf: str):
    """(addr, size, name) for defined function-like symbols, demangled when possible."""
    try:
        text = subprocess.run([nm_bin, "-C", "-S", "--defined-only", elf],
                              capture_output=True, text=True, timeout=120).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    out = []
    for line in text.splitlines():
        match = FUNC_LINE_RE.match(line.strip())
        if not match:
            continue
        addr = int(match.group(1), 16)
        size = int(match.group(2), 16)
        kind = match.group(3)
        name = match.group(4).strip()
        if kind not in "TtWw" or not name:
            continue
        out.append({"addr": addr, "size": size, "name": name})
    return out


def parse_objdump_line(line):
    """(addr, mnemonic, operands) for one objdump -d line, or None for labels and blanks.

    Accepts both `addr:\\tmnemonic\\toperands` and `addr:\\thexbytes\\tmnemonic\\toperands`.
    """
    head, sep, rest = line.partition(":")
    if not sep or not re.fullmatch(r"\s*[0-9a-fA-F]{4,8}", head):
        return None
    try:
        addr = int(head.strip(), 16)
    except ValueError:
        return None
    parts = [part.strip() for part in rest.split("\t") if part.strip()]
    if parts and _RAW_INSN_WORD.fullmatch(parts[0]):
        parts = parts[1:]
    if not parts:
        return None
    token = parts[0]
    mnemonic = token.split(" ")[0]
    operands = parts[1] if len(parts) > 1 else token[len(mnemonic):].strip()
    if " @" in operands:
        operands = operands.split(" @", 1)[0].strip()
    return addr, mnemonic, operands


def objdump_disasm(objdump: str, elf: str, cache_path: str | None = None):
    """Address -> (mnemonic, operands) over the whole image, cached by ELF hash."""
    digest = sha256_file(elf)
    if cache_path and os.path.exists(cache_path):
        try:
            cached = read_json(cache_path)
            if cached.get("elf_sha256") == digest and cached.get("parser") == DISASM_PARSER_VERSION and cached.get("insns"):
                return {int(key, 16): tuple(value) for key, value in cached["insns"].items()}, cached
        except Exception:
            pass
    try:
        text = subprocess.run([objdump, "-d", "--no-show-raw-insn", elf],
                              capture_output=True, text=True, timeout=300).stdout
    except (OSError, subprocess.SubprocessError):
        return {}, {"elf_sha256": digest, "insns": {}}
    insns = {}
    labels = {}
    for line in text.splitlines():
        label = OBJDUMP_LABEL_RE.match(line)
        if label:
            labels[int(label.group(1), 16)] = label.group(2)
            continue
        parsed = parse_objdump_line(line)
        if parsed is None:
            continue
        addr, mnemonic, operands = parsed
        insns[addr] = (mnemonic, operands)
    payload = {"elf_sha256": digest, "parser": DISASM_PARSER_VERSION,
               "insns": {"0x%x" % key: list(value) for key, value in insns.items()},
               "labels": {"0x%x" % key: value for key, value in labels.items()}}
    if cache_path:
        write_json(cache_path, payload)
    return insns, payload


INDIRECT_BRANCH = re.compile(r"^(blx|bx)$")
INDIRECT_LOAD = "ldr"


def is_indirect_transfer(mnemonic: str, operands: str) -> bool:
    mnemonic = mnemonic.lower()
    if mnemonic in ("blx", "bx", "bxj"):
        return bool(re.match(r"^r\d+$", operands.strip()))
    if mnemonic in ("mov", "add") and re.search(r"\bpc\b", operands) and "r15" not in operands:
        return bool(re.search(r"\bpc\b", operands))
    if mnemonic == "ldr" and operands.strip().startswith("pc"):
        return True
    return False


def build_call_graph(insns, functions):
    """Direct call edges and an address->function lookup over the symbol table."""
    by_addr = sorted(functions, key=lambda item: item["addr"])
    starts = [entry["addr"] for entry in by_addr]

    def owner(addr):
        import bisect
        index = bisect.bisect_right(starts, addr) - 1
        if index < 0:
            return None
        entry = by_addr[index]
        end = entry["addr"] + entry["size"] if entry["size"] else (
            by_addr[index + 1]["addr"] if index + 1 < len(by_addr) else 0xFFFFFFFF)
        return entry if entry["addr"] <= addr < end else None

    edges = {}
    for addr, (mnemonic, operands) in insns.items():
        if mnemonic.lower() not in ("bl", "blx"):
            continue
        match = re.match(r"^(0x)?([0-9a-fA-F]+)\s*<([^>]*)>", operands)
        if not match:
            continue
        target = int(match.group(2), 16)
        caller = owner(addr)
        callee = owner(target)
        if caller is None or callee is None:
            continue
        key = (caller["name"], callee["name"])
        entry = edges.setdefault(key, {"callsites": [], "target": target})
        entry["callsites"].append(addr)
    return edges, owner


def sink_evidence(insns, owner, functions, indirect_edges):
    """Sink candidate list: library copy/format calls plus hand-written loop stores."""
    sinks = []
    for addr, (mnemonic, operands) in insns.items():
        low = mnemonic.lower()
        if low not in ("bl", "blx"):
            continue
        match = re.match(r"^(?:0x)?([0-9a-fA-F]+)\s*<([^>]*)>", operands)
        if not match:
            continue
        target_name = match.group(2).split("+")[0].strip()
        caller = owner(addr)
        if caller is None or target_name not in SINK_SYMBOLS:
            continue
        sinks.append({"kind": "library_call", "function": caller["name"], "callee": target_name,
                      "callsite": "0x%x" % addr, "evidence": "%s -> %s" % (mnemonic, target_name)})
    back_edge_functions = set()
    loop_stores = {}
    for addr, (mnemonic, operands) in insns.items():
        low = mnemonic.lower()
        if low.startswith("b") and low not in ("bl", "blx", "bx", "bic", "bfi", "bfl", "bfc"):
            branch = re.match(r"^(?:0x)?([0-9a-fA-F]+)", operands)
            if branch and int(branch.group(1), 16) < addr:
                caller = owner(addr)
                if caller is not None:
                    back_edge_functions.add(caller["name"])
        if low in ("str", "strb", "strh"):
            caller = owner(addr)
            if caller is not None:
                loop_stores.setdefault(caller["name"], []).append(
                    {"addr": addr, "text": "%s %s" % (mnemonic, operands)})
    for name in sorted(back_edge_functions & set(loop_stores)):
        stores = loop_stores[name]
        sinks.append({"kind": "hand_loop_store", "function": name, "callee": None,
                      "callsite": "0x%x" % stores[0]["addr"],
                      "evidence": "%d stores in a loop, first: %s" % (len(stores), stores[0]["text"]),
                      "stores": ["0x%x: %s" % (store["addr"], store["text"]) for store in stores[:8]]})
    # Indexed stores: the store address is base + index register, the shape a bounds-check bug
    # needs.  A loop is not required: a ring-buffer write is often straight-line code.
    for addr, (mnemonic, operands) in insns.items():
        if mnemonic.lower() not in ("str", "strb", "strh"):
            continue
        if not re.match(r"^r\d+,\s*\[r\d+,\s*r\d+\]", operands):
            continue
        caller = owner(addr)
        if caller is None:
            continue
        sinks.append({"kind": "indexed_store", "function": caller["name"], "callee": None,
                      "callsite": "0x%x" % addr,
                      "evidence": "%s %s" % (mnemonic, operands)})
    for source, targets in indirect_edges.items():
        for target in targets:
            if target in SINK_SYMBOLS:
                sinks.append({"kind": "library_call_dynamic", "function": source, "callee": target,
                              "callsite": None, "evidence": "runtime indirect call edge"})
    return sinks


def simple_paths(graph, start, goals, max_depth=8, max_paths=8):
    """Depth-first simple call paths from start to any goal, shortest first.

    A source that is itself a sink still yields the zero-length path, but exploration
    continues so the interesting source->callee->sink chains are not masked.
    """
    results = [[start]] if start in goals else []
    stack = [(start, [start])]
    while stack and len(results) < max_paths * 4:
        node, path = stack.pop()
        if len(path) > max_depth:
            continue
        for target in sorted(graph.get(node, ())):
            if target in path:
                continue
            if target in goals:
                results.append(path + [target])
                continue
            stack.append((target, path + [target]))
    results.sort(key=len)
    return results[:max_paths]


def indirect_edges_from_trace(trace_entries, insns, owner):
    """Runtime indirect call edges: predecessor block ends in an indirect transfer."""
    edges = {}
    previous = None
    for entry in trace_entries:
        if previous is not None:
            end = int(previous["end"], 16)
            last = None
            for candidate in (end - 4, end - 2):
                if candidate in insns:
                    last = insns[candidate]
                    break
            if last and is_indirect_transfer(last[0], last[1]):
                source_func = previous["function"]
                target_func = entry["function"]
                if source_func and target_func and source_func != target_func:
                    edges.setdefault(source_func, set()).add(target_func)
        previous = entry
    return {key: sorted(value) for key, value in edges.items()}


def reachable_functions(work: Work, seed_path: str, round_name: str, timeout_s=30):
    """Functions executed by one seed, from a bounded QEMU trace replay."""
    trace_path = os.path.join(work.evidence_dir(), "tmp-trace.txt")
    out_path = os.path.join(work.evidence_dir(), "tmp-replay.log")
    for stale in (trace_path, out_path):
        if os.path.exists(stale):
            os.unlink(stale)
    command = [work.qemu_shim(), "-nographic", "-board", work.board, "-mcu", work.mcu,
               "-image", work.elf, "-pm-stage", "3", "-aflFile", seed_path,
               "-model-input", work.model_path(round_name), "-trace", trace_path]
    rc, timed_out, _ = spawn_bounded(command, work.dir, work.execution_env(), timeout_s, out_path,
                                     owned=work.owned, label="reach-trace")
    functions = []
    if os.path.exists(trace_path):
        seen = set()
        for entry in parse_trace(trace_path):
            name = entry["function"]
            if name not in seen:
                seen.add(name)
                functions.append(name)
    return {"seed": os.path.basename(seed_path), "sha256": sha256_file(seed_path),
            "exit_code": rc, "timed_out": timed_out, "functions": functions}


FAULT_RE = re.compile(r"illegal (read|write) at (0x[0-9a-fA-F]+)")
EXEC_PERI_RE = re.compile(r"guest_code_fetch\s+addr=(0x[0-9a-fA-F]+)(?:\s+pc=(0x[0-9a-fA-F]+))?")
BBL_PREFIX_RE = re.compile(r"^\[(?:0x)?([0-9a-fA-F]+),\s*(?:0x)?([0-9a-fA-F]+)\]")


def parse_fault(log_path: str):
    """Extract fault kind/address (including PM_EXEC_PERI 0x72 code fetch) and enclosing BBL from a QEMU log."""
    if not os.path.exists(log_path):
        return None
    fault = None
    bbl = None
    with open(log_path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            match = FAULT_RE.search(line)
            if match:
                fault = {"kind": match.group(1), "address": match.group(2).lower()}
                prefix = BBL_PREFIX_RE.match(line)
                if prefix:
                    bbl = {"start": "0x" + prefix.group(1).lower(), "end": "0x" + prefix.group(2).lower()}
                continue
            exec_match = EXEC_PERI_RE.search(line)
            if exec_match:
                fault = {"kind": "exec_peri", "address": hex(int(exec_match.group(1), 16))}
                if exec_match.group(2):
                    pc = hex(int(exec_match.group(2), 16))
                    bbl = {"start": pc, "end": pc}
    if fault is None:
        return None
    return {"fault": fault, "bbl": bbl}


# ----------------------------------------------------------------- commands

def cmd_identify(args):
    elf = os.path.abspath(args.elf)
    if not os.path.isfile(elf):
        fail(EXIT_REFUSED, "no such ELF: %s" % elf)
    image = ElfImage(elf)
    digest = sha256_file(elf)
    scores = image.family_scores()
    family = max(scores, key=lambda key: scores[key]) if scores else "unknown"
    target = args.target
    spec = BOARD_FOR_TARGET.get(target)
    board = args.board or (spec[0] if spec else None)
    mcu = args.mcu or (spec[1] if spec else None)
    expected_family = spec[2] if spec else None

    flash = image.flash_base()
    vector_base, initial_sp, reset = image.vector_table()

    svc_count = None
    if os.path.exists(DEFAULT_OBJDUMP):
        try:
            text = subprocess.run([DEFAULT_OBJDUMP, "-d", elf], capture_output=True, text=True,
                                  timeout=180).stdout
            svc_count = len(re.findall(r"\bsvc\s+(?:63|0x3f)\b", text))
        except (OSError, subprocess.SubprocessError):
            svc_count = None

    functions = [entry for entry in image.symbols if entry["type"] == ElfImage.STT_FUNC and entry["value"]]
    afl_call = sorted({entry["name"] for entry in image.symbols if "afl" in entry["name"].lower()})

    record = {
        "schema": "mcu-p2im/identity-0.2",
        "target": target,
        "source_path": elf,
        "sha256": digest,
        "bytes": os.path.getsize(elf),
        "elf": {
            "type": image.e_type, "machine": image.e_machine, "entry_raw": "0x%08x" % image.e_entry,
            "flash_base": "0x%08x" % flash if flash is not None else None,
            "ram_base": "0x%08x" % image.ram_base() if image.ram_base() is not None else None,
            "vector_table_base": "0x%08x" % vector_base if vector_base is not None else None,
            "vector_initial_sp": "0x%08x" % initial_sp if initial_sp is not None else None,
            "vector_reset": "0x%08x" % reset if reset is not None else None,
            "sections": [{"name": entry["name"], "addr": "0x%08x" % entry["addr"],
                          "size": entry["size"], "flags": entry["flags"]}
                         for entry in image.alloc_sections()][:12],
        },
        "symbols": {"function_count": len(functions), "afl_call_symbols": afl_call},
        "afl_call": {"svc_0x3f_count": svc_count, "present": bool(svc_count)},
        "family": {"scores": scores, "inferred": family, "expected": expected_family,
                   "matches": family == expected_family if expected_family else None},
        "board": {"qemu_board": board, "mcu": mcu,
                  "evidence": "firmware build config + ELF family markers"},
        "instruction_authority": "none",
    }
    if args.out:
        write_json(args.out, record)
    ok(identity=record)


def _read_os_release_first_line() -> str:
    if not os.path.exists("/etc/os-release"):
        return ""
    with open("/etc/os-release", "r", encoding="utf-8", errors="replace") as handle:
        lines = handle.read().splitlines()
    return lines[0] if lines else ""


def cmd_identify_all(args):
    """Inspect the ten unpatched images and write P2IM_10_UNPATCHED_MANIFEST.json."""
    real_root = args.real_root
    unpatched_root = args.unpatched_root
    records = []
    for target in BOARD_FOR_TARGET:
        if target == "Soldering_Iron":
            path = os.path.join(unpatched_root, target, target + ".elf")
            source_kind = "unpatched-est-data-set"
        else:
            path = os.path.join(real_root, target)
            source_kind = "p2im-real_firmware/binary"
        if not os.path.isfile(path):
            records.append({"target": target, "source_kind": source_kind, "path": path,
                            "status": "missing", "sha256": None})
            continue
        image = ElfImage(path)
        scores = image.family_scores()
        family = max(scores, key=lambda key: scores[key]) if scores else "unknown"
        spec = BOARD_FOR_TARGET[target]
        flash = image.flash_base()
        vector_base, initial_sp, reset_word = image.vector_table()
        svc = None
        if os.path.exists(DEFAULT_OBJDUMP):
            try:
                text = subprocess.run([DEFAULT_OBJDUMP, "-d", path], capture_output=True, text=True,
                                      timeout=180).stdout
                svc = len(re.findall(r"\bsvc\s+(?:63|0x3f)\b", text))
            except (OSError, subprocess.SubprocessError):
                svc = None
        funcs = [entry for entry in image.symbols if entry["type"] == ElfImage.STT_FUNC and entry["value"]]
        record = {
            "target": target,
            "source_kind": source_kind,
            "path": path,
            "status": "ok",
            "sha256": sha256_file(path),
            "bytes": os.path.getsize(path),
            "machine": image.e_machine,
            "entry_raw": "0x%08x" % image.e_entry,
            "flash_base": "0x%08x" % flash if flash is not None else None,
            "ram_base": "0x%08x" % image.ram_base() if image.ram_base() is not None else None,
            "vector_table_base": "0x%08x" % vector_base if vector_base is not None else None,
            "vector_initial_sp": "0x%08x" % initial_sp if initial_sp is not None else None,
            "vector_reset": "0x%08x" % reset_word if reset_word is not None else None,
            "function_symbols": len(funcs),
            "afl_call": {"svc_0x3f_count": svc, "present": bool(svc)},
            "family": {"inferred": family, "expected": spec[2], "scores": scores,
                       "matches": family == spec[2]},
            "board": {"qemu_board": spec[0], "mcu": spec[1]},
            "p2im_runnable": bool(svc) or target == "Soldering_Iron",
            "instruction_authority": "none",
        }
        if target == "Soldering_Iron":
            record["auto_forkserver_pc"] = "0x08000268"
            record["runnable_note"] = (
                "The unpatched ELF has no svc 0x3f. The rebuilt QEMU calls startForkserver once "
                "when a translation block covers 0x08000268 and P2IM_AUTO_FORKSERVER_PC is set. "
                "Image bytes stay unchanged."
            )
        records.append(record)
    manifest = {
        "schema": "mcu-p2im/manifest-0.2",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "oracle_version": VERSION,
        "host": {"user": "reproducer", "kernel": os.uname().release,
                 "distro": _read_os_release_first_line()},
        "sources": {"p2im_real_firmware": real_root, "unpatched_est_data_set": unpatched_root},
        "counts": {"targets": len(records), "present": sum(1 for r in records if r.get("status") == "ok"),
                   "with_svc_0x3f": sum(1 for r in records if r.get("afl_call", {}).get("present"))},
        "targets": records,
        "instruction_authority": "none",
    }
    write_json(args.out, manifest)
    ok(manifest_path=args.out, counts=manifest["counts"],
       missing=[r["target"] for r in records if r.get("status") != "ok"],
       without_afl_call=[r["target"] for r in records if r.get("status") == "ok" and not r["afl_call"]["present"]])


SHORT_SEED = b"0\n\x00\x00"


def write_initial_seeds(inputs_dir: str, elf_digest: str, seed_bytes: int, trial_seed: int | None = None):
    """Keep the historical 256-byte seed (or seed-parameterized paired variant) plus a 4B short seed."""
    os.makedirs(inputs_dir, exist_ok=True)
    seed_path = os.path.join(inputs_dir, "seed-random")
    if not os.path.exists(seed_path):
        tag = "mcu-p2im/seed/" + elf_digest if trial_seed is None else f"mcu-p2im/seed/{elf_digest}/trial/{trial_seed}"
        material = hashlib.sha256(tag.encode()).digest()
        stream = bytearray()
        counter = 0
        while len(stream) < seed_bytes:
            stream.extend(hashlib.sha256(material + struct.pack("<I", counter)).digest())
            counter += 1
        with open(seed_path, "wb") as handle:
            handle.write(bytes(stream[:seed_bytes]))
    short_path = os.path.join(inputs_dir, "seed-short")
    if not os.path.exists(short_path):
        with open(short_path, "wb") as handle:
            handle.write(SHORT_SEED)
    return seed_path, short_path


def cmd_prepare(args):
    work = Work(args.work_root, args.target)
    elf = os.path.abspath(args.elf)
    if not os.path.isfile(elf):
        fail(EXIT_REFUSED, "no such ELF: %s" % elf)
    digest = sha256_file(elf)
    if args.expect_sha256 and digest != args.expect_sha256.lower():
        fail(EXIT_REFUSED, "ELF hash does not match the unpatched manifest",
             expected=args.expect_sha256, actual=digest)
    spec = BOARD_FOR_TARGET[args.target]
    board = args.board or spec[0]
    mcu = args.mcu or spec[1]
    trial_seed = getattr(args, "trial_seed", None)
    os.makedirs(work.dir, exist_ok=True)
    dest = os.path.join(work.dir, args.target + ".elf")
    if not os.path.exists(dest) or sha256_file(dest) != digest:
        shutil.copyfile(elf, dest)
    work.meta = {
        "schema": "mcu-p2im/target-0.2",
        "target": args.target,
        "slug": work.slug,
        "trial_seed": trial_seed,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "elf": {"path": dest, "source_path": elf, "sha256": digest, "bytes": os.path.getsize(dest)},
        "board": {"qemu_board": board, "mcu": mcu},
        "paths": {"work_dir": work.dir, "inputs": os.path.join(work.dir, "inputs"),
                  "segments": work.segments_dir(), "evidence": work.evidence_dir()},
        "limits": {"cfg_path_max": 100},
        "auto_forkserver_pc": args.auto_forkserver_pc or None,
        "instruction_authority": "none",
    }
    write_json(work.meta_path, work.meta)
    shim = work.install_shim(os.path.join(args.tools_root, "qemu", "qemu-system-gnuarmeclipse"))
    seed_path, short_path = write_initial_seeds(
        os.path.join(work.dir, "inputs"), digest, args.seed_bytes, trial_seed=trial_seed
    )
    long_paths = [
        path for path in (work.cfg_path("s1"), work.model_path("0.seed-random.10"), work.model_path("0.q9999.10"))
        if len(path.encode("utf-8")) >= 100
    ]
    if long_paths:
        fail(EXIT_REFUSED, "working paths exceed the P2IM -c 100-byte limit", paths=long_paths)
    ok(target=args.target, work_dir=work.dir, elf_sha256=digest, board=board, mcu=mcu,
       trial_seed=trial_seed,
       shim=shim, seed_sha256=sha256_file(seed_path), seed_bytes=os.path.getsize(seed_path),
       short_seed_sha256=sha256_file(short_path), short_seed_bytes=os.path.getsize(short_path))


def classify_smoke_outcome(rc, timed_out: bool, fault) -> str:
    if timed_out:
        return "timeout"
    if rc is None or rc in (126, 127):
        return "error"
    if fault or rc in (0x72, 0xFF, 139, -11):
        return "crash"
    if rc in (0, 0x40, 0x41):
        return "ok"
    return "error"


def read_log_tail(path: str, max_lines: int = 20) -> list[str]:
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        lines = handle.read().splitlines()
    return lines[-max_lines:]


def cmd_smoke(args):
    work = Work(args.work_root, args.target)
    work.require()
    work.require_qemu(args.tools_root)
    seed = args.seed or os.path.join(work.dir, "inputs", "seed-random")
    round_name = args.round or work.latest_round()
    out_path = os.path.join(work.evidence_dir(), "smoke.log")
    command = [work.qemu_shim(), "-nographic", "-board", work.board, "-mcu", work.mcu,
               "-image", work.elf, "-pm-stage", "3", "-aflFile", seed]
    if round_name:
        command += ["-model-input", work.model_path(round_name)]
    rc, timed_out, duration = spawn_bounded(command, work.dir, work.execution_env(), args.timeout,
                                            out_path, owned=work.owned, label="smoke")
    fault = parse_fault(out_path)
    outcome = classify_smoke_outcome(rc, timed_out, fault)
    result = {"target": args.target, "outcome": outcome, "exit_code": rc, "timed_out": timed_out,
              "duration_s": duration, "fault": fault, "seed_sha256": sha256_file(seed),
              "round": round_name, "log": out_path, "instruction_authority": "none"}
    if outcome == "error":
        log_tail = read_log_tail(out_path)
        result["log_tail"] = log_tail
        write_json(os.path.join(work.evidence_dir(), "smoke.json"), result)
        fail(EXIT_FAILED, "smoke execution failed (exit_code=%s)" % rc, smoke=result, log_tail=log_tail)
    write_json(os.path.join(work.evidence_dir(), "smoke.json"), result)
    ok(smoke=result)


def cmd_me(args):
    work = Work(args.work_root, args.target)
    work.require()
    work.require_qemu(args.tools_root)
    os.makedirs(os.path.join(work.dir, "run"), exist_ok=True)
    round_name = args.round or "0"
    cfg = work.write_fuzz_cfg("me-%s" % round_name.replace(".", "-"),
                              os.path.join(work.dir, "outputs-nome"), args.afl_bin, args.p2im_root,
                              tools_root=args.tools_root)
    command = ["python3", os.path.join(args.tools_root, "scripts", "me.py"), "-c", cfg, "--run-num", round_name,
               "--print-to-file"]
    if args.afl_file and args.model_if:
        command += ["--run-from-forkserver", "--afl-file", args.afl_file, "--model-if", args.model_if]
    out_path = os.path.join(work.evidence_dir(), "me-%s.log" % round_name.replace(".", "-"))
    rc, timed_out, duration = spawn_bounded(command, work.dir, work.execution_env(), args.timeout, out_path,
                                            owned=work.owned, label="me-%s" % round_name)
    model_path = work.model_path(round_name)
    if not os.path.exists(model_path):
        fail(EXIT_FAILED, "model instantiation produced no model", round=round_name, exit_code=rc,
             timed_out=timed_out, log=out_path)
    summary = read_model_summary(model_path)
    result = {"target": args.target, "round": round_name, "exit_code": rc, "timed_out": timed_out,
              "duration_s": duration, "model": summary, "log": out_path,
              "instruction_authority": "none"}
    write_json(os.path.join(work.evidence_dir(), "me-round.json"), result)
    ok(me=result)


def sweep_work(work: "Work") -> list[dict]:
    """Kill every process whose command line names this work directory.

    Process-group signalling covers the normal path.  me.py may spawn QEMU outside the group,
    and a killed helper cannot clean up at all, so the oracle also sweeps by command line
    before it reports and again on ``cleanup``.  The match is anchored on the absolute work
    directory and never touches another target's processes.
    """
    killed = []
    marker = work.dir.encode("utf-8")
    me = os.getpid()
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid == me:
            continue
        try:
            with open("/proc/%d/cmdline" % pid, "rb") as handle:
                cmdline = handle.read()
        except OSError:
            continue
        if marker not in cmdline:
            continue
        try:
            pgid = os.getpgid(pid)
        except OSError:
            pgid = pid
        if pgid != os.getpgid(me):
            try:
                os.killpg(pgid, signal.SIGKILL)
            except OSError:
                pass
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
        killed.append({"pid": pid, "pgid": pgid, "cmdline": cmdline.replace(b"\x00", b" ").decode("utf-8", "replace")[:240]})
    return killed


def prepare_segment_inputs(work: Work, segment: str, include_proposed: bool = False, inherit_queue: str | None = None) -> dict:
    """Assemble segment-local inputs with ultra-short names (<8B) so 0.<seed>.<n>/peripheral_model.json
    stays strictly under P2IM AFL's 100-byte MODEL_IF_LEN buffer, without touching original dirs."""
    base_inputs = os.path.join(work.dir, "inputs")
    if not os.path.isdir(base_inputs):
        os.makedirs(base_inputs)

    src_queue_dir = None
    if inherit_queue is not None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", inherit_queue):
            fail(EXIT_REFUSED, "invalid inherit-queue segment name", segment=inherit_queue)
        src_queue_dir = os.path.join(work.dir, "outputs-" + inherit_queue, "queue")
        if not os.path.isdir(src_queue_dir):
            fail(EXIT_REFUSED, "inherit queue directory does not exist", segment=inherit_queue, path=src_queue_dir)

    base_files = [
        name for name in sorted(os.listdir(base_inputs))
        if not name.startswith(".") and name != "README.txt" and os.path.isfile(os.path.join(base_inputs, name))
    ]
    if not include_proposed and inherit_queue is None:
        return {
            "input_dir": base_inputs,
            "base_seeds": len(base_files),
            "inherit_queue": None,
            "inherited_queue_total": 0,
            "inherited_queue_files": 0,
            "inherited_queue_deduped": 0,
            "proposed_seeds": 0,
            "seed_map_path": None,
        }

    input_dir = os.path.join(work.dir, "inputs-" + segment)
    if os.path.isdir(input_dir):
        shutil.rmtree(input_dir)
    os.makedirs(input_dir)

    seen_sha256: set[str] = set()
    seed_map: list[dict] = []
    for idx, name in enumerate(base_files):
        src = os.path.join(base_inputs, name)
        digest = sha256_file(src)
        seen_sha256.add(digest)
        dest_name = name if len(name) <= 12 else f"b{idx:02d}"
        shutil.copyfile(src, os.path.join(input_dir, dest_name))
        seed_map.append({"dest": dest_name, "kind": "base", "source": name, "sha256": digest, "bytes": os.path.getsize(src)})

    inherited_total = 0
    inherited_copied = 0
    inherited_deduped = 0
    if src_queue_dir is not None and inherit_queue is not None:
        for name in sorted(os.listdir(src_queue_dir)):
            if name.startswith(".") or name == "README.txt":
                continue
            src = os.path.join(src_queue_dir, name)
            if not os.path.isfile(src):
                continue
            inherited_total += 1
            digest = sha256_file(src)
            if digest in seen_sha256:
                inherited_deduped += 1
                continue
            seen_sha256.add(digest)
            dest_name = f"q{inherited_copied:04d}"
            shutil.copyfile(src, os.path.join(input_dir, dest_name))
            seed_map.append({
                "dest": dest_name, "kind": "inherited_queue", "segment": inherit_queue,
                "source": name, "sha256": digest, "bytes": os.path.getsize(src),
            })
            inherited_copied += 1

    proposed_copied = 0
    if include_proposed:
        proposed = os.path.join(work.dir, "proposed-seeds")
        if os.path.isdir(proposed):
            for name in sorted(os.listdir(proposed)):
                if not name.endswith(".bin"):
                    continue
                src = os.path.join(proposed, name)
                if not os.path.isfile(src):
                    continue
                digest = sha256_file(src)
                dest_name = f"p{proposed_copied:02d}"
                shutil.copyfile(src, os.path.join(input_dir, dest_name))
                seed_map.append({"dest": dest_name, "kind": "proposed", "source": name, "sha256": digest, "bytes": os.path.getsize(src)})
                proposed_copied += 1

    # Verify every assembled seed yields a <100-byte P2IM -c peripheral_model.json path even at round .10
    overlong = [
        work.model_path(f"0.{item['dest']}.10")
        for item in seed_map
        if len(work.model_path(f"0.{item['dest']}.10").encode("utf-8")) >= 100
    ]
    if overlong:
        fail(EXIT_REFUSED, "segment seed model_if path exceeds P2IM 100-byte -c limit", paths=overlong[:3])

    map_path = os.path.join(work.evidence_dir(), f"inputs-{segment}-map.json")
    write_json(map_path, {"segment": segment, "count": len(seed_map), "seeds": seed_map, "instruction_authority": "none"})

    return {
        "input_dir": input_dir,
        "base_seeds": len(base_files),
        "inherit_queue": inherit_queue,
        "inherited_queue_total": inherited_total,
        "inherited_queue_files": inherited_copied,
        "inherited_queue_deduped": inherited_deduped,
        "proposed_seeds": proposed_copied,
        "seed_map_path": map_path,
    }


def prepare_segment_model_continuity(work: Work, segment: str, tools_root: str = DEFAULT_TOOLS_ROOT) -> tuple[str | None, bool]:
    """Carry the cumulative peripheral model from prior segments into segment >= 2 and archive old 1..N dirs
    so QEMU's forkserver (run_num=1..) neither resets to round 0 nor leaves stale higher-numbered rounds."""
    latest = work.latest_round()
    fuzz_py = os.path.join(tools_root, "scripts", "fuzz.py")
    supports_skip_prefix = False
    if os.path.isfile(fuzz_py):
        try:
            with open(fuzz_py, "r", encoding="utf-8", errors="replace") as handle:
                supports_skip_prefix = "--skip-seed-prefix" in handle.read()
        except OSError:
            supports_skip_prefix = False
    if not latest or segment == "s1":
        return None, supports_skip_prefix

    carry_round = f"0.{segment}"
    carry_model = work.model_path(carry_round)
    if len(carry_model.encode("utf-8")) >= 100:
        fail(EXIT_REFUSED, "carryover model path exceeds P2IM 100-byte -c limit", path=carry_model)
    os.makedirs(os.path.dirname(carry_model), exist_ok=True)
    shutil.copyfile(work.model_path(latest), carry_model)

    int_rounds = [r for r in work.round_dirs() if re.fullmatch(r"[1-9]\d*", r)]
    if int_rounds:
        archive_dir = os.path.join(work.dir, "rounds-archive", f"before-{segment}")
        os.makedirs(archive_dir, exist_ok=True)
        for rname in int_rounds:
            src_dir = os.path.join(work.dir, rname)
            dst_dir = os.path.join(archive_dir, rname)
            if os.path.exists(dst_dir):
                shutil.rmtree(dst_dir)
            shutil.move(src_dir, dst_dir)
    return carry_model, supports_skip_prefix


def cmd_fuzz(args):
    work = Work(args.work_root, args.target)
    work.require()
    work.require_qemu(args.tools_root)
    segment = args.segment or ("s%d" % (len([n for n in os.listdir(work.segments_dir())
                                             if re.match(r"^s\d+\.json$", n)]) + 1))
    output_dir = os.path.join(work.dir, "outputs-" + segment)
    if os.path.isdir(output_dir) and os.listdir(output_dir):
        fail(EXIT_REFUSED, "segment output directory is not empty", path=output_dir)
    prep = prepare_segment_inputs(
        work,
        segment,
        include_proposed=bool(args.include_proposed),
        inherit_queue=args.inherit_queue,
    )
    carry_model, supports_skip = prepare_segment_model_continuity(work, segment, args.tools_root)
    input_dir = prep["input_dir"]
    cfg = work.write_fuzz_cfg(segment, output_dir, args.afl_bin, args.p2im_root,
                              input_dir=input_dir, tools_root=args.tools_root)
    active_model_probe = carry_model or work.model_path(work.latest_round() or "0")
    if len(active_model_probe.encode("utf-8")) >= 100:
        fail(EXIT_REFUSED, "model_if path exceeds 100 bytes", path=active_model_probe)
    log_path = os.path.join(work.evidence_dir(), "fuzz-%s.log" % segment)
    command = ["python3", os.path.join(args.tools_root, "scripts", "fuzz.py"), "-c", cfg]
    if carry_model:
        command.extend(["--model-if", carry_model])
    if supports_skip and prep["inherited_queue_files"] > 0:
        command.extend(["--skip-seed-prefix", "q"])
    max_execs = getattr(args, "max_execs", 0) or 0
    stats_path = os.path.join(output_dir, "fuzzer_stats")
    exec_cap_hit = {"reached": False}

    def _check_exec_cap() -> bool:
        if max_execs <= 0 or not os.path.exists(stats_path):
            return False
        cur = int(parse_fuzzer_stats(stats_path).get("execs_done") or 0)
        if cur >= max_execs:
            exec_cap_hit["reached"] = True
            return True
        return False

    sweep_work(work)
    rc, timed_out, duration = spawn_bounded(
        command, work.dir, work.execution_env(), args.seconds, log_path,
        owned=work.owned, label="fuzz-%s" % segment,
        stop_when=_check_exec_cap if max_execs > 0 else None,
    )
    strays = sweep_work(work)
    stats = parse_fuzzer_stats(stats_path)
    crashes = crash_files(output_dir)
    program_abort = False
    if os.path.isfile(log_path):
        with open(log_path, "r", encoding="utf-8", errors="replace") as handle:
            program_abort = "PROGRAM ABORT" in handle.read()
    execs_done = int(stats.get("execs_done", 0) or 0)
    aborted = program_abort or (args.seconds >= 5 and execs_done == 0 and not exec_cap_hit["reached"])
    record = {
        "schema": "mcu-p2im/segment-0.2",
        "target": args.target, "segment": segment, "requested_seconds": args.seconds,
        "max_execs": max_execs if max_execs > 0 else None,
        "exec_cap_reached": exec_cap_hit["reached"],
        "duration_s": duration, "exit_code": rc, "timed_out": timed_out,
        "program_abort": program_abort, "aborted": aborted,
        "output_dir": output_dir, "stats": stats,
        "execs_done": execs_done, "paths_total": stats.get("paths_total", 0),
        "unique_crashes": stats.get("unique_crashes", 0), "unique_hangs": stats.get("unique_hangs", 0),
        "bitmap_cvg": stats.get("bitmap_cvg"),
        "queue_files": len(queue_files(output_dir)), "crash_files": len(crashes),
        "crashes": crashes, "rounds": work.round_dirs(), "carry_model": carry_model, "log": log_path,
        "input_dir": input_dir, "proposed_seeds": prep["proposed_seeds"],
        "inherit_queue": prep["inherit_queue"],
        "inherited_queue_total": prep["inherited_queue_total"],
        "inherited_queue_files": prep["inherited_queue_files"],
        "inherited_queue_deduped": prep["inherited_queue_deduped"],
        "seed_map_path": prep["seed_map_path"],
        "strays_killed": strays,
        "instruction_authority": "none",
    }
    write_json(os.path.join(work.segments_dir(), segment + ".json"), record)
    if aborted:
        fail(EXIT_FAILED, "AFL segment %s aborted (program_abort=%s, execs_done=%d)" % (segment, program_abort, execs_done),
             segment=record, log_tail=read_log_tail(log_path))
    ok(segment=record)


def cmd_status(args):
    work = Work(args.work_root, args.target)
    work.require()
    segments = []
    directory = work.segments_dir()
    for name in sorted(os.listdir(directory)):
        if re.match(r"^s\d+\.json$", name):
            segments.append(read_json(os.path.join(directory, name)))
    totals = {"execs_done": 0, "crash_files": 0, "queue_files": 0, "unique_crashes": 0,
              "unique_hangs": 0, "seconds": 0.0}
    for segment in segments:
        totals["execs_done"] += segment.get("execs_done") or 0
        totals["crash_files"] += segment.get("crash_files") or 0
        totals["queue_files"] += segment.get("queue_files") or 0
        totals["unique_crashes"] += segment.get("unique_crashes") or 0
        totals["unique_hangs"] += segment.get("unique_hangs") or 0
        totals["seconds"] += segment.get("duration_s") or 0
    rounds = work.round_dirs()
    latest = rounds[-1] if rounds else None
    model = read_model_summary(work.model_path(latest)) if latest else None
    result = {"target": args.target, "work_dir": work.dir, "segments": len(segments),
              "totals": totals, "rounds": rounds, "latest_round": latest,
              "model": {k: model[k] for k in ("sha256", "peripheral_count", "dr_registers", "aup")} if model else None,
              "instruction_authority": "none"}
    ok(status=result)


def cmd_crashes(args):
    work = Work(args.work_root, args.target)
    work.require()
    rows = []
    for name in sorted(os.listdir(work.dir)):
        if not name.startswith("outputs"):
            continue
        output_dir = os.path.join(work.dir, name)
        if not os.path.isdir(output_dir):
            continue
        for entry in crash_files(output_dir):
            entry["segment_dir"] = name
            rows.append(entry)
    unique = {}
    for row in rows:
        key = (row["sha256"], row["ret_v"])
        if key in unique:
            unique[key]["duplicates"].append({"segment_dir": row["segment_dir"], "id": row["id"]})
        else:
            row["duplicates"] = []
            unique[key] = row
    result = {"target": args.target, "raw_files": len(rows), "unique": len(unique),
              "crashes": list(unique.values()), "instruction_authority": "none"}
    write_json(os.path.join(work.evidence_dir(), "crash-index.json"), result)
    ok(crashes=result)


def replay_once(work: Work, round_name: str, input_path: str, timeout_s: int, with_trace: bool):
    run_id = uuid.uuid4().hex[:12]
    run_dir = os.path.join(work.evidence_dir(), "replays", run_id)
    os.makedirs(run_dir, exist_ok=True)
    log_path = os.path.join(run_dir, "qemu.log")
    command = [work.qemu_shim(), "-nographic", "-board", work.board, "-mcu", work.mcu,
               "-image", work.elf, "-pm-stage", "3", "-aflFile", input_path,
               "-model-input", work.model_path(round_name)]
    trace_path = None
    if with_trace:
        trace_path = os.path.join(run_dir, "trace.txt")
        command += ["-trace", trace_path]
    rc, timed_out, duration = spawn_bounded(command, work.dir, work.execution_env(), timeout_s, log_path,
                                            owned=work.owned, label="replay")
    parsed = parse_fault(log_path)
    last_bbl = None
    if trace_path and os.path.exists(trace_path):
        entries = parse_trace(trace_path)
        if entries:
            last_bbl = entries[-1]
    if timed_out:
        outcome = "hang"
    elif parsed or rc in (0x72, 0xFF, 139, -11):
        outcome = "crash"
    elif rc == 0:
        outcome = "ok"
    else:
        outcome = "error"
    result = {"run_id": run_id, "input": input_path, "input_sha256": sha256_file(input_path),
              "input_bytes": os.path.getsize(input_path), "round": round_name,
              "outcome": outcome, "exit_code": rc, "timed_out": timed_out, "duration_s": duration,
              "fault": parsed["fault"] if parsed else None,
              "fault_bbl": parsed["bbl"] if parsed else None,
              "last_bbl": last_bbl, "log": log_path,
              "instruction_authority": "none"}
    write_json(os.path.join(run_dir, "replay.json"), result)
    append_jsonl(os.path.join(work.evidence_dir(), "replays.jsonl"), result)
    return result


def resolve_input(work: "Work", value: str) -> str | None:
    """Accept an absolute path, a run-relative path, or a bare crash/queue file name."""
    candidates = []
    if os.path.isabs(value):
        candidates.append(value)
    else:
        candidates.append(os.path.join(work.dir, value))
    for name in sorted(os.listdir(work.dir)) if os.path.isdir(work.dir) else []:
        if not name.startswith("outputs"):
            continue
        for sub in ("crashes", "queue", "hangs"):
            candidates.append(os.path.join(work.dir, name, sub, value))
    candidates.append(os.path.join(work.evidence_dir(), value))
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None


def cmd_replay(args):
    work = Work(args.work_root, args.target)
    work.require()
    work.require_qemu(args.tools_root)
    round_name = args.round or work.latest_round()
    if not round_name:
        fail(EXIT_REFUSED, "no model round on disk")
    input_path = resolve_input(work, args.input)
    if input_path is None:
        fail(EXIT_REFUSED, "no such input: %s" % args.input)
    runs = [replay_once(work, round_name, input_path, args.timeout, not args.no_trace)
            for _ in range(max(1, args.repeat))]
    first = runs[0]
    deterministic = all(run["outcome"] == first["outcome"] and
                        (run["fault"] or {}).get("address") == (first["fault"] or {}).get("address") and
                        (run["last_bbl"] or {}).get("start") == (first["last_bbl"] or {}).get("start")
                        for run in runs[1:])
    ok(replay=first, repeated=len(runs), deterministic=deterministic,
       outcomes=[{"run_id": run["run_id"], "outcome": run["outcome"],
                  "exit_code": run["exit_code"], "fault": run["fault"],
                  "last_bbl": run["last_bbl"]} for run in runs])


def _replay_bytes(work: Work, round_name: str, data: bytes, timeout_s: int, tag: str):
    scratch = os.path.join(work.evidence_dir(), "tmp", tag)
    os.makedirs(os.path.dirname(scratch), exist_ok=True)
    with open(scratch, "wb") as handle:
        handle.write(data)
    return replay_once(work, round_name, scratch, timeout_s, with_trace=False), scratch


def cmd_contrast(args):
    work = Work(args.work_root, args.target)
    work.require()
    work.require_qemu(args.tools_root)
    round_name = args.round or work.latest_round()
    input_path = resolve_input(work, args.input)
    if input_path is None:
        fail(EXIT_REFUSED, "no such input: %s" % args.input)
    with open(input_path, "rb") as handle:
        original = handle.read()
    baseline = replay_once(work, round_name, input_path, args.timeout, with_trace=False)
    if baseline["outcome"] != "crash":
        fail(EXIT_REFUSED, "the input does not reproduce a crash under this round",
             outcome=baseline["outcome"], run_id=baseline["run_id"])
    fault_addr = (baseline["fault"] or {}).get("address")
    budget = {"replays": 0, "max": args.max_replays}

    def still_crashes(data: bytes):
        if budget["replays"] >= budget["max"]:
            return None
        budget["replays"] += 1
        result, _ = _replay_bytes(work, round_name, data, args.timeout, "contrast")
        return result["outcome"] == "crash" and (result["fault"] or {}).get("address") == fault_addr

    current = bytearray(original)
    # Keep a third of the budget for the causal step; a pure ddmin pass would spend it all.
    reserve = max(8, args.max_replays // 3)
    minimize_cap = max(4, args.max_replays - reserve)
    if args.op == "shorten":
        target = args.to if args.to is not None else max(1, len(current) // 2)
        candidate = bytes(current[:target])
        verdict = still_crashes(candidate)
        if verdict:
            current = bytearray(candidate)
    else:
        chunk = max(1, len(current) // 4)
        while chunk >= 1 and budget["replays"] < minimize_cap:
            index = 0
            changed = False
            while index < len(current) and budget["replays"] < minimize_cap:
                candidate = current[:index] + current[index + chunk:]
                if not candidate:
                    break
                verdict = still_crashes(bytes(candidate))
                if verdict:
                    current = bytearray(candidate)
                    changed = True
                else:
                    index += chunk
            if not changed:
                chunk //= 2
    # Causal step 1: one decisive byte. Removing it must stop the crash while the rest stays.
    decisive = None
    for index in range(len(current)):
        if budget["replays"] >= args.max_replays:
            break
        candidate = current[:index] + current[index + 1:]
        if not candidate:
            continue
        verdict = still_crashes(bytes(candidate))
        if verdict is False:
            decisive = index
            break
    # Causal step 2: a truncation that removes the fault, for length-driven copies.
    truncation = None
    if decisive is None:
        for length in range(len(current) - 1, 0, -1):
            if budget["replays"] >= args.max_replays:
                break
            verdict = still_crashes(bytes(current[:length]))
            if verdict is False:
                truncation = length
                break
    positive_path = os.path.join(work.evidence_dir(), "contrast-%s.min" % time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(os.path.dirname(positive_path), exist_ok=True)
    with open(positive_path, "wb") as handle:
        handle.write(bytes(current))
    positive = replay_once(work, round_name, positive_path, args.timeout, with_trace=False)
    negative = None
    negative_path = None
    negative_bytes = None
    if decisive is not None:
        negative_bytes = current[:decisive] + current[decisive + 1:]
    elif truncation is not None:
        negative_bytes = current[:truncation]
    if negative_bytes is not None:
        negative_path = positive_path + ".neg"
        with open(negative_path, "wb") as handle:
            handle.write(bytes(negative_bytes))
        negative = replay_once(work, round_name, negative_path, args.timeout, with_trace=False)
    result = {
        "schema": "mcu-p2im/contrast-0.2", "target": args.target, "round": round_name,
        "original": {"path": input_path, "sha256": sha256_file(input_path), "bytes": len(original),
                     "outcome": baseline["outcome"], "fault": baseline["fault"]},
        "minimized": {"path": positive_path, "sha256": sha256_file(positive_path), "bytes": len(current),
                      "outcome": positive["outcome"], "fault": positive["fault"]},
        "decisive_byte": decisive,
        "decisive": ({"kind": "byte_deleted", "index": decisive} if decisive is not None else
                     ({"kind": "truncated_to", "bytes": truncation} if truncation is not None else None)),
        "negative": None if negative is None else
                    {"path": negative_path, "sha256": sha256_file(negative_path), "bytes": len(negative_bytes),
                     "outcome": negative["outcome"], "fault": negative["fault"]},
        "contrast_confirmed": bool(negative is not None and negative["outcome"] != "crash"),
        "replays_used": budget["replays"], "replay_budget": args.max_replays,
        "instruction_authority": "none",
    }
    write_json(os.path.join(work.evidence_dir(), "contrast.json"), result)
    ok(contrast=result)


def cmd_extract_sources(args):
    work = Work(args.work_root, args.target)
    work.require()
    round_name = args.round or work.latest_round()
    if not round_name:
        fail(EXIT_REFUSED, "no model round on disk")
    model = read_model_summary(work.model_path(round_name))
    dr = {entry["register"].lower(): entry for entry in model["dr_registers"]}
    # A single round stops at the first unmodeled access, so the union over every round on disk
    # is a strictly better view of which functions read external bytes.  Round order is preserved
    # in the evidence so the newest site wins ties.
    rounds_with_logs = [name for name in work.round_dirs() if find_round_artifacts(work, name, "reg_acc")]
    if round_name not in rounds_with_logs:
        rounds_with_logs.append(round_name)
    read_sites = {}
    scanned = []
    for scan_round in rounds_with_logs:
        reg_acc_paths = find_round_artifacts(work, scan_round, "reg_acc")
        if not reg_acc_paths:
            continue
        parsed = []
        for reg_acc_path in reg_acc_paths:
            scanned.append({"round": scan_round, "reg_acc": reg_acc_path})
            parsed.extend(parse_reg_acc(reg_acc_path))
        names = demangle({entry["function"] for entry in parsed})
        for entry in parsed:
            entry["function"] = names.get(entry["function"], entry["function"])
            if entry["op"] != "r" or entry["address"] not in dr:
                continue
            key = (entry["function"], entry["address"])
            site = read_sites.setdefault(key, {"function": entry["function"], "register": entry["address"],
                                               "peripheral_base": dr[entry["address"]]["peripheral_base"],
                                               "reads": 0, "bbl": [], "lines": [], "rounds": []})
            site["reads"] += 1
            bbl = {"start": entry["bbl_start"], "end": entry["bbl_end"]}
            if bbl not in site["bbl"]:
                site["bbl"].append(bbl)
            if scan_round not in site["rounds"]:
                site["rounds"].append(scan_round)
            if len(site["lines"]) < 5:
                site["lines"].append(entry["line"])
    sources = []
    round_paths = {entry["round"]: entry["reg_acc"] for entry in scanned}
    for (function, register), site in sorted(read_sites.items(), key=lambda item: -item[1]["reads"]):
        first_round = site["rounds"][0] if site["rounds"] else round_name
        sources.append({
            "function": function, "register": register,
            "peripheral_base": site["peripheral_base"], "reads": site["reads"],
            "read_bbls": site["bbl"][:8], "rounds": site["rounds"],
            "evidence": {"kind": "runtime_register_read",
                         "file": round_paths.get(first_round, ""), "lines": site["lines"]},
        })
    result = {
        "schema": "mcu-p2im/sources-0.2", "target": args.target, "round": round_name,
        "model_sha256": model["sha256"], "elf_sha256": work.meta["elf"]["sha256"],
        "dr_registers": model["dr_registers"], "source_count": len(sources), "sources": sources,
        "scanned_rounds": scanned,
        "notes": ["P2IM consumes DR bytes sequentially from one flat input; the ordinal is not "
                  "attributable per register, so no byte offset is claimed here."],
        "instruction_authority": "none",
    }
    path = os.path.join(work.analysis_dir(), "sources.json")
    write_json(path, result)
    ok(sources_path=path, source_count=len(sources), dr_registers=len(dr),
       top=[{"function": s["function"], "register": s["register"], "reads": s["reads"]} for s in sources[:8]])


PC_RELATIVE_LOAD = re.compile(r"\[pc\s*,\s*#(-?(?:0x[0-9a-fA-F]+|\d+))\]", re.I)
LDR_ABSOLUTE = re.compile(r"=\s*(0x[0-9a-fA-F]+)\b")
SRAM_LOW = 0x1FFF0000
SRAM_HIGH = 0x40000000
ADJACENT_GAP = 64


def thumb_literal_addr(insn_addr, imm):
    """Thumb literal pool: Align(PC, 4) where PC is the instruction address plus 4, then the immediate."""
    return ((insn_addr + 4) & ~3) + imm


def pc_relative_load(mnemonic, operands):
    """('pool', imm) for ldr rX, [pc, #imm], ('abs', addr) for ldr rX, =0x..., else None."""
    if mnemonic.lower() not in ("ldr", "ldr.w"):
        return None
    pool = PC_RELATIVE_LOAD.search(operands)
    if pool:
        return ("pool", int(pool.group(1), 0))
    absolute = LDR_ABSOLUTE.search(operands)
    if absolute:
        return ("abs", int(absolute.group(1), 0))
    return None


def crc16_modbus(payload: bytes) -> int:
    crc = 0xFFFF
    for byte in payload:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def validate_proposed_seed(payload: bytes, frame: str):
    """None when the seed may be admitted. A string names the refused check."""
    if not payload or len(payload) > 256:
        return "length"
    if frame == "raw":
        return None
    if frame != "modbus_rtu":
        return "frame"
    if len(payload) < 4:
        return "length"
    expect = crc16_modbus(payload[:-2])
    got = payload[-2] | (payload[-1] << 8)
    if got != expect:
        return "crc16"
    return None


def is_mapping_symbol(name: str) -> bool:
    """ARM mapping symbols ($d/$t/$a) sit on the same address as the real object and would hide it."""
    return bool(name) and name.startswith("$")


def sram_data_symbols(image: ElfImage):
    """Named objects in SRAM (.bss/.data and kin). Functions and mapping symbols are excluded."""
    objects = []
    for sym in image.symbols:
        if not sym["name"] or sym["shndx"] in (0,):
            continue
        if is_mapping_symbol(sym["name"]):
            continue
        if sym["type"] == ElfImage.STT_FUNC:
            continue
        if sym["type"] not in (0, 1):
            continue
        addr = sym["value"]
        if not (SRAM_LOW <= addr < SRAM_HIGH):
            continue
        objects.append({"name": sym["name"], "addr": addr, "size": sym["size"] or 0})
    names = demangle({entry["name"] for entry in objects})
    for entry in objects:
        entry["name"] = names.get(entry["name"], entry["name"]).split("(", 1)[0].strip()
    objects.sort(key=lambda item: (item["addr"], -item["size"], item["name"]))
    for index, obj in enumerate(objects):
        if obj["size"]:
            continue
        nxt = None
        for later in objects[index + 1:]:
            if later["addr"] > obj["addr"]:
                nxt = later["addr"]
                break
        obj["size"] = min(4096, (nxt - obj["addr"]) if nxt else 4)
    return objects


def symbol_containing(objects, addr):
    hits = [obj for obj in objects
            if not is_mapping_symbol(obj["name"]) and obj["addr"] <= addr < obj["addr"] + max(obj["size"], 1)]
    if not hits:
        return None
    hits.sort(key=lambda obj: (obj["addr"] != addr, obj["size"], obj["name"]))
    return hits[0]


def pc_relative_sram_xrefs(insns, image: ElfImage, owner):
    """Functions whose literal pool loads a SRAM address. The loaded word is the object address."""
    xrefs = []
    for addr, (mnemonic, operands) in insns.items():
        parsed = pc_relative_load(mnemonic, operands)
        if parsed is None:
            continue
        kind, value = parsed
        if kind == "pool":
            literal = thumb_literal_addr(addr, value)
            try:
                loaded = image.word_at(literal)
            except ValueError:
                continue
        else:
            loaded = value
        if not (SRAM_LOW <= loaded < SRAM_HIGH):
            continue
        func = owner(addr)
        if func is None:
            continue
        xrefs.append({"function": func["name"], "insn": addr, "loaded": loaded})
    return xrefs


def _gap(left, right):
    left_end = left["addr"] + max(left["size"], 1)
    right_end = right["addr"] + max(right["size"], 1)
    if right["addr"] >= left_end:
        return right["addr"] - left_end
    if left["addr"] >= right_end:
        return left["addr"] - right_end
    return 0


def link_shared_globals(xrefs, objects, source_side, sink_side, window=ADJACENT_GAP):
    """Associate an interrupt-side writer and a main-loop consumer that load the same SRAM object.

    The result is evidence of a shared global. It is not a call edge and must not be merged
    into the call graph.
    """
    grouped = {}
    for xref in xrefs:
        symbol = symbol_containing(objects, xref["loaded"])
        if symbol is None:
            continue
        key = (symbol["name"], symbol["addr"])
        bucket = grouped.setdefault(key, {"symbol": symbol, "by_function": {}})
        bucket["by_function"].setdefault(xref["function"], []).append(xref["insn"])
    xref_addrs = {bucket["symbol"]["addr"] for bucket in grouped.values()}
    links = []
    for bucket in grouped.values():
        names = sorted(bucket["by_function"])
        writers = sorted(name for name in names if name in source_side)
        consumers = sorted(name for name in names if name in sink_side)
        symbol = bucket["symbol"]
        neighbor_xref = any(
            other["addr"] != symbol["addr"] and other["addr"] in xref_addrs and _gap(symbol, other) <= window
            for other in objects)
        # Same-object writer/consumer, or a one-sided object sitting next to another referenced object.
        # The second form is how an overflow of au8Buffer reaches the adjacent rx_callback slot.
        if not ((writers and consumers and len(names) >= 2) or (names and neighbor_xref and (writers or consumers))):
            continue
        adjacent = []
        for other in objects:
            if is_mapping_symbol(other["name"]):
                continue
            if other["addr"] == symbol["addr"] and other["name"] == symbol["name"]:
                continue
            gap = _gap(symbol, other)
            if gap <= window:
                adjacent.append({"symbol": other["name"], "address": "0x%x" % other["addr"], "gap": gap})
        adjacent.sort(key=lambda item: (item["gap"], item["address"]))
        links.append({
            "symbol": symbol["name"],
            "address": "0x%x" % symbol["addr"],
            "size": symbol["size"],
            "kind": "via_shared_global",
            "call_edge": False,
            "referencers": [{"function": name, "sites": ["0x%x" % site for site in sites[:4]]}
                            for name, sites in sorted(bucket["by_function"].items())],
            "interrupt_write_side": writers,
            "main_consume_side": consumers,
            "adjacent": adjacent[:8],
            "note": "shared SRAM object; not a call edge",
        })
    links.sort(key=lambda item: (item["address"], item["symbol"]))
    both = [item for item in links if item["interrupt_write_side"] and item["main_consume_side"]]
    rest = [item for item in links if item not in both]
    return (both + rest)[:24]


def expand_names(graph, roots, depth):
    seen = set(roots)
    frontier = set(roots)
    for _ in range(max(0, depth)):
        nxt = set()
        for node in frontier:
            for target in graph.get(node, ()):
                if target not in seen:
                    seen.add(target)
                    nxt.add(target)
        frontier = nxt
        if not frontier:
            break
        seen |= frontier
    return seen


_REG_HEAD = re.compile(r"^(r\d+|lr|sp|pc)\b", re.I)
_MOV_REG = re.compile(r"^(r\d+|lr)\s*,\s*(r\d+|lr)$", re.I)
_ADD2 = re.compile(r"^(r\d+)\s*,\s*(r\d+)$", re.I)
_ADD3 = re.compile(r"^(r\d+)\s*,\s*(r\d+)\s*,\s*(r\d+)$", re.I)
_FIELD_LOAD = re.compile(
    r"^(r\d+)\s*,\s*\[(r\d+)\s*,\s*#(-?(?:0x[0-9a-fA-F]+|\d+))\]\s*$", re.I)
_MEM_IMM = re.compile(r"\[(r\d+)\s*,\s*#(-?(?:0x[0-9a-fA-F]+|\d+))\]", re.I)
_CMP_IMM = re.compile(r"^(r\d+)\s*,\s*#(-?(?:0x[0-9a-fA-F]+|\d+))\s*$", re.I)
_BL_ADDR = re.compile(r"^(?:0x)?([0-9a-fA-F]+)\b")
_CALLS = {"bl", "blx", "bl.w", "blx.w"}
_CALLER_CLOBBER = ("r0", "r1", "r2", "r3", "lr")
_INDEX_LOAD = {"ldrb", "ldrb.w", "ldrsb", "ldrsb.w"}
_KEEP_INDEX = {"uxtb", "uxtb.w", "uxth", "uxth.w", "sxtb", "sxtb.w"}


def _reg(operands):
    match = _REG_HEAD.match(operands.strip())
    return match.group(1).lower() if match else None


def _resolve_pool_load(mnemonic, operands, insn_addr, image, objects):
    """SRAM object loaded by ldr rX, [pc, #imm] or ldr rX, =0x........"""
    parsed = pc_relative_load(mnemonic, operands)
    if parsed is None:
        return None
    kind, value = parsed
    if kind == "pool":
        if image is None:
            return None
        literal = thumb_literal_addr(insn_addr, value)
        try:
            loaded = image.word_at(literal)
        except ValueError:
            return None
    else:
        loaded = value
    if not (SRAM_LOW <= loaded < SRAM_HIGH):
        return None
    return symbol_containing(objects, loaded)


def indexed_member_sites(insns, owner, objects, image=None):
    """Byte-index stores of the form base+index, then [sum, #member].

    The base is a SRAM object that arrived in r0 or was loaded from a literal pool.
    An 8-bit index reaches member+0 .. member+max_index. A compare of that index
    against a small immediate lowers max_index. This is not a call edge.
    """
    bodies = {}
    for addr in sorted(insns):
        func = owner(addr)
        if func is None:
            continue
        mnemonic, operands = insns[addr]
        bodies.setdefault(func["name"], []).append((addr, mnemonic, operands))
    entry = {}
    sites = []
    for _ in range(4):
        found = []
        for name, rows in bodies.items():
            found.extend(_scan_indexed(name, rows, entry.get(name), objects, image, owner))
        entry_changed = False
        for target_name, obj in found:
            bucket = entry.setdefault(target_name, {})
            if obj["addr"] not in bucket:
                bucket[obj["addr"]] = obj
                entry_changed = True
        if not entry_changed and _ > 0:
            break
    # A second pass with the settled r0 map records the stores. The first passes
    # only discovered which callees receive the object.
    sites = []
    seen = set()
    for name, rows in bodies.items():
        for site in _scan_indexed(name, rows, entry.get(name), objects, image, owner, collect=True):
            key = (site["function"], site["base_address"], site["member_offset"], site["index_field"])
            if key in seen:
                continue
            seen.add(key)
            sites.append(site)
    return sites


def _entry_object(bucket):
    if not bucket or len(bucket) != 1:
        return None
    return next(iter(bucket.values()))


def _scan_indexed(name, rows, entry_bucket, objects, image, owner, collect=False):
    """One function. Without collect, return (callee, object) pairs. With collect, return sites."""
    reg_obj = {}
    index = {}
    sums = {}
    caps = {}
    pending = []
    raw_sites = []
    base = _entry_object(entry_bucket)
    if base is not None:
        reg_obj["r0"] = base

    def clobber(reg):
        reg_obj.pop(reg, None)
        index.pop(reg, None)
        sums.pop(reg, None)

    for addr, mnemonic, operands in rows:
        low = mnemonic.lower()
        ops = operands.strip()
        if low in _CALLS:
            match = _BL_ADDR.match(ops)
            if match and "r0" in reg_obj:
                callee = owner(int(match.group(1), 16))
                if callee is not None and callee["name"] != name:
                    pending.append((callee["name"], reg_obj["r0"]))
            for reg in _CALLER_CLOBBER:
                clobber(reg)
            continue
        if low in ("cmp", "cmp.w"):
            match = _CMP_IMM.match(ops)
            if match and match.group(1).lower() in index:
                obj, field = index[match.group(1).lower()]
                immediate = int(match.group(2), 0)
                if 0 <= immediate <= 255:
                    key = (obj["addr"], field)
                    caps[key] = min(caps.get(key, 255), immediate)
            continue
        if low in ("mov", "mov.w", "movs", "movs.w"):
            copied = _MOV_REG.match(ops)
            dest = _reg(ops)
            if dest is None:
                continue
            if copied:
                src = copied.group(2).lower()
                if src in reg_obj:
                    reg_obj[dest] = reg_obj[src]
                else:
                    reg_obj.pop(dest, None)
                if src in index:
                    index[dest] = index[src]
                else:
                    index.pop(dest, None)
                if src in sums:
                    sums[dest] = sums[src]
                else:
                    sums.pop(dest, None)
            else:
                clobber(dest)
            continue
        if low in _KEEP_INDEX:
            dest = _reg(ops)
            if dest is None:
                continue
            parts = [part.strip().lower() for part in ops.split(",")]
            src = parts[1] if len(parts) > 1 else dest
            if src != dest:
                if src in index:
                    index[dest] = index[src]
                else:
                    index.pop(dest, None)
                reg_obj.pop(dest, None)
                sums.pop(dest, None)
            continue
        if low in ("adds", "add", "add.w", "adds.w", "sub", "subs", "sub.w", "subs.w"):
            if re.match(r"^r\d+\s*,\s*#", ops, re.I):
                continue
            three = _ADD3.match(ops)
            two = _ADD2.match(ops)
            if three and low.startswith("add"):
                dest, left, right = (part.lower() for part in three.groups())
                made = None
                if left in reg_obj and right in index and index[right][0]["addr"] == reg_obj[left]["addr"]:
                    made = (reg_obj[left], index[right][1])
                elif right in reg_obj and left in index and index[left][0]["addr"] == reg_obj[right]["addr"]:
                    made = (reg_obj[right], index[left][1])
                reg_obj.pop(dest, None)
                index.pop(dest, None)
                if made is None:
                    sums.pop(dest, None)
                else:
                    sums[dest] = made
                continue
            if two and low.startswith("add"):
                dest, src = two.group(1).lower(), two.group(2).lower()
                made = None
                if dest in index and src in reg_obj and index[dest][0]["addr"] == reg_obj[src]["addr"]:
                    made = (reg_obj[src], index[dest][1])
                elif src in index and dest in reg_obj and index[src][0]["addr"] == reg_obj[dest]["addr"]:
                    made = (reg_obj[dest], index[src][1])
                if made is None:
                    clobber(dest)
                else:
                    reg_obj.pop(dest, None)
                    index.pop(dest, None)
                    sums[dest] = made
                continue
            dest = _reg(ops)
            if dest:
                clobber(dest)
            continue
        loaded = _resolve_pool_load(mnemonic, operands, addr, image, objects)
        if loaded is not None:
            dest = _reg(ops)
            if dest:
                reg_obj[dest] = loaded
                index.pop(dest, None)
                sums.pop(dest, None)
            continue
        if low in _INDEX_LOAD:
            match = _FIELD_LOAD.match(ops)
            dest = _reg(ops)
            if match and match.group(2).lower() in reg_obj:
                obj = reg_obj[match.group(2).lower()]
                index[match.group(1).lower()] = (obj, int(match.group(3), 0))
                reg_obj.pop(match.group(1).lower(), None)
                sums.pop(match.group(1).lower(), None)
                continue
            if dest:
                clobber(dest)
            continue
        if low.startswith("str") or low.startswith("ldr"):
            mem = _MEM_IMM.search(ops)
            if mem and low.startswith("str") and mem.group(1).lower() in sums:
                obj, field = sums[mem.group(1).lower()]
                raw_sites.append({
                    "function": name, "insn": addr, "obj": obj, "field": field,
                    "member": int(mem.group(2), 0),
                })
            if low.startswith("ldr"):
                dest = _reg(ops)
                if dest:
                    clobber(dest)
            continue
        dest = _reg(ops)
        if dest and low[:1] not in ("b",) and not low.startswith(("cb", "push", "pop", "stm", "ldm", "nop", "it")):
            if low.startswith(("lsl", "lsr", "asr", "ror", "and", "orr", "eor", "bic", "mul", "mvn", "neg", "rsb")):
                clobber(dest)
    if not collect:
        return pending
    cooked = []
    for site in raw_sites:
        cap = caps.get((site["obj"]["addr"], site["field"]), 255)
        reach_lo = site["obj"]["addr"] + site["member"]
        cooked.append({
            "function": site["function"],
            "insn": site["insn"],
            "base_symbol": site["obj"]["name"],
            "base_address": "0x%x" % site["obj"]["addr"],
            "index_field": site["field"],
            "member_offset": site["member"],
            "max_index": cap,
            "reach_lo": reach_lo,
            "reach_hi": reach_lo + cap,
            "obj": site["obj"],
        })
    return cooked


def merge_indexed_reach(links, sites, objects):
    """Attach indexed writers to a shared object their byte reach overlaps. Not a call edge."""
    by_addr = {}
    for link in links:
        try:
            addr = int(str(link["address"]), 16)
        except (KeyError, TypeError, ValueError):
            continue
        by_addr.setdefault(addr, []).append(link)
    for site in sites:
        lo, hi = site["reach_lo"], site["reach_hi"]
        base_addr = int(site["base_address"], 16)
        for obj in objects:
            if is_mapping_symbol(obj["name"]):
                continue
            if obj["addr"] == base_addr and obj["name"] == site["base_symbol"]:
                continue
            obj_hi = obj["addr"] + max(obj["size"], 1) - 1
            if hi < obj["addr"] or lo > obj_hi:
                continue
            for link in by_addr.get(obj["addr"], []):
                if link.get("symbol") != obj["name"]:
                    continue
                refs = link.setdefault("referencers", [])
                if not any(item.get("function") == site["function"] for item in refs):
                    refs.append({"function": site["function"], "sites": ["0x%x" % site["insn"]]})
                reach = link.setdefault("indexed_reach", [])
                if any(row.get("function") == site["function"] and row.get("member_offset") == site["member_offset"]
                       for row in reach):
                    continue
                if len(reach) >= 8:
                    continue
                reach.append({
                    "function": site["function"],
                    "base_symbol": site["base_symbol"],
                    "base_address": site["base_address"],
                    "member_offset": site["member_offset"],
                    "index_field": site["index_field"],
                    "max_index": site["max_index"],
                    "reach": ["0x%x" % lo, "0x%x" % hi],
                    "call_edge": False,
                })
    return links


def build_shared_globals(insns, image, owner, source_side, sink_side):
    objects = sram_data_symbols(image)
    xrefs = pc_relative_sram_xrefs(insns, image, owner)
    links = link_shared_globals(xrefs, objects, source_side, sink_side)
    sites = indexed_member_sites(insns, owner, objects, image)
    return merge_indexed_reach(links, sites, objects)


def cmd_slice_paths(args):
    work = Work(args.work_root, args.target)
    work.require()
    round_name = args.round or work.latest_round()
    sources_path = os.path.join(work.analysis_dir(), "sources.json")
    if not os.path.exists(sources_path):
        fail(EXIT_REFUSED, "run extract-sources first", expected=sources_path)
    sources = read_json(sources_path)
    functions = nm_functions(args.nm, work.elf)
    if not functions:
        fail(EXIT_FAILED, "no function symbols in the image")
    insns, dump = objdump_disasm(args.objdump, work.elf,
                                 os.path.join(work.analysis_dir(), "disasm-cache.json"))
    edges, owner = build_call_graph(insns, functions)
    graph = {}
    for (caller, callee) in edges:
        graph.setdefault(caller, set()).add(callee)
    trace_path = find_round_artifact(work, round_name, "trace")
    trace_entries = parse_trace(trace_path) if trace_path else []
    dynamic = indirect_edges_from_trace(trace_entries, insns, owner)
    for caller, targets in dynamic.items():
        for target in targets:
            graph.setdefault(caller, set()).add(target)
    sinks = sink_evidence(insns, owner, functions, dynamic)
    sink_goals = {sink["function"] for sink in sinks}
    direct_sources = [entry["function"] for entry in sources["sources"]]
    # A DR read usually hands the byte to a callback through a function pointer.  Walk a few
    # static hops and keep every function that the runtime actually reached through an indirect
    # edge: those are the real consumers, marked apart from the static registration site.
    dynamic_targets = {target for targets in dynamic.values() for target in targets}
    runtime_sources = []
    frontier = list(direct_sources)
    seen = set(direct_sources)
    for _ in range(3):
        next_frontier = []
        for node in frontier:
            for target in graph.get(node, ()):
                if target in seen:
                    continue
                seen.add(target)
                next_frontier.append(target)
                if target in dynamic_targets and target not in runtime_sources:
                    runtime_sources.append(target)
        frontier = next_frontier
        if not frontier:
            break
    paths = []
    for source, source_class in [(name, "register_read") for name in direct_sources] + \
                                [(name, "runtime_callback") for name in runtime_sources]:
        for path in simple_paths(graph, source, sink_goals, args.max_depth, args.max_paths):
            sink_entries = [sink for sink in sinks if sink["function"] == path[-1]]
            callsites = []
            for caller, callee in zip(path, path[1:]):
                entry = edges.get((caller, callee))
                if entry:
                    callsites.append({"caller": caller, "callee": callee,
                                      "sites": ["0x%x" % site for site in entry["callsites"][:4]]})
                elif callee in dynamic.get(caller, []):
                    callsites.append({"caller": caller, "callee": callee, "sites": ["runtime-indirect"]})
            paths.append({
                "source": source, "source_class": source_class, "sink": path[-1],
                "functions": path, "depth": len(path) - 1,
                "callsites": callsites,
                "sink_evidence": sink_entries[:2],
                "static_or_dynamic": "dynamic-edge" if any(
                    callee in dynamic.get(caller, []) for caller, callee in zip(path, path[1:])) else "static",
            })
    # Reverse chains into each sink: how the firmware's own top level reaches the copy site.
    # This is the half a pure source-rooted walk misses on MCU images, where the input buffer is
    # shared state rather than an argument passed down the call stack.
    reverse = {}
    for (caller, callee) in edges:
        reverse.setdefault(callee, set()).add(caller)
    sink_chains = []
    for sink in sinks:
        name = sink["function"]
        chains = []
        frontier = [[name]]
        for _ in range(3):
            next_frontier = []
            for chain in frontier:
                head = chain[-1]
                for caller in sorted(reverse.get(head, ()))[:3]:
                    if caller in chain:
                        continue
                    extended = chain + [caller]
                    chains.append(list(reversed(extended)))
                    next_frontier.append(extended)
            frontier = next_frontier
            if not frontier:
                break
        if chains:
            sink_chains.append({"sink": name, "kind": sink["kind"], "chains": chains[:3]})
    source_side = expand_names(graph, set(direct_sources) | set(runtime_sources), 4)
    sink_side = {sink["function"] for sink in sinks}
    for entry in sink_chains:
        for chain in entry["chains"]:
            sink_side.update(chain)
    try:
        image = ElfImage(work.elf)
    except (OSError, ValueError):
        image = None
    shared_globals = build_shared_globals(insns, image, owner, source_side, sink_side) if image is not None else []
    # The call graph above is unchanged. shared_globals is a separate association.
    reachable = []
    if args.reach_seeds > 0:
        seeds = []
        for name in sorted(os.listdir(work.dir)):
            if name.startswith("outputs"):
                seeds.extend(queue_files(os.path.join(work.dir, name))[: args.reach_seeds])
                seeds.extend([crash["path"] for crash in crash_files(os.path.join(work.dir, name))])
        seeds = seeds[: max(args.reach_seeds, 1) * 2]
        if seeds:
            work.require_qemu(args.tools_root)
        cache_path = os.path.join(work.analysis_dir(), "seed-functions.json")
        cache = read_json(cache_path) if os.path.exists(cache_path) else {}
        for seed in seeds:
            digest = sha256_file(seed)
            if digest not in cache:
                cache[digest] = reachable_functions(work, seed, round_name, args.timeout)
                write_json(cache_path, cache)
            reachable.append({"seed_path": seed, "sha256": digest,
                              "functions": cache[digest]["functions"], "exit_code": cache[digest]["exit_code"]})
    for path in paths:
        witnesses = [entry["seed_path"] for entry in reachable
                     if any(name in entry["functions"] for name in path["functions"])]
        path["reachable_seeds"] = witnesses[:4]
        path["reachable_seed_sha256"] = [sha256_file(seed) for seed in witnesses[:4]]
    result = {
        "schema": "mcu-p2im/paths-0.3", "target": args.target, "round": round_name,
        "elf_sha256": work.meta["elf"]["sha256"],
        "counts": {"functions": len(functions), "static_edges": len(edges),
                   "dynamic_indirect_edges": sum(len(value) for value in dynamic.values()),
                   "sinks": len(sinks), "sources": len(direct_sources) + len(runtime_sources), "paths": len(paths),
                   "shared_globals": len(shared_globals)},
        "shared_globals": shared_globals,
        "source_classes": {"register_read": direct_sources, "runtime_callback": runtime_sources},
        "sink_chains": sink_chains[:120],
        "sinks": sinks[:120], "paths": paths,
        "dynamic_edges": dynamic,
        "reachability": {"seeds_tested": len(reachable), "cache": "analysis/seed-functions.json"},
        "instruction_authority": "none",
    }
    out_path = os.path.join(work.analysis_dir(), "paths.json")
    write_json(out_path, result)
    leak = LEAK_PATTERN.search(json.dumps(result))
    if leak:
        fail(EXIT_FAILED, "artifact contains a truth-set token", token=leak.group(0))
    brief = [{"symbol": item["symbol"], "address": item["address"], "kind": item["kind"],
              "call_edge": False,
              "interrupt_write_side": item["interrupt_write_side"],
              "main_consume_side": item["main_consume_side"],
              "referencers": [entry["function"] for entry in item.get("referencers", [])[:8]],
              "indexed_reach": [{
                  "function": row["function"], "base_symbol": row["base_symbol"],
                  "member_offset": row["member_offset"], "max_index": row["max_index"],
                  "reach": row["reach"],
              } for row in item.get("indexed_reach", [])[:6]],
              "adjacent": [entry["symbol"] for entry in item["adjacent"]]} for item in shared_globals]
    ok(paths_path=out_path, counts=result["counts"], shared_globals=brief,
       shortest=[{"source": p["source"], "sink": p["sink"], "depth": p["depth"],
                  "seeds": len(p["reachable_seeds"])} for p in paths[:6]])


def cmd_admit_seed(args):
    """Validate one proposed seed and write it outside the original corpus.

    The original inputs/ directory is not modified. discover_seg2 copies admitted seeds
    into a segment-local input directory.
    """
    work = Work(args.work_root, args.target)
    work.require()
    note = args.note or ""
    if LEAK_PATTERN.search(note):
        fail(EXIT_REFUSED, "seed note contains a truth-set token")
    try:
        payload = bytes.fromhex(args.hex)
    except ValueError:
        fail(EXIT_REFUSED, "seed hex is not hexadecimal")
    if LEAK_PATTERN.search(payload.decode("latin1", "replace")):
        fail(EXIT_REFUSED, "seed bytes contain a truth-set token")
    reason = validate_proposed_seed(payload, args.frame)
    if reason:
        fail(EXIT_REFUSED, "seed refused", check=reason, frame=args.frame, bytes=len(payload))
    dest_dir = os.path.join(work.dir, "proposed-seeds")
    os.makedirs(dest_dir, exist_ok=True)
    existing = [name for name in os.listdir(dest_dir) if name.endswith(".bin")]
    digest = hashlib.sha256(payload).hexdigest()
    path = os.path.join(dest_dir, digest + ".bin")
    if digest + ".bin" not in existing and len(existing) >= args.max_seeds:
        fail(EXIT_REFUSED, "proposed seed cap reached", max_seeds=args.max_seeds)
    if not os.path.exists(path):
        with open(path, "wb") as handle:
            handle.write(payload)
    record = {
        "sha256": digest, "bytes": len(payload), "frame": args.frame,
        "crc_checked": args.frame == "modbus_rtu", "note": note,
        "path": path, "admitted_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "instruction_authority": "none",
    }
    append_jsonl(os.path.join(dest_dir, "provenance.jsonl"), record)
    ok(seed={"sha256": digest, "bytes": len(payload), "frame": args.frame,
             "crc_checked": record["crc_checked"], "path": path})


def cmd_gdb_watch(args):
    """Best-effort SRAM watchpoint on one replay. Missing gdb is a refusal, not a crash verdict.

    The ELF is not modified. The QEMU process is killed before this command returns.
    """
    work = Work(args.work_root, args.target)
    work.require()
    work.require_qemu(args.tools_root)
    gdb = args.gdb or shutil.which("gdb-multiarch") or shutil.which("gdb")
    if not gdb or not os.path.exists(gdb):
        fail(EXIT_REFUSED, "gdb not available")
    try:
        watch = int(args.watch, 0)
    except ValueError:
        fail(EXIT_REFUSED, "watch address is not an integer")
    if not (SRAM_LOW <= watch < SRAM_HIGH):
        fail(EXIT_REFUSED, "watch address is not in SRAM")
    round_name = args.round or work.latest_round()
    if not round_name:
        fail(EXIT_REFUSED, "no model round on disk")
    input_path = resolve_input(work, args.input)
    if input_path is None:
        fail(EXIT_REFUSED, "no such input: %s" % args.input)
    sock = __import__("socket").socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    log_path = os.path.join(work.evidence_dir(), "gdb-watch.log")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    command = [work.qemu_shim(), "-nographic", "-gdb", "tcp::%d" % port, "-S",
               "-board", work.board, "-mcu", work.mcu, "-image", work.elf,
               "-pm-stage", "3", "-aflFile", input_path, "-model-input", work.model_path(round_name)]
    gdb_log = os.path.join(work.evidence_dir(), "gdb-watch.gdb")
    hit = False
    gdb_error = None
    with open(log_path, "wb") as handle:
        try:
            proc = subprocess.Popen(command, cwd=work.dir, env=work.execution_env(), stdout=handle,
                                    stderr=subprocess.STDOUT, start_new_session=True, stdin=subprocess.DEVNULL)
        except OSError as exc:
            fail(EXIT_FAILED, "qemu gdb stub failed to start", detail=str(exc))
        pgid = os.getpgid(proc.pid)
        work.owned.register(pgid, "gdb-watch", command)
        script = "\n".join([
            "set pagination off", "set confirm off",
            "target remote 127.0.0.1:%d" % port,
            "watch *(unsigned char*)0x%x" % watch,
            "continue", "quit",
        ])
        try:
            completed = subprocess.run([gdb, "-batch", "-nx", "-q"], input=script, capture_output=True,
                                       text=True, timeout=args.timeout)
            text = completed.stdout + "\n" + completed.stderr
            with open(gdb_log, "w", encoding="utf-8") as gdb_handle:
                gdb_handle.write(text)
            hit = "Watchpoint" in text or "Hardware watchpoint" in text
            if "Connection refused" in text or "Remote communication error" in text:
                gdb_error = "gdb could not attach"
                hit = False
        except subprocess.TimeoutExpired as exc:
            gdb_error = "gdb timed out"
            partial = ((exc.stdout or "") if isinstance(exc.stdout, str) else (exc.stdout or b"").decode("utf-8", "replace"))
            with open(gdb_log, "w", encoding="utf-8") as gdb_handle:
                gdb_handle.write(partial)
        finally:
            if _alive(pgid):
                _signal_group(pgid, signal.SIGKILL)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            work.owned.forget(pgid)
    ok(gdb={"watch": "0x%x" % watch, "hit": hit, "error": gdb_error, "log": gdb_log,
            "instruction_authority": "none"})


def cmd_cleanup(args):
    work = Work(args.work_root, args.target)
    owned = work.owned
    killed = []
    for entry in list(owned.entries):
        pgid = entry.get("pgid")
        if isinstance(pgid, int) and _alive(pgid):
            _signal_group(pgid, signal.SIGKILL)
            killed.append({"pgid": pgid, "label": entry.get("label")})
        owned.forget(pgid)
    strays = sweep_work(work)
    remaining = [entry for entry in owned.entries]
    ok(cleaned=killed, strays=strays, remaining=remaining)


def extract_unique_bbls_from_trace(trace_path: str) -> tuple[list[str], list[str]]:
    """Return sorted unique (start..end BBL ranges, demangled function names) from a QEMU trace."""
    if not os.path.exists(trace_path):
        return [], []
    bbls: set[str] = set()
    raw_funcs: set[str] = set()
    with open(trace_path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = TRACE_RE.match(line.strip())
            if not match:
                continue
            bbls.add(f"{match.group(1).lower()}..{match.group(2).lower()}")
            raw_funcs.add(match.group(3))
    names = demangle(raw_funcs)
    funcs = sorted({names.get(name, name) for name in raw_funcs})
    return sorted(bbls), funcs


def compute_bbl_union(
    per_segment_bbls: dict[str, set[str]],
    per_segment_funcs: dict[str, set[str]] | None = None,
    segment_order: list[str] | None = None,
) -> dict:
    """Compute per-segment BBL counts, incremental deltas, and cross-segment union coverage."""
    order = list(segment_order) if segment_order is not None else sorted(per_segment_bbls)
    cum_bbls: set[str] = set()
    cum_funcs: set[str] = set()
    segments: dict[str, dict] = {}
    for seg in order:
        seg_bbls = set(per_segment_bbls.get(seg, ()))
        seg_funcs = set((per_segment_funcs or {}).get(seg, ()))
        new_bbls = seg_bbls - cum_bbls
        cum_bbls |= seg_bbls
        cum_funcs |= seg_funcs
        segments[seg] = {
            "unique_bbls": len(seg_bbls),
            "unique_functions": len(seg_funcs),
            "new_bbls_over_prior": len(new_bbls),
            "cumulative_unique_bbls": len(cum_bbls),
        }
    return {
        "segments": segments,
        "union": {
            "unique_bbls": len(cum_bbls),
            "unique_functions": len(cum_funcs),
            "bbl_set_sorted": sorted(cum_bbls),
            "function_set_sorted": sorted(cum_funcs),
        },
    }


def _discover_segment_names(work: Work) -> list[str]:
    names: set[str] = set()
    if os.path.isdir(work.dir):
        for entry in os.listdir(work.dir):
            if entry.startswith("outputs-") and os.path.isdir(os.path.join(work.dir, entry)):
                seg = entry[len("outputs-"):]
                if seg != "nome" and re.fullmatch(r"[A-Za-z0-9_-]{1,32}", seg):
                    names.add(seg)
    def sort_key(seg: str):
        m = re.fullmatch(r"s(\d+)", seg)
        return (0, int(m.group(1)), seg) if m else (1, 0, seg)
    return sorted(names, key=sort_key)


def cmd_bbl_coverage(args):
    """Compute exact per-segment and union unique basic-block coverage by replaying queue/crash inputs."""
    work = Work(args.work_root, args.target)
    work.require()
    work.require_qemu(args.tools_root)
    round_name = args.round or work.latest_round()
    if not round_name:
        fail(EXIT_REFUSED, "no model round on disk")

    if args.segments:
        segments = [seg.strip() for seg in args.segments.split(",") if seg.strip()]
        for seg in segments:
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", seg):
                fail(EXIT_REFUSED, "invalid segment name", segment=seg)
            if not os.path.isdir(os.path.join(work.dir, "outputs-" + seg)):
                fail(EXIT_REFUSED, "segment output directory missing", segment=seg)
    else:
        segments = _discover_segment_names(work)
        if not segments:
            fail(EXIT_REFUSED, "no segment output directories found under %s" % work.dir)

    buckets = [b.strip() for b in args.buckets.split(",") if b.strip()]
    allowed_buckets = {"queue", "crashes", "hangs"}
    if not buckets or any(b not in allowed_buckets for b in buckets):
        fail(EXIT_REFUSED, "invalid coverage buckets", buckets=buckets)

    cache_path = os.path.join(work.analysis_dir(), "bbl-cache.json")
    cache: dict[str, dict] = {}
    if os.path.exists(cache_path):
        try:
            loaded = read_json(cache_path)
            if isinstance(loaded, dict):
                cache = loaded
        except Exception:
            cache = {}

    tmp_dir = os.path.join(work.evidence_dir(), "tmp-bbl")
    os.makedirs(tmp_dir, exist_ok=True)
    tmp_trace = os.path.join(tmp_dir, "trace.txt")
    tmp_log = os.path.join(tmp_dir, "qemu.log")

    per_seg_bbls: dict[str, set[str]] = {}
    per_seg_funcs: dict[str, set[str]] = {}
    per_seg_counts: dict[str, int] = {}
    cache_dirty = False
    try:
        for seg in segments:
            seg_out = os.path.join(work.dir, "outputs-" + seg)
            seed_paths: list[str] = []
            for bucket in buckets:
                bdir = os.path.join(seg_out, bucket)
                if not os.path.isdir(bdir):
                    continue
                for name in sorted(os.listdir(bdir)):
                    if name == "README.txt" or name.startswith("."):
                        continue
                    full = os.path.join(bdir, name)
                    if os.path.isfile(full):
                        seed_paths.append(full)
            if args.max_inputs_per_segment > 0:
                seed_paths = seed_paths[:args.max_inputs_per_segment]
            seg_bbls: set[str] = set()
            seg_funcs: set[str] = set()
            for seed_path in seed_paths:
                digest = sha256_file(seed_path)
                ckey = f"{round_name}:{digest}"
                entry = cache.get(ckey)
                if not isinstance(entry, dict) or "bbls" not in entry:
                    for stale in (tmp_trace, tmp_log):
                        if os.path.exists(stale):
                            os.unlink(stale)
                    command = [
                        work.qemu_shim(), "-nographic", "-board", work.board, "-mcu", work.mcu,
                        "-image", work.elf, "-pm-stage", "3", "-aflFile", seed_path,
                        "-model-input", work.model_path(round_name), "-trace", tmp_trace,
                    ]
                    rc, timed_out, _ = spawn_bounded(
                        command, work.dir, work.execution_env(), args.timeout, tmp_log,
                        owned=work.owned, label="bbl-cov",
                    )
                    bbls, funcs = extract_unique_bbls_from_trace(tmp_trace)
                    entry = {"bbls": bbls, "functions": funcs, "exit_code": rc, "timed_out": timed_out}
                    cache[ckey] = entry
                    cache_dirty = True
                seg_bbls.update(entry.get("bbls") or ())
                seg_funcs.update(entry.get("functions") or ())
            per_seg_bbls[seg] = seg_bbls
            per_seg_funcs[seg] = seg_funcs
            per_seg_counts[seg] = len(seed_paths)
    finally:
        for stale in (tmp_trace, tmp_log):
            if os.path.exists(stale):
                try:
                    os.unlink(stale)
                except OSError:
                    pass
        if cache_dirty:
            write_json(cache_path, cache)

    computed = compute_bbl_union(per_seg_bbls, per_seg_funcs, segment_order=segments)
    seg_details: dict[str, dict] = {}
    total_execs_done = 0
    total_fuzz_seconds = 0.0
    for seg in segments:
        row = dict(computed["segments"][seg])
        row["inputs_traced"] = per_seg_counts[seg]
        seg_meta_path = os.path.join(work.segments_dir(), seg + ".json")
        if os.path.exists(seg_meta_path):
            seg_meta = read_json(seg_meta_path)
            execs = int(seg_meta.get("execs_done") or 0)
            dur = float(seg_meta.get("duration_s") or 0.0)
            row["execs_done"] = execs
            row["duration_s"] = dur
            row["paths_total"] = int(seg_meta.get("paths_total") or 0)
            total_execs_done += execs
            total_fuzz_seconds += dur
        seg_details[seg] = row

    union_meta = {
        "unique_bbls": computed["union"]["unique_bbls"],
        "unique_functions": computed["union"]["unique_functions"],
    }
    full_payload = {
        "schema": "mcu-p2im/bbl-coverage-0.1",
        "target": args.target,
        "elf_sha256": work.meta["elf"]["sha256"],
        "round": round_name,
        "buckets": buckets,
        "segments_order": segments,
        "total_execs_done": total_execs_done,
        "total_fuzz_seconds": round(total_fuzz_seconds, 3),
        "segments": seg_details,
        "union": union_meta,
        "unique_bbls_list": computed["union"]["bbl_set_sorted"],
        "unique_functions_list": computed["union"]["function_set_sorted"],
        "instruction_authority": "none",
    }
    out_path = os.path.join(work.analysis_dir(), "bbl-coverage.json")
    write_json(out_path, full_payload)
    if args.out and os.path.abspath(args.out) != os.path.abspath(out_path):
        write_json(args.out, full_payload)

    summary = {k: v for k, v in full_payload.items() if k not in ("unique_bbls_list", "unique_functions_list")}
    ok(coverage=summary, coverage_path=out_path)


def cmd_aggregate(args):
    """Roll the per-target evidence into one table; no truth data is consulted."""
    rows = []
    root = os.path.abspath(args.work_root)
    for name in sorted(os.listdir(root)):
        meta_path = os.path.join(root, name, "meta.json")
        if not os.path.exists(meta_path):
            continue
        meta = read_json(meta_path)
        segments = []
        seg_dir = os.path.join(root, name, "segments")
        if os.path.isdir(seg_dir):
            segments = [read_json(os.path.join(seg_dir, entry)) for entry in sorted(os.listdir(seg_dir))
                        if re.match(r"^s\d+\.json$", entry)]
        analysis = {}
        for key, filename in (("sources", "sources.json"), ("paths", "paths.json")):
            path = os.path.join(root, name, "analysis", filename)
            if os.path.exists(path):
                body = read_json(path)
                analysis[key] = body.get("counts") or {"source_count": body.get("source_count")}
        replays = []
        replay_log = os.path.join(root, name, "evidence", "replays.jsonl")
        if os.path.exists(replay_log):
            with open(replay_log, "r", encoding="utf-8") as handle:
                replays = [json.loads(line) for line in handle if line.strip()]
        rows.append({
            "target": meta["target"], "board": meta["board"], "elf_sha256": meta["elf"]["sha256"],
            "segments": len(segments),
            "execs_done": sum(segment.get("execs_done") or 0 for segment in segments),
            "crash_files": sum(segment.get("crash_files") or 0 for segment in segments),
            "analysis": analysis,
            "replays": {"total": len(replays),
                        "crash": sum(1 for r in replays if r.get("outcome") == "crash"),
                        "deterministic": sum(1 for r in replays if r.get("deterministic") is True)},
        })
    result = {"schema": "mcu-p2im/aggregate-0.2", "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
              "targets": rows, "instruction_authority": "none"}
    write_json(args.out, result)
    ok(aggregate_path=args.out, targets=len(rows))


# ---------------------------------------------------------------------- parser

GLOBAL_DEFAULTS = {
    "--work-root": DEFAULT_WORK_ROOT,
    "--tools-root": DEFAULT_TOOLS_ROOT,
    "--p2im-root": DEFAULT_P2IM_ROOT,
    "--afl-bin": os.path.join(DEFAULT_P2IM_ROOT, "afl", "afl-fuzz"),
    "--objdump": DEFAULT_OBJDUMP,
    "--nm": DEFAULT_NM,
}


def add_global_options(parser):
    """Global paths are accepted both before and after the subcommand.

    argparse only resolves a parent option before the subcommand, while the TypeScript host
    appends ``--work-root`` to every call.  Registering the same destination on the subparser
    keeps a single value: the parent default is set first, the subparser only overrides it when
    the flag is actually present after the subcommand.
    """
    for flag, default in GLOBAL_DEFAULTS.items():
        dest = flag.lstrip("-").replace("-", "_")
        parser.add_argument(flag, dest=dest, default=argparse.SUPPRESS)


def build_parser():
    parser = argparse.ArgumentParser(description="P2IM execution/evidence helper for mcu-p2im")
    for flag, default in GLOBAL_DEFAULTS.items():
        parser.add_argument(flag, default=default)
    sub = parser.add_subparsers(dest="command", required=True)

    identify = sub.add_parser("identify")
    identify.add_argument("--elf", required=True)
    identify.add_argument("--target", default="")
    identify.add_argument("--board")
    identify.add_argument("--mcu")
    identify.add_argument("--out")
    identify.set_defaults(func=cmd_identify)

    identify_all = sub.add_parser("identify-all")
    identify_all.add_argument("--real-root", default=os.path.join(DEFAULT_P2IM_ROOT, "externals",
                                                                 "p2im-real_firmware", "binary"))
    identify_all.add_argument("--unpatched-root",
                              default=os.path.join(DEFAULT_HOEDUR_ROOT, "targets", "arm",
                                                   "unpatched-est-data-set", "P2IM"))
    identify_all.add_argument("--out", required=True)
    identify_all.set_defaults(func=cmd_identify_all)

    prepare = sub.add_parser("prepare")
    prepare.add_argument("--target", required=True, choices=sorted(BOARD_FOR_TARGET))
    prepare.add_argument("--elf", required=True)
    prepare.add_argument("--expect-sha256")
    prepare.add_argument("--board")
    prepare.add_argument("--mcu")
    prepare.add_argument("--seed-bytes", type=int, default=256)
    prepare.add_argument("--trial-seed", type=int, default=None,
                         help="Optional paired trial seed ID (e.g. 1707/2707/3707) for deterministic seed-random derivation")
    prepare.add_argument("--auto-forkserver-pc", default=None)
    prepare.set_defaults(func=cmd_prepare)

    smoke = sub.add_parser("smoke")
    smoke.add_argument("--target", required=True)
    smoke.add_argument("--seed")
    smoke.add_argument("--round")
    smoke.add_argument("--timeout", type=int, default=20)
    smoke.set_defaults(func=cmd_smoke)

    me = sub.add_parser("me")
    me.add_argument("--target", required=True)
    me.add_argument("--round")
    me.add_argument("--afl-file")
    me.add_argument("--model-if")
    me.add_argument("--timeout", type=int, default=900)
    me.set_defaults(func=cmd_me)

    fuzz = sub.add_parser("fuzz")
    fuzz.add_argument("--target", required=True)
    fuzz.add_argument("--segment")
    fuzz.add_argument("--seconds", type=int, required=True)
    fuzz.add_argument("--max-execs", type=int, default=0,
                      help="Optional target execution cap (stops AFL cleanly once fuzzer_stats execs_done >= N)")
    fuzz.add_argument("--include-proposed", action="store_true")
    fuzz.add_argument("--inherit-queue", default=None,
                      help="Optional prior segment name (e.g. s1) whose outputs-<seg>/queue/* are seeded into inputs-<segment>/")
    fuzz.set_defaults(func=cmd_fuzz)

    status = sub.add_parser("status")
    status.add_argument("--target", required=True)
    status.set_defaults(func=cmd_status)

    crashes = sub.add_parser("crashes")
    crashes.add_argument("--target", required=True)
    crashes.set_defaults(func=cmd_crashes)

    replay = sub.add_parser("replay")
    replay.add_argument("--target", required=True)
    replay.add_argument("--round")
    replay.add_argument("--input", required=True)
    replay.add_argument("--repeat", type=int, default=1)
    replay.add_argument("--timeout", type=int, default=30)
    replay.add_argument("--no-trace", action="store_true")
    replay.set_defaults(func=cmd_replay)

    contrast = sub.add_parser("contrast")
    contrast.add_argument("--target", required=True)
    contrast.add_argument("--round")
    contrast.add_argument("--input", required=True)
    contrast.add_argument("--op", choices=["trim", "shorten"], default="trim")
    contrast.add_argument("--to", type=int)
    contrast.add_argument("--max-replays", type=int, default=120)
    contrast.add_argument("--timeout", type=int, default=30)
    contrast.set_defaults(func=cmd_contrast)

    sources = sub.add_parser("extract-sources")
    sources.add_argument("--target", required=True)
    sources.add_argument("--round")
    sources.set_defaults(func=cmd_extract_sources)

    paths = sub.add_parser("slice-paths")
    paths.add_argument("--target", required=True)
    paths.add_argument("--round")
    paths.add_argument("--max-depth", type=int, default=8)
    paths.add_argument("--max-paths", type=int, default=6)
    paths.add_argument("--reach-seeds", type=int, default=4)
    paths.add_argument("--timeout", type=int, default=30)
    paths.set_defaults(func=cmd_slice_paths)

    admit = sub.add_parser("admit-seed")
    admit.add_argument("--target", required=True)
    admit.add_argument("--hex", required=True)
    admit.add_argument("--frame", choices=["raw", "modbus_rtu"], required=True)
    admit.add_argument("--note", default="")
    admit.add_argument("--max-seeds", type=int, default=4)
    admit.set_defaults(func=cmd_admit_seed)

    gdb_watch = sub.add_parser("gdb-watch")
    gdb_watch.add_argument("--target", required=True)
    gdb_watch.add_argument("--input", required=True)
    gdb_watch.add_argument("--watch", required=True)
    gdb_watch.add_argument("--round")
    gdb_watch.add_argument("--gdb")
    gdb_watch.add_argument("--timeout", type=int, default=40)
    gdb_watch.set_defaults(func=cmd_gdb_watch)

    cleanup = sub.add_parser("cleanup")
    cleanup.add_argument("--target", required=True)
    cleanup.add_argument("--sweep", action="store_true")
    cleanup.set_defaults(func=cmd_cleanup)

    bbl_cov = sub.add_parser("bbl-coverage")
    bbl_cov.add_argument("--target", required=True)
    bbl_cov.add_argument("--segments", default="")
    bbl_cov.add_argument("--round")
    bbl_cov.add_argument("--buckets", default="queue,crashes")
    bbl_cov.add_argument("--timeout", type=int, default=5)
    bbl_cov.add_argument("--max-inputs-per-segment", type=int, default=0)
    bbl_cov.add_argument("--out")
    bbl_cov.set_defaults(func=cmd_bbl_coverage)

    aggregate = sub.add_parser("aggregate")
    aggregate.add_argument("--out", required=True)
    aggregate.set_defaults(func=cmd_aggregate)
    for action in sub.choices.values():
        add_global_options(action)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - the CLI contract is one JSON object
        fail(EXIT_FAILED, "%s: %s" % (type(exc).__name__, exc), command=args.command)


if __name__ == "__main__":
    main()
