#!/usr/bin/env python3
"""Host-only L5 scorer for the P2IM blind test.

This is the ONLY component allowed to read the known-bug truth set. It runs after every Agent
phase has ended, in a separate process, and prints counts, bug-deduplicated totals, and our own
candidate names only, so truth prose never re-enters an orchestrator or Agent context.

Inputs:
  --notes PATH        P2IM_patching_notes.md. Firmware sections are level-2 headings (## PLC).
  --paper-text PATH   optional plain-text extraction of the P2IM paper. Read only in this process.
  --candidates PATH   JSON list/dict of verified candidates {target, function, addresses, bbl_range,
                      upstream_functions, via_shared_global, ...}
  --elf PATH          optional unpatched target ELF used to map primary patch addresses to symbols
  --target NAME       restrict scoring to one firmware
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{4,8}")
PATCH_ADDRESS_RE = re.compile(r"(?m)^\s*address:\s*(0x[0-9a-fA-F]{4,8})\b")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
BUG_HEADING_RE = re.compile(r"(?m)^###\s+((?:Bug\b|Known,\s*unpatched\s+Bugs\b)[^\n]*)$", re.I)
AFFECTED_BLOCK_RE = re.compile(r"Affected function:\s*```[^\n]*\n(.*?)```", re.S)
AFFECTED_INLINE_RE = re.compile(r"Affected function:\s*`([^`\n]+)`", re.I)
IN_FUNCTION_INLINE_RE = re.compile(r"\bIn function\s+`([^`\n]+)`", re.I)
FUNC_SUCH_AS_RE = re.compile(r"\bfunctions?\s+such\s+as\s+`([A-Za-z_][\w:]*)`", re.I)
QUALIFIED_BACKTICK_RE = re.compile(r"`([A-Za-z_][\w]*::[A-Za-z_][\w]*)`")
FUNC_MENTION_BEFORE_RE = re.compile(r"`([A-Za-z_][\w:]*)`\s+function\b")
FUNC_MENTION_AFTER_RE = re.compile(r"\bfunction\s+`([A-Za-z_][\w:]*)`")
HEADING_IN_FUNC_RE = re.compile(r"\bin\s+`?([A-Za-z_][\w:]+)`?\s*$")
QUALIFIED_RE = re.compile(r"\b([A-Za-z_][\w]*::[A-Za-z_][\w]*)\s*\(")
FC_HANDLER_RE = re.compile(r"\b((?:[A-Za-z_][\w]*::)?(?:process|get)_FC\d+)\b")
CLONE_SUFFIX_RE = re.compile(r"(?:\.(?:lto_priv|constprop|isra|part)\.\d+)+$", re.I)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_MANIFEST = os.path.join(REPO_ROOT, "docs", "P2IM_10_UNPATCHED_MANIFEST.json")


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (text or "").lower())


def clean_symbol_base(name: str) -> str:
    base = (name or "").split("(", 1)[0].strip()
    return CLONE_SUFFIX_RE.sub("", base)


def function_key(name: str) -> str:
    """Drop parameter list, compiler LTO/clone suffixes, and whitespace; keep '::'."""
    base = clean_symbol_base(name).lower()
    return re.sub(r"\s+", "", base)


def function_match(left: str, right: str) -> bool:
    a = function_key(left)
    b = function_key(right)
    if not a or not b:
        return False
    if a == b:
        return True
    if "::" in a and a.split("::")[-1] == b and len(b) > 3:
        return True
    if "::" in b and b.split("::")[-1] == a and len(a) > 3:
        return True
    return False


def _demangle(names: set[str]) -> dict[str, str]:
    unique = sorted(n for n in names if n)
    if not unique:
        return {}
    for filt in ("/usr/bin/c++filt", "/usr/bin/arm-none-eabi-c++filt", "c++filt"):
        try:
            proc = subprocess.run([filt], input="\n".join(unique) + "\n", capture_output=True, text=True, timeout=30)
            lines = proc.stdout.splitlines()
            if proc.returncode == 0 and len(lines) == len(unique):
                return dict(zip(unique, lines))
        except (OSError, subprocess.SubprocessError):
            continue
    return {n: n for n in unique}


def load_elf_functions(elf_path: str | None) -> list[tuple[int, int, str]]:
    """Read STT_FUNC ranges (start_even, size, demangled_base_name) directly from ELF32 .symtab."""
    if not elf_path or not os.path.isfile(elf_path):
        return []
    try:
        with open(elf_path, "rb") as handle:
            data = handle.read()
    except OSError:
        return []
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[4] != 1:
        return []
    endian = "<" if data[5] == 1 else ">"
    try:
        (_etype, _emach, _ever, _eentry, _ephoff, e_shoff, _eflags, _eehsize,
         _ephentsize, _ephnum, e_shentsize, e_shnum, _eshstrndx) = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
        sections = []
        for idx in range(e_shnum):
            base = e_shoff + idx * e_shentsize
            fields = struct.unpack_from(endian + "IIIIIIIIII", data, base)
            sections.append({"type": fields[1], "offset": fields[4], "size": fields[5], "link": fields[6], "entsize": fields[9]})
        raw_funcs: list[tuple[int, int, str]] = []
        for sec in sections:
            if sec["type"] != 2 or sec["link"] >= len(sections):  # SHT_SYMTAB = 2
                continue
            str_sec = sections[sec["link"]]
            strtab = data[str_sec["offset"]:str_sec["offset"] + str_sec["size"]]
            blob = data[sec["offset"]:sec["offset"] + sec["size"]]
            entsz = sec["entsize"] or 16
            for off in range(0, len(blob) - entsz + 1, entsz):
                name_off, val, size, info, _other, shndx = struct.unpack_from(endian + "IIIBBH", blob, off)
                if shndx == 0 or (info & 0xF) != 2 or val == 0:  # STT_FUNC = 2
                    continue
                end = strtab.find(b"\x00", name_off)
                raw_name = strtab[name_off:(end if end >= 0 else len(strtab))].decode("utf-8", "replace")
                if not raw_name or raw_name.startswith("$"):
                    continue
                raw_funcs.append((val & ~1, size, raw_name))
    except struct.error:
        return []
    demangled = _demangle({name for _a, _s, name in raw_funcs})
    by_addr = sorted(raw_funcs, key=lambda item: (item[0], -item[1]))
    resolved: list[tuple[int, int, str]] = []
    for idx, (addr, size, raw_name) in enumerate(by_addr):
        eff_size = size
        if eff_size == 0 and idx + 1 < len(by_addr) and by_addr[idx + 1][0] > addr:
            eff_size = min(4096, by_addr[idx + 1][0] - addr)
        if eff_size <= 0:
            eff_size = 4
        resolved.append((addr, eff_size, clean_symbol_base(demangled.get(raw_name, raw_name))))
    return resolved


def resolve_elf_path(target: str, explicit_elf: str | None = None, work_dir: str | None = None) -> str | None:
    if explicit_elf and os.path.isfile(explicit_elf):
        return explicit_elf
    if work_dir and target:
        cand = os.path.join(work_dir, f"{target}.elf")
        if os.path.isfile(cand):
            return cand
    if target and os.path.isfile(DEFAULT_MANIFEST):
        try:
            with open(DEFAULT_MANIFEST, "r", encoding="utf-8") as handle:
                manifest = json.load(handle)
            p2im_root = os.environ.get("P2IM_ROOT", os.path.expanduser("~/deps/p2im")).rstrip("/")
            hoedur_root = os.environ.get("HOEDUR_EXPERIMENTS_ROOT", os.path.expanduser("~/deps/hoedur-experiments")).rstrip("/")
            for row in manifest.get("targets", []):
                if row.get("target") == target and isinstance(row.get("path"), str):
                    expanded = row["path"].replace("${P2IM_ROOT}", p2im_root).replace("${HOEDUR_EXPERIMENTS_ROOT}", hoedur_root)
                    if os.path.isfile(expanded):
                        return expanded
        except Exception:
            pass
    return None


def firmware_sections(text: str) -> list[tuple[str, str]]:
    """Split on level-2 headings. The heading is the firmware name and is not discarded."""
    sections = []
    current_name = ""
    current_lines = []
    for line in (text or "").splitlines():
        match = HEADING_RE.match(line.strip())
        if match and len(match.group(1)) == 2:
            sections.append((current_name, "\n".join(current_lines)))
            current_name = match.group(2).strip()
            current_lines = [line]
        else:
            current_lines.append(line)
    sections.append((current_name, "\n".join(current_lines)))
    return sections


def section_matches(name: str, target: str) -> bool:
    if not target or not name:
        return False
    needle = normalize(target)
    hay = normalize(name)
    return hay == needle or needle in hay


def _clean_extracted_func(token: str) -> str | None:
    cand = clean_symbol_base(token)
    m = QUALIFIED_RE.search(token + "(") or re.search(r"\b([A-Za-z_][\w:]*(?:::[A-Za-z_][\w]*)*)\b", cand)
    if not m:
        return None
    name = m.group(1)
    if name.lower() in {"if", "for", "while", "switch", "return", "sizeof", "void", "int", "char", "uint8_t", "uint16_t", "uint32_t"}:
        return None
    if len(name) <= 2:
        return None
    return name


def affected_functions_from_description(desc_body: str, heading_title: str = "") -> list[str]:
    """Extract bug root-cause function names from prose/code description (excluding Fix code caves)."""
    found: list[str] = []
    for block in AFFECTED_BLOCK_RE.findall(desc_body or ""):
        match = QUALIFIED_RE.search(block) or re.search(r"\b([A-Za-z_][\w]*)\s*\(", block)
        if match:
            cleaned = _clean_extracted_func(match.group(1))
            if cleaned:
                found.append(cleaned)
    for regex in (AFFECTED_INLINE_RE, IN_FUNCTION_INLINE_RE, FUNC_SUCH_AS_RE, QUALIFIED_BACKTICK_RE,
                  FUNC_MENTION_BEFORE_RE, FUNC_MENTION_AFTER_RE):
        for raw in regex.findall(desc_body or ""):
            cleaned = _clean_extracted_func(raw)
            if cleaned:
                found.append(cleaned)
    if heading_title:
        hm = HEADING_IN_FUNC_RE.search(heading_title.strip())
        if hm:
            cleaned = _clean_extracted_func(hm.group(1))
            if cleaned:
                found.append(cleaned)
    for fc in FC_HANDLER_RE.findall(desc_body or ""):
        cleaned = _clean_extracted_func(fc)
        if cleaned:
            found.append(cleaned)
    unique: list[str] = []
    seen: set[str] = set()
    for name in found:
        key = function_key(name)
        if key and key not in seen:
            seen.add(key)
            unique.append(clean_symbol_base(name))
    return unique


def affected_functions(body: str) -> list[str]:
    """Backward-compatible helper over a section or bug body."""
    desc = (body or "").split("#### Fix", 1)[0]
    return affected_functions_from_description(desc)


def patch_addresses(body: str) -> list[int]:
    return [int(token, 16) for token in PATCH_ADDRESS_RE.findall(body or "")]


def extract_target_bugs(
    matched_notes: list[tuple[str, str]],
    matched_paper: list[tuple[str, str]],
    target: str,
    elf_funcs: list[tuple[int, int, str]],
) -> list[dict]:
    """Build structured per-bug truth records {bug_id, functions, addresses} for one target."""
    bugs: list[dict] = []
    bug_seq = 0

    def owner_of(addr: int) -> list[str]:
        even = addr & ~1
        return [fn for (fa, fs, fn) in elf_funcs if fa <= even < fa + fs]

    for _sec_name, sec_body in matched_notes:
        matches = list(BUG_HEADING_RE.finditer(sec_body or ""))
        if not matches:
            raw_addrs = patch_addresses(sec_body)
            funcs = affected_functions(sec_body)
            if not funcs and raw_addrs and elf_funcs:
                for fn in owner_of(raw_addrs[0]):
                    if function_key(fn) not in {function_key(x) for x in funcs}:
                        funcs.append(fn)
            addrs_set = set(raw_addrs)
            if funcs and raw_addrs and elf_funcs:
                in_func = {a for a in raw_addrs if any(function_match(fn, f) for fn in owner_of(a) for f in funcs)}
                addrs_set = in_func
            if funcs or addrs_set:
                bug_seq += 1
                bugs.append({"bug_id": f"{target or 'target'}#bug{bug_seq}", "functions": funcs, "addresses": addrs_set})
            continue

        for idx, m in enumerate(matches):
            start = m.start()
            end = matches[idx + 1].start() if idx + 1 < len(matches) else len(sec_body)
            sub_body = sec_body[start:end]
            heading_title = m.group(1)
            desc_part = sub_body.split("#### Fix", 1)[0]
            funcs = affected_functions_from_description(desc_part, heading_title=heading_title)
            raw_addrs = patch_addresses(sub_body)
            # Only fall back to ELF symbol lookup of primary patch site when prose description omitted function names;
            # when functions are known and ELF symbols are loaded, drop secondary code-cave donor patch addresses.
            if not funcs and raw_addrs and elf_funcs:
                for fn in owner_of(raw_addrs[0]):
                    if function_key(fn) not in {function_key(x) for x in funcs}:
                        funcs.append(fn)
            addrs_set = set(raw_addrs)
            if funcs and raw_addrs and elf_funcs:
                in_func = {a for a in raw_addrs if any(function_match(fn, f) for fn in owner_of(a) for f in funcs)}
                addrs_set = in_func
            if not funcs and not addrs_set:
                continue
            bug_seq += 1
            bugs.append({
                "bug_id": f"{target or 'target'}#bug{bug_seq}",
                "functions": funcs,
                "addresses": addrs_set,
            })

    for _sec_name, p_body in matched_paper:
        p_funcs: list[str] = []
        p_funcs.extend(FC_HANDLER_RE.findall(p_body or ""))
        for block in AFFECTED_BLOCK_RE.findall(p_body or ""):
            p_funcs.extend(affected_functions("Affected function:\n```\n" + block + "\n```"))
        for fn in p_funcs:
            cleaned = _clean_extracted_func(fn)
            if not cleaned:
                continue
            if any(any(function_match(cleaned, existing) for existing in b["functions"]) for b in bugs):
                continue
            bug_seq += 1
            bugs.append({"bug_id": f"{target or 'target'}#paper{bug_seq}", "functions": [cleaned], "addresses": set()})

    return bugs


def mention_count(matched: list[tuple[str, str]], target: str) -> int:
    if not target:
        return 0
    needle = target.lower()
    count = 0
    for name, body in matched:
        if needle in name.lower():
            count += 1
        for line in body.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if needle in stripped.lower():
                count += 1
    return count


def parse_addresses(values) -> set[int]:
    found = set()
    for value in values or []:
        text = str(value).strip().lower()
        if text.startswith("0x"):
            text = text[2:]
        if re.fullmatch(r"[0-9a-f]{4,8}", text):
            found.add(int(text, 16))
    return found


def parse_bbl_range(value) -> tuple[int, int] | None:
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        return None
    pts = []
    for item in value:
        text = str(item or "").strip().lower()
        if text.startswith("0x"):
            text = text[2:]
        if not re.fullmatch(r"[0-9a-f]{4,8}", text):
            return None
        pts.append(int(text, 16) & ~1)
    if pts[1] < pts[0] or pts[1] - pts[0] > 512:
        return None
    return pts[0], pts[1]


def score(notes_text: str, paper_text: str, candidates: list[dict], target: str, elf_path: str | None = None) -> dict:
    notes_sections = firmware_sections(notes_text)
    paper_sections = firmware_sections(paper_text) if paper_text else []
    matched_notes = [(name, body) for name, body in notes_sections if section_matches(name, target)]
    matched_paper = [(name, body) for name, body in paper_sections if section_matches(name, target)]

    elf_funcs = load_elf_functions(elf_path)
    bugs = extract_target_bugs(matched_notes, matched_paper, target, elf_funcs)

    known_functions: list[str] = []
    seen_fn: set[str] = set()
    known_addresses: set[int] = set()
    for bug in bugs:
        known_addresses |= bug["addresses"]
        for fn in bug["functions"]:
            k = function_key(fn)
            if k and k not in seen_fn:
                seen_fn.add(k)
                known_functions.append(fn)

    diagnostics = {
        "sections_matched": len(matched_notes) + len(matched_paper),
        "notes_sections_matched": [name for name, _body in matched_notes],
        "paper_sections_matched": len(matched_paper),
        "rows_mentioning_target": mention_count(matched_notes + matched_paper, target),
        "known_bugs": len(bugs),
        "known_functions": len(known_functions),
        "patch_addresses": len(known_addresses),
        "elf_symbols_loaded": len(elf_funcs) > 0,
        "heading_rule": "level-2",
    }

    results = []
    direct_bug_ids: set[str] = set()
    downstream_bug_ids: set[str] = set()
    unmatched_fps: set[tuple[str, tuple[int, ...]]] = set()
    bare_unmatched_fps: set[tuple[str, tuple[int, ...]]] = set()

    for candidate in candidates:
        if target and candidate.get("target") not in (None, "", target):
            continue
        function = candidate.get("function") or ""
        addresses = parse_addresses(candidate.get("addresses") or [])
        norm_addrs = {a & ~1 for a in addresses}
        bbl_span = parse_bbl_range(candidate.get("bbl_range"))
        upstream = [name for name in (candidate.get("upstream_functions") or []) if isinstance(name, str)]

        direct_by: list[str] = []
        known_hit: str | None = None
        matched_direct_bugs: list[str] = []
        address_hits: set[int] = set()

        for bug in bugs:
            bug_direct = False
            for known in bug["functions"]:
                if function_match(function, known):
                    if "function" not in direct_by:
                        direct_by.append("function")
                    if known_hit is None:
                        known_hit = known
                    bug_direct = True
                    break
            for paddr in bug["addresses"]:
                peven = paddr & ~1
                in_set = (paddr in addresses) or (peven in norm_addrs)
                in_bbl = bbl_span is not None and (bbl_span[0] <= peven <= bbl_span[1])
                if in_set or in_bbl:
                    address_hits.add(paddr)
                    bug_direct = True
            if bug_direct:
                matched_direct_bugs.append(bug["bug_id"])

        if address_hits:
            direct_by.append("patch_address")
            direct_by.extend("address:0x%x" % value for value in sorted(address_hits))

        upstream_hits: list[str] = []
        matched_downstream_bugs: list[str] = []
        for bug in bugs:
            for name in upstream:
                hit_fn = next((known for known in bug["functions"] if function_match(name, known)), None)
                if hit_fn is not None:
                    if hit_fn not in upstream_hits:
                        upstream_hits.append(hit_fn)
                    if bug["bug_id"] not in matched_downstream_bugs:
                        matched_downstream_bugs.append(bug["bug_id"])
                    break

        fp = (function_key(function) or "nofunc", tuple(sorted(norm_addrs)))
        if direct_by:
            status = "known_p2im_bug_direct"
            direct_bug_ids.update(matched_direct_bugs)
            match = {
                "matched_by": direct_by,
                "known_function": known_hit,
                "bug_ids": matched_direct_bugs,
                "patch_addresses": ["0x%x" % value for value in sorted(address_hits)],
            }
        elif upstream_hits:
            status = "known_p2im_bug_downstream"
            downstream_bug_ids.update(matched_downstream_bugs)
            bare_unmatched_fps.add(fp)
            match = {
                "matched_by": ["upstream_function"],
                "known_function": upstream_hits[0],
                "bug_ids": matched_downstream_bugs,
                "upstream_functions": upstream_hits,
                "via_shared_global": candidate.get("via_shared_global"),
                "adjacent_global": candidate.get("adjacent_global"),
            }
        else:
            status = "unmatched_verified_candidate"
            unmatched_fps.add(fp)
            bare_unmatched_fps.add(fp)
            match = None

        results.append({
            "candidate": {key: candidate.get(key) for key in (
                "target", "function", "addresses", "bbl_range", "upstream_functions", "via_shared_global", "adjacent_global")},
            "matched": status != "unmatched_verified_candidate",
            "match": match,
            "status": status,
        })

    direct = sum(1 for item in results if item["status"] == "known_p2im_bug_direct")
    downstream = sum(1 for item in results if item["status"] == "known_p2im_bug_downstream")
    unmatched = sum(1 for item in results if item["status"] == "unmatched_verified_candidate")

    unique_direct_bugs = len(direct_bug_ids)
    unique_downstream_only_bugs = len(downstream_bug_ids - direct_bug_ids)
    unique_total_bugs = len(direct_bug_ids | downstream_bug_ids)

    return {
        "schema": "mcu-p2im/l5-0.4",
        "target": target,
        "raw_text_emitted": False,
        "diagnostics": diagnostics,
        "counts": {
            "candidates": len(results),
            "known_p2im_bug_direct": direct,
            "known_p2im_bug_downstream": downstream,
            "unmatched_verified_candidate": unmatched,
        },
        "unique_bugs": {
            "known_bugs_in_truth": len(bugs),
            "unique_known_bugs_direct": unique_direct_bugs,
            "unique_known_bugs_downstream": unique_downstream_only_bugs,
            "unique_known_bugs_total": unique_total_bugs,
            "matched_bug_ids": sorted(direct_bug_ids | downstream_bug_ids),
            "unique_unmatched_fingerprints": len(unmatched_fps),
        },
        "attribution_split": {
            "bare_without_sram_slice": {
                "candidates": len(results),
                "known_p2im_bug_direct": direct,
                "known_p2im_bug_downstream": 0,
                "unmatched_verified_candidate": len(results) - direct,
                "matched_total": direct,
                "unique_known_bugs_direct": unique_direct_bugs,
                "unique_known_bugs_downstream": 0,
                "unique_known_bugs_total": unique_direct_bugs,
                "unique_unmatched_fingerprints": len(bare_unmatched_fps),
            },
            "with_shared_sram_slice": {
                "candidates": len(results),
                "known_p2im_bug_direct": direct,
                "known_p2im_bug_downstream": downstream,
                "unmatched_verified_candidate": unmatched,
                "matched_total": direct + downstream,
                "unique_known_bugs_direct": unique_direct_bugs,
                "unique_known_bugs_downstream": unique_downstream_only_bugs,
                "unique_known_bugs_total": unique_total_bugs,
                "unique_unmatched_fingerprints": len(unmatched_fps),
            },
            "sram_slice_net_gain": {
                "additional_matched_candidates": downstream,
                "downstream_attributed": downstream,
                "additional_unique_known_bugs": unique_downstream_only_bugs,
            },
        },
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--notes", required=True)
    parser.add_argument("--paper-text")
    parser.add_argument("--candidates", required=True)
    parser.add_argument("--elf", help="Optional path to unpatched target ELF for patch-address symbol lookup")
    parser.add_argument("--target", default="")
    parser.add_argument("--summary-only", action="store_true",
                        help="Omit per-candidate upstream lists and emit summary counts + deduplicated bug totals")
    parser.add_argument("--out")
    args = parser.parse_args()
    with open(args.notes, "r", encoding="utf-8", errors="replace") as handle:
        notes_text = handle.read()
    paper_text = ""
    if args.paper_text:
        if not os.path.isfile(args.paper_text):
            print(json.dumps({"ok": False, "error": "paper text is not a file"}), file=sys.stderr)
            return 3
        with open(args.paper_text, "r", encoding="utf-8", errors="replace") as handle:
            paper_text = handle.read()
    with open(args.candidates, "r", encoding="utf-8") as handle:
        cand_doc = json.load(handle)
    work_dir = None
    if isinstance(cand_doc, dict):
        work_dir = cand_doc.get("work_dir")
        if not args.target and isinstance(cand_doc.get("target"), str):
            args.target = cand_doc["target"]
        candidates = cand_doc.get("candidates", [])
    else:
        candidates = cand_doc
    elf_path = resolve_elf_path(args.target, explicit_elf=args.elf, work_dir=work_dir)
    result = score(notes_text, paper_text, candidates, args.target, elf_path=elf_path)
    if args.summary_only:
        result = {k: v for k, v in result.items() if k != "results"}
        result["summary_only"] = True
    result["sources"] = {
        "notes_sha256": sha256_file(args.notes),
        "paper_text_present": bool(paper_text),
        "paper_sha256": sha256_file(args.paper_text) if paper_text else None,
        "elf_resolved": bool(elf_path),
    }
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(result, handle, indent=2)
            handle.write("\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
