#!/usr/bin/env python3
"""Host-only L5 scorer for the P2IM blind test.

This is the ONLY component allowed to read the known-bug truth set. It runs after every Agent
phase has ended, in a separate process, and by default prints counts and our own candidate names
only, so the truth text does not re-enter an orchestrator or Agent context that could later be
reused for another target.

Inputs:
  --notes PATH        P2IM_patching_notes.md. Firmware sections are level-2 headings (## PLC).
  --paper-text PATH   optional plain-text extraction of the P2IM paper. Read only in this process.
  --candidates PATH   JSON list of verified candidates {target, function, addresses,
                      upstream_functions, via_shared_global, ...}
  --target NAME       restrict scoring to one firmware
Outputs one JSON object on stdout. Matched truth text is not echoed; only the function name,
the match rule and the status are.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{4,8}")
PATCH_ADDRESS_RE = re.compile(r"(?m)^\s*address:\s*(0x[0-9a-fA-F]{4,8})\b")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
AFFECTED_BLOCK_RE = re.compile(r"Affected function:\s*```[^\n]*\n(.*?)```", re.S)
QUALIFIED_RE = re.compile(r"\b([A-Za-z_][\w]*::[A-Za-z_][\w]*)\s*\(")
PROCESS_FC_RE = re.compile(r"\b((?:[A-Za-z_][\w]*::)?process_FC\d+)\b")


def sha256_file(path):
    import hashlib
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize(text):
    return re.sub(r"[^a-z0-9]+", "", (text or "").lower())


def function_key(name):
    """Drop a parameter list and whitespace. Keep '::' so a suffix cannot impersonate a qualifier."""
    base = (name or "").split("(", 1)[0].strip().lower()
    return re.sub(r"\s+", "", base)


def function_match(left, right):
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


def firmware_sections(text):
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


def section_matches(name, target):
    if not target or not name:
        return False
    needle = normalize(target)
    hay = normalize(name)
    return hay == needle or needle in hay


def affected_functions(body):
    """Bug functions are the signatures under 'Affected function', plus process_FC* names.

    Other callees that happen to be quoted in the same section (send path, code cave) are not
    bug functions. A crash in one of those is not a direct hit.
    """
    found = []
    for block in AFFECTED_BLOCK_RE.findall(body or ""):
        match = QUALIFIED_RE.search(block) or re.search(r"\b([A-Za-z_][\w]*)\s*\(", block)
        if match:
            name = match.group(1)
            if name not in ("if", "for", "while", "switch"):
                found.append(name)
    found.extend(PROCESS_FC_RE.findall(body or ""))
    unique = []
    seen = set()
    for name in found:
        key = function_key(name)
        if key and key not in seen:
            seen.add(key)
            unique.append(name.split("(", 1)[0].strip())
    return unique


def patch_addresses(body):
    return {int(token, 16) for token in PATCH_ADDRESS_RE.findall(body or "")}


def mention_count(matched, target):
    """How the firmware name is anchored. A level-2 heading counts even though it starts with #."""
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


def parse_addresses(values):
    found = set()
    for value in values or []:
        text = str(value).strip().lower()
        if text.startswith("0x"):
            text = text[2:]
        if re.fullmatch(r"[0-9a-f]{4,8}", text):
            found.add(int(text, 16))
    return found


def score(notes_text, paper_text, candidates, target):
    notes_sections = firmware_sections(notes_text)
    paper_sections = firmware_sections(paper_text) if paper_text else []
    matched_notes = [(name, body) for name, body in notes_sections if section_matches(name, target)]
    matched_paper = [(name, body) for name, body in paper_sections if section_matches(name, target)]
    known_functions = []
    known_addresses = set()
    for _name, body in matched_notes:
        known_functions.extend(affected_functions(body))
        known_addresses |= patch_addresses(body)
    # Paper text may name the same bug functions. It does not add patch addresses and it does
    # not add every symbol mentioned beside a crash site; those stay downstream.
    for _name, body in matched_paper:
        known_functions.extend(PROCESS_FC_RE.findall(body))
        for block in AFFECTED_BLOCK_RE.findall(body):
            known_functions.extend(affected_functions("Affected function:\n```\n" + block + "\n```"))
    deduped = []
    seen = set()
    for name in known_functions:
        key = function_key(name)
        if key and key not in seen:
            seen.add(key)
            deduped.append(name.split("(", 1)[0].strip())
    known_functions = deduped
    diagnostics = {
        "sections_matched": len(matched_notes) + len(matched_paper),
        "notes_sections_matched": [name for name, _body in matched_notes],
        "paper_sections_matched": len(matched_paper),
        "rows_mentioning_target": mention_count(matched_notes + matched_paper, target),
        "known_functions": len(known_functions),
        "patch_addresses": len(known_addresses),
        "heading_rule": "level-2",
    }
    results = []
    for candidate in candidates:
        if target and candidate.get("target") not in (None, "", target):
            continue
        function = candidate.get("function") or ""
        addresses = parse_addresses(candidate.get("addresses") or [])
        upstream = [name for name in (candidate.get("upstream_functions") or []) if isinstance(name, str)]
        direct_by = []
        known_hit = None
        for known in known_functions:
            if function_match(function, known):
                direct_by.append("function")
                known_hit = known
                break
        address_hits = sorted(addresses & known_addresses)
        if address_hits:
            direct_by.append("patch_address")
            direct_by.extend("address:0x%x" % value for value in address_hits)
        upstream_hits = []
        for name in upstream:
            for known in known_functions:
                if function_match(name, known):
                    upstream_hits.append(known)
                    break
        if direct_by:
            status = "known_p2im_bug_direct"
            match = {"matched_by": direct_by, "known_function": known_hit,
                     "patch_addresses": ["0x%x" % value for value in address_hits]}
        elif upstream_hits:
            status = "known_p2im_bug_downstream"
            match = {"matched_by": ["upstream_function"], "known_function": upstream_hits[0],
                     "upstream_functions": upstream_hits,
                     "via_shared_global": candidate.get("via_shared_global"),
                     "adjacent_global": candidate.get("adjacent_global")}
        else:
            status = "unmatched_verified_candidate"
            match = None
        results.append({
            "candidate": {key: candidate.get(key) for key in (
                "target", "function", "addresses", "upstream_functions", "via_shared_global", "adjacent_global")},
            "matched": status != "unmatched_verified_candidate",
            "match": match,
            "status": status,
        })
    direct = sum(1 for item in results if item["status"] == "known_p2im_bug_direct")
    downstream = sum(1 for item in results if item["status"] == "known_p2im_bug_downstream")
    unmatched = sum(1 for item in results if item["status"] == "unmatched_verified_candidate")
    return {
        "schema": "mcu-p2im/l5-0.3",
        "target": target,
        "diagnostics": diagnostics,
        "counts": {
            "candidates": len(results),
            "known_p2im_bug_direct": direct,
            "known_p2im_bug_downstream": downstream,
            "unmatched_verified_candidate": unmatched,
        },
        "results": results,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--notes", required=True)
    parser.add_argument("--paper-text")
    parser.add_argument("--candidates", required=True)
    parser.add_argument("--target", default="")
    parser.add_argument("--summary-only", action="store_true")
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
        candidates = json.load(handle)
    if isinstance(candidates, dict):
        candidates = candidates.get("candidates", [])
    result = score(notes_text, paper_text, candidates, args.target)
    result["sources"] = {"notes_sha256": sha256_file(args.notes),
                         "paper_text_present": bool(paper_text),
                         "paper_sha256": sha256_file(args.paper_text) if paper_text else None}
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2)
            handle.write("\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
