#!/usr/bin/env python3
"""Pre-publish privacy, secret, and build-artifact audit for firmagent-p2im."""

from __future__ import annotations

import os
import re
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

FORBIDDEN_LITERALS = (
    "".join(("magic", "spirit")),
    "".join(("189", "93")),
    "".join(("Stability", "TestW")),
    "".join(("058a8636", "036e443ca0faa50587f353da")),
    "".join(("b945ff59", "62dd484baef665de1495306c")),
    "".join(("100.", "80.", "74.8")),
    "\x2ecredentials\x2eyaml",
    "\u5b98\u5bb6",
    "\u81e3\u5148",
    "\u542f\u594f",
)

FORBIDDEN_REGEXES = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}"),
    re.compile(r"DEEPSEEK_API_KEY\s*=\s*['\"]?sk-", re.IGNORECASE),
    re.compile(r"BEGIN\s+(?:RSA|OPENSSH|EC|DSA)?\s*PRIVATE\s+KEY"),
)

FORBIDDEN_DIR_NAMES = {".git" + "_ignore_none", "node_modules", "dist", "__pycache__", "runs", "work", "deps"}
FORBIDDEN_FILE_NAMES = {"auth.json", ".env"}


def main() -> int:
    hits = []
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs if d != ".git"]
        for d in dirs:
            if d in FORBIDDEN_DIR_NAMES:
                hits.append({"path": os.path.relpath(os.path.join(root, d), REPO_ROOT), "reason": f"forbidden_dir:{d}"})
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, REPO_ROOT)
            if name in FORBIDDEN_FILE_NAMES or name.startswith(".env.") or name.endswith(".pyc") or name.endswith(".tar.zst"):
                hits.append({"path": rel, "reason": f"forbidden_file:{name}"})
                continue
            try:
                raw = open(full, "rb").read()
            except OSError as exc:
                hits.append({"path": rel, "reason": f"unreadable:{exc}"})
                continue
            if raw.startswith(b"\x7fELF") and len(raw) > 1024 * 1024:
                hits.append({"path": rel, "reason": "large_elf_binary"})
                continue
            text = raw.decode("utf-8", errors="ignore")
            for literal in FORBIDDEN_LITERALS:
                if literal in text:
                    hits.append({"path": rel, "reason": f"forbidden_literal_len_{len(literal)}"})
            for regex in FORBIDDEN_REGEXES:
                if regex.search(text):
                    hits.append({"path": rel, "reason": f"forbidden_regex:{regex.pattern}"})

    print(f"privacy_audit: scanned {REPO_ROOT}, hits={len(hits)}")
    for item in hits:
        print(f"  [FAIL] {item['path']}: {item['reason']}")
    return 0 if not hits else 1


if __name__ == "__main__":
    sys.exit(main())
