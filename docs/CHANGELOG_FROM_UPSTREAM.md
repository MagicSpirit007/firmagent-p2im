# Upstream Modifications & Technical Changelog (`CHANGELOG_FROM_UPSTREAM.md`)

To guarantee full experimental reproducibility without altering any target firmware binary bytes, all modifications required to run stock P2IM (`RiS3-Lab/p2im@0e64506a`) and legacy `FirmAgent` concepts cleanly on Ubuntu 24.04 + Pi SDK `0.85.1` are documented below across three layers—including **Before (Stock Failure Symptom) -> After (Observable Fix & Verification)** evidence.

---

## Layer A: Ubuntu 24.04 & Python 3.12 Host Adaptations (over Stock `RiS3-Lab/p2im`)

| Component | Upstream State & Failure Symptom (Before) | Modification in This Repo (Location) | Observable After & Verification |
|---|---|---|---|
| AFL 2.06b (`afl/`) | Only 2015 C source shipped; no compatible x86-64 Ubuntu 24.04 binary | Compiled natively with GCC 13+ via `make -C "$P2IM_ROOT/afl" -j"$(nproc)"` | Produces runnable `$P2IM_ROOT/afl/afl-fuzz` ABI-matched to host glibc |
| `fuzz.py`, `me.py`, `cov.py` | Fails on Python 3.12 (`SafeConfigParser` removed); naive rename breaks `fuzz.cfg` inline `#` comments; retries `0x72` loops; resets `--model-if` to `0/` on `s2`; runs unscoped `killall` | `patches/p2im-python312-scripts.patch`: uses `ConfigParser(inline_comment_prefixes=('#', ';'))`, invokes `wsl_compat.apply_wsl_compat()`, adds `no_retry = {0x72}`, preserves explicit `--model-if` and supports `--skip-seed-prefix`, removes unscoped `killall` in signal handlers, preserves `qemu-stderr.txt` | Python 3.12 runs `me.py`/`fuzz.py`/`cov.py` cleanly without `SyntaxWarning`, preserves `s1 -> s2` model continuity, and avoids killing parallel experiments |
| `wsl_compat.py` + `me` wrapper | Direct `#!` execution fails on WSL2 CRLF/missing `AFL_*` env vars (`All test cases time out or crash` / CPU scaling check) | `p2im-shim/wsl_compat.py` + bash `me` wrapper (`exec python3 .../me.py "$@"`) | Ensures `AFL_SKIP_CPUFREQ`, `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES`, `AFL_NO_AFFINITY`, `AFL_SKIP_CRASHES`, `PYTHONUNBUFFERED` under WSL2 |
| Host package `psmisc` & ARM binutils | Minimal Ubuntu/WSL2 lacks `killall`, causing `me.py` / `cov.py` to fail cleanup or leave stray QEMU processes | Requires `psmisc` (`killall`) + `binutils-arm-none-eabi` (`/usr/bin/arm-none-eabi-objdump/nm/readelf`) + `sweep_work()` in `tools/p2im_oracle.py` | Clean round termination with zero orphan `afl-fuzz` / `qemu-system-gnuarmeclipse` processes |
| Runtime working tree layout | Upstreams fail silently or abort with `EPERM: fsync` on `/mnt/*` and `-c options should be shorter than 100 bytes` on nested dirs | Enforces Linux ext4 short paths (`/tmp/fa-p2im/<slug>`) and validates length upfront in `scripts/generate_configs.py` & `cmd_prepare`/`cmd_fuzz` | Rejects unsafe paths immediately with exit `3` instead of failing minutes into fuzzing |

> **Prebuilt-QEMU note (Before -> After)**: Running upstream P2IM's precompiled 2017 Ubuntu 16.04 binary directly on Ubuntu 24.04 hits `GLIBC_PRIVATE` mismatches against bundled `librt*.so` / `libutil*.so`, while keeping 2017 `libglib-2.0.so.0` (2.51) on `LD_LIBRARY_PATH` breaks newly built QEMU binaries with `undefined symbol: g_string_free_and_steal`. Rebuilding QEMU natively and isolating it via `Work.install_shim()` (`unset LD_LIBRARY_PATH`) eliminates both classes of dynamic-linker failure.

---

## Layer B: QEMU 2.3.50 C-Level & Build Fixes (`patches/p2im-qemu-auto-forkserver.patch`)

16 files modified inside `RiS3-Lab/p2im/qemu/src/qemu.git`:

1. **Opt-in `P2IM_AUTO_FORKSERVER_PC` (`cpu-exec.c`, `target-arm/translate.c`)**:
   - **Before**: Unpatched `Soldering_Iron.elf` (`44a6f0e3…`, from `hoedur-experiments/targets/arm/unpatched-est-data-set/P2IM`) contains `0` `svc #0x3f` instructions (`p2im_runnable=false`), so QEMU never calls `startForkserver` and cannot run under `me.py` or `afl-fuzz`.
   - **Modification**: Added `p2im_maybe_auto_forkserver(env, tb->pc, tb->size)` invoked right before `cpu_tb_exec`. Strictly gated on `P2IM_AUTO_FORKSERVER_PC` (no-op when unset for all 9 `svc 0x3f` targets; set only in `soldering-iron.json` to `"0x08000268"`).
   - **After**: Zero ELF bytes modified; historical WSL validation measured `smoke` (`0.016s`, `start up afl forkserver!`), Round 0 model (`13` peripherals, `33` DR), and `60.066s` fuzzing (`193 execs`, `12 paths`).
2. **Peripheral MMIO Instruction-Fetch Guard `PM_EXEC_PERI = 0x72` (`cputlb.c`, `memory.c`, `include/peri-mod/peri-mod.h`, `include/afl/afl-qemu-cpu-inl.h`)**:
   - **Before**: Out-of-bounds bugs (such as Modbus write overflows overwriting `rx_callback`) jump PC into `0x40000000..0x5fffffff`; QEMU's code fetch hit `unassigned_mem_read`, misclassifying the crash as an unmodeled peripheral access (`0x40`) and triggering pointless `me.py` retry loops.
   - **Modification**: `pm_fetching_code` ensures `unassigned_mem_read` returns `0` during instruction fetch; `get_page_addr_code` logs `guest_code_fetch addr=... pc=... r0=... r3=...` and exits cleanly with `0x72`, paired with `no_retry = {0x72}` in `fuzz.py`/`me.py`/`cov.py`.
   - **After**: False `0x40` retry loops are suppressed and crash register context is preserved.
3. **Headless & Python 3.12 Build Fixes (`configure`, `hw/display/gpio-led.c`, `hw/arm/cortexm-helper.c`, `scripts/*.py`)**:
   - **Before**: `configure` rejected Python `>= 3`; `qapi`/`tracetool` failed Python 3 syntax checks; `--disable-sdl` broke `gpio-led.c`/`cortexm-helper.c`; enabling `CONFIG_KINETIS=y` registered `FRDM-K64F` twice and aborted startup.
   - **After**: Compiles headless `gnuarmeclipse-softmmu` natively on Ubuntu 24.04 with `-nographic`, `CONFIG_STM32=y` and `CONFIG_KINETIS=n`/`CONFIG_SAM=n`, verified by `nm ... | grep ' T p2im_maybe_auto_forkserver'`.

---

## Layer C: FirmAgent/Pi `mcu-p2im` Mode, Slicer & Offline `L5` Scorer

1. **Controlled Pi SDK `0.85.1` Runtime (`src/`)**:
   - **Before**: Free-form Linux agent shells risked orphan QEMU/AFL processes, unbudgeted token spend, provider fallbacks, or reading known-CVE files on disk.
   - **After**: Single controlled session factory (`src/core/session.ts`), serial `RunGovernance` budget ledger (`src/campaign/governance.ts`), `/proc` start-time-verified cleanup (`src/campaign/owned-process.ts`), and frozen role prompts (`main`, `discover`, `replay`).
2. **Two-Stage Closed-Loop Pipeline (`src/campaign/mcu-runtime.ts`)**:
   - `prepare -> model -> discover_seg1 -> slice -> analyze_and_propose -> discover_seg2 (--include-proposed) -> triage_and_verify (3x replay + Contrast byte ablation) -> score`.
   - Host-side `seed_propose` validator verifies hex encoding, max 256-byte cap, Modbus RTU CRC16 checksum (`crc16_modbus`), and blind-test anti-leak regex before admitting seeds into `proposed-seeds/` (leaving original `inputs/` untouched).
3. **Host Execution Oracle & `10/10` Compatibility Fixes (`tools/p2im_oracle.py`)**:
   - **Reflow_Oven (`Before -> After`)**: Single 256B `seed-random` caused immediate dry-run crash (`afl-fuzz.c:2811` `PROGRAM ABORT`, `0.366s`, `0 execs`); writing a 4B `seed-short` (`0\n\x00\x00`) alongside `seed-random` unblocked fuzzing (`60.604s`, `2582 execs`, `26 paths` in historical 2026-11-17 validation).
   - **CNC Board Lock (`Before -> After`)**: Defaulting `CNC` to `STM32F4-Discovery / STM32F407VG` exited `-11` (`mem_r *0x0`, `0` peripherals/`0` DR); empirical lock to `STM32F429I-Discovery / STM32F429ZI` enabled P2IM modeling (`12` peripherals, `39` DR, `2926 execs` in `60.017s`).
   - **Register Stride & Trace Demangling (`Before -> After`)**: `reg_size` stride (`base + index * reg_size`) fixed 1-byte K64F UART slots (`Console`), recursive `reg_acc*` collection captured `depth:*` logs, and `c++filt` aligned QEMU/nm C++ symbols.
4. **Shared-SRAM Dataflow & `indexed_reach` Slicer (`tools/p2im_oracle.py`, `src/campaign/mcu-runtime.ts`)**:
   - **Before**: Three-letter `add` mnemonics were dropped by objdump parsing, literal pools (`slave` `0x20000124` -> `rx_callback` `0x20000214`) were unlinked across ISR-to-main boundaries, and plain self-references in `HAL_UART_RxCpltCallback` overwrote cross-object upstream links (`L5 downstream = 0` on `PLC` attempt 2).
   - **After**: `DISASM_PARSER_VERSION = 3` + `indexed_member_sites` + `merge_indexed_reach` attach bounded vs unbounded byte-index overlaps with `call_edge: false`, and `sharedViaRank()` ranks `indexed_reach (3) > adjacent (2) > self (1)`. `s2` inherits `s1` queue seeds via `<100B`-safe short names (`b00`/`q0000`/`p00`, mapped in `evidence/inputs-s2-map.json`) and carries cumulative peripheral models via `0.s2/peripheral_model.json`.
5. **Isolated Offline `L5` Scorer, Multi-Arm Comparator & Anti-Leak Gate (`scripts/score_l5.py`, `scripts/eval_arms.py`, `scripts/leak_check.py`)**:
   - **Before**: `score_l5.py` discarded markdown `#` headings and inline backtick / address-only bug entries (missing truth functions on `CNC`, `Heat_Press`, `Soldering_Iron`, and `Gateway` Bug 1), and counted multiple crash witnesses of the same bug separately.
   - **After**: Parses per-bug `### Bug` / `### Known, unpatched Bugs` subsections across all 5 truth-annotated targets (12 bugs total) backed by pure-Python ELF32 `.symtab` code-cave filtering and `bbl_range` containment, deduplicates `L2–L4` by crash fingerprint (`s2`-first interleaved triage) and `L5` (`unique_bugs`) by `bug_id`, separates `B0` bare vs `B0` + offline SRAM slice attribution (`eval_arms.py`), isolates post-hoc `bbl-coverage` from `end_to_end_wall_ms`, and enforces zero `CVE-`/`CWE-`/`Table 5` leakage across prompts, slices, tool envelopes, and `ledger.jsonl`.
