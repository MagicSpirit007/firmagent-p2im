# Upstream Modifications & Technical Changelog (`CHANGELOG_FROM_UPSTREAM.md`)

To guarantee full experimental reproducibility without altering any target firmware binary bytes, all modifications required to run stock P2IM (`RiS3-Lab/p2im@0e64506a`) and legacy `FirmAgent` concepts cleanly on Ubuntu 24.04 + Pi SDK `0.85.1` are documented below across three layers.

---

## Layer A: Ubuntu 24.04 & Python 3.12 Host Adaptations (over Stock `RiS3-Lab/p2im`)

| Component | Upstream State | Modification in This Repo | Reason |
|---|---|---|---|
| AFL 2.06b (`afl/`) | Only 2015 C source shipped | Compiled natively with GCC 13+ via `make -C afl` | Upstream provides no Linux x86-64 binary compatible with modern toolchains |
| `fuzz.py`, `me.py`, `cov.py` | Calls removed `configparser.SafeConfigParser()`, lacks WSL2 env setup, lacks `0x72` handling | `patches/p2im-python312-scripts.patch`: uses `ConfigParser(inline_comment_prefixes=('#', ';'))`, invokes `wsl_compat.apply_wsl_compat()`, adds `no_retry = {0x72}`, preserves `qemu-stderr.txt`, uses `error_rv.get` | Python 3.12 removed `SafeConfigParser`; inline comments in `fuzz.cfg` must stay ignored; `0x72` peripheral instruction fetches must not trigger pointless retry loops |
| `wsl_compat.py` + `me` wrapper | Direct `#!` execution fails on WSL2 CRLF/missing `AFL_*` env vars | `p2im-shim/wsl_compat.py` + bash `me` wrapper (`exec python3 .../me.py "$@"`) | Ensures `AFL_SKIP_CPUFREQ`, `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES`, `AFL_NO_AFFINITY`, `AFL_SKIP_CRASHES`, `PYTHONUNBUFFERED` under WSL2 |
| Host package `psmisc` & ARM binutils | Assumes `killall` & 2017 `arm-none-eabi-gcc` | Requires `psmisc` (`killall`) + `binutils-arm-none-eabi` (`/usr/bin/arm-none-eabi-objdump/nm/readelf`) | `me.py` / `cov.py` call `killall`; model instantiation & slicing need `objdump` / `nm` without compiling new firmware |
| Runtime working tree layout | Upstreams assumed native short Linux path | Enforces Linux ext4 short paths (`/tmp/fa-p2im/<slug>`) | Prevents 9p `fsync EPERM` on `/mnt/*` and satisfies P2IM AFL's hardcoded `< 100` byte `-c` buffer limit |

> **Prebuilt-QEMU note (historical context)**: When running upstream P2IM's original precompiled Ubuntu 16.04 binary instead of rebuilding from source, its bundled `librt*.so` / `libutil*.so` (glibc 2.19) conflict with Ubuntu 24.04 `GLIBC_PRIVATE` symbols and must be unlinked, while `libglib-2.0.so.0` (2.51) breaks newly compiled QEMU binaries (`g_string_free_and_steal`). Our release rebuilds QEMU natively via `scripts/setup_upstreams.sh` and drops `LD_LIBRARY_PATH` inside the oracle wrapper shim.

---

## Layer B: QEMU 2.3.50 C-Level & Build Fixes (`patches/p2im-qemu-auto-forkserver.patch`)

16 files modified inside `RiS3-Lab/p2im/qemu/src/qemu.git`:

1. **Opt-in `P2IM_AUTO_FORKSERVER_PC` (`cpu-exec.c`, `target-arm/translate.c`)**:
   - Unpatched `Soldering_Iron.elf` (`44a6f0e3…`, from `hoedur-experiments/targets/arm/unpatched-est-data-set/P2IM`) contains `0` `svc #0x3f` instructions and thus never enters `startForkserver` in stock P2IM.
   - Added `p2im_maybe_auto_forkserver(env, tb->pc, tb->size)` invoked right before `cpu_tb_exec`. When `P2IM_AUTO_FORKSERVER_PC` is unset, it is a strict no-op; when set (only in `soldering-iron.json` to `"0x08000268"`), it invokes `startForkserver(env, 0)` once, running the completely unmodified binary through `me.py`, AFL, and deterministic replay.
2. **Peripheral MMIO Instruction-Fetch Guard `PM_EXEC_PERI = 0x72` (`cputlb.c`, `memory.c`, `include/peri-mod/peri-mod.h`, `include/afl/afl-qemu-cpu-inl.h`)**:
   - Out-of-bounds bugs (such as Modbus write overflows overwriting a function pointer table) can jump into `0x40000000..0x5fffffff`.
   - `pm_fetching_code` ensures `unassigned_mem_read` returns `0` during code fetch instead of spuriously creating an unmodeled peripheral (`0x40`); `get_page_addr_code` logs `guest_code_fetch addr=... pc=... r0=... r3=...` and exits cleanly with `0x72`, which `afl_forkserver` ignores instead of triggering `me.py` abort loops.
3. **Headless & Python 3.12 Build Fixes (`configure`, `hw/display/gpio-led.c`, `hw/arm/cortexm-helper.c`, `scripts/*.py`)**:
   - Removed Python `>= 3` rejection in `configure`; guarded SDL graphics code under `#if defined(CONFIG_SDL)` for `--disable-sdl`; updated 7 QEMU build scripts for Python 3.12.
   - Kept `default-configs/gnuarmeclipse-softmmu.mak` at `CONFIG_STM32=y` and `CONFIG_KINETIS=n`/`CONFIG_SAM=n` so P2IM's `FRDM-K64F` board in `stm32-boards.c` is not registered twice.

---

## Layer C: FirmAgent/Pi `mcu-p2im` Mode, Slicer & Offline `L5` Scorer

1. **Controlled Pi SDK `0.85.1` Runtime (`src/`)**:
   - Single controlled session factory (`src/core/session.ts`) with resource leak assertions, serial governed budget accounting (`src/campaign/governance.ts`), `/proc` start-time-verified process cleanup (`src/campaign/owned-process.ts`), and frozen role prompts (`main`, `discover`, `replay`).
2. **Two-Stage Closed-Loop Pipeline (`src/campaign/mcu-runtime.ts`)**:
   - `prepare → model → discover_seg1 → slice → analyze_and_propose → discover_seg2 (--include-proposed) → triage_and_verify (3x replay + Contrast byte ablation) → score`.
   - Host-side `seed_propose` validator verifies hex encoding, max 256-byte cap, Modbus RTU CRC16 checksum (`crc16_modbus`), and blind-test anti-leak regex before admitting seeds into `proposed-seeds/` (keeping `inputs/` clean).
3. **Host Execution Oracle & `10/10` Compatibility Fixes (`tools/p2im_oracle.py`)**:
   - Dual seed initialization (`seed-random` 256B + `seed-short` `0\n\x00\x00` 4B) unblocks `Reflow_Oven` where `256B` causes an immediate dry-run crash (`afl-fuzz.c:2811` `PROGRAM ABORT`).
   - Empirical board lock places `CNC` on `STM32F429I-Discovery / STM32F429ZI` (on `STM32F4-Discovery`, `smoke` fails `-11` on `mem_r *0x0` and `me` yields `0` peripherals/`0` DR).
   - Register stride uses actual `reg_size` (`base + index * reg_size`, essential for 1-byte K64 UART slots on `Console`) and `extract-sources` scans all `reg_acc*` files recursively including `depth:*` subdirectories with `c++filt` demangling.
4. **Shared-SRAM Dataflow & `indexed_reach` Slicer (`tools/p2im_oracle.py`, `src/campaign/mcu-runtime.ts`)**:
   - Bare-metal ISRs write global ring buffers (`rx_buffer` / `slave`) consumed asynchronously by main-loop protocol handlers (`Modbus::process_FC*`) with no direct call edge.
   - Disassembly literal-pool cross-referencing + 3-letter `add` mnemonic fix (`DISASM_PARSER_VERSION = 3`) tracks byte-indexed writes and compares (`cmp #N`), attaching `indexed_reach` overlaps onto adjacent SRAM symbols (e.g. `slave` overflowing `rx_callback`) with `call_edge: false`, and `sharedViaRank()` ensures cross-object `indexed_reach` links are never overwritten by plain self-references (`rx_callback_obj`).
5. **Isolated Offline `L5` Scorer & Anti-Leak Gate (`scripts/score_l5.py`, `scripts/leak_check.py`)**:
   - Host prompts/artifacts assert zero `CVE-`/`CWE-`/`Table 5` strings (`assertNoLeak`).
   - Post-hoc `score_l5.py` (`l5-0.3`) splits `P2IM_patching_notes.md` on level-2 headings (`## <Firmware>`) and classifies verified candidates into `known_p2im_bug_direct`, `known_p2im_bug_downstream` (upstream shared-SRAM corruption root cause), and `unmatched_verified_candidate`.
