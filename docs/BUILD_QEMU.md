# Building Patched `qemu-system-gnuarmeclipse` (Ubuntu 22.04 / 24.04)

This guide explains how and why `patches/p2im-qemu-auto-forkserver.patch` patches upstream `RiS3-Lab/p2im` (`qemu/src/qemu.git` at commit `0e64506a371b9c66ff67ed64a3fa65fa7e197e21`) for modern Linux hosts and unmodified P2IM evaluation targets.

> Most users can run `bash scripts/setup_upstreams.sh` instead of invoking these steps manually.

## What the 16-File QEMU Patch Covers

1. **`target-arm/translate.c` & `cpu-exec.c` (`p2im_maybe_auto_forkserver`)**:
   - Upstream P2IM assumes every target binary calls `svc #0x3f` (`aflCall` / `startForkserver`).
   - The unpatched `Soldering_Iron.elf` from `hoedur-experiments` has `0` `svc 0x3f` instructions.
   - `p2im_maybe_auto_forkserver(env, tb->pc, tb->size)` is a strict opt-in hook gated on `P2IM_AUTO_FORKSERVER_PC` (e.g. `0x08000268`). When unset, it is a no-op and preserves exact behavior for all 9 `svc 0x3f` images. When set, the first translated basic block covering that Thumb PC invokes `startForkserver(env, 0)` once without modifying a single byte of the firmware ELF.
2. **`cputlb.c`, `memory.c`, `include/peri-mod/peri-mod.h`, `include/afl/afl-qemu-cpu-inl.h` (`PM_EXEC_PERI = 0x72`)**:
   - When an firmware bug (such as an out-of-bounds Modbus write in `PLC.elf`) corrupts a RAM callback slot (e.g. `rx_callback`) to point into the peripheral MMIO region (`0x40000000..0x5fffffff`), `blx r3` triggers an instruction fetch from an unmapped/MMIO address.
   - `pm_fetching_code` prevents `unassigned_mem_read` from mistaking the instruction fetch for an unmodeled peripheral register access (`0x40`), and `get_page_addr_code` exits cleanly with `exit(0x72)` (`PM_EXEC_PERI`) while logging `guest_code_fetch addr=... pc=... r0=... r3=...`, preventing abort loops inside `me.py`.
3. **`hw/display/gpio-led.c`, `hw/arm/cortexm-helper.c` (`CONFIG_SDL` guards)**:
   - Wraps SDL surface/timer helper calls behind `#if defined(CONFIG_SDL)` so headless servers without legacy `libsdl1.2-dev` can build with `--disable-sdl`. Headless fuzzing always runs with `-nographic`.
4. **`configure` & `scripts/{ordereddict,qapi,qapi-commands,qapi-event,qapi-types,qapi-visit,tracetool}.py`**:
   - Updates QEMU 2.3's configure check and Python QAPI/tracetool generators from Python 2 syntax (`except E, e`, `has_key`, `StringIO`, `string.maketrans`, Python 3 iterator `.keys()`/`map()`/`filter()`) to work natively under Python 3.12 on Ubuntu 24.04.

## Critical Build Constraints

- **Target list**: Always build `--target-list=gnuarmeclipse-softmmu` (NOT `arm-softmmu`).
- **Board config invariant**: Keep `default-configs/gnuarmeclipse-softmmu.mak` with `CONFIG_STM32=y` and `CONFIG_KINETIS=n` / `CONFIG_LPC=n` / `CONFIG_TIVA=n` / `CONFIG_XMC=n` / `CONFIG_SAM=n`. P2IM registers `FRDM-K64F` and `Arduino-Due` inside `stm32-boards.c`; enabling `CONFIG_KINETIS=y` registers `FRDM-K64F` twice and aborts QEMU on startup.
- **Avoid 2017 bundled `libglib-2.0.so.0.5100.0`**: When invoking a modern-host-compiled `qemu-system-gnuarmeclipse`, do NOT put upstream P2IM's precompiled 2017 `qemu/*.so` directory on `LD_LIBRARY_PATH`, or dynamic linking fails with `undefined symbol: g_string_free_and_steal`. The `tools/p2im_oracle.py` wrapper shim explicitly runs `unset LD_LIBRARY_PATH`.
- **Jansson development library**: Ensure `libjansson-dev` (`jansson.h` + `-ljansson`) is installed so `config-host.mak` links cleanly.

## Manual Out-of-Tree Build Commands

```bash
export P2IM_ROOT="${P2IM_ROOT:-$HOME/deps/p2im}"
export P2IM_TOOLS_ROOT="${P2IM_TOOLS_ROOT:-$HOME/p2im-tools}"
export QEMU_BUILD_DIR="${QEMU_BUILD_DIR:-$HOME/deps/p2im-qemu-build}"

git -C "$P2IM_ROOT" apply --directory=qemu/src/qemu.git patches/p2im-qemu-auto-forkserver.patch

mkdir -p "$QEMU_BUILD_DIR" && cd "$QEMU_BUILD_DIR"
"$P2IM_ROOT/qemu/src/qemu.git/configure" \
  --prefix="$QEMU_BUILD_DIR/install" \
  --target-list=gnuarmeclipse-softmmu \
  --python="$(command -v python3)" \
  --disable-werror --disable-docs --disable-gtk --disable-sdl \
  --disable-vnc --disable-xen --disable-kvm --disable-guest-agent \
  --extra-cflags="$(pkg-config --cflags jansson 2>/dev/null || true)" \
  --extra-ldflags="$(pkg-config --libs jansson 2>/dev/null || echo -ljansson)"

# Ensure -ljansson appears at the tail of LIBS in config-host.mak
grep -q 'ljansson' config-host.mak || {
  echo "QEMU_CFLAGS+=$(pkg-config --cflags jansson 2>/dev/null || true)" >> config-host.mak
  echo "LIBS+=$(pkg-config --libs jansson 2>/dev/null || echo -ljansson)" >> config-host.mak
}

make -j"$(nproc)"
install -Dm755 "$QEMU_BUILD_DIR/gnuarmeclipse-softmmu/qemu-system-gnuarmeclipse" \
  "$P2IM_TOOLS_ROOT/qemu/qemu-system-gnuarmeclipse"
nm "$P2IM_TOOLS_ROOT/qemu/qemu-system-gnuarmeclipse" | grep 'p2im_maybe_auto_forkserver'
```
