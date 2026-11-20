#!/usr/bin/env bash
# Automated upstream setup for firmagent-p2im on Ubuntu 22.04/24.04 or WSL2 Ubuntu 24.04.
# Fetches pinned public commits of RiS3-Lab/p2im and fuzzware-fuzzer/hoedur-experiments,
# builds AFL 2.06b and patched gnuarmeclipse-softmmu QEMU, installs Python 3.12 P2IM scripts,
# verifies all 10 unpatched firmware SHA256 digests, and generates configs/m3/*.json.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPS_ROOT="${DEPS_ROOT:-$HOME/deps}"
P2IM_ROOT="${P2IM_ROOT:-$DEPS_ROOT/p2im}"
HOEDUR_EXPERIMENTS_ROOT="${HOEDUR_EXPERIMENTS_ROOT:-$DEPS_ROOT/hoedur-experiments}"
P2IM_TOOLS_ROOT="${P2IM_TOOLS_ROOT:-$HOME/p2im-tools}"
P2IM_WORK_ROOT="${P2IM_WORK_ROOT:-/tmp/fa-p2im}"
QEMU_BUILD_DIR="${QEMU_BUILD_DIR:-$DEPS_ROOT/p2im-qemu-build}"

P2IM_COMMIT="0e64506a371b9c66ff67ed64a3fa65fa7e197e21"
P2IM_REAL_FW_COMMIT="d4c7456574ce2c2ed038e6f14fea8e3142b3c1f7"
HOEDUR_COMMIT="2babc78b72b1331b3122c11f170e9367132b8aa2"

if [ -n "${OS:-}" ] && [ "${OS}" = "Windows_NT" ]; then
  echo "Run this script inside Ubuntu Linux / WSL2 bash, not Windows cmd/PowerShell." >&2
  exit 1
fi

echo "[1/7] Checking host build and cross-binutils dependencies..."
missing=()
for cmd in git gcc g++ make pkg-config python3 patch killall arm-none-eabi-objdump arm-none-eabi-nm arm-none-eabi-readelf node npm; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    missing+=("$cmd")
  fi
done
if ! pkg-config --exists jansson glib-2.0 pixman-1 zlib 2>/dev/null; then
  missing+=("dev-libs(jansson/glib-2.0/pixman-1/zlib)")
fi
if [ ! -f /usr/include/libfdt.h ] && ! pkg-config --exists libfdt 2>/dev/null; then
  missing+=("libfdt-dev")
fi
if [ "${#missing[@]}" -gt 0 ]; then
  echo "Missing prerequisites: ${missing[*]}" >&2
  echo "Install Ubuntu packages with:" >&2
  echo "  sudo apt-get update && sudo apt-get install -y build-essential git pkg-config python3 psmisc binutils-arm-none-eabi libglib2.0-dev libpixman-1-dev libfdt-dev zlib1g-dev libjansson-dev gdb-multiarch" >&2
  echo "And ensure Node.js >= 22.19.0 is on PATH." >&2
  exit 2
fi

node -e 'const [M,m]=process.versions.node.split(".").map(Number); if (M<22 || (M===22 && m<19)) process.exit(1);' || {
  echo "Node.js >= 22.19.0 is required; found $(node -v)" >&2
  exit 2
}

mkdir -p "$DEPS_ROOT" "$P2IM_TOOLS_ROOT/qemu" "$P2IM_TOOLS_ROOT/scripts"

echo "[2/7] Fetching pinned RiS3-Lab/p2im (${P2IM_COMMIT})..."
if [ ! -d "$P2IM_ROOT/.git" ]; then
  git clone https://github.com/RiS3-Lab/p2im.git "$P2IM_ROOT"
fi
git -C "$P2IM_ROOT" fetch origin
git -C "$P2IM_ROOT" checkout --force "$P2IM_COMMIT"
git -C "$P2IM_ROOT" submodule update --init externals/p2im-real_firmware

echo "[3/7] Fetching pinned Soldering_Iron & offline notes from hoedur-experiments (${HOEDUR_COMMIT})..."
if [ ! -d "$HOEDUR_EXPERIMENTS_ROOT/.git" ]; then
  git clone --filter=blob:none --no-checkout https://github.com/fuzzware-fuzzer/hoedur-experiments.git "$HOEDUR_EXPERIMENTS_ROOT"
fi
git -C "$HOEDUR_EXPERIMENTS_ROOT" sparse-checkout init --cone
git -C "$HOEDUR_EXPERIMENTS_ROOT" sparse-checkout set \
  targets/arm/unpatched-est-data-set/P2IM/Soldering_Iron \
  02-coverage-est-data-set/binary-patching
git -C "$HOEDUR_EXPERIMENTS_ROOT" checkout "$HOEDUR_COMMIT"

echo "[4/7] Building P2IM AFL 2.06b..."
make -C "$P2IM_ROOT/afl" -j"$(nproc)"
test -x "$P2IM_ROOT/afl/afl-fuzz"

echo "[5/7] Patching and building P2IM gnuarmeclipse-softmmu QEMU..."
QEMU_SRC="$P2IM_ROOT/qemu/src/qemu.git"
if git -C "$P2IM_ROOT" apply --reverse --check --directory=qemu/src/qemu.git "$REPO_ROOT/patches/p2im-qemu-auto-forkserver.patch" 2>/dev/null; then
  echo "  QEMU patch already applied."
else
  git -C "$P2IM_ROOT" apply --directory=qemu/src/qemu.git "$REPO_ROOT/patches/p2im-qemu-auto-forkserver.patch"
fi

if ! grep -q '^CONFIG_STM32=y' "$QEMU_SRC/default-configs/gnuarmeclipse-softmmu.mak" || \
   ! grep -q '^CONFIG_KINETIS=n' "$QEMU_SRC/default-configs/gnuarmeclipse-softmmu.mak"; then
  echo "Unexpected gnuarmeclipse-softmmu.mak configuration; refusing duplicate FRDM-K64F build." >&2
  exit 3
fi

mkdir -p "$QEMU_BUILD_DIR"
pushd "$QEMU_BUILD_DIR" >/dev/null
"$QEMU_SRC/configure" \
  --prefix="$QEMU_BUILD_DIR/install" \
  --target-list=gnuarmeclipse-softmmu \
  --python="$(command -v python3)" \
  --disable-werror \
  --disable-docs \
  --disable-gtk \
  --disable-sdl \
  --disable-vnc \
  --disable-xen \
  --disable-kvm \
  --disable-guest-agent \
  --extra-cflags="$(pkg-config --cflags jansson 2>/dev/null || true)" \
  --extra-ldflags="$(pkg-config --libs jansson 2>/dev/null || echo -ljansson)"

if ! grep -qE '^LIBS[[:space:]]*\+?=.*-ljansson([[:space:]]|$)' config-host.mak; then
  echo "QEMU_CFLAGS+=$(pkg-config --cflags jansson 2>/dev/null || true)" >> config-host.mak
  echo "LIBS+=$(pkg-config --libs jansson 2>/dev/null || echo -ljansson)" >> config-host.mak
fi

make -j"$(nproc)"
popd >/dev/null

install -m 755 "$QEMU_BUILD_DIR/gnuarmeclipse-softmmu/qemu-system-gnuarmeclipse" \
  "$P2IM_TOOLS_ROOT/qemu/qemu-system-gnuarmeclipse"
nm "$P2IM_TOOLS_ROOT/qemu/qemu-system-gnuarmeclipse" | grep -q ' T p2im_maybe_auto_forkserver'

echo "[6/7] Installing Python 3.12 P2IM runner scripts to ${P2IM_TOOLS_ROOT}/scripts..."
cp "$P2IM_ROOT/model_instantiation/fuzz.py" "$P2IM_TOOLS_ROOT/scripts/fuzz.py"
cp "$P2IM_ROOT/model_instantiation/me.py" "$P2IM_TOOLS_ROOT/scripts/me.py"
cp "$P2IM_ROOT/utilities/coverage/cov.py" "$P2IM_TOOLS_ROOT/scripts/cov.py"
cp "$P2IM_ROOT/utilities/model_stat/statFp3.py" "$P2IM_TOOLS_ROOT/scripts/statFp3.py"
python3 - "$P2IM_TOOLS_ROOT/scripts" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
for name in ("fuzz.py", "me.py", "cov.py", "statFp3.py"):
    p = root / name
    p.write_bytes(p.read_bytes().replace(b"\r\n", b"\n"))
PY
patch -d "$P2IM_TOOLS_ROOT/scripts" -p1 < "$REPO_ROOT/patches/p2im-python312-scripts.patch"
cp "$REPO_ROOT/p2im-shim/wsl_compat.py" "$P2IM_TOOLS_ROOT/scripts/wsl_compat.py"
cat > "$P2IM_TOOLS_ROOT/scripts/me" <<'EOF'
#!/usr/bin/env bash
exec python3 "$(cd "$(dirname "$0")" && pwd)/me.py" "$@"
EOF
chmod +x "$P2IM_TOOLS_ROOT/scripts/fuzz.py" "$P2IM_TOOLS_ROOT/scripts/me.py" \
  "$P2IM_TOOLS_ROOT/scripts/cov.py" "$P2IM_TOOLS_ROOT/scripts/statFp3.py" "$P2IM_TOOLS_ROOT/scripts/me"

echo "[7/7] Verifying 10 unpatched ELF SHA256 hashes and generating configs/m3/*.json..."
python3 - "$REPO_ROOT/docs/P2IM_10_UNPATCHED_MANIFEST.json" "$P2IM_ROOT" "$HOEDUR_EXPERIMENTS_ROOT" <<'PY'
import hashlib, json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    manifest = json.load(fh)
p2im_root, hoedur_root = sys.argv[2].rstrip("/"), sys.argv[3].rstrip("/")
for item in manifest["targets"]:
    path = item["path"].replace("${P2IM_ROOT}", p2im_root).replace("${HOEDUR_EXPERIMENTS_ROOT}", hoedur_root)
    with open(path, "rb") as elf_fh:
        h = hashlib.sha256(elf_fh.read()).hexdigest()
    assert h == item["sha256"], f"SHA256 mismatch for {item['target']}: got {h}, expected {item['sha256']}"
    print(f"  OK {item['target']:17s} {h[:12]}... ({item['board']['qemu_board']})")
PY

python3 "$REPO_ROOT/scripts/generate_configs.py" \
  --p2im-root "$P2IM_ROOT" \
  --hoedur-root "$HOEDUR_EXPERIMENTS_ROOT" \
  --work-root "$P2IM_WORK_ROOT" \
  --out-dir "$REPO_ROOT/configs/m3"

echo "SETUP_COMPLETE: P2IM_ROOT=$P2IM_ROOT P2IM_TOOLS_ROOT=$P2IM_TOOLS_ROOT P2IM_WORK_ROOT=$P2IM_WORK_ROOT"
