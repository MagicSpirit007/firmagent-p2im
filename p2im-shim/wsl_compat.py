"""Apply Linux/WSL2 compatibility env that AFL/QEMU need. fuzz.py / me.py call this.

Python cannot source a shell file; this writes the same keys into os.environ
so child QEMU/AFL inherit them.
"""
import os
import sys

_QEMU_LIB = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "qemu"))


def _is_wsl():
    if os.environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        with open("/proc/version", encoding="utf-8") as handle:
            version = handle.read().lower()
        return "microsoft" in version or "wsl" in version
    except OSError:
        return False


def apply_wsl_compat():
    ld = os.environ.get("LD_LIBRARY_PATH", "")
    parts = [part for part in ld.split(":") if part]
    if _QEMU_LIB not in parts:
        os.environ["LD_LIBRARY_PATH"] = _QEMU_LIB + ((":" + ld) if ld else "")

    if not _is_wsl():
        return

    os.environ.setdefault("AFL_SKIP_CPUFREQ", "1")
    os.environ.setdefault("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
    os.environ.setdefault("AFL_NO_AFFINITY", "1")
    os.environ.setdefault("AFL_SKIP_CRASHES", "1")
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    if "AFL_NO_FORKSRV" not in os.environ:
        os.environ["AFL_NO_FORKSRV"] = ""

    # PYTHONUNBUFFERED is too late for the running interpreter; enable line buffering.
    for stream in (sys.stdout, sys.stderr):
        reconf = getattr(stream, "reconfigure", None)
        if reconf is not None:
            try:
                reconf(line_buffering=True)
            except Exception:
                pass
