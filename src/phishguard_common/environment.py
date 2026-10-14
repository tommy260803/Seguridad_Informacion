"""Hardware, OS, Python, package, and Git metadata collector for reproducible artifacts."""
from __future__ import annotations

import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any


def _safe_pkg_version(name: str) -> str | None:
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def _get_git_metadata(repo_root: Path) -> dict[str, Any]:
    try:
        commit = (
            subprocess.check_output(
                ["git", "rev-parse", "HEAD"],
                cwd=str(repo_root),
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
            .strip()
        )
        branch = (
            subprocess.check_output(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=str(repo_root),
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
            .strip()
        )
        status_out = (
            subprocess.check_output(
                ["git", "status", "--porcelain"],
                cwd=str(repo_root),
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
            .strip()
        )
        return {
            "commit_sha": commit,
            "branch": branch,
            "working_tree_dirty": bool(status_out),
        }
    except Exception:
        return {
            "commit_sha": None,
            "branch": None,
            "working_tree_dirty": None,
        }


def _get_hardware_metadata() -> dict[str, Any]:
    cpu_model = platform.processor() or "unknown"
    total_ram_gb: float | None = None
    available_ram_gb: float | None = None

    # Try psutil first if installed
    try:
        import psutil  # type: ignore

        vm = psutil.virtual_memory()
        total_ram_gb = round(vm.total / (1024**3), 2)
        available_ram_gb = round(vm.available / (1024**3), 2)
        physical_cores = psutil.cpu_count(logical=False)
        logical_cores = psutil.cpu_count(logical=True)
    except Exception:
        physical_cores = None
        logical_cores = os.cpu_count()
        if sys.platform == "win32":
            try:
                import ctypes

                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                    ]

                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(stat)
                if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                    total_ram_gb = round(stat.ullTotalPhys / (1024**3), 2)
                    available_ram_gb = round(stat.ullAvailPhys / (1024**3), 2)
            except Exception:
                pass

    if sys.platform == "win32":
        try:
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
            ) as key:
                cpu_name, _ = winreg.QueryValueEx(key, "ProcessorNameString")
                if cpu_name:
                    cpu_model = str(cpu_name).strip()
        except Exception:
            pass

    return {
        "cpu_model": cpu_model,
        "cpu_logical_cores": logical_cores,
        "cpu_physical_cores": physical_cores,
        "ram_total_gb": total_ram_gb,
        "ram_available_gb": available_ram_gb,
        "os_system": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "machine_arch": platform.machine(),
    }


def collect_environment_metadata(repo_root: str | Path | None = None) -> dict[str, Any]:
    """Return a structured dictionary of real hardware, OS, Python, package, and Git metadata."""
    root = Path(repo_root) if repo_root else Path(__file__).resolve().parents[2]
    packages = {
        pkg: _safe_pkg_version(pkg)
        for pkg in (
            "scikit-learn",
            "numpy",
            "scipy",
            "joblib",
            "httpx",
            "playwright",
            "Pillow",
            "matplotlib",
            "fastapi",
            "pydantic",
        )
    }
    return {
        "captured_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "hardware": _get_hardware_metadata(),
        "packages": {k: v for k, v in packages.items() if v is not None},
        "git": _get_git_metadata(root),
    }
