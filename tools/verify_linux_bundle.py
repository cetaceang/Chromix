#!/usr/bin/env python3
"""Validate an extracted Linux bundle; optionally smoke-test it on a native host."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time

try:
    from .platform_pins import load_pins
except ImportError:
    from platform_pins import load_pins

MACHINES = {"x64": 62, "arm64": 183}
REQUIRED_EXECUTABLES = ("chromix", "chrome", "chrome_crashpad_handler", "chrome-sandbox")
REQUIRED_ELF = REQUIRED_EXECUTABLES[1:]
REPO = Path(__file__).resolve().parents[1]
VERSION_TIMEOUT = 30
DOM_TIMEOUT = 60
KILL_TIMEOUT = 5
MAX_OUTPUT_BYTES = 128 * 1024
DOM_MARKER = "<p>chromix-smoke-ok</p>"
SMOKE_URL = "data:text/html," + DOM_MARKER


class VerificationError(ValueError):
    """The extracted bundle failed a static or runtime check."""


def _check_elf(path: Path, root: Path, arch: str, required: bool = False) -> bool:
    relative = path.relative_to(root).as_posix()
    with path.open("rb") as stream:
        header = stream.read(64)
    if header[:4] != b"\x7fELF":
        if required:
            raise VerificationError(f"required executable is not ELF: {relative}")
        return False
    if len(header) < 64:
        raise VerificationError(f"truncated ELF header (need at least 64 bytes): {relative}")
    if header[4] != 2 or header[5] != 1:
        raise VerificationError(f"expected ELF64 little-endian file: {relative}")
    if (header[6] != 1 or struct.unpack_from("<I", header, 20)[0] != 1
            or struct.unpack_from("<H", header, 52)[0] != 64):
        raise VerificationError(f"invalid ELF64 header version or size: {relative}")
    machine = struct.unpack_from("<H", header, 18)[0]
    if machine != MACHINES[arch]:
        raise VerificationError(
            f"wrong ELF architecture in {relative}: e_machine={machine}, "
            f"expected {MACHINES[arch]} ({arch})")
    return True


def _check_link(path: Path, root: Path) -> None:
    try:
        target = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise VerificationError(f"broken or cyclic bundle symlink: {path}") from error
    if not target.is_relative_to(root):
        raise VerificationError(f"bundle symlink escapes bundle: {path}")
    if not (target.is_file() or target.is_dir()):
        raise VerificationError(f"bundle symlink targets a special file: {path}")


def validate_bundle(bundle: Path | str, arch: str) -> dict:
    """Check target ELF headers without executing code; return JSON-ready evidence."""
    if arch not in MACHINES:
        raise VerificationError(f"unsupported Linux bundle architecture: {arch}")
    path = Path(bundle).absolute()
    if path.is_symlink():
        raise VerificationError(f"bundle directory must not be a symlink: {path}")
    root = path.resolve(strict=True)
    if not root.is_dir():
        raise VerificationError(f"bundle directory is not a directory: {root}")
    for name in REQUIRED_EXECUTABLES:
        executable = root / name
        try:
            info = executable.lstat()
        except FileNotFoundError as error:
            raise VerificationError(f"missing required executable: {name}") from error
        if not stat.S_ISREG(info.st_mode):
            raise VerificationError(f"required executable must be a regular file, not a symlink: {name}")
        if not info.st_mode & 0o111 or not info.st_size:
            raise VerificationError(f"required executable is empty or lacks execute permissions: {name}")

    def walk_error(error):
        raise error

    elf_files = []
    for directory, directories, files in os.walk(root, followlinks=False, onerror=walk_error):
        directories.sort()
        for name in sorted(directories + files):
            entry = Path(directory) / name
            mode = entry.lstat().st_mode
            if stat.S_ISLNK(mode):
                _check_link(entry, root)
            elif stat.S_ISREG(mode):
                required = entry.parent == root and name in REQUIRED_ELF
                if _check_elf(entry, root, arch, required):
                    elf_files.append(entry.relative_to(root).as_posix())
            elif not stat.S_ISDIR(mode):
                raise VerificationError(f"special file is not allowed in bundle: {entry}")
    return {
        "bundle_dir": str(root),
        "arch": arch,
        "static": {
            "status": "passed",
            "required_executables": list(REQUIRED_EXECUTABLES),
            "elf_count": len(elf_files),
            "elf_files": sorted(elf_files),
        },
        "runtime": {"status": "not_run"},
    }


def _output_details(stdout, stderr) -> str:
    def text(value):
        return value.decode("utf-8", errors="replace") if isinstance(value, (bytes, bytearray)) else value

    return (f"\nstdout: {text(stdout)[:2000]}\nstderr: {text(stderr)[:2000]}").rstrip()


def _kill_process_group(process) -> None:
    # Kill descendants even when the launcher has already exited.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as error:
        raise VerificationError(f"could not kill browser process group {process.pid}: {error}") from error
    try:
        process.wait(timeout=KILL_TIMEOUT)
    except subprocess.TimeoutExpired as error:
        raise VerificationError(
            f"browser did not exit within {KILL_TIMEOUT}s after process-group kill") from error


def _run_browser(launcher: Path, arguments: list[str], timeout: int, label: str):
    command = [str(launcher), *arguments]
    try:
        process = subprocess.Popen(
            command, cwd=launcher.parent, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
            start_new_session=True)
    except OSError as error:
        raise VerificationError(f"{label} could not start: {error}") from error
    output = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                for key, _ in selector.select(remaining):
                    # Unbuffered pipe reads return available bytes, not a full buffer.
                    chunk = key.fileobj.read(min(8192, MAX_OUTPUT_BYTES - total + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    available = MAX_OUTPUT_BYTES - total
                    output[key.data].extend(chunk[:available])
                    total += len(chunk)
                    if total > MAX_OUTPUT_BYTES:
                        raise VerificationError(
                            f"{label} exceeded the {MAX_OUTPUT_BYTES}-byte output limit"
                            + _output_details(**output))
            returncode = process.wait(timeout=max(0, deadline - time.monotonic()))
        if returncode:
            raise VerificationError(f"{label} exited with status {returncode}" + _output_details(**output))
        return subprocess.CompletedProcess(
            command, returncode, output["stdout"].decode("utf-8", errors="replace"),
            output["stderr"].decode("utf-8", errors="replace"))
    except subprocess.TimeoutExpired as error:
        raise VerificationError(f"{label} timed out after {timeout}s" + _output_details(**output)) from error
    except OSError as error:
        raise VerificationError(f"{label} failed: {error}" + _output_details(**output)) from error
    finally:
        try:
            _kill_process_group(process)
        finally:
            process.stdout.close()
            process.stderr.close()


def runtime_smoke(bundle: Path | str, arch: str, chromium_version: str | None = None) -> dict:
    """Validate the bundle and run sandboxed smoke checks only on a matching Linux host."""
    report = validate_bundle(bundle, arch)
    machine = platform.machine().lower()
    host_arch = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    if sys.platform != "linux" or host_arch != arch:
        raise VerificationError(
            f"runtime smoke requires a native Linux {arch} host; got {sys.platform}/{machine}")
    version = (load_pins(REPO, "linux")["ChromiumVersion"]
               if chromium_version is None else chromium_version).strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", version):
        raise VerificationError(f"invalid Chromium version: {version!r}")
    launcher = Path(report["bundle_dir"]) / "chromix"
    with tempfile.TemporaryDirectory(prefix="chromix-linux-smoke-") as profile:
        result = _run_browser(launcher, ["--version"], VERSION_TIMEOUT, "launcher --version")
        if not re.search(rf"(?<![\d.]){re.escape(version)}(?![\d.])", result.stdout):
            raise VerificationError(
                f"launcher --version did not report Chromium {version}"
                + _output_details(result.stdout, result.stderr))
        version_output = result.stdout.strip()[:2000]
        result = _run_browser(
            launcher, ["--headless", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
                       f"--user-data-dir={profile}", "--dump-dom", SMOKE_URL],
            DOM_TIMEOUT, "headless --dump-dom")
        if DOM_MARKER not in result.stdout:
            raise VerificationError(
                "headless --dump-dom is missing the smoke page marker"
                + _output_details(result.stdout, result.stderr))
    report["runtime"] = {
        "status": "passed", "host_arch": host_arch, "chromium_version": version,
        "version_output": version_output, "dom_marker": DOM_MARKER,
    }
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-dir", type=Path, required=True, help="extracted chromix directory")
    parser.add_argument("--arch", choices=tuple(MACHINES), required=True, help="package target architecture")
    parser.add_argument("--runtime", action="store_true", help="also run smoke checks on a native Linux host")
    parser.add_argument("--chromium-version", help="expected runtime version (default: repository Linux pin)")
    args = parser.parse_args(argv)
    try:
        report = (runtime_smoke(args.bundle_dir, args.arch, args.chromium_version) if args.runtime
                  else validate_bundle(args.bundle_dir, args.arch))
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Linux bundle verification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
