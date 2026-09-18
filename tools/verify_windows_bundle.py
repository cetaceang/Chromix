#!/usr/bin/env python3
"""Check Windows bundle architecture and integrity, with optional native smoke tests."""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys
import tempfile
import time
import zipfile

try:
    from .platform_pins import load_pins
except ImportError:
    from platform_pins import load_pins

MACHINES = {'x64': 0x8664, 'arm64': 0xAA64}
REQUIRED = ('chromix.cmd', 'chrome.exe', 'chrome.dll', 'chrome_elf.dll', 'libEGL.dll',
            'libGLESv2.dll', 'chrome_100_percent.pak', 'chrome_200_percent.pak',
            'resources.pak', 'icudtl.dat', 'LICENSE.chromix', 'LICENSE.chromium')
MAX_EXPANDED = 2 * 1024 ** 3
MAX_OUTPUT = 1024 * 1024
DOM_MARKER = '<p>chromix-smoke-ok</p>'
REPO = Path(__file__).resolve().parents[1]


class VerificationError(ValueError):
    """The bundle is invalid or its native smoke test failed."""


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def check_pe(path, arch):
    """Validate the COFF machine and bounded PE32+ headers without execution."""
    size = path.stat().st_size
    with path.open('rb') as stream:
        dos = stream.read(64)
        if len(dos) != 64 or dos[:2] != b'MZ':
            raise VerificationError(f'missing DOS header: {path}')
        offset = struct.unpack_from('<I', dos, 60)[0]
        if offset < 64 or offset + 24 > size:
            raise VerificationError(f'PE header is outside file: {path}')
        stream.seek(offset)
        header = stream.read(24)
        if header[:4] != b'PE\0\0':
            raise VerificationError(f'invalid PE signature: {path}')
        machine, sections = struct.unpack_from('<HH', header, 4)
        optional_size, characteristics = struct.unpack_from('<HH', header, 20)
        if machine != MACHINES[arch]:
            raise VerificationError(f'wrong PE architecture: {path}: 0x{machine:04x}, expected {arch}')
        if not 1 <= sections <= 96 or not characteristics & 2:
            raise VerificationError(f'invalid PE sections or executable flag: {path}')
        section_end = offset + 24 + optional_size + sections * 40
        if optional_size < 112 or section_end > size:
            raise VerificationError(f'truncated optional or section headers: {path}')
        optional = stream.read(optional_size)
        if struct.unpack_from('<H', optional)[0] != 0x20B:
            raise VerificationError(f'expected PE32+ image: {path}')
        count = struct.unpack_from('<I', optional, 108)[0]
        if count > 16 or 112 + count * 8 > optional_size:
            raise VerificationError(f'truncated PE data directories: {path}')
        for _ in range(sections):
            section = stream.read(40)
            raw_size, raw_offset = struct.unpack_from('<II', section, 16)
            if raw_size and (raw_offset < section_end or raw_offset + raw_size > size):
                raise VerificationError(f'PE section data is outside file: {path}')
    return {'machine': machine, 'size': size, 'sha256': sha256(path)}


def validate_bundle(bundle, arch):
    if arch not in MACHINES:
        raise VerificationError(f'unsupported Windows architecture: {arch}')
    root = Path(bundle).absolute()
    if (root.is_symlink() or not root.is_dir()
            or getattr(root.lstat(), 'st_file_attributes', 0) & 0x400):
        raise VerificationError('bundle must be a directory, not a link')
    root = root.resolve(strict=True)
    for name in REQUIRED:
        path = root / name
        if path.is_symlink() or not path.is_file() or not path.stat().st_size:
            raise VerificationError(f'missing or empty required file: {name}')
    if not any((root / name).is_file() and (root / name).stat().st_size
               for name in ('v8_context_snapshot.bin', 'snapshot_blob.bin')):
        raise VerificationError('V8 snapshot is missing')
    if not (root / 'locales/en-US.pak').is_file() or not (root / 'locales/en-US.pak').stat().st_size:
        raise VerificationError('en-US locale is missing')
    if not any(path.is_file() and path.stat().st_size for path in root.glob('*.manifest')):
        raise VerificationError('Windows side-by-side manifest is missing')
    binaries = {}
    def walk_error(error):
        raise error

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise VerificationError(f'links and reparse points are not allowed: {path}')
            if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
                raise VerificationError(f'special file is not allowed: {path}')
            if path.is_file():
                with path.open('rb') as stream:
                    is_pe = stream.read(2) == b'MZ'
                if is_pe or path.suffix.lower() in ('.exe', '.dll'):
                    binaries[path.relative_to(root).as_posix()] = check_pe(path, arch)
    portable = binaries['chrome.dll']['sha256']
    for name, identity in binaries.items():
        if re.fullmatch(r'\d+\.\d+\.\d+\.\d+/chrome\.dll', name, re.I) and identity['sha256'] != portable:
            raise VerificationError('versioned chrome.dll differs from the portable DLL')
    return {'bundle_dir': str(root), 'arch': arch,
            'static': {'status': 'passed', 'pe_count': len(binaries), 'pe_files': binaries},
            'runtime': {'status': 'not_run'}}


def extract_archive(archive, manifest, dest, arch):
    archive, manifest, dest = Path(archive), Path(manifest), Path(dest)
    expected_name = f'chromix-win-{arch}.zip'
    if archive.name != expected_name:
        raise VerificationError(f'expected archive name {expected_name}')
    if manifest.stat().st_size > 64 * 1024:
        raise VerificationError('checksum manifest exceeds 64 KiB')
    entries = [line for line in manifest.read_text(encoding='utf-8-sig').splitlines()
               if re.fullmatch(r'[0-9a-fA-F]{64}\s+\*?' + re.escape(expected_name), line)]
    digest = sha256(archive)
    if len(entries) != 1 or entries[0][:64].lower() != digest:
        raise VerificationError('archive SHA256 does not match a unique manifest entry')
    if dest.exists() or dest.is_symlink():
        raise VerificationError('extraction destination must not already exist')
    with zipfile.ZipFile(archive) as container:
        members = container.infolist()
        if not members or len(members) > 10000 or sum(item.file_size for item in members) > MAX_EXPANDED:
            raise VerificationError('archive member count or expanded size exceeds limit')
        seen = {}
        reserved = re.compile(r'^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)', re.I)
        for item in members:
            # ZipInfo normalizes backslashes on Windows and truncates at NUL.
            # Validate the original name, not a platform-repaired alias.
            raw = item.orig_filename.rstrip('/')
            path = PurePosixPath(raw)
            if (item.filename != item.orig_filename or not raw or '\0' in raw
                    or '\\' in raw or path.is_absolute() or raw != path.as_posix()
                    or path.parts[0] != 'chromix' or any(
                        part in ('.', '..') or part[-1:] in (' ', '.') or reserved.match(part)
                        or re.search(r'[\x00-\x1f\x7f:<>"|?*]', part) for part in path.parts)):
                raise VerificationError(f'unsafe Windows archive path: {item.orig_filename!r}')
            mode = item.external_attr >> 16
            if (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)
                    or (stat.S_IFMT(mode) == stat.S_IFDIR and not item.is_dir())
                    or (item.is_dir() and item.file_size != 0)
                    or item.flag_bits & 1):
                raise VerificationError(f'unsupported archive member: {item.filename}')
            key = raw.casefold()
            if key in seen:
                raise VerificationError(f'duplicate Windows archive path: {item.filename}')
            seen[key] = item.is_dir()
        for name in seen:
            for parent in PurePosixPath(name).parents:
                if parent.as_posix() in seen and not seen[parent.as_posix()]:
                    raise VerificationError('archive file shadows a parent directory')
        dest.mkdir(parents=True)
        for item in members:
            target = dest / PurePosixPath(item.filename)
            if item.is_dir():
                with container.open(item) as source:
                    if source.read(1):
                        raise VerificationError('archive directory contains data')
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with container.open(item) as source, target.open('xb') as output:
                total = 0
                for chunk in iter(lambda: source.read(1024 * 1024), b''):
                    total += len(chunk)
                    if total > item.file_size:
                        raise VerificationError('archive member exceeded declared size')
                    output.write(chunk)
                if total != item.file_size:
                    raise VerificationError('archive member length mismatch')
    report = validate_bundle(dest / 'chromix', arch)
    report['archive'] = {'name': archive.name, 'sha256': digest, 'size': archive.stat().st_size}
    return report


def native_architecture():
    if sys.platform != 'win32':
        raise VerificationError('native smoke requires Windows')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.IsWow64Process2.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.USHORT), ctypes.POINTER(wintypes.USHORT))
    kernel.IsWow64Process2.restype = wintypes.BOOL
    process, native = wintypes.USHORT(), wintypes.USHORT()
    if not kernel.IsWow64Process2(kernel.GetCurrentProcess(), ctypes.byref(process), ctypes.byref(native)):
        raise ctypes.WinError(ctypes.get_last_error())
    return next((arch for arch, machine in MACHINES.items() if machine == native.value), None)


def product_version(path):
    library = ctypes.WinDLL('version', use_last_error=True)
    library.GetFileVersionInfoSizeW.argtypes = (wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD))
    library.GetFileVersionInfoSizeW.restype = wintypes.DWORD
    library.GetFileVersionInfoW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p)
    library.GetFileVersionInfoW.restype = wintypes.BOOL
    library.VerQueryValueW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT))
    library.VerQueryValueW.restype = wintypes.BOOL
    ignored = wintypes.DWORD()
    size = library.GetFileVersionInfoSizeW(str(path), ctypes.byref(ignored))
    if not 0 < size <= 16 * 1024 * 1024:
        raise VerificationError(f'missing or excessive Windows version resource: {path}')
    buffer = ctypes.create_string_buffer(size)
    pointer, length = ctypes.c_void_p(), wintypes.UINT()
    if (not library.GetFileVersionInfoW(str(path), 0, size, buffer)
            or not library.VerQueryValueW(buffer, '\\', ctypes.byref(pointer), ctypes.byref(length))
            or length.value < 52):
        raise VerificationError(f'invalid Windows version resource: {path}')
    fields = (wintypes.DWORD * 13).from_address(pointer.value)
    if fields[0] != 0xFEEF04BD:
        raise VerificationError(f'invalid fixed version signature: {path}')
    return '.'.join(str(value) for value in (fields[4] >> 16, fields[4] & 0xFFFF,
                                            fields[5] >> 16, fields[5] & 0xFFFF))


def run_headless(bundle, profile, logs):
    from fingerprint_subprocess import WindowsJob
    launcher = bundle / 'chromix.cmd'
    arguments = [str(launcher), '--headless', '--disable-gpu', '--no-first-run',
                 '--no-default-browser-check', f'--user-data-dir={profile}',
                 '--dump-dom', 'data:text/html,' + DOM_MARKER]
    if any(re.search(r'["%\r\n\x00]', value) for value in arguments):
        raise VerificationError('unsupported shell character in smoke path')
    comspec = os.environ.get('COMSPEC', r'C:\Windows\System32\cmd.exe')
    if re.search(r'["%\r\n\x00]', comspec):
        raise VerificationError('unsupported shell character in COMSPEC')
    command = ('"' + comspec + '" /d /v:off /s /c "'
               + ' '.join('"' + value + '"' for value in arguments) + '"')
    gate = ('import subprocess,sys; sys.exit(subprocess.call(sys.argv[1], stdin=subprocess.DEVNULL) '
            'if sys.stdin.buffer.read(1)==b"1" else 125)')
    logs.mkdir(parents=True, exist_ok=True)
    stdout_path, stderr_path = logs / 'headless.stdout', logs / 'headless.stderr'
    job, process = WindowsJob(), None
    try:
        with stdout_path.open('xb') as output, stderr_path.open('xb') as errors:
            process = subprocess.Popen([sys.executable, '-c', gate, command], cwd=bundle,
                                       stdin=subprocess.PIPE, stdout=output, stderr=errors,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
            job.assign(process)
            process.stdin.write(b'1')
            process.stdin.close()
            deadline = time.monotonic() + 60
            while process.poll() is None:
                if stdout_path.stat().st_size + stderr_path.stat().st_size > MAX_OUTPUT:
                    raise VerificationError('headless output exceeds 1 MiB')
                if time.monotonic() >= deadline:
                    raise VerificationError('headless did not exit within 60 seconds')
                time.sleep(0.05)
            if process.returncode != 0:
                raise VerificationError(f'headless exited with status {process.returncode}')
    finally:
        try:
            job.terminate()
        finally:
            try:
                job.close()
            finally:
                if process is not None:
                    if process.stdin and not process.stdin.closed:
                        process.stdin.close()
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=5)
    if stdout_path.stat().st_size + stderr_path.stat().st_size > MAX_OUTPUT:
        raise VerificationError('headless output exceeds 1 MiB')
    if DOM_MARKER not in stdout_path.read_text(encoding='utf-8', errors='replace'):
        raise VerificationError('headless output is missing the smoke DOM marker')
    return {'status': 'passed', 'exit_code': 0, 'timeout_seconds': 60,
            'stdout': str(stdout_path), 'stderr': str(stderr_path)}


def runtime_smoke(report, version, logs):
    if native_architecture() != report['arch']:
        raise VerificationError(f'native Windows {report["arch"]} host is required')
    if not re.fullmatch(r'\d+\.\d+\.\d+\.\d+', version):
        raise VerificationError('invalid expected Chromium version')
    bundle = Path(report['bundle_dir'])
    for name in ('chrome.exe', 'chrome.dll'):
        if product_version(bundle / name) != version:
            raise VerificationError(f'Windows product version mismatch: {name}')
    with tempfile.TemporaryDirectory(prefix='chromix-win-smoke-') as profile:
        result = run_headless(bundle, profile, logs)
    if validate_bundle(bundle, report['arch'])['static'] != report['static']:
        raise VerificationError('bundle binaries changed during native smoke')
    report['runtime'] = {**result, 'version': version, 'native_arch': report['arch']}
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--bundle', type=Path)
    source.add_argument('--archive', type=Path)
    parser.add_argument('--arch', choices=tuple(MACHINES), required=True)
    parser.add_argument('--sha256-file', type=Path)
    parser.add_argument('--dest', type=Path)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--version', help='expected Chromium version (default: resolved Windows pins)')
    parser.add_argument('--report', type=Path)
    args = parser.parse_args(argv)
    report = {'arch': args.arch, 'static': {'status': 'failed'}, 'runtime': {'status': 'not_run'}}
    try:
        if args.version is None:
            args.version = load_pins(REPO, 'windows')['ChromiumVersion']
        if args.archive:
            if not args.sha256_file or not args.dest:
                raise VerificationError('--archive requires --sha256-file and --dest')
            report = extract_archive(args.archive, args.sha256_file, args.dest, args.arch)
        else:
            report = validate_bundle(args.bundle, args.arch)
        if args.native:
            report['runtime'] = {'status': 'failed'}
            logs = args.report.parent if args.report else Path(tempfile.mkdtemp(prefix='chromix-win-diagnostics-'))
            report = runtime_smoke(report, args.version, logs)
        code = 0
    except (OSError, ValueError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        code = 1
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
