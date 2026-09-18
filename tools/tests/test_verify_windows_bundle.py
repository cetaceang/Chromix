"""Small real PE/ZIP fixtures; Windows APIs and browser processes are mocked."""
from contextlib import redirect_stdout
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock
import warnings
import zipfile

import pytest

from tools import verify_windows_bundle as verify
from tools.tests.test_windows_platform_pins import repository


VERSION = "152.0.7977.82"
PE_OFFSET = 128
OPTIONAL_OFFSET = PE_OFFSET + 24
SECTION_OFFSET = OPTIONAL_OFFSET + 240


def pe_fixture(arch="arm64", *, dll=False):
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, PE_OFFSET)
    data[PE_OFFSET:PE_OFFSET + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, PE_OFFSET + 4, verify.MACHINES[arch], 1,
                     0, 0, 0, 240, 0x22 | (0x2000 if dll else 0))
    struct.pack_into("<H", data, OPTIONAL_OFFSET, 0x20B)
    struct.pack_into("<I", data, OPTIONAL_OFFSET + 4, 512)
    struct.pack_into("<IIQII", data, OPTIONAL_OFFSET + 16,
                     0x1000, 0x1000, 0x140000000, 0x1000, 512)
    struct.pack_into("<HH", data, OPTIONAL_OFFSET + 40, 6, 0)
    struct.pack_into("<HH", data, OPTIONAL_OFFSET + 48, 6, 0)
    struct.pack_into("<II", data, OPTIONAL_OFFSET + 56, 0x2000, 512)
    struct.pack_into("<HH", data, OPTIONAL_OFFSET + 68, 3, 0x8160)
    struct.pack_into("<QQQQ", data, OPTIONAL_OFFSET + 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into("<I", data, OPTIONAL_OFFSET + 108, 16)
    struct.pack_into("<8sIIIIIIHHI", data, SECTION_OFFSET, b".text", 4, 0x1000,
                     512, 512, 0, 0, 0, 0, 0x60000020)
    code = b"\xc0\x03\x5f\xd6" if arch == "arm64" else b"\xc3"
    data[512:512 + len(code)] = code
    return bytes(data)


def bundle_fixture(root, arch="arm64"):
    root.mkdir(parents=True, exist_ok=True)
    for name in verify.REQUIRED:
        path = root / name
        path.write_bytes(pe_fixture(arch, dll=path.suffix == ".dll")
                         if path.suffix in (".exe", ".dll") else b"fixture data\n")
    (root / "chromix.cmd").write_bytes(b'@echo off\r\n"%~dp0chrome.exe" %*\r\n')
    (root / "v8_context_snapshot.bin").write_bytes(b"snapshot")
    (root / "locales").mkdir(exist_ok=True)
    (root / "locales/en-US.pak").write_bytes(b"locale")
    (root / "chrome.exe.manifest").write_bytes(b'<assembly manifestVersion="1.0"/>')
    return root


def archive_fixture(root, arch="arm64", extras=()):
    bundle = bundle_fixture(root / "source/chromix", arch)
    archive = root / f"chromix-win-{arch}.zip"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as output:
            for path in sorted(bundle.rglob("*")):
                if path.is_file():
                    output.write(path, path.relative_to(bundle.parent).as_posix())
            for name, payload in extras:
                if isinstance(name, str):
                    mode = stat.S_IFDIR | 0o755 if name.endswith('/') else stat.S_IFREG | 0o644
                    name = member_info(name, mode)
                output.writestr(name, payload)
    manifest = root / "SHA256SUMS"
    update_manifest(archive, manifest)
    return archive, manifest, root / "extracted"


def update_manifest(archive, manifest):
    manifest.write_text(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n",
                        encoding="utf-8")


def corrupt_member(archive, name):
    with zipfile.ZipFile(archive) as container:
        item = container.getinfo(name)
    data = bytearray(archive.read_bytes())
    name_size, extra_size = struct.unpack_from("<HH", data, item.header_offset + 26)
    offset = item.header_offset + 30 + name_size + extra_size
    assert item.file_size and item.compress_type == zipfile.ZIP_STORED
    data[offset] ^= 1
    archive.write_bytes(data)


def member_info(name, mode):
    item = zipfile.ZipInfo(name)
    # ZipInfo normalizes backslashes on Windows. Preserve the exact archive
    # input instead of accidentally repairing an unsafe fixture while writing.
    item.filename = item.orig_filename = name
    item.create_system = 3
    item.external_attr = mode << 16
    return item


@pytest.mark.parametrize("arch", verify.MACHINES)
def test_complete_pe32plus_headers_and_identity(tmp_path, arch):
    assert verify.MACHINES == {"x64": 0x8664, "arm64": 0xAA64}
    path = tmp_path / "chrome.exe"
    data = pe_fixture(arch)
    path.write_bytes(data)
    assert verify.check_pe(path, arch) == {
        "machine": verify.MACHINES[arch], "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


@pytest.mark.parametrize("arch,other", [("arm64", "x64"), ("x64", "arm64")])
def test_wrong_pe_machine(tmp_path, arch, other):
    path = tmp_path / "chrome.dll"
    path.write_bytes(pe_fixture(other, dll=True))
    with pytest.raises(verify.VerificationError, match="wrong PE architecture"):
        verify.check_pe(path, arch)


@pytest.mark.parametrize("arch", verify.MACHINES)
@pytest.mark.parametrize("length", [0, 2, 63, 64, 127, 151, 152, 200, 391, 431, 1023])
def test_truncated_pe_headers_and_raw_section(tmp_path, arch, length):
    path = tmp_path / "chrome.exe"
    path.write_bytes(pe_fixture(arch)[:length])
    with pytest.raises(verify.VerificationError):
        verify.check_pe(path, arch)


@pytest.mark.parametrize("arch", verify.MACHINES)
@pytest.mark.parametrize("offset,fmt,value,message", [
    (0, "H", 0, "DOS header"),
    (60, "I", 63, "PE header is outside"),
    (60, "I", 0xFFFFFFFF, "PE header is outside"),
    (PE_OFFSET, "I", 0, "PE signature"),
    (PE_OFFSET + 6, "H", 0, "sections or executable"),
    (PE_OFFSET + 6, "H", 97, "sections or executable"),
    (PE_OFFSET + 22, "H", 0x20, "sections or executable"),
    (PE_OFFSET + 20, "H", 111, "truncated optional"),
    (PE_OFFSET + 20, "H", 65535, "truncated optional"),
    (OPTIONAL_OFFSET, "H", 0x10B, "PE32\\+"),
    (OPTIONAL_OFFSET + 108, "I", 17, "data directories"),
    (PE_OFFSET + 20, "H", 232, "data directories"),
    (SECTION_OFFSET + 20, "I", 0, "section data is outside"),
    (SECTION_OFFSET + 20, "I", 1, "section data is outside"),
    (SECTION_OFFSET + 20, "I", SECTION_OFFSET + 39, "section data is outside"),
    (SECTION_OFFSET + 20, "I", 513, "section data is outside"),
    (SECTION_OFFSET + 20, "I", 0xFFFFFFF0, "section data is outside"),
    (SECTION_OFFSET + 16, "I", 0xFFFFFFFF, "section data is outside"),
])
def test_malformed_pe_header_fields(tmp_path, arch, offset, fmt, value, message):
    data = bytearray(pe_fixture(arch))
    struct.pack_into("<" + fmt, data, offset, value)
    path = tmp_path / "chrome.exe"
    path.write_bytes(data)
    with pytest.raises(verify.VerificationError, match=message):
        verify.check_pe(path, arch)


def test_all_sections_are_bounded_and_zero_raw_data_is_valid(tmp_path):
    data = bytearray(pe_fixture())
    struct.pack_into("<H", data, PE_OFFSET + 6, 2)
    struct.pack_into("<8sIIIIIIHHI", data, SECTION_OFFSET + 40, b".bss", 128, 0x2000,
                     0, 0, 0, 0, 0, 0, 0xC0000080)
    path = tmp_path / "chrome.exe"
    path.write_bytes(data)
    verify.check_pe(path, "arm64")
    struct.pack_into("<II", data, SECTION_OFFSET + 40 + 16, 1, len(data))
    path.write_bytes(data)
    with pytest.raises(verify.VerificationError, match="section data is outside"):
        verify.check_pe(path, "arm64")


@pytest.mark.parametrize("arch", verify.MACHINES)
def test_static_bundle_is_host_independent_and_never_executes(tmp_path, arch):
    bundle = bundle_fixture(tmp_path / "chromix", arch)
    with mock.patch.object(verify, "native_architecture", side_effect=AssertionError("host queried")), \
            mock.patch.object(verify.subprocess, "Popen", side_effect=AssertionError("executed")):
        report = verify.validate_bundle(bundle, arch)
    assert report["arch"] == arch
    assert report["bundle_dir"] == str(bundle.resolve())
    assert report["runtime"] == {"status": "not_run"}
    assert report["static"]["status"] == "passed"
    binaries = {name for name in verify.REQUIRED if Path(name).suffix in (".exe", ".dll")}
    assert report["static"]["pe_count"] == len(binaries)
    assert set(report["static"]["pe_files"]) == binaries


@pytest.mark.parametrize("name", verify.REQUIRED)
@pytest.mark.parametrize("kind", ["missing", "empty", "directory"])
def test_required_layout_files(tmp_path, name, kind):
    bundle = bundle_fixture(tmp_path / "chromix")
    path = bundle / name
    path.unlink()
    if kind == "empty":
        path.touch()
    elif kind == "directory":
        path.mkdir()
    with pytest.raises(verify.VerificationError, match="missing or empty required file"):
        verify.validate_bundle(bundle, "arm64")


@pytest.mark.parametrize("name,message", [
    ("v8_context_snapshot.bin", "V8 snapshot"),
    ("locales/en-US.pak", "en-US locale"),
    ("chrome.exe.manifest", "side-by-side manifest"),
])
@pytest.mark.parametrize("empty", [False, True])
def test_required_snapshot_locale_manifest(tmp_path, name, message, empty):
    bundle = bundle_fixture(tmp_path / "chromix")
    path = bundle / name
    if empty:
        path.write_bytes(b"")
    else:
        path.unlink()
    with pytest.raises(verify.VerificationError, match=message):
        verify.validate_bundle(bundle, "arm64")


def test_alternative_snapshot_blob_is_accepted(tmp_path):
    bundle = bundle_fixture(tmp_path / "chromix")
    (bundle / "v8_context_snapshot.bin").unlink()
    (bundle / "snapshot_blob.bin").write_bytes(b"snapshot")
    assert verify.validate_bundle(bundle, "arm64")["static"]["status"] == "passed"


@pytest.mark.parametrize("arch,other", [("arm64", "x64"), ("x64", "arm64")])
@pytest.mark.parametrize("name", ["chrome.exe", "chrome.dll", "nested/helpers/extra.DLL",
                                  ".hidden/utility.EXE", ".hidden/blob", "drivers/extra.sys",
                                  f"{VERSION}/chrome.dll"])
def test_mixed_architecture_including_nested_dlls(tmp_path, arch, other, name):
    bundle = bundle_fixture(tmp_path / "chromix", arch)
    path = bundle / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pe_fixture(other, dll=path.suffix.lower() == ".dll"))
    with pytest.raises(verify.VerificationError, match="wrong PE architecture"):
        verify.validate_bundle(bundle, arch)


@pytest.mark.parametrize("name", ["chrome.dll", "CHROME.DLL", "Chrome.Dll"])
def test_identical_versioned_dll_is_required(tmp_path, name):
    bundle = bundle_fixture(tmp_path / "chromix")
    path = bundle / VERSION / name
    path.parent.mkdir()
    path.write_bytes((bundle / "chrome.dll").read_bytes())
    report = verify.validate_bundle(bundle, "arm64")
    assert f"{VERSION}/{name}" in report["static"]["pe_files"]
    path.write_bytes(path.read_bytes() + b"different overlay")
    with pytest.raises(verify.VerificationError, match="versioned chrome.dll differs"):
        verify.validate_bundle(bundle, "arm64")


@pytest.mark.parametrize("kind", ["root", "required", "snapshot", "locale", "manifest", "file", "directory", "broken"])
def test_bundle_rejects_symlinks(tmp_path, kind):
    bundle = bundle_fixture(tmp_path / "chromix")
    target = tmp_path / "outside"
    target.write_bytes(b"outside")
    if kind == "root":
        link = tmp_path / "linked"
        link.symlink_to(bundle, target_is_directory=True)
        bundle = link
    else:
        name = {"required": "chrome.exe", "snapshot": "v8_context_snapshot.bin",
                "locale": "locales/en-US.pak", "manifest": "chrome.exe.manifest"}.get(kind, "optional")
        link = bundle / name
        if link.exists():
            target.write_bytes(link.read_bytes())
            link.unlink()
        if kind == "directory":
            target = tmp_path / "outside-directory"
            target.mkdir()
        if kind == "broken":
            target = tmp_path / "nonexistent"
        link.symlink_to(target, target_is_directory=kind == "directory")
    with pytest.raises(verify.VerificationError, match="link|required file|reparse"):
        verify.validate_bundle(bundle, "arm64")


def test_bundle_rejects_special_file_and_scan_errors(tmp_path, monkeypatch):
    bundle = bundle_fixture(tmp_path / "chromix")
    if hasattr(os, "mkfifo"):
        os.mkfifo(bundle / "pipe")
        with pytest.raises(verify.VerificationError, match="special file"):
            verify.validate_bundle(bundle, "arm64")
        (bundle / "pipe").unlink()

    def failed_walk(root, *, followlinks, onerror):
        onerror(PermissionError("unreadable fixture directory"))

    monkeypatch.setattr(verify.os, "walk", failed_walk)
    with pytest.raises(PermissionError, match="unreadable fixture"):
        verify.validate_bundle(bundle, "arm64")


@pytest.mark.parametrize("at_root", [False, True])
def test_bundle_rejects_mock_windows_reparse_attribute(tmp_path, monkeypatch, at_root):
    bundle = bundle_fixture(tmp_path / "chromix")
    link = bundle if at_root else bundle / "optional"
    if not at_root:
        link.write_bytes(b"fixture")
    original = Path.lstat

    def lstat(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path == link:
            return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
        return info

    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(verify.VerificationError, match="reparse points|not a link"):
        verify.validate_bundle(bundle, "arm64")


def test_unsupported_architecture_and_invalid_bundle_root(tmp_path):
    with pytest.raises(verify.VerificationError, match="unsupported Windows architecture"):
        verify.validate_bundle(tmp_path, "ia32")
    for path in (tmp_path / "missing", tmp_path / "file"):
        if path.name == "file":
            path.write_bytes(b"file")
        with pytest.raises(verify.VerificationError, match="bundle must be a directory"):
            verify.validate_bundle(path, "arm64")


@pytest.mark.parametrize("arch", verify.MACHINES)
@pytest.mark.parametrize("style", ["plain", "binary-uppercase-bom"])
def test_real_zip_sha_manifest_and_static_extraction(tmp_path, arch, style):
    archive, manifest, dest = archive_fixture(tmp_path, arch, extras=[("chromix/empty/", b"")])
    if style == "binary-uppercase-bom":
        digest = hashlib.sha256(archive.read_bytes()).hexdigest().upper()
        manifest.write_text(f"{digest} *{archive.name}\n{'0' * 64}  unrelated.zip\n", encoding="utf-8-sig")
    with mock.patch.object(verify.subprocess, "Popen", side_effect=AssertionError("executed")):
        report = verify.extract_archive(archive, manifest, dest, arch)
    assert report["static"]["status"] == "passed"
    assert report["runtime"] == {"status": "not_run"}
    assert report["archive"] == {"name": archive.name, "size": archive.stat().st_size,
                                  "sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
    assert (dest / "chromix/empty").is_dir()
    assert (dest / "chromix/chrome.exe").read_bytes() == pe_fixture(arch)


@pytest.mark.parametrize("problem", ["digest", "missing", "duplicate", "wrong-name", "oversized"])
def test_archive_checksum_manifest_failures_precede_extraction(tmp_path, problem):
    archive, manifest, dest = archive_fixture(tmp_path)
    original = manifest.read_text()
    values = {"digest": f"{'0' * 64}  {archive.name}\n", "missing": "",
              "duplicate": original * 2, "wrong-name": original.replace(archive.name, "other.zip"),
              "oversized": " " * (64 * 1024 + 1)}
    manifest.write_text(values[problem])
    with pytest.raises(verify.VerificationError, match="manifest|SHA256"):
        verify.extract_archive(archive, manifest, dest, "arm64")
    assert not dest.exists()


def test_archive_requires_platform_filename_and_fresh_destination(tmp_path):
    archive, manifest, dest = archive_fixture(tmp_path)
    wrong = archive.with_name("renamed.zip")
    archive.rename(wrong)
    with pytest.raises(verify.VerificationError, match="expected archive name"):
        verify.extract_archive(wrong, manifest, dest, "arm64")
    wrong.rename(archive)
    dest.mkdir()
    sentinel = dest / "keep"
    sentinel.write_bytes(b"untouched")
    with pytest.raises(verify.VerificationError, match="destination must not already exist"):
        verify.extract_archive(archive, manifest, dest, "arm64")
    assert sentinel.read_bytes() == b"untouched"
    sentinel.unlink()
    dest.rmdir()
    dest.symlink_to(tmp_path / "missing", target_is_directory=True)
    with pytest.raises(verify.VerificationError, match="destination must not already exist"):
        verify.extract_archive(archive, manifest, dest, "arm64")


def test_archive_corrupt_file_crc_is_rejected_even_with_matching_sha(tmp_path):
    archive, manifest, dest = archive_fixture(tmp_path)
    corrupt_member(archive, "chromix/resources.pak")
    update_manifest(archive, manifest)
    with pytest.raises(zipfile.BadZipFile, match="CRC"):
        verify.extract_archive(archive, manifest, dest, "arm64")


@pytest.mark.parametrize("name", [
    "../outside", "chromix/../../outside", "chromix/../outside", "/chromix/outside",
    "C:/chromix/outside", "//server/share/file", "chromix\\outside", "chromix/dir\\outside",
    "other/file", "Chromix/file", "chromix/./file", "chromix//file", "chromix/file.",
    "chromix/file ", "chromix/dir./file", "chromix/dir /file", "chromix/file:stream",
    "chromix/CON", "chromix/con.txt", "chromix/PRN.dat", "chromix/AuX/file",
    "chromix/NUL", "chromix/COM1.txt", "chromix/com9/file", "chromix/LPT1", "chromix/lpt9.txt",
    "chromix/a<b", "chromix/a>b", 'chromix/a"b', "chromix/a|b", "chromix/a?b", "chromix/a*b",
    "chromix/a\x01b", "chromix/a\x7fb", "chromix/a\nb", "chromix/a\rb",
])
def test_archive_rejects_unsafe_windows_paths_before_writing(tmp_path, name):
    archive, manifest, dest = archive_fixture(tmp_path, extras=[(name, b"unsafe")])
    with zipfile.ZipFile(archive) as container:
        assert any(item.orig_filename == name for item in container.infolist())
    with pytest.raises(verify.VerificationError, match="unsafe Windows archive path"):
        verify.extract_archive(archive, manifest, dest, "arm64")
    assert not dest.exists()
    assert not (tmp_path / "outside").exists()


@pytest.mark.parametrize("name", ["chromix\\outside", "chromix/dir\\outside"])
def test_archive_rejects_original_name_when_decoder_normalizes_slashes(tmp_path, monkeypatch, name):
    archive, manifest, dest = archive_fixture(tmp_path, extras=[(name, b"unsafe")])
    original = zipfile.ZipInfo.__init__

    def normalizing_decoder(item, *args, **kwargs):
        original(item, *args, **kwargs)
        # Exercise Windows' decoder behavior even on a POSIX CI runner.
        item.filename = item.filename.replace("\\", "/")

    monkeypatch.setattr(zipfile.ZipInfo, "__init__", normalizing_decoder)
    with pytest.raises(verify.VerificationError, match="unsafe Windows archive path"):
        verify.extract_archive(archive, manifest, dest, "arm64")
    assert not dest.exists()


@pytest.mark.parametrize("names", [
    ["chromix/extra", "chromix/extra"],
    ["chromix/EXTRA", "chromix/extra"],
    ["chromix/extra/", "chromix/EXTRA"],
    ["chromix/extra", "chromix/EXTRA/nested"],
    ["chromix/EXTRA/nested", "chromix/extra"],
])
def test_archive_rejects_duplicates_and_file_parent_aliases(tmp_path, names):
    archive, manifest, dest = archive_fixture(
        tmp_path, extras=[(name, b"" if name.endswith("/") else b"x") for name in names])
    with pytest.raises(verify.VerificationError, match="duplicate Windows|shadows a parent"):
        verify.extract_archive(archive, manifest, dest, "arm64")
    assert not dest.exists()


@pytest.mark.parametrize("mode,payload", [
    (stat.S_IFLNK | 0o777, b"../../outside"),
    (stat.S_IFIFO | 0o600, b""),
    (stat.S_IFCHR | 0o600, b""),
    (stat.S_IFDIR | 0o755, b""),
])
def test_archive_rejects_links_special_files_and_directory_mode_mismatch(tmp_path, mode, payload):
    item = member_info("chromix/extra", mode)
    archive, manifest, dest = archive_fixture(tmp_path, extras=[(item, payload)])
    with pytest.raises(verify.VerificationError, match="unsupported archive member"):
        verify.extract_archive(archive, manifest, dest, "arm64")
    assert not dest.exists()


def test_archive_rejects_encrypted_member_before_writing(tmp_path):
    archive, manifest, dest = archive_fixture(tmp_path)
    data = bytearray(archive.read_bytes())
    central = data.index(b"PK\x01\x02")
    for offset in (6, central + 8):
        struct.pack_into("<H", data, offset, struct.unpack_from("<H", data, offset)[0] | 1)
    archive.write_bytes(data)
    update_manifest(archive, manifest)
    with pytest.raises(verify.VerificationError, match="unsupported archive member"):
        verify.extract_archive(archive, manifest, dest, "arm64")
    assert not dest.exists()


@pytest.mark.parametrize("problem", ["empty", "member-count", "expanded-size"])
def test_archive_resource_limits_use_tiny_fixtures(tmp_path, monkeypatch, problem):
    archive, manifest, dest = archive_fixture(tmp_path)
    if problem == "expanded-size":
        monkeypatch.setattr(verify, "MAX_EXPANDED", 1)
    else:
        with zipfile.ZipFile(archive, "w") as output:
            if problem == "member-count":
                for index in range(10001):
                    output.writestr(f"chromix/f{index}", b"")
        update_manifest(archive, manifest)
    with pytest.raises(verify.VerificationError, match="member count or expanded size"):
        verify.extract_archive(archive, manifest, dest, "arm64")
    assert not dest.exists()


def test_archive_mixed_architecture_is_not_static_pass(tmp_path):
    archive, manifest, dest = archive_fixture(tmp_path, extras=[("chromix/nested/foreign.DLL", pe_fixture("x64"))])
    with pytest.raises(verify.VerificationError, match="wrong PE architecture"):
        verify.extract_archive(archive, manifest, dest, "arm64")


@pytest.mark.parametrize("name", ["chromix/COM¹.txt", "chromix/com²", "chromix/COM³/file",
                                  "chromix/LPT¹", "chromix/lpt².txt", "chromix/LPT³/file"])
def test_archive_rejects_windows_superscript_device_aliases(tmp_path, name):
    archive, manifest, dest = archive_fixture(tmp_path, extras=[(name, b"unsafe")])
    with pytest.raises(verify.VerificationError, match="unsafe Windows archive path"):
        verify.extract_archive(archive, manifest, dest, "arm64")
    assert not dest.exists()


def test_archive_rejects_nul_in_original_zip_member_name(tmp_path):
    name = b"chromix/extra.txtXignored"
    archive, manifest, dest = archive_fixture(tmp_path, extras=[(name.decode(), b"unsafe")])
    data = archive.read_bytes()
    assert data.count(name) == 2
    archive.write_bytes(data.replace(name, name.replace(b"X", b"\0")))
    update_manifest(archive, manifest)
    with zipfile.ZipFile(archive) as container:
        item = container.infolist()[-1]
        assert "\0" in item.orig_filename and "\0" not in item.filename
    with pytest.raises(verify.VerificationError, match="unsafe Windows archive path"):
        verify.extract_archive(archive, manifest, dest, "arm64")
    assert not dest.exists()


def test_archive_checks_crc_of_directory_members(tmp_path):
    archive, manifest, dest = archive_fixture(tmp_path, extras=[("chromix/extra/", b"directory payload")])
    corrupt_member(archive, "chromix/extra/")
    update_manifest(archive, manifest)
    with zipfile.ZipFile(archive) as container:
        assert container.testzip() == "chromix/extra/"
    with pytest.raises((verify.VerificationError, zipfile.BadZipFile)):
        verify.extract_archive(archive, manifest, dest, "arm64")


def test_archive_checks_crc_of_empty_directory_members(tmp_path):
    archive, manifest, dest = archive_fixture(tmp_path, extras=[("chromix/empty/", b"")])
    with zipfile.ZipFile(archive) as container:
        item = container.getinfo("chromix/empty/")
    data = bytearray(archive.read_bytes())
    struct.pack_into("<I", data, item.header_offset + 14, 1)
    central = data.index(b"PK\x01\x02")
    while True:
        name_size, extra_size, comment_size = struct.unpack_from("<HHH", data, central + 28)
        name = data[central + 46:central + 46 + name_size].decode()
        if name == item.filename:
            struct.pack_into("<I", data, central + 16, 1)
            break
        central += 46 + name_size + extra_size + comment_size
        assert data[central:central + 4] == b"PK\x01\x02"
    archive.write_bytes(data)
    update_manifest(archive, manifest)
    with zipfile.ZipFile(archive) as container:
        assert container.testzip() == "chromix/empty/"
    with pytest.raises((verify.VerificationError, zipfile.BadZipFile)):
        verify.extract_archive(archive, manifest, dest, "arm64")


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_native_architecture_rejects_non_windows_before_loading_api(monkeypatch, platform):
    monkeypatch.setattr(verify.sys, "platform", platform)
    loader = mock.Mock(side_effect=AssertionError("Windows API called on non-Windows"))
    monkeypatch.setattr(verify.ctypes, "WinDLL", loader, raising=False)
    with pytest.raises(verify.VerificationError, match="native smoke requires Windows"):
        verify.native_architecture()
    loader.assert_not_called()


@pytest.mark.parametrize("native,process,expected", [(0xAA64, 0, "arm64"), (0x8664, 0, "x64"),
                                                       (0xAA64, 0x8664, "arm64"),
                                                       (0x8664, 0x014C, "x64"), (0x014C, 0, None)])
def test_mock_native_api_uses_host_not_emulated_process_machine(monkeypatch, native, process, expected):
    def query(handle, process_pointer, native_pointer):
        process_pointer._obj.value = process
        native_pointer._obj.value = native
        return 1

    kernel = SimpleNamespace(GetCurrentProcess=mock.Mock(return_value=42), IsWow64Process2=mock.Mock(side_effect=query))
    monkeypatch.setattr(verify.sys, "platform", "win32")
    monkeypatch.setattr(verify.ctypes, "WinDLL", mock.Mock(return_value=kernel), raising=False)
    assert verify.native_architecture() == expected
    assert kernel.IsWow64Process2.call_args.args[0] == 42


def test_mock_native_api_failure_is_not_an_architecture_pass(monkeypatch):
    kernel = SimpleNamespace(GetCurrentProcess=mock.Mock(return_value=42), IsWow64Process2=mock.Mock(return_value=0))
    monkeypatch.setattr(verify.sys, "platform", "win32")
    monkeypatch.setattr(verify.ctypes, "WinDLL", mock.Mock(return_value=kernel), raising=False)
    monkeypatch.setattr(verify.ctypes, "get_last_error", lambda: 5, raising=False)
    monkeypatch.setattr(verify.ctypes, "WinError", lambda code: OSError(code, "mock Windows API failure"), raising=False)
    with pytest.raises(OSError, match="mock Windows API failure"):
        verify.native_architecture()


@pytest.mark.parametrize("problem", [None, "missing", "oversized", "load", "query", "short", "signature"])
def test_mock_product_version_resource_validation(monkeypatch, problem):
    fields = (verify.wintypes.DWORD * 13)()
    fields[0], fields[4], fields[5] = 0xFEEF04BD, (152 << 16), (7977 << 16) | 82
    if problem == "signature":
        fields[0] = 0

    def query(buffer, subblock, pointer, length):
        assert subblock == "\\"
        pointer._obj.value = ctypes.addressof(fields)
        length._obj.value = 51 if problem == "short" else ctypes.sizeof(fields)
        return problem != "query"

    size = 0 if problem == "missing" else 16 * 1024 * 1024 + 1 if problem == "oversized" else 256
    library = SimpleNamespace(GetFileVersionInfoSizeW=mock.Mock(return_value=size),
                              GetFileVersionInfoW=mock.Mock(return_value=problem != "load"),
                              VerQueryValueW=mock.Mock(side_effect=query))
    monkeypatch.setattr(verify.ctypes, "WinDLL", mock.Mock(return_value=library), raising=False)
    if problem is None:
        assert verify.product_version(Path("chrome.exe")) == VERSION
    else:
        with pytest.raises(verify.VerificationError, match="version resource|version signature"):
            verify.product_version(Path("chrome.exe"))
    if problem in ("missing", "oversized"):
        library.GetFileVersionInfoW.assert_not_called()


@pytest.fixture
def runtime_fixture(tmp_path, monkeypatch):
    bundle = bundle_fixture(tmp_path / "chromix")
    report = verify.validate_bundle(bundle, "arm64")
    original = tempfile.TemporaryDirectory
    profiles = []

    def temporary_profile(**kwargs):
        directory = original(dir=tmp_path, **kwargs)
        profiles.append(Path(directory.name))
        return directory

    def headless(bundle, profile, logs):
        assert Path(profile).is_dir()
        (Path(profile) / "cache").write_bytes(b"profile fixture")
        return {"status": "passed", "exit_code": 0, "timeout_seconds": 60}

    native = mock.Mock(return_value="arm64")
    version = mock.Mock(return_value=VERSION)
    smoke = mock.Mock(side_effect=headless)
    monkeypatch.setattr(verify, "native_architecture", native)
    monkeypatch.setattr(verify, "product_version", version)
    monkeypatch.setattr(verify, "run_headless", smoke)
    monkeypatch.setattr(verify.tempfile, "TemporaryDirectory", temporary_profile)
    return SimpleNamespace(bundle=bundle, report=report, native=native, version=version,
                           smoke=smoke, profiles=profiles, logs=tmp_path / "logs")


@pytest.mark.parametrize("host", ["x64", None])
def test_mock_runtime_rejects_wrong_or_unknown_native_host(runtime_fixture, host):
    fixture = runtime_fixture
    fixture.native.return_value = host
    with pytest.raises(verify.VerificationError, match="native Windows arm64 host is required"):
        verify.runtime_smoke(fixture.report, VERSION, fixture.logs)
    fixture.version.assert_not_called()
    fixture.smoke.assert_not_called()
    assert fixture.profiles == []
    assert fixture.report["runtime"]["status"] != "passed"


@pytest.mark.parametrize("version", ["", "152", "152.0.7977", "152.0.7977.82\n", "152.0.7977.82suffix"])
def test_mock_runtime_rejects_invalid_expected_version(runtime_fixture, version):
    fixture = runtime_fixture
    with pytest.raises(verify.VerificationError, match="invalid expected Chromium version"):
        verify.runtime_smoke(fixture.report, version, fixture.logs)
    fixture.version.assert_not_called()
    fixture.smoke.assert_not_called()


@pytest.mark.parametrize("versions,name", [(["1.2.3.4"], "chrome.exe"), ([VERSION, "1.2.3.4"], "chrome.dll")])
def test_mock_runtime_checks_both_product_versions(runtime_fixture, versions, name):
    fixture = runtime_fixture
    fixture.version.side_effect = versions
    with pytest.raises(verify.VerificationError, match=f"product version mismatch: {name}"):
        verify.runtime_smoke(fixture.report, VERSION, fixture.logs)
    fixture.smoke.assert_not_called()
    assert fixture.profiles == []


def test_mock_runtime_success_revalidates_real_pe_files_and_cleans_profile(runtime_fixture):
    fixture = runtime_fixture
    result = verify.runtime_smoke(fixture.report, VERSION, fixture.logs)
    assert result["runtime"] == {"status": "passed", "exit_code": 0, "timeout_seconds": 60,
                                  "version": VERSION, "native_arch": "arm64"}
    assert fixture.version.call_args_list == [mock.call(fixture.bundle / "chrome.exe"),
                                              mock.call(fixture.bundle / "chrome.dll")]
    assert len(fixture.profiles) == 1 and not fixture.profiles[0].exists()


@pytest.mark.parametrize("failure", ["headless", "changed", "removed", "foreign"])
def test_mock_runtime_failure_and_binary_mutation_cannot_pass(runtime_fixture, failure):
    fixture = runtime_fixture

    def smoke(*args):
        if failure == "headless":
            raise verify.VerificationError("mock headless failure")
        binary = fixture.bundle / "chrome.dll"
        if failure == "removed":
            binary.unlink()
        else:
            binary.write_bytes(pe_fixture("x64", dll=True) if failure == "foreign"
                               else binary.read_bytes() + b"changed during smoke")
        return {"status": "passed"}

    fixture.smoke.side_effect = smoke
    with pytest.raises(verify.VerificationError, match="headless failure|binaries changed|required file|architecture"):
        verify.runtime_smoke(fixture.report, VERSION, fixture.logs)
    assert fixture.report["runtime"]["status"] != "passed"
    assert len(fixture.profiles) == 1 and not fixture.profiles[0].exists()


class GateInput(io.BytesIO):
    def __init__(self, owner):
        super().__init__()
        self.owner = owner
        self.released = bytearray()

    def write(self, value):
        self.owner.events.append("release")
        assert self.owner.assigned
        self.released.extend(value)
        return super().write(value)

    def close(self):
        self.owner.events.append("stdin-close")
        super().close()


class FakeProcess:
    def __init__(self, owner):
        self.owner = owner
        self.stdin = GateInput(owner)
        self.returncode = 0
        self.running = False
        self.wait = mock.Mock(side_effect=self.wait_for_exit)
        self.kill = mock.Mock(side_effect=self.kill_process)

    def poll(self):
        self.owner.events.append("poll")
        return None if self.running else self.returncode

    def kill_process(self):
        self.owner.events.append("kill")
        self.running = False
        self.returncode = -9

    def wait_for_exit(self, timeout):
        self.owner.events.append("wait")
        assert timeout == 5
        assert not self.running
        return self.returncode


@pytest.fixture
def headless_fixture(tmp_path, monkeypatch):
    fixture = SimpleNamespace(bundle=bundle_fixture(tmp_path / "bundle & (fixture)!/chromix"),
                              profile=tmp_path / "profile & (fixture)!", logs=tmp_path / "logs",
                              events=[], assigned=False, stdout=verify.DOM_MARKER.encode(), stderr=b"", streams=[])
    fixture.process = FakeProcess(fixture)

    def assign(process):
        assert process is fixture.process
        fixture.events.append("assign")
        fixture.assigned = True

    job = SimpleNamespace(assign=mock.Mock(side_effect=assign),
                          terminate=mock.Mock(side_effect=lambda: fixture.events.append("terminate")),
                          close=mock.Mock(side_effect=lambda: fixture.events.append("job-close")))
    fixture.job = job
    fixture.job_factory = mock.Mock(return_value=job)
    monkeypatch.setitem(sys.modules, "fingerprint_subprocess", SimpleNamespace(WindowsJob=fixture.job_factory))

    def start(command, **kwargs):
        fixture.events.append("start")
        fixture.streams = [kwargs["stdout"], kwargs["stderr"]]
        for stream, data in zip(fixture.streams, (fixture.stdout, fixture.stderr)):
            stream.write(data)
            stream.flush()
        return fixture.process

    fixture.popen = mock.Mock(side_effect=start)
    monkeypatch.setattr(verify.subprocess, "Popen", fixture.popen)
    monkeypatch.setattr(verify.subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    monkeypatch.setenv("COMSPEC", r"C:\Windows\System32\cmd.exe")
    monkeypatch.setattr(verify.time, "sleep", mock.Mock())
    return fixture


def assert_headless_clean(fixture, *, started=True):
    fixture.job.terminate.assert_called_once_with()
    fixture.job.close.assert_called_once_with()
    assert all(stream.closed for stream in fixture.streams)
    if started:
        assert fixture.process.stdin.closed
        fixture.process.wait.assert_called_once_with(timeout=5)


def test_mock_headless_launch_gate_quoting_and_job_cleanup(headless_fixture):
    fixture = headless_fixture
    result = verify.run_headless(fixture.bundle, fixture.profile, fixture.logs)
    assert result["status"] == "passed" and result["exit_code"] == 0
    assert result["timeout_seconds"] == 60
    command = fixture.popen.call_args.args[0]
    assert command[:2] == [sys.executable, "-c"]
    assert 'sys.stdin.buffer.read(1)==b"1"' in command[2]
    assert "stdin=subprocess.DEVNULL" in command[2]
    arguments = [str(fixture.bundle / "chromix.cmd"), "--headless", "--disable-gpu", "--no-first-run",
                 "--no-default-browser-check", f"--user-data-dir={fixture.profile}",
                 "--dump-dom", "data:text/html," + verify.DOM_MARKER]
    assert command[3] == ('"C:\\Windows\\System32\\cmd.exe" /d /v:off /s /c "'
                          + " ".join(f'"{value}"' for value in arguments) + '"')
    assert "--no-sandbox" not in command[3] and "chrome.exe" not in command[3]
    kwargs = fixture.popen.call_args.kwargs
    assert kwargs["cwd"] == fixture.bundle
    assert kwargs["stdin"] == subprocess.PIPE
    assert kwargs["creationflags"] == 0x08000000
    assert "shell" not in kwargs
    assert fixture.process.stdin.released == b"1"
    assert fixture.events.index("assign") < fixture.events.index("release")
    assert fixture.events.index("terminate") < fixture.events.index("job-close") < fixture.events.index("wait")
    fixture.process.kill.assert_not_called()
    assert Path(result["stdout"]).read_bytes() == fixture.stdout
    assert Path(result["stderr"]).read_bytes() == fixture.stderr
    assert_headless_clean(fixture)


@pytest.mark.parametrize("stdout,stderr", [(b"", b""), (b"<p>chromix-smoke-", b""),
                                           (b"unrelated", verify.DOM_MARKER.encode())])
def test_mock_headless_missing_or_stderr_only_marker_fails(headless_fixture, stdout, stderr):
    fixture = headless_fixture
    fixture.stdout, fixture.stderr = stdout, stderr
    with pytest.raises(verify.VerificationError, match="missing the smoke DOM marker"):
        verify.run_headless(fixture.bundle, fixture.profile, fixture.logs)
    assert_headless_clean(fixture)


@pytest.mark.parametrize("returncode", [1, 7, -1])
def test_mock_headless_nonzero_exit_fails_despite_marker(headless_fixture, returncode):
    fixture = headless_fixture
    fixture.process.returncode = returncode
    with pytest.raises(verify.VerificationError, match=f"exited with status {returncode}"):
        verify.run_headless(fixture.bundle, fixture.profile, fixture.logs)
    assert_headless_clean(fixture)


def test_mock_headless_timeout_kills_and_reaps_gated_child(headless_fixture, monkeypatch):
    fixture = headless_fixture
    fixture.process.running = True
    monkeypatch.setattr(verify.time, "monotonic", mock.Mock(side_effect=[0, 61]))
    with pytest.raises(verify.VerificationError, match="did not exit within 60 seconds"):
        verify.run_headless(fixture.bundle, fixture.profile, fixture.logs)
    fixture.process.kill.assert_called_once_with()
    assert_headless_clean(fixture)


@pytest.mark.parametrize("running", [False, True])
def test_mock_headless_combined_output_bound_before_and_after_exit(headless_fixture, monkeypatch, running):
    fixture = headless_fixture
    fixture.stdout, fixture.stderr = verify.DOM_MARKER.encode() + b"x" * 32, b"y" * 32
    fixture.process.running = running
    monkeypatch.setattr(verify, "MAX_OUTPUT", 64)
    with pytest.raises(verify.VerificationError, match="output exceeds"):
        verify.run_headless(fixture.bundle, fixture.profile, fixture.logs)
    assert_headless_clean(fixture)


def test_mock_headless_polling_allows_normal_exit_and_bounded_sleep(headless_fixture, monkeypatch):
    fixture = headless_fixture
    polls = iter([None, 0, 0])
    fixture.process.poll = mock.Mock(side_effect=lambda: next(polls))
    monkeypatch.setattr(verify.time, "monotonic", mock.Mock(side_effect=[0, 1]))
    assert verify.run_headless(fixture.bundle, fixture.profile, fixture.logs)["status"] == "passed"
    verify.time.sleep.assert_called_once_with(0.05)
    assert_headless_clean(fixture)


def test_mock_headless_unavailable_returncode_cannot_pass(headless_fixture, monkeypatch):
    fixture = headless_fixture
    fixture.process.returncode = None
    monkeypatch.setattr(verify.time, "monotonic", mock.Mock(side_effect=[0, 61]))
    with pytest.raises(verify.VerificationError, match="60 seconds|exited with status"):
        verify.run_headless(fixture.bundle, fixture.profile, fixture.logs)
    fixture.process.kill.assert_called_once_with()
    assert_headless_clean(fixture)


@pytest.mark.parametrize("stage", ["construct", "start", "assign", "release", "terminate", "close", "wait"])
def test_mock_headless_failures_never_skip_remaining_job_cleanup(headless_fixture, stage):
    fixture = headless_fixture
    failure = OSError(f"mock {stage} failure")
    if stage == "construct":
        fixture.job_factory.side_effect = failure
    elif stage == "start":
        fixture.popen.side_effect = failure
    elif stage == "assign":
        fixture.job.assign.side_effect = failure
        fixture.process.running = True
    elif stage == "release":
        fixture.process.stdin.write = mock.Mock(side_effect=failure)
        fixture.process.running = True
    elif stage == "terminate":
        fixture.job.terminate.side_effect = failure
        fixture.process.running = False
    elif stage == "close":
        fixture.job.close.side_effect = failure
    else:
        failure = subprocess.TimeoutExpired("mock-child", 5)
        fixture.process.wait.side_effect = failure
    with pytest.raises(type(failure)):
        verify.run_headless(fixture.bundle, fixture.profile, fixture.logs)
    if stage == "construct":
        fixture.popen.assert_not_called()
        fixture.job.terminate.assert_not_called()
        fixture.job.close.assert_not_called()
    else:
        assert_headless_clean(fixture, started=stage != "start")
    if stage in ("assign", "release"):
        assert fixture.process.stdin.released == b""
        fixture.process.kill.assert_called_once_with()


@pytest.mark.parametrize("stage", ["terminate", "close"])
def test_mock_headless_timeout_cleanup_failure_still_kills_and_reaps(headless_fixture, monkeypatch, stage):
    fixture = headless_fixture
    fixture.process.running = True
    getattr(fixture.job, stage).side_effect = OSError(f"mock {stage} cleanup failure")
    monkeypatch.setattr(verify.time, "monotonic", mock.Mock(side_effect=[0, 61]))
    with pytest.raises((OSError, verify.VerificationError)):
        verify.run_headless(fixture.bundle, fixture.profile, fixture.logs)
    fixture.process.kill.assert_called_once_with()
    assert_headless_clean(fixture)


@pytest.mark.parametrize("name", ["headless.stdout", "headless.stderr"])
def test_mock_headless_refuses_existing_logs_without_clobber(headless_fixture, name):
    fixture = headless_fixture
    fixture.logs.mkdir()
    path = fixture.logs / name
    path.write_bytes(b"existing evidence")
    with pytest.raises(FileExistsError):
        verify.run_headless(fixture.bundle, fixture.profile, fixture.logs)
    assert path.read_bytes() == b"existing evidence"
    fixture.popen.assert_not_called()
    assert_headless_clean(fixture, started=False)


@pytest.mark.parametrize("character", ['"', "%", "\r", "\n", "\0"])
@pytest.mark.parametrize("target", ["bundle", "profile", "COMSPEC"])
def test_mock_headless_rejects_shell_expansion_and_quotes_before_launch(headless_fixture, monkeypatch, target, character):
    fixture = headless_fixture
    if target == "COMSPEC":
        monkeypatch.setattr(verify.os, "environ", {"COMSPEC": f"cmd{character}.exe"})
    elif target == "bundle":
        fixture.bundle = Path(f"bundle{character}")
    else:
        fixture.profile = f"profile{character}"
    with pytest.raises(verify.VerificationError, match="unsupported shell character"):
        verify.run_headless(fixture.bundle, fixture.profile, fixture.logs)
    fixture.job_factory.assert_not_called()
    fixture.popen.assert_not_called()
    assert not fixture.logs.exists()


@pytest.mark.parametrize("arch", verify.MACHINES)
def test_cli_static_json_report_is_not_native_success(tmp_path, arch):
    bundle = bundle_fixture(tmp_path / "chromix", arch)
    report_path = tmp_path / "reports/static.json"
    stdout = io.StringIO()
    with redirect_stdout(stdout), mock.patch.object(verify, "runtime_smoke") as runtime:
        code = verify.main(["--bundle", str(bundle), "--arch", arch, "--report", str(report_path)])
    assert code == 0
    runtime.assert_not_called()
    report = json.loads(stdout.getvalue())
    assert json.loads(report_path.read_text()) == report
    assert report["static"]["status"] == "passed"
    assert report["runtime"] == {"status": "not_run"}


@pytest.mark.skipif(sys.platform == "win32", reason="requires an actual non-Windows test host")
def test_cli_actual_non_windows_native_request_fails_without_launch(tmp_path):
    bundle = bundle_fixture(tmp_path / "chromix")
    report_path = tmp_path / "reports/native.json"
    stdout = io.StringIO()
    with redirect_stdout(stdout), mock.patch.object(verify.subprocess, "Popen") as popen:
        code = verify.main(["--bundle", str(bundle), "--arch", "arm64", "--native", "--report", str(report_path)])
    assert code == 1
    popen.assert_not_called()
    report = json.loads(stdout.getvalue())
    assert json.loads(report_path.read_text()) == report
    assert report["static"]["status"] == "passed"
    assert report["runtime"] == {"status": "failed"}
    assert "native smoke requires Windows" in report["error"]


@pytest.mark.parametrize("problem", ["architecture", "archive-arguments", "crc", "zip"])
def test_cli_errors_return_nonzero_and_failed_report(tmp_path, problem):
    if problem in ("crc", "zip"):
        archive, manifest, dest = archive_fixture(tmp_path)
        if problem == "crc":
            corrupt_member(archive, "chromix/chrome.exe")
        else:
            archive.write_bytes(b"not a ZIP")
        update_manifest(archive, manifest)
        arguments = ["--archive", str(archive), "--sha256-file", str(manifest), "--dest", str(dest)]
    elif problem == "archive-arguments":
        arguments = ["--archive", str(tmp_path / "chromix-win-arm64.zip")]
    else:
        arguments = ["--bundle", str(bundle_fixture(tmp_path / "chromix", "x64"))]
    report_path = tmp_path / "failure.json"
    stdout = io.StringIO()
    with redirect_stdout(stdout):
        code = verify.main([*arguments, "--arch", "arm64", "--report", str(report_path)])
    assert code == 1
    report = json.loads(stdout.getvalue())
    assert report["static"]["status"] == "failed"
    assert report["runtime"]["status"] == "not_run"
    assert report["error"]
    assert json.loads(report_path.read_text()) == report


def test_cli_default_native_version_uses_resolved_windows_override(repository, runtime_fixture, monkeypatch):
    fixture = runtime_fixture
    monkeypatch.setattr(verify, "REPO", repository)
    fixture.version.return_value = "153.0.8010.47"
    output = io.StringIO()
    with redirect_stdout(output):
        code = verify.main(["--bundle", str(fixture.bundle), "--arch", "arm64", "--native",
                            "--report", str(fixture.logs / "report.json")])
    assert code == 0, output.getvalue()
    assert json.loads(output.getvalue())["runtime"]["version"] == "153.0.8010.47"
    assert fixture.version.call_count == 2
    fixture.smoke.assert_called_once()


@pytest.mark.parametrize("version", [VERSION, "", "153", "153.0.8010.47\n"])
def test_cli_explicit_version_bypasses_pins_but_preserves_validation(runtime_fixture, monkeypatch, version):
    fixture = runtime_fixture
    resolver = mock.Mock(side_effect=AssertionError("explicit version must not resolve repository pins"))
    monkeypatch.setattr(verify, "load_pins", resolver)
    output = io.StringIO()
    with redirect_stdout(output):
        code = verify.main(["--bundle", str(fixture.bundle), "--arch", "arm64", "--native",
                            "--version", version, "--report", str(fixture.logs / "report.json")])
    resolver.assert_not_called()
    report = json.loads(output.getvalue())
    if version == VERSION:
        assert code == 0
        assert report["runtime"]["version"] == VERSION
        fixture.smoke.assert_called_once()
    else:
        assert code == 1
        assert report["runtime"]["status"] == "failed"
        assert "invalid expected Chromium version" in report["error"]
        fixture.version.assert_not_called()
        fixture.smoke.assert_not_called()


def test_cli_invalid_default_pins_fail_with_report_before_archive_extraction(repository, tmp_path, monkeypatch):
    (repository / "CHROMIUM_WINDOWS_VERSION").write_text("153.0.8010.36\n")
    monkeypatch.setattr(verify, "REPO", repository)
    archive, manifest, dest = archive_fixture(tmp_path)
    report_path = tmp_path / "failed-pins.json"
    output = io.StringIO()
    with redirect_stdout(output):
        code = verify.main(["--archive", str(archive), "--sha256-file", str(manifest), "--dest", str(dest),
                            "--arch", "arm64", "--report", str(report_path)])
    assert code == 1
    report = json.loads(output.getvalue())
    assert "CHROMIUM_WINDOWS_VERSION" in report["error"]
    assert report["static"]["status"] == "failed"
    assert report["runtime"]["status"] == "not_run"
    assert json.loads(report_path.read_text()) == report
    assert not dest.exists()
