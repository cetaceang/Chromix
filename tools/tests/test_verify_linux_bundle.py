"""Tiny ELF fixtures and fake browser processes; no compilation or downloads."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from tools import verify_linux_bundle as verify

REPO = Path(__file__).resolve().parents[2]
VERSION = "152.0.7977.82"


def elf(arch="arm64"):
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    return ident + struct.pack("<HHIQQQIHHHHHH", 3, verify.MACHINES[arch], 1,
                               0, 0, 0, 0, 64, 0, 0, 0, 0, 0)


def bundle_fixture(root, arch="arm64"):
    root.mkdir(parents=True, exist_ok=True)
    (root / "chromix").write_text('#!/bin/sh\nexec "$(dirname "$0")/chrome" "$@"\n')
    for name in verify.REQUIRED_ELF:
        (root / name).write_bytes(elf(arch))
    for name in verify.REQUIRED_EXECUTABLES:
        (root / name).chmod(0o755)
    (root / "resources.pak").write_bytes(b"resource fixture")
    return root


class BundleTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="linux bundle ' ")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bundle = bundle_fixture(self.root / "extracted/chromix")

    def test_target_headers_are_checked_without_execution_or_host_dependency(self):
        for arch in verify.MACHINES:
            with self.subTest(arch=arch):
                bundle_fixture(self.bundle, arch)
                with mock.patch.object(verify.platform, "machine", side_effect=AssertionError("host queried")), \
                        mock.patch.object(verify.subprocess, "Popen", side_effect=AssertionError("executed")):
                    result = verify.validate_bundle(str(self.bundle), arch)
                self.assertEqual(result["arch"], arch)
                self.assertEqual(result["static"]["status"], "passed")
                self.assertEqual(result["static"]["elf_files"], sorted(verify.REQUIRED_ELF))
                self.assertEqual(result["static"]["elf_count"], 3)
                self.assertEqual(result["runtime"], {"status": "not_run"})

    def test_unknown_architecture_and_non_directory_bundle_fail(self):
        with self.assertRaisesRegex(verify.VerificationError, "unsupported"):
            verify.validate_bundle(self.bundle, "riscv64")
        with self.assertRaisesRegex(verify.VerificationError, "not a directory"):
            verify.validate_bundle(self.bundle / "chrome", "arm64")
        with self.assertRaises(FileNotFoundError):
            verify.validate_bundle(self.root / "missing", "arm64")

    def test_required_executables_must_exist(self):
        for name in verify.REQUIRED_EXECUTABLES:
            with self.subTest(name=name):
                executable = self.bundle / name
                original = executable.read_bytes()
                executable.unlink()
                with self.assertRaisesRegex(verify.VerificationError, f"missing required executable: {name}"):
                    verify.validate_bundle(self.bundle, "arm64")
                executable.write_bytes(original)
                executable.chmod(0o755)

    def test_required_executables_must_be_nonempty_and_executable(self):
        for name in verify.REQUIRED_EXECUTABLES:
            for mode, data in ((0o644, elf()), (0o755, b"")):
                with self.subTest(name=name, mode=mode):
                    path = self.bundle / name
                    original = path.read_bytes()
                    path.write_bytes(data)
                    path.chmod(mode)
                    with self.assertRaisesRegex(verify.VerificationError, "empty or lacks execute"):
                        verify.validate_bundle(self.bundle, "arm64")
                    path.write_bytes(original)
                    path.chmod(0o755)

    def test_required_executables_reject_internal_and_external_symlinks(self):
        for name in verify.REQUIRED_EXECUTABLES:
            for target in (self.bundle / "real-binary", self.root / "external-binary"):
                with self.subTest(name=name, target=target):
                    path = self.bundle / name
                    original = path.read_bytes()
                    target.write_bytes(original)
                    target.chmod(0o755)
                    path.unlink()
                    path.symlink_to(target)
                    with self.assertRaisesRegex(verify.VerificationError, "regular file, not a symlink"):
                        verify.validate_bundle(self.bundle, "arm64")
                    path.unlink()
                    path.write_bytes(original)
                    path.chmod(0o755)
                    target.unlink()

    def test_required_directory_and_fifo_are_rejected_without_opening(self):
        path = self.bundle / "chrome"
        path.unlink()
        path.mkdir()
        with self.assertRaisesRegex(verify.VerificationError, "regular file"):
            verify.validate_bundle(self.bundle, "arm64")
        path.rmdir()
        os.mkfifo(path)
        with self.assertRaisesRegex(verify.VerificationError, "regular file"):
            verify.validate_bundle(self.bundle, "arm64")

    def test_browser_helpers_must_be_elf_not_scripts_or_text(self):
        for name in verify.REQUIRED_ELF:
            with self.subTest(name=name):
                path = self.bundle / name
                path.write_bytes(b"#!/bin/sh\nexit 0\n")
                with self.assertRaisesRegex(verify.VerificationError, f"not ELF: {name}"):
                    verify.validate_bundle(self.bundle, "arm64")
                path.write_bytes(elf())

    def test_full_elf64_header_is_required_even_for_optional_libraries(self):
        for path in (self.bundle / "chrome", self.bundle / "liboptional.so"):
            for length in (4, 16, 20, 63):
                with self.subTest(path=path, length=length):
                    path.write_bytes(elf()[:length])
                    with self.assertRaisesRegex(verify.VerificationError, "at least 64 bytes"):
                        verify.validate_bundle(self.bundle, "arm64")
            path.write_bytes(elf())
        self.assertEqual(verify.validate_bundle(self.bundle, "arm64")["static"]["elf_count"], 4)

    def test_invalid_class_byte_order_version_and_header_size_fail(self):
        for offset, value, message in ((4, 1, "ELF64 little-endian"), (5, 2, "ELF64 little-endian"),
                                       (6, 0, "version or size"), (20, 0, "version or size"),
                                       (52, 52, "version or size")):
            with self.subTest(offset=offset):
                header = bytearray(elf())
                header[offset] = value
                (self.bundle / "chrome").write_bytes(header)
                with self.assertRaisesRegex(verify.VerificationError, message):
                    verify.validate_bundle(self.bundle, "arm64")

    def test_wrong_architecture_in_any_elf_including_optional_nested_files_fails(self):
        for arch, other in (("arm64", "x64"), ("x64", "arm64")):
            for name in (*verify.REQUIRED_EXECUTABLES, "lib/libc++.so", "libEGL.so", ".hidden/blob"):
                with self.subTest(arch=arch, name=name):
                    bundle = bundle_fixture(self.root / arch / name.replace("/", "_") / "chromix", arch)
                    path = bundle / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(elf(other))
                    with self.assertRaisesRegex(verify.VerificationError, "wrong ELF architecture"):
                        verify.validate_bundle(bundle, arch)

    def test_confined_library_and_directory_links_are_allowed_without_following_loops(self):
        library = self.bundle / "lib/libEGL.so.1"
        library.parent.mkdir()
        library.write_bytes(elf())
        (self.bundle / "libEGL.so").symlink_to("lib/libEGL.so.1")
        (self.bundle / "libraries").symlink_to("lib", target_is_directory=True)
        (self.bundle / "lib/root").symlink_to("..", target_is_directory=True)
        result = verify.validate_bundle(self.bundle, "arm64")
        self.assertEqual(result["static"]["elf_count"], 4)
        self.assertIn("lib/libEGL.so.1", result["static"]["elf_files"])
        library.write_bytes(elf("x64"))
        with self.assertRaisesRegex(verify.VerificationError, "wrong ELF architecture"):
            verify.validate_bundle(self.bundle, "arm64")

    def test_external_file_and_directory_links_are_rejected(self):
        outside = self.root / "outside.so"
        outside.write_bytes(elf())
        for target in (outside, self.root):
            with self.subTest(target=target):
                link = self.bundle / "link"
                link.symlink_to(target)
                with self.assertRaisesRegex(verify.VerificationError, "escapes bundle"):
                    verify.validate_bundle(self.bundle, "arm64")
                link.unlink()

    def test_broken_and_cyclic_links_are_rejected(self):
        link = self.bundle / "link"
        for target in ("missing", "link"):
            with self.subTest(target=target):
                link.symlink_to(target)
                with self.assertRaisesRegex(verify.VerificationError, "broken or cyclic"):
                    verify.validate_bundle(self.bundle, "arm64")
                link.unlink()

    def test_bundle_root_symlink_is_rejected(self):
        link = self.root / "linked-bundle"
        link.symlink_to(self.bundle, target_is_directory=True)
        with self.assertRaisesRegex(verify.VerificationError, "directory must not be a symlink"):
            verify.validate_bundle(link, "arm64")

    def test_optional_special_file_and_link_to_it_are_rejected(self):
        fifo = self.bundle / "pipe"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(verify.VerificationError, "special file"):
            verify.validate_bundle(self.bundle, "arm64")
        (self.bundle / "a-link").symlink_to("pipe")
        with self.assertRaisesRegex(verify.VerificationError, "targets a special file"):
            verify.validate_bundle(self.bundle, "arm64")

    def test_scan_errors_are_not_silently_skipped(self):
        def failed_walk(root, *, followlinks, onerror):
            onerror(PermissionError("unreadable bundle directory"))

        with mock.patch.object(verify.os, "walk", side_effect=failed_walk):
            with self.assertRaisesRegex(PermissionError, "unreadable"):
                verify.validate_bundle(self.bundle, "arm64")

    def test_cli_static_outputs_json_without_running_browser(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout), mock.patch.object(verify.subprocess, "Popen") as popen, \
                mock.patch.object(verify.platform, "machine", return_value="x86_64"):
            status = verify.main(["--bundle-dir", str(self.bundle), "--arch", "arm64"])
        self.assertEqual(status, 0)
        popen.assert_not_called()
        report = json.loads(stdout.getvalue())
        self.assertEqual(report["static"]["status"], "passed")
        self.assertEqual(report["runtime"]["status"], "not_run")

    def test_cli_failure_is_nonzero_without_success_json(self):
        (self.bundle / "chrome").write_bytes(elf("x64"))
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = verify.main(["--bundle-dir", str(self.bundle), "--arch", "arm64"])
        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("wrong ELF architecture", stderr.getvalue())


class FakeProcess:
    def __init__(self, stdout=b"", stderr=b"", returncode=0, wait_failures=0):
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode = returncode
        self.pid = 4242
        self.wait_failures = wait_failures
        self.waits = []

    def wait(self, timeout=None):
        if timeout is None:
            raise AssertionError("unbounded process wait")
        self.waits.append(timeout)
        if self.wait_failures:
            self.wait_failures -= 1
            raise subprocess.TimeoutExpired("fake-browser", timeout)
        return self.returncode


class FakeSelector:
    def __init__(self):
        self.entries = {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.entries.clear()

    def register(self, stream, events, data):
        self.entries[stream] = SimpleNamespace(fileobj=stream, data=data)

    def unregister(self, stream):
        del self.entries[stream]

    def get_map(self):
        return self.entries

    def select(self, timeout=None):
        if timeout is None or timeout <= 0:
            raise AssertionError("unbounded or expired select")
        return [(key, verify.selectors.EVENT_READ) for key in self.entries.values()]


class RuntimeTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="linux runtime ' ")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bundle = bundle_fixture(self.root / "extracted/chromix")
        self.profiles = []
        real_temporary_directory = tempfile.TemporaryDirectory

        def profile_directory(**kwargs):
            directory = real_temporary_directory(dir=self.root, **kwargs)
            self.profiles.append(Path(directory.name))
            return directory

        self.patch(verify.tempfile, "TemporaryDirectory", side_effect=profile_directory)
        self.patch(verify.sys, "platform", "linux")
        self.patch(verify.platform, "machine", return_value="aarch64")
        self.patch(verify.selectors, "DefaultSelector", FakeSelector)
        self.killpg = self.patch(verify.os, "killpg")
        self.processes = []
        self.popen = self.patch(verify.subprocess, "Popen", side_effect=self.start_browser)
        self.add_process(f"Chromium {VERSION}\n".encode())
        self.add_process(b"<html><body>" + verify.DOM_MARKER.encode() + b"</body></html>")

    def patch(self, target, name, *args, **kwargs):
        patcher = mock.patch.object(target, name, *args, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def add_process(self, stdout=b"", stderr=b"", returncode=0, wait_failures=0):
        process = FakeProcess(stdout, stderr, returncode, wait_failures)
        self.processes.append(process)
        return process

    def start_browser(self, command, **kwargs):
        index = self.popen.call_count - 1
        if "--dump-dom" in command:
            profile = Path(next(arg.split("=", 1)[1] for arg in command if arg.startswith("--user-data-dir=")))
            self.assertTrue(profile.is_dir())
            (profile / "fixture-cache").write_bytes(b"temporary browser data")
        return self.processes[index]

    def assert_clean(self):
        self.assertTrue(self.profiles)
        self.assertTrue(all(not path.exists() for path in self.profiles))
        for process in self.processes[:self.popen.call_count]:
            self.assertTrue(process.stdout.closed)
            self.assertTrue(process.stderr.closed)
            self.assertTrue(process.waits)
            self.assertTrue(all(0 <= timeout <= verify.DOM_TIMEOUT for timeout in process.waits))

    def smoke(self):
        return verify.runtime_smoke(self.bundle, "arm64", VERSION)

    def test_native_runtime_uses_extracted_launcher_and_ci_flags(self):
        result = self.smoke()
        self.assertEqual(result["static"]["status"], "passed")
        self.assertEqual(result["runtime"]["status"], "passed")
        self.assertEqual(result["runtime"]["chromium_version"], VERSION)
        self.assertEqual(self.popen.call_count, 2)
        version, dom = self.popen.call_args_list
        self.assertEqual(version.args[0], [str(self.bundle / "chromix"), "--version"])
        arguments = ["--headless", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
                     f"--user-data-dir={self.profiles[0]}", "--dump-dom", verify.SMOKE_URL]
        self.assertEqual(dom.args[0], [str(self.bundle / "chromix"), *arguments])
        source = (REPO / "build/posix/ci-stage.sh").read_text()
        for flag in (*arguments[:4], "--dump-dom", verify.SMOKE_URL):
            self.assertIn(flag, source)
        self.assertEqual((verify.VERSION_TIMEOUT, verify.DOM_TIMEOUT), (30, 60))
        for call in (version, dom):
            self.assertEqual(call.kwargs["cwd"], self.bundle)
            self.assertTrue(call.kwargs["start_new_session"])
            self.assertEqual(call.kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(call.kwargs["stdout"], subprocess.PIPE)
            self.assertEqual(call.kwargs["stderr"], subprocess.PIPE)
            self.assertEqual(call.kwargs["bufsize"], 0)
            self.assertNotIn("--no-sandbox", call.args[0])
            self.assertNotIn("--disable-setuid-sandbox", call.args[0])
            self.assertNotIn("shell", call.kwargs)
        self.assertEqual(self.killpg.call_args_list, [mock.call(4242, signal.SIGKILL)] * 2)
        self.assert_clean()

    def test_native_x64_and_arm64_machine_aliases(self):
        for arch, machine in (("x64", "x86_64"), ("x64", "AMD64"), ("arm64", "aarch64"), ("arm64", "arm64")):
            with self.subTest(arch=arch, machine=machine):
                bundle_fixture(self.bundle, arch)
                with mock.patch.object(verify.platform, "machine", return_value=machine), \
                        mock.patch.object(verify, "_run_browser", side_effect=[
                            subprocess.CompletedProcess([], 0, f"Chromium {VERSION}", ""),
                            subprocess.CompletedProcess([], 0, verify.DOM_MARKER, "")]):
                    result = verify.runtime_smoke(self.bundle, arch, VERSION)
                self.assertEqual(result["runtime"]["host_arch"], arch)

    def test_runtime_rejects_foreign_non_linux_and_unknown_hosts(self):
        for system, machine in (("linux", "x86_64"), ("darwin", "arm64"), ("win32", "ARM64"),
                                ("linux", "armv7l"), ("linux", "unknown")):
            with self.subTest(system=system, machine=machine):
                with mock.patch.object(verify.sys, "platform", system), \
                        mock.patch.object(verify.platform, "machine", return_value=machine):
                    with self.assertRaisesRegex(verify.VerificationError, "native Linux arm64 host"):
                        self.smoke()
        self.popen.assert_not_called()
        self.assertFalse(self.profiles)

    def test_runtime_always_validates_optional_elf_before_execution(self):
        (self.bundle / "optional.so").write_bytes(elf("x64"))
        with self.assertRaisesRegex(verify.VerificationError, "wrong ELF architecture"):
            self.smoke()
        self.popen.assert_not_called()

    def test_cli_reads_repository_version_by_default_and_allows_override(self):
        pinned = verify.load_pins(REPO, "linux")["ChromiumVersion"]
        for version, extra in ((pinned, []), ("100.1.2.3", ["--chromium-version", "100.1.2.3"])):
            with self.subTest(version=version):
                self.popen.reset_mock()
                self.processes.clear()
                self.add_process(f"Chromium {version}\n".encode())
                self.add_process(verify.DOM_MARKER.encode())
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    status = verify.main(["--bundle-dir", str(self.bundle), "--arch", "arm64", "--runtime", *extra])
                self.assertEqual(status, 0)
                report = json.loads(stdout.getvalue())
                self.assertEqual(report["runtime"]["chromium_version"], version)
                self.assertEqual(report["runtime"]["status"], "passed")
                self.assert_clean()

    def test_linux_default_uses_override_and_rejects_partial_pins_before_launch(self):
        self.patch(verify, "REPO", self.root)
        (self.root / "CHROMIUM_VERSION").write_text("152.0.7977.82\n")
        (self.root / "CHROMIUM_LINUX_VERSION").write_text("153.0.8010.36\n")
        (self.root / "build").mkdir()
        pins = self.root / "build/ungoogled-revisions.psd1"
        pins.write_text('@{\n'
                        '  ChromiumVersion = "152.0.7977.82"\n'
                        '  UngoogledVersion = "152.0.7977.82-1"\n'
                        f'  UngoogledCommit = "{"a" * 40}"\n'
                        '  LinuxChromiumVersion = "153.0.8010.36"\n'
                        '  LinuxUngoogledVersion = "153.0.8010.36-1"\n'
                        f'  LinuxUngoogledCommit = "{"b" * 40}"\n'
                        '  UngoogledLinuxVersion = "153.0.8010.36-1"\n'
                        f'  UngoogledLinuxCommit = "{"c" * 40}"\n'
                        '}\n')
        self.processes[0] = FakeProcess(b"Chromium 153.0.8010.36\n")
        result = verify.runtime_smoke(self.bundle, "arm64")
        self.assertEqual(result["runtime"]["chromium_version"], "153.0.8010.36")
        self.assert_clean()
        self.popen.reset_mock()
        (self.root / "CHROMIUM_LINUX_VERSION").unlink()
        with self.assertRaisesRegex(ValueError, "must all be present"):
            verify.runtime_smoke(self.bundle, "arm64")
        self.popen.assert_not_called()

    def test_invalid_expected_version_does_not_launch_browser(self):
        for version in ("", "152", "152.0.7977.82\nanything"):
            with self.subTest(version=version):
                with self.assertRaisesRegex(verify.VerificationError, "invalid Chromium version"):
                    verify.runtime_smoke(self.bundle, "arm64", version)
        self.popen.assert_not_called()

    def test_version_mismatch_and_stderr_only_version_fail(self):
        for stdout, stderr in ((b"Chromium 151.0.0.1", b""), (f"Chromium {VERSION}0".encode(), b""),
                               (b"", f"Chromium {VERSION}".encode())):
            with self.subTest(stdout=stdout):
                self.popen.reset_mock()
                self.processes[0] = FakeProcess(stdout, stderr)
                with self.assertRaisesRegex(verify.VerificationError, "--version did not report Chromium"):
                    self.smoke()
                self.assertEqual(self.popen.call_count, 1)
                self.assert_clean()

    def test_missing_dom_marker_fails_even_if_stderr_contains_it(self):
        self.processes[1] = FakeProcess(b"<html></html>", verify.DOM_MARKER.encode())
        with self.assertRaisesRegex(verify.VerificationError, "missing the smoke page marker"):
            self.smoke()
        self.assert_clean()

    def test_version_and_dom_nonzero_exit_fail_despite_expected_output(self):
        for index, label in ((0, "launcher --version"), (1, "headless --dump-dom")):
            with self.subTest(label=label):
                self.popen.reset_mock()
                self.processes = [FakeProcess(f"Chromium {VERSION}".encode()), FakeProcess(verify.DOM_MARKER.encode())]
                self.processes[index].returncode = 7
                self.processes[index].stderr = io.BytesIO(b"sandbox startup failed")
                with self.assertRaisesRegex(verify.VerificationError, f"{label} exited with status 7") as raised:
                    self.smoke()
                self.assertIn("sandbox startup failed", str(raised.exception))
                self.assertEqual(self.popen.call_count, index + 1)
                self.assert_clean()

    def test_start_failure_cleans_profile_and_is_actionable(self):
        self.popen.side_effect = OSError("permission denied")
        with self.assertRaisesRegex(verify.VerificationError, "launcher --version could not start: permission denied"):
            self.smoke()
        self.assertTrue(all(not path.exists() for path in self.profiles))
        self.killpg.assert_not_called()

    def test_timeout_with_open_pipes_kills_group_and_cleans_profile(self):
        with mock.patch.object(verify.time, "monotonic", side_effect=[0, 31]):
            with self.assertRaisesRegex(verify.VerificationError, "launcher --version timed out after 30s"):
                self.smoke()
        self.killpg.assert_called_once_with(4242, signal.SIGKILL)
        self.assertEqual(self.processes[0].waits, [verify.KILL_TIMEOUT])
        self.assert_clean()

    def test_timeout_after_pipes_close_still_has_bounded_group_cleanup(self):
        self.processes[0].wait_failures = 1
        with self.assertRaisesRegex(verify.VerificationError, "launcher --version timed out after 30s"):
            self.smoke()
        self.killpg.assert_called_once_with(4242, signal.SIGKILL)
        self.assertEqual(self.processes[0].waits[-1], verify.KILL_TIMEOUT)
        self.assert_clean()

    def test_dom_timeout_cleans_written_profile_and_kills_descendants(self):
        self.processes[1].wait_failures = 1
        with self.assertRaisesRegex(verify.VerificationError, "headless --dump-dom timed out after 60s"):
            self.smoke()
        self.assertEqual(self.killpg.call_count, 2)
        self.assert_clean()

    def test_output_capture_is_bounded_across_stdout_and_stderr(self):
        self.processes[0] = FakeProcess(b"a" * 100000, b"b" * 100000)
        with self.assertRaisesRegex(verify.VerificationError, "output limit") as raised:
            self.smoke()
        self.assertLess(len(str(raised.exception)), 4200)
        self.killpg.assert_called_once_with(4242, signal.SIGKILL)
        self.assert_clean()

    def test_pipe_read_failure_kills_group_and_closes_streams(self):
        self.processes[0].stdout = mock.Mock(wraps=io.BytesIO())
        self.processes[0].stdout.read.side_effect = OSError("pipe read failed")
        with self.assertRaisesRegex(verify.VerificationError, "launcher --version failed: pipe read failed"):
            self.smoke()
        self.processes[0].stdout.close.assert_called_once_with()
        self.killpg.assert_called_once_with(4242, signal.SIGKILL)
        self.assertTrue(all(not path.exists() for path in self.profiles))

    def test_missing_process_group_is_harmless(self):
        self.killpg.side_effect = ProcessLookupError()
        self.assertEqual(self.smoke()["runtime"]["status"], "passed")
        self.assert_clean()

    def test_unreapable_child_and_group_kill_failure_remain_finite_errors(self):
        self.processes[0].wait_failures = 2
        with self.assertRaisesRegex(verify.VerificationError, "did not exit within 5s"):
            self.smoke()
        self.assertEqual(len(self.processes[0].waits), 2)
        self.assert_clean()
        self.popen.reset_mock()
        self.processes[0] = FakeProcess(f"Chromium {VERSION}".encode())
        self.killpg.side_effect = PermissionError("kill denied")
        with self.assertRaisesRegex(verify.VerificationError, "could not kill browser process group"):
            self.smoke()
        self.assert_clean()

    def test_cli_runtime_failure_never_emits_passed_json(self):
        self.processes[0].returncode = 1
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = verify.main(["--bundle-dir", str(self.bundle), "--arch", "arm64", "--runtime",
                                  "--chromium-version", VERSION])
        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("launcher --version exited with status 1", stderr.getvalue())
        self.assert_clean()


if __name__ == "__main__":
    unittest.main()
