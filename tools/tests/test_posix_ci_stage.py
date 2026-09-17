"""Fail-closed CI gates using tiny cache trees, never downloads or compiles."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

from tools import restore_upstream_cache as restore


REPO = Path(__file__).resolve().parents[2]
BASH32 = Path.home() / ".local/bash-3.2-for-ci/bash"


class FullCacheFixture:
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="required cache ")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / "repo"
        self.work = self.root / "work"
        self.cache = self.root / "chromix-upstream"
        self.calls = self.root / "calls"
        self.work.mkdir()
        self.env = {**os.environ, "CALL_LOG": str(self.calls), "RUNNER_TEMP": str(self.root),
                    "CHROMIX_USE_UPSTREAM_CACHE": "1", "FETCH_RC": "0",
                    "PYTHONDONTWRITEBYTECODE": "1"}

    def put(self, path, content, executable=False):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
        if executable:
            path.chmod(0o755)

    def seed(self, platform="linux", arch="x64", reason=None):
        identity, pin, manifest = restore.identities(getattr(self, "pin_repo", REPO), platform, arch)
        donor = self.cache / "tree" / pin["source_roots"][0]
        result = {
            "owner": restore.fetcher.OWNER, "status": "miss" if reason else "hit",
            "source": None if reason else str(donor), "destination": str(self.cache),
            "platform": platform, "arch": arch, "manifest": manifest,
            "extraction_scope": restore.fetcher.SOURCE_SCOPE,
            "skipped_external_symlinks": 0, "external_symlink_paths": [],
            "reason": reason,
        }
        self.put(self.cache / "result.json", json.dumps(result))
        if reason:
            return
        version = "\n".join(f"{key}={value}" for key, value in zip(
            ("MAJOR", "MINOR", "BUILD", "PATCH"), identity["chromium_version"].split(".")))
        for relative, value in {
            "chrome/VERSION": version, "BUILD.gn": 'group("fixture") {}\n',
            "out/Default/args.gn": f'target_cpu = "{arch}"\n',
            "out/Default/build.ninja": "# tiny fixture\n",
            "out/Default/.ninja_log": "# ninja log v5\n",
            "out/Default/.ninja_deps": b"# ninjadeps\n\x04\x00\x00\x00",
            "out/Default/obj/retained.o": b"tiny cached object",
        }.items():
            self.put(donor / relative, value)

    def called(self):
        return self.calls.read_text().splitlines() if self.calls.exists() else []


class PosixRequiredCacheTest(FullCacheFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.env.pop("CHROMIX_CACHE_TIMEOUT_SECONDS", None)
        self.env.pop("CHROMIX_RESERVE_MINUTES", None)
        self.stage = self.repo / "build/posix/ci-stage.sh"
        self.put(self.stage, (REPO / "build/posix/ci-stage.sh").read_bytes())
        # The stage now delegates snapshot extraction to the shared helper;
        # mirror the production tool layout in this isolated fixture.
        for relative in ("build/posix/restore-snapshot.sh",
                         "tools/restore_posix_snapshot.py",
                         "tools/snapshot_volumes.py",
                         "tools/download_posix_snapshot.py"):
            self.put(self.repo / relative, (REPO / relative).read_bytes())
        self.put(self.repo / "build/posix/fetch-upstream-cache.sh",
                 '#!/bin/sh\nprintf "fetch\\n" >> "$CALL_LOG"\n'
                 'printf "%s\\n" "$CHROMIX_CACHE_TIMEOUT_SECONDS" > "$CALL_LOG.timeout"\n'
                 'exit "$FETCH_RC"\n', True)
        self.put(self.repo / "tools/restore_upstream_cache.py",
                 'import os, runpy, sys\n'
                 'with open(os.environ["CALL_LOG"], "a") as log:\n'
                 '    log.write(sys.argv[sys.argv.index("--phase") + 1] + "\\n")\n'
                 f'sys.path.insert(0, {str(REPO / "tools")!r})\n'
                 f'runpy.run_path({str(REPO / "tools/restore_upstream_cache.py")!r}, run_name="__main__")\n')
        self.put(self.repo / "build/prepare-ungoogled.sh",
                 '#!/bin/sh\nprintf "prepare\\n" >> "$CALL_LOG"\n'
                 'mkdir -p "$1/src"\ntouch "$1/src/.chromix-source-ready"\n', True)
        for builder in ("build/build.sh", "build/macos/build.sh"):
            self.put(self.repo / builder,
                     '#!/bin/sh\nprintf "ninja\\n" >> "$CALL_LOG"\nexit 124\n', True)
        self.put(self.repo / "build/posix/ci-parts.sh",
                 '#!/bin/sh\nprintf "snapshot\\n" >> "$CALL_LOG"\n', True)

    def run_stage(self, platform="linux", arch="x64", stage=1, snapshot=None,
                  minutes=300, enabled=True, shell=None):
        args = [str(shell or shutil.which("bash")), str(self.stage),
                "--platform", platform, "--arch", arch, "--workdir", str(self.work),
                "--stage-index", str(stage), "--deadline-epoch", str(int(time.time()) + minutes * 60)]
        if snapshot:
            args += ["--from-snapshot", str(snapshot)]
        return subprocess.run(args, capture_output=True, text=True, timeout=15,
                              env={**self.env, "CHROMIX_USE_UPSTREAM_CACHE": str(int(enabled)),
                                   "GITHUB_OUTPUT": str(self.root / "outputs")})

    def test_miss_disk_shortage_and_timeout_never_prepare_or_snapshot(self):
        for reason in ("unavailable", "insufficient_disk_space", "cache_timeout", "network_unavailable"):
            with self.subTest(reason=reason):
                self.seed(reason=reason)
                result = self.run_stage()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f"required fetch failed: {reason}", result.stderr)
                self.assertNotIn("restore receipt missing", result.stderr)
                self.assertEqual(json.loads((self.cache / "result.json").read_text())["reason"], reason)
                self.assertEqual(self.called(), ["fetch"])
                self.assertFalse((self.work / "src").exists())
                self.calls.unlink()

    def test_miss_summary_excludes_untrusted_strings_and_reports_safe_progress(self):
        self.seed(reason="network_unavailable")
        receipt = self.cache / "result.json"
        original = json.loads(receipt.read_text())
        for reason in ("network_unavailable", "https://blob.example/?sig=SECRET", ["SECRET"]):
            with self.subTest(reason=reason):
                value = {**original, "reason": reason, "download_partial_bytes": 2228224000,
                         "download_expected_bytes": 12291676644, "download_timeout_seconds": 2700,
                         "duration_seconds": 546.872, "token": "SECRET",
                         "phase": "SECRET", "download_attempts": [{"error": "SECRET"}]}
                receipt.write_text(json.dumps(value))
                result = self.run_stage()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("download_partial_bytes=2228224000", result.stderr)
                self.assertIn("duration_seconds=546.872", result.stderr)
                self.assertNotIn("SECRET", result.stdout + result.stderr)
                self.assertEqual(self.called(), ["fetch"])
                self.calls.unlink()

    def test_invalid_fetch_receipt_stops_before_restore(self):
        for problem in ("missing", "malformed", "array", "owner", "destination", "platform",
                        "arch", "symlink", "fifo", "oversized"):
            with self.subTest(problem=problem):
                self.seed(reason="network_unavailable")
                receipt = self.cache / "result.json"
                original = json.loads(receipt.read_text())
                if problem in ("owner", "destination", "platform", "arch"):
                    receipt.write_text(json.dumps({**original, problem: "wrong"}))
                elif problem in ("malformed", "array", "oversized"):
                    receipt.write_text({"malformed": "{", "array": "[]", "oversized": " " * (1024 * 1024 + 1)}[problem])
                else:
                    receipt.unlink()
                    if problem == "symlink":
                        outside = self.root / "outside.json"
                        outside.write_text(json.dumps(original))
                        receipt.symlink_to(outside)
                    elif problem == "fifo":
                        os.mkfifo(receipt)
                result = self.run_stage()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("missing or invalid fetch receipt", result.stderr)
                self.assertEqual(self.called(), ["fetch"])
                self.assertFalse((self.work / "src").exists())
                self.calls.unlink()
                if receipt.exists() or receipt.is_symlink():
                    receipt.unlink()

    def test_fetch_hit_uses_fetcher_destination_normalization(self):
        self.seed()
        (self.root / "existing").mkdir()
        self.env["RUNNER_TEMP"] = str(self.root / "existing" / "..")
        result = self.run_stage()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.called(), ["fetch", "restore", "verify", "prepare", "ninja", "snapshot"])

    def test_fetch_miss_never_bypasses_restore_identity_verification(self):
        self.seed()
        receipt = self.cache / "result.json"
        value = json.loads(receipt.read_text())
        value["manifest"]["sha256"] = "0" * 64
        receipt.write_text(json.dumps(value))
        result = self.run_stage()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.called(), ["fetch", "restore"])
        self.assertFalse((self.work / "src/.chromix-upstream-restored.json").exists())

    def test_insufficient_budget_fails_without_fetch_or_handoff(self):
        result = self.run_stage(minutes=60)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("insufficient stage budget", result.stderr)
        self.assertEqual(self.called(), [])

    def test_timeout_and_reserve_determine_admission_with_ceil_minutes(self):
        binaries = self.root / "bin"
        self.put(binaries / "date", '#!/bin/sh\nprintf "1700000000\\n"\n', True)
        self.env["PATH"] = str(binaries) + os.pathsep + os.environ["PATH"]
        self.env["FETCH_RC"] = "7"
        for shell in (shutil.which("bash"), *([BASH32] if BASH32.is_file() else [])):
            for timeout, reserve, required in ((None, 45, 135), ("1200", 45, 95),
                                               ("3601", 45, 136), ("61", 15, 47)):
                for minutes in (required - 1, required):
                    with self.subTest(shell=str(shell), timeout=timeout, reserve=reserve, minutes=minutes):
                        if timeout is None:
                            self.env.pop("CHROMIX_CACHE_TIMEOUT_SECONDS", None)
                        else:
                            self.env["CHROMIX_CACHE_TIMEOUT_SECONDS"] = timeout
                        result = subprocess.run(
                            [str(shell), str(self.stage), "--platform", "linux", "--arch", "x64",
                             "--workdir", str(self.work), "--reserve-minutes", str(reserve),
                             "--deadline-epoch", str(1700000000 + minutes * 60)],
                            env=self.env, capture_output=True, text=True, timeout=15)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(self.called(), ["fetch"] if minutes == required else [])
                        if minutes < required:
                            self.assertIn(f"need {required}m", result.stderr)
                        else:
                            self.assertEqual(self.calls.with_suffix(".timeout").read_text().strip(), timeout or "3600")
                        if self.calls.exists():
                            self.calls.unlink()

    def test_invalid_timeout_rejected_before_fetch(self):
        for timeout in ("0", "", "-1", "1.5", "abc", "01"):
            with self.subTest(timeout=timeout):
                self.env["CHROMIX_CACHE_TIMEOUT_SECONDS"] = timeout
                result = self.run_stage()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("CHROMIX_CACHE_TIMEOUT_SECONDS must be a positive integer", result.stderr)
                self.assertEqual(self.called(), [])

    def test_fetch_failure_and_timeout_exit_never_prepare(self):
        for rc in (7, 124):
            with self.subTest(rc=rc):
                self.env["FETCH_RC"] = str(rc)
                result = self.run_stage()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.called(), ["fetch"])
                self.calls.unlink()

    def test_fresh_explicit_no_cache_keeps_cold_path(self):
        result = self.run_stage(enabled=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.called(), ["prepare", "ninja", "snapshot"])

    def test_ready_cold_workdir_cannot_satisfy_required_mode(self):
        self.put(self.work / "src/.chromix-source-ready", "old cold snapshot")
        result = self.run_stage(stage=2)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("restore receipt missing", result.stderr)
        self.assertEqual(self.called(), [])

    def test_four_targets_restore_and_verify_before_prepare(self):
        for platform, arch in (("linux", "x64"), ("linux", "arm64"),
                               ("macos", "x64"), ("macos", "arm64")):
            with self.subTest(platform=platform, arch=arch):
                self.seed(platform, arch)
                result = self.run_stage(platform, arch)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.called(), ["fetch", "restore", "verify", "prepare", "ninja", "snapshot"])
                self.assertEqual((self.work / "src/out/Default/obj/retained.o").read_bytes(), b"tiny cached object")
                self.assertFalse((self.work / "src/out/Chromix").exists())
                shutil.rmtree(self.work / "src")
                self.calls.unlink()

    @unittest.skipUnless(shutil.which("zstd"), "zstd required")
    def test_real_snapshot_requires_valid_receipt_even_with_low_budget(self):
        self.seed()
        self.assertEqual(restore.restore(self.work, "linux", "x64", self.cache)["status"], "hit")
        receipt = self.work / "src" / restore.MARKER
        original = receipt.read_bytes()
        for state in ("valid", "missing", "invalid"):
            with self.subTest(state=state):
                self.put(receipt, original if state == "valid" else "{}")
                if state == "missing":
                    receipt.unlink()
                snapshot = self.root / "snapshot"
                packed = subprocess.run(["bash", str(REPO / "build/posix/ci-parts.sh"),
                                         str(self.work), str(snapshot)], capture_output=True, text=True, timeout=15)
                self.assertEqual(packed.returncode, 0, packed.stderr)
                shutil.rmtree(self.work / "src")
                result = self.run_stage(stage=2, snapshot=snapshot, minutes=60)
                if state == "valid":
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(self.called(), ["verify", "snapshot"])
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(self.called(), [] if state == "missing" else ["verify"])
                if self.calls.exists():
                    self.calls.unlink()

    @unittest.skipUnless(BASH32.is_file(), "bash 3.2 required")
    def test_macos_bash32_budget_fails_closed(self):
        result = self.run_stage("macos", "arm64", minutes=60, shell=BASH32)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("insufficient stage budget", result.stderr)
        self.assertEqual(self.called(), [])


if __name__ == "__main__":
    unittest.main()
