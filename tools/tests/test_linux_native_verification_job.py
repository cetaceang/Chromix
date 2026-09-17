"""Exercise the native ARM workflow's bundle gate with tiny same-run ZIPs."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile

import yaml

REPO = Path(__file__).resolve().parents[2]


class LinuxNativeVerificationJobTest(unittest.TestCase):
    def run_gate(self, *, checksum="valid", member=None, runtime_exit=0, sandbox_exit=0, missing=False):
        with tempfile.TemporaryDirectory(prefix="native bundle ") as directory:
            root = Path(directory)
            workspace, temp = root / "repo", root / "temp"
            bundle = temp / "chromix-native-bundle"
            bundle.mkdir(parents=True)
            extractor = workspace / "sdk/python/chromix/_binary.py"
            extractor.parent.mkdir(parents=True)
            shutil.copy2(REPO / "sdk/python/chromix/_binary.py", extractor)
            script = workspace / "build/linux/prepare-ci-sandbox.sh"
            script.parent.mkdir(parents=True)
            script.write_text('#!/bin/sh\nprintf "sandbox\\n" >> "$CALL_LOG"\n'
                              'test -x "$1" || exit 90\n' + f'exit {sandbox_exit}\n')
            verifier = workspace / "tools/verify_linux_bundle.py"
            verifier.parent.mkdir()
            verifier.write_text('import os, pathlib, sys\n'
                                'assert sys.argv[1] == "--bundle-dir"\n'
                                'assert sys.argv[3:] == ["--arch", "arm64", "--runtime", "--chromium-version", "153.0.8010.36"]\n'
                                'assert os.access(pathlib.Path(sys.argv[2]) / "chrome", os.X_OK)\n'
                                'with open(os.environ["CALL_LOG"], "a") as stream: stream.write("runtime\\n")\n'
                                f'sys.exit({runtime_exit})\n')
            asset = bundle / "chromix-linux-arm64.zip"
            if not missing:
                with zipfile.ZipFile(asset, "w") as archive:
                    for name in ("chromix/chromix", "chromix/chrome"):
                        entry = zipfile.ZipInfo(name)
                        entry.create_system = 3
                        entry.external_attr = 0o100755 << 16
                        archive.writestr(entry, "fixture")
                    if member:
                        archive.writestr(member, "rejected")
                digest = hashlib.sha256(asset.read_bytes()).hexdigest()
                if checksum == "wrong":
                    digest = "0" * 64
                entry = f"{digest}  {asset.name}\n"
                (bundle / "SHA256SUMS").write_text(entry * (2 if checksum == "duplicate" else 1))
            workflow = yaml.safe_load((REPO / ".github/workflows/build-posix-github.yml").read_text())
            steps = workflow["jobs"]["verify-linux-arm64"]["steps"]
            command = next(step["run"] for step in steps if step.get("name") == "Verify checksum and native launcher")
            log = root / "calls"
            env = dict(os.environ, RUNNER_TEMP=str(temp), GITHUB_WORKSPACE=str(workspace), CALL_LOG=str(log),
                       CHROMIUM_VERSION="153.0.8010.36")
            result = subprocess.run(["bash", "-c", command], env=env, text=True, capture_output=True, timeout=15)
            calls = log.read_text().splitlines() if log.exists() else []
            extracted = (temp / "chromix-native-smoke/chromix/chrome").exists()
            return result, calls, extracted

    def test_valid_bundle_preserves_modes_and_runs_sandbox_before_runtime(self):
        result, calls, extracted = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(calls, ["sandbox", "runtime"])
        self.assertTrue(extracted)

    def test_missing_or_bad_checksum_stops_before_extraction(self):
        for options in ({"missing": True}, {"checksum": "wrong"}, {"checksum": "duplicate"}):
            with self.subTest(options=options):
                result, calls, extracted = self.run_gate(**options)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, [])
                self.assertFalse(extracted)

    def test_noncanonical_members_stop_before_any_extraction(self):
        for member in ("chromix/../escape", "outside", "/absolute"):
            with self.subTest(member=member):
                result, calls, extracted = self.run_gate(member=member)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Unsafe ZIP path", result.stderr)
                self.assertEqual(calls, [])
                self.assertFalse(extracted)

    def test_runtime_failure_survives_tee(self):
        result, calls, _ = self.run_gate(runtime_exit=31)
        self.assertEqual(result.returncode, 31)
        self.assertEqual(calls, ["sandbox", "runtime"])

    def test_sandbox_failure_prevents_runtime(self):
        result, calls, _ = self.run_gate(sandbox_exit=29)
        self.assertEqual(result.returncode, 29)
        self.assertEqual(calls, ["sandbox"])
