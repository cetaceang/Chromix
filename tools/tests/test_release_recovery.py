"""Stateful release recovery tests model remote uploads and delete-before-clobber."""
import copy
import hashlib
import io
import json
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from tools import reconcile_browser_release as reconcile
from tools import release_browser as release
from tools.tests.test_release_browser import arm64_pe, native_job


REPO = "owner/chromix"
SHA = "a" * 40
PINNED_SHA = "b" * 40
TAG = "v1.2.3.4"
INCOMING = "chromix-linux-x64.zip"
WINDOWS = "chromix-win-x64.zip"


def checksum(data):
    return hashlib.sha256(data).hexdigest()


def backup_name(data):
    return "SHA256SUMS.backup." + checksum(data)


def bundle_bytes(name, version="1.2.3.4"):
    stream = io.BytesIO()
    if "-win-" in name:
        members = ["chromix/chromix.cmd", "chromix/chrome.exe"]
        if name == "chromix-win-arm64.zip":
            members += ["chromix/chrome.dll", "chromix/chrome_elf.dll", "chromix/libEGL.dll", "chromix/libGLESv2.dll"]
    else:
        executable = "chromix/Chromium.app/Contents/MacOS/Chromium" if "-mac-" in name else "chromix/chrome"
        members = ["chromix/chromix", executable]
    with zipfile.ZipFile(stream, "w") as archive:
        for member in (*members, "chromix/LICENSE.chromix", "chromix/LICENSE.chromium"):
            data = arm64_pe(version=version) if name == "chromix-win-arm64.zip" and member.endswith((".exe", ".dll")) else b"fixture"
            archive.writestr(zipfile.ZipInfo(member), data)
    return stream.getvalue()


class ReleaseRecoveryTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.attempts = 0
        self.run = {
            "id": 100, "run_attempt": 1, "name": "build-linux-x64",
            "path": ".github/workflows/build-linux-x64.yml", "head_sha": SHA,
            "head_branch": "main", "event": "push", "status": "completed", "conclusion": "success",
            "repository": {"full_name": REPO}, "head_repository": {"full_name": REPO},
        }
        self.current_run = copy.deepcopy(self.run)
        self.artifacts = {INCOMING: bundle_bytes(INCOMING)}
        self.remote = {WINDOWS: b"unchanged manually verified Windows ZIP", "LICENSE.chromium": b"license"}
        self.old_manifest = (f"{checksum(self.remote[WINDOWS]).upper()} *{WINDOWS}\r\n"
                             f"{checksum(self.remote['LICENSE.chromium'])}  LICENSE.chromium").encode()
        self.remote["SHA256SUMS"] = self.old_manifest
        self.metadata = {"tag_name": TAG, "draft": False, "target_commitish": PINNED_SHA,
                         "body": f"Manual Windows release\nSource commit: `{PINNED_SHA}`\n"}
        self.mutations = []
        self.artifact_downloads = []
        self.upload_snapshots = []
        self.primary_failures = 0
        self.abort_primary = False
        self.fail_backup = None
        self.corrupt_backup_download = False
        self.corrupt_artifact_checksum = False
        self.expired_artifact = False
        self.notes_failures = 0
        self.available_runs = None
        self.tag = TAG
        self.versions = {SHA: TAG[1:], PINNED_SHA: TAG[1:]}
        self.linux_versions = {}
        self.windows_versions = {}
        self.release_downloads = []
        self.gh = self.enterContext(patch.object(release, "gh", side_effect=self.fake_gh))
        self.enterContext(patch("sys.stdout", new_callable=io.StringIO))

    def fake_gh(self, *args):
        if args[:3] == ("api", "--paginate", "--slurp"):
            if args[3] == f"repos/{REPO}/releases?per_page=100":
                response = dict(self.metadata, assets=[{"name": name} for name in self.remote]) if self.metadata else None
                return json.dumps([[response] if response else []])
            prefix = f"repos/{REPO}/actions/runs?head_sha="
            if args[3].startswith(prefix):
                sha = args[3][len(prefix):].split("&")[0]
                runs = self.available_runs.values() if self.available_runs is not None else [self.current_run]
                return json.dumps([{"workflow_runs": [run for run in runs if run["head_sha"] == sha]}])
            prefix = f"repos/{REPO}/actions/runs/"
            if args[3].startswith(prefix) and "/attempts/" in args[3]:
                run_id = int(args[3][len(prefix):].split("/")[0])
                runs = self.available_runs.values() if self.available_runs is not None else [self.current_run]
                candidate = next(run for run in runs if run["id"] == run_id)
                return json.dumps([{"jobs": [native_job(candidate)]}])
        if args[0] == "api":
            prefix = f"repos/{REPO}/actions/workflows/"
            if args[1].startswith(prefix):
                workflow = args[1][len(prefix):].split(".yml/")[0]
                run = (self.available_runs or {}).get(workflow)
                return json.dumps({"workflow_runs": [run] if run else [], "total_count": int(run is not None)})
            prefix = f"repos/{REPO}/actions/runs/"
            if args[1].startswith(prefix):
                runs = self.available_runs.values() if self.available_runs is not None else [self.current_run]
                return json.dumps(next(run for run in runs if run["id"] == int(args[1][len(prefix):])))
            for filename, versions in (("CHROMIUM_LINUX_VERSION", self.linux_versions),
                                       ("CHROMIUM_WINDOWS_VERSION", self.windows_versions)):
                prefix = f"repos/{REPO}/contents/{filename}?ref="
                if args[1].startswith(prefix):
                    sha = args[1][len(prefix):]
                    if sha not in versions:
                        raise subprocess.CalledProcessError(1, ["gh", *args], stderr="gh: Not Found (HTTP 404)\n")
                    return versions[sha]
            prefix = f"repos/{REPO}/contents/CHROMIUM_VERSION?ref="
            if args[1].startswith(prefix):
                return self.versions[args[1][len(prefix):]]
            if args[1] == f"repos/{REPO}/git/matching-refs/tags/{self.tag}":
                target = self.metadata["target_commitish"] if self.metadata else PINNED_SHA
                refs = [{"ref": f"refs/tags/{self.tag}", "object": {"type": "commit", "sha": target}}]
                return json.dumps(refs if self.metadata else [])
        if args[:2] == ("run", "download"):
            self.assertEqual(int(args[2]), self.run["id"])
            name = args[args.index("--name") + 1]
            name = "chromix-win-arm64.zip" if name == "win-arm64" else name + ".zip"
            self.artifact_downloads.append((int(args[2]), name))
            if self.expired_artifact:
                raise subprocess.CalledProcessError(1, ["gh", *args])
            directory = Path(args[args.index("--dir") + 1])
            directory.mkdir(parents=True)
            data = self.artifacts[name]
            (directory / name).write_bytes(data)
            value = "0" * 64 if self.corrupt_artifact_checksum else checksum(data)
            (directory / "SHA256SUMS").write_text(f"{value}  {name}\n")
            return ""
        if args[:2] == ("release", "download"):
            name = args[args.index("--pattern") + 1]
            self.release_downloads.append(name)
            directory = Path(args[args.index("--dir") + 1])
            directory.mkdir(parents=True, exist_ok=True)
            data = self.remote[name]
            if self.corrupt_backup_download and name.startswith("SHA256SUMS.backup."):
                data = b"corrupted backup"
            self.assertFalse((directory / name).exists(), "gh download would refuse to overwrite")
            (directory / name).write_bytes(data)
            return ""
        if args[:2] == ("release", "create"):
            self.mutations.append(args)
            self.assertIsNone(self.metadata)
            self.assertIn("--draft", args)
            self.metadata = {"tag_name": self.tag, "draft": True,
                             "target_commitish": args[args.index("--target") + 1],
                             "body": Path(args[args.index("--notes-file") + 1]).read_text()}
            return ""
        if args[:2] == ("release", "upload"):
            self.mutations.append(args)
            path = Path(args[3])
            name = path.name
            self.upload_snapshots.append((name, copy.deepcopy(self.remote)))
            if "--clobber" in args:
                self.assertEqual(name, "SHA256SUMS", "browser ZIPs and backups must never be replaced")
                self.remote.pop(name, None)
            elif name in self.remote:
                raise subprocess.CalledProcessError(1, ["gh", *args])
            if name == "SHA256SUMS":
                if self.abort_primary:
                    self.abort_primary = False
                    raise SystemExit("runner terminated after delete")
                if self.primary_failures:
                    self.primary_failures -= 1
                    raise subprocess.CalledProcessError(1, ["gh", *args])
            if name == self.fail_backup:
                self.fail_backup = None
                raise subprocess.CalledProcessError(1, ["gh", *args])
            self.remote[name] = path.read_bytes()
            return ""
        if args[:2] == ("release", "edit"):
            self.mutations.append(args)
            if self.notes_failures:
                self.notes_failures -= 1
                raise subprocess.CalledProcessError(1, ["gh", *args])
            if "--draft=false" in args:
                self.metadata["draft"] = False
            self.metadata["body"] = Path(args[args.index("--notes-file") + 1]).read_text()
            self.assertNotIn("--target", args)
            return ""
        raise AssertionError(f"Unexpected GitHub CLI invocation: {args}")

    def attempt(self, collect=True):
        self.attempts += 1
        root = self.root / str(self.attempts)
        root.mkdir()
        if collect:
            bundles = release.collect(REPO, self.run, root / "artifact")
        else:
            name = release.WORKFLOWS[self.run["name"]][0] + ".zip"
            path = root / name
            path.write_bytes(self.remote[name])
            bundles = {name: path}
        release.publish(REPO, self.run, self.tag, bundles, root)

    def switch_platform(self, workflow, run_id, sha=SHA):
        self.run.update(id=run_id, name=workflow, path=f".github/workflows/{workflow}.yml", head_sha=sha)
        self.current_run = copy.deepcopy(self.run)
        self.versions[sha] = TAG[1:]
        asset = release.WORKFLOWS[workflow][0] + ".zip"
        self.artifacts.setdefault(asset, bundle_bytes(asset))
        return asset

    def merged_manifest(self, name=INCOMING):
        return self.old_manifest + f"\n{checksum(self.artifacts[name])}  {name}\n".encode()

    def uploads(self, name):
        return [args for args in self.mutations if args[1] == "upload" and Path(args[3]).name == name]

    def assert_remote_checksums(self):
        hashes = release.parse_manifest(self.remote["SHA256SUMS"].decode(), set(self.remote))
        for name, value in hashes.items():
            self.assertEqual(checksum(self.remote[name]), value)
        self.assertEqual(set(self.remote) & release.ASSETS, set(hashes) & release.ASSETS)

    def test_failed_manifest_restores_old_then_retry_recovers_uploaded_incoming_slot(self):
        original = copy.deepcopy(self.remote)
        self.primary_failures = 1
        with self.assertRaises(subprocess.CalledProcessError):
            self.attempt()
        self.assertEqual(self.remote["SHA256SUMS"], self.old_manifest)
        self.assertEqual(self.remote[INCOMING], self.artifacts[INCOMING])
        self.assertEqual(len(self.uploads(INCOMING)), 1)
        self.assertFalse(any("--draft=false" in args for args in self.mutations))
        saved_backups = {name: data for name, data in self.remote.items() if name.startswith("SHA256SUMS.backup.")}
        self.assertEqual(set(saved_backups), {backup_name(self.old_manifest), backup_name(self.merged_manifest())})
        self.attempt()
        self.assertEqual(self.remote["SHA256SUMS"], self.merged_manifest())
        self.assertEqual(len(self.uploads(INCOMING)), 1)
        self.assertEqual(len(self.artifact_downloads), 3)
        for name, data in saved_backups.items():
            self.assertEqual(self.remote[name], data)
            self.assertEqual(len(self.uploads(name)), 1)
        for name in (WINDOWS, "LICENSE.chromium"):
            self.assertEqual(self.remote[name], original[name])
        self.assert_remote_checksums()

    def test_primary_and_rollback_failure_recover_from_durable_backup(self):
        self.primary_failures = 2
        with self.assertRaises(subprocess.CalledProcessError):
            self.attempt()
        self.assertNotIn("SHA256SUMS", self.remote)
        self.assertIn(backup_name(self.old_manifest), self.remote)
        self.assertIn(backup_name(self.merged_manifest()), self.remote)
        self.attempt()
        self.assertEqual(self.remote["SHA256SUMS"], self.merged_manifest())
        self.assertEqual(len(self.uploads(INCOMING)), 1)
        self.assert_remote_checksums()

    def test_runner_termination_after_primary_delete_is_recoverable(self):
        self.abort_primary = True
        with self.assertRaises(SystemExit):
            self.attempt()
        self.assertNotIn("SHA256SUMS", self.remote)
        self.assertIn(backup_name(self.old_manifest), self.remote)
        self.assertIn(backup_name(self.merged_manifest()), self.remote)
        self.attempt()
        self.assert_remote_checksums()
        self.assertEqual(len(self.uploads(INCOMING)), 1)

    def test_backup_exists_and_is_verified_before_destructive_primary_upload(self):
        self.attempt()
        for name, remote in self.upload_snapshots:
            if name == "SHA256SUMS":
                self.assertEqual(remote[backup_name(self.old_manifest)], self.old_manifest)
                self.assertEqual(remote[backup_name(self.merged_manifest())], self.merged_manifest())
        self.assertEqual(self.remote["SHA256SUMS"], self.merged_manifest())

    def test_failed_old_backup_upload_leaves_release_completely_unchanged(self):
        original = copy.deepcopy(self.remote)
        self.fail_backup = backup_name(self.old_manifest)
        with self.assertRaises(subprocess.CalledProcessError):
            self.attempt()
        self.assertEqual(self.remote, original)
        self.assertEqual(self.uploads(INCOMING), [])
        self.assertEqual(self.uploads("SHA256SUMS"), [])
        self.attempt()
        self.assert_remote_checksums()

    def test_failed_new_backup_upload_leaves_old_manifest_and_recoverable_incoming_zip(self):
        self.fail_backup = backup_name(self.merged_manifest())
        with self.assertRaises(subprocess.CalledProcessError):
            self.attempt()
        self.assertEqual(self.remote["SHA256SUMS"], self.old_manifest)
        self.assertEqual(self.remote[INCOMING], self.artifacts[INCOMING])
        self.assertEqual(self.uploads("SHA256SUMS"), [])
        self.attempt()
        self.assertEqual(len(self.uploads(INCOMING)), 1)
        self.assert_remote_checksums()

    def test_backup_verification_failure_never_clobbers_primary(self):
        self.corrupt_backup_download = True
        with self.assertRaisesRegex(ValueError, "backup digest mismatch"):
            self.attempt()
        self.assertEqual(self.remote["SHA256SUMS"], self.old_manifest)
        self.assertEqual(self.uploads("SHA256SUMS"), [])

    def test_preexisting_content_addressed_backup_is_never_replaced(self):
        name = backup_name(self.old_manifest)
        self.remote[name] = self.old_manifest
        self.attempt()
        self.assertEqual(self.remote[name], self.old_manifest)
        self.assertEqual(self.uploads(name), [])
        self.assert_remote_checksums()

    def test_corrupt_preexisting_backup_blocks_clobber_without_replacement(self):
        name = backup_name(self.old_manifest)
        self.remote[name] = b"not the content addressed by its name"
        with self.assertRaisesRegex(ValueError, "backup digest mismatch"):
            self.attempt()
        self.assertEqual(self.remote["SHA256SUMS"], self.old_manifest)
        self.assertEqual(self.uploads(name), [])
        self.assertEqual(self.uploads("SHA256SUMS"), [])

    def test_missing_primary_recovery_validates_backup_against_every_release_file(self):
        self.remote[backup_name(self.old_manifest)] = self.remote.pop("SHA256SUMS")
        self.remote["LICENSE.chromium"] = b"changed license"
        with self.assertRaisesRegex(ValueError, "Existing release checksum mismatch"):
            self.attempt()
        self.assertEqual(self.mutations, [])

    def test_missing_primary_with_old_backup_recovers_only_exact_incoming_orphan(self):
        self.remote[backup_name(self.old_manifest)] = self.remote.pop("SHA256SUMS")
        self.remote[INCOMING] = self.artifacts[INCOMING]
        self.attempt()
        self.assertEqual(self.remote["SHA256SUMS"], self.merged_manifest())
        self.assertEqual(self.uploads(INCOMING), [])
        self.assertEqual(len(self.artifact_downloads), 2)
        self.assert_remote_checksums()

    def test_missing_primary_rejects_content_addressed_backup_with_wrong_digest(self):
        self.remote.pop("SHA256SUMS")
        self.remote[backup_name(self.old_manifest)] = self.old_manifest + b"\n"
        with self.assertRaisesRegex(ValueError, "backup digest mismatch"):
            self.attempt()
        self.assertEqual(self.mutations, [])

    def test_missing_primary_rejects_divergent_backup_histories(self):
        self.remote[backup_name(self.old_manifest)] = self.remote.pop("SHA256SUMS")
        other = f"{checksum(self.remote[WINDOWS])}  {WINDOWS}\n".encode()
        self.remote[backup_name(other)] = other
        with self.assertRaisesRegex(ValueError, "append-only history"):
            self.attempt()
        self.assertEqual(self.mutations, [])

    def test_missing_primary_rejects_backup_referencing_a_missing_release_asset(self):
        self.remote.pop("SHA256SUMS")
        self.remote[backup_name(self.merged_manifest())] = self.merged_manifest()
        with self.assertRaisesRegex(ValueError, "references missing release assets"):
            self.attempt()
        self.assertEqual(self.mutations, [])

    def test_unrelated_orphan_is_not_adopted_even_with_valid_incoming_artifact(self):
        self.remote["chromix-linux-arm64.zip"] = bundle_bytes("chromix-linux-arm64.zip")
        with self.assertRaisesRegex(ValueError, "Unrelated published browser"):
            self.attempt()
        self.assertEqual(self.mutations, [])

    def test_orphan_cannot_be_validated_by_matching_untrusted_local_bundle(self):
        self.remote[INCOMING] = b"untrusted bytes that match the supplied local file"
        with self.assertRaisesRegex(ValueError, "differs from verified incoming artifact"):
            self.attempt(collect=False)
        self.assertEqual(self.artifact_downloads, [(100, INCOMING)])
        self.assertEqual(self.mutations, [])

    def test_orphan_recovery_rejects_stale_successful_attempt(self):
        self.remote[INCOMING] = self.artifacts[INCOMING]
        self.current_run["run_attempt"] = 2
        self.attempt(collect=False)
        self.assertEqual(self.artifact_downloads, [])
        self.assertEqual(self.mutations, [])

    def test_orphan_recovery_rejects_invalid_independent_artifact_checksum(self):
        self.remote[INCOMING] = self.artifacts[INCOMING]
        self.corrupt_artifact_checksum = True
        with self.assertRaisesRegex(ValueError, "Checksum mismatch"):
            self.attempt(collect=False)
        self.assertEqual(self.mutations, [])

    def test_orphan_recovery_rejects_invalid_artifact_layout_even_when_digests_match(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("chromix/chrome", "incomplete")
        self.artifacts[INCOMING] = self.remote[INCOMING] = stream.getvalue()
        with self.assertRaisesRegex(ValueError, "Incomplete browser ZIP"):
            self.attempt(collect=False)
        self.assertEqual(self.mutations, [])

    def test_orphan_recovery_rejects_corrupt_artifact_crc_even_when_digests_match(self):
        data = self.artifacts[INCOMING].replace(b"fixture", b"corrupt", 1)
        self.artifacts[INCOMING] = self.remote[INCOMING] = data
        with self.assertRaises((ValueError, zipfile.BadZipFile)):
            self.attempt(collect=False)
        self.assertEqual(self.mutations, [])

    def test_orphan_recovery_rejects_expired_independent_artifact(self):
        self.remote[INCOMING] = self.artifacts[INCOMING]
        self.expired_artifact = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.attempt(collect=False)
        self.assertEqual(self.mutations, [])

    def test_no_manifest_or_backup_cannot_adopt_other_published_platforms(self):
        self.remote.pop("SHA256SUMS")
        with self.assertRaisesRegex(ValueError, "Unrelated published browser"):
            self.attempt()
        self.assertEqual(self.mutations, [])

    def test_later_platform_update_retains_all_immutable_backups_and_old_text(self):
        self.attempt()
        first = self.remote["SHA256SUMS"]
        old_backups = {name: data for name, data in self.remote.items() if name.startswith("SHA256SUMS.backup.")}
        self.run.update(id=101, name="build-linux-arm64", path=".github/workflows/build-linux-arm64.yml")
        self.current_run = copy.deepcopy(self.run)
        incoming = "chromix-linux-arm64.zip"
        self.artifacts[incoming] = bundle_bytes(incoming)
        self.attempt()
        second = self.remote["SHA256SUMS"]
        self.assertTrue(second.startswith(first))
        for name, data in old_backups.items():
            self.assertEqual(self.remote[name], data)
            self.assertEqual(len(self.uploads(name)), 1)
        self.assertIn(backup_name(second), self.remote)
        self.remote.pop("SHA256SUMS")
        self.attempt()
        self.assertEqual(self.remote["SHA256SUMS"], second)
        self.assertEqual(len(self.uploads(incoming)), 1)
        self.assert_remote_checksums()

    def test_new_release_primary_failure_stays_draft_and_retry_recovers(self):
        self.metadata = None
        self.remote = {}
        self.primary_failures = 1
        with self.assertRaises(subprocess.CalledProcessError):
            self.attempt()
        self.assertTrue(self.metadata["draft"])
        self.assertNotIn("SHA256SUMS", self.remote)
        self.assertIn(INCOMING, self.remote)
        self.assertEqual(len([name for name in self.remote if name.startswith("SHA256SUMS.backup.")]), 1)
        self.attempt()
        self.assertFalse(self.metadata["draft"])
        self.assertEqual(len(self.uploads(INCOMING)), 1)
        self.assert_remote_checksums()

    def test_notes_failure_leaves_new_slot_unchecksummed_and_retry_adds_provenance(self):
        self.notes_failures = 1
        with self.assertRaises(subprocess.CalledProcessError):
            self.attempt()
        self.assertEqual(self.remote["SHA256SUMS"], self.old_manifest)
        self.assertEqual(self.uploads("SHA256SUMS"), [])
        self.attempt()
        self.assertIn(f"actions/runs/{self.run['id']}", self.metadata["body"])
        self.assertIn(f"Source commit: `{SHA}`", self.metadata["body"])
        self.assertEqual(len(self.uploads(INCOMING)), 1)
        self.assert_remote_checksums()

    def test_primary_replacement_is_preceded_by_public_build_provenance(self):
        original_gh = self.fake_gh

        def check_order(*args):
            if args[:2] == ("release", "upload") and Path(args[3]).name == "SHA256SUMS":
                self.assertIn(f"actions/runs/{self.run['id']}", self.metadata["body"])
                self.assertIn(f"Source commit: `{SHA}`", self.metadata["body"])
            return original_gh(*args)

        self.gh.side_effect = check_order
        self.attempt()
        self.assert_remote_checksums()

    def test_reconcile_restores_rolled_back_append_before_new_earlier_platform(self):
        arm = self.switch_platform("build-linux-arm64", 100)
        self.primary_failures = 1
        with self.assertRaises(subprocess.CalledProcessError):
            self.attempt()
        arm_run = copy.deepcopy(self.run)
        merged = self.merged_manifest(arm)
        self.assertEqual(self.remote["SHA256SUMS"], self.old_manifest)
        self.assertEqual(self.remote[backup_name(merged)], merged)
        self.assertIn("Workflow: build-linux-arm64", self.metadata["body"])
        before = copy.deepcopy(self.remote)
        old_body = self.metadata["body"]
        self.switch_platform("build-linux-x64", 101, "c" * 40)
        self.available_runs = {arm_run["name"]: arm_run, self.run["name"]: copy.deepcopy(self.run)}
        self.mutations.clear()
        self.artifact_downloads.clear()
        original_gh = self.fake_gh

        def check_recovery_order(*args):
            if args[:2] == ("run", "download"):
                self.assertEqual(self.remote["SHA256SUMS"], merged)
            return original_gh(*args)

        self.gh.side_effect = check_recovery_order
        reconcile.reconcile(REPO, TAG[1:])
        self.assertEqual(self.artifact_downloads, [(101, INCOMING)])
        self.assertEqual(Path(self.mutations[0][3]).name, "SHA256SUMS")
        self.assertEqual(self.mutations[0][:2], ("release", "upload"))
        self.assertTrue(self.remote["SHA256SUMS"].startswith(merged))
        for name, data in before.items():
            if name != "SHA256SUMS":
                self.assertEqual(self.remote[name], data)
        self.assertTrue(self.metadata["body"].startswith(old_body))
        self.assertIn(f"Source commit: `{'c' * 40}`", self.metadata["body"])
        self.assertEqual(self.metadata["target_commitish"], PINNED_SHA)
        self.assertEqual(self.uploads(arm), [])
        self.assert_remote_checksums()
        self.mutations.clear()
        self.artifact_downloads.clear()
        reconcile.reconcile(REPO, TAG[1:])
        self.assertEqual(self.mutations, [])
        self.assertEqual(self.artifact_downloads, [])

    def test_reconcile_restores_missing_primary_before_newer_different_occupied_build(self):
        self.attempt()
        original_zip = self.remote[INCOMING]
        first = self.remote["SHA256SUMS"]
        arm = self.switch_platform("build-linux-arm64", 101, "c" * 40)
        self.abort_primary = True
        with self.assertRaises(SystemExit):
            self.attempt()
        arm_run = copy.deepcopy(self.run)
        merged = first + f"{checksum(self.artifacts[arm])}  {arm}\n".encode()
        self.assertNotIn("SHA256SUMS", self.remote)
        self.assertEqual(self.remote[backup_name(merged)], merged)
        self.switch_platform("build-linux-x64", 102, "d" * 40)
        stream = io.BytesIO(self.artifacts[INCOMING])
        with zipfile.ZipFile(stream, "a") as archive:
            archive.writestr("chromix/new-build", "different successful build")
        self.artifacts[INCOMING] = stream.getvalue()
        self.available_runs = {arm_run["name"]: arm_run, self.run["name"]: copy.deepcopy(self.run)}
        before = copy.deepcopy(self.remote)
        metadata = copy.deepcopy(self.metadata)
        self.mutations.clear()
        self.artifact_downloads.clear()
        reconcile.reconcile(REPO, TAG[1:])
        self.assertEqual(self.remote, {**before, "SHA256SUMS": merged})
        self.assertEqual(self.metadata, metadata)
        self.assertEqual(self.remote[INCOMING], original_zip)
        self.assertNotEqual(self.remote[INCOMING], self.artifacts[INCOMING])
        self.assertEqual(self.artifact_downloads, [])
        self.assertEqual(len(self.mutations), 1)
        self.assertEqual(Path(self.mutations[0][3]).name, "SHA256SUMS")
        self.assert_remote_checksums()
        self.mutations.clear()
        reconcile.reconcile(REPO, TAG[1:])
        self.assertEqual(self.mutations, [])
        self.assertEqual(self.artifact_downloads, [])

    def test_reconcile_integrity_failure_never_restores_or_collects(self):
        self.primary_failures = 1
        with self.assertRaises(subprocess.CalledProcessError):
            self.attempt()
        clean = copy.deepcopy(self.remote)
        merged_name = backup_name(self.merged_manifest())
        self.available_runs = {self.run["name"]: copy.deepcopy(self.run)}
        for primary in (True, False):
            for damage in ("zip", "sidecar", "backup", "missing", "history"):
                with self.subTest(primary=primary, damage=damage):
                    self.remote = copy.deepcopy(clean)
                    if not primary:
                        self.remote.pop("SHA256SUMS")
                    if damage == "zip":
                        self.remote[INCOMING] = b"changed ZIP"
                    elif damage == "sidecar":
                        self.remote["LICENSE.chromium"] = b"changed license"
                    elif damage == "backup":
                        self.remote[merged_name] = b"invalid backup"
                    elif damage == "missing":
                        self.remote.pop(INCOMING)
                    else:
                        other = f"{checksum(self.remote[WINDOWS])}  {WINDOWS}\n".encode()
                        self.remote[backup_name(other)] = other
                    before = copy.deepcopy(self.remote)
                    metadata = copy.deepcopy(self.metadata)
                    self.mutations.clear()
                    self.artifact_downloads.clear()
                    with self.assertRaises(ValueError):
                        reconcile.reconcile(REPO, TAG[1:])
                    self.assertEqual(self.remote, before)
                    self.assertEqual(self.metadata, metadata)
                    self.assertEqual(self.mutations, [])
                    self.assertEqual(self.artifact_downloads, [])

    def test_reconcile_restore_upload_failures_keep_backups_recoverable(self):
        self.primary_failures = 1
        with self.assertRaises(subprocess.CalledProcessError):
            self.attempt()
        clean = copy.deepcopy(self.remote)
        metadata = copy.deepcopy(self.metadata)
        merged = self.merged_manifest()
        self.available_runs = {}
        for failures in (1, 2):
            with self.subTest(failures=failures):
                self.remote = copy.deepcopy(clean)
                self.primary_failures = failures
                self.mutations.clear()
                with self.assertRaises(subprocess.CalledProcessError):
                    reconcile.reconcile(REPO, TAG[1:])
                if failures == 1:
                    self.assertEqual(self.remote["SHA256SUMS"], self.old_manifest)
                else:
                    self.assertNotIn("SHA256SUMS", self.remote)
                for name, data in clean.items():
                    if name != "SHA256SUMS":
                        self.assertEqual(self.remote[name], data)
                reconcile.reconcile(REPO, TAG[1:])
                self.assertEqual(self.remote, {**clean, "SHA256SUMS": merged})
                self.assertEqual(self.metadata, metadata)
                self.assertTrue(all(Path(args[3]).name == "SHA256SUMS" for args in self.mutations))
                self.assert_remote_checksums()

    def test_reconcile_missing_tag_blocks_restore_before_downloads(self):
        self.remote[backup_name(self.old_manifest)] = self.remote.pop("SHA256SUMS")
        self.available_runs = {}
        original_gh = self.fake_gh

        def missing_tag(*args):
            if args[:2] == ("api", f"repos/{REPO}/git/matching-refs/tags/{TAG}"):
                return "[]"
            return original_gh(*args)

        self.gh.side_effect = missing_tag
        before = copy.deepcopy(self.remote)
        with self.assertRaisesRegex(ValueError, "no verifiable tag"):
            reconcile.reconcile(REPO, TAG[1:])
        self.assertEqual(self.remote, before)
        self.assertEqual(self.mutations, [])
        self.assertEqual(self.release_downloads, [])

    def test_reconcile_version_mismatch_blocks_manifest_restore(self):
        self.remote[backup_name(self.old_manifest)] = self.remote.pop("SHA256SUMS")
        self.available_runs = {}
        self.versions[PINNED_SHA] = "9.9.9.9"
        before = copy.deepcopy(self.remote)
        with self.assertRaisesRegex(ValueError, "Pinned tag commit Chromium version"):
            reconcile.reconcile(REPO, TAG[1:])
        self.assertEqual(self.remote, before)
        self.assertEqual(self.mutations, [])
        self.assertEqual(self.release_downloads, [])

    def test_reconcile_restores_without_any_current_build_artifacts(self):
        self.remote[backup_name(self.old_manifest)] = self.remote.pop("SHA256SUMS")
        self.available_runs = {}
        self.expired_artifact = True
        before = copy.deepcopy(self.metadata)
        reconcile.reconcile(REPO, TAG[1:])
        self.assertEqual(self.remote["SHA256SUMS"], self.old_manifest)
        self.assertEqual(self.metadata, before)
        self.assertEqual(self.artifact_downloads, [])
        self.assertEqual(len(self.mutations), 1)
        self.assert_remote_checksums()

    def test_reconcile_legacy_primary_is_read_only_and_skips_new_windows_build(self):
        self.switch_platform("build-win-x64-github", 101)
        self.available_runs = {self.run["name"]: copy.deepcopy(self.run)}
        self.expired_artifact = True
        before = copy.deepcopy(self.remote)
        metadata = copy.deepcopy(self.metadata)
        with patch.object(release, "validate_bundle", side_effect=AssertionError("Legacy ZIP revalidated")):
            reconcile.reconcile(REPO, TAG[1:])
        self.assertEqual(self.remote, before)
        self.assertEqual(self.metadata, metadata)
        self.assertEqual(self.mutations, [])
        self.assertEqual(self.artifact_downloads, [])
        self.assertEqual(self.release_downloads, ["SHA256SUMS"])

    def test_reconcile_rejects_unverifiable_unrelated_orphan(self):
        self.remote["chromix-linux-arm64.zip"] = bundle_bytes("chromix-linux-arm64.zip")
        self.available_runs = {self.run["name"]: copy.deepcopy(self.run)}
        before = copy.deepcopy(self.remote)
        with self.assertRaisesRegex(ValueError, "Unrelated published browser"):
            reconcile.reconcile(REPO, TAG[1:])
        self.assertEqual(self.remote, before)
        self.assertEqual(self.mutations, [])

    def configure_migration_recovery(self, tag, workflow):
        self.tag = tag
        self.versions = {SHA: "152.0.7977.82", PINNED_SHA: "152.0.7977.82"}
        self.linux_versions = {SHA: "153.0.8010.36", PINNED_SHA: "153.0.8010.36"}
        self.windows_versions = dict(self.linux_versions)
        self.available_runs = {}
        for index, name in enumerate(release.WORKFLOWS):
            self.available_runs[name] = {**self.run, "id": 200 + index, "name": name,
                                        "path": f".github/workflows/{name}.yml", "head_sha": SHA}
        self.run = copy.deepcopy(self.available_runs[workflow])
        self.current_run = copy.deepcopy(self.run)
        self.artifacts = {name: bundle_bytes(name, version="153.0.8010.36") for name in release.ASSETS}
        incoming = release.WORKFLOWS[workflow][0] + ".zip"
        names = {name for name in release.ASSETS if ("-mac-" in name) == tag.startswith("v152")}
        self.remote = {name: self.artifacts[name] for name in names - {incoming}}
        self.old_manifest = "".join(f"{checksum(data).upper()} *{name}\r\n"
                                    for name, data in sorted(self.remote.items())).encode()
        self.remote["SHA256SUMS"] = self.old_manifest
        self.metadata = {"tag_name": tag, "draft": False, "target_commitish": SHA,
                         "body": f"Existing version group\nSource commit: `{SHA}`\n"}
        self.mutations.clear()
        self.artifact_downloads.clear()
        self.release_downloads.clear()
        self.expired_artifact = False
        return incoming, names

    def test_same_sha_linux_windows153_and_macos152_recover_without_cross_group_downloads(self):
        groups = (("v153.0.8010.36", "build-win-arm64-github"), ("v152.0.7977.82", "build-macos-arm64"))
        for tag, workflow in groups:
            for failure in ("rollback", "interrupted"):
                with self.subTest(tag=tag, failure=failure):
                    incoming, names = self.configure_migration_recovery(tag, workflow)
                    if failure == "rollback":
                        self.primary_failures = 1
                    else:
                        self.abort_primary = True
                    with self.assertRaises(subprocess.CalledProcessError if failure == "rollback" else SystemExit):
                        self.attempt()
                    merged = self.old_manifest + f"{checksum(self.artifacts[incoming])}  {incoming}\n".encode()
                    self.assertEqual(self.remote[backup_name(merged)], merged)
                    self.assertEqual(self.remote[incoming], self.artifacts[incoming])
                    self.assertEqual(len(self.uploads(incoming)), 1)
                    self.assertIn(f"Workflow: {workflow}", self.metadata["body"])
                    if failure == "rollback":
                        self.assertEqual(self.remote["SHA256SUMS"], self.old_manifest)
                    else:
                        self.assertNotIn("SHA256SUMS", self.remote)
                    before = copy.deepcopy(self.remote)
                    metadata = copy.deepcopy(self.metadata)
                    self.mutations.clear()
                    self.artifact_downloads.clear()
                    self.release_downloads.clear()
                    self.expired_artifact = True
                    reconcile.reconcile(REPO, tag[1:])
                    self.assertEqual(self.remote, {**before, "SHA256SUMS": merged})
                    self.assertEqual(self.metadata, metadata)
                    self.assertEqual(set(release.parse_manifest(merged.decode())), names)
                    self.assertEqual(set(self.release_downloads) & release.ASSETS, names)
                    self.assertEqual(self.artifact_downloads, [])
                    self.assertEqual(len(self.mutations), 1)
                    self.assertEqual(self.mutations[0][:3], ("release", "upload", tag))
                    self.assertEqual(Path(self.mutations[0][3]).name, "SHA256SUMS")
                    self.assert_remote_checksums()
                    self.mutations.clear()
                    reconcile.reconcile(REPO, tag[1:])
                    self.assertEqual(self.mutations, [])
                    self.assertEqual(self.artifact_downloads, [])

    def test_windows_pin_errors_block_backup_recovery_without_shared_downgrade(self):
        for value in ("152.0.7977.82", "153.0.8010.36-1.1", "", "forbidden", "404-lookalike"):
            with self.subTest(value=value):
                self.configure_migration_recovery("v153.0.8010.36", "build-win-arm64-github")
                self.remote[backup_name(self.old_manifest)] = self.remote.pop("SHA256SUMS")
                self.available_runs = {}
                before = copy.deepcopy(self.remote)
                metadata = copy.deepcopy(self.metadata)
                self.gh.reset_mock()

                def bad_windows_pin(*args):
                    if args[:2] == ("api", f"repos/{REPO}/contents/CHROMIUM_WINDOWS_VERSION?ref={SHA}"):
                        if value in ("forbidden", "404-lookalike"):
                            message = "gh: Forbidden (HTTP 403)" if value == "forbidden" else "gh: Not Found (HTTP 404) extra"
                            raise subprocess.CalledProcessError(1, ["gh", *args], stderr=message)
                        return value
                    return self.fake_gh(*args)

                self.gh.side_effect = bad_windows_pin
                with self.assertRaises(subprocess.CalledProcessError if value in ("forbidden", "404-lookalike") else ValueError):
                    reconcile.reconcile(REPO, self.tag[1:])
                self.assertEqual(self.remote, before)
                self.assertEqual(self.metadata, metadata)
                self.assertEqual(self.mutations, [])
                self.assertEqual(self.artifact_downloads, [])
                self.assertEqual(self.release_downloads, [])
                self.assertFalse(any("/contents/CHROMIUM_VERSION?ref=" in str(call.args) for call in self.gh.call_args_list))

    def test_identical_retry_has_no_manifest_or_backup_uploads(self):
        self.attempt()
        self.mutations.clear()
        before = copy.deepcopy(self.remote)
        self.attempt()
        self.assertEqual(self.remote, before)
        self.assertEqual([args[1] for args in self.mutations], ["edit"])


if __name__ == "__main__":
    unittest.main()
