"""Release orchestration tests use tiny ZIP fixtures and a mocked GitHub CLI."""
import copy
import hashlib
import io
import json
import os
import re
import struct
import subprocess
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

from tools import release_browser as release


REPO = "owner/chromix"
SHA = "a" * 40
OTHER_SHA = "b" * 40
TAG = "v1.2.3.4"
EXPECTED_WORKFLOWS = {
    "build-linux-x64": ("chromix-linux-x64",),
    "build-linux-arm64": ("chromix-linux-arm64",),
    "build-macos-x64": ("chromix-mac-x64",),
    "build-macos-arm64": ("chromix-mac-arm64",),
    "build-win-x64-github": ("chromix-win-x64",),
    "build-win-arm64-github": ("chromix-win-arm64",),
}
EXPECTED_ARTIFACTS = {"chromix-win-arm64": "win-arm64"}


def arm64_pe(machine=0xAA64, version="1.2.3.4", product_version=None):
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 64)
    data[64:68] = b"PE\0\0"
    struct.pack_into("<HH", data, 68, machine, 1)
    struct.pack_into("<HH", data, 84, 240, 2)
    struct.pack_into("<H", data, 88, 0x20B)
    struct.pack_into("<I", data, 196, 16)
    struct.pack_into("<II", data, 216, 0x1000, 512)
    data[328:336] = b".rsrc\0\0\0"
    struct.pack_into("<IIII", data, 336, 512, 0x1000, 512, 512)
    for offset, kind, target in ((512, 16, 0x80000018), (536, 1, 0x80000030), (560, 1033, 72)):
        struct.pack_into("<HHII", data, offset + 12, 0, 1, kind, target)
    struct.pack_into("<IIII", data, 584, 0x1060, 92, 0, 0)
    struct.pack_into("<HHH", data, 608, 92, 52, 0)
    data[614:646] = "VS_VERSION_INFO\0".encode("utf-16le")
    numbers = []
    for value in (version, product_version or version):
        a, b, c, d = map(int, value.split("."))
        numbers += [(a << 16) | b, (c << 16) | d]
    struct.pack_into("<13I", data, 648, 0xFEEF04BD, 0x10000, *numbers, *([0] * 7))
    return bytes(data)


def native_job(run, **changes):
    job = {"name": "native Windows ARM64 bundle and fingerprint verification", "run_id": run["id"],
           "run_attempt": run["run_attempt"], "head_sha": run["head_sha"],
           "labels": ["windows-11-arm"], "status": "completed", "conclusion": "success"}
    job.update(changes)
    return job


def backup_name(data):
    return "SHA256SUMS.backup." + hashlib.sha256(data).hexdigest()


def make_run(name="build-linux-x64", run_id=100, **changes):
    run = {
        "id": run_id, "run_attempt": 1, "name": name,
        "path": f".github/workflows/{name}.yml",
        "head_sha": SHA, "head_branch": "main", "event": "push",
        "repository": {"full_name": REPO}, "head_repository": {"full_name": REPO},
        "status": "completed", "conclusion": "success",
        "html_url": f"https://github.com/{REPO}/actions/runs/{run_id}",
    }
    run.update(changes)
    return run


def write_bundle(path, missing=None, extra=None, corrupt=False, version="1.2.3.4"):
    if path.name in ("chromix-win-x64.zip", "chromix-win-arm64.zip"):
        members = ["chromix/chromix.cmd", "chromix/chrome.exe"]
        if path.name == "chromix-win-arm64.zip":
            members += ["chromix/chrome.dll", "chromix/chrome_elf.dll", "chromix/libEGL.dll",
                        "chromix/libGLESv2.dll"]
    elif path.name.startswith("chromix-mac-"):
        members = ["chromix/chromix", "chromix/Chromium.app/Contents/MacOS/Chromium"]
    else:
        members = ["chromix/chromix", "chromix/chrome"]
    members += ["chromix/LICENSE.chromix", "chromix/LICENSE.chromium"]
    path.parent.mkdir(parents=True, exist_ok=True)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
            for name in members:
                if name != missing:
                    payload = (arm64_pe(version=version) if path.name == "chromix-win-arm64.zip"
                               and name.endswith((".exe", ".dll")) else b"fixture")
                    archive.writestr(zipfile.ZipInfo(name), payload)
            if extra:
                archive.writestr(zipfile.ZipInfo(extra[0]), extra[1])
    if corrupt:
        data = path.read_bytes()
        path.write_bytes(data.replace(b"fixture", b"corrupt", 1))


class GhCommandTest(unittest.TestCase):
    def test_cli_captures_error_details_for_http_status_classification(self):
        with patch.object(subprocess, "check_output", return_value="1.2.3.4\n") as output:
            self.assertEqual(release.gh("api", "contents"), "1.2.3.4")
        output.assert_called_once_with(["gh", "api", "contents"], text=True, stderr=subprocess.PIPE)


class ReleaseFixtureTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.runs = {name: make_run(name, 100 + i) for i, name in enumerate(EXPECTED_WORKFLOWS)}
        self.pages = [{"workflow_runs": list(self.runs.values())}]
        self.release = None
        self.refs = []
        self.tags = {}
        self.downloads = []
        self.mutations = []
        self.release_files = {}
        self.artifact_errors = {}
        self.version = "1.2.3.4"
        self.source_versions = {}
        self.linux_source_versions = {}
        self.windows_source_versions = {}
        self.macos_source_versions = {}
        self.bundle_version = "1.2.3.4"
        self.uploaded_files = {}
        self.notes = []
        self.fail_upload = None
        self.release_downloads = []
        self.event_run = self.runs["build-win-x64-github"]
        self.event_response = self.event_run
        self.listing_responses = []
        self.native_jobs = None
        self.gh = self.enterContext(patch.object(release, "gh", side_effect=self.fake_gh))
        self.stdout = self.enterContext(patch("sys.stdout", new_callable=io.StringIO))

    def fake_gh(self, *args):
        if args[:3] == ("api", "--paginate", "--slurp"):
            if re.fullmatch(f"repos/{REPO}/actions/runs\\?head_sha=[a-f0-9]{{40}}&per_page=100", args[3]):
                pages = self.listing_responses.pop(0) if self.listing_responses else self.pages
                return json.dumps(pages)
            if args[3] == f"repos/{REPO}/releases?per_page=100":
                return json.dumps([[self.release] if self.release else []])
            match = re.fullmatch(f"repos/{REPO}/actions/runs/([0-9]+)/attempts/([0-9]+)/jobs\\?per_page=100", args[3])
            if match:
                candidate = next(run for run in self.runs.values() if run["id"] == int(match[1]))
                if self.event_run["id"] == candidate["id"]:
                    candidate = self.event_run
                jobs = [native_job(candidate)] if self.native_jobs is None else self.native_jobs
                return json.dumps([{"jobs": jobs}])
        if args[0] == "api":
            if args[1] == f"repos/{REPO}/actions/runs/{self.event_run['id']}":
                return json.dumps(self.event_response)
            for filename, versions in (("CHROMIUM_LINUX_VERSION", self.linux_source_versions),
                                       ("CHROMIUM_WINDOWS_VERSION", self.windows_source_versions),
                                       ("CHROMIUM_MACOS_VERSION", self.macos_source_versions)):
                prefix = f"repos/{REPO}/contents/{filename}?ref="
                if args[1].startswith(prefix):
                    self.assertIn("Accept: application/vnd.github.raw+json", args)
                    sha = args[1][len(prefix):]
                    if sha not in versions:
                        raise subprocess.CalledProcessError(1, ["gh", *args], stderr="gh: Not Found (HTTP 404)\n")
                    return versions[sha]
            prefix = f"repos/{REPO}/contents/CHROMIUM_VERSION?ref="
            if args[1].startswith(prefix):
                self.assertIn("Accept: application/vnd.github.raw+json", args)
                return self.source_versions.get(args[1][len(prefix):], self.version)
            if args[1].startswith(f"repos/{REPO}/git/matching-refs/tags/"):
                return json.dumps(self.refs)
            for sha, obj in self.tags.items():
                if args[1] == f"repos/{REPO}/git/tags/{sha}":
                    return json.dumps({"object": obj})
        if args[:2] == ("run", "download"):
            name = args[args.index("--name") + 1]
            dest = Path(args[args.index("--dir") + 1])
            self.assertEqual(args[args.index("--repo") + 1], REPO)
            self.downloads.append((int(args[2]), name))
            error = self.artifact_errors.get(name)
            if error == "expired":
                raise RuntimeError("Artifact expired")
            asset = dest / ("chromix-win-arm64.zip" if name == "win-arm64" else name + ".zip")
            write_bundle(asset, missing="chromix/LICENSE.chromium" if error == "layout" else None,
                         corrupt=error == "corrupt", version=self.bundle_version)
            if name == "win-arm64" and error in ("x64", "version"):
                executable = "chromix/chrome.exe"
                payload = arm64_pe(machine=0x8664, version=self.bundle_version) if error == "x64" else arm64_pe(version="9.9.9.9")
                write_bundle(asset, missing=executable, extra=(executable, payload), version=self.bundle_version)
            if error != "missing-checksum":
                checksum = "0" * 64 if error == "checksum" else release.digest(asset)
                (dest / "SHA256SUMS").write_text(f"{checksum}  {asset.name}\n")
                if error == "foreign-checksum":
                    with (dest / "SHA256SUMS").open("a") as stream:
                        stream.write(f"{'a' * 64}  chromix-linux-x64.zip\n")
            if error == "unexpected":
                (dest / "unrelated.txt").write_text("unexpected")
            return ""
        if args[:2] == ("release", "download"):
            name = args[args.index("--pattern") + 1]
            dest = Path(args[args.index("--dir") + 1])
            dest.mkdir(parents=True, exist_ok=True)
            self.assertEqual(args[args.index("--repo") + 1], REPO)
            self.assertFalse((dest / name).exists(), "gh download cannot overwrite an existing file")
            self.release_downloads.append(name)
            (dest / name).write_bytes(self.release_files[name])
            return ""
        if args[:2] in (("release", "create"), ("release", "upload"), ("release", "edit")):
            self.mutations.append(args)
            self.assertEqual(args[args.index("--repo") + 1], REPO)
            if args[1] == "create":
                self.assertIsNone(self.release)
                self.release = {
                    "tag_name": args[2], "target_commitish": args[args.index("--target") + 1],
                    "draft": "--draft" in args, "body": "", "assets": [],
                }
            elif args[1] == "upload":
                path = Path(args[3])
                if "--clobber" in args:
                    self.assertEqual(path.name, "SHA256SUMS", "ZIPs and backup assets must remain immutable")
                    self.release_files.pop(path.name, None)
                    self.release["assets"] = [asset for asset in self.release["assets"]
                                              if asset["name"] != path.name]
                elif path.name in self.release_files:
                    raise subprocess.CalledProcessError(1, ["gh", *args])
                if path.name == self.fail_upload:
                    self.fail_upload = None
                    raise subprocess.CalledProcessError(1, ["gh", *args])
                data = path.read_bytes()
                self.uploaded_files[path.name] = data
                self.release_files[path.name] = data
                self.release["assets"].append({"name": path.name})
            elif "--draft=false" in args:
                self.release["draft"] = False
                if not any(ref["ref"] == f"refs/tags/{args[2]}" for ref in self.refs):
                    self.refs.append({"ref": f"refs/tags/{args[2]}",
                                      "object": {"type": "commit", "sha": self.release["target_commitish"]}})
            if "--notes-file" in args:
                notes = Path(args[args.index("--notes-file") + 1]).read_text()
                self.notes.append(notes)
                self.release["body"] = notes
            return ""
        raise AssertionError(f"Unexpected GitHub CLI invocation: {args}")

    def run_main(self, *args):
        event_path = self.root / "event.json"
        event_path.write_text(json.dumps({"workflow_run": self.event_run}))
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": REPO, "GITHUB_EVENT_PATH": str(event_path),
                                     "GITHUB_OUTPUT": str(self.root / "output")}):
            release.main(list(args))

    def bundles(self):
        bundles = {}
        for name in sorted(release.ASSETS):
            path = self.root / "bundles" / name
            write_bundle(path, version=self.bundle_version)
            bundles[name] = path
        return bundles

    def incoming(self):
        name = EXPECTED_WORKFLOWS[self.event_run["name"]][0] + ".zip"
        path = self.root / "incoming" / name
        write_bundle(path, version=self.bundle_version)
        return {name: path}

    def existing_release(self, bundles, draft=False, sha=SHA, tag=TAG):
        self.refs = [{"ref": f"refs/tags/{tag}", "object": {"type": "commit", "sha": sha}}]
        self.release_files = {name: path.read_bytes() for name, path in bundles.items()}
        self.release_files["SHA256SUMS"] = "".join(
            f"{release.digest(path)}  {name}\n" for name, path in sorted(bundles.items())
        ).encode("ascii")
        self.release = {
            "tag_name": tag, "target_commitish": sha, "draft": draft,
            "body": f"Existing release\nSource commit: `{sha}`\n",
            "assets": [{"name": name} for name in self.release_files],
        }


class RunSelectionTest(ReleaseFixtureTest):
    def test_platform_workflows_each_own_exactly_one_asset(self):
        self.assertEqual(release.WORKFLOWS, EXPECTED_WORKFLOWS)
        self.assertEqual(release.ASSETS, {names[0] + ".zip" for names in EXPECTED_WORKFLOWS.values()})
        self.assertEqual(set(release.WORKFLOW_PLATFORMS), set(EXPECTED_WORKFLOWS))
        self.assertEqual(set(release.ASSET_PLATFORMS), release.ASSETS)
        for workflow, names in EXPECTED_WORKFLOWS.items():
            platform = "linux" if workflow.startswith("build-linux-") else (
                "macos" if workflow.startswith("build-macos-") else "windows")
            self.assertEqual(release.WORKFLOW_PLATFORMS[workflow], platform)
            self.assertEqual(release.ASSET_PLATFORMS[names[0] + ".zip"], platform)

    def test_download_tables_list_each_registered_asset_without_claiming_acceptance(self):
        root = Path(__file__).resolve().parents[2]
        for filename in ("README.md", "readme_cn.md"):
            text = (root / filename).read_text()
            for asset in release.ASSETS:
                with self.subTest(file=filename, asset=asset):
                    self.assertIn(f"`{asset}` |", text)
            self.assertIn("`windows-2022`", text)
            self.assertIn("`windows-11-arm`", text)

    def test_workflow_subscribes_to_six_successful_main_builds(self):
        path = Path(__file__).resolve().parents[2] / ".github/workflows/release-browser.yml"
        source = path.read_text()
        workflows = re.search(r"    workflows:\n(.*?)    types:", source, re.DOTALL)[1]
        self.assertEqual([line.strip()[2:] for line in workflows.splitlines()], list(EXPECTED_WORKFLOWS))
        self.assertIn("types: [completed]", source)
        self.assertIn("branches: [main]", source)
        for condition in (
            "github.event.workflow_run.conclusion == 'success'",
            "github.event.workflow_run.repository.full_name == github.repository",
            "github.event.workflow_run.head_repository.full_name == github.repository",
            "github.event.workflow_run.event == 'push'",
            "github.event.workflow_run.event == 'workflow_dispatch'",
        ):
            self.assertIn(condition, source)
        self.assertNotIn("build-cross-platform", source)
        self.assertNotIn("build-posix-github", source)
        self.assertNotIn("group: release-browser-${{ github.event.workflow_run.head_sha }}", source)
        self.assertIn("cancel-in-progress: false", source)

    def test_invalid_events_cannot_enter_validated_version_publish_queue(self):
        path = Path(__file__).resolve().parents[2] / ".github/workflows/release-browser.yml"
        source = path.read_text()
        defaults, jobs = source.split("\njobs:\n", 1)
        readiness, publishing = jobs.split("\n  release:\n", 1)
        self.assertIn("permissions:\n  actions: read\n  contents: read\n", defaults)
        self.assertNotIn("concurrency:", defaults)
        self.assertNotIn("contents: write", readiness)
        self.assertNotIn("concurrency:", readiness)
        self.assertIn("ready: ${{ steps.check.outputs.ready }}", readiness)
        self.assertIn("version: ${{ steps.check.outputs.version }}", readiness)
        self.assertIn("python3 tools/reconcile_browser_release.py --check-ready", readiness)
        self.assertIn("needs: readiness\n    if: needs.readiness.outputs.ready == 'true'", publishing)
        self.assertIn("    concurrency:\n      group: release-browser-publish-${{ needs.readiness.outputs.version }}\n"
                      "      cancel-in-progress: false", publishing)
        self.assertIn("RELEASE_VERSION: ${{ needs.readiness.outputs.version }}", publishing)
        self.assertNotIn("inputs.version", publishing)
        self.assertNotIn("github.event.workflow_run.head_sha", publishing)
        self.assertIn("contents: write", publishing)
        self.assertIn("run: python3 tools/reconcile_browser_release.py\n", publishing)
        self.assertIn("ref: main", readiness)
        self.assertIn("controller_sha: ${{ steps.controller.outputs.sha }}", readiness)
        self.assertIn("ref: ${{ needs.readiness.outputs.controller_sha }}", publishing)
        self.assertNotIn("ref: ${{ github.event.workflow_run.head_sha }}", source)
        for job in (readiness, publishing):
            self.assertIn("persist-credentials: false", job)
            self.assertIn("python-version: '3.13'", job)

    def test_listing_checks_sha_both_repositories_branch_event_name_and_path(self):
        invalid = [
            {"head_sha": OTHER_SHA}, {"head_sha": None},
            {"repository": {"full_name": "other/chromix"}},
            {"head_repository": {"full_name": "other/chromix"}},
            {"repository": None}, {"head_repository": None},
            {"head_branch": "feature"}, {"event": "pull_request"}, {"event": "workflow_call"},
            {"name": "build-cross-platform"},
            {"path": ".github/workflows/copied-workflow.yml"},
            {"path": ".github/workflows/build-linux-x64.yml@refs/heads/main"},
        ]
        valid = make_run(event="workflow_dispatch")
        self.pages = [{"workflow_runs": [make_run(run_id=1000 + i, **changes)
                                         for i, changes in enumerate(invalid)]},
                      {"workflow_runs": [valid]}]
        self.assertEqual(release.successful_runs(REPO, SHA), {valid["name"]: valid})
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                release.validate_run(make_run(**changes), REPO, SHA)

    def test_newest_run_and_attempt_win_independent_of_page_order(self):
        old = make_run(run_id=100, run_attempt=9)
        latest = make_run(run_id=101, run_attempt=2)
        older_attempt = make_run(run_id=101, run_attempt=1)
        for pages in ([old, latest, older_attempt], [older_attempt, latest, old]):
            with self.subTest(order=[release.run_identity(run) for run in pages]):
                self.pages = [{"workflow_runs": [run]} for run in pages]
                self.assertEqual(release.successful_runs(REPO, SHA), {latest["name"]: latest})

    def test_newer_non_success_never_falls_back_to_old_success(self):
        for status, conclusion in (("completed", "failure"), ("completed", "cancelled"),
                                   ("completed", "skipped"), ("in_progress", None), ("queued", None)):
            for run_id, attempt in ((101, 1), (100, 2)):
                old = make_run()
                latest = make_run(run_id=run_id, run_attempt=attempt, status=status, conclusion=conclusion)
                for runs in ([old, latest], [latest, old]):
                    with self.subTest(status=status, conclusion=conclusion, run_id=run_id, attempt=attempt):
                        self.pages = [{"workflow_runs": [run]} for run in runs]
                        self.assertEqual(release.successful_runs(REPO, SHA), {})

    def test_conflicting_snapshot_of_same_attempt_fails_closed(self):
        success = make_run()
        pending = make_run(status="in_progress", conclusion=None)
        for runs in ([success, pending], [pending, success]):
            self.pages = [{"workflow_runs": [run]} for run in runs]
            self.assertEqual(release.successful_runs(REPO, SHA), {})


class BundleValidationTest(ReleaseFixtureTest):
    def test_manifest_accepts_named_assets_and_rejects_invalid_entries(self):
        self.assertEqual(release.parse_manifest(f"{'A' * 64} *chromix-linux-x64.zip\n"),
                         {"chromix-linux-x64.zip": "a" * 64})
        for text in (f"{'a' * 64}  unrelated.zip\n", "bad  chromix-linux-x64.zip\n",
                     f"{'a' * 64}  chromix-linux-x64.zip\n{'b' * 64}  chromix-linux-x64.zip\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                release.parse_manifest(text)

    def test_manifest_rejects_unsafe_paths_even_when_listed_as_existing_assets(self):
        for name in ("../LICENSE", "/LICENSE", "dir/LICENSE", "LICENSE\\outside", "LICENSE:stream", "SHA256SUMS"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                release.parse_manifest(f"{'a' * 64}  {name}\n", {name})

    def test_all_six_platform_layouts(self):
        for path in self.bundles().values():
            with self.subTest(asset=path.name):
                release.validate_bundle(path, "1.2.3.4")

    def test_missing_or_empty_required_members_are_rejected(self):
        path = self.root / "chromix-win-x64.zip"
        write_bundle(path, missing="chromix/chrome.exe")
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            release.validate_bundle(path)
        write_bundle(path, missing="chromix/chrome.exe", extra=("chromix/chrome.exe", ""))
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            release.validate_bundle(path)

    def test_unsafe_and_duplicate_zip_members_are_rejected(self):
        path = self.root / "chromix-linux-x64.zip"
        for member in ("chromix/../outside", "/chromix/outside", "other/chrome",
                       "chromix/drive:file", "chromix\\outside", "chromix/chrome"):
            with self.subTest(member=member):
                write_bundle(path, extra=(member, "bad"))
                with self.assertRaises(ValueError):
                    release.validate_bundle(path)

    def test_corruption_is_rejected_even_when_checksum_matches(self):
        self.artifact_errors["chromix-linux-x64"] = "corrupt"
        with self.assertRaises((ValueError, zipfile.BadZipFile)):
            release.collect(REPO, self.runs["build-linux-x64"], self.root)
        self.assertEqual(self.mutations, [])

    def test_collection_downloads_only_each_workflows_owned_artifact(self):
        for name, run in self.runs.items():
            bundles = release.collect(REPO, run, self.root)
            self.assertEqual(set(bundles), {EXPECTED_WORKFLOWS[name][0] + ".zip"})
        self.assertEqual(self.downloads, [(run["id"], EXPECTED_ARTIFACTS.get(EXPECTED_WORKFLOWS[name][0],
                                                                          EXPECTED_WORKFLOWS[name][0]))
                                         for name, run in self.runs.items()])

    def test_arm64_requires_source_version_and_core_dlls(self):
        path = self.root / "chromix-win-arm64.zip"
        write_bundle(path)
        for version in (None, "", "1.2.3.4\n"):
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "source Chromium version"):
                release.validate_bundle(path, version)
        for member in ("chrome.exe", "chrome.dll", "chrome_elf.dll", "libEGL.dll", "libGLESv2.dll"):
            write_bundle(path, missing="chromix/" + member)
            with self.subTest(member=member), self.assertRaisesRegex(ValueError, "Incomplete"):
                release.validate_bundle(path, "1.2.3.4")

    def test_arm64_checks_all_pe_members_not_just_the_launcher(self):
        path = self.root / "chromix-win-arm64.zip"
        for member in ("chrome.exe", "chrome.dll", "libEGL.dll", "nested/helper.EXE", "payload.bin"):
            name = "chromix/" + member
            for machine in (0x8664, 0x14C, 0xA641, 0xA64E):
                write_bundle(path, missing=name, extra=(name, arm64_pe(machine=machine)))
                with self.subTest(member=member, machine=machine), self.assertRaisesRegex(ValueError, "ARM64 PE"):
                    release.validate_bundle(path, "1.2.3.4")

    def test_arm64_version_is_read_from_resources_in_both_chrome_binaries(self):
        path = self.root / "chromix-win-arm64.zip"
        for member in ("chromix/chrome.exe", "chromix/chrome.dll", "chromix/1.2.3.4/chrome.dll"):
            for payload in (arm64_pe(version="1.2.3.5"), arm64_pe(product_version="1.2.3.5")):
                write_bundle(path, missing=member, extra=(member, payload))
                with self.subTest(member=member), self.assertRaisesRegex(ValueError, "PE version does not match"):
                    release.validate_bundle(path, "1.2.3.4")
        write_bundle(path, extra=("chromix/third-party.dll", arm64_pe(version="9.8.7.6")))
        release.validate_bundle(path, "1.2.3.4")

    def test_arm64_truncated_and_forged_pe_resources_are_rejected(self):
        valid = arm64_pe()
        mutations = [(0, b"XX"), (60, struct.pack("<I", 0xFFFFFFFF)), (64, b"XXXX"),
                     (70, struct.pack("<H", 0)), (88, struct.pack("<H", 0x10B)),
                     (196, struct.pack("<I", 17)), (216, struct.pack("<II", 0, 0)),
                     (348, struct.pack("<I", 99999)), (528, struct.pack("<I", 17)),
                     (532, struct.pack("<I", 0x80000000)), (580, struct.pack("<I", 0x80000048)),
                     (584, struct.pack("<I", 0xFFFFFFFF)), (588, struct.pack("<I", 10)),
                     (608, struct.pack("<H", 20)), (610, struct.pack("<H", 0)),
                     (614, b"X\0"), (648, struct.pack("<I", 0))]
        payloads = [valid[:length] for length in (0, 63, 80, 200, 500, 700)]
        for offset, value in mutations:
            changed = bytearray(valid)
            changed[offset:offset + len(value)] = value
            payloads.append(bytes(changed))
        for index, payload in enumerate(payloads):
            with self.subTest(case=index), self.assertRaises(ValueError):
                release.validate_arm64_pe(io.BytesIO(payload), len(payload), "chrome.exe", "1.2.3.4")

    def test_arm64_rejects_case_aliases_and_special_zip_members(self):
        path = self.root / "chromix-win-arm64.zip"
        for name in ("chromix/CHROME.EXE", "chromix/chrome.exe.", "chromix/chrome.exe "):
            write_bundle(path, extra=(name, arm64_pe()))
            with self.subTest(member=name), self.assertRaises(ValueError):
                release.validate_bundle(path, "1.2.3.4")
        write_bundle(path)
        with zipfile.ZipFile(path, "a") as archive:
            info = zipfile.ZipInfo("chromix/link")
            info.external_attr = 0o120777 << 16
            archive.writestr(info, "chrome.exe")
        with self.assertRaisesRegex(ValueError, "Special Windows ZIP"):
            release.validate_bundle(path, "1.2.3.4")

    def test_arm64_source_mismatch_is_rejected_during_collection(self):
        run = self.runs["build-win-arm64-github"]
        self.source_versions[run["head_sha"]] = "1.2.3.5"
        with self.assertRaisesRegex(ValueError, "PE version does not match"):
            release.collect(REPO, run, self.root)
        self.assertEqual(self.downloads, [(run["id"], "win-arm64")])
        self.assertEqual(self.mutations, [])


class Arm64NativeGateTest(ReleaseFixtureTest):
    def setUp(self):
        super().setUp()
        self.event_run = self.event_response = self.runs["build-win-arm64-github"]

    def test_exact_native_attempt_is_required_and_job_pages_are_paginated(self):
        self.event_run["run_attempt"] = 3
        self.assertTrue(release.native_verification_passed(REPO, self.event_run))
        self.gh.assert_called_once_with("api", "--paginate", "--slurp",
                                       f"repos/{REPO}/actions/runs/{self.event_run['id']}/attempts/3/jobs?per_page=100")

    def test_build_only_success_never_downloads_or_publishes(self):
        valid = native_job(self.event_run)
        invalid = [{"conclusion": "skipped"}, {"conclusion": "failure"}, {"conclusion": "cancelled"},
                   {"status": "in_progress"}, {"labels": ["windows-2022"]}, {"labels": None},
                   {"run_attempt": 2}, {"run_id": 999}, {"head_sha": OTHER_SHA}, {"name": "build"}]
        for jobs in ([], [valid, valid], *[[{**valid, **change}] for change in invalid]):
            with self.subTest(jobs=jobs):
                self.native_jobs = jobs
                self.run_main("--check-ready")
                self.assertTrue((self.root / "output").read_text().endswith("ready=false\n"))
                self.run_main()
                with self.assertRaisesRegex(ValueError, "native verification"):
                    release.collect(REPO, self.event_run, self.root)
        self.assertEqual(self.downloads, [])
        self.assertEqual(self.mutations, [])

    def test_arm64_keeps_all_strict_source_identity_checks(self):
        invalid = [{"repository": {"full_name": "other/repo"}}, {"head_repository": {"full_name": "other/repo"}},
                   {"head_branch": "feature"}, {"event": "pull_request"}, {"head_sha": None},
                   {"path": ".github/workflows/build-win-x64-github.yml"}, {"conclusion": "failure"}]
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                release.collect(REPO, {**self.event_run, **changes}, self.root)
        self.gh.assert_not_called()

    def test_renamed_x64_and_wrong_version_block_all_release_mutations(self):
        for error in ("x64", "version", "checksum", "missing-checksum", "foreign-checksum", "unexpected", "layout"):
            with self.subTest(error=error):
                self.artifact_errors["win-arm64"] = error
                with self.assertRaises(ValueError):
                    self.run_main()
                self.assertEqual(self.mutations, [])

    def test_native_gate_is_rechecked_before_release_writes(self):
        with patch.object(release, "native_verification_passed", side_effect=[True, True, False]):
            self.run_main()
        self.assertEqual(self.downloads, [(self.event_run["id"], "win-arm64")])
        self.assertEqual(self.mutations, [])

    def test_publish_cannot_bypass_pe_checks_with_local_bundle(self):
        bundles = self.incoming()
        path = next(iter(bundles.values()))
        write_bundle(path, missing="chromix/chrome.exe", extra=("chromix/chrome.exe", arm64_pe(machine=0x8664)))
        with self.assertRaisesRegex(ValueError, "ARM64 PE"):
            release.publish(REPO, self.event_run, TAG, bundles, self.root)
        self.assertEqual(self.mutations, [])

    def test_orphan_recovery_revalidates_independent_arm64_artifact(self):
        incoming = self.incoming()
        self.existing_release(incoming)
        self.release_files["SHA256SUMS"] = b""
        for error in ("x64", "version"):
            with self.subTest(error=error):
                root = self.root / error
                root.mkdir()
                self.artifact_errors["win-arm64"] = error
                with self.assertRaises(ValueError):
                    release.publish(REPO, self.event_run, TAG, incoming, root)
                self.assertEqual(self.mutations, [])


class ReadinessTest(ReleaseFixtureTest):
    def assert_read_only(self):
        self.assertEqual(self.downloads, [])
        self.assertEqual(self.mutations, [])
        for call in self.gh.call_args_list:
            self.assertEqual(call.args[0], "api")
            self.assertTrue(any(f"repos/{REPO}/actions/runs" in arg for arg in call.args))

    def test_ready_mode_outputs_true_without_downloads_or_github_writes(self):
        self.pages = [{"workflow_runs": [self.event_run]}]
        (self.root / "output").write_text("existing=value\n")
        self.run_main("--check-ready")
        self.assertEqual((self.root / "output").read_text(), "existing=value\nready=true\n")
        self.assertEqual(self.gh.call_count, 2)
        self.assert_read_only()

    def test_other_platforms_missing_failed_running_or_foreign_sha_do_not_gate(self):
        for changes in (None, {"conclusion": "failure"}, {"status": "in_progress"}, {"head_sha": OTHER_SHA}):
            with self.subTest(changes=changes):
                runs = [self.event_run]
                if changes:
                    runs.append(make_run(**changes))
                self.pages = [{"workflow_runs": runs}]
                (self.root / "output").write_text("")
                self.run_main("--check-ready")
                self.assertEqual((self.root / "output").read_text(), "ready=true\n")
                self.assert_read_only()

    def test_missing_stale_or_failed_trigger_is_not_ready(self):
        for latest in (None, {"id": 200}, {"run_attempt": 2}, {"conclusion": "failure"},
                       {"status": "in_progress", "conclusion": None}):
            with self.subTest(latest=latest):
                runs = [{**self.event_run, **latest}] if latest else []
                self.pages = [{"workflow_runs": runs}]
                (self.root / "output").write_text("")
                self.run_main("--check-ready")
                self.assertEqual((self.root / "output").read_text(), "ready=false\n")
                self.assert_read_only()

    def test_rerun_success_is_not_consumed_by_previous_attempt_event(self):
        self.event_response = {**self.event_run, "run_attempt": 2}
        self.pages = [{"workflow_runs": [self.event_response]}]
        self.run_main("--check-ready")
        self.assertEqual((self.root / "output").read_text(), "ready=false\n")
        self.assert_read_only()

    def test_newer_same_platform_other_sha_does_not_block(self):
        self.pages = [{"workflow_runs": [self.event_run, {**self.event_run, "id": 200,
                                                        "head_sha": OTHER_SHA, "conclusion": "failure"}]}]
        self.run_main("--check-ready")
        self.assertEqual((self.root / "output").read_text(), "ready=true\n")
        self.assert_read_only()

    def test_invalid_trigger_does_not_emit_ready_output(self):
        self.event_response = {**self.event_run, "head_sha": OTHER_SHA}
        with self.assertRaisesRegex(ValueError, "identity changed"):
            self.run_main("--check-ready")
        self.assertFalse((self.root / "output").exists())
        self.assert_read_only()

    def test_publish_rechecks_readiness_after_waiting_for_global_queue(self):
        self.run_main("--check-ready")
        self.assertEqual((self.root / "output").read_text(), "ready=true\n")
        self.pages[0]["workflow_runs"].append({**self.event_run, "run_attempt": 2, "conclusion": "failure"})
        self.run_main()
        self.assertIn("Pending release", self.stdout.getvalue())
        self.assertEqual(self.gh.call_count, 4)
        self.assert_read_only()


class MainTest(ReleaseFixtureTest):
    def test_each_independent_platform_creates_a_draft_then_publishes_only_its_asset(self):
        for name, run in self.runs.items():
            with self.subTest(platform=name):
                self.event_run = self.event_response = run
                self.pages = [{"workflow_runs": [run]}]
                self.downloads.clear()
                self.mutations.clear()
                self.uploaded_files.clear()
                self.release = None
                self.release_files.clear()
                self.refs = []
                self.run_main()
                asset = EXPECTED_WORKFLOWS[name][0] + ".zip"
                self.assertEqual(self.downloads, [(run["id"], EXPECTED_ARTIFACTS.get(asset[:-4], asset[:-4]))])
                manifest_bytes = self.uploaded_files["SHA256SUMS"]
                backup = backup_name(manifest_bytes)
                self.assertEqual(set(self.uploaded_files), {asset, "SHA256SUMS", backup})
                self.assertEqual(self.release_files[backup], manifest_bytes)
                self.assertIn(backup, self.release_downloads)
                manifest = release.parse_manifest(manifest_bytes.decode())
                self.assertEqual(set(manifest), {asset})
                self.assertEqual(self.mutations[0][:2], ("release", "create"))
                self.assertIn("--draft", self.mutations[0])
                self.assertEqual(self.mutations[0][self.mutations[0].index("--target") + 1], SHA)
                self.assertEqual(self.mutations[0][self.mutations[0].index("--title") + 1], "Chromix 1.2.3.4")
                self.assertEqual([args[1] for args in self.mutations], ["create", "upload", "upload", "upload", "edit"])
                self.assertEqual([Path(args[3]).name for args in self.mutations if args[1] == "upload"],
                                 [asset, backup, "SHA256SUMS"])
                self.assertFalse(self.release["draft"])
                self.assertIn("--draft=false", self.mutations[-1])
                notes = self.notes[-1]
                self.assertEqual(notes.count("Verified build:"), 1)
                self.assertIn(f"Workflow: {name} (attempt 1)", notes)
                self.assertIn(f"Source commit: `{SHA}`", notes)
                self.assertIn(f"Assets: {asset}", notes)
                self.assertIn(run["html_url"], notes)
                self.assertNotIn("All five", notes)
                self.assertNotIn("only Windows", notes)

    def test_same_sha_publishes_linux153_and_windows_macos152_separately(self):
        self.version = self.bundle_version = "152.0.7977.82"
        self.linux_source_versions[SHA] = "153.0.8010.36"
        releases = {}
        files = {}
        for name, run in self.runs.items():
            version = "153.0.8010.36" if name.startswith("build-linux-") else self.version
            tag = "v" + version
            self.event_run = self.event_response = run
            self.release = releases.get(tag)
            self.release_files = files.get(tag, {})
            self.run_main()
            releases[tag] = self.release
            files[tag] = self.release_files
            self.assertEqual(self.release["target_commitish"], SHA)
            self.assertEqual(self.release["tag_name"], tag)
            self.assertFalse(self.release["draft"])
        self.assertEqual(set(releases), {"v153.0.8010.36", "v152.0.7977.82"})
        for tag, assets in files.items():
            expected = {name for name in release.ASSETS if ("-linux-" in name) == tag.startswith("v153")}
            self.assertEqual(set(release.parse_manifest(assets["SHA256SUMS"].decode())), expected)
        self.assertEqual(len([args for args in self.mutations if args[1] == "create"]), 2)
        self.assertEqual({ref["object"]["sha"] for ref in self.refs}, {SHA})

    def test_same_sha_publishes_linux_windows153_and_macos152_separately(self):
        self.version = self.bundle_version = "153.0.8010.36"
        self.macos_source_versions[SHA] = "152.0.7977.82"
        self.linux_source_versions[SHA] = self.windows_source_versions[SHA] = self.bundle_version
        releases, files = {}, {}
        for name, run in self.runs.items():
            tag = "v" + (self.macos_source_versions[SHA] if name.startswith("build-macos-") else self.version)
            with self.subTest(workflow=name):
                self.event_run = self.event_response = run
                self.release = releases.get(tag)
                self.release_files = files.get(tag, {})
                self.run_main()
                releases[tag], files[tag] = self.release, self.release_files
                self.assertEqual(self.release["target_commitish"], SHA)
                self.assertEqual(self.release["tag_name"], tag)
                self.assertFalse(self.release["draft"])
        self.assertEqual(set(releases), {"v153.0.8010.36", "v152.0.7977.82"})
        for tag, assets in files.items():
            expected = {name for name in release.ASSETS if ("-mac-" in name) == tag.startswith("v152")}
            self.assertEqual(set(release.parse_manifest(assets["SHA256SUMS"].decode())), expected)
            self.assertEqual(set(assets) & release.ASSETS, expected)
            for name in expected:
                self.assertEqual(release.parse_manifest(assets["SHA256SUMS"].decode())[name],
                                 hashlib.sha256(assets[name]).hexdigest())
            expected_workflows = {name for name in self.runs if name.startswith("build-macos-") == tag.startswith("v152")}
            body = releases[tag]["body"]
            self.assertEqual(body.count("Verified build:"), len(expected_workflows))
            for name in self.runs:
                self.assertEqual(f"Workflow: {name} (" in body, name in expected_workflows)
        self.assertEqual(len([args for args in self.mutations if args[1] == "create"]), 2)
        self.assertEqual(len(self.downloads), 6)
        self.assertEqual({ref["object"]["sha"] for ref in self.refs}, {SHA})
        self.assertTrue(all(Path(args[3]).name == "SHA256SUMS" for args in self.mutations if "--clobber" in args))

    def test_trigger_that_has_started_rerunning_is_pending(self):
        self.event_response = {**self.event_run, "status": "in_progress", "conclusion": None, "run_attempt": 2}
        self.run_main()
        self.assertIn("Pending release", self.stdout.getvalue())
        self.assertEqual(self.downloads, [])
        self.assertEqual(self.mutations, [])

    def test_trigger_api_cannot_change_commit_workflow_path_id_or_event(self):
        for changes in ({"head_sha": OTHER_SHA}, {"name": "build-linux-x64"}, {"id": 999},
                        {"event": "workflow_dispatch"}, {"path": ".github/workflows/copied.yml"},
                        {"repository": {"full_name": "other/chromix"}},
                        {"head_repository": {"full_name": "other/chromix"}}, {"head_branch": "feature"}):
            with self.subTest(changes=changes):
                self.event_response = {**self.event_run, **changes}
                with self.assertRaisesRegex(ValueError, "identity changed"):
                    self.run_main()
        self.assertEqual(self.downloads, [])
        self.assertEqual(self.mutations, [])

    def test_old_aggregate_event_is_never_consumed_even_with_successful_platform_artifacts(self):
        for name in ("build-cross-platform", "build-posix-github"):
            for conclusion in ("failure", "success"):
                with self.subTest(name=name, conclusion=conclusion):
                    self.event_run = make_run(name, 34308090891, conclusion=conclusion)
                    with self.assertRaises(ValueError):
                        self.run_main()
        self.gh.assert_not_called()

    def test_invalid_incoming_artifact_blocks_all_mutations(self):
        for error in ("layout", "checksum", "missing-checksum", "foreign-checksum", "unexpected", "corrupt", "expired"):
            with self.subTest(error=error):
                self.downloads.clear()
                self.artifact_errors["chromix-win-x64"] = error
                with self.assertRaises((ValueError, zipfile.BadZipFile, RuntimeError)):
                    self.run_main()
                self.assertEqual(self.downloads, [(self.event_run["id"], "chromix-win-x64")])
                self.assertEqual(self.mutations, [])

    def test_run_changes_during_download_remain_pending(self):
        for changes in ({"run_attempt": 2, "status": "in_progress", "conclusion": None},
                        {"run_attempt": 2, "conclusion": "failure"}, {"run_attempt": 2}, {"id": 200}):
            with self.subTest(changes=changes):
                self.listing_responses = [self.pages, [{"workflow_runs": [{**self.event_run, **changes}]}]]
                self.run_main()
                self.assertEqual(self.mutations, [])
                self.assertIn("platform run changed", self.stdout.getvalue())

    def test_other_platform_changes_during_download_do_not_block(self):
        self.listing_responses = [self.pages, [{"workflow_runs": [self.event_run, make_run(conclusion="failure")]}]]
        self.run_main()
        self.assertEqual(self.mutations[-1][1], "edit")

    def test_invalid_version_blocks_collection_and_publication(self):
        self.version = "not-a-version"
        with self.assertRaisesRegex(ValueError, "Invalid Chromium version"):
            self.run_main()
        self.assertEqual(self.downloads, [])
        self.assertEqual(self.mutations, [])

    def test_new_release_upload_failure_leaves_draft_not_partial_public_release(self):
        for asset in ("chromix-win-x64.zip", "SHA256SUMS"):
            with self.subTest(asset=asset):
                self.fail_upload = asset
                self.mutations.clear()
                self.release = None
                self.release_files.clear()
                self.refs = []
                with self.assertRaises(subprocess.CalledProcessError):
                    self.run_main()
                self.assertTrue(self.release["draft"])
                self.assertNotIn("SHA256SUMS", self.release_files)
                self.assertEqual(self.mutations[0][1], "create")
                self.assertIn("--draft", self.mutations[0])
                self.assertNotIn("edit", [args[1] for args in self.mutations])


class SourceVersionTest(ReleaseFixtureTest):
    def test_default_keeps_shared_pin(self):
        self.version = "153.0.8010.36"
        self.macos_source_versions[SHA] = "152.0.7977.82"
        self.assertEqual(release.source_version(REPO, SHA), self.version)
        self.gh.assert_called_once_with("api", f"repos/{REPO}/contents/CHROMIUM_VERSION?ref={SHA}",
                                       "-H", "Accept: application/vnd.github.raw+json")

    def test_macos_uses_152_override_under_shared_153(self):
        self.version = "153.0.8010.36"
        self.macos_source_versions[SHA] = "152.0.7977.82"
        self.assertEqual(release.source_version(REPO, SHA, "macos"), "152.0.7977.82")
        self.gh.assert_called_once_with("api", f"repos/{REPO}/contents/CHROMIUM_MACOS_VERSION?ref={SHA}",
                                       "-H", "Accept: application/vnd.github.raw+json")

    def test_macos_override_is_checked_at_incoming_and_immutable_tag_commits(self):
        self.version = "153.0.8010.36"
        self.macos_source_versions = {SHA: "152.0.7977.82", OTHER_SHA: "153.0.8010.36"}
        tag = "v152.0.7977.82"
        self.refs = [{"ref": f"refs/tags/{tag}", "object": {"type": "commit", "sha": OTHER_SHA}}]
        with self.assertRaisesRegex(ValueError, "Pinned tag commit Chromium version"):
            release.validate_release_revision(REPO, tag, SHA, None, "macos")
        self.macos_source_versions[OTHER_SHA] = "152.0.7977.82"
        self.assertEqual(release.validate_release_revision(REPO, tag, SHA, None, "macos"), OTHER_SHA)
        with self.assertRaisesRegex(ValueError, "Incoming source Chromium version"):
            release.validate_release_revision(REPO, "v153.0.8010.36", SHA, None, "macos")
        self.assertEqual(self.mutations, [])

    def test_platforms_use_their_commit_pin_without_reading_shared_version(self):
        self.version = "not-a-version"
        self.linux_source_versions[SHA] = self.windows_source_versions[SHA] = self.macos_source_versions[SHA] = "153.0.8010.36"
        for platform in ("linux", "windows", "macos"):
            with self.subTest(platform=platform):
                self.gh.reset_mock()
                self.assertEqual(release.source_version(REPO, SHA, platform), "153.0.8010.36")
                self.gh.assert_called_once_with("api", f"repos/{REPO}/contents/CHROMIUM_{platform.upper()}_VERSION?ref={SHA}",
                                               "-H", "Accept: application/vnd.github.raw+json")

    def test_only_exact_missing_platform_file_falls_back_at_same_sha(self):
        self.source_versions[OTHER_SHA] = "152.0.7977.82"
        for platform in ("linux", "windows", "macos"):
            with self.subTest(platform=platform):
                self.gh.reset_mock()
                self.assertEqual(release.source_version(REPO, OTHER_SHA, platform), "152.0.7977.82")
                self.assertEqual([call.args[1] for call in self.gh.call_args_list],
                                 [f"repos/{REPO}/contents/{name}?ref={OTHER_SHA}"
                                  for name in (f"CHROMIUM_{platform.upper()}_VERSION", "CHROMIUM_VERSION")])

    def test_exact_404_allows_only_line_ending_variants(self):
        for platform in ("linux", "windows", "macos"):
            for ending in ("", "\n", "\r\n"):
                with self.subTest(platform=platform, ending=ending):
                    self.gh.reset_mock()
                    error = subprocess.CalledProcessError(1, ["gh", "api"],
                                                         stderr="gh: Not Found (HTTP 404)" + ending)
                    self.gh.side_effect = [error, "152.0.7977.82"]
                    self.assertEqual(release.source_version(REPO, SHA, platform), "152.0.7977.82")
                    self.assertEqual(self.gh.call_count, 2)
                    self.assertEqual(self.gh.call_args.args[1], f"repos/{REPO}/contents/CHROMIUM_VERSION?ref={SHA}")

    def test_malformed_platform_contents_never_fall_back(self):
        for platform, versions in (("linux", self.linux_source_versions), ("windows", self.windows_source_versions),
                                   ("macos", self.macos_source_versions)):
            for value in ("", "153.0.8010.36-1", "153.0.8010.36-1.1", "153.0.8010", "153.0.8010.36\nextra",
                          "153.0.8010.36\n", '{"message":"Not Found","status":"404"}', '[]'):
                with self.subTest(platform=platform, value=value):
                    self.gh.reset_mock()
                    versions[SHA] = value
                    with self.assertRaisesRegex(ValueError, "Invalid Chromium version"):
                        release.source_version(REPO, SHA, platform)
                    self.assertEqual(self.gh.call_count, 1)

    def test_api_failures_and_404_lookalikes_never_fall_back(self):
        for platform in ("linux", "windows", "macos"):
            for message in (None, "", "HTTP 404", "gh: Not Found (HTTP 4040)",
                            " gh: Not Found (HTTP 404)", "gh: Not Found (HTTP 404) ",
                            "gh: Not Found (HTTP 404) extra", "gh: Not Found (HTTP 404)\nrate limited",
                            b"gh: Not Found (HTTP 404)\n", "gh: Unauthorized (HTTP 401)",
                            "gh: Forbidden (HTTP 403)", "gh: Server Error (HTTP 500)",
                            "gh: API rate limit exceeded (HTTP 429)"):
                with self.subTest(platform=platform, stderr=message):
                    error = subprocess.CalledProcessError(1, ["gh", "api"],
                                                         output='{"status":"404"}', stderr=message)
                    self.gh.reset_mock()
                    self.gh.side_effect = error
                    with self.assertRaises(subprocess.CalledProcessError) as caught:
                        release.source_version(REPO, SHA, platform)
                    self.assertIs(caught.exception, error)
                    self.assertEqual(self.gh.call_count, 1)

    def test_non_http_failures_never_fall_back(self):
        for platform in ("linux", "windows", "macos"):
            for error in (subprocess.CalledProcessError(2, ["gh", "api"], stderr="gh: Not Found (HTTP 404)\n"),
                          subprocess.TimeoutExpired(["gh", "api"], 30), OSError("connection reset")):
                with self.subTest(platform=platform, error=type(error).__name__):
                    self.gh.reset_mock()
                    self.gh.side_effect = error
                    with self.assertRaises(type(error)) as caught:
                        release.source_version(REPO, SHA, platform)
                    self.assertIs(caught.exception, error)
                    self.assertEqual(self.gh.call_count, 1)

    def test_shared_404_and_missing_legacy_pin_fail_closed(self):
        error = subprocess.CalledProcessError(1, ["gh", "api"], stderr="gh: Not Found (HTTP 404)\n")
        for platform in (None, "windows", "macos", "linux"):
            with self.subTest(platform=platform):
                self.gh.reset_mock()
                self.gh.side_effect = error
                with self.assertRaises(subprocess.CalledProcessError):
                    release.source_version(REPO, SHA, platform)
                self.assertEqual(self.gh.call_count, 2 if platform is not None else 1)

    def test_invalid_legacy_pin_still_fails_after_exact_404(self):
        self.version = "malformed"
        for platform in ("linux", "windows", "macos"):
            with self.subTest(platform=platform):
                self.gh.reset_mock()
                with self.assertRaisesRegex(ValueError, "Invalid Chromium version"):
                    release.source_version(REPO, SHA, platform)
                self.assertEqual(self.gh.call_count, 2)

    def test_invalid_sha_or_platform_never_reaches_github(self):
        for sha, platform in (("main", "linux"), (SHA + "\n", "linux"), ("main", "windows"),
                              (SHA + "\n", "windows"), (SHA, "linx")):
            with self.subTest(sha=sha, platform=platform), self.assertRaises(ValueError):
                release.source_version(REPO, sha, platform)
        self.gh.assert_not_called()


class RevisionTest(ReleaseFixtureTest):
    def test_incoming_version_must_match_valid_tag_before_downloads_or_writes(self):
        bundles = self.incoming()
        for tag, version in ((TAG, "9.9.9.9"), ("v1.2.3.4-other", "1.2.3.4"), (TAG, "not-a-version")):
            with self.subTest(tag=tag, version=version):
                self.version = version
                with self.assertRaises(ValueError):
                    release.publish(REPO, self.event_run, tag, bundles, self.root)
                self.assertEqual(self.release_downloads, [])
                self.assertEqual(self.mutations, [])

    def test_existing_tag_can_point_to_other_sha_only_for_same_chromium_version(self):
        self.refs = [{"ref": f"refs/tags/{TAG}", "object": {"type": "commit", "sha": OTHER_SHA}}]
        self.assertEqual(release.validate_release_revision(REPO, TAG, SHA, None), OTHER_SHA)
        self.source_versions[OTHER_SHA] = "1.2.3.5"
        with self.assertRaisesRegex(ValueError, "Pinned tag commit Chromium version"):
            release.publish(REPO, self.event_run, TAG, self.incoming(), self.root)
        self.assertEqual(self.release_downloads, [])
        self.assertEqual(self.mutations, [])

    def test_annotated_tags_are_peeled_and_version_checked(self):
        tag_sha = "c" * 40
        nested_sha = "d" * 40
        self.refs = [{"ref": f"refs/tags/{TAG}", "object": {"type": "tag", "sha": tag_sha}}]
        self.tags[tag_sha] = {"type": "tag", "sha": nested_sha}
        self.tags[nested_sha] = {"type": "commit", "sha": OTHER_SHA}
        self.assertEqual(release.validate_release_revision(REPO, TAG, SHA, None), OTHER_SHA)
        self.source_versions[OTHER_SHA] = "2.3.4.5"
        with self.assertRaisesRegex(ValueError, "Pinned tag commit Chromium version"):
            release.validate_release_revision(REPO, TAG, SHA, None)
        self.tags[nested_sha] = {"type": "tag", "sha": tag_sha}
        with self.assertRaisesRegex(ValueError, "Invalid annotated"):
            release.validate_release_revision(REPO, TAG, SHA, None)

    def test_noncommit_tag_is_rejected(self):
        self.refs = [{"ref": f"refs/tags/{TAG}", "object": {"type": "tree", "sha": SHA}}]
        with self.assertRaisesRegex(ValueError, "does not point to a commit"):
            release.validate_release_revision(REPO, TAG, SHA, None)

    def test_similar_prefix_tag_is_not_treated_as_release_tag(self):
        self.refs = [{"ref": f"refs/tags/{TAG}-other", "object": {"type": "commit", "sha": OTHER_SHA}}]
        self.assertEqual(release.validate_release_revision(REPO, TAG, SHA, None), SHA)

    def test_release_target_must_match_immutable_tag_not_incoming_sha(self):
        self.existing_release({}, sha=OTHER_SHA)
        self.assertEqual(release.validate_release_revision(REPO, TAG, SHA, self.release), OTHER_SHA)
        self.release["target_commitish"] = SHA
        with self.assertRaisesRegex(ValueError, "target conflicts"):
            release.validate_release_revision(REPO, TAG, SHA, self.release)
        self.release["target_commitish"] = "main"
        self.assertEqual(release.validate_release_revision(REPO, TAG, SHA, self.release), OTHER_SHA)

    def test_published_release_requires_tag_and_untagged_draft_requires_commit_version(self):
        self.existing_release({}, sha=OTHER_SHA)
        self.refs = []
        with self.assertRaisesRegex(ValueError, "no verifiable tag or draft commit"):
            release.validate_release_revision(REPO, TAG, SHA, self.release)
        self.release["draft"] = True
        self.assertEqual(release.validate_release_revision(REPO, TAG, SHA, self.release), OTHER_SHA)
        self.release["target_commitish"] = "main"
        with self.assertRaisesRegex(ValueError, "no verifiable tag or draft commit"):
            release.validate_release_revision(REPO, TAG, SHA, self.release)
        self.release["target_commitish"] = OTHER_SHA
        self.source_versions[OTHER_SHA] = "1.2.3.5"
        with self.assertRaisesRegex(ValueError, "Pinned tag commit Chromium version"):
            release.validate_release_revision(REPO, TAG, SHA, self.release)

    def test_new_release_uses_existing_tag_commit_without_moving_tag(self):
        self.refs = [{"ref": f"refs/tags/{TAG}", "object": {"type": "commit", "sha": OTHER_SHA}}]
        release.publish(REPO, self.event_run, TAG, self.incoming(), self.root)
        create = self.mutations[0]
        self.assertEqual(create[create.index("--target") + 1], OTHER_SHA)
        self.assertTrue(all(args[0] == "release" for args in self.mutations))
        self.assertNotIn("--target", self.mutations[-1])

    def test_changed_pinned_commit_during_download_fails_before_mutation(self):
        self.existing_release({}, sha=OTHER_SHA)
        self.release["target_commitish"] = "main"
        original_gh = self.fake_gh

        def download_then_move_tag(*args):
            result = original_gh(*args)
            if args[:2] == ("release", "download"):
                self.refs[0]["object"]["sha"] = "c" * 40
            return result

        self.gh.side_effect = download_then_move_tag
        with self.assertRaisesRegex(ValueError, "Pinned release commit changed"):
            release.publish(REPO, self.event_run, TAG, self.incoming(), self.root)
        self.assertEqual(self.mutations, [])


class PlatformRevisionTest(ReleaseFixtureTest):
    def setUp(self):
        super().setUp()
        self.version = self.bundle_version = "152.0.7977.82"
        self.linux_source_versions = {SHA: "153.0.8010.36", OTHER_SHA: "153.0.8010.36"}
        self.linux_tag = "v153.0.8010.36"

    def test_incoming_and_pinned_commit_use_the_same_platform(self):
        for platform, tag in (("linux", self.linux_tag), ("windows", "v" + self.version),
                              ("macos", "v" + self.version)):
            with self.subTest(platform=platform):
                self.refs = [{"ref": f"refs/tags/{tag}", "object": {"type": "commit", "sha": OTHER_SHA}}]
                self.assertEqual(release.validate_release_revision(REPO, tag, SHA, None, platform), OTHER_SHA)
        self.source_versions[OTHER_SHA] = self.linux_tag[1:]
        self.linux_source_versions[OTHER_SHA] = self.version
        self.refs = [{"ref": f"refs/tags/{self.linux_tag}", "object": {"type": "commit", "sha": OTHER_SHA}}]
        with self.assertRaisesRegex(ValueError, "Pinned tag commit Chromium version"):
            release.validate_release_revision(REPO, self.linux_tag, SHA, None, "linux")

    def test_wrong_platform_tag_is_rejected_even_at_same_sha(self):
        for name, run in self.runs.items():
            self.event_run = self.event_response = run
            tag = "v" + self.version if name.startswith("build-linux-") else self.linux_tag
            with self.subTest(workflow=name), self.assertRaisesRegex(ValueError, "Incoming source Chromium version"):
                release.publish(REPO, run, tag, self.incoming(), self.root)
        self.assertEqual(self.downloads, [])
        self.assertEqual(self.release_downloads, [])
        self.assertEqual(self.mutations, [])

    def test_annotated_and_untagged_draft_linux_commits_keep_platform_verification(self):
        tag_sha = "c" * 40
        self.refs = [{"ref": f"refs/tags/{self.linux_tag}", "object": {"type": "tag", "sha": tag_sha}}]
        self.tags[tag_sha] = {"type": "commit", "sha": OTHER_SHA}
        self.assertEqual(release.validate_release_revision(REPO, self.linux_tag, SHA, None, "linux"), OTHER_SHA)
        self.refs = []
        draft = {"draft": True, "target_commitish": OTHER_SHA, "assets": []}
        self.assertEqual(release.validate_release_revision(REPO, self.linux_tag, SHA, draft, "linux"), OTHER_SHA)
        self.linux_source_versions[OTHER_SHA] = self.version
        with self.assertRaisesRegex(ValueError, "Pinned tag commit Chromium version"):
            release.validate_release_revision(REPO, self.linux_tag, SHA, draft, "linux")

    def test_mixed_platform_assets_are_not_adopted_even_with_valid_hashes(self):
        bundles = self.bundles()
        for name, run in self.runs.items():
            linux = name.startswith("build-linux-")
            foreign = "chromix-win-x64.zip" if linux else "chromix-linux-x64.zip"
            tag = self.linux_tag if linux else "v" + self.version
            self.event_run = self.event_response = run
            self.existing_release({foreign: bundles[foreign]}, tag=tag)
            with self.subTest(workflow=name), self.assertRaisesRegex(ValueError, "Pinned tag commit Chromium version"):
                release.publish(REPO, run, tag, self.incoming(), self.root)
        self.assertEqual(self.release_downloads, [])
        self.assertEqual(self.mutations, [])

    def test_recovery_derives_all_known_asset_platforms_without_incoming_run(self):
        bundles = self.bundles()
        for tag, names in ((self.linux_tag, {"chromix-linux-x64.zip", "chromix-linux-arm64.zip"}),
                           ("v" + self.version, {"chromix-win-x64.zip", "chromix-win-arm64.zip",
                                                "chromix-mac-x64.zip", "chromix-mac-arm64.zip"})):
            with self.subTest(tag=tag):
                self.existing_release({name: bundles[name] for name in names}, tag=tag)
                original = self.release_files.pop("SHA256SUMS")
                self.release_files[backup_name(original)] = original
                self.release["assets"] = [{"name": name} for name in self.release_files]
                directory = self.root / tag
                directory.mkdir()
                hashes = release.restore_release_manifest(REPO, tag, self.release, directory)
                self.assertEqual(set(hashes), names)
                self.assertEqual(self.release_files["SHA256SUMS"], original)
        self.assertEqual([args[1] for args in self.mutations], ["upload", "upload"])
        self.assertEqual(self.downloads, [])

    def test_recovery_rejects_mixed_assets_with_primary_backup_or_orphan(self):
        bundles = self.bundles()
        for tag in (self.linux_tag, "v" + self.version):
            for state in ("primary", "backup", "orphan"):
                self.existing_release({name: bundles[name] for name in ("chromix-linux-x64.zip", "chromix-win-x64.zip")},
                                      tag=tag)
                if state != "primary":
                    original = self.release_files.pop("SHA256SUMS")
                    if state == "backup":
                        self.release_files[backup_name(original)] = original
                    self.release["assets"] = [{"name": name} for name in self.release_files]
                with self.subTest(tag=tag, state=state), self.assertRaisesRegex(ValueError, "Pinned tag commit Chromium version"):
                    release.restore_release_manifest(REPO, tag, self.release, self.root)
        self.assertEqual(self.release_downloads, [])
        self.assertEqual(self.mutations, [])

    def test_recovery_rechecks_linux_pin_before_manifest_upload(self):
        bundles = self.bundles()
        self.existing_release({"chromix-linux-x64.zip": bundles["chromix-linux-x64.zip"]}, tag=self.linux_tag)
        original = self.release_files.pop("SHA256SUMS")
        self.release_files[backup_name(original)] = original
        self.release["assets"] = [{"name": name} for name in self.release_files]
        original_gh = self.fake_gh

        def download_then_change_version(*args):
            result = original_gh(*args)
            if args[:2] == ("release", "download") and "chromix-linux-x64.zip" in args:
                self.linux_source_versions[SHA] = self.version
            return result

        self.gh.side_effect = download_then_change_version
        with self.assertRaisesRegex(ValueError, "Pinned tag commit Chromium version"):
            release.restore_release_manifest(REPO, self.linux_tag, self.release, self.root)
        self.assertEqual(self.mutations, [])

    def test_assetless_recovery_explicitly_retains_legacy_version_default(self):
        self.existing_release({}, tag=self.linux_tag)
        with self.assertRaisesRegex(ValueError, "Pinned tag commit Chromium version"):
            release.restore_release_manifest(REPO, self.linux_tag, self.release, self.root)
        self.assertEqual(self.mutations, [])


class WindowsPlatformRevisionTest(ReleaseFixtureTest):
    def setUp(self):
        super().setUp()
        self.version = "152.0.7977.82"
        self.bundle_version = "153.0.8010.36"
        self.tag = "v" + self.bundle_version
        self.linux_source_versions = {SHA: self.bundle_version, OTHER_SHA: self.bundle_version}
        self.windows_source_versions = dict(self.linux_source_versions)

    def test_windows_incoming_and_pinned_commits_use_windows_pin(self):
        self.refs = [{"ref": f"refs/tags/{self.tag}", "object": {"type": "commit", "sha": OTHER_SHA}}]
        self.assertEqual(release.validate_release_revision(REPO, self.tag, SHA, None, "windows"), OTHER_SHA)
        self.windows_source_versions = {SHA: self.bundle_version, OTHER_SHA: self.version}
        self.source_versions[OTHER_SHA] = self.bundle_version
        with self.assertRaisesRegex(ValueError, "Pinned tag commit Chromium version"):
            release.validate_release_revision(REPO, self.tag, SHA, None, "windows")
        self.assertEqual(self.mutations, [])

    def test_wrong_version_group_is_rejected_before_downloads_or_writes(self):
        for name, run in self.runs.items():
            tag = self.tag if name.startswith("build-macos-") else "v" + self.version
            self.event_run = self.event_response = run
            with self.subTest(workflow=name), self.assertRaisesRegex(ValueError, "Incoming source Chromium version"):
                release.publish(REPO, run, tag, self.incoming(), self.root)
        self.assertEqual(self.downloads, [])
        self.assertEqual(self.release_downloads, [])
        self.assertEqual(self.mutations, [])

    def test_recovery_accepts_linux_windows153_and_macos152_groups(self):
        bundles = self.bundles()
        for tag in (self.tag, "v" + self.version):
            names = {name for name in bundles if ("-mac-" in name) == (tag == "v" + self.version)}
            with self.subTest(tag=tag):
                self.existing_release({name: bundles[name] for name in names}, tag=tag)
                original = self.release_files.pop("SHA256SUMS")
                self.release_files[backup_name(original)] = original
                self.release["assets"] = [{"name": name} for name in self.release_files]
                before = copy.deepcopy(self.release_files)
                metadata = copy.deepcopy(self.release)
                directory = self.root / tag
                directory.mkdir()
                self.assertEqual(set(release.restore_release_manifest(REPO, tag, self.release, directory)), names)
                self.assertEqual(self.release_files, {**before, "SHA256SUMS": original})
                self.assertEqual(self.release["body"], metadata["body"])
                self.assertEqual(self.release["target_commitish"], SHA)
        self.assertEqual([args[1] for args in self.mutations], ["upload", "upload"])
        self.assertEqual(self.downloads, [])

    def test_recovery_rejects_windows153_macos152_mix_in_every_manifest_state(self):
        bundles = self.bundles()
        for tag in (self.tag, "v" + self.version):
            for state in ("primary", "backup", "orphan"):
                self.existing_release({name: bundles[name] for name in ("chromix-win-x64.zip", "chromix-mac-x64.zip")},
                                      tag=tag)
                if state != "primary":
                    original = self.release_files.pop("SHA256SUMS")
                    if state == "backup":
                        self.release_files[backup_name(original)] = original
                    self.release["assets"] = [{"name": name} for name in self.release_files]
                with self.subTest(tag=tag, state=state), self.assertRaisesRegex(ValueError, "Pinned tag commit Chromium version"):
                    release.restore_release_manifest(REPO, tag, self.release, self.root)
        self.assertEqual(self.release_downloads, [])
        self.assertEqual(self.mutations, [])

    def test_recovery_rechecks_windows_pin_before_manifest_upload(self):
        bundles = self.bundles()
        self.existing_release({name: bundles[name] for name in ("chromix-linux-x64.zip", "chromix-win-arm64.zip")},
                              tag=self.tag)
        original = self.release_files.pop("SHA256SUMS")
        self.release_files[backup_name(original)] = original
        self.release["assets"] = [{"name": name} for name in self.release_files]
        before = copy.deepcopy(self.release_files)

        def download_then_change_version(*args):
            result = self.fake_gh(*args)
            if args[:2] == ("release", "download") and "chromix-win-arm64.zip" in args:
                self.windows_source_versions = {SHA: self.version}
            return result

        self.gh.side_effect = download_then_change_version
        with self.assertRaisesRegex(ValueError, "Pinned tag commit Chromium version"):
            release.restore_release_manifest(REPO, self.tag, self.release, self.root)
        self.assertEqual(self.release_files, before)
        self.assertEqual(self.mutations, [])

    def test_windows153_arm64_requires_matching_file_and_product_resources(self):
        self.event_run = self.event_response = self.runs["build-win-arm64-github"]
        for member in ("chromix/chrome.exe", "chromix/chrome.dll"):
            for field in ("version", "product_version"):
                with self.subTest(member=member, field=field):
                    bundles = self.incoming()
                    path = next(iter(bundles.values()))
                    values = {"version": self.bundle_version, field: self.version}
                    write_bundle(path, missing=member, extra=(member, arm64_pe(**values)), version=self.bundle_version)
                    with self.assertRaisesRegex(ValueError, "PE version does not match"):
                        release.publish(REPO, self.event_run, self.tag, bundles, self.root)
        self.assertEqual(self.mutations, [])

    def test_windows153_arm64_keeps_native_attempt_and_machine_gates(self):
        self.event_run = self.event_response = self.runs["build-win-arm64-github"]
        valid = native_job(self.event_run)
        for changes in ({"conclusion": "skipped"}, {"run_attempt": 2}, {"labels": ["windows-2022"]}):
            with self.subTest(changes=changes):
                self.native_jobs = [{**valid, **changes}]
                self.run_main()
        self.assertEqual(self.downloads, [])
        self.native_jobs = [valid]
        self.artifact_errors["win-arm64"] = "x64"
        with self.assertRaisesRegex(ValueError, "ARM64 PE"):
            self.run_main()
        self.assertEqual(self.mutations, [])


class PublicationTest(ReleaseFixtureTest):
    def test_publishing_accepts_only_triggering_platform_asset(self):
        for bundles in ({}, self.bundles(), {"chromix-win-x64.zip": self.root / "chromix-mac-x64.zip"}):
            with self.subTest(assets=set(bundles)), self.assertRaisesRegex(ValueError, "triggering platform"):
                release.publish(REPO, self.event_run, TAG, bundles, self.root)
        self.gh.assert_not_called()

    def test_append_to_different_sha_release_preserves_all_assets_hashes_and_provenance(self):
        bundles = self.bundles()
        incoming = {"chromix-win-x64.zip": bundles.pop("chromix-win-x64.zip")}
        sidecar = self.root / "LICENSE.chromium"
        sidecar.write_text("license fixture")
        bundles[sidecar.name] = sidecar
        self.existing_release(bundles, sha=OTHER_SHA)
        self.release_files["unlisted.txt"] = b"untouched metadata"
        self.release["assets"].append({"name": "unlisted.txt"})
        self.release["body"] += f"Source commit: `{'c' * 40}`\n"
        original = copy.deepcopy(self.release_files)
        original_notes = self.release["body"]
        original_refs = copy.deepcopy(self.refs)
        release.publish(REPO, self.event_run, TAG, incoming, self.root)
        backups = {backup_name(original["SHA256SUMS"]), backup_name(self.uploaded_files["SHA256SUMS"])}
        self.assertEqual(set(self.uploaded_files), {"chromix-win-x64.zip", "SHA256SUMS"} | backups)
        for name, data in original.items():
            if name != "SHA256SUMS":
                self.assertEqual(self.release_files[name], data)
        self.assertEqual(self.release_files[backup_name(original["SHA256SUMS"])], original["SHA256SUMS"])
        self.assertEqual(self.release_files[backup_name(self.uploaded_files["SHA256SUMS"])],
                         self.uploaded_files["SHA256SUMS"])
        self.assertEqual(self.refs, original_refs)
        self.assertTrue(self.uploaded_files["SHA256SUMS"].startswith(original["SHA256SUMS"]))
        merged = release.parse_manifest(self.uploaded_files["SHA256SUMS"].decode(), set(original) | release.ASSETS)
        for name, checksum in release.parse_manifest(original["SHA256SUMS"].decode(), set(original)).items():
            self.assertEqual(merged[name], checksum)
        self.assertEqual(set(merged), set(bundles) | set(incoming))
        notes = self.notes[-1]
        self.assertTrue(notes.startswith(original_notes))
        self.assertIn(f"Source commit: `{SHA}`", notes)
        self.assertIn("may use different source commits", notes)
        self.assertNotIn("All five platforms", notes)
        self.assertEqual(set(self.release_downloads), set(bundles) | {"SHA256SUMS"} | backups)
        self.assertTrue(all("--target" not in args for args in self.mutations))
        self.assertTrue(all("--clobber" not in args for args in self.mutations if args[1] == "upload"
                            and Path(args[3]).name != "SHA256SUMS"))

    def test_five_later_platforms_append_to_manual_windows_release_at_distinct_source_shas(self):
        windows = self.incoming()["chromix-win-x64.zip"]
        write_bundle(windows, missing="chromix/LICENSE.chromium")
        initial = {windows.name: windows}
        for name in ("LICENSE.chromix", "LICENSE.chromium"):
            path = self.root / name
            path.write_text(f"sidecar {name}")
            initial[name] = path
        self.existing_release(initial, sha=OTHER_SHA)
        pinned_refs = copy.deepcopy(self.refs)
        for index, name in enumerate(name for name in EXPECTED_WORKFLOWS if name != "build-win-x64-github"):
            with self.subTest(platform=name):
                sha = str(index + 1) * 40
                self.event_run = self.event_response = {**self.runs[name], "head_sha": sha}
                self.pages = [{"workflow_runs": [self.event_run]}]
                before = copy.deepcopy(self.release_files)
                self.uploaded_files.clear()
                self.mutations.clear()
                root = self.root / name
                root.mkdir()
                release.publish(REPO, self.event_run, TAG, self.incoming(), root)
                asset = EXPECTED_WORKFLOWS[name][0] + ".zip"
                backups = {backup_name(before["SHA256SUMS"]), backup_name(self.uploaded_files["SHA256SUMS"])}
                new_backups = backups - set(before)
                self.assertEqual(set(self.uploaded_files), {asset, "SHA256SUMS"} | new_backups)
                self.assertTrue(self.uploaded_files["SHA256SUMS"].startswith(before["SHA256SUMS"]))
                for backup in backups:
                    self.assertIn(backup, self.release_downloads)
                for key, value in before.items():
                    if key != "SHA256SUMS":
                        self.assertEqual(self.release_files[key], value)
                self.assertEqual(self.refs, pinned_refs)
                self.assertIn(f"Source commit: `{sha}`", self.release["body"])
                self.assertIn(f"Workflow: {name} (attempt 1)", self.release["body"])
                self.assertEqual([args[1] for args in self.mutations],
                                 ["upload"] * len(new_backups) + ["edit", "upload", "upload", "edit"])
                edits = [args for args in self.mutations if args[1] == "edit"]
                self.assertNotIn("--draft=false", edits[0])
                self.assertIn("--draft=false", edits[-1])
        backup_assets = {name for name in self.release_files if name.startswith("SHA256SUMS.backup.")}
        self.assertEqual(len(backup_assets), 6)
        for name in backup_assets:
            self.assertEqual(name, backup_name(self.release_files[name]))
        self.assertEqual(set(self.release_files),
                         release.ASSETS | {"SHA256SUMS", "LICENSE.chromix", "LICENSE.chromium"} | backup_assets)
        self.assertIn(f"Source commit: `{OTHER_SHA}`", self.release["body"])
        self.assertEqual(self.release["body"].count("Verified build:"), 5)

    def test_legacy_windows_zip_without_internal_licenses_is_not_repacked_or_revalidated(self):
        bundles = self.bundles()
        windows = bundles["chromix-win-x64.zip"]
        write_bundle(windows, missing="chromix/LICENSE.chromium")
        license_path = self.root / "LICENSE.chromium"
        license_path.write_text("sidecar license")
        self.existing_release({windows.name: windows, license_path.name: license_path}, sha=OTHER_SHA)
        self.event_run = self.event_response = self.runs["build-linux-x64"]
        original = windows.read_bytes()
        release.publish(REPO, self.event_run, TAG, {"chromix-linux-x64.zip": bundles["chromix-linux-x64.zip"]}, self.root)
        self.assertNotIn(windows.name, self.uploaded_files)
        self.assertEqual(self.release_files[windows.name], original)
        self.assertIn(license_path.name.encode(), self.uploaded_files["SHA256SUMS"])

    def test_identical_retry_preserves_provenance_and_does_not_clobber_manifest(self):
        incoming = self.incoming()
        self.existing_release(incoming)
        release.publish(REPO, self.event_run, TAG, incoming, self.root)
        notes = self.notes[-1]
        self.assertEqual(notes.count("Verified build:"), 1)
        self.release["body"] = notes
        second_root = self.root / "retry"
        second_root.mkdir()
        release.publish(REPO, self.event_run, TAG, incoming, second_root)
        self.assertEqual(self.notes[-1], notes)
        self.assertEqual([args[1] for args in self.mutations], ["edit", "edit"])
        self.assertEqual(self.uploaded_files, {})

    def test_legacy_same_source_claim_is_removed_without_removing_provenance(self):
        self.existing_release({})
        self.release["body"] += "All five platforms are verified at one source commit. Old provenance."
        release.publish(REPO, self.event_run, TAG, self.incoming(), self.root)
        self.assertNotIn("All five platforms", self.notes[-1])
        self.assertIn("Old provenance.", self.notes[-1])
        self.assertIn("may use different source commits", self.notes[-1])

    def test_different_published_bytes_are_never_replaced_even_same_version(self):
        bundles = self.incoming()
        self.existing_release(bundles, sha=OTHER_SHA)
        write_bundle(bundles["chromix-win-x64.zip"], extra=("chromix/extra", "different"))
        with self.assertRaisesRegex(ValueError, "Refusing to replace a different published browser"):
            release.publish(REPO, self.event_run, TAG, bundles, self.root)
        self.assertEqual(self.mutations, [])

    def test_existing_manifest_mismatch_fails_before_any_mutation(self):
        bundles = self.incoming()
        self.existing_release(bundles)
        self.release_files["SHA256SUMS"] = f"{'0' * 64}  chromix-win-x64.zip\n".encode("ascii")
        with self.assertRaisesRegex(ValueError, "Existing release checksum mismatch"):
            release.publish(REPO, self.event_run, TAG, bundles, self.root)
        self.assertEqual(self.mutations, [])

    def test_sidecar_checksum_mismatch_is_not_silently_rewritten(self):
        sidecar = self.root / "LICENSE.chromix"
        sidecar.write_text("original license")
        self.existing_release({sidecar.name: sidecar})
        self.release_files[sidecar.name] = b"changed license"
        with self.assertRaisesRegex(ValueError, "Existing release checksum mismatch"):
            release.publish(REPO, self.event_run, TAG, self.incoming(), self.root)
        self.assertEqual(self.mutations, [])

    def test_unrelated_public_browser_without_existing_checksum_is_not_adopted(self):
        bundles = self.bundles()
        self.existing_release({"chromix-linux-x64.zip": bundles["chromix-linux-x64.zip"]})
        self.release_files["SHA256SUMS"] = b""
        with self.assertRaisesRegex(ValueError, "missing existing checksums"):
            release.publish(REPO, self.event_run, TAG, self.incoming(), self.root)
        self.assertEqual(self.downloads, [])
        self.assertEqual(self.mutations, [])

    def test_matching_incoming_public_browser_can_recover_missing_checksum(self):
        incoming = self.incoming()
        self.existing_release(incoming)
        original = self.release_files["chromix-win-x64.zip"]
        self.release_files["SHA256SUMS"] = b""
        release.publish(REPO, self.event_run, TAG, incoming, self.root)
        hashes = release.parse_manifest(self.uploaded_files["SHA256SUMS"].decode())
        self.assertEqual(hashes["chromix-win-x64.zip"], release.digest(incoming["chromix-win-x64.zip"]))
        self.assertEqual(self.downloads, [(self.event_run["id"], "chromix-win-x64")])
        self.assertEqual(self.release_files["chromix-win-x64.zip"], original)
        self.assertEqual(set(self.uploaded_files), {"SHA256SUMS", backup_name(b""),
                                                  backup_name(self.uploaded_files["SHA256SUMS"])})

    def test_recovered_slot_must_match_fresh_artifact_not_just_local_bytes(self):
        incoming = self.incoming()
        write_bundle(incoming["chromix-win-x64.zip"], extra=("chromix/extra", "untrusted"))
        self.existing_release(incoming)
        self.release_files["SHA256SUMS"] = b""
        with self.assertRaisesRegex(ValueError, "differs from verified incoming artifact"):
            release.publish(REPO, self.event_run, TAG, incoming, self.root)
        self.assertEqual(self.downloads, [(self.event_run["id"], "chromix-win-x64")])
        self.assertEqual(self.mutations, [])

    def test_orphan_recollection_keeps_artifact_validation_fail_closed(self):
        incoming = self.incoming()
        self.existing_release(incoming)
        self.release_files["SHA256SUMS"] = b""
        for error in ("layout", "checksum", "missing-checksum", "foreign-checksum", "unexpected", "corrupt", "expired"):
            with self.subTest(error=error):
                root = self.root / error
                root.mkdir()
                self.downloads.clear()
                self.artifact_errors["chromix-win-x64"] = error
                with self.assertRaises((ValueError, zipfile.BadZipFile, RuntimeError)):
                    release.publish(REPO, self.event_run, TAG, incoming, root)
                self.assertEqual(self.downloads, [(self.event_run["id"], "chromix-win-x64")])
                self.assertEqual(self.mutations, [])

    def test_rerun_during_existing_asset_download_blocks_all_mutations(self):
        self.existing_release(self.incoming())
        original_gh = self.fake_gh

        def download_then_rerun(*args):
            result = original_gh(*args)
            if args[:2] == ("release", "download"):
                self.event_response = {**self.event_run, "run_attempt": 2, "status": "in_progress", "conclusion": None}
            return result

        self.gh.side_effect = download_then_rerun
        release.publish(REPO, self.event_run, TAG, self.incoming(), self.root)
        self.assertIn("Pending release", self.stdout.getvalue())
        self.assertEqual(self.mutations, [])

    def test_existing_manifest_cannot_reference_missing_assets(self):
        self.existing_release(self.incoming())
        self.release["assets"] = [{"name": "SHA256SUMS"}]
        with self.assertRaisesRegex(ValueError, "references missing release assets"):
            release.publish(REPO, self.event_run, TAG, self.incoming(), self.root)
        self.assertEqual(self.mutations, [])

    def test_duplicate_or_unsafe_existing_manifest_entries_fail_closed(self):
        self.existing_release(self.incoming())
        self.release_files["SHA256SUMS"] *= 2
        with self.assertRaisesRegex(ValueError, "Invalid or duplicate"):
            release.publish(REPO, self.event_run, TAG, self.incoming(), self.root)
        self.assertEqual(self.mutations, [])

    def test_duplicate_release_asset_names_fail_closed(self):
        self.existing_release(self.incoming())
        self.release["assets"].append({"name": "chromix-win-x64.zip"})
        with self.assertRaisesRegex(ValueError, "Duplicate existing release asset"):
            release.publish(REPO, self.event_run, TAG, self.incoming(), self.root)
        self.assertEqual(self.mutations, [])

    def test_existing_manifest_bytes_are_preserved_including_crlf_uppercase_and_no_newline(self):
        bundles = self.bundles()
        self.existing_release({"chromix-linux-x64.zip": bundles["chromix-linux-x64.zip"]})
        checksum = release.digest(bundles["chromix-linux-x64.zip"]).upper()
        original = f"\r\n{checksum} *chromix-linux-x64.zip".encode()
        self.release_files["SHA256SUMS"] = original
        release.publish(REPO, self.event_run, TAG, self.incoming(), self.root)
        self.assertTrue(self.uploaded_files["SHA256SUMS"].startswith(original + b"\n"))
        self.assertEqual(len(release.parse_manifest(self.uploaded_files["SHA256SUMS"].decode())), 2)

    def test_manifest_upload_failure_restores_old_manifest_and_retry_recovers_remote_zip(self):
        self.existing_release({})
        original = self.release_files["SHA256SUMS"]
        incoming = self.incoming()
        self.fail_upload = "SHA256SUMS"
        with self.assertRaises(subprocess.CalledProcessError):
            release.publish(REPO, self.event_run, TAG, incoming, self.root)
        self.assertEqual(self.uploaded_files["SHA256SUMS"], original)
        self.assertEqual(self.release_files["SHA256SUMS"], original)
        self.assertEqual(self.release_files["chromix-win-x64.zip"], incoming["chromix-win-x64.zip"].read_bytes())
        self.assertEqual([args[1] for args in self.mutations], ["upload", "upload", "edit", "upload", "upload", "upload"])
        self.assertNotIn("--draft=false", self.mutations[2])
        self.assertIn(f"Source commit: `{SHA}`", self.release["body"])
        self.assertIn("existing", self.mutations[-1][3])
        backups = {name: data for name, data in self.release_files.items() if name.startswith("SHA256SUMS.backup.")}
        self.assertEqual(len(backups), 2)
        self.assertEqual(backups[backup_name(original)], original)
        retry = self.root / "retry"
        retry.mkdir()
        release.publish(REPO, self.event_run, TAG, incoming, retry)
        self.assertEqual(self.downloads, [(self.event_run["id"], "chromix-win-x64")])
        self.assertEqual(len([args for args in self.mutations if args[1] == "upload"
                              and Path(args[3]).name == "chromix-win-x64.zip"]), 1)
        hashes = release.parse_manifest(self.release_files["SHA256SUMS"].decode())
        self.assertEqual(hashes, {"chromix-win-x64.zip": release.digest(incoming["chromix-win-x64.zip"])})
        for name, data in backups.items():
            self.assertEqual(self.release_files[name], data)
        self.assertEqual(self.mutations[-1][1], "edit")

    def test_partial_draft_is_completed_without_waiting_for_other_platforms(self):
        incoming = self.incoming()
        self.existing_release(incoming, draft=True, sha=OTHER_SHA)
        self.refs = []
        self.release_files.pop("SHA256SUMS")
        self.release["assets"] = [{"name": "chromix-win-x64.zip"}]
        release.publish(REPO, self.event_run, TAG, incoming, self.root)
        self.assertEqual(set(self.uploaded_files), {"SHA256SUMS", backup_name(self.uploaded_files["SHA256SUMS"])})
        self.assertEqual(self.downloads, [(self.event_run["id"], "chromix-win-x64")])
        self.assertFalse(self.release["draft"])
        self.assertEqual(self.mutations[-1][1], "edit")
        self.assertIn("--draft=false", self.mutations[-1])
        self.assertNotIn("--target", self.mutations[-1])


if __name__ == "__main__":
    unittest.main()
