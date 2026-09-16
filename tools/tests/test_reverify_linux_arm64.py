"""Pinned prebuilt-only recovery fixtures; no native runtime claim or compilation."""
from contextlib import nullcontext
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import stat
import struct
import sys
import time
import zipfile

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import download_posix_snapshot as download
import reverify_linux_arm64 as recovery
from test_download_posix_snapshot import HTTPSFixture, Response, SIGNED, TOKEN


def dispatch():
    return {"build_mode": "verify", "resume_run_id": str(recovery.DONOR_RUN), "resume_attempt": "1",
            "resume_tree_stage": "final", "resume_artifact_ids": "10465215017,10464950664",
            "compile_jobs": "auto", "build_profile": "fast", "use_upstream_cache": True}


def test_explicit_final_dispatch_accepts_either_id_order():
    inputs = dispatch()
    recovery.dispatch_guard(inputs, "workflow_dispatch", recovery.REPOSITORY)
    inputs["resume_artifact_ids"] = "10464950664,10465215017"
    recovery.dispatch_guard(inputs, "workflow_dispatch", recovery.REPOSITORY)


@pytest.mark.parametrize("key,value", [
    ("build_mode", "staged"), ("build_mode", True), ("resume_run_id", recovery.DONOR_RUN),
    ("resume_run_id", "1"), ("resume_attempt", True), ("resume_attempt", 1), ("resume_attempt", "2"),
    ("resume_tree_stage", "7"), ("resume_tree_stage", "1"), ("resume_tree_stage", ""),
    ("compile_jobs", "2"), ("build_profile", "release"), ("use_upstream_cache", "true"),
    ("use_upstream_cache", 1), ("use_upstream_cache", False), ("resume_artifact_ids", "10465215017"),
    ("resume_artifact_ids", "10465215017,10465215017"),
    ("resume_artifact_ids", "10465215017,10464950664,10464790799"),
    ("resume_artifact_ids", "10465215017,10464492257"), ("resume_artifact_ids", [10465215017,10464950664]),
])
def test_dispatch_type_and_checkpoint_guards(key, value):
    inputs = dispatch()
    inputs[key] = value
    with pytest.raises(ValueError):
        recovery.dispatch_guard(inputs, "workflow_dispatch", recovery.REPOSITORY)


@pytest.mark.parametrize("event,repo", [("push", recovery.REPOSITORY), ("workflow_dispatch", "fork/Chromix")])
def test_dispatch_origin(event, repo):
    with pytest.raises(ValueError):
        recovery.dispatch_guard(dispatch(), event, repo)


class MetadataFixture:
    def __init__(self):
        self.run = {"id": recovery.DONOR_RUN, "run_attempt": 1, "name": recovery.WORKFLOW,
                    "path": recovery.WORKFLOW_PATH, "workflow_id": recovery.WORKFLOW_ID,
                    "head_sha": recovery.DONOR_SHA, "head_branch": recovery.DONOR_BRANCH,
                    "event": "workflow_dispatch", "status": "completed", "conclusion": "failure",
                    "repository": {"full_name": recovery.REPOSITORY, "id": recovery.REPOSITORY_ID},
                    "head_repository": {"full_name": recovery.REPOSITORY, "id": recovery.REPOSITORY_ID}}
        self.attempt = deepcopy(self.run)
        self.job = {"id": recovery.DONOR_JOB, "name": recovery.DONOR_JOB_NAME, "run_id": recovery.DONOR_RUN,
                    "run_attempt": 1, "head_sha": recovery.DONOR_SHA, "head_branch": recovery.DONOR_BRANCH,
                    "workflow_name": recovery.WORKFLOW, "status": "completed", "conclusion": "success",
                    "started_at": "2026-09-16T14:58:28Z", "completed_at": "2026-09-16T19:16:41Z",
                    "steps": [
                        {"name": "Run stage 1", "status": "completed", "conclusion": "success",
                         "started_at": "2026-09-16T15:07:13Z", "completed_at": "2026-09-16T19:16:02Z"},
                        {"name": "Upload final bundle", "status": "completed", "conclusion": "success",
                         "started_at": "2026-09-16T19:16:02Z", "completed_at": "2026-09-16T19:16:06Z"},
                        {"name": "Upload fingerprint source receipt", "status": "completed", "conclusion": "success",
                         "started_at": "2026-09-16T19:16:08Z", "completed_at": "2026-09-16T19:16:09Z"}]}
        self.jobs = [self.job]
        self.artifacts = []
        for item, created in zip(recovery.ARTIFACTS, ("2026-09-16T19:16:06Z", "2026-09-16T19:16:09Z")):
            self.artifacts.append({**item, "created_at": created, "updated_at": created,
                "workflow_run": {"id": recovery.DONOR_RUN, "head_sha": recovery.DONOR_SHA,
                                 "head_branch": recovery.DONOR_BRANCH, "repository_id": recovery.REPOSITORY_ID,
                                 "head_repository_id": recovery.REPOSITORY_ID}})

    def get(self, path):
        return self.attempt if path.endswith("/attempts/1") else self.run

    def items(self, path, key):
        return self.jobs if key == "jobs" else self.artifacts


def test_successful_stage_from_overall_failed_run_is_allowed():
    report = recovery.validate_metadata(MetadataFixture())
    assert report["run_conclusion"] == "failure"
    assert report["source_sha"] == recovery.DONOR_SHA
    assert report["job_id"] == recovery.DONOR_JOB
    assert len(report["artifacts"]) == 2


@pytest.mark.parametrize("target,key,value", [
    ("run", "run_attempt", True), ("run", "run_attempt", 2), ("attempt", "run_attempt", 1.0),
    ("attempt", "head_sha", "a" * 40), ("run", "name", "build-linux-x64"),
    ("run", "path", ".github/workflows/other.yml"), ("run", "workflow_id", 1),
    ("run", "event", "push"), ("run", "head_branch", "main"), ("run", "status", "in_progress"),
    ("run", "conclusion", "cancelled"), ("run", "repository", {"full_name": "fork/Chromix", "id": 1}),
    ("attempt", "head_repository", {"full_name": recovery.REPOSITORY, "id": True}),
    ("job", "run_attempt", True), ("job", "run_id", 1), ("job", "head_sha", "a" * 40),
    ("job", "head_branch", "main"), ("job", "conclusion", "failure"), ("job", "status", "queued"),
])
def test_metadata_origin_attempt_and_success_are_strict(target, key, value):
    fixture = MetadataFixture()
    getattr(fixture, target)[key] = value
    with pytest.raises(ValueError):
        recovery.validate_metadata(fixture)


@pytest.mark.parametrize("index", range(3))
@pytest.mark.parametrize("conclusion", ["skipped", "failure", None])
def test_each_build_and_upload_step_must_succeed(index, conclusion):
    fixture = MetadataFixture()
    fixture.job["steps"][index]["conclusion"] = conclusion
    with pytest.raises(ValueError):
        recovery.validate_metadata(fixture)


@pytest.mark.parametrize("key,value", [
    ("id", 1), ("size_in_bytes", True), ("size_in_bytes", 18226.0), ("expired", 0), ("expired", True),
    ("digest", "sha256:" + "0" * 64), ("created_at", "2026-09-16T19:16:07Z"),
    ("updated_at", "2026-09-16T19:16:10Z"), ("workflow_run", {}),
])
def test_source_artifact_pin_and_upload_window(key, value):
    fixture = MetadataFixture()
    fixture.artifacts[1][key] = value
    with pytest.raises(ValueError):
        recovery.validate_metadata(fixture)


@pytest.mark.parametrize("target", ["artifacts", "jobs", "steps"])
def test_ambiguous_metadata_rejected(target):
    fixture = MetadataFixture()
    values = fixture.job["steps"] if target == "steps" else getattr(fixture, target)
    values.append(deepcopy(values[0]))
    with pytest.raises(ValueError):
        recovery.validate_metadata(fixture)


def opener(client, responses):
    fixture = HTTPSFixture(responses)
    client.opener = recovery.urllib.request.build_opener(
        recovery.urllib.request.ProxyHandler({}), download.NoRedirect(), fixture)
    return fixture


def test_metadata_redirect_is_never_followed_or_exposed():
    client = recovery.Metadata(TOKEN)
    fixture = opener(client, [Response(status=302, headers={"Location": SIGNED})])
    with pytest.raises(ValueError, match="metadata_request_failed") as error:
        client.get(f"/actions/runs/{recovery.DONOR_RUN}")
    assert SIGNED not in str(error.value) and TOKEN not in str(error.value)
    assert len(fixture.requests) == 1


def test_reused_download_drops_authorization_and_checks_digest_size(tmp_path):
    data = b"outer artifact fixture"
    client = recovery.Metadata(TOKEN)
    fixture = opener(client, [Response(status=302, headers={"Location": SIGNED}), Response(data)])
    artifact = {"id": 1, "size_in_bytes": len(data), "digest": "sha256:" + hashlib.sha256(data).hexdigest()}
    record = {"attempts": []}
    path = client.download(recovery.REPOSITORY, artifact, tmp_path, time.monotonic() + 60, record)
    assert path.read_bytes() == data
    assert fixture.requests[0].get_header("Authorization") == "Bearer " + TOKEN
    assert fixture.requests[1].get_header("Authorization") is None
    assert record["attempts"][0]["status"] == "success"


@pytest.mark.parametrize("mismatch", ["size_in_bytes", "digest"])
def test_download_integrity_failure_never_publishes(tmp_path, mismatch):
    data = b"wrong outer artifact"
    client = recovery.Metadata(TOKEN)
    opener(client, [Response(data)])
    artifact = {"id": 1, "size_in_bytes": len(data), "digest": "sha256:" + hashlib.sha256(data).hexdigest()}
    artifact[mismatch] = len(data) + 1 if mismatch == "size_in_bytes" else "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        client.download(recovery.REPOSITORY, artifact, tmp_path, time.monotonic() + 60, {"attempts": []})
    assert not list(tmp_path.iterdir())


def make_zip(path, entries):
    with zipfile.ZipFile(path, "w") as archive:
        for name, mode, data in entries:
            info = zipfile.ZipInfo(name)
            info.external_attr = mode << 16
            archive.writestr(info, data)


@pytest.mark.parametrize("name,mode", [("../source-final.json", stat.S_IFREG),
    ("/source-final.json", stat.S_IFREG), ("source-final.json", stat.S_IFLNK),
    ("source-final.json", stat.S_IFIFO), ("source-final.json\x00bad", stat.S_IFREG)])
def test_outer_paths_and_types_are_rejected(tmp_path, name, mode):
    archive = tmp_path / "outer.zip"
    make_zip(archive, [(name, mode, b"receipt")])
    if "\x00" in name:
        data = archive.read_bytes().replace(b"source-final.json", b"source-final\x00json")
        archive.write_bytes(data)
    with pytest.raises(ValueError):
        recovery.extract_outer(archive, tmp_path / "out", {"source-final.json": 100})


def test_outer_crc_failure(tmp_path):
    archive = tmp_path / "outer.zip"
    make_zip(archive, [("source-final.json", stat.S_IFREG, b"receipt-original")])
    archive.write_bytes(archive.read_bytes().replace(b"receipt-original", b"receipt-corrupt!"))
    with pytest.raises(zipfile.BadZipFile):
        recovery.extract_outer(archive, tmp_path / "out", {"source-final.json": 100})


def elf(machine=183):
    return b"\x7fELF\x02\x01\x01" + b"\0" * 9 + struct.pack("<HHIQQQIHHHHHH", 3, machine, 1,
                                                            0, 0, 0, 0, 64, 0, 0, 0, 0, 0)


def bundle_entries(machine=183):
    return [("chromix/chromix", stat.S_IFREG | 0o755, b"#!/bin/sh\n"),
            *(("chromix/" + name, stat.S_IFREG | 0o755, elf(machine))
              for name in ("chrome", "chrome-sandbox", "chrome_crashpad_handler"))]


def test_inner_extract_preserves_executable_modes_and_checks_native_elf(tmp_path):
    archive = tmp_path / "inner.zip"
    make_zip(archive, bundle_entries())
    report = recovery.extract_bundle(archive, tmp_path / "bundle")
    assert report["static"]["status"] == "passed"
    assert report["static"]["elf_count"] == 3
    assert report["runtime"]["status"] == "not_run"
    make_zip(archive, bundle_entries(62))
    with pytest.raises(ValueError, match="architecture"):
        recovery.extract_bundle(archive, tmp_path / "wrong")


@pytest.mark.parametrize("entry", [("chromix/../escape", stat.S_IFREG, b"unsafe"),
    ("chromix/link", stat.S_IFLNK, b"../../escape"), ("chromix/chrome", stat.S_IFREG, b"duplicate")])
def test_inner_safe_extraction(tmp_path, entry):
    archive = tmp_path / "inner.zip"
    with pytest.warns(UserWarning) if entry[0] == "chromix/chrome" else nullcontext():
        make_zip(archive, [*bundle_entries(), entry])
    with pytest.raises(ValueError):
        recovery.extract_bundle(archive, tmp_path / "bundle")


@pytest.mark.parametrize("mutation", ["valid", "duplicate", "wrong_name", "wrong_digest", "corrupt", "size"])
def test_inner_checksum_manifest_is_exact_and_hashes_actual_zip(tmp_path, monkeypatch, mutation):
    inner = tmp_path / "chromix-linux-arm64.zip"
    inner.write_bytes(b"pinned inner ZIP bytes")
    digest = recovery.sha256(inner)
    monkeypatch.setattr(recovery, "INNER_SHA", digest)
    monkeypatch.setattr(recovery, "INNER_SIZE", inner.stat().st_size)
    line = digest + "  chromix-linux-arm64.zip\n"
    if mutation == "duplicate":
        line += line
    elif mutation == "wrong_name":
        line = line.replace("chromix-linux-arm64.zip", "../chromix-linux-arm64.zip")
    elif mutation == "wrong_digest":
        line = "0" * 64 + line[64:]
    elif mutation == "corrupt":
        inner.write_bytes(b"changed inner ZIP data")
    elif mutation == "size":
        inner.write_bytes(b"short")
    (tmp_path / "SHA256SUMS").write_text(line)
    if mutation == "valid":
        assert recovery.verify_inner(tmp_path) == inner
    else:
        with pytest.raises(ValueError):
            recovery.verify_inner(tmp_path)


def test_inner_crc_failure(tmp_path):
    archive = tmp_path / "inner.zip"
    make_zip(archive, bundle_entries())
    archive.write_bytes(archive.read_bytes().replace(b"#!/bin/sh\n", b"#!/bin/xx\n"))
    with pytest.raises(ValueError, match="inner_crc_failure"):
        recovery.extract_bundle(archive, tmp_path / "bundle")


def source_fixture(tmp_path, monkeypatch):
    inputs, patches = recovery.load_stack(recovery.REPO)
    lite_root = recovery.REPO / "build/windows/lite-tarball-files"
    files = [{"path": p.relative_to(lite_root).as_posix(), "sha256": recovery.sha256(p),
              "mode": stat.S_IMODE(p.stat().st_mode)} for p in sorted(lite_root.rglob("*")) if p.is_file()]
    data = {"schema_version": 1, "status": "verified", "method": "reverse-forward-in-scratch",
            "domain_substituted": True, "patch_count": 187,
            "identity": {"platform": "linux", "schema_version": 1, "series": {
                "sha256": inputs["series_sha256"], "patches": inputs["patches"]},
                "lite": {"path": "build/windows/lite-tarball-files", "files": files}},
            "outputs": {entry[0]: "a" * 64 for _, _, entries in patches for entry in entries}}
    path = tmp_path / "source-final.json"
    path.write_text(json.dumps(data))
    monkeypatch.setattr(recovery, "SOURCE_SHA", recovery.sha256(path))
    monkeypatch.setattr(recovery, "SOURCE_SIZE", path.stat().st_size)
    return path, data


def test_current_187_source_stack_and_exact_target_coverage(tmp_path, monkeypatch):
    path, data = source_fixture(tmp_path, monkeypatch)
    result = recovery.validate_source(path)
    assert result["patch_count"] == 187
    assert result["check"] == "producer-receipt-only"
    assert result["donor_sha"] == recovery.DONOR_SHA
    path.write_text(path.read_text() + " ")
    with pytest.raises(ValueError):
        recovery.validate_source(path)


@pytest.mark.parametrize("change", ["patch", "targets", "count", "lite", "version"])
def test_changed_source_inputs_cannot_reuse_bundle(tmp_path, monkeypatch, change):
    path, data = source_fixture(tmp_path, monkeypatch)
    if change == "patch":
        data["identity"]["series"]["patches"][0]["sha256"] = "b" * 64
    elif change == "targets":
        data["outputs"].pop(next(iter(data["outputs"])))
    elif change == "count":
        data["patch_count"] = True
    elif change == "lite":
        data["identity"]["lite"]["files"] = []
    else:
        monkeypatch.setattr(recovery, "load_pins", lambda *_: {"ChromiumVersion": "152.0.0.0"})
    path.write_text(json.dumps(data))
    monkeypatch.setattr(recovery, "SOURCE_SHA", recovery.sha256(path))
    monkeypatch.setattr(recovery, "SOURCE_SIZE", path.stat().st_size)
    with pytest.raises(ValueError):
        recovery.validate_source(path)


def final_fixture(tmp_path, monkeypatch):
    diagnostics = tmp_path / "diagnostics"
    diagnostics.mkdir()
    acceptance_dir = diagnostics / "acceptance"
    acceptance_dir.mkdir()
    verifier = {"sha": "a" * 40}
    monkeypatch.setattr(recovery, "verifier_identity", lambda: verifier)
    monkeypatch.setattr(recovery, "validate_source", lambda _: {"sha256": recovery.SOURCE_SHA})
    monkeypatch.setenv("ACCEPTANCE_OUTCOME", "success")
    browser = tmp_path / "bundle/chromix/chrome"
    browser.parent.mkdir(parents=True)
    browser.write_bytes(b"pinned browser")
    monkeypatch.setattr(recovery, "BROWSER_SHA", recovery.sha256(browser))
    prepared = {"status": "prepared", "verifier": verifier, "donor": {"run_id": recovery.DONOR_RUN}}
    (diagnostics / "preparation.json").write_text(json.dumps(prepared))
    native = {"runtime": {"status": "passed", "host_arch": "arm64", "chromium_version": recovery.VERSION}}
    (diagnostics / "native-smoke.json").write_text(json.dumps(native))
    acceptance = {"ci_gate_passed": True, "control": False, "errors": [], "status": "incomplete",
                  "browser": {"sha256": recovery.BROWSER_SHA, "version": recovery.VERSION},
                  "source": {"sha256": recovery.SOURCE_SHA, "check": "producer-receipt-only"},
                  "provenance": {"commit": verifier["sha"], "dirty": False}, "suites": [],
                  "gaps": ["optional capability"], "full_acceptance": False}
    for name, _, _ in recovery.SUITES:
        report = acceptance_dir / (name + ".json")
        report.write_text("{}")
        acceptance["suites"].append({"name": name, "errors": [], "timed_out": False, "cleanup_errors": [],
                                    "report": report.name, "report_sha256": recovery.sha256(report)})
    path = acceptance_dir / "acceptance.json"
    path.write_text(json.dumps(acceptance))
    return path, acceptance


def test_final_result_binds_donor_verifier_and_unchanged_gate_semantics(tmp_path, monkeypatch):
    final_fixture(tmp_path, monkeypatch)
    result = {}
    recovery.finalize(tmp_path, result)
    assert result["status"] == "reverified" and result["ci_gate_passed"] is True
    assert result["donor"]["run_id"] == recovery.DONOR_RUN
    assert result["verifier"]["sha"] == "a" * 40
    assert result["full_acceptance"] is False
    assert result["gaps"] == ["optional capability"]


@pytest.mark.parametrize("change", ["failed", "version", "browser", "source", "commit", "dirty", "missing_suite",
                                     "timed_out", "cleanup", "suite_changed", "step_failed", "gate_bool"])
def test_final_result_cannot_mask_gate_failures(tmp_path, monkeypatch, change):
    path, report = final_fixture(tmp_path, monkeypatch)
    if change == "failed":
        report["errors"] = ["identity failed"]
    elif change in ("version", "browser"):
        report["browser"]["version" if change == "version" else "sha256"] = "wrong"
    elif change == "source":
        report["source"]["sha256"] = "wrong"
    elif change in ("commit", "dirty"):
        report["provenance"][change] = "wrong"
    elif change == "missing_suite":
        report["suites"].pop()
    elif change in ("timed_out", "cleanup"):
        report["suites"][0]["timed_out" if change == "timed_out" else "cleanup_errors"] = True
    elif change == "suite_changed":
        (path.parent / "identity.json").write_text('{"changed":true}')
    elif change == "step_failed":
        monkeypatch.setenv("ACCEPTANCE_OUTCOME", "failure")
    else:
        report["ci_gate_passed"] = 1
    path.write_text(json.dumps(report))
    with pytest.raises(ValueError):
        recovery.finalize(tmp_path, {})


def test_failed_finalization_still_writes_diagnostics(tmp_path, monkeypatch):
    monkeypatch.setenv("REVERIFY_INPUTS", json.dumps(dispatch()))
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("GITHUB_REPOSITORY", recovery.REPOSITORY)
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    assert recovery.main(["finalize", "--prebuilt-only", "--directory", str(tmp_path)]) == 1
    result = json.loads((tmp_path / "diagnostics/reverified.json").read_text())
    assert result["status"] == "failed" and result["ci_gate_passed"] is False


def test_registered_workflow_isolates_verify_from_all_build_paths():
    workflow = yaml.safe_load((recovery.REPO / recovery.WORKFLOW_PATH).read_text())
    inputs = workflow[True]["workflow_dispatch"]["inputs"]
    assert inputs["build_mode"]["options"] == ["staged", "single", "verify"]
    assert "final" in inputs["resume_tree_stage"]["description"]
    assert "bundle + source receipt" in inputs["resume_artifact_ids"]["description"]
    build = workflow["jobs"]["build"]
    assert build["if"] == "${{ inputs.build_mode != 'verify' }}"
    job = workflow["jobs"]["reverify"]
    assert job["if"] == "${{ github.event_name == 'workflow_dispatch' && inputs.build_mode == 'verify' }}"
    assert job["runs-on"] == "ubuntu-24.04-arm" and "needs" not in job
    assert job["env"]["REVERIFY_INPUTS"] == "${{ toJSON(inputs) }}"
    steps = job["steps"]
    script = "\n".join(step.get("run", "") for step in steps)
    assert 'TMPDIR=${RUNNER_TEMP}/chromix-arm64-reverify-tmp' in script
    assert "--prebuilt-only" in script
    assert "--source-report" in script and "fingerprint_acceptance.py" in script
    assert "--expected-version 153.0.8010.36" in script
    assert recovery.BROWSER_SHA in script
    assert "prepare-ci-sandbox.sh" in script and "--arch arm64 --runtime" in script
    assert "fingerprint-requirements.txt" in script
    for forbidden in ("ci-stage.sh", "ninja ", "restore-snapshot", "gen_posix", "--control", "--skip", "--no-sandbox"):
        assert forbidden not in script
    assert all("continue-on-error" not in step for step in steps)
    assert steps[-1]["if"] == "always()" and steps[-2]["if"] == "always()"
    assert steps[-1]["with"]["path"].endswith("/diagnostics/")
