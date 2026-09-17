#!/usr/bin/env python3
"""Reverify one immutable Linux 153 ARM64 final bundle; never restore or compile."""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile

from download_posix_snapshot import GitHub, SnapshotError, require, require_space, write_report
from fingerprint_acceptance import SUITES, check_source, read_json
from platform_pins import load_pins
from verify_linux_bundle import validate_bundle
from verify_patch_stack import load_stack

REPO = Path(__file__).resolve().parents[1]
REPOSITORY = "xiaozhou26/Chromix"
REPOSITORY_ID = 1342691290
WORKFLOW = "build-linux-arm64"
WORKFLOW_PATH = f".github/workflows/{WORKFLOW}.yml"
WORKFLOW_ID = 353725464
DONOR_RUN = 35112146785
DONOR_ATTEMPT = 1
DONOR_SHA = "d80f322148d8c64271b27b48d5b94291b67ab6bd"
DONOR_BRANCH = "build/linux153-cache347578-20260914"
DONOR_JOB = 104848353557
DONOR_JOB_NAME = "Linux arm64 (x64-host build + native smoke) / linux-arm64 stage 1 (prepare + first compile)"
VERSION = "153.0.8010.36"
BROWSER_SHA = "be8a47546e2771d20b7ffdde88059e6ae83d840ce03145b0a23a9acaf076c33f"
INNER_SHA = "851b2ee8dbefa69092115c023b1a59f6044399b4604ae754767c42d65a1c54e1"
INNER_SIZE = 249090640
SOURCE_SHA = "98f04f0b2775528ef79b6daf1f8cffeb0076f8523a5d23452d9e0455971453d5"
SOURCE_SIZE = 57287
SERIES_SHA = "e8063741e4dcdc4573d269b1ddf55e3ccf9e7e49b503cad90155eda6215f83b9"
ARTIFACTS = (
    {"id": 10465215017, "name": "chromix-linux-arm64", "size_in_bytes": 249091002,
     "digest": "sha256:bd25f45e52e5b4a7c4a57c6de2b90ce8131b4604a60221b7719988fd668f93ae",
     "expired": False},
    {"id": 10464950664, "name": "chromix-linux-arm64-fingerprint-source", "size_in_bytes": 18226,
     "digest": "sha256:974edfaf7410a044916e21a5af55373501a263539f805d359e11bcd8be847c63",
     "expired": False},
)
LIMIT = 2 * 1024 * 1024


def matches(actual, expected, label):
    require(isinstance(actual, dict), label)
    for key, value in expected.items():
        require(type(actual.get(key)) is type(value) and actual[key] == value, label + ": " + key)


def dispatch_guard(inputs, event, repository):
    require(event == "workflow_dispatch" and repository == REPOSITORY, "wrong_dispatch_origin")
    require(isinstance(inputs, dict), "invalid_dispatch_inputs")
    matches(inputs, {"build_mode": "verify", "resume_run_id": str(DONOR_RUN),
                     "resume_attempt": str(DONOR_ATTEMPT), "resume_tree_stage": "final",
                     "compile_jobs": "auto", "build_profile": "fast", "use_upstream_cache": True},
            "verify_requires_final_bundle_not_tree_or_build_options")
    ids = inputs.get("resume_artifact_ids")
    require(isinstance(ids, str) and re.fullmatch(r"[1-9][0-9]*(?:,[1-9][0-9]*)", ids),
            "invalid_artifact_ids")
    identifiers = [int(value) for value in ids.split(",")]
    require(len(identifiers) == 2 and set(identifiers) == {a["id"] for a in ARTIFACTS},
            "complete_pinned_bundle_and_source_ids_required")


class Metadata(GitHub):
    """Use the download client's no-proxy, no-redirect opener for API JSON too."""

    def get(self, path):
        require(path.startswith("/actions/") and not any(c in path for c in "\r\n#"), "invalid_api_path")
        request = urllib.request.Request(f"https://api.github.com/repos/{REPOSITORY}" + path,
            headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
        request.add_unredirected_header("Authorization", "Bearer " + self.token)
        try:
            with self.opener.open(request, timeout=60) as response:
                require(response.status == 200, "metadata_http_status")
                data = response.read(LIMIT + 1)
        except (urllib.error.URLError, OSError):
            raise SnapshotError("metadata_request_failed") from None
        require(len(data) <= LIMIT, "metadata_size_limit")
        result = json.loads(data)
        require(isinstance(result, dict), "invalid_metadata")
        return result

    def items(self, path, key):
        result, total = [], None
        for page in range(1, 21):
            data = self.get(f"{path}?per_page=100&page={page}")
            count, batch = data.get("total_count"), data.get(key)
            require(type(count) is int and 0 <= count <= 2000 and isinstance(batch, list)
                    and all(isinstance(item, dict) for item in batch), "invalid_pagination")
            require(total is None or count == total, "metadata_changed_during_pagination")
            total = count
            result.extend(batch)
            if len(result) == total:
                return result
            require(batch and len(result) < total, "incomplete_pagination")
        raise SnapshotError("pagination_limit")


def timestamp(value):
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value),
            "invalid_metadata_timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate_metadata(client):
    run_path = f"/actions/runs/{DONOR_RUN}"
    expected_run = {"id": DONOR_RUN, "run_attempt": DONOR_ATTEMPT, "name": WORKFLOW,
                    "path": WORKFLOW_PATH, "workflow_id": WORKFLOW_ID, "head_sha": DONOR_SHA,
                    "head_branch": DONOR_BRANCH, "event": "workflow_dispatch", "status": "completed"}
    runs = [client.get(run_path), client.get(run_path + f"/attempts/{DONOR_ATTEMPT}")]
    for run in runs:
        matches(run, expected_run, "donor_run_mismatch")
        require(run.get("conclusion") in ("success", "failure"), "donor_run_not_terminal")
        for key in ("repository", "head_repository"):
            matches(run.get(key), {"full_name": REPOSITORY, "id": REPOSITORY_ID}, "donor_repository_mismatch")
    jobs = client.items(run_path + f"/attempts/{DONOR_ATTEMPT}/jobs", "jobs")
    candidates = [j for j in jobs if j.get("id") == DONOR_JOB or j.get("name") == DONOR_JOB_NAME]
    require(len(candidates) == 1, "missing_or_ambiguous_build_job")
    job = candidates[0]
    matches(job, {"id": DONOR_JOB, "name": DONOR_JOB_NAME, "run_id": DONOR_RUN,
                  "run_attempt": DONOR_ATTEMPT, "head_sha": DONOR_SHA, "head_branch": DONOR_BRANCH,
                  "workflow_name": WORKFLOW, "status": "completed", "conclusion": "success"},
            "donor_build_job_mismatch")
    steps = job.get("steps")
    require(isinstance(steps, list) and all(isinstance(s, dict) for s in steps), "invalid_build_steps")
    successful = {}
    for name in ("Run stage 1", "Upload final bundle", "Upload fingerprint source receipt"):
        found = [s for s in steps if s.get("name") == name]
        require(len(found) == 1, "missing_or_duplicate_build_step")
        matches(found[0], {"status": "completed", "conclusion": "success"}, "unsuccessful_build_step")
        require(timestamp(job["started_at"]) <= timestamp(found[0]["started_at"])
                <= timestamp(found[0]["completed_at"]) <= timestamp(job["completed_at"]), "invalid_step_window")
        successful[name] = found[0]
    artifacts = client.items(run_path + "/artifacts", "artifacts")
    selected = [a for a in artifacts if a.get("name") in {p["name"] for p in ARTIFACTS}
                or a.get("id") in {p["id"] for p in ARTIFACTS}]
    require(len(selected) == len(ARTIFACTS), "incomplete_or_ambiguous_final_artifacts")
    for pinned, step_name in zip(ARTIFACTS, ("Upload final bundle", "Upload fingerprint source receipt")):
        found = [a for a in selected if a.get("id") == pinned["id"]]
        require(len(found) == 1, "missing_pinned_artifact")
        artifact = found[0]
        matches(artifact, pinned, "artifact_pin_mismatch")
        matches(artifact.get("workflow_run"), {"id": DONOR_RUN, "repository_id": REPOSITORY_ID,
                "head_repository_id": REPOSITORY_ID, "head_branch": DONOR_BRANCH, "head_sha": DONOR_SHA},
                "artifact_origin_mismatch")
        step = successful[step_name]
        require(timestamp(successful["Run stage 1"]["completed_at"]) <= timestamp(step["started_at"])
                <= timestamp(artifact.get("created_at")) <= timestamp(artifact.get("updated_at"))
                <= timestamp(step["completed_at"]), "artifact_outside_successful_upload_window")
    return {"repository": REPOSITORY, "run_id": DONOR_RUN, "attempt": DONOR_ATTEMPT,
            "source_sha": DONOR_SHA, "branch": DONOR_BRANCH, "workflow": WORKFLOW_PATH,
            "job_id": DONOR_JOB, "run_conclusion": runs[1]["conclusion"],
            "runs": runs, "build_job": job, "artifacts": selected}


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_file(path, size, digest):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size == size, "file_size_mismatch")
    require(sha256(path) == digest, "file_digest_mismatch")


def extract_outer(path, destination, expected):
    destination.mkdir()
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        require(len(members) == len(expected), "unexpected_outer_members")
        seen = set()
        for info in members:
            name = info.orig_filename
            require(name == info.filename and name in expected and name not in seen, "unsafe_outer_member")
            seen.add(name)
            require(not info.is_dir() and stat.S_IFMT(info.external_attr >> 16) in (0, stat.S_IFREG)
                    and not info.flag_bits & 1 and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                    "non_regular_outer_member")
            require(0 < info.file_size <= expected[name], "outer_expansion_limit")
        require_space(destination, sum(info.file_size for info in members))
        for info in members:
            with archive.open(info) as source, (destination / info.filename).open("xb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
            require((destination / info.filename).stat().st_size == info.file_size, "outer_member_size_mismatch")


def verify_inner(directory):
    inner = directory / "chromix-linux-arm64.zip"
    sums = (directory / "SHA256SUMS").read_text(encoding="ascii")
    require(re.fullmatch(r"[0-9a-f]{64}  chromix-linux-arm64\.zip\n?", sums), "invalid_inner_checksums")
    require(sums[:64] == INNER_SHA, "inner_checksum_pin_mismatch")
    verify_file(inner, INNER_SIZE, INNER_SHA)
    return inner


def extract_bundle(archive, destination):
    with zipfile.ZipFile(archive) as inner:
        members = inner.infolist()
        require(1 <= len(members) <= 1024 and sum(i.file_size for i in members) <= 1024**3,
                "inner_expansion_limit")
        require(all(not i.flag_bits & 1 and i.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    for i in members), "unsupported_inner_member")
        require_space(destination.parent, sum(i.file_size for i in members))
        require(inner.testzip() is None, "inner_crc_failure")
    spec = importlib.util.spec_from_file_location("chromix_bundle_extract", REPO / "sdk/python/chromix/_binary.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    destination.mkdir()
    module._extract_zip(archive, destination)
    return validate_bundle(destination / "chromix", "arm64")


def validate_source(path, repo=REPO):
    verify_file(path, SOURCE_SIZE, SOURCE_SHA)
    inputs, patches = load_stack(repo)
    require(len(patches) == 187 and inputs["series_sha256"] == SERIES_SHA, "current_stack_not_pinned_187")
    source = read_json(path)
    identity = source.get("identity", {})
    matches(identity, {"platform": "linux", "schema_version": 1}, "source_identity_mismatch")
    require(source.get("domain_substituted") is True, "source_not_domain_substituted")
    checked = check_source(path, None, inputs, {entry[0] for _, _, entries in patches for entry in entries})
    lite = identity.get("lite", {})
    matches(lite, {"path": "build/windows/lite-tarball-files"}, "source_lite_path_mismatch")
    root = repo / lite["path"]
    files = [{"path": p.relative_to(root).as_posix(), "sha256": sha256(p), "mode": stat.S_IMODE(p.stat().st_mode)}
             for p in sorted(root.rglob("*")) if p.is_file()]
    require(files == lite.get("files") and all(not p.is_symlink() for p in root.rglob("*")), "source_lite_mismatch")
    require(load_pins(repo, "linux")["ChromiumVersion"] == VERSION, "current_linux_version_changed")
    return {**checked, "patch_count": len(patches), "series_sha256": inputs["series_sha256"],
            "donor_run_id": DONOR_RUN, "donor_attempt": DONOR_ATTEMPT, "donor_sha": DONOR_SHA,
            "binding": "pinned receipt bytes and exact same-repository artifact/upload provenance; receipt has no embedded run identity"}


def verifier_identity():
    sha = os.environ.get("GITHUB_SHA", "")
    require(re.fullmatch(r"[0-9a-f]{40}", sha), "invalid_verifier_sha")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True, timeout=10).strip()
    require(head == sha, "verifier_checkout_mismatch")
    require(not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"],
                                        cwd=REPO, text=True, timeout=10).strip(), "dirty_verifier_checkout")
    return {"sha": sha, "run_id": os.environ.get("GITHUB_RUN_ID"), "attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "ref": os.environ.get("GITHUB_REF"), "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF"),
            "helper_sha256": sha256(Path(__file__))}


def prepare(directory, result):
    result["verifier"] = verifier_identity()
    result["phase"] = "metadata"
    client = Metadata()
    result["donor"] = validate_metadata(client)
    write_report(directory / "diagnostics/donor.json", result["donor"])
    result["downloads"] = []
    staging = directory / "downloads"
    staging.mkdir()
    deadline = time.monotonic() + 1200
    for artifact, expected, label in zip(ARTIFACTS,
            ({"chromix-linux-arm64.zip": INNER_SIZE, "SHA256SUMS": 1024}, {"source-final.json": SOURCE_SIZE}),
            ("final", "source")):
        result["phase"] = "download_" + label
        record = {**artifact, "attempts": []}
        result["downloads"].append(record)
        outer = client.download(REPOSITORY, artifact, staging, deadline, record)
        verify_file(outer, artifact["size_in_bytes"], artifact["digest"].removeprefix("sha256:"))
        extract_outer(outer, staging / label, expected)
        outer.unlink()
    inner = verify_inner(staging / "final")
    source = directory / "diagnostics/source-final.json"
    shutil.copyfile(staging / "source/source-final.json", source)
    result["phase"] = "source_receipt"
    result["source"] = validate_source(source)
    result["phase"] = "bundle"
    result["static"] = extract_bundle(inner, directory / "bundle")
    require(sha256(directory / "bundle/chromix/chrome") == BROWSER_SHA, "browser_hash_mismatch")
    result.update(status="prepared", phase="complete", browser_sha256=BROWSER_SHA,
                  chromium_version=VERSION, inner_zip_sha256=INNER_SHA, inner_crc="passed")


def finalize(directory, result):
    diagnostics = directory / "diagnostics"
    prepared = read_json(diagnostics / "preparation.json")
    result["preparation_sha256"] = sha256(diagnostics / "preparation.json")
    result["donor"] = prepared.get("donor")
    result["verifier"] = verifier_identity()
    require(prepared.get("status") == "prepared" and prepared.get("verifier") == result["verifier"],
            "preparation_not_verified")
    require(os.environ.get("ACCEPTANCE_OUTCOME") == "success", "acceptance_step_not_successful")
    result["source"] = validate_source(diagnostics / "source-final.json")
    require(sha256(directory / "bundle/chromix/chrome") == BROWSER_SHA, "browser_changed")
    native = read_json(diagnostics / "native-smoke.json")
    matches(native.get("runtime"), {"status": "passed", "host_arch": "arm64", "chromium_version": VERSION},
            "native_smoke_not_passed")
    acceptance = read_json(diagnostics / "acceptance/acceptance.json")
    result["acceptance_sha256"] = sha256(diagnostics / "acceptance/acceptance.json")
    matches(acceptance, {"ci_gate_passed": True, "control": False, "errors": []}, "acceptance_not_passed")
    require(acceptance.get("status") in ("passed", "incomplete"), "invalid_acceptance_status")
    matches(acceptance.get("browser"), {"sha256": BROWSER_SHA, "version": VERSION}, "acceptance_browser_mismatch")
    matches(acceptance.get("source"), {"sha256": SOURCE_SHA, "check": "producer-receipt-only"},
            "acceptance_source_mismatch")
    matches(acceptance.get("provenance"), {"commit": result["verifier"]["sha"], "dirty": False},
            "acceptance_verifier_mismatch")
    suites = acceptance.get("suites")
    require(isinstance(suites, list) and all(isinstance(s, dict) for s in suites)
            and [s.get("name") for s in suites] == [s[0] for s in SUITES], "incomplete_acceptance_suites")
    for suite in suites:
        matches(suite, {"errors": [], "timed_out": False, "cleanup_errors": []}, "failed_acceptance_suite")
        require(suite.get("report") == suite["name"] + ".json", "invalid_suite_report_path")
        require(sha256(diagnostics / "acceptance" / suite["report"]) == suite.get("report_sha256"),
                "suite_report_changed")
    result.update(status="reverified", phase="complete", ci_gate_passed=True, chromium_version=VERSION, browser_sha256=BROWSER_SHA,
                  source_sha256=SOURCE_SHA, inner_zip_sha256=INNER_SHA, acceptance_status=acceptance["status"],
                  full_acceptance=acceptance.get("full_acceptance"), gaps=acceptance.get("gaps"),
                  qualification=acceptance.get("qualification"),
                  source_qualification="producer receipt only; no live-source replay or signed binary/source attestation")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("guard", "prepare", "finalize"))
    parser.add_argument("--prebuilt-only", action="store_true", required=True,
                        help="explicitly acknowledge final-bundle verification; never invokes a compiler")
    parser.add_argument("--directory", type=Path)
    args = parser.parse_args(argv)
    result = {"schema_version": 1, "status": "failed", "ci_gate_passed": False, "phase": "guard"}
    report = None
    try:
        if args.directory is not None:
            require(args.directory.is_absolute() and not args.directory.is_symlink(), "absolute_session_directory_required")
            diagnostics = args.directory / "diagnostics"
            diagnostics.mkdir(parents=True, exist_ok=True)
            report = diagnostics / ("reverified.json" if args.operation == "finalize" else "preparation.json")
        dispatch_guard(json.loads(os.environ.get("REVERIFY_INPUTS", "{}")),
                       os.environ.get("GITHUB_EVENT_NAME"), os.environ.get("GITHUB_REPOSITORY"))
        temporary = Path(os.environ.get("TMPDIR", ""))
        require(temporary.is_absolute() and temporary.is_dir(), "absolute_existing_tmpdir_required")
        if args.operation == "guard":
            print("Pinned final-bundle re-verification only; no tree restore, build, or publication.")
            return 0
        require(report is not None, "directory_required")
        (prepare if args.operation == "prepare" else finalize)(args.directory, result)
    except Exception as error:
        result.update(status="failed", ci_gate_passed=False,
                      reason=str(error) if isinstance(error, SnapshotError) else type(error).__name__)
        print("ARM64 re-verification failed: " + result["reason"], file=sys.stderr)
    finally:
        if report is not None:
            write_report(report, result)
    if result["status"] == "failed":
        return 1
    print(json.dumps({"status": result["status"], "report": str(report)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
