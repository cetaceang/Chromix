#!/usr/bin/env python3
"""Validate an exact same-repository Windows cold-build snapshot using metadata only."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re

if __package__:
    from .validate_posix_snapshot import Client as MetadataClient, positive
else:
    from validate_posix_snapshot import Client as MetadataClient, positive


WORKFLOW = "build-win-x64-github"


class Client(MetadataClient):
    def get(self, path: str) -> dict:
        data = super().get(path)
        for key in ("jobs", "artifacts"):
            if path.split("?", 1)[0].endswith("/" + key):
                if (not isinstance(data.get(key), list)
                        or type(data.get("total_count")) is not int or data["total_count"] < 0):
                    raise ValueError("invalid paginated GitHub response")
        return data


def validate(client, repository: str, run_id: int, stage: int, attempt: int,
             expected_sha: str, expected_artifact_ids: list[int], *,
             recovery_branch: str | None = None) -> dict:
    if (not isinstance(repository, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
            or any(part in (".", "..") for part in repository.split("/"))):
        raise ValueError("invalid repository")
    if (any(type(value) is not int or value < 1 for value in (run_id, stage, attempt))
            or stage > 12):
        raise ValueError("invalid Windows snapshot selection")
    if not isinstance(expected_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
        raise ValueError("expected SHA must be exactly 40 lowercase hexadecimal characters")
    if recovery_branch is not None and (
            not isinstance(recovery_branch, str) or not recovery_branch
            or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in recovery_branch)):
        raise ValueError("invalid recovery branch")
    if (not isinstance(expected_artifact_ids, list) or not 1 <= len(expected_artifact_ids) <= 4
            or any(type(value) is not int or value <= 0 for value in expected_artifact_ids)
            or len(set(expected_artifact_ids)) != len(expected_artifact_ids)):
        raise ValueError("supply the complete recorded set of snapshot artifact IDs (1-4 unique IDs)")

    run = client.get(f"/actions/runs/{run_id}")
    if (not isinstance(run, dict) or type(run.get("id")) is not int or run["id"] != run_id
            or run.get("name") != WORKFLOW
            or run.get("path") != f".github/workflows/{WORKFLOW}.yml"
            or not isinstance(run.get("head_branch"), str)
            or run["head_branch"] not in ("main", recovery_branch)
            or run.get("event") not in ("push", "workflow_dispatch")
            or (run["head_branch"] != "main" and run["event"] != "workflow_dispatch")
            or not isinstance(run.get("repository"), dict)
            or run["repository"].get("full_name") != repository
            or not isinstance(run.get("head_repository"), dict)
            or run["head_repository"].get("full_name") != repository
            or run.get("status") != "completed" or run.get("head_sha") != expected_sha
            or type(run.get("run_attempt")) is not int or attempt > run["run_attempt"]):
        raise ValueError("snapshot run identity, origin, SHA, or terminal status mismatch")

    jobs = client.items(f"/actions/runs/{run_id}/attempts/{attempt}/jobs", "jobs")
    if not isinstance(jobs, list) or any(
            not isinstance(job, dict) or not isinstance(job.get("name"), str) for job in jobs):
        raise ValueError("invalid snapshot jobs metadata")
    description = "fetch + sync + first compile" if stage == 1 else "resume compile"
    candidates = [job for job in jobs if job["name"] == f"stage {stage} ({description})"]
    if len(candidates) != 1 or candidates[0].get("status") != "completed":
        raise ValueError("exact donor stage is missing or incomplete")
    job = candidates[0]
    if (type(job.get("id")) is not int or job["id"] <= 0
            or type(job.get("run_id")) is not int or job["run_id"] != run_id
            or type(job.get("run_attempt")) is not int or job["run_attempt"] != attempt
            or job.get("head_sha") != expected_sha):
        raise ValueError("donor job identity, producer attempt, or SHA mismatch")
    steps = job.get("steps")
    if not isinstance(steps, list) or any(
            not isinstance(step, dict) or not isinstance(step.get("name"), str) for step in steps):
        raise ValueError("invalid donor steps metadata")
    for name in ("Ensure build tree snapshot", *[f"Upload tree part {n}" for n in range(1, 5)]):
        matches = [step for step in steps if step["name"] == name]
        if len(matches) != 1 or matches[0].get("conclusion") != "success":
            raise ValueError(f"donor checkpoint step is missing, ambiguous, or unsuccessful: {name}")

    prefix = f"tree-s{stage}-attempt-{attempt}-part"
    listed = client.items(f"/actions/runs/{run_id}/artifacts", "artifacts")
    if not isinstance(listed, list) or any(
            not isinstance(item, dict) or not isinstance(item.get("name"), str)
            or type(item.get("id")) is not int or item["id"] <= 0 for item in listed):
        raise ValueError("invalid snapshot artifacts metadata")
    artifacts = [item for item in listed if item["name"].startswith(prefix)]
    if not 1 <= len(artifacts) <= 4:
        raise ValueError("snapshot artifact set missing or ambiguous")
    if (len({item["id"] for item in artifacts}) != len(artifacts)
            or {item["id"] for item in artifacts} != set(expected_artifact_ids)):
        raise ValueError("snapshot artifact set differs from the complete recorded ID set")
    by_part = {}
    for item in artifacts:
        suffix = item["name"][len(prefix):]
        if suffix not in ("1", "2", "3", "4") or suffix in by_part:
            raise ValueError("invalid or duplicate snapshot part")
        if (item.get("expired") is not False or type(item.get("size_in_bytes")) is not int
                or item["size_in_bytes"] <= 0):
            raise ValueError("snapshot part expired or empty")
        digest = item.get("digest")
        if not isinstance(digest, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("snapshot artifact has no verified SHA-256 digest")
        origin = item.get("workflow_run")
        if (not isinstance(origin, dict) or type(origin.get("id")) is not int
                or origin["id"] != run_id or origin.get("head_sha") != expected_sha):
            raise ValueError("snapshot artifact origin mismatch")
        by_part[suffix] = item
    if set(by_part) != {str(index) for index in range(1, len(artifacts) + 1)}:
        raise ValueError("snapshot parts are not contiguous")
    return {
        "repository": repository, "platform": "windows", "workflow": WORKFLOW, "arch": "x64",
        "run_id": run_id, "attempt": attempt, "stage": stage,
        "head_sha": expected_sha, "job_id": job["id"], "pattern": prefix + "*",
        "artifacts": [{key: item[key] for key in ("id", "name", "size_in_bytes", "expired", "digest")}
                      for _, item in sorted(by_part.items())],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--stage", required=True, help="Producer stage (1-12), not the stage to resume")
    parser.add_argument("--attempt", required=True, help="Exact producer attempt")
    parser.add_argument("--expected-sha", required=True, help="Exact 40-character lowercase donor commit SHA")
    parser.add_argument("--artifact-ids", required=True, help="Complete comma-separated set of 1-4 artifact IDs")
    parser.add_argument("--recovery-branch", help="Also accept a manual donor from this exact recovery branch")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    client = Client(args.repository, os.environ.get("GH_TOKEN", ""))
    report = validate(client, args.repository, positive(args.run_id, "run ID"),
                      positive(args.stage, "stage"), positive(args.attempt, "attempt"), args.expected_sha,
                      [positive(value.strip(), "artifact ID") for value in args.artifact_ids.split(",")],
                      recovery_branch=args.recovery_branch)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write(f"head_sha={report['head_sha']}\npattern={report['pattern']}\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
