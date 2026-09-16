#!/usr/bin/env python3
"""Download digest-pinned Windows ZIPs and publish verified tree.7z.NNN volumes.

The manifest must come from validate_windows_snapshot.py. The 7z stream is not
unpacked. A verified report confirms integrity, not publication; only success
with publication=published confirms both. A final report failure preserves the
published destination and returns a nonzero exit status.
"""
from __future__ import annotations

import argparse
import hashlib
import math
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import time
import zipfile
from zipfile import ZipFile

if __package__:
    from . import download_posix_snapshot as base
else:
    import download_posix_snapshot as base

SnapshotError = base.SnapshotError
GitHub = base.GitHub
CHUNK = base.CHUNK
TOTAL_SECONDS = base.TOTAL_SECONDS
MAX_VOLUME_BYTES = base.MAX_VOLUME_BYTES
MAX_TOTAL_BYTES = base.MAX_TOTAL_BYTES
MAX_ARTIFACTS = 4
MAX_VOLUMES = base.MAX_FILES
require = base.require
remaining = base.remaining
require_space = base.require_space


def load_manifest(path):
    data = base.load_manifest(path)
    require(len(data["artifacts"]) <= MAX_ARTIFACTS, "invalid_artifact_set")
    return data


def _reparse(path):
    try:
        metadata = Path(path).lstat()
    except FileNotFoundError:
        return False
    return (stat.S_ISLNK(metadata.st_mode)
            or bool(getattr(metadata, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)))


def _safe_path(path):
    path = Path(os.path.abspath(path))
    current = path
    while True:
        if _reparse(current):
            raise SnapshotError("output_path_is_reparse_point")
        parent = current.parent
        if parent == current:
            break
        current = parent
    return path


def output_paths(manifest, destination, report):
    manifest = _safe_path(manifest)
    destination = _safe_path(destination)
    report = _safe_path(report)
    destination, report = base.output_paths(manifest, destination, report)
    require(not destination.is_relative_to(report), "output_overlap")
    require(not manifest.resolve().is_relative_to(destination), "output_overlaps_manifest")
    if report.exists():
        require(not report.samefile(manifest), "report_overwrites_manifest")
        require(report.is_file(), "report_not_regular")
    return destination, report


def _volume_name(info):
    name = info.orig_filename
    require(name == info.filename and "\\" not in name and not name.startswith("/"),
            "unsafe_zip_name")
    parts = name.split("/")
    require(1 <= len(parts) <= 2 and all(part not in ("", ".", "..")
            and re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts),
            "unsafe_zip_name")
    require(re.fullmatch(r"tree\.7z\.[0-9]{3}", parts[-1]), "unexpected_zip_member")
    mode = stat.S_IFMT(info.external_attr >> 16)
    require(not info.is_dir() and not info.external_attr & (0x10 | 0x400)
            and mode in (0, stat.S_IFREG) and not info.flag_bits & (1 | 0x40),
            "non_regular_zip_member")
    require(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
            "unsupported_zip_compression")
    return parts[-1]


def extract_volumes(outer, staging, artifact_id, volumes, deadline):
    try:
        _extract_volumes(outer, staging, artifact_id, volumes, deadline)
    except SnapshotError:
        raise
    except OSError:
        raise SnapshotError("local_io_error") from None
    except Exception:
        # ZIP parsers may include attacker-controlled member names in any error.
        raise SnapshotError("zip_integrity_error") from None


def _extract_volumes(outer, staging, artifact_id, volumes, deadline):
    remaining(deadline)
    with ZipFile(outer) as archive:
        members = archive.infolist()
        require(members and len(members) + len(volumes) <= MAX_VOLUMES,
                "volume_count_limit")
        selected, names = [], set(volumes)
        total = sum(item["size_in_bytes"] for item in volumes.values())
        for info in members:
            name = _volume_name(info)
            require(name not in names, "duplicate_volume")
            names.add(name)
            require(0 < info.file_size <= MAX_VOLUME_BYTES, "volume_size_limit")
            total += info.file_size
            require(total <= MAX_TOTAL_BYTES, "total_size_limit")
            selected.append((info, name))
        # Free space excludes the retained ZIP and previously extracted volumes.
        require_space(staging, sum(info.file_size for info, _ in selected))
        for info, name in selected:
            size, digest = 0, hashlib.sha256()
            output_path = staging / name
            with archive.open(info) as source, output_path.open("xb") as output:
                while True:
                    remaining(deadline)
                    chunk = source.read(CHUNK)
                    remaining(deadline)
                    if not chunk:
                        break
                    size += len(chunk)
                    require(size <= info.file_size and size <= MAX_VOLUME_BYTES,
                            "volume_size_mismatch")
                    require_space(staging, len(chunk))
                    output.write(chunk)
                    digest.update(chunk)
                output.flush()
                os.fsync(output.fileno())
            require(size == info.file_size and output_path.stat().st_size == size,
                    "volume_size_mismatch")
            volumes[name] = {"name": name, "artifact_id": artifact_id,
                             "size_in_bytes": size, "sha256": digest.hexdigest()}


def publish(staging, destination, *, platform=None, rename=None):
    _safe_path(staging)
    _safe_path(destination)
    require(not os.path.lexists(destination), "destination_exists")
    if (sys.platform if platform is None else platform) == "win32":
        try:
            # Windows rename is a no-replace operation; do not use os.replace.
            (os.rename if rename is None else rename)(staging, destination)
        except FileExistsError:
            raise SnapshotError("destination_exists") from None
        except OSError:
            if os.path.lexists(destination):
                raise SnapshotError("destination_exists") from None
            raise SnapshotError("atomic_publish_failed") from None
    else:
        base.publish(staging, destination)


def write_report(path, result):
    _safe_path(path)
    base.write_report(path, result)


def download_snapshot(manifest, destination, report, *, client=None,
                      timeout_seconds=TOTAL_SECONDS):
    started = time.monotonic()
    destination, report = output_paths(manifest, destination, report)
    result = {"status": "failed", "phase": "arguments", "destination": str(destination),
              "artifacts": [], "volumes": [], "publication": "not_attempted",
              "timeout_seconds": None}
    staging, volumes = None, {}
    try:
        require(type(timeout_seconds) in (int, float) and math.isfinite(timeout_seconds)
                and timeout_seconds > 0, "invalid_timeout")
        deadline = started + timeout_seconds
        require(math.isfinite(deadline), "invalid_timeout")
        result.update(phase="manifest", timeout_seconds=timeout_seconds)
        require(not os.path.lexists(destination), "destination_exists")
        metadata = load_manifest(manifest)
        result.update({key: metadata[key] for key in ("repository", "head_sha", "run_id")})
        client = client if client is not None else GitHub()
        remaining(deadline)
        staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.staging-",
                                       dir=destination.parent))
        for artifact in metadata["artifacts"]:
            record = {**artifact, "attempts": []}
            result["artifacts"].append(record)
            result["phase"] = "download"
            outer = client.download(metadata["repository"], artifact, staging, deadline, record)
            try:
                result["phase"] = "extract_zip"
                extract_volumes(outer, staging, artifact["id"], volumes, deadline)
            finally:
                outer.unlink(missing_ok=True)
        result["phase"] = "validate_sequence"
        require(1 <= len(volumes) <= MAX_VOLUMES
                and sorted(volumes) == [f"tree.7z.{index:03d}"
                                        for index in range(1, len(volumes) + 1)],
                "noncontiguous_volumes")
        result["volumes"] = [volumes[name] for name in sorted(volumes)]
        result["total_size_in_bytes"] = sum(item["size_in_bytes"] for item in volumes.values())
        result["phase"] = "publish"
        remaining(deadline)
        result.update(status="verified", publication="unconfirmed",
                      duration_seconds=round(time.monotonic() - started, 3))
        write_report(report, result)
        remaining(deadline)
        publish(staging, destination)
        staging = None
        result.update(status="success", publication="published", phase="complete",
                      duration_seconds=round(time.monotonic() - started, 3))
        try:
            write_report(report, result)
        except (SnapshotError, OSError):
            raise SnapshotError("published_report_write_failed") from None
        return result
    except (SnapshotError, OSError, KeyboardInterrupt) as error:
        if isinstance(error, KeyboardInterrupt):
            reason = "interrupted"
        elif isinstance(error, SnapshotError):
            reason = str(error)
        else:
            reason = "local_io_error"
        result.update(status="failed", reason=reason,
                      volumes=[volumes[name] for name in sorted(volumes)],
                      duration_seconds=round(time.monotonic() - started, 3))
        try:
            write_report(report, result)
        except (SnapshotError, OSError):
            if isinstance(error, KeyboardInterrupt):
                raise error from None
            reason = ("published_report_write_failed" if result["publication"] == "published"
                      else "report_write_failed")
            raise SnapshotError(reason) from None
        if isinstance(error, KeyboardInterrupt):
            raise
        raise SnapshotError(reason) from None
    finally:
        if staging is not None and staging.exists():
            shutil.rmtree(staging)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=TOTAL_SECONDS)
    args = parser.parse_args(argv)
    try:
        result = download_snapshot(args.manifest, args.destination, args.report,
                                   timeout_seconds=args.timeout_seconds)
    except (SnapshotError, OSError) as error:
        reason = str(error) if isinstance(error, SnapshotError) else "local_io_error"
        print(f"snapshot download failed: {reason}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("snapshot download failed: interrupted", file=sys.stderr)
        return 130
    print(f"snapshot download succeeded: {len(result['volumes'])} verified volumes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
