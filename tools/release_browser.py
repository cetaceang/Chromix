#!/usr/bin/env python3
"""Publish verified inner browser ZIPs from successful, same-repository CI runs."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

WORKFLOWS = {
    "build-linux-x64": ("chromix-linux-x64",),
    "build-linux-arm64": ("chromix-linux-arm64",),
    "build-macos-x64": ("chromix-mac-x64",),
    "build-macos-arm64": ("chromix-mac-arm64",),
    "build-win-x64-github": ("chromix-win-x64",),
    "build-win-arm64-github": ("chromix-win-arm64",),
}
ASSETS = {name + ".zip" for names in WORKFLOWS.values() for name in names}
WORKFLOW_PLATFORMS = {
    "build-linux-x64": "linux",
    "build-linux-arm64": "linux",
    "build-macos-x64": "macos",
    "build-macos-arm64": "macos",
    "build-win-x64-github": "windows",
    "build-win-arm64-github": "windows",
}
ASSET_PLATFORMS = {name + ".zip": WORKFLOW_PLATFORMS[workflow]
                   for workflow, names in WORKFLOWS.items() for name in names}
ARTIFACT_NAMES = {"chromix-win-arm64": "win-arm64"}
ARM64_WORKFLOW = "build-win-arm64-github"
ARM64_NATIVE_JOB = "native Windows ARM64 bundle and fingerprint verification"


def native_verification_passed(repo: str, run: dict) -> bool:
    if run["name"] != ARM64_WORKFLOW:
        return True
    run_id, attempt = run_identity(run)
    pages = json.loads(gh("api", "--paginate", "--slurp",
                          f"repos/{repo}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100"))
    jobs = [job for page in pages for job in page.get("jobs", []) if job.get("name") == ARM64_NATIVE_JOB]
    return (len(jobs) == 1 and jobs[0].get("run_id") == run_id
            and jobs[0].get("run_attempt") == attempt and jobs[0].get("head_sha") == run["head_sha"]
            and jobs[0].get("status") == "completed" and jobs[0].get("conclusion") == "success"
            and isinstance(jobs[0].get("labels"), list) and "windows-11-arm" in jobs[0]["labels"])


def gh(*args: str) -> str:
    return subprocess.check_output(["gh", *args], text=True, stderr=subprocess.PIPE).strip()


def api(repo: str, path: str):
    return json.loads(gh("api", f"repos/{repo}/{path}"))


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def parse_manifest(text: str, allowed_assets: set[str] | None = None) -> dict[str, str]:
    allowed_assets = ASSETS if allowed_assets is None else allowed_assets
    result = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([a-fA-F0-9]{64})[ \t]+\*?([A-Za-z0-9][A-Za-z0-9._-]*)", line.strip())
        if (not match or match[2] not in allowed_assets or match[2] == "SHA256SUMS"
                or match[2] in result):
            raise ValueError("Invalid or duplicate SHA256SUMS entry")
        result[match[2]] = match[1].lower()
    return result


def matches_run(run: dict, repo: str, head_sha: str) -> bool:
    return (isinstance(head_sha, str)
            and run.get("head_sha") == head_sha
            and re.fullmatch(r"[0-9a-f]{40}", head_sha) is not None
            and run.get("head_branch") == "main"
            and (run.get("repository") or {}).get("full_name") == repo
            and (run.get("head_repository") or {}).get("full_name") == repo
            and run.get("event") in ("push", "workflow_dispatch")
            and run.get("name") in WORKFLOWS
            and run.get("path") == f".github/workflows/{run.get('name')}.yml")


def run_identity(run: dict) -> tuple[int, int]:
    return int(run["id"]), int(run.get("run_attempt", 1))


def successful_runs(repo: str, head_sha: str) -> dict[str, dict]:
    pages = json.loads(gh("api", "--paginate", "--slurp", f"repos/{repo}/actions/runs?head_sha={head_sha}&per_page=100"))
    latest = {}
    for page in pages:
        for run in page.get("workflow_runs", []):
            if not matches_run(run, repo, head_sha):
                continue
            name = run["name"]
            # Rank runs and rerun attempts before considering their conclusions.
            identity = run_identity(run)
            previous = latest.get(name)
            if (previous is None or identity > run_identity(previous)
                    or (identity == run_identity(previous)
                        and (run.get("status") != "completed" or run.get("conclusion") != "success"))):
                latest[name] = run
    return {name: run for name, run in latest.items()
            if run.get("status") == "completed" and run.get("conclusion") == "success"}


def validate_run(run: dict, repo: str, head_sha: str | None = None) -> tuple[str, ...]:
    if (not matches_run(run, repo, head_sha if head_sha is not None else run.get("head_sha", ""))
            or run.get("status") != "completed" or run.get("conclusion") != "success"):
        raise ValueError("Only successful, same-repository main browser builds at the expected SHA may be released")
    return WORKFLOWS[run["name"]]


def validate_arm64_pe(stream, size: int, name: str, version: str | None = None) -> None:
    """Read ARM64 headers and RT_VERSION resources without executing the image."""
    def read(offset, length):
        if offset < 0 or length < 0 or offset + length > size:
            raise ValueError(f"Truncated PE file: {name}")
        stream.seek(offset)
        data = stream.read(length)
        if len(data) != length:
            raise ValueError(f"Truncated PE file: {name}")
        return data

    header = read(0, 64)
    pe_offset = struct.unpack_from("<I", header, 60)[0]
    if header[:2] != b"MZ" or not 64 <= pe_offset <= 1024 * 1024:
        raise ValueError(f"Invalid DOS/PE header: {name}")
    pe = read(pe_offset, 24)
    machine, sections = struct.unpack_from("<HH", pe, 4)
    optional_size, characteristics = struct.unpack_from("<HH", pe, 20)
    if pe[:4] != b"PE\0\0" or machine != 0xAA64:
        raise ValueError(f"Expected ARM64 PE machine 0xaa64: {name}")
    if not 1 <= sections <= 96 or not 112 <= optional_size <= 4096 or not characteristics & 2:
        raise ValueError(f"Invalid PE headers: {name}")
    optional = read(pe_offset + 24, optional_size)
    if struct.unpack_from("<H", optional)[0] != 0x20B:
        raise ValueError(f"Expected ARM64 PE32+ optional header: {name}")
    directory_count = struct.unpack_from("<I", optional, 108)[0]
    if directory_count > 16 or 112 + directory_count * 8 > optional_size:
        raise ValueError(f"Invalid PE data directory count: {name}")
    section_table = read(pe_offset + 24 + optional_size, sections * 40)
    ranges = []
    for offset in range(0, len(section_table), 40):
        _, rva, raw_size, raw_offset = struct.unpack_from("<IIII", section_table, offset + 8)
        if raw_size and (raw_offset < pe_offset + 24 + optional_size + sections * 40
                         or raw_offset + raw_size > size):
            raise ValueError(f"Invalid PE section bounds: {name}")
        ranges.append((rva, raw_size, raw_offset))
    if version is None:
        return

    def read_rva(rva, length):
        offsets = [raw + rva - base for base, count, raw in ranges
                   if base <= rva and rva + length <= base + count]
        if len(offsets) != 1:
            raise ValueError(f"Invalid PE resource RVA: {name}")
        return read(offsets[0], length)

    if optional_size < 136 or struct.unpack_from("<I", optional, 108)[0] < 3:
        raise ValueError(f"Missing PE version resource: {name}")
    resource_rva, resource_size = struct.unpack_from("<II", optional, 128)
    if not resource_rva or not 16 <= resource_size <= 16 * 1024 * 1024:
        raise ValueError(f"Invalid PE resource directory: {name}")

    resources = read_rva(resource_rva, resource_size)

    def resource_read(offset, length):
        if offset < 0 or offset + length > resource_size:
            raise ValueError(f"Invalid PE resource bounds: {name}")
        return resources[offset:offset + length]

    def entries(offset):
        directory = resource_read(offset, 16)
        named, numbered = struct.unpack_from("<HH", directory, 12)
        count = named + numbered
        if not 1 <= count <= 4096:
            raise ValueError(f"Invalid PE resource entries: {name}")
        data = resource_read(offset + 16, count * 8)
        return [struct.unpack_from("<II", data, index * 8) for index in range(count)]

    roots = [target for kind, target in entries(0) if kind == 16]
    if len(roots) != 1 or not roots[0] & 0x80000000:
        raise ValueError(f"Missing or ambiguous PE version resource: {name}")
    versions = []
    for _, target in entries(roots[0] & 0x7FFFFFFF):
        if not target & 0x80000000:
            raise ValueError(f"Invalid PE version name directory: {name}")
        for _, leaf in entries(target & 0x7FFFFFFF):
            if leaf & 0x80000000:
                raise ValueError(f"Invalid PE version language entry: {name}")
            value_rva, value_size, _, _ = struct.unpack("<IIII", resource_read(leaf, 16))
            if not 92 <= value_size <= 1024 * 1024:
                raise ValueError(f"Invalid PE version data size: {name}")
            value = resource_read(value_rva - resource_rva, value_size)
            length, value_length, kind = struct.unpack_from("<HHH", value)
            key = "VS_VERSION_INFO\0".encode("utf-16le")
            fixed_offset = (6 + len(key) + 3) & ~3
            if (not fixed_offset + 52 <= length <= len(value) or value_length != 52 or kind != 0
                    or value[6:6 + len(key)] != key):
                raise ValueError(f"Invalid VS_VERSION_INFO: {name}")
            fixed = struct.unpack_from("<13I", value, fixed_offset)
            if fixed[:2] != (0xFEEF04BD, 0x10000):
                raise ValueError(f"Invalid VS_FIXEDFILEINFO: {name}")
            for high, low in ((fixed[2], fixed[3]), (fixed[4], fixed[5])):
                versions.append(f"{high >> 16}.{high & 0xFFFF}.{low >> 16}.{low & 0xFFFF}")
    if not versions or any(found != version for found in versions):
        raise ValueError(f"PE version does not match source Chromium version {version}: {name}")


def validate_bundle(path: Path, version: str | None = None) -> None:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(set(names)) != len(names):
            raise ValueError(f"Duplicate ZIP members in {path.name}")
        for name in names:
            parts = PurePosixPath(name).parts
            if (not parts or parts[0] != "chromix" or ".." in parts
                    or "\\" in name or ":" in name):
                raise ValueError(f"Unsafe browser ZIP member: {name}")
        if path.name in ("chromix-win-x64.zip", "chromix-win-arm64.zip"):
            required = {"chromix/chromix.cmd", "chromix/chrome.exe"}
            if path.name == "chromix-win-arm64.zip":
                required |= {"chromix/chrome.dll", "chromix/chrome_elf.dll", "chromix/libEGL.dll",
                             "chromix/libGLESv2.dll"}
        elif path.name.startswith("chromix-mac-"):
            required = {"chromix/chromix", "chromix/Chromium.app/Contents/MacOS/Chromium"}
        else:
            required = {"chromix/chromix", "chromix/chrome"}
        required |= {"chromix/LICENSE.chromix", "chromix/LICENSE.chromium"}
        if not required.issubset(names) or any(archive.getinfo(n).file_size == 0 for n in required):
            raise ValueError(f"Incomplete browser ZIP: {path.name}")
        if archive.testzip() is not None:
            raise ValueError(f"Corrupt browser ZIP: {path.name}")
        if path.name == "chromix-win-arm64.zip":
            if version is None or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", version):
                raise ValueError("ARM64 bundle verification requires the source Chromium version")
            if len({name.casefold() for name in names}) != len(names):
                raise ValueError("Case-colliding Windows ZIP members")
            for info in archive.infolist():
                mode = stat.S_IFMT(info.external_attr >> 16)
                if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ValueError(f"Special Windows ZIP member: {info.filename}")
                if any(part.endswith((".", " ")) for part in PurePosixPath(info.filename).parts):
                    raise ValueError(f"Unsafe Windows ZIP member: {info.filename}")
                if info.is_dir():
                    continue
                with archive.open(info) as stream:
                    is_pe = stream.read(2) == b"MZ"
                    if is_pe or info.filename.lower().endswith((".exe", ".dll")):
                        expected = version if PurePosixPath(info.filename).name.lower() in ("chrome.exe", "chrome.dll") else None
                        validate_arm64_pe(stream, info.file_size, info.filename, expected)


def collect(repo: str, run: dict, root: Path) -> dict[str, Path]:
    names = validate_run(run, repo)
    if not native_verification_passed(repo, run):
        raise ValueError("Windows ARM64 native verification has not passed for this run attempt")
    version = (source_version(repo, run["head_sha"], WORKFLOW_PLATFORMS[run["name"]])
               if run["name"] == ARM64_WORKFLOW else None)
    result = {}
    for name in names:
        dest = root / name
        artifact = ARTIFACT_NAMES.get(name, name)
        gh("run", "download", str(run["id"]), "--repo", repo, "--name", artifact, "--dir", str(dest))
        files = {p.relative_to(dest).as_posix(): p for p in dest.rglob("*") if p.is_file()}
        asset = name + ".zip"
        if asset not in files or set(files) - {asset, "SHA256SUMS"}:
            raise ValueError(f"Unexpected artifact contents: {name}")
        checksum = digest(files[asset])
        if "SHA256SUMS" in files:
            sums = parse_manifest(files["SHA256SUMS"].read_text(encoding="ascii"), {asset})
            if sums.get(asset) != checksum:
                raise ValueError(f"Checksum mismatch: {asset}")
        else:
            raise ValueError(f"Missing checksum: {asset}")
        validate_bundle(files[asset], version)
        result[asset] = files[asset]
    return result


def source_version(repo: str, sha: str, platform: str | None = None) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Invalid source commit")
    if platform not in (None, "linux", "macos", "windows"):
        raise ValueError("Unknown release platform")
    filename = {"linux": "CHROMIUM_LINUX_VERSION", "windows": "CHROMIUM_WINDOWS_VERSION"}.get(
        platform, "CHROMIUM_VERSION")
    try:
        version = gh("api", f"repos/{repo}/contents/{filename}?ref={sha}",
                     "-H", "Accept: application/vnd.github.raw+json")
    except subprocess.CalledProcessError as error:
        # Only GitHub's exact missing-file response permits legacy shared pins.
        if (platform not in ("linux", "windows") or error.returncode != 1 or not isinstance(error.stderr, str)
                or error.stderr.rstrip("\r\n") != "gh: Not Found (HTTP 404)"):
            raise
        version = gh("api", f"repos/{repo}/contents/CHROMIUM_VERSION?ref={sha}",
                     "-H", "Accept: application/vnd.github.raw+json")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Invalid Chromium version in the built commit")
    return version


def validate_release_revision(repo: str, tag: str, head_sha: str | None, release: dict | None,
                              platform: str | None = None) -> str:
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("Invalid release version tag")
    if head_sha is not None and source_version(repo, head_sha, platform) != tag[1:]:
        raise ValueError("Incoming source Chromium version does not match release tag")
    refs = api(repo, f"git/matching-refs/tags/{tag}")
    ref = next((ref for ref in refs if ref["ref"] == f"refs/tags/{tag}"), None)
    pinned_sha = head_sha
    if ref:
        obj = ref["object"]
        seen = set()
        while obj["type"] == "tag":
            if obj["sha"] in seen or len(seen) >= 10:
                raise ValueError("Invalid annotated release tag chain")
            seen.add(obj["sha"])
            obj = api(repo, f"git/tags/{obj['sha']}")["object"]
        if obj["type"] != "commit":
            raise ValueError("Release tag does not point to a commit")
        pinned_sha = obj["sha"]
    elif release:
        target = release.get("target_commitish", "")
        if not release.get("draft") or not re.fullmatch(r"[0-9a-f]{40}", target):
            raise ValueError("Existing release has no verifiable tag or draft commit")
        pinned_sha = target
    if pinned_sha is None:
        raise ValueError("No verifiable release commit")
    asset_platforms = {ASSET_PLATFORMS[asset["name"]] for asset in release.get("assets", [])
                       if asset["name"] in ASSET_PLATFORMS} if release else set()
    # Recovery has no incoming run; every known asset must belong to this tag's version.
    platforms = set(asset_platforms)
    if head_sha is not None or platform is not None or not platforms:
        platforms.add(platform)
    for candidate in sorted(platforms, key=lambda value: value or ""):
        if head_sha is not None and pinned_sha == head_sha and candidate == platform:
            continue
        if source_version(repo, pinned_sha, candidate) != tag[1:]:
            raise ValueError("Pinned tag commit Chromium version does not match release tag")
    if release:
        target = release.get("target_commitish", "")
        if re.fullmatch(r"[0-9a-fA-F]{40}", target) and target.lower() != pinned_sha:
            raise ValueError("Existing release target conflicts with its pinned tag commit")
    return pinned_sha


def recover_release_manifest(repo: str, tag: str, existing: dict, directory: Path,
                             *, include_backups: bool = False) -> tuple[str, dict[str, str]]:
    backups = {name for name in existing if re.fullmatch(r"SHA256SUMS\.backup\.[0-9a-f]{64}", name)}
    names = ["SHA256SUMS"] if "SHA256SUMS" in existing else []
    if include_backups or not names:
        names += sorted(backups)
    candidates = []
    for name in names:
        gh("release", "download", tag, "--repo", repo, "--pattern", name, "--dir", str(directory))
        path = directory / name
        if name in backups and digest(path) != name.rsplit(".", 1)[1]:
            raise ValueError(f"Existing manifest backup digest mismatch: {name}")
        text = path.read_bytes().decode("ascii")
        hashes = parse_manifest(text, (set(existing) | ASSETS) - backups)
        if set(hashes) - set(existing):
            raise ValueError("Existing manifest references missing release assets")
        candidates.append((text, hashes))
    if not candidates:
        return "", {}
    text, hashes = max(candidates, key=lambda candidate: len(candidate[0]))
    if any(not text.startswith(candidate[0]) for candidate in candidates):
        raise ValueError("Existing manifest backups do not form an append-only history")
    if include_backups and "SHA256SUMS" in existing:
        primary = directory / "primary"
        primary.mkdir()
        (directory / "SHA256SUMS").rename(primary / "SHA256SUMS")
    # Keep the recovered bytes available for rollback even when the primary was lost.
    (directory / "SHA256SUMS").write_bytes(text.encode("ascii"))
    return text, hashes


def restore_release_manifest(repo: str, tag: str, release: dict, directory: Path) -> dict[str, str]:
    existing = {asset["name"]: asset for asset in release["assets"]}
    if len(existing) != len(release["assets"]):
        raise ValueError("Duplicate existing release asset names")
    pinned_sha = validate_release_revision(repo, tag, None, release)
    _, hashes = recover_release_manifest(repo, tag, existing, directory, include_backups=True)
    manifest = directory / "SHA256SUMS"
    primary = directory / "primary" / "SHA256SUMS"
    if not manifest.exists() or (primary.exists() and primary.read_bytes() == manifest.read_bytes()):
        return hashes
    assets_dir = directory / "assets"
    assets_dir.mkdir()
    for name, checksum in sorted(hashes.items()):
        gh("release", "download", tag, "--repo", repo, "--pattern", name, "--dir", str(assets_dir))
        if digest(assets_dir / name) != checksum:
            raise ValueError(f"Existing release checksum mismatch: {name}")
    if validate_release_revision(repo, tag, None, release) != pinned_sha:
        raise ValueError("Pinned release commit changed during manifest verification")
    try:
        gh("release", "upload", tag, str(manifest), "--repo", repo, "--clobber")
    except subprocess.CalledProcessError:
        if primary.exists():
            gh("release", "upload", tag, str(primary), "--repo", repo, "--clobber")
        raise
    return hashes


def backup_release_manifest(repo: str, tag: str, manifest: Path, existing: dict, directory: Path) -> None:
    name = "SHA256SUMS.backup." + digest(manifest)
    directory.mkdir(exist_ok=True)
    backup = directory / name
    backup.write_bytes(manifest.read_bytes())
    if name not in existing:
        gh("release", "upload", tag, str(backup), "--repo", repo)
        existing[name] = {"name": name}
    verified = directory / "verified"
    verified.mkdir(exist_ok=True)
    path = verified / name
    if not path.exists():
        gh("release", "download", tag, "--repo", repo, "--pattern", name, "--dir", str(verified))
    if path.read_bytes() != backup.read_bytes():
        raise ValueError(f"Existing manifest backup digest mismatch: {name}")


def publish(repo: str, run: dict, tag: str, bundles: dict[str, Path], root: Path) -> None:
    assets = {name + ".zip" for name in validate_run(run, repo)}
    if set(bundles) != assets or any(path.name != name for name, path in bundles.items()):
        raise ValueError("Only the triggering platform's verified browser bundles may be published")
    head_sha = run["head_sha"]
    platform = WORKFLOW_PLATFORMS[run["name"]]
    releases = json.loads(gh("api", "--paginate", "--slurp", f"repos/{repo}/releases?per_page=100"))
    release = next((r for page in releases for r in page if r["tag_name"] == tag), None)
    pinned_sha = validate_release_revision(repo, tag, head_sha, release, platform)
    if run["name"] == ARM64_WORKFLOW:
        for path in bundles.values():
            validate_bundle(path, tag[1:])
    existing = {a["name"]: a for a in release["assets"]} if release else {}
    if release and len(existing) != len(release["assets"]):
        raise ValueError("Duplicate existing release asset names")
    old_dir = root / "existing"
    old_dir.mkdir()
    old_text, hashes = recover_release_manifest(repo, tag, existing, old_dir)
    old_hashes = dict(hashes)
    orphans = (set(existing) & ASSETS) - set(hashes)
    if orphans - assets:
        raise ValueError("Unrelated published browser assets are missing existing checksums")
    verified_incoming = {}
    if orphans:
        if not ready_run(repo, run):
            print(f"Pending release for {head_sha}: cannot recover an orphan from a stale platform run")
            return
        verified_incoming = collect(repo, run, root / "recovery-artifact")
    # Verify every recorded hash, including sidecar licenses, without rewriting old ZIPs.
    for name in sorted(set(hashes) | (set(existing) & ASSETS)):
        gh("release", "download", tag, "--repo", repo, "--pattern", name, "--dir", str(old_dir))
        actual = digest(old_dir / name)
        if name in hashes and hashes[name] != actual:
            raise ValueError(f"Existing release checksum mismatch: {name}")
        if name in orphans and actual != digest(verified_incoming[name]):
            raise ValueError(f"Unmanifested browser differs from verified incoming artifact: {name}")
        hashes[name] = actual
    for name, path in bundles.items():
        checksum = digest(path)
        if name in existing and hashes[name] != checksum:
            raise ValueError(f"Refusing to replace a different published browser: {name}")
        hashes[name] = checksum
    # Recheck the exact triggering attempt after all CI-side downloads and before any write.
    if not ready_run(repo, run):
        print(f"Pending release for {head_sha}: platform run changed during artifact verification")
        return
    if validate_release_revision(repo, tag, head_sha, release, platform) != pinned_sha:
        raise ValueError("Pinned release commit changed during artifact verification")
    manifest = root / "SHA256SUMS"
    additions = "".join(f"{hashes[name]}  {name}\n" for name in sorted(set(hashes) - set(old_hashes)))
    manifest_text = old_text + ("\n" if old_text and not old_text.endswith("\n") and additions else "") + additions
    manifest.write_bytes(manifest_text.encode("ascii"))
    notes = root / "notes.md"
    body = (release.get("body") or "") if release else (
        f"Chromix {tag[1:]} browser bundles. "
        "Browser assets are ZIP archives; verify downloads against SHA256SUMS.\n\n"
        "macOS bundles are not Developer ID signed or notarized. Gatekeeper may block them."
    )
    body = body.replace("All five platforms are verified at one source commit. ", "")
    policy = ("Platforms are published independently for this Chromium version and may use different "
              "source commits. The version tag stays pinned to its initial source commit; "
              "per-platform provenance below identifies each incoming build.")
    if policy not in body:
        body += "\n\n" + policy
    provenance = (f"\n\nVerified build: https://github.com/{repo}/actions/runs/{run['id']}\n"
                  f"Workflow: {run['name']} (attempt {run.get('run_attempt', 1)})\n"
                  f"Source commit: `{head_sha}`\n"
                  f"Assets: {', '.join(sorted(assets))}.\n")
    if provenance not in body:
        body += provenance
    notes.write_text(body, encoding="utf-8")
    if not release:
        gh("release", "create", tag, "--repo", repo, "--target", pinned_sha,
           "--title", f"Chromix {tag[1:]}", "--draft", "--notes-file", str(notes))
    manifest_changed = "SHA256SUMS" not in existing or manifest_text != old_text
    if manifest_changed and (old_dir / "SHA256SUMS").exists():
        backup_release_manifest(repo, tag, old_dir / "SHA256SUMS", existing, root / "backups")
    for name, path in sorted(bundles.items()):
        if name not in existing:
            gh("release", "upload", tag, str(path), "--repo", repo)
    if manifest_changed:
        if release and not release.get("draft"):
            # Recovered manifests must also retain each platform's build provenance.
            gh("release", "edit", tag, "--repo", repo, "--title", f"Chromix {tag[1:]}",
               "--notes-file", str(notes))
        backup_release_manifest(repo, tag, manifest, existing, root / "backups")
        try:
            gh("release", "upload", tag, str(manifest), "--repo", repo, "--clobber")
        except subprocess.CalledProcessError:
            # Immutable backups survive both delete-before-upload and failed rollback.
            if (old_dir / "SHA256SUMS").exists():
                gh("release", "upload", tag, str(old_dir / "SHA256SUMS"), "--repo", repo, "--clobber")
            raise
    gh("release", "edit", tag, "--repo", repo, "--title", f"Chromix {tag[1:]}",
       "--draft=false", "--notes-file", str(notes))
    print(f"Published {tag}: {', '.join(sorted(bundles))}")


def ready_run(repo: str, event_run: dict) -> dict | None:
    validate_run(event_run, repo)
    head_sha = event_run["head_sha"]
    run = api(repo, f"actions/runs/{int(event_run['id'])}")
    if (not matches_run(run, repo, head_sha) or run["name"] != event_run["name"]
            or run.get("event") != event_run["event"] or int(run["id"]) != int(event_run["id"])):
        raise ValueError("Triggering workflow run identity changed")
    if (run.get("status") != "completed" or run.get("conclusion") != "success"
            or run_identity(run) != run_identity(event_run)):
        print(f"Pending release for {head_sha}: triggering attempt is no longer the successful event attempt")
        return None
    latest = successful_runs(repo, head_sha).get(run["name"])
    if (latest is None or run_identity(latest) != run_identity(event_run)
            or latest.get("event") != event_run["event"]):
        print(f"Pending release for {head_sha}: {run['name']} event is not its latest successful run/attempt")
        return None
    if not native_verification_passed(repo, run):
        print(f"Pending release for {head_sha}: Windows ARM64 native verification has not passed")
        return None
    return run


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-ready", action="store_true",
                        help="Write readiness to GITHUB_OUTPUT without downloading or publishing artifacts")
    args = parser.parse_args(argv)
    repo = os.environ["GITHUB_REPOSITORY"]
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    run = ready_run(repo, event["workflow_run"])
    if args.check_ready:
        ready = "true" if run else "false"
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write(f"ready={ready}\n")
        print(f"Release readiness: {ready}")
        return
    if not run:
        return
    version = source_version(repo, run["head_sha"], WORKFLOW_PLATFORMS[run["name"]])
    with tempfile.TemporaryDirectory(prefix="chromix-release-") as directory:
        root = Path(directory)
        bundles = collect(repo, run, root)
        publish(repo, run, "v" + version, bundles, root)


if __name__ == "__main__":
    main()
