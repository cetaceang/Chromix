#!/usr/bin/env python3
"""Explicitly migrate a verified, already-patched restored POSIX source snapshot.

The caller must authenticate previous-repo's exact original head_sha separately.
Only current Python helpers and trusted host Git/GNU patch are executed. Interrupted
migrations are not resumable; restore a clean snapshot rather than removing markers.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time

try:
    from . import apply_restored_patches as arp
    from . import restore_upstream_cache as restore
    from .platform_pins import LINUX_VERSION_FILE, load_pins
except ImportError:
    import apply_restored_patches as arp
    import restore_upstream_cache as restore
    from platform_pins import LINUX_VERSION_FILE, load_pins

READY = ".chromix-source-ready"
# Existing preparation entry points recognize both blockers.
TRANSACTION = ".chromix-domain-substitution-in-progress"
PIN_FILES = ("CHROMIUM_VERSION", "build/ungoogled-revisions.psd1", "build/upstream-cache.json",
             LINUX_VERSION_FILE)
SCRIPT_FILES = ("build/prepare-ungoogled.sh", "build/apply-patches.sh",
                "tools/apply_restored_patches.py")
PLATFORM_TOOLING = {
    "linux": ("ungoogled-chromium-portablelinux", "UngoogledLinuxCommit"),
    "macos": ("ungoogled-chromium-macos", "UngoogledMacOSCommit"),
}


def _pins(repo: Path, platform: str) -> dict:
    for name in ("build/ungoogled-revisions.psd1", "CHROMIUM_VERSION"):
        arp._read(repo, name)
    if platform == "linux":
        path = arp._path(repo, LINUX_VERSION_FILE)
        if path.exists():
            arp._read(repo, LINUX_VERSION_FILE)
    return load_pins(repo, platform)


def _same_inputs(previous: Path, repo: Path, platform: str = "linux") -> None:
    for name in (*PIN_FILES, *SCRIPT_FILES):
        if name == LINUX_VERSION_FILE:
            if platform != "linux":
                continue
            paths = [arp._path(root, name) for root in (previous, repo)]
            if all(not path.exists() for path in paths):
                continue
            if not all(path.is_file() for path in paths):
                raise arp.ApplyError(f"migration requires identical pins/preparation tooling: {name}")
        if arp._read(previous, name) != arp._read(repo, name):
            raise arp.ApplyError(f"migration requires identical pins/preparation tooling: {name}")
    for name in SCRIPT_FILES:
        if arp._read(repo, name) != arp._read(Path(__file__).resolve().parents[1], name):
            raise arp.ApplyError(f"repository preparation tooling differs from running trusted checkout: {name}")


def source_ready_key(repo: Path, platform: str, arch: str) -> str:
    """Match prepare-ungoogled.sh's path-plus-content hash without running it."""
    pins = _pins(repo, platform)
    names = ["build/prepare-ungoogled.sh", "build/apply-patches.sh", "patches/series"]
    names.extend(name for line in arp._read(repo, "patches/series").decode().splitlines()
                 if (name := line.split("#", 1)[0].strip()))
    arp._path(repo, arp.LITE + "/.path-check")
    for path in sorted((repo / arp.LITE).rglob("*")):
        if path.is_symlink():
            raise arp.ApplyError(f"symlink lite payload: {path}")
        if path.is_file():
            names.append(path.relative_to(repo).as_posix())
    digest = hashlib.sha256()
    for name in names:
        digest.update(name.encode())
        digest.update(arp._read(repo, name))
    return "|".join((platform, arch, pins["ChromiumVersion"], pins["UngoogledCommit"],
                     pins[PLATFORM_TOOLING[platform][1]], digest.hexdigest()))


def _host_program(name: str, roots: tuple[Path, ...]) -> str:
    found = shutil.which(name)
    if not found:
        raise arp.ApplyError(f"required trusted host executable not found: {name}")
    path = Path(found).resolve()
    if any(path.is_relative_to(root) for root in roots):
        raise arp.ApplyError(f"refusing to execute previous repository/donor code: {path}")
    return str(path)


def _verify_tooling(work: Path, repo: Path, roots: tuple[Path, ...], platform: str) -> None:
    """Hash tracked files against pinned Git objects without invoking worktree filters."""
    git = _host_program("git", roots)
    pins = _pins(repo, platform)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_OPTIONAL_LOCKS="0", GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1",
                       LC_ALL="C")
    platform_name, platform_pin = PLATFORM_TOOLING[platform]
    for name, commit in (("ungoogled-chromium", pins["UngoogledCommit"]),
                         (platform_name, pins[platform_pin])):
        root = restore.local_path(work / "tooling" / name)
        command = [git, "--no-pager", "-c", "core.fsmonitor=false", "-c",
                   "core.hooksPath=" + os.devnull, "-C", str(root)]

        def run(*args):
            result = subprocess.run([*command, *args], env=environment, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60,
                                    check=False)
            if result.returncode:
                raise arp.ApplyError(f"pinned tooling verification failed: {name}: "
                                     + result.stderr.decode(errors="replace"))
            return result.stdout

        if run("rev-parse", "HEAD").decode().strip() != commit:
            raise arp.ApplyError(f"tooling checkout does not match pins: {name}")
        required = {"domain_regex.list", "domain_substitution.list"} if name == "ungoogled-chromium" else set()
        for entry in run("ls-tree", "-rz", "--full-tree", commit).split(b"\0"):
            if not entry:
                continue
            metadata, filename = entry.split(b"\t", 1)
            mode, kind, digest = metadata.decode().split()
            filename = filename.decode("utf-8")
            if (name == platform_name and filename == "ungoogled-chromium"
                    and (mode, kind, digest) == ("160000", "commit", pins["UngoogledCommit"])):
                continue
            if kind != "blob" or mode not in ("100644", "100755"):
                raise arp.ApplyError(f"unsupported pinned tooling entry: {name}/{filename}")
            raw = arp._read(root, filename)
            actual = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
            executable = bool(arp._path(root, filename).stat().st_mode & 0o111)
            if actual != digest or executable != (mode == "100755"):
                raise arp.ApplyError(f"pinned tooling content/mode changed: {name}/{filename}")
            required.discard(filename)
        if required:
            raise arp.ApplyError(f"regex/list missing from pinned tooling: {name}: {sorted(required)}")


def _names(patches: list, lite: dict) -> set[str]:
    names = set(lite) | {entry[0] for _, _, entries in patches for entry in entries}
    if any(name.split("/", 1)[0].lower() == "out" for name in names):
        raise arp.ApplyError("patch/lite inputs must not touch the object cache (out/)")
    return names


def _marker(src: Path, name: str) -> Path:
    return arp._path(src, name, marker=True)


def _ready(src: Path, key: str) -> None:
    path = _marker(src, READY)
    if not path.is_file() or path.read_bytes().rstrip(b"\n") != key.encode():
        raise arp.ApplyError(f"previous source-ready key does not match scripts/pins/arch. {arp.CLEAN}")


def _tooling_identity_root(identity: dict) -> Path:
    roots = []
    for field, filename in (("regex", "domain_regex.list"), ("list", "domain_substitution.list")):
        entry = identity.get(field)
        raw = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(raw, str) or not raw.startswith("/"):
            raise ValueError(f"invalid {field} tooling path")
        path = Path(raw)
        if (path.as_posix() != raw or path.parts[-3:] != ("tooling", "ungoogled-chromium", filename)
                or len(path.parts) < 5):
            raise ValueError(f"invalid {field} tooling root/suffix")
        # The old host need not exist here; any existing path components must be safe.
        arp._path(Path("/"), raw[1:])
        roots.append(path.parents[2])
    if roots[0] != roots[1]:
        raise ValueError("regex/list must share one tooling root")
    return roots[0]


def _previous_completed(src: Path, identity: dict, names: set[str]) -> bytes:
    """Accept only a relocation of the two POSIX tooling paths, without rewriting receipts."""
    marker = _marker(src, arp.MARKER)
    if not marker.exists():
        raise arp.ApplyError("old restored patch completion manifest is missing")
    try:
        saved = json.loads(marker.read_bytes())
        old = saved.get("identity") if isinstance(saved, dict) else None
        if (not isinstance(old, dict) or type(saved.get("schema_version")) is not int
                or saved["schema_version"] != arp.SCHEMA
                or saved.get("identity_sha256") != arp._sha(arp._json(old))):
            raise ValueError("invalid saved identity hash/schema")
        _tooling_identity_root(old)
        _tooling_identity_root(identity)
        relocated = dict(old)
        for field in ("regex", "list"):
            relocated[field] = dict(old[field], path=identity[field]["path"])
        if arp._json(relocated) != arp._json(identity):
            raise ValueError("non-path restored patch identity changed")
        # Reuse the strict checker for the original identity and every output, including deletions.
        if not arp._completed(src, old, names):
            raise ValueError("completion manifest disappeared")
        return arp._json(saved)
    except (ValueError, TypeError, OSError) as exc:
        raise arp.ApplyError(f"invalid previous restored patches: {exc}. {arp.CLEAN}") from exc


def _claim(path: Path, payload: bytes) -> None:
    try:
        with path.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise arp.ApplyError(f"another or interrupted migration owns {path.name}. {arp.CLEAN}") from exc


def _reverse(stage: Path, scratch: Path, patches: list, program: str) -> None:
    for number, (name, data, entries) in enumerate(reversed(patches)):
        for target, action, _ in entries:
            path = arp._path(stage, target)
            if (action == "delete" and path.exists()
                    or action != "delete" and not path.is_file()):
                raise arp.ApplyError(f"unexpected old reverse input: {target}")
        patch_file = scratch / f"reverse-{number:04d}.patch"
        patch_file.write_bytes(data)
        result = subprocess.run(arp._patch_command(program, patch_file, "--reverse"), cwd=stage,
                                env=arp._patch_environment(), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        if result.returncode:
            raise arp.ApplyError(f"old patch reverse failed: {name}\n"
                                 + result.stdout.decode(errors="replace"))
        for target, action, mode in entries:
            path = arp._path(stage, target)
            if action == "create":
                if path.exists():
                    raise arp.ApplyError(f"reverse did not remove old created file: {target}")
            elif not path.is_file():
                raise arp.ApplyError(f"reverse did not restore file: {target}")
            elif action == "delete":
                os.chmod(path, mode or 0o644)


def _unchanged(src: Path, before: dict) -> None:
    for name, (data, info) in before.items():
        path = arp._path(src, name, marker=name.startswith(".chromix"))
        current = (path.read_bytes(), path.stat()) if path.exists() else (None, None)
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (data != current[0] or (info is None) != (current[1] is None)
                or info and any(getattr(info, field) != getattr(current[1], field) for field in fields)):
            raise arp.ApplyError(f"source/receipt changed concurrently: {name}. {arp.CLEAN}")


def migrate(workdir: Path | str, previous_repo: Path | str, repo: Path | str,
            platform: str, arch: str, *, patch_bin: str | None = None) -> dict:
    """Verify, stage, and publish only net source changes, retaining Ninja state."""
    if platform not in PLATFORM_TOOLING or arch not in ("x64", "arm64"):
        raise arp.ApplyError("migration supports only linux/macos x64/arm64")
    work, previous, repo = (restore.local_path(p) for p in (workdir, previous_repo, repo))
    src = restore.local_path(work / "src")
    core = restore.local_path(work / "tooling/ungoogled-chromium")
    tooling = restore.local_path(work / "tooling" / PLATFORM_TOOLING[platform][0])
    roots = (work, previous, repo)
    for root in (*roots, src, core, tooling):
        if not root.is_dir():
            raise arp.ApplyError(f"not a directory: {root}")
    if any(root.is_relative_to(src) for root in (previous, repo, core, tooling)):
        raise arp.ApplyError("SRC must not contain repositories or donor tooling")
    for name in (TRANSACTION, arp.IN_PROGRESS):
        if _marker(src, name).exists():
            raise arp.ApplyError(f"in-progress/partial migration detected: {name}. {arp.CLEAN}")
    _same_inputs(previous, repo, platform)
    old_receipt = restore.verify_restored(work, platform, arch, repo=previous)
    receipt = restore.verify_restored(work, platform, arch, repo=repo)
    if old_receipt != receipt:
        raise arp.ApplyError("restore receipt changed during validation")
    _verify_tooling(work, repo, roots, platform)
    old_identity, old_patches, old_lite = arp._load(previous, core, tooling, platform)
    identity, patches, lite = arp._load(repo, core, tooling, platform)
    if old_identity["lite"] != identity["lite"] or old_lite != lite:
        raise arp.ApplyError("unsupported lite payload change; migration requires identical lite files/modes")
    old_names, names = _names(old_patches, old_lite), _names(patches, lite)
    old_key, key = (source_ready_key(root, platform, arch) for root in (previous, repo))
    _ready(src, old_key)
    previous_identity = _previous_completed(src, old_identity, old_names)
    before = arp._snapshot(src, old_names | names)
    markers = {name: (_marker(src, name).read_bytes(), _marker(src, name).stat())
               for name in (READY, arp.MARKER, restore.MARKER)}
    # Revalidate after taking the snapshot, before acquiring persistent blockers.
    _ready(src, old_key)
    if _previous_completed(src, old_identity, old_names) != previous_identity:
        raise arp.ApplyError("previous completion identity changed during validation")
    if restore.verify_restored(work, platform, arch, repo=repo) != receipt:
        raise arp.ApplyError("restore receipt changed during validation")
    _unchanged(src, before | markers)
    temp_root = Path(tempfile.gettempdir()).resolve()
    if any(temp_root.is_relative_to(root) for root in roots):
        raise arp.ApplyError("temporary directory must be outside workdir/repositories; set TMPDIR")
    candidates = [patch_bin] if patch_bin is not None else [os.environ.get("PATCH_BIN", "gpatch"), "patch"]
    program = arp.select_patch_program(candidates, roots)
    report = {"status": "migrated", "previous_key": old_key, "key": key,
              "identity_sha256": arp._sha(arp._json(identity)),
              "old_patch_count": len(old_patches), "patch_count": len(patches), "changed_files": []}
    payload = arp._json(dict(report, operation="restored-snapshot-migration"))
    _claim(_marker(src, TRANSACTION), payload)
    _claim(_marker(src, arp.IN_PROGRESS), payload)
    with tempfile.TemporaryDirectory(prefix="chromix-snapshot-migration-", dir=temp_root) as temporary:
        scratch = Path(temporary)
        stage = scratch / "src"
        stage.mkdir()
        for name, (data, info) in before.items():
            if data is not None:
                path = arp._path(stage, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                os.chmod(path, stat.S_IMODE(info.st_mode))
        _reverse(stage, scratch, old_patches, program)
        for name, (data, _) in lite.items():
            if arp._read(stage, name) != data:
                raise arp.ApplyError(f"old reversed lite content cannot be proven unchanged: {name}")
        arp.run_apply(stage, repo, core, tooling, platform, program)
        arp.run_apply(stage, repo, core, tooling, platform, program, check=True)
        after = arp._snapshot(stage, old_names | names)
        _same_inputs(previous, repo, platform)
        _verify_tooling(work, repo, roots, platform)
        if (arp._load(previous, core, tooling, platform) != (old_identity, old_patches, old_lite)
                or arp._load(repo, core, tooling, platform) != (identity, patches, lite)
                or source_ready_key(previous, platform, arch) != old_key
                or source_ready_key(repo, platform, arch) != key):
            raise arp.ApplyError("repository/tooling inputs changed during migration")
        if (restore.verify_restored(work, platform, arch, repo=previous) != receipt
                or restore.verify_restored(work, platform, arch, repo=repo) != receipt):
            raise arp.ApplyError("restore receipt changed during migration")
        _tooling_identity_root(json.loads(previous_identity)["identity"])
        _tooling_identity_root(old_identity)
        _ready(src, old_key)
        _unchanged(src, before | markers)
        changed = [name for name in sorted(before) if before[name][0] != after[name][0]
                   or before[name][1] and after[name][1]
                   and stat.S_IMODE(before[name][1].st_mode) != stat.S_IMODE(after[name][1].st_mode)]
        for name in changed:
            path = arp._path(src, name)
            data, info = after[name]
            if data is None:
                path.unlink()
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                old_info = before[name][1]
                mtime = max(time.time_ns(), old_info.st_mtime_ns + 1_000_000_000 if old_info else 0)
                arp._atomic_write(path, data, stat.S_IMODE(info.st_mode), mtime)
        # Publish the scratch manifest verbatim: it describes only the current series.
        arp._atomic_write(_marker(src, arp.MARKER), _marker(stage, arp.MARKER).read_bytes())
        arp._atomic_write(_marker(src, READY), (key + "\n").encode())
        _marker(src, arp.IN_PROGRESS).unlink()
        # TRANSACTION still blocks all preparation while the final check runs.
        arp.run_apply(src, repo, core, tooling, platform, program, check=True)
        restore.verify_restored(work, platform, arch, repo=repo)
        _ready(src, key)
        report["changed_files"] = changed
    _marker(src, TRANSACTION).unlink()
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("workdir", "previous-repo", "repo"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--platform", choices=("linux", "macos"), required=True)
    parser.add_argument("--arch", choices=("x64", "arm64"), required=True)
    parser.add_argument("--patch-bin", help="trusted host GNU patch (otherwise PATCH_BIN/gpatch/patch)")
    args = parser.parse_args(argv)
    try:
        result = migrate(args.workdir, args.previous_repo, args.repo, args.platform, args.arch,
                         patch_bin=args.patch_bin)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"snapshot migration failed: {exc}. {arp.CLEAN}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
