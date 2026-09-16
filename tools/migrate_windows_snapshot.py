#!/usr/bin/env python3
"""Opt-in, one-shot 0152 migration of the pinned Windows x64 cold snapshot.

Run from the trusted target checkout, before prepare, with all build processes
stopped. Authenticate/extract the donor artifact separately. No donor code runs.
A failed transaction requires a fresh extraction; never delete its blocker.
Repeated invocation is deliberately rejected, including after a successful run.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

import apply_restored_patches as arp
import verify_patch_stack as stack

DONOR_SHA = "97f2881b0e5f43b7e9563569d92dfe702ed1df0b"
VERSION = "152.0.7977.82"
PATCH = "patches/0152-devtools-font-provenance-implementation.patch"
SOURCE = "third_party/blink/renderer/core/inspector/inspector_css_agent.cc"
READY = ".chromix-source-ready"
PATCH_MARKER = ".chromix-patches"
RECEIPT = ".chromix-windows-snapshot-migration.json"
# Both prepare and ci-stage reject this workdir directory, including an empty one.
BLOCKER = ".chromix-upstream-restore-windows-0152-migration"
TRUSTED_REPO = Path(__file__).resolve().parents[1]
WINDOWS = os.name == "nt"
PROTECTED_TREES = ("build", "assets", "patches")
PROTECTED_FILES = (
    "CHROMIUM_VERSION", ".gitattributes", "tools/apply_restored_patches.py", "tools/verify_patch_stack.py",
    "tools/prepare_restored_build.py", "tools/restore_upstream_cache.py",
    "tools/fetch_upstream_cache.py", "tools/upstream_script_identity.py",
)
# Orchestration changes do not change cold preparation inputs.
EXCLUDED = {"build/windows/ci-stage.ps1"}
STAT_FIELDS = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")


def _safe(path: Path, *, directory: bool = False, missing: bool = False) -> Path:
    path = Path(os.path.abspath(path))
    chain = list(reversed(path.parents)) + [path]
    for entry in chain:
        try:
            info = entry.lstat()
        except FileNotFoundError:
            if missing:
                continue
            raise arp.ApplyError(f"missing path: {entry}")
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise arp.ApplyError(f"symlink/reparse path is not supported: {entry}")
        is_dir = entry != path or directory
        if is_dir and not stat.S_ISDIR(info.st_mode):
            raise arp.ApplyError(f"not a directory: {entry}")
        if not is_dir and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
            raise arp.ApplyError(f"not a single-link regular file: {entry}")
    return path


def _file(root: Path, name: str, *, missing: bool = False) -> Path:
    if not name.startswith(".chromix-"):
        arp._relative(name)
    return _safe(root / name, missing=missing)


def _stat(info) -> tuple:
    return tuple(getattr(info, field) for field in STAT_FIELDS)


def _fingerprint(path: Path, *, missing: bool = False):
    _safe(path, missing=missing)
    if not path.exists():
        return None
    before = path.stat()
    digest = hashlib.sha256()
    blob = hashlib.sha1(f"blob {before.st_size}\0".encode())
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            blob.update(chunk)
    if _stat(before) != _stat(path.stat()):
        raise arp.ApplyError(f"input changed concurrently: {path}")
    normalized_blob = blob.hexdigest()
    if WINDOWS:
        raw = path.read_bytes()
        # Only lossless, uniform text checkout CRLF is accepted; filters never run.
        if b"\x00" not in raw and b"\r\n" in raw and b"\n" not in raw.replace(b"\r\n", b""):
            raw = raw.replace(b"\r\n", b"\n")
            normalized_blob = hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest()
        if _stat(before) != _stat(path.stat()):
            raise arp.ApplyError(f"input changed concurrently: {path}")
    return digest.hexdigest(), _stat(before), blob.hexdigest(), normalized_blob


def _capture(root: Path, names) -> dict:
    return {name: _fingerprint(_file(root, name, missing=True), missing=True) for name in sorted(names)}


def _unchanged(root: Path, before: dict) -> None:
    if _capture(root, before) != before:
        raise arp.ApplyError(f"input/source stat or hash changed concurrently: {root}")


def _host_git(roots: tuple[Path, ...]) -> str:
    found = shutil.which("git")
    if not found:
        raise arp.ApplyError("trusted host git is required")
    path = Path(found).resolve()
    if any(path.is_relative_to(root) for root in roots):
        raise arp.ApplyError(f"refusing donor/repository executable: {path}")
    return str(path)


def _git(program: str, root: Path, *args: str) -> bytes:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS="0",
               GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1", LC_ALL="C")
    command = [program, "--no-pager", "-c", "core.fsmonitor=false", "-c",
               "core.hooksPath=" + os.devnull, "-c", "core.autocrlf=false", "-C", str(root)]
    result = subprocess.run([*command, *args], env=env, stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=120)
    if result.returncode:
        raise arp.ApplyError("Git identity verification failed: " + result.stderr.decode(errors="replace"))
    return result.stdout


def _tree(program: str, root: Path, expected: str | None = None) -> tuple[str, dict]:
    _safe(root / ".git", directory=(root / ".git").is_dir())
    top = _git(program, root, "rev-parse", "--show-toplevel").decode().strip()
    if Path(top).resolve() != root:
        raise arp.ApplyError(f"not an independent Git checkout: {root}")
    if _git(program, root, "rev-parse", "--show-object-format").decode().strip() != "sha1":
        raise arp.ApplyError("only pinned SHA-1 Git repositories are supported")
    head = _git(program, root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    if not re.fullmatch("[0-9a-f]{40}", head) or expected is not None and head != expected:
        raise arp.ApplyError(f"Git HEAD does not match expected commit: {root}: {head}")
    entries = {}
    folded = set()
    for record in _git(program, root, "ls-tree", "-rz", "--full-tree", head).split(b"\0"):
        if not record:
            continue
        metadata, name = record.split(b"\t", 1)
        mode, kind, digest = metadata.decode("ascii").split()
        name = arp._relative(name.decode("utf-8"))
        if name.casefold() in folded:
            raise arp.ApplyError(f"Windows case-colliding Git path: {name}")
        folded.add(name.casefold())
        entries[name] = (mode, kind, digest)
    return head, entries


def _tracked(root: Path, entries: dict, *, core_pin: str | None = None) -> dict:
    files = {}
    for name, (mode, kind, digest) in entries.items():
        if (name == "ungoogled-chromium" and core_pin is not None
                and (mode, kind, digest) == ("160000", "commit", core_pin)):
            continue
        if kind != "blob" or mode not in ("100644", "100755"):
            raise arp.ApplyError(f"unsupported pinned Git entry: {root}/{name}")
        value = _fingerprint(_file(root, name))
        executable = bool(value[1][2] & 0o111)
        # Windows checkout permissions do not represent Git's executable bit.
        if digest not in value[2:] or not WINDOWS and executable != (mode == "100755"):
            raise arp.ApplyError(f"pinned tracked content/mode changed: {root}/{name}")
        files[name] = value
    return files


def _protected(name: str) -> bool:
    return name not in EXCLUDED and (name in PROTECTED_FILES or
        any(name.startswith(prefix + "/") for prefix in PROTECTED_TREES))


def _walk_files(root: Path, relative: str) -> set[str]:
    base = _safe(root / relative, directory=True)
    names = set()
    for directory, dirs, files in os.walk(base, followlinks=False):
        for name in dirs:
            _safe(Path(directory) / name, directory=True)
        for name in files:
            path = _safe(Path(directory) / name)
            names.add(path.relative_to(root).as_posix())
    return names


def _inputs(previous: Path, repo: Path, old_tree: dict, new_tree: dict) -> tuple[dict, dict]:
    old_names = {name for name in old_tree if _protected(name)}
    new_names = {name for name in new_tree if _protected(name)}
    if old_names != new_names or not set(PROTECTED_FILES).issubset(old_names):
        raise arp.ApplyError("preparation input inventory differs from the donor")
    captures = []
    for root in (previous, repo):
        actual = set(PROTECTED_FILES)
        for directory in PROTECTED_TREES:
            actual.update(_walk_files(root, directory))
        if {name for name in actual if _protected(name)} != old_names:
            raise arp.ApplyError("untracked/extra or missing preparation input")
        captures.append(_capture(root, old_names))
    old, new = captures
    for name in sorted(old_names):
        if old_tree[name][:2] != new_tree[name][:2]:
            raise arp.ApplyError(f"preparation Git mode changed: {name}")
        if not WINDOWS and bool(old[name][1][2] & 0o111) != bool(new[name][1][2] & 0o111):
            raise arp.ApplyError(f"preparation executable mode changed: {name}")
        if name != PATCH and old_tree[name] != new_tree[name]:
            raise arp.ApplyError(f"committed preparation inputs differ: {name}")
        if name != PATCH and old[name][0] != new[name][0]:
            raise arp.ApplyError(f"pins/preparation/assets/lite/series differ: {name}")
    if PATCH not in old or old[PATCH][0] == new[PATCH][0]:
        raise arp.ApplyError("requires exactly one changed patch: 0152")
    return old, new


def _pins(repo: Path) -> dict:
    raw = _file(repo, "build/ungoogled-revisions.psd1").read_text(encoding="utf-8-sig")
    pairs = re.findall(r'^\s*(\w+) = "([^"\n]+)"\s*$', raw, re.M)
    pins = dict(pairs)
    if len(pairs) != len(pins):
        raise arp.ApplyError("duplicate revision pins")
    if (pins.get("ChromiumVersion") != VERSION or
            _text(_file(repo, "CHROMIUM_VERSION")) != VERSION):
        raise arp.ApplyError("only Chromium 152.0.7977.82 Windows x64 is supported")
    for key in ("UngoogledCommit", "UngoogledWindowsCommit"):
        if not re.fullmatch("[0-9a-f]{40}", pins.get(key, "")):
            raise arp.ApplyError("invalid revision pin: " + key)
    return pins


def _text(path: Path) -> str:
    return path.read_bytes().decode("utf-8-sig").strip()


def patch_set_key(repo: Path) -> str:
    """Match Windows Get-PatchSetKey: patch bytes, then lite relative path+bytes.

    The pinned payload has one file. Reject ordering ambiguities rather than
    approximate PowerShell's culture-sensitive Sort-Object for future payloads.
    """
    digest = hashlib.sha256()
    names = [line.split("#", 1)[0].strip() for line in
             _file(repo, "patches/series").read_text(encoding="utf-8-sig").splitlines()]
    names = [name for name in names if name]
    if not names or len(names) != len(set(names)) or names.count(PATCH) != 1:
        raise arp.ApplyError("invalid patch series")
    for name in names:
        digest.update(_file(repo, name).read_bytes())
    lite = _walk_files(repo, arp.LITE)
    if len(lite) != 1 or lite != {arp.LITE + "/v8/test/torque/test-torque.tq"}:
        raise arp.ApplyError("unsupported lite inventory for pinned Windows patchSetKey")
    for name in sorted(lite):
        digest.update(name[len(arp.LITE) + 1:].encode("utf-8"))
        digest.update(_file(repo, name).read_bytes())
    return digest.hexdigest()


def source_ready_key(repo: Path) -> str:
    pins = _pins(repo)
    return "|".join((VERSION, pins["UngoogledCommit"], pins["UngoogledWindowsCommit"], patch_set_key(repo)))


def _blockers(work: Path, src: Path, *, owned: bool = False) -> None:
    for root in (work, src):
        for path in root.iterdir():
            name = path.name.casefold()
            if root == work and name == BLOCKER and owned:
                continue
            if (name.startswith(".chromix") and re.search(r"in[-_]?progress", name)
                    or name.startswith(".chromix-upstream-restore-")):
                raise arp.ApplyError(f"in-progress/unknown transaction detected: {path}")
    for name in (".chromix-upstream-restored.json", arp.MARKER):
        if _file(src, name, missing=True).exists():
            raise arp.ApplyError("cold snapshot must not contain upstream/restored-patches receipts")


def _markers(src: Path, pins: dict, key: str) -> dict:
    values = {
        ".chromix-source-unpacked": VERSION,
        ".chromix-ungoogled-core": pins["UngoogledCommit"],
        ".chromix-ungoogled-windows": pins["UngoogledWindowsCommit"],
        ".chromix-binaries-pruned": pins["UngoogledCommit"],
        ".chromix-domain-substituted": pins["UngoogledCommit"],
        PATCH_MARKER: key.rsplit("|", 1)[1], READY: key,
    }
    for name, value in values.items():
        if _text(_file(src, name)) != value:
            raise arp.ApplyError("missing/mismatched prepared layer marker: " + name)
    return _capture(src, values)


def _cold_identity(work: Path, src: Path, core: Path, tooling: Path, pins: dict) -> dict:
    expected = "\n".join(f"{k}={v}" for k, v in zip(("MAJOR", "MINOR", "BUILD", "PATCH"), VERSION.split(".")))
    if _text(_file(src, "chrome/VERSION")).replace("\r\n", "\n") != expected:
        raise arp.ApplyError("source chrome/VERSION mismatch")
    for root, name, value in ((core, "chromium_version.txt", VERSION),
                             (core, "revision.txt", "1"), (tooling, "revision.txt", "1")):
        if _text(_file(root, name)) != value:
            raise arp.ApplyError("tooling version mismatch: " + name)
    arch = _file(work, ".chromix-target-arch", missing=True)
    if arch.exists() and _text(arch) != "x64":
        raise arp.ApplyError("only Windows x64 donor is supported")
    if (src / "out/Default").exists():
        raise arp.ApplyError("cold donor must use out/Chromix, not out/Default")
    args = _file(src, "out/Chromix/args.gn")
    text = _text(args)
    for key, value in (("target_cpu", "x64"), ("v8_target_cpu", "x64"), ("target_os", "win")):
        matches = re.findall(r"(?m)^\s*" + key + r"\s*=([^\n]*)", text)
        if key == "target_cpu" and not matches or any(
                not re.fullmatch(r'\s*"' + value + r'"\s*(?:#.*)?', item) for item in matches):
            raise arp.ApplyError("non-x64/ambiguous Windows GN argument: " + key)
    _file(src, "out/Chromix/build.ninja")
    return _capture(work, [".chromix-target-arch", "src/chrome/VERSION", "src/out/Chromix/args.gn"])


def _verify(src: Path, repo: Path, core: Path, tooling: Path) -> dict:
    return stack.verify(src, repo, core=core, tooling=tooling, platform="windows")


def _apply(stage: Path, scratch: Path, data: bytes, program: str, *, reverse: bool) -> None:
    path = scratch / ("old.patch" if reverse else "new.patch")
    path.write_bytes(data)
    args = ("--reverse",) if reverse else ()
    result = subprocess.run(arp._patch_command(program, path, *args), cwd=stage,
                            env=arp._patch_environment(), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
    if result.returncode:
        raise arp.ApplyError("0152 scratch " + ("reverse" if reverse else "apply") + " failed: " +
                             result.stdout.decode(errors="replace"))


def _write(path: Path, data: bytes, *, mode: int = 0o644, mtime_ns: int | None = None) -> None:
    _safe(path, missing=True)
    arp._atomic_write(path, data, mode, mtime_ns)
    if path.read_bytes() != data or mtime_ns is not None and path.stat().st_mtime_ns < mtime_ns:
        raise arp.ApplyError("atomic publication verification failed: " + str(path))


def migrate(workdir: Path | str, previous_repo: Path | str, repo: Path | str,
            expected_previous_sha: str, *, patch_bin: str, report_stream=None) -> dict:
    if expected_previous_sha != DONOR_SHA:
        raise arp.ApplyError("expected-previous-sha must be the fixed supported donor SHA")
    work, previous, repo = (_safe(Path(p), directory=True) for p in (workdir, previous_repo, repo))
    if repo != TRUSTED_REPO:
        raise arp.ApplyError("--repo must be the running trusted helper checkout")
    roots = (work, previous, repo)
    if any(a.is_relative_to(b) for a in roots for b in roots if a != b) or len(set(roots)) != 3:
        raise arp.ApplyError("workdir and repositories must be separate, non-nested directories")
    src = _safe(work / "src", directory=True)
    core = _safe(work / "tooling/ungoogled-chromium", directory=True)
    tooling = _safe(work / "tooling/ungoogled-chromium-windows", directory=True)
    temporary = _safe(Path(tempfile.gettempdir()), directory=True)
    if any(temporary.is_relative_to(root) for root in roots):
        raise arp.ApplyError("temporary directory must be outside workdir/repositories")
    _blockers(work, src)
    if _file(src, RECEIPT, missing=True).exists():
        raise arp.ApplyError("explicit repeat refused: migration receipt already exists; do not migrate twice")
    git = _host_git(roots)
    old_head, old_tree = _tree(git, previous, DONOR_SHA)
    old_tracked = _tracked(previous, old_tree)
    new_head, new_tree = _tree(git, repo)
    old_inputs, new_inputs = _inputs(previous, repo, old_tree, new_tree)
    for name in new_inputs:
        mode, kind, digest = new_tree[name]
        if kind != "blob" or mode not in ("100644", "100755"):
            raise arp.ApplyError("unsupported target preparation Git entry: " + name)
        if name != PATCH and digest not in new_inputs[name][2:]:
            raise arp.ApplyError("target preparation content differs from committed input: " + name)
    pins = _pins(repo)
    tool_state = []
    for root, pin, submodule in ((core, pins["UngoogledCommit"], None),
                                 (tooling, pins["UngoogledWindowsCommit"], pins["UngoogledCommit"])):
        head, tree = _tree(git, root, pin)
        tool_state.append((root, head, tree, _tracked(root, tree, core_pin=submodule)))
    old_key, key = source_ready_key(previous), source_ready_key(repo)
    markers = _markers(src, pins, old_key)
    cold = _cold_identity(work, src, core, tooling, pins)
    old_identity, old_patches, old_lite = arp._load(previous, core, tooling, "windows")
    identity, patches, lite = arp._load(repo, core, tooling, "windows")
    names = {entry[0] for _, _, entries in patches for entry in entries}
    if any(name.split("/", 1)[0].casefold() == "out" or name.startswith(".ninja") for name in names | set(lite)):
        raise arp.ApplyError("patch/lite inputs must not touch the object cache")
    old_patch = next(data for name, data, _ in old_patches if name == PATCH)
    new_patch = next(data for name, data, _ in patches if name == PATCH)
    for sequence in (old_patches, patches):
        entries = next(entries for name, _, entries in sequence if name == PATCH)
        if entries != [(SOURCE, "modify", None)]:
            raise arp.ApplyError("0152 must only modify the single approved source file")
    if set(lite) & names:
        raise arp.ApplyError("unsupported patch/lite overlap")
    for name, (data, _) in old_lite.items():
        if _file(src, name).read_bytes() != data:
            raise arp.ApplyError("source lite payload mismatch: " + name)
    before = _capture(src, names | set(lite))
    old_report = _verify(src, previous, core, tooling)
    _unchanged(src, before | markers)
    original = _file(src, SOURCE).read_bytes()
    crlf = b"\r\n" in original
    if crlf and b"\n" in original.replace(b"\r\n", b""):
        raise arp.ApplyError("mixed source line endings are unsupported")

    receipt_state = None

    def recheck():
        _blockers(work, src, owned=True)
        if _fingerprint(_file(src, RECEIPT, missing=True), missing=True) != receipt_state:
            raise arp.ApplyError("migration receipt changed concurrently")
        if _tree(git, previous, DONOR_SHA) != (old_head, old_tree):
            raise arp.ApplyError("previous repository changed concurrently")
        if _tree(git, repo) != (new_head, new_tree):
            raise arp.ApplyError("target repository changed concurrently")
        _unchanged(previous, old_tracked)
        _unchanged(repo, new_inputs)
        if _inputs(previous, repo, old_tree, new_tree) != (old_inputs, new_inputs):
            raise arp.ApplyError("preparation inventory changed concurrently")
        for root, head, tree, captured in tool_state:
            if _tree(git, root, head) != (head, tree):
                raise arp.ApplyError("tooling Git tree changed concurrently")
            _unchanged(root, captured)
        _unchanged(work, cold)

    recheck()
    program = arp._patch_program(patch_bin, roots)
    blocker = work / BLOCKER
    blocker.mkdir()
    state = blocker / "transaction.json"
    _write(state, arp._json({"operation": "windows-cold-0152-migration", "previous_key": old_key, "key": key}))
    lock_state = _fingerprint(state)
    with tempfile.TemporaryDirectory(prefix="chromix-windows-0152-", dir=temporary) as directory:
        scratch = Path(directory)
        stage = scratch / "src"
        stage.mkdir()
        target = stage / SOURCE
        target.parent.mkdir(parents=True)
        target.write_bytes(original.replace(b"\r\n", b"\n"))
        _apply(stage, scratch, old_patch, program, reverse=True)
        _apply(stage, scratch, new_patch, program, reverse=False)
        candidate = target.read_bytes()
        if crlf:
            candidate = candidate.replace(b"\n", b"\r\n")
        target.write_bytes(candidate)
        if candidate == original:
            raise arp.ApplyError("0152 did not change the source")
        recheck()
        _unchanged(src, before | markers)
        # The complete stack is checked in an isolated projection, never via donor Python.
        for name in names | set(lite):
            if name == SOURCE or before[name] is None:
                continue
            path = stage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(_file(src, name).read_bytes())
        (stage / ".chromix-domain-substituted").write_bytes(pins["UngoogledCommit"].encode())
        candidate_report = _verify(stage, repo, core, tooling)
        recheck()
        _unchanged(src, before | markers)
        _safe(blocker, directory=True)
        if _fingerprint(state) != lock_state:
            raise arp.ApplyError("transaction blocker changed concurrently")
        info = _file(src, SOURCE).stat()
        # NTFS timestamps have 100 ns resolution; round up to a whole second.
        mtime = ((max(time.time_ns(), info.st_mtime_ns + 1_000_000_000) + 999_999_999)
                 // 1_000_000_000 * 1_000_000_000)
        _write(_file(src, SOURCE), candidate, mode=stat.S_IMODE(info.st_mode), mtime_ns=mtime)
        published = _capture(src, [SOURCE])
        final_report = _verify(src, repo, core, tooling)
        if final_report["outputs"] != candidate_report["outputs"]:
            raise arp.ApplyError("published source differs from verified candidate")
        recheck()
        _unchanged(src, before | published | markers)
        if _fingerprint(state) != lock_state:
            raise arp.ApplyError("transaction blocker changed concurrently")
        report = {
            "schema_version": 1, "status": "migrated", "operation": "windows-cold-0152-migration",
            "platform": "windows", "arch": "x64", "version": VERSION,
            "previous_sha": old_head, "target_sha": new_head,
            "previous_key": old_key, "key": key,
            "previous_identity": old_identity, "identity": identity,
            "changed_files": [SOURCE], "patch_count": len(patches),
            "source_change": {"path": SOURCE, "before_sha256": before[SOURCE][0],
                              "after_sha256": published[SOURCE][0],
                              "before_mtime_ns": info.st_mtime_ns,
                              "after_mtime_ns": _file(src, SOURCE).stat().st_mtime_ns,
                              "diff": "".join(difflib.unified_diff(
                                  original.decode("utf-8").splitlines(keepends=True),
                                  candidate.decode("utf-8").splitlines(keepends=True),
                                  fromfile="a/" + SOURCE, tofile="b/" + SOURCE))},
            "old_verification": old_report, "new_verification": final_report,
            "qualification": "patch structure verified; not compilation or full upstream attestation",
        }
        _write(_file(src, PATCH_MARKER), (key.rsplit("|", 1)[1] + "\r\n").encode("ascii"))
        _write(_file(src, READY), (key + "\r\n").encode("ascii"))
        _write(_file(src, RECEIPT, missing=True), arp._json(report))
        receipt_state = _fingerprint(_file(src, RECEIPT))
        _markers(src, pins, key)
        recheck()
        _unchanged(src, before | published)
        _safe(blocker, directory=True)
        if _fingerprint(state) != lock_state:
            raise arp.ApplyError("transaction blocker changed concurrently")
    if report_stream is not None:
        report_stream.write(arp._json(report))
        report_stream.flush()
        os.fsync(report_stream.fileno())
    published_ready = _markers(src, pins, key)
    unchanged_markers = {name: value for name, value in markers.items() if name not in (READY, PATCH_MARKER)}
    _unchanged(src, before | published | unchanged_markers)
    recheck()
    _unchanged(src, published_ready)
    if _fingerprint(state) != lock_state:
        raise arp.ApplyError("transaction blocker changed concurrently")
    state.unlink()
    blocker.rmdir()
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("workdir", "previous-repo", "repo", "report"):
        parser.add_argument("--" + flag, type=Path, required=True)
    parser.add_argument("--expected-previous-sha", required=True)
    parser.add_argument("--patch-bin", required=True, help="absolute trusted host GNU patch executable")
    args = parser.parse_args(argv)
    report_path = Path(os.path.abspath(args.report))
    protected = [args.workdir / "src", args.workdir / "tooling", args.previous_repo, args.repo]
    try:
        _safe(report_path, missing=True)
        if report_path.exists() or any(report_path.is_relative_to(Path(os.path.abspath(p))) for p in protected):
            raise arp.ApplyError("report must be a new file outside source/tooling/repositories")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with report_path.open("xb") as output:
            result = {"schema_version": 1, "status": "failed", "error": "migration did not complete"}
            try:
                result = migrate(args.workdir, args.previous_repo, args.repo,
                                 args.expected_previous_sha, patch_bin=args.patch_bin, report_stream=output)
            except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
                result["error"] = str(error) + "; restore a clean donor snapshot; never delete a blocker"
                output.seek(0)
                output.truncate()
                output.write(arp._json(result))
                output.flush()
                os.fsync(output.fileno())
    except (OSError, RuntimeError) as error:
        print(f"snapshot migration failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"status": result["status"], "report": str(report_path), "error": result.get("error")}))
    return int(result["status"] != "migrated")


if __name__ == "__main__":
    sys.exit(main())
