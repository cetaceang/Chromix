#!/usr/bin/env python3
"""Apply pre-substitution Chromix patches to a domain-substituted source tree.

Only trusted patch-bin is executed. Donor tooling supplies data, never Python code.
A failed/interrupted run requires a clean workdir; it cannot be resumed in place.
"""
from __future__ import annotations

import argparse
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

MARKER = ".chromix-restored-patches.json"
IN_PROGRESS = ".chromix-restored-patches-in-progress"
SCHEMA = 1
LITE = "build/windows/lite-tarball-files"
CLEAN = "Use a clean workdir restored from upstream; do not remove markers and retry."
HUNK = re.compile(rb"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n")
HEX = re.compile(r"[0-9a-f]{64}")
PATCH_OPTIONS = ("-p1", "--fuzz=0", "--batch", "--forward", "--binary",
                 "--get=0", "--no-backup-if-mismatch", "--reject-file=-")


class ApplyError(RuntimeError):
    """The restored source cannot safely receive this patch set."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def _relative(name: str) -> str:
    parts = name.split("/")
    if (not name or any(c in name for c in '\\:\x00')
            or any(ord(c) < 32 or ord(c) == 127 for c in name)
            or any(p in ("", ".", "..") or p.endswith((".", " ")) for p in parts)
            or any(p.lower() in (".git", ".hg", ".svn") for p in parts)
            or parts[0].lower().startswith(".chromix")
            or any(re.fullmatch(r"(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", p)
                   for p in parts)):
        raise ApplyError(f"unsafe path: {name!r}")
    return name


def _path(root: Path, name: str, *, marker: bool = False) -> Path:
    if not marker:
        _relative(name)
    target = root
    parts = name.split("/")
    for index, part in enumerate(parts):
        target = target / part
        if target.is_symlink():
            raise ApplyError(f"symlink path is not supported: {target}")
        if target.exists():
            mode = target.stat().st_mode
            if index < len(parts) - 1 and not stat.S_ISDIR(mode):
                raise ApplyError(f"non-directory parent: {target}")
            if index == len(parts) - 1 and not stat.S_ISREG(mode):
                raise ApplyError(f"not a regular file: {target}")
    return target


def _read(root: Path, name: str) -> bytes:
    path = _path(root, name)
    if not path.is_file():
        raise ApplyError(f"missing input file: {path}")
    return path.read_bytes()


def _decode(data: bytes) -> tuple[str, str]:
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return data.decode("latin-1"), "latin-1"


def _rules(data: bytes) -> list[tuple[re.Pattern, str]]:
    rules = []
    for number, line in enumerate(data.decode("utf-8").splitlines(), 1):
        if not line:
            continue
        if line.count("#") != 1:
            raise ApplyError(f"invalid domain_regex.list line {number}: expected pattern#replacement")
        pattern, replacement = line.split("#")
        try:
            compiled = re.compile(pattern)
            compiled.sub(replacement, "")  # Validate backreferences even without a match.
        except (re.error, IndexError) as exc:
            raise ApplyError(f"invalid domain_regex.list line {number}: {exc}") from exc
        rules.append((compiled, replacement))
    return rules


def _substitute(text: str, rules: list[tuple[re.Pattern, str]]) -> str:
    for pattern, replacement in rules:
        text = pattern.sub(replacement, text)
    return text


def transform_patch(data: bytes, listed: set[str], rules: list[tuple[re.Pattern, str]],
                    *, stage: Path | None = None
                    ) -> tuple[bytes, list[tuple[str, str, int | None]]]:
    """Return a lossless-metadata Git unified diff and (path, action, mode) entries.

    Renames, copies, binary diffs, symlink/mode-only patches and quoted paths are
    deliberately unsupported. Each file section selects UTF-8, then Latin-1.
    With stage, LF-only sections follow an existing uniformly CRLF target's EOL.
    """
    if not data.endswith(b"\n") or b"\x00" in data:
        raise ApplyError("unsupported diff: missing final newline or binary content")
    lines = [line + b"\n" for line in data.split(b"\n")[:-1]]
    output, entries = [], []
    i = 0
    while i < len(lines):
        header = re.fullmatch(rb"diff --git a/([^\s]+) b/([^\s]+)\n", lines[i])
        if not header:
            raise ApplyError(f"unsupported diff header: {lines[i][:160]!r}")
        try:
            old, new = (item.decode("utf-8") for item in header.groups())
        except UnicodeDecodeError as exc:
            raise ApplyError("unsupported non-UTF-8 diff path") from exc
        _relative(old)
        _relative(new)
        if old != new or '"' in old:
            raise ApplyError("unsupported diff: rename or quoted path")
        name = old
        start = i
        i += 1
        action, mode = "modify", None
        seen_metadata = set()
        while i < len(lines) and not lines[i].startswith(b"--- "):
            index = re.fullmatch(rb"index [0-9a-f]+\.\.[0-9a-f]+(?: (100644|100755))?\n", lines[i])
            filemode = re.fullmatch(rb"(new|deleted) file mode (100644|100755)\n", lines[i])
            key = "index" if index else "mode"
            if (not index and not filemode) or key in seen_metadata:
                raise ApplyError(f"unsupported diff metadata: {lines[i][:160]!r}")
            seen_metadata.add(key)
            if filemode:
                action = "create" if filemode[1] == b"new" else "delete"
                mode = int(filemode[2], 8) & 0o777
            i += 1
        if i + 1 >= len(lines):
            raise ApplyError(f"missing diff file headers: {name}")
        minus, plus = lines[i:i + 2]
        if minus == b"--- /dev/null\n" and action == "modify":
            action = "create"
        if plus == b"+++ /dev/null\n" and action == "modify":
            action = "delete"
        expected_minus = "/dev/null" if action == "create" else f"a/{name}"
        expected_plus = "/dev/null" if action == "delete" else f"b/{name}"
        if minus != f"--- {expected_minus}\n".encode() or plus != f"+++ {expected_plus}\n".encode():
            raise ApplyError(f"unsupported or mismatched diff file paths: {name}")
        i += 2
        body_indexes = []
        hunk_count = 0
        while i < len(lines) and not lines[i].startswith(b"diff --git "):
            match = HUNK.fullmatch(lines[i])
            if not match:
                raise ApplyError(f"unsupported or malformed hunk: {name}: {lines[i][:160]!r}")
            remaining_old, remaining_new = int(match[2] or 1), int(match[4] or 1)
            if (action == "create" and (int(match[1]) or remaining_old)
                    or action == "delete" and (int(match[3]) or remaining_new)):
                raise ApplyError(f"invalid {action} hunk: {name}")
            if not remaining_old and not remaining_new:
                raise ApplyError(f"empty hunk: {name}")
            hunk_count += 1
            i += 1
            while remaining_old or remaining_new:
                if i >= len(lines) or lines[i][:1] not in (b" ", b"-", b"+"):
                    raise ApplyError(f"hunk length mismatch: {name}")
                prefix = lines[i][:1]
                remaining_old -= prefix in (b" ", b"-")
                remaining_new -= prefix in (b" ", b"+")
                if remaining_old < 0 or remaining_new < 0:
                    raise ApplyError(f"hunk length mismatch: {name}")
                body_indexes.append(i)
                i += 1
                if i < len(lines) and lines[i] == b"\\ No newline at end of file\n":
                    i += 1
        if not hunk_count:
            raise ApplyError(f"unsupported diff without hunks: {name}")
        if name in listed:
            _, encoding = _decode(b"".join(lines[start:i]))
            for number in body_indexes:
                before = lines[number][1:].decode(encoding)
                after = _substitute(before, rules)
                if (after.count("\n") != 1 or not after.endswith("\n")
                        or after.count("\r") != before.count("\r") or "\x00" in after):
                    raise ApplyError(f"domain substitution changes hunk line boundaries: {name}")
                lines[number] = lines[number][:1] + after.encode(encoding)
        if stage is not None and action != "create":
            source = _read(stage, name)
            # A no-newline marker's preceding CR is content, not a line ending.
            terminated = [number for number in body_indexes
                          if number + 1 == i
                          or lines[number + 1] != b"\\ No newline at end of file\n"]
            if (b"\r\n" in source and source.count(b"\n") == source.count(b"\r\n")
                    and not any(lines[number].endswith(b"\r\n") for number in terminated)):
                # Mixed source/patch endings are explicit; never normalize them.
                for number in terminated:
                    lines[number] = lines[number][:-1] + b"\r\n"
        output.extend(lines[start:i])
        entries.append((name, action, mode))
    if not entries:
        raise ApplyError("empty diff")
    return b"".join(output), entries


def _load(repo: Path, core: Path, tooling: Path, platform: str) -> tuple[dict, list, dict]:
    series = _read(repo, "patches/series")
    regex_data = _read(core, "domain_regex.list")
    list_root = tooling if platform == "windows" else core
    list_data = _read(list_root, "domain_substitution.list")
    listed = {_relative(line) for line in list_data.decode("utf-8").splitlines() if line}
    rules = _rules(regex_data)
    names = [line.split("#", 1)[0].strip() for line in series.decode("utf-8").splitlines()]
    names = [name for name in names if name]
    if not names or len(set(names)) != len(names):
        raise ApplyError("empty series or duplicate series entries")
    patches, patch_ids = [], []
    for name in names:
        raw = _read(repo, name)
        transformed, entries = transform_patch(raw, listed, rules)
        patches.append((name, transformed, entries))
        patch_ids.append({"path": name, "sha256": _sha(raw)})
    lite, lite_ids = {}, []
    payload_root = repo / LITE
    # Check all parents without accepting a directory as a file.
    _path(repo, LITE + "/.path-check")
    if payload_root.exists():
        for directory, dirs, files in os.walk(payload_root, followlinks=False):
            for child in dirs:
                if (Path(directory) / child).is_symlink():
                    raise ApplyError(f"symlink lite payload directory: {child}")
            for child in files:
                path = Path(directory) / child
                name = path.relative_to(payload_root).as_posix()
                raw = _read(payload_root, name)
                mode = stat.S_IMODE(path.stat().st_mode)
                text, encoding = _decode(raw)
                effective = _substitute(text, rules).encode(encoding) if name in listed else raw
                lite[name] = (effective, mode)
                lite_ids.append({"path": name, "sha256": _sha(raw), "mode": mode})
    lite_ids.sort(key=lambda entry: entry["path"])
    identity = {
        "schema_version": SCHEMA,
        "platform": platform,
        "series": {"path": "patches/series", "sha256": _sha(series), "patches": patch_ids},
        "lite": {"path": LITE, "sha256": _sha(_json(lite_ids)), "files": lite_ids},
        "regex": {"path": str(core / "domain_regex.list"), "sha256": _sha(regex_data)},
        "list": {"path": str(list_root / "domain_substitution.list"), "sha256": _sha(list_data)},
    }
    return identity, patches, lite


def _snapshot(src: Path, names: set[str]) -> dict:
    result = {}
    for name in sorted(names):
        path = _path(src, name)
        if path.exists():
            result[name] = (path.read_bytes(), path.stat())
        else:
            result[name] = (None, None)
    return result


def _completed(src: Path, identity: dict, names: set[str]) -> bool:
    if _path(src, IN_PROGRESS, marker=True).exists():
        raise ApplyError(f"in-progress/partial restored patch run detected. {CLEAN}")
    marker = _path(src, MARKER, marker=True)
    if not marker.exists():
        return False
    try:
        saved = json.loads(marker.read_bytes())
        if (not isinstance(saved, dict) or saved.get("schema_version") != SCHEMA
                or saved.get("identity") != identity
                or saved.get("identity_sha256") != _sha(_json(identity))):
            raise ValueError("changed series, lite payload, regex/list identities or invalid marker")
        outputs = saved.get("outputs")
        if not isinstance(outputs, dict) or set(outputs) != names:
            raise ValueError("incomplete output manifest")
        for name, digest in outputs.items():
            path = _path(src, name)
            if digest is None:
                valid = not path.exists()
            else:
                valid = (isinstance(digest, str) and HEX.fullmatch(digest) and path.is_file()
                         and _sha(path.read_bytes()) == digest)
            if not valid:
                raise ValueError(f"completed source changed or partial: {name}")
    except (ValueError, TypeError, OSError) as exc:
        raise ApplyError(f"invalid completed restored patches: {exc}. {CLEAN}") from exc
    return True


def _atomic_write(path: Path, data: bytes, mode: int = 0o644,
                  mtime_ns: int | None = None) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".chromix-write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        if mtime_ns is not None:
            os.utime(temporary, ns=(mtime_ns, mtime_ns))
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _patch_command(program: str, patch_file: Path, *options: str) -> list[str]:
    return [program, *PATCH_OPTIONS, *options, "--input", str(patch_file)]


def _patch_environment() -> dict[str, str]:
    return dict(os.environ, LC_ALL="C", PATCH_GET="0")


def _probe_patch(program: str, donor_roots: tuple[Path, ...]) -> None:
    """Exercise the exact application options without touching source or receipts."""
    temp_root = Path(tempfile.gettempdir()).resolve()
    if any(temp_root.is_relative_to(root) for root in donor_roots):
        raise ApplyError("patch probe temporary directory must be outside SRC/tooling")
    with tempfile.TemporaryDirectory(prefix="chromix patch probe ", dir=temp_root) as temporary:
        scratch = Path(temporary)
        stage = scratch / "source tree"
        stage.mkdir()
        source = stage / "probe.txt"
        original = b"context\r\nold\r\ntail\r\n"
        expected = b"context\r\nnew\r\ntail\r\n"
        patch_file = scratch / "tiny change.patch"
        patch_file.write_bytes(
            b"diff --git a/probe.txt b/probe.txt\n--- a/probe.txt\n+++ b/probe.txt\n"
            b"@@ -1,3 +1,3 @@\n context\r\n-old\r\n+new\r\n tail\r\n")
        source.write_bytes(original)
        steps = (
            ("dry-run", ("--dry-run",), 0, original),
            ("apply", (), 0, expected),
            ("duplicate forward", (), 1, expected),
            ("reverse dry-run", ("--reverse", "--dry-run"), 0, expected),
            ("reverse", ("--reverse",), 0, original),
            ("reject fuzz", ("--dry-run",), 1, original.replace(b"context", b"mismatch")),
        )
        for label, options, code, content in steps:
            if label == "reject fuzz":
                source.write_bytes(content)
            try:
                result = subprocess.run(
                    _patch_command(program, patch_file, *options), cwd=stage,
                    env=_patch_environment(), stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, timeout=10)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ApplyError(f"patch capability probe failed ({label}): {program}: {exc}") from exc
            if (result.returncode != code or not source.is_file()
                    or source.read_bytes() != content or set(stage.iterdir()) != {source}):
                detail = result.stdout.decode("utf-8", errors="replace").strip()
                raise ApplyError(f"patch capability probe failed ({label}): {program} "
                                 f"(exit {result.returncode}, expected {code})\n{detail}")


def _patch_program(patch_bin: str | Path, donor_roots: tuple[Path, ...]) -> str:
    if not str(patch_bin).strip():
        raise ApplyError("patch binary path is empty or whitespace")
    found = shutil.which(str(patch_bin))
    if not found:
        raise ApplyError(f"patch binary not executable: {patch_bin}")
    path = Path(found).resolve()
    if any(path.is_relative_to(root) for root in donor_roots):
        raise ApplyError(f"refusing to execute donor code as patch binary: {path}")
    _probe_patch(str(path), donor_roots)
    return str(path)


def select_patch_program(candidates: list[str], donor_roots: tuple[Path, ...]) -> str:
    failures = []
    for candidate in dict.fromkeys(candidates):
        try:
            return _patch_program(candidate, donor_roots)
        except ApplyError as exc:
            failures.append(str(exc))
    raise ApplyError("no compatible host patch binary passed the capability probe:\n"
                     + "\n".join(failures))


def run_apply(src: Path | str, repo: Path | str, core: Path | str,
              platform_tooling: Path | str, platform: str, patch_bin: Path | str,
              *, check: bool = False) -> dict:
    """Return status (applied/skipped/checked), identity_sha256, patch_count, changed_files.

    check=True is read-only and requires a completed matching input/output manifest.
    Conflicts are staged outside repo/SRC, so they leave only IN_PROGRESS in SRC.
    Any failure after claiming IN_PROGRESS leaves it intact, including publish errors.
    ApplyError (or an OS error) means callers must not mark other build layers ready.
    """
    src, repo, core, tooling = (Path(p).resolve() for p in (src, repo, core, platform_tooling))
    if platform not in ("linux", "macos", "windows"):
        raise ApplyError(f"unsupported platform: {platform}")
    for root in (src, repo, core, tooling):
        if not root.is_dir():
            raise ApplyError(f"not a directory: {root}")
    if any(root.is_relative_to(src) for root in (repo, core, tooling)):
        raise ApplyError("SRC must not contain the repository or donor tooling")
    if _path(src, IN_PROGRESS, marker=True).exists():
        raise ApplyError(f"in-progress/partial restored patch run detected. {CLEAN}")
    identity, patches, lite = _load(repo, core, tooling, platform)
    names = set(lite) | {entry[0] for _, _, entries in patches for entry in entries}
    report = {"identity_sha256": _sha(_json(identity)), "patch_count": len(patches),
              "changed_files": []}
    if _completed(src, identity, names):
        return dict(report, status="checked" if check else "skipped")
    if check:
        raise ApplyError("restored patches are not completed: completion marker is missing")
    temp_root = Path(tempfile.gettempdir()).resolve()
    if any(temp_root.is_relative_to(root) for root in (repo, src, core, tooling)):
        raise ApplyError("temporary directory must be outside repo/SRC/tooling; set TMPDIR or TEMP")
    program = _patch_program(patch_bin, (src, core, tooling))
    progress = _path(src, IN_PROGRESS, marker=True)
    try:
        with progress.open("xb") as lock:
            lock.write(_json({"identity_sha256": report["identity_sha256"]}))
            lock.flush()
            os.fsync(lock.fileno())
    except FileExistsError as exc:
        raise ApplyError(f"another or interrupted patch run owns IN_PROGRESS. {CLEAN}") from exc
    if _path(src, MARKER, marker=True).exists():
        raise ApplyError(f"completion marker appeared concurrently. {CLEAN}")
    before = _snapshot(src, names)
    with tempfile.TemporaryDirectory(prefix="chromix-restored-patches-", dir=temp_root) as temporary:
        scratch = Path(temporary)
        stage = scratch / "src"
        stage.mkdir()
        for name, (data, info) in before.items():
            if data is not None:
                path = stage / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                os.chmod(path, stat.S_IMODE(info.st_mode) | stat.S_IWUSR)
        for name, (data, mode) in lite.items():
            path = _path(stage, name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            os.chmod(path, mode | stat.S_IWUSR)
        environment = _patch_environment()
        for number, (name, data, entries) in enumerate(patches):
            groups = [(data, entries)]
            if len({entry[0] for entry in entries}) != len(entries):
                # Repeated targets need current staged state, including create/delete.
                sections = re.split(rb"(?m)(?=^diff --git )", data)[1:]
                groups = [(section, [entry]) for section, entry in zip(sections, entries, strict=True)]
            for section, section_entries in groups:
                for target, action, _ in section_entries:
                    path = _path(stage, target)
                    if action == "create" and path.exists():
                        raise ApplyError(f"new file already exists (duplicate/partial): {target}. {CLEAN}")
                    if action != "create" and not path.is_file():
                        raise ApplyError(f"unknown/missing patch path: {target}. {CLEAN}")
                patch_file = scratch / f"{number:04d}.patch"
                effective, _ = transform_patch(section, set(), [], stage=stage)
                patch_file.write_bytes(effective)
                command = _patch_command(program, patch_file)
                result = subprocess.run(command, cwd=stage, env=environment, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
                if result.returncode:
                    detail = result.stdout.decode("utf-8", errors="replace")
                    raise ApplyError(f"patch failed: {name} (exit {result.returncode})\n{detail}\n{CLEAN}")
                for target, action, mode in section_entries:
                    path = _path(stage, target)
                    if action == "delete":
                        if path.exists():
                            raise ApplyError(f"patch did not delete {target}. {CLEAN}")
                    elif not path.is_file():
                        raise ApplyError(f"patch did not produce {target}. {CLEAN}")
                    elif action == "create":
                        os.chmod(path, mode or 0o644)
        after = _snapshot(stage, names)
        for name, (data, info) in before.items():
            path = _path(src, name)
            current = path.read_bytes() if path.exists() else None
            if current != data or (info and path.stat().st_mtime_ns != info.st_mtime_ns):
                raise ApplyError(f"source changed concurrently: {name}. {CLEAN}")
        changed = [name for name in sorted(names) if before[name][0] != after[name][0]]
        for name in changed:
            path = _path(src, name)
            data, stage_info = after[name]
            old_info = before[name][1]
            if data is None:
                path.unlink()
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                mode = stat.S_IMODE((old_info or stage_info).st_mode)
                mtime_ns = max(time.time_ns(), old_info.st_mtime_ns + 1_000_000_000 if old_info else 0)
                _atomic_write(path, data, mode, mtime_ns)
        outputs = {name: _sha(data) if data is not None else None for name, (data, _) in after.items()}
        _atomic_write(_path(src, MARKER, marker=True), _json({
            "schema_version": SCHEMA, "identity": identity,
            "identity_sha256": report["identity_sha256"], "outputs": outputs,
        }))
    progress.unlink()
    return dict(report, status="applied", changed_files=changed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("src", "repo", "core", "platform-tooling"):
        parser.add_argument(f"--{flag}", type=Path, required=True)
    parser.add_argument("--patch-bin", required=True)
    parser.add_argument("--patch-candidate", action="append", default=[],
                        help="fallback executable for --select-patch-bin (repeatable)")
    parser.add_argument("--select-patch-bin", action="store_true",
                        help="probe candidates and print the compatible host executable only")
    parser.add_argument("--platform", choices=("linux", "macos", "windows"), required=True)
    parser.add_argument("--check", action="store_true", help="verify completion without changing SRC")
    args = parser.parse_args(argv)
    if (args.patch_candidate and not args.select_patch_bin) or (args.select_patch_bin and args.check):
        parser.error("patch candidates require --select-patch-bin without --check")
    try:
        if args.select_patch_bin:
            roots = tuple(p.resolve() for p in (args.src, args.core, args.platform_tooling))
            print(select_patch_program([args.patch_bin, *args.patch_candidate], roots))
            return 0
        result = run_apply(args.src, args.repo, args.core, args.platform_tooling,
                           args.platform, args.patch_bin, check=args.check)
    except (ApplyError, OSError, UnicodeError, re.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
