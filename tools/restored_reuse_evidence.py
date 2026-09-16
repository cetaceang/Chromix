#!/usr/bin/env python3
"""Bounded observations of restored objects across actual, caller-owned builds.

Call before after GN/plan and BEFORE the first actual build in WORK/src/out/Default;
call after with the actual exit code, including failures/timeouts. Repeat the pair
on later stages without replacing WORK/upstream-reuse/baseline.json. No build is
run here. The caller must serialize these calls and builds, preserve nanosecond
mtimes across handoffs, and not build objects before the initial baseline.
Keep result.json too: disqualification is permanent, and every observation checks
the preceding full log prefix. Compaction or missing state cannot prove reuse.
Ninja 1.11.x/1.12.x/1.13.x (including .chromium.N) is required for -t inputs;
1.10 is unsupported and the caller must select a newer compatible Ninja.

The restore receipt verifies source provenance, not original per-object records.
Retention is measured since the first baseline, not independently back to the
upstream build, and is not a cache-hit percentage or compiler compatibility claim.
The result-only architecture_evidence v1 classifies retained Linux ELF64 ET_REL
headers from fully hashed bytes. Bitcode and other formats remain unknown.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import signal
import stat
import struct
import subprocess
import sys
import threading
import time
from collections import Counter
from pathlib import Path

try:
    from . import restore_upstream_cache as restore
    from . import upstream_object_cache as objects
except ImportError:
    import restore_upstream_cache as restore
    import upstream_object_cache as objects

REPO = restore.REPO
OWNER = "chromix-restored-reuse-v1"
DIRECTORY = "upstream-reuse"
MAX_SAMPLES = 128
MAX_HASH_BYTES = 64 * 1024**2
MAX_FILE_BYTES = 8 * 1024**2
MAX_INPUT_BYTES = 64 * 1024**2
MAX_LOG_BYTES = 128 * 1024**2
MAX_LINE_BYTES = 16 * 1024
MAX_JSON_BYTES = 2 * 1024**2
MAX_PATH_EXAMPLES = 8
MAX_PATH_EXAMPLE_CHARS = 256
MAX_QUERY_STDERR_BYTES = 4096
NINJA_TIMEOUT = 10
NINJA_INPUTS_TIMEOUT = 600
ELF_ARCHITECTURES = {62: "x64", 183: "arm64"}
ARCHITECTURE_METHOD = "linux-elf64-le-et-rel"
SCOPE = "retained since first Chromix build, upstream source verified"
CONTRACT = "Initial before follows GN/plan, precedes all actual object builds, and is preserved across stages."
SAFE_ENV = ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA", "GITHUB_JOB", "GITHUB_HEAD_REF")
DISQUALIFICATION_REASONS = {"log_prefix_mismatch", "appended_record_changed", "appended_record_repeated",
                          "not_in_target_inputs",
                          "target_inputs_changed", "missing_record", "record_changed", "missing_file",
                          "file_metadata_changed", "content_changed", "unsupported_appended_output"}


class EvidenceError(ValueError):
    """The observation cannot support a retention claim."""


def run_identity() -> dict:
    return {key: os.environ[key] for key in SAFE_ENV
            if re.fullmatch(r"[A-Za-z0-9_./+-]{1,200}", os.environ.get(key, ""))}


def regular(path: Path):
    if restore.linked(path):
        raise EvidenceError("linked evidence input")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise EvidenceError("evidence input is not an independent regular file")
    return info


def stamp(info) -> tuple:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def object_name(name: str) -> str:
    if (not isinstance(name, str) or len(name) > 2048
            or not re.fullmatch(r"[A-Za-z0-9_./+=-]+\.(?:o|obj)", name)
            or name.startswith("/") or ".." in name.split("/")
            or Path(name).as_posix() != name):
        raise EvidenceError("unsafe or unsupported object path")
    return name


def object_path(out: Path, name: str) -> Path:
    return restore.safe_path(out, Path(object_name(name)))


def object_like(name: str) -> bool:
    # Quotes and archive-member delimiters are recognized, never normalized.
    return re.search(r"\.(?:o|obj)[\"')]*\Z", name) is not None


def escaped_path(value) -> str:
    text = ascii(value)
    return text if len(text) <= MAX_PATH_EXAMPLE_CHARS else text[:MAX_PATH_EXAMPLE_CHARS - 3] + "..."


def path_example(examples: list, name: str, origin: str, line: int) -> None:
    if len(examples) < MAX_PATH_EXAMPLES:
        examples.append({"origin": origin, "line": line, "path_escaped": escaped_path(name)})


def json_bytes(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate evidence JSON key")
        result[key] = value
    return result


def read_json(path: Path) -> dict:
    info = regular(path)
    if info.st_size > MAX_JSON_BYTES:
        raise EvidenceError("evidence JSON exceeds byte cap")
    with path.open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES or stamp(regular(path)) != stamp(info):
        raise EvidenceError("evidence JSON changed or exceeds byte cap")
    value = json.loads(raw, object_pairs_hook=no_duplicates)
    if not isinstance(value, dict):
        raise EvidenceError("invalid evidence JSON")
    return value


def write_json(path: Path, value: dict, *, exclusive=False) -> None:
    if len(json_bytes(value)) > MAX_JSON_BYTES:
        raise EvidenceError("evidence report exceeds byte cap")
    if path.exists():
        regular(path)
    if exclusive:
        with path.open("xb") as stream:
            stream.write(json_bytes(value))
    else:
        objects.write_json(path, value)


def query(ninja: Path, out: Path, args: list[str], limit: int) -> bytes:
    # Inputs traverses and sorts the full manifest closure before emitting output.
    timeout = NINJA_INPUTS_TIMEOUT if args[:2] == ["-t", "inputs"] else NINJA_TIMEOUT
    started = time.monotonic()
    timed_out = threading.Event()
    stderr = bytearray()
    stderr_size = 0
    process = None
    terminated = False
    own_group = os.name == "posix" and threading.current_thread() is threading.main_thread()

    def kill():
        if process is not None:
            try:
                if own_group:
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
            except ProcessLookupError:
                pass

    def terminate(signum, frame):
        nonlocal terminated
        terminated = True
        kill()

    # Register before spawning: the query group is outside the stage timeout's group.
    previous_sigterm = signal.signal(signal.SIGTERM, terminate) if own_group else None
    try:
        with subprocess.Popen([str(ninja), *args], cwd=out, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              start_new_session=own_group) as process:
            if terminated:
                kill()

            def expire():
                timed_out.set()
                kill()

            def drain_stderr():
                nonlocal stderr_size
                # Drain continuously, retaining only a bounded diagnostic prefix.
                while data := process.stderr.read1(64 * 1024):
                    stderr_size += len(data)
                    stderr.extend(data[:max(0, MAX_QUERY_STDERR_BYTES - len(stderr))])

            reader = threading.Thread(target=drain_stderr, daemon=True)
            timer = threading.Timer(timeout, expire)
            timer.daemon = True
            reader.start()
            timer.start()
            try:
                data = process.stdout.read(limit + 1)
                if len(data) > limit:
                    kill()
                process.wait()
                reader.join()
            finally:
                timer.cancel()
                timer.join()
                kill()
                process.wait()
                reader.join()
            if terminated:
                reason = "interrupted by SIGTERM"
            elif len(data) > limit:
                reason = "exceeds stdout byte cap"
            elif timed_out.is_set():
                reason = "timed out"
            elif process.returncode != 0:
                reason = "failed (nonzero exit)"
            elif stderr_size:
                reason = "produced unexpected stderr"
            else:
                return data
            command = escaped_path(args)
            if len(command) > 96:
                command = command[:93] + "..."
            raise EvidenceError((f"Ninja query {command} {reason}; timeout={timeout:g}s; "
                                 f"elapsed={time.monotonic() - started:.2f}s; returncode={process.returncode}; "
                                 f"stdout_bytes={len(data)}; stdout_cap={limit}; stderr_bytes={stderr_size}; "
                                 f"stderr={escaped_path(bytes(stderr))}")[:512])
    finally:
        if own_group:
            signal.signal(signal.SIGTERM, previous_sigterm)
            if terminated:
                # Preserve caller termination semantics after the query is reaped.
                os.kill(os.getpid(), signal.SIGTERM)


def target_inputs(ninja: Path, out: Path, targets: list[str]) -> tuple[set[str], dict]:
    raw = query(ninja, out, ["-t", "inputs", *targets], MAX_INPUT_BYTES)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError(f"invalid UTF-8 in ninja -t inputs at byte {error.start}: "
                            f"{escaped_path(raw[error.start:error.start + MAX_PATH_EXAMPLE_CHARS])}") from error
    if text and not text.endswith("\n"):
        line_number = text.count("\n") + 1
        fragment = text.rsplit("\n", 1)[-1]
        raise EvidenceError(f"unterminated Ninja inputs output at ninja -t inputs line {line_number}: {escaped_path(fragment)}")
    names, examples = set(), []
    count = excluded = 0
    for count, line in enumerate(text[:-1].split("\n") if text else [], 1):
        line = line.removesuffix("\r")
        if not line or len(line) > MAX_LINE_BYTES or any(ord(char) < 32 for char in line):
            raise EvidenceError(f"malformed Ninja inputs output at ninja -t inputs line {count}: {escaped_path(line)}")
        if object_like(line):
            try:
                name = object_name(line)
            except EvidenceError:
                excluded += 1
                path_example(examples, line, "ninja -t inputs", count)
            else:
                names.add(name)
    return names, {"sha256": hashlib.sha256(raw).hexdigest(), "input_count": count,
                   "object_count": len(names), "tool": "ninja -t inputs",
                   "excluded_object_inputs": excluded, "excluded_object_input_examples": examples,
                   "validation_inputs_included": False}


def context(workdir: Path, platform: str, arch: str, ninja: Path, targets, repo: Path):
    work = restore.local_path(workdir)
    receipt = restore.verify_restored(work, platform, arch, repo=repo)
    out = restore.safe_path(work, Path("src/out/Default"))
    directory = restore.safe_path(work, Path(DIRECTORY))
    directory.mkdir(exist_ok=True)
    for name in ("baseline.json", "result.json"):
        restore.safe_path(directory, Path(name))
    ninja = Path(ninja)
    if (not ninja.is_absolute() or len(str(ninja)) > 4096
            or any(ord(char) < 32 for char in str(ninja))):
        raise EvidenceError("Ninja must be an absolute executable path")
    regular(ninja)
    targets = sorted(set(targets))
    if (not targets or len(targets) > 16 or any(not isinstance(value, str)
            or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_./+-]{0,199}", value)
            or ".." in value.split("/") for value in targets)):
        raise EvidenceError("invalid Ninja targets")
    version = query(ninja, out, ["--version"], 128).decode("ascii").strip()
    if not re.fullmatch(r"1\.(?:11|12|13)\.[0-9]+(?:\.chromium\.[0-9]+)?", version):
        raise EvidenceError("unsupported Ninja version; requires 1.11.x, 1.12.x or 1.13.x")
    manifest = {key: value for key, value in receipt["manifest"].items() if key != "path"}
    normalized = dict(receipt, manifest=manifest)
    source = {"identity": receipt["identity"], "manifest": manifest,
              "receipt_sha256": hashlib.sha256(json_bytes(normalized)).hexdigest()}
    return work, out, directory, source, targets, {"path": str(ninja), "version": version}


def parse_record(line: str, version: int) -> dict:
    if not line.endswith("\n"):
        raise EvidenceError("unterminated Ninja log record")
    fields = line.rstrip("\r\n").split("\t")
    if len(fields) != 5:
        raise EvidenceError("malformed Ninja log record")
    start, end, mtime, output, command_hash = fields
    if (not all(re.fullmatch(r"[0-9]{1,19}", value) for value in (start, end, mtime))
            or not 0 <= int(start) <= int(end) < 1 << 63 or not 0 <= int(mtime) < 1 << 63
            or not output or len(output) > 2048 or any(ord(char) < 32 for char in output)
            or not re.fullmatch(r"[0-9a-fA-F]{1,16}", command_hash)):
        raise EvidenceError("invalid Ninja log record")
    return {"start": int(start), "end": int(end), "mtime": int(mtime),
            "output": output, "hash": command_hash, "version": version}


def read_log(out: Path, selected: set[str], *, baseline=None, previous=None) -> tuple[dict, dict, tuple, dict]:
    path = restore.safe_path(out, Path(".ninja_log"))
    info = regular(path)
    if info.st_size > MAX_LOG_BYTES:
        raise EvidenceError("Ninja log exceeds byte cap")
    records, changed, count, total = {}, {}, 0, 0
    excluded, examples = 0, []
    unsupported_appended = False
    digest, prefix = hashlib.sha256(), hashlib.sha256()
    prefix_size = previous["size_bytes"] if previous is not None else 0
    originals = {sample["output"]: sample["record"] for sample in baseline["samples"]} if baseline else {}

    def consume(data):
        nonlocal total
        if total < prefix_size:
            prefix.update(data[:prefix_size - total])
        digest.update(data)
        total += len(data)

    with path.open("rb") as stream:
        header = stream.readline(128)
        match = re.fullmatch(rb"# ninja log v([567])\r?\n", header)
        if not match:
            raise EvidenceError("unsupported Ninja log version")
        version = int(match[1])
        consume(header)
        while True:
            line = stream.readline(MAX_LINE_BYTES + 1)
            if not line:
                break
            offset = total
            consume(line)
            if len(line) > MAX_LINE_BYTES or total > MAX_LOG_BYTES:
                raise EvidenceError(f"Ninja log exceeds byte cap at .ninja_log line {count + 2}: {escaped_path(line)}")
            try:
                record = parse_record(line.decode("utf-8"), version)
            except (EvidenceError, UnicodeDecodeError) as error:
                reason = "invalid UTF-8" if isinstance(error, UnicodeDecodeError) else str(error)
                raise EvidenceError(f"{reason} at .ninja_log line {count + 2}: {escaped_path(line)}") from error
            count += 1
            name = record["output"]
            if name in selected:
                records[name] = record
                if baseline and offset >= baseline["log"]["size_bytes"]:
                    changed.setdefault(name, "appended_record_changed" if record != originals[name]
                                       else "appended_record_repeated")
            elif object_like(name):
                try:
                    object_name(name)
                except EvidenceError:
                    excluded += 1
                    path_example(examples, name, ".ninja_log", count + 1)
                    if baseline and offset >= baseline["log"]["size_bytes"]:
                        unsupported_appended = True
    if stamp(regular(path)) != stamp(info):
        raise EvidenceError("Ninja log changed during observation")
    continuity = previous is None or (version == previous["version"] and total >= prefix_size
                                     and prefix.hexdigest() == previous["sha256"])
    if unsupported_appended:
        # An unsupported output may alias any sample, even with unchanged bytes and mtime.
        changed = dict.fromkeys(selected, "unsupported_appended_output")
    if not continuity:
        changed = dict.fromkeys(selected, "log_prefix_mismatch")
    log = {"version": version, "size_bytes": total, "record_count": count,
           "sha256": digest.hexdigest(), "prefix_size_bytes": prefix_size,
           "prefix_sha256": prefix.hexdigest(), "prefix_matches_previous": continuity,
           "unselected_unsupported_object_records": excluded, "unselected_unsupported_object_examples": examples}
    return records, log, stamp(info), changed


def file_record(path: Path, budget: int = MAX_HASH_BYTES, expected=None, *, header: bytearray | None = None) -> dict:
    info = regular(path)
    if (not 0 < info.st_size <= min(MAX_FILE_BYTES, budget)
            or not 0 < info.st_mtime_ns < 1 << 63):
        raise EvidenceError("object size or mtime outside supported bounds")
    if expected is not None and (info.st_size, info.st_mtime_ns) != (expected["size"], expected["mtime_ns"]):
        raise EvidenceError("object changed before hashing")
    digest = hashlib.sha256()
    prefix = b""
    remaining = info.st_size
    with path.open("rb") as stream:
        while remaining:
            data = stream.read(min(1024 * 1024, remaining))
            if not data:
                raise EvidenceError("object shortened during hashing")
            digest.update(data)
            if header is not None and len(prefix) < 64:
                prefix += data[:64 - len(prefix)]
            remaining -= len(data)
    if stamp(regular(path)) != stamp(info):
        raise EvidenceError("object changed during hashing")
    if header is not None:
        header.extend(prefix)
    return {"sha256": digest.hexdigest(), "size": info.st_size, "mtime_ns": info.st_mtime_ns}


def elf_architecture(header: bytes | bytearray) -> str:
    if (len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01"
            or struct.unpack_from("<H", header, 16)[0] != 1
            or struct.unpack_from("<I", header, 20)[0] != 1
            or struct.unpack_from("<H", header, 52)[0] != 64):
        return "unknown"
    return ELF_ARCHITECTURES.get(struct.unpack_from("<H", header, 18)[0], "unknown")


def architecture_report(source: dict, retained_outputs: dict, *, successful=False) -> dict:
    counts = dict.fromkeys((*ELF_ARCHITECTURES.values(), "unknown"), 0)
    counts.update(Counter(retained_outputs.values()))
    identity = source["identity"]
    target_count = counts.get(identity["arch"], 0) if identity["platform"] == "linux" else 0
    return {"schema_version": 1, "method": ARCHITECTURE_METHOD, "retained_outputs": retained_outputs,
            "retained_by_arch": counts, "target_retained_count": target_count,
            "target_retention_proven": successful and target_count > 0}


def architecture_valid(state: dict, baseline: dict) -> None:
    if "architecture_evidence" not in state:
        return
    data = state["architecture_evidence"]
    keys = {"schema_version", "method", "retained_outputs", "retained_by_arch",
            "target_retained_count", "target_retention_proven"}
    if (not isinstance(data, dict) or set(data) != keys
            or type(data["schema_version"]) is not int or data["schema_version"] != 1
            or data["method"] != ARCHITECTURE_METHOD
            or type(data["target_retained_count"]) is not int
            or type(data["target_retention_proven"]) is not bool):
        raise EvidenceError("invalid architecture evidence metadata")
    selected = {sample["output"]: sample for sample in baseline["samples"]}
    retained = data["retained_outputs"]
    counts = data["retained_by_arch"]
    if (not isinstance(retained, dict) or any(name not in selected or name in state["disqualified"]
            or not isinstance(arch, str) or arch not in (*ELF_ARCHITECTURES.values(), "unknown")
            for name, arch in retained.items())
            or not isinstance(counts, dict) or set(counts) != {*ELF_ARCHITECTURES.values(), "unknown"}
            or any(type(count) is not int or not 0 <= count <= len(selected) for count in counts.values())
            or (baseline["source"]["identity"]["platform"] != "linux"
                and any(arch != "unknown" for arch in retained.values()))):
        raise EvidenceError("invalid retained architecture counts")
    samples = state.get("samples", [])
    if not isinstance(samples, list) or len(samples) > len(selected):
        raise EvidenceError("invalid architecture observation samples")
    seen, observed_retained = set(), set()
    for sample in samples:
        if not isinstance(sample, dict) or not isinstance(sample.get("output"), str):
            raise EvidenceError("invalid architecture observation sample")
        name = sample["output"]
        if (name not in selected or name in seen
                or sample.get("status") != state["disqualified"].get(name, "retained")):
            raise EvidenceError("inconsistent architecture observation status")
        seen.add(name)
        if sample["status"] == "retained":
            if sample.get("file") != selected[name]["file"] or sample.get("record") != selected[name]["record"]:
                raise EvidenceError("architecture observation lacks retained content")
            observed_retained.add(name)
    if (("samples" in state or state["phase"] == "after") and seen != set(selected)
            or set(retained) != observed_retained):
        raise EvidenceError("inconsistent retained architecture outputs")
    if state["phase"] == "after":
        if (type(state.get("exit_code")) is not int or type(state.get("retained_count")) is not int
                or state["retained_count"] != len(retained)):
            raise EvidenceError("invalid architecture build outcome")
    elif state.get("exit_code") is not None:
        raise EvidenceError("invalid architecture before outcome")
    expected = architecture_report(baseline["source"], retained,
                                   successful=state["phase"] == "after" and state["exit_code"] == 0)
    if data != expected:
        raise EvidenceError("inconsistent architecture evidence summary")


def path_diagnostics_valid(data: dict, count_key: str, examples_key: str, origin: str, total: int) -> None:
    # Older observations did not include these diagnostic-only fields.
    if count_key not in data and examples_key not in data:
        return
    count, examples = data.get(count_key), data.get(examples_key)
    if (type(count) is not int or not 0 <= count <= total
            or not isinstance(examples, list) or len(examples) != min(count, MAX_PATH_EXAMPLES)):
        raise EvidenceError("invalid path exclusion diagnostics")
    first_line = 2 if origin == ".ninja_log" else 1
    for example in examples:
        if (not isinstance(example, dict) or set(example) != {"origin", "line", "path_escaped"}
                or example["origin"] != origin or type(example["line"]) is not int
                or not first_line <= example["line"] < total + first_line
                or not isinstance(example["path_escaped"], str)
                or not 0 < len(example["path_escaped"]) <= MAX_PATH_EXAMPLE_CHARS
                or any(not 32 <= ord(char) < 127 for char in example["path_escaped"])):
            raise EvidenceError("invalid path exclusion example")


def log_valid(log) -> None:
    if (not isinstance(log, dict) or type(log.get("version")) is not int or log["version"] not in (5, 6, 7)
            or any(type(log.get(key)) is not int or not 0 <= log[key] <= MAX_LOG_BYTES
                   for key in ("size_bytes", "record_count"))
            or not isinstance(log.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", log["sha256"])):
        raise EvidenceError("invalid log metadata")
    path_diagnostics_valid(log, "unselected_unsupported_object_records", "unselected_unsupported_object_examples",
                           ".ninja_log", log["record_count"])


def membership_valid(membership) -> None:
    if (not isinstance(membership, dict) or membership.get("tool") != "ninja -t inputs"
            or membership.get("validation_inputs_included") is not False
            or any(type(membership.get(key)) is not int or not 0 <= membership[key] <= MAX_INPUT_BYTES
                   for key in ("input_count", "object_count"))
            or not isinstance(membership.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", membership["sha256"])):
        raise EvidenceError("invalid target membership metadata")
    path_diagnostics_valid(membership, "excluded_object_inputs", "excluded_object_input_examples",
                           "ninja -t inputs", membership["input_count"])


def baseline_valid(data: dict, source: dict, targets: list[str]) -> None:
    if (data.get("schema_version") != 1 or data.get("owner") != OWNER
            or data.get("phase") != "baseline" or data.get("source") != source or data.get("targets") != targets
            or data.get("scope") != SCOPE or data.get("retention_proven") is not False
            or not isinstance(data.get("run"), dict)):
        raise EvidenceError("baseline identity, targets or schema changed")
    log = data.get("log")
    log_valid(log)
    membership_valid(data.get("membership"))
    samples = data.get("samples")
    if not isinstance(samples, list) or len(samples) > MAX_SAMPLES:
        raise EvidenceError("invalid baseline samples")
    names, total = set(), 0
    for sample in samples:
        if not isinstance(sample, dict) or set(sample) != {"output", "record", "file"}:
            raise EvidenceError("invalid baseline sample")
        name = object_name(sample["output"])
        record, file = sample["record"], sample["file"]
        if not isinstance(record, dict) or set(record) != {"start", "end", "mtime", "output", "hash", "version"}:
            raise EvidenceError("invalid baseline full log record")
        if (name in names or record["output"] != name or record["version"] != log["version"]
                or any(type(record[key]) is not int for key in ("start", "end", "mtime", "version"))):
            raise EvidenceError("inconsistent baseline log record")
        line = "\t".join(str(record[key]) for key in ("start", "end", "mtime", "output", "hash")) + "\n"
        if parse_record(line, record["version"]) != record or record["mtime"] <= 0:
            raise EvidenceError("invalid baseline log record")
        if (not isinstance(file, dict) or set(file) != {"sha256", "size", "mtime_ns"}
                or type(file["size"]) is not int or not 0 < file["size"] <= MAX_FILE_BYTES
                or type(file["mtime_ns"]) is not int or not 0 < file["mtime_ns"] < 1 << 63
                or not isinstance(file["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", file["sha256"])):
            raise EvidenceError("invalid baseline file metadata")
        names.add(name)
        total += file["size"]
    if total > MAX_HASH_BYTES:
        raise EvidenceError("baseline exceeds hashing byte cap")


def base_report(phase: str, source: dict, targets: list[str], ninja: dict) -> dict:
    return {"schema_version": 1, "owner": OWNER, "phase": phase, "status": "unproven",
            "retention_proven": False, "upstream_source_verified": True,
            "original_donor_records_verified": False, "scope": SCOPE,
            "caller_contract": CONTRACT, "source": source, "targets": targets,
            "ninja": ninja, "run": run_identity(), "exit_code": None,
            "limits": {"samples": MAX_SAMPLES, "object_hash_bytes": MAX_HASH_BYTES,
                       "object_bytes": MAX_FILE_BYTES}}


def state_valid(state: dict, baseline: dict) -> dict:
    if (state.get("schema_version") != 1 or state.get("owner") != OWNER
            or state.get("phase") not in ("before", "after") or state.get("status") == "error"
            or state.get("source") != baseline["source"] or state.get("targets") != baseline["targets"]
            or state.get("baseline_sha256") != hashlib.sha256(json_bytes(baseline)).hexdigest()):
        raise EvidenceError("previous observation identity or baseline changed")
    log_valid(state.get("log"))
    membership_valid(state.get("membership"))
    selected = {sample["output"] for sample in baseline["samples"]}
    disqualified = state.get("disqualified")
    if (not isinstance(disqualified, dict) or any(name not in selected or not isinstance(reason, str)
            or reason not in DISQUALIFICATION_REASONS for name, reason in disqualified.items())
            or type(state.get("disqualified_count")) is not int or state["disqualified_count"] != len(disqualified)
            or state.get("disqualification_reasons") != dict(Counter(disqualified.values()))):
        raise EvidenceError("invalid permanent disqualification metadata")
    architecture_valid(state, baseline)
    return dict(disqualified)


def observe(out: Path, baseline: dict, previous: dict, names: set[str], membership: dict, *, after_build=False) -> dict:
    disqualified = state_valid(previous, baseline)
    selected = {sample["output"] for sample in baseline["samples"]}
    records, log, log_stamp, changed = read_log(out, selected, baseline=baseline, previous=previous["log"])
    for name, reason in changed.items():
        disqualified.setdefault(name, reason)
    graph_changed = after_build and any(membership[key] != previous["membership"][key] for key in
                                        ("sha256", "input_count", "object_count", "tool", "validation_inputs_included"))
    observations, hashed = [], 0
    retained_architectures = {}
    for sample in baseline["samples"]:
        name = sample["output"]
        observation = {"output": name, "baseline": sample, "record": records.get(name)}
        if name in disqualified:
            status = disqualified[name]
        elif name not in names:
            status = "not_in_target_inputs"
        elif graph_changed:
            status = "target_inputs_changed"
        elif name not in records:
            status = "missing_record"
        elif records[name] != sample["record"]:
            status = "record_changed"
        else:
            try:
                path = object_path(out, name)
                info = regular(path)
            except (FileNotFoundError, NotADirectoryError):
                status = "missing_file"
            else:
                if info.st_size != sample["file"]["size"] or info.st_mtime_ns != sample["file"]["mtime_ns"]:
                    status = "file_metadata_changed"
                else:
                    header = bytearray()
                    observed = file_record(path, MAX_HASH_BYTES - hashed, sample["file"], header=header)
                    hashed += observed["size"]
                    observation["file"] = observed
                    status = "retained" if observed == sample["file"] else "content_changed"
                    if status == "retained":
                        retained_architectures[name] = (elf_architecture(header)
                            if baseline["source"]["identity"]["platform"] == "linux" else "unknown")
        if status != "retained":
            disqualified.setdefault(name, status)
        observation["status"] = status
        observations.append(observation)
    if hashed > MAX_HASH_BYTES:
        raise EvidenceError("objects changed beyond hashing byte cap")
    if stamp(regular(out / ".ninja_log")) != log_stamp:
        raise EvidenceError("Ninja log changed during observation")
    return {"log": log, "samples": observations, "object_hash_bytes": hashed,
            "architecture_evidence": architecture_report(baseline["source"], retained_architectures),
            "disqualified": disqualified, "disqualified_count": len(disqualified),
            "disqualification_reasons": dict(Counter(disqualified.values()))}


def before(workdir: Path, platform: str, arch: str, ninja: Path, targets=("chrome",), *, repo=REPO) -> dict:
    """Return the immutable baseline; result.json marks this invocation unproven."""
    _, out, directory, source, targets, runner = context(workdir, platform, arch, ninja, targets, repo)
    names, membership = target_inputs(Path(runner["path"]), out, targets)
    path = directory / "baseline.json"
    if path.exists():
        baseline = read_json(path)
        baseline_valid(baseline, source, targets)
        previous = read_json(directory / "result.json")
        observation = observe(out, baseline, previous, names, membership)
    else:
        if (directory / "result.json").exists():
            raise EvidenceError("baseline is missing from an existing observation; refusing to resample")
        selected, budget = set(), 0
        skipped = {"missing_file": 0, "file_byte_cap": 0, "total_byte_cap": 0,
                   "missing_record": 0, "nonpositive_log_mtime": 0}
        for name in sorted(names):
            try:
                candidate = object_path(out, name)
                info = regular(candidate)
            except (FileNotFoundError, NotADirectoryError):
                skipped["missing_file"] += 1
                continue
            if not 0 < info.st_size <= MAX_FILE_BYTES:
                skipped["file_byte_cap"] += 1
                continue
            if budget + info.st_size > MAX_HASH_BYTES:
                skipped["total_byte_cap"] += 1
                continue
            selected.add(name)
            budget += info.st_size
            if len(selected) == MAX_SAMPLES:
                break
        records, log, log_stamp, _ = read_log(out, selected)
        samples, hashed = [], 0
        for name in sorted(selected):
            if name not in records:
                skipped["missing_record"] += 1
                continue
            if records[name]["mtime"] <= 0:
                skipped["nonpositive_log_mtime"] += 1
                continue
            file = file_record(object_path(out, name), MAX_HASH_BYTES - hashed)
            hashed += file["size"]
            if hashed > MAX_HASH_BYTES:
                raise EvidenceError("objects changed beyond hashing byte cap")
            samples.append({"output": name, "record": records[name], "file": file})
        if stamp(regular(out / ".ninja_log")) != log_stamp:
            raise EvidenceError("Ninja log changed during baseline capture")
        baseline = base_report("baseline", source, targets, runner)
        baseline.update(samples=samples, membership=membership, log=log,
                        object_hash_bytes=hashed, skipped=skipped)
        baseline_valid(baseline, source, targets)
        write_json(path, baseline, exclusive=True)
        observation = {"log": log, "object_hash_bytes": hashed, "disqualified": {},
                       "architecture_evidence": architecture_report(source, {}),
                       "disqualified_count": 0, "disqualification_reasons": {}}
    report = base_report("before", source, targets, runner)
    report.update(observation)
    report.update(baseline_sha256=hashlib.sha256(json_bytes(baseline)).hexdigest(),
                  sample_count=len(baseline["samples"]), membership=membership,
                  eligible_outputs=sorted(names.intersection(sample["output"] for sample in baseline["samples"])),
                  retained_count=0, reason="Actual build outcome has not been observed.")
    write_json(directory / "result.json", report)
    return baseline


def after(workdir: Path, platform: str, arch: str, ninja: Path, targets=("chrome",), *, exit_code: int, repo=REPO) -> dict:
    """Compare original samples, permanently excluding every observed change."""
    if type(exit_code) is not int:
        raise EvidenceError("actual build exit code must be an integer")
    _, out, directory, source, targets, runner = context(workdir, platform, arch, ninja, targets, repo)
    baseline = read_json(directory / "baseline.json")
    baseline_valid(baseline, source, targets)
    pending = read_json(directory / "result.json")
    state_valid(pending, baseline)
    if (pending.get("phase") != "before" or pending.get("ninja") != runner or pending.get("run") != run_identity()):
        raise EvidenceError("after requires a matching before invocation and unchanged baseline")
    names, membership = target_inputs(Path(runner["path"]), out, targets)
    selected = {sample["output"] for sample in baseline["samples"]}
    eligible = pending.get("eligible_outputs")
    if (not isinstance(eligible, list) or any(not isinstance(name, str) or name not in selected for name in eligible)
            or len(set(eligible)) != len(eligible)):
        raise EvidenceError("invalid before membership metadata")
    observation = observe(out, baseline, pending, names.intersection(eligible), membership, after_build=True)
    observation["architecture_evidence"] = architecture_report(
        source, observation["architecture_evidence"]["retained_outputs"], successful=exit_code == 0)
    retained = sum(item["status"] == "retained" for item in observation["samples"])
    report = base_report("after", source, targets, runner)
    report.update(observation)
    report.update(status="incomplete" if exit_code else "retained" if retained else "unproven",
                  retention_proven=exit_code == 0 and retained > 0, exit_code=exit_code,
                  invocation_successful=exit_code == 0,
                  baseline_sha256=hashlib.sha256(json_bytes(baseline)).hexdigest(),
                  baseline_run=baseline["run"], sample_count=len(baseline["samples"]), retained_count=retained,
                  retained_bytes=sum(item["baseline"]["file"]["size"] for item in observation["samples"] if item["status"] == "retained"),
                  membership=membership, baseline_membership=baseline["membership"], before_membership=pending["membership"],
                  reason="Only sampled baseline objects are observed; no universal reuse percentage is inferred.")
    write_json(directory / "result.json", report)
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", nargs="?", choices=("before", "after"))
    parser.add_argument("--phase", dest="phase_option", choices=("before", "after"))
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--arch", required=True)
    parser.add_argument("--ninja", type=Path, required=True)
    parser.add_argument("--target", action="append", required=True)
    parser.add_argument("--exit-code", type=int)
    args = parser.parse_args(argv)
    phase = args.phase_option or args.phase
    if not phase or args.phase and args.phase_option and args.phase != args.phase_option:
        parser.error("specify one before/after phase")
    if (phase == "after") != (args.exit_code is not None):
        parser.error("--exit-code is required only for after")
    try:
        kwargs = {"exit_code": args.exit_code} if phase == "after" else {}
        value = (before if phase == "before" else after)(
            args.workdir, args.platform, args.arch, args.ninja, args.target, **kwargs)
        print(json.dumps({"phase": phase, "status": value["status"],
                          "retention_proven": value["retention_proven"]}, sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, restore.LocalError, subprocess.SubprocessError) as error:
        report = {"schema_version": 1, "owner": OWNER, "phase": phase, "status": "error",
                  "retention_proven": False, "upstream_source_verified": False,
                  "exit_code": args.exit_code, "run": run_identity(), "reason": str(error)[:512]}
        try:
            work = restore.local_path(args.workdir)
            directory = restore.safe_path(work, Path(DIRECTORY))
            directory.mkdir(exist_ok=True)
            path = restore.safe_path(directory, Path("result.json"))
            write_json(path, report)
        except (OSError, ValueError, RuntimeError, restore.LocalError):
            pass
        print("restored reuse evidence: " + report["reason"], file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
