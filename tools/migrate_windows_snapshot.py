#!/usr/bin/env python3
"""Opt-in, one-shot migration of explicitly pinned historical Windows 152 x64 snapshots.

These profiles cannot migrate a 152 snapshot to a Chromium 153 target checkout.
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
import merge_gn_args
import verify_patch_stack as stack

DONOR_SHA = "97f2881b0e5f43b7e9563569d92dfe702ed1df0b"
STAGE9_DONOR_SHA = "30dbab28692793fa311c82ae639186003f3a67d9"
VERSION = "152.0.7977.82"
PATCH = "patches/0152-devtools-font-provenance-implementation.patch"
SOURCE = "third_party/blink/renderer/core/inspector/inspector_css_agent.cc"
READY = ".chromix-source-ready"
PATCH_MARKER = ".chromix-patches"
RECEIPT = ".chromix-windows-snapshot-migration.json"
LEGACY_PROFILE = "windows-152-x64-legacy-0152"
STAGE9_PROFILE = "windows-152-x64-stage9"
# Historical 152 patch names are not the merged main patch numbering.
# Source inventories are modify-only; additions require an explicit series entry.
STAGE9_PATCH_TARGETS = {
    "patches/0031-third_party-blink-renderer-platform-graphics-image_data_buffer-cc.patch": (
        "third_party/blink/renderer/platform/graphics/image_data_buffer.cc",),
    "patches/0036-chrome-app-chrome_main-fingerprint-normalize.patch": ("chrome/app/chrome_main.cc",),
    "patches/0125-display-emulation-backend.patch": (
        "third_party/blink/renderer/core/frame/screen_metrics_emulator.cc",),
    "patches/0126-display-widget-initialization.patch": (
        "third_party/blink/renderer/core/frame/web_frame_widget_impl.cc",),
    "patches/0127-display-widget-state.patch": (
        "third_party/blink/renderer/core/frame/web_frame_widget_impl.h",),
    "patches/0128-display-oopif-initialization.patch": (
        "third_party/blink/renderer/core/frame/web_remote_frame_impl.cc",),
    "patches/0175-blink-clock-quantization.patch": (
        "third_party/blink/renderer/core/timing/time_clamper.cc",),
    "patches/0176-launch-input-clock-aliases.patch": ("chrome/app/chrome_main.cc",),
    "patches/0182-mediarecorder-codec-policy.patch": (
        "third_party/blink/renderer/modules/mediarecorder/media_recorder_handler.cc",),
    "patches/0192-display-native-emulated-transport.patch": (
        "content/browser/renderer_host/cross_process_frame_connector.cc",),
    "patches/0193-animation-clock-quantization.patch": (
        "third_party/blink/renderer/core/animation/animation_clock.cc",),
    "patches/0194-document-timeline-clock-origin.patch": (
        "third_party/blink/renderer/core/animation/document_timeline.cc",),
    "patches/0195-display-render-widget-host-propagation.patch": (
        "content/browser/renderer_host/render_widget_host_impl.cc",),
    "patches/0196-display-render-widget-host-state.patch": (
        "content/browser/renderer_host/render_widget_host_impl.h",),
    "patches/0197-display-frame-visual-properties-mojo-read.patch": (
        "third_party/blink/common/frame/frame_visual_properties_mojom_traits.cc",),
    "patches/0198-display-widget-visual-properties-equality.patch": (
        "third_party/blink/common/widget/visual_properties.cc",),
    "patches/0199-display-widget-visual-properties-mojo-read.patch": (
        "third_party/blink/common/widget/visual_properties_mojom_traits.cc",),
    "patches/0200-display-frame-visual-properties-state.patch": (
        "third_party/blink/public/common/frame/frame_visual_properties.h",),
    "patches/0201-display-frame-visual-properties-mojo-traits.patch": (
        "third_party/blink/public/common/frame/frame_visual_properties_mojom_traits.h",),
    "patches/0202-display-widget-visual-properties-state.patch": (
        "third_party/blink/public/common/widget/visual_properties.h",),
    "patches/0203-display-widget-visual-properties-mojo-traits.patch": (
        "third_party/blink/public/common/widget/visual_properties_mojom_traits.h",),
    "patches/0204-display-frame-visual-properties-mojom.patch": (
        "third_party/blink/public/mojom/frame/frame_visual_properties.mojom",),
    "patches/0205-display-widget-visual-properties-mojom.patch": (
        "third_party/blink/public/mojom/widget/visual_properties.mojom",),
    "patches/0206-display-remote-frame-propagation.patch": (
        "third_party/blink/renderer/core/frame/remote_frame.cc",),
    "patches/0207-display-remote-frame-declaration.patch": (
        "third_party/blink/renderer/core/frame/remote_frame.h",),
    "patches/0208-display-native-emulated-regressions.patch": (
        "third_party/blink/renderer/core/frame/web_frame_widget_test.cc",),
}
STAGE9_CONTEXT_ONLY_PATCHES = frozenset({"patches/0176-launch-input-clock-aliases.patch"})
STAGE9_ALLOWED_PATCHES = frozenset(STAGE9_PATCH_TARGETS)
STAGE9_ALLOWED_SERIES_PATCHES = (
    "patches/0192-display-native-emulated-transport.patch",
    "patches/0193-animation-clock-quantization.patch",
    "patches/0194-document-timeline-clock-origin.patch",
    "patches/0195-display-render-widget-host-propagation.patch",
    "patches/0196-display-render-widget-host-state.patch",
    "patches/0197-display-frame-visual-properties-mojo-read.patch",
    "patches/0198-display-widget-visual-properties-equality.patch",
    "patches/0199-display-widget-visual-properties-mojo-read.patch",
    "patches/0200-display-frame-visual-properties-state.patch",
    "patches/0201-display-frame-visual-properties-mojo-traits.patch",
    "patches/0202-display-widget-visual-properties-state.patch",
    "patches/0203-display-widget-visual-properties-mojo-traits.patch",
    "patches/0204-display-frame-visual-properties-mojom.patch",
    "patches/0205-display-widget-visual-properties-mojom.patch",
    "patches/0206-display-remote-frame-propagation.patch",
    "patches/0207-display-remote-frame-declaration.patch",
    "patches/0208-display-native-emulated-regressions.patch",
)
LEGACY_SOURCE_REPLACEMENTS = (
    (b"  if (typeface.getTableTags(tags.data()) != count) {\n",
     b"  if (typeface.readTableTags(SkSpan<SkFontTableTag>(tags.data(), tags.size())) !=\n      count) {\n"),
    (b"             ? String::FromUTF8(base::HexEncodeLower(result))\n",
     b"             ? String::FromUtf8(base::HexEncodeLower(result))\n"),
    (b"    if (!value.table_hash.IsEmpty()) {\n", b"    if (!value.table_hash.empty()) {\n"),
)
LEGACY_PATCH_SHA256 = "5f17aff4fe201ebcf2744b5771b7b7762b37954e1bfa8d91b4e76cd95a11ad58"
LEGACY_PATCH_KEYS = frozenset({
    "ffe485c26dccca2067dd54eea8ed2cfca82926af1ce06c4a1bbe5ed6b603cc5b",
    "36e977855519280f2ced9e79673de54b37cee0395ecaf2b38a88ab924e5726dd",
})
MIGRATION_PROFILES = {
    LEGACY_PROFILE: {
        "name": LEGACY_PROFILE, "donor_sha": DONOR_SHA, "version": VERSION,
        "arch": "x64", "allowed_patches": frozenset({PATCH}),
        "allowed_series_patches": (), "accept_prior_receipt": False,
        "patch_targets": {PATCH: SOURCE},
    },
    STAGE9_PROFILE: {
        "name": STAGE9_PROFILE, "donor_sha": STAGE9_DONOR_SHA, "version": VERSION,
        "arch": "x64", "allowed_patches": STAGE9_ALLOWED_PATCHES,
        "allowed_series_patches": STAGE9_ALLOWED_SERIES_PATCHES,
        "accept_prior_receipt": True, "patch_targets": STAGE9_PATCH_TARGETS,
        "prior_targets": frozenset({"3bf77f6ca83d4f7a5041bc1b671effca9aa83a20"}),
        "prior_receipt_sha256": "cb7b483eaef7da43d1b125e296ff27067fd2fdc110e49c8b3c47852d6b147da9",
        "context_only_patches": STAGE9_CONTEXT_ONLY_PATCHES,
    },
}
# Both prepare and ci-stage reject this workdir directory, including an empty one.
BLOCKER = ".chromix-upstream-restore-windows-0152-migration"
TRUSTED_REPO = Path(__file__).resolve().parents[1]
WINDOWS = os.name == "nt"
PROTECTED_TREES = ("build", "assets", "patches")
PROTECTED_FILES = (
    "CHROMIUM_VERSION", ".gitattributes", "tools/apply_restored_patches.py", "tools/verify_patch_stack.py",
    "tools/prepare_restored_build.py", "tools/restore_upstream_cache.py",
    "tools/fetch_upstream_cache.py", "tools/upstream_script_identity.py", "tools/merge_gn_args.py",
    "tools/restore_ninja.py", "UNGOOGLED_VERSION", "UNGOOGLED_WINDOWS_VERSION",
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


def _profile(name: str | None) -> dict:
    selected = name or os.environ.get("CHROMIX_WINDOWS_MIGRATION_PROFILE", LEGACY_PROFILE)
    try:
        profile = MIGRATION_PROFILES[selected]
    except KeyError as exc:
        raise arp.ApplyError(f"unsupported Windows migration profile: {selected}") from exc
    return profile


def _profile_donor(profile: dict) -> str:
    return DONOR_SHA if profile["name"] == LEGACY_PROFILE else profile["donor_sha"]


def _series(repo: Path) -> list[str]:
    names = [line.split("#", 1)[0].strip() for line in
             _file(repo, "patches/series").read_text(encoding="utf-8-sig").splitlines()]
    names = [name for name in names if name]
    if not names or len(names) != len(set(names)):
        raise arp.ApplyError("invalid patch series")
    return names


def _series_additions(old: list[str], new: list[str], allowed) -> None:
    if new != old + list(allowed):
        raise arp.ApplyError("patch series differs outside the migration profile allowlist")


def _portable_identity(identity: dict, core: Path, tooling: Path) -> dict:
    value = json.loads(json.dumps(identity))
    for key, root, filename in (("regex", core, "domain_regex.list"),
                                ("list", tooling, "domain_substitution.list")):
        path = value[key]["path"].replace("\\", "/")
        if not path.endswith("/" + root.name + "/" + filename):
            raise arp.ApplyError("existing migration receipt has invalid tooling paths")
        value[key]["path"] = str(root / filename)
    return value


def _source_diff(name: str, before: bytes, after: bytes) -> str:
    return "".join(difflib.unified_diff(
        before.decode("utf-8").splitlines(keepends=True),
        after.decode("utf-8").splitlines(keepends=True),
        fromfile="a/" + name, tofile="b/" + name))


def _receipt_provenance(receipt: dict, old_key: str, old_report: dict,
                        profile: dict, before: dict, core: Path, tooling: Path,
                        source: bytes) -> None:
    try:
        if (not isinstance(receipt, dict) or type(receipt["schema_version"]) is not int
                or receipt["schema_version"] != 1 or receipt["status"] != "migrated"
                or receipt["operation"] != "windows-cold-0152-migration"
                or receipt["platform"] != "windows" or receipt["arch"] != "x64"
                or receipt["version"] != VERSION or receipt["previous_sha"] != DONOR_SHA
                or receipt["target_sha"] not in profile["prior_targets"]
                or receipt["key"] != old_key or receipt["changed_files"] != [SOURCE]
                or type(receipt["patch_count"]) is not int
                or receipt["patch_count"] != old_report["patch_count"]
                or receipt.get("profile", LEGACY_PROFILE) != LEGACY_PROFILE
                or "prior_receipt" in receipt):
            raise ValueError("wrong prior migration identity")
        prefix, legacy_key = receipt["previous_key"].rsplit("|", 1)
        if prefix != old_key.rsplit("|", 1)[0] or legacy_key not in LEGACY_PATCH_KEYS:
            raise ValueError("wrong prior preparation key")
        identity = old_report["identity"]
        if _portable_identity(receipt["identity"], core, tooling) != identity:
            raise ValueError("wrong donor input identity")
        previous_identity = json.loads(json.dumps(identity))
        entry = next(item for item in previous_identity["series"]["patches"] if item["path"] == PATCH)
        entry["sha256"] = LEGACY_PATCH_SHA256
        if _portable_identity(receipt["previous_identity"], core, tooling) != previous_identity:
            raise ValueError("wrong legacy input identity")
        change = receipt["source_change"]
        if (change["path"] != SOURCE or change["after_sha256"] != before[SOURCE][0]
                or not re.fullmatch(r"[0-9a-f]{64}", change["before_sha256"])
                or change["before_sha256"] == change["after_sha256"]
                or any(type(change[key]) is not int or change[key] < 0
                       for key in ("before_mtime_ns", "after_mtime_ns"))
                or change["after_mtime_ns"] < change["before_mtime_ns"] + 1_000_000_000
                or not change["diff"].startswith(f"--- a/{SOURCE}\n+++ b/{SOURCE}\n")):
            raise ValueError("wrong source transition")
        original = source
        newline = b"\r\n" if b"\r\n" in source else b"\n"
        for old, new in LEGACY_SOURCE_REPLACEMENTS:
            old, new = (part.replace(b"\n", newline) for part in (old, new))
            if original.count(new) != 1 or old in original:
                raise ValueError("source is not the exact legacy 0152 transition")
            original = original.replace(new, old)
        if (hashlib.sha256(original).hexdigest() != change["before_sha256"]
                or change["diff"] != _source_diff(SOURCE, original, source)
                or receipt.get("changed_patches", [PATCH]) != [PATCH]
                or receipt.get("source_changes", [change]) != [change]):
            raise ValueError("forged legacy source transition")
        for key, expected_identity in (("new_verification", identity),
                                       ("old_verification", previous_identity)):
            recorded = receipt[key]
            if _portable_identity(recorded["identity"], core, tooling) != expected_identity:
                raise ValueError("wrong stack proof identity")
            for field in ("schema_version", "status", "method", "domain_substituted", "patch_count"):
                if type(recorded[field]) is not type(old_report[field]) or recorded[field] != old_report[field]:
                    raise ValueError("wrong stack proof")
            outputs = dict(old_report["outputs"])
            if key == "old_verification":
                outputs[SOURCE] = change["before_sha256"]
            if recorded["outputs"] != outputs:
                raise ValueError("source differs from recorded stack outputs")
    except (KeyError, TypeError, ValueError, StopIteration, AttributeError) as exc:
        raise arp.ApplyError(f"existing migration receipt has invalid provenance: {exc}") from exc


def _load_receipt(path: Path) -> dict:
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate receipt field: " + key)
            value[key] = item
        return value

    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=unique_object)
        if not isinstance(value, dict):
            raise ValueError("receipt must be an object")
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise arp.ApplyError("existing migration receipt is not valid JSON provenance") from exc
    return value


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


def _patch_edits(data: bytes) -> list[bytes]:
    edits = []
    in_hunk = False
    for line in data.splitlines(keepends=True):
        if line.startswith(b"diff --git "):
            in_hunk = False
        elif arp.HUNK.fullmatch(line):
            in_hunk = True
        elif in_hunk and line[:1] in (b"+", b"-"):
            edits.append(line)
    return edits


def _inputs(previous: Path, repo: Path, old_tree: dict, new_tree: dict,
            profile: dict) -> tuple[dict, dict]:
    old_names = {name for name in old_tree if _protected(name)}
    new_names = {name for name in new_tree if _protected(name)}
    additions = set(profile["allowed_series_patches"])
    if ((old_names - additions) != (new_names - additions)
            or not set(PROTECTED_FILES).issubset(old_names)
            or not additions.issubset(new_names)):
        raise arp.ApplyError("preparation input inventory differs from the migration profile")
    captures = []
    for root, names in ((previous, old_names), (repo, new_names)):
        actual = set(PROTECTED_FILES)
        for directory in PROTECTED_TREES:
            actual.update(_walk_files(root, directory))
        if {name for name in actual if _protected(name)} != names:
            raise arp.ApplyError("untracked/extra or missing preparation input")
        captures.append(_capture(root, names))
    old, new = captures
    old_series, new_series = _series(previous), _series(repo)
    _series_additions(old_series, new_series, profile["allowed_series_patches"])
    if additions:
        expected_series = _file(previous, "patches/series").read_bytes() + b"".join(
            (name + "\n").encode("utf-8") for name in profile["allowed_series_patches"])
        if _file(repo, "patches/series").read_bytes() != expected_series:
            raise arp.ApplyError("series addition must be the exact allowlisted append")
    for name in sorted(old_names | new_names):
        if name in additions and name not in old_names:
            if new_tree[name][:2] != ("100644", "blob"):
                raise arp.ApplyError("series addition must be a regular non-executable patch: " + name)
            continue
        if old_tree.get(name, (None, None))[:2] != new_tree.get(name, (None, None))[:2]:
            raise arp.ApplyError(f"preparation Git mode changed: {name}")
        if name in old_names and name in new_names:
            if not WINDOWS and bool(old[name][1][2] & 0o111) != bool(new[name][1][2] & 0o111):
                raise arp.ApplyError(f"preparation executable mode changed: {name}")
            changed = old_tree[name] != new_tree[name] or old[name][0] != new[name][0]
            if changed and name in profile.get("context_only_patches", ()):
                if _patch_edits(_file(previous, name).read_bytes()) != _patch_edits(_file(repo, name).read_bytes()):
                    raise arp.ApplyError("only context relocation is allowed for " + name)
            if changed and name not in profile["allowed_patches"] and name != "patches/series":
                raise arp.ApplyError(f"pins/preparation/assets/lite/series differ outside migration profile: {name}")
            if name == "patches/series" and changed and not additions:
                raise arp.ApplyError("patch series changed without an explicit profile addition")
    changed = {name for name in old_names & new_names
               if old_tree[name] != new_tree[name] or old[name][0] != new[name][0]}
    changed.update(new_names - old_names)
    if not changed or not changed.issubset(set(profile["allowed_patches"]) | {"patches/series"}):
        raise arp.ApplyError("changed preparation patches are not explicitly allowlisted")
    if "patches/series" in changed:
        if not additions:
            raise arp.ApplyError("patch series changed without an explicit profile addition")
        if not set(profile["allowed_series_patches"]).issubset(set(profile["allowed_patches"])):
            raise arp.ApplyError("profile series addition is not also an allowed patch")
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


def _native_args(src: Path, repo: Path, core: Path, tooling: Path) -> None:
    order, merged = [], {}
    for root, name in ((core, "flags.gn"), (tooling, "flags.windows.gn"), (repo, "build/args.windows.gn")):
        keys, values = merge_gn_args.parse(_file(root, name))
        for key in keys:
            if key not in merged:
                order.append(key)
            merged[key] = values[key]
    expected = "\n".join([merge_gn_args.GENERATED_HEADER, *(merged[key] for key in order)])
    if _text(_file(src, "out/Chromix/args.gn")).replace("\r\n", "\n") != expected:
        raise arp.ApplyError("stage9 GN inputs must exactly match the pinned native configuration")


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
        raise arp.ApplyError("stack scratch " + ("reverse" if reverse else "apply") + " failed: " +
                             result.stdout.decode(errors="replace"))


def _write(path: Path, data: bytes, *, mode: int = 0o644, mtime_ns: int | None = None) -> None:
    _safe(path, missing=True)
    arp._atomic_write(path, data, mode, mtime_ns)
    if path.read_bytes() != data or mtime_ns is not None and path.stat().st_mtime_ns < mtime_ns:
        raise arp.ApplyError("atomic publication verification failed: " + str(path))


def migrate(workdir: Path | str, previous_repo: Path | str, repo: Path | str,
            expected_previous_sha: str, *, patch_bin: str, report_stream=None,
            profile: str | None = None) -> dict:
    profile = _profile(profile)
    donor_sha = _profile_donor(profile)
    if expected_previous_sha != donor_sha:
        raise arp.ApplyError("expected-previous-sha must be the fixed supported donor SHA for the profile")
    if profile["name"] == STAGE9_PROFILE and os.environ.get("CHROMIX_BUILD_PROFILE", "native") != "native":
        raise arp.ApplyError("stage9 migration requires the native build profile")
    work, previous, repo = (_safe(Path(p), directory=True) for p in (workdir, previous_repo, repo))
    if repo != TRUSTED_REPO:
        raise arp.ApplyError("--repo must be the running trusted helper checkout")
    roots = (work, previous, repo)
    if any(a.is_relative_to(b) for a in roots for b in roots if a != b) or len(set(roots)) != 3:
        raise arp.ApplyError("workdir and repositories must be separate, non-nested directories")
    _pins(repo)
    src = _safe(work / "src", directory=True)
    core = _safe(work / "tooling/ungoogled-chromium", directory=True)
    tooling = _safe(work / "tooling/ungoogled-chromium-windows", directory=True)
    temporary = _safe(Path(tempfile.gettempdir()), directory=True)
    if any(temporary.is_relative_to(root) for root in roots):
        raise arp.ApplyError("temporary directory must be outside workdir/repositories")
    _blockers(work, src)
    receipt_path = _file(src, RECEIPT, missing=True)
    receipt_state = _fingerprint(receipt_path, missing=True)
    prior_receipt = None
    if receipt_state is not None:
        if not profile["accept_prior_receipt"]:
            raise arp.ApplyError("explicit repeat refused: migration receipt already exists; do not migrate twice")
        prior_receipt = _load_receipt(receipt_path)
        if isinstance(prior_receipt, dict) and prior_receipt.get("profile") == profile["name"]:
            raise arp.ApplyError("explicit repeat refused: this profile already has a migration receipt")
        if receipt_state[0] != profile["prior_receipt_sha256"]:
            raise arp.ApplyError("existing migration receipt provenance digest does not match the pinned snapshot")
    elif profile["accept_prior_receipt"]:
        raise arp.ApplyError("stage9 requires the exact prior 0152 migration receipt")
    git = _host_git(roots)
    old_head, old_tree = _tree(git, previous, donor_sha)
    old_tracked = _tracked(previous, old_tree)
    new_head, new_tree = _tree(git, repo)
    old_inputs, new_inputs = _inputs(previous, repo, old_tree, new_tree, profile)
    for name in new_inputs:
        mode, kind, digest = new_tree[name]
        if kind != "blob" or mode not in ("100644", "100755"):
            raise arp.ApplyError("unsupported target preparation Git entry: " + name)
        if name not in profile["allowed_patches"] and digest not in new_inputs[name][2:]:
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
    if profile["name"] == STAGE9_PROFILE:
        _native_args(src, repo, core, tooling)
    old_identity, old_patches, old_lite = arp._load(previous, core, tooling, "windows")
    identity, patches, lite = arp._load(repo, core, tooling, "windows")
    names = {entry[0] for sequence in (old_patches, patches) for _, _, entries in sequence for entry in entries}
    if any(name.split("/", 1)[0].casefold() == "out" or name.startswith(".ninja") for name in names | set(lite)):
        raise arp.ApplyError("patch/lite inputs must not touch the object cache")
    changed_patches = {name for name in profile["allowed_patches"]
                       if name in new_inputs and (name not in old_inputs or old_inputs[name][0] != new_inputs[name][0])}
    affected = set()
    if not changed_patches.issubset({name for name, _, _ in patches}):
        raise arp.ApplyError("changed allowlisted patch is absent from the active series")
    for sequence in (old_patches, patches):
        for name, _, entries in sequence:
            if name not in changed_patches:
                continue
            targets = profile["patch_targets"].get(name, ())
            if isinstance(targets, str):
                targets = (targets,)
            approved = [(target, "modify", None) for target in targets]
            if (not entries or any(entry not in approved for entry in entries)
                    or sequence is patches and entries != approved):
                raise arp.ApplyError(f"{name} must only modify the single approved source file or exact profile inventory")
            affected.update(entry[0] for entry in entries)
    if not affected or set(lite) & names or lite != old_lite:
        raise arp.ApplyError("unsupported patch/lite overlap or empty source change")
    for name, (data, _) in old_lite.items():
        if _file(src, name).read_bytes() != data:
            raise arp.ApplyError("source lite payload mismatch: " + name)
    before = _capture(src, names | set(lite))
    old_report = _verify(src, previous, core, tooling)
    _unchanged(src, before | markers)
    if prior_receipt is not None:
        _receipt_provenance(prior_receipt, old_key, old_report, profile, before, core, tooling,
                            _file(src, SOURCE).read_bytes())
    originals = {name: _file(src, name).read_bytes() if before[name] is not None else None for name in before}
    for original in originals.values():
        if original is not None and b"\r\n" in original and b"\n" in original.replace(b"\r\n", b""):
            raise arp.ApplyError("mixed source line endings are unsupported")

    def recheck():
        _blockers(work, src, owned=True)
        if _fingerprint(_file(src, RECEIPT, missing=True), missing=True) != receipt_state:
            raise arp.ApplyError("migration receipt changed concurrently")
        if _tree(git, previous, donor_sha) != (old_head, old_tree):
            raise arp.ApplyError("previous repository changed concurrently")
        if _tree(git, repo) != (new_head, new_tree):
            raise arp.ApplyError("target repository changed concurrently")
        _unchanged(previous, old_tracked)
        _unchanged(repo, new_inputs)
        if _inputs(previous, repo, old_tree, new_tree, profile) != (old_inputs, new_inputs):
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
    operation = "windows-cold-0152-migration" if profile["name"] == LEGACY_PROFILE else "windows-stage9-migration"
    _write(state, arp._json({"operation": operation, "profile": profile["name"], "previous_key": old_key, "key": key}))
    lock_state = _fingerprint(state)
    with tempfile.TemporaryDirectory(prefix="chromix-windows-0152-", dir=temporary) as directory:
        scratch = Path(directory)
        stage = scratch / "src"
        stage.mkdir()
        for name, original in originals.items():
            if original is not None:
                target = stage / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(original.replace(b"\r\n", b"\n"))
        # Reverse the complete old stack; overlapping later patches cannot be skipped.
        for sequence, reverse in ((reversed(old_patches), True), (patches, False)):
            for _, data, entries in sequence:
                _apply(stage, scratch, data, program, reverse=reverse)
                for name, action, _ in entries:
                    target = _file(stage, name, missing=True)
                    removed = action == ("create" if reverse else "delete")
                    if target.exists() == removed:
                        raise arp.ApplyError("scratch stack has unexpected file state: " + name)
        candidates = {}
        for name, original in originals.items():
            target = _file(stage, name, missing=True)
            candidate = target.read_bytes() if target.exists() else None
            if original is not None and candidate is not None and b"\r\n" in original:
                candidate = candidate.replace(b"\n", b"\r\n")
            if candidate is not None:
                target.write_bytes(candidate)
            if candidate != original:
                if name not in affected or candidate is None or original is None:
                    raise arp.ApplyError("source change outside approved modify-only targets: " + name)
                candidates[name] = candidate
        if not candidates:
            raise arp.ApplyError("allowlisted patches did not change the source")
        recheck()
        _unchanged(src, before | markers)
        (stage / ".chromix-domain-substituted").write_bytes(pins["UngoogledCommit"].encode())
        candidate_report = _verify(stage, repo, core, tooling)
        recheck()
        _unchanged(src, before | markers)
        _safe(blocker, directory=True)
        if _fingerprint(state) != lock_state:
            raise arp.ApplyError("transaction blocker changed concurrently")
        changes = []
        published = {}
        for name, candidate in sorted(candidates.items()):
            _unchanged(src, before | published | markers)
            info = _file(src, name).stat()
            # NTFS timestamps have 100 ns resolution; round up to a whole second.
            mtime = ((max(time.time_ns(), info.st_mtime_ns + 1_000_000_000) + 999_999_999)
                     // 1_000_000_000 * 1_000_000_000)
            _write(_file(src, name), candidate, mode=stat.S_IMODE(info.st_mode), mtime_ns=mtime)
            changes.append({"path": name, "before_sha256": before[name][0],
                            "after_sha256": hashlib.sha256(candidate).hexdigest(),
                            "before_mtime_ns": info.st_mtime_ns,
                            "after_mtime_ns": _file(src, name).stat().st_mtime_ns,
                            "diff": _source_diff(name, originals[name], candidate)})
            published.update(_capture(src, [name]))
        final_report = _verify(src, repo, core, tooling)
        if final_report["outputs"] != candidate_report["outputs"]:
            raise arp.ApplyError("published source differs from verified candidate")
        recheck()
        _unchanged(src, before | published | markers)
        if _fingerprint(state) != lock_state:
            raise arp.ApplyError("transaction blocker changed concurrently")
        report = {
            "schema_version": 1, "status": "migrated", "operation": operation,
            "profile": profile["name"],
            "platform": "windows", "arch": "x64", "version": VERSION,
            "previous_sha": old_head, "target_sha": new_head,
            "previous_key": old_key, "key": key,
            "previous_identity": old_identity, "identity": identity,
            "changed_files": sorted(candidates), "patch_count": len(patches),
            "changed_patches": sorted(changed_patches), "source_changes": changes,
            "old_verification": old_report, "new_verification": final_report,
            "qualification": "patch structure verified; not compilation or full upstream attestation",
        }
        if profile["name"] == LEGACY_PROFILE:
            report["source_change"] = changes[0]
        if prior_receipt is not None:
            report["prior_receipt"] = prior_receipt
            report["prior_receipt_sha256"] = receipt_state[0]
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
    parser.add_argument("--profile", choices=tuple(MIGRATION_PROFILES),
                        help="explicit pinned migration profile (or CHROMIX_WINDOWS_MIGRATION_PROFILE)")
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
                                 args.expected_previous_sha, patch_bin=args.patch_bin, report_stream=output,
                                 profile=args.profile)
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
