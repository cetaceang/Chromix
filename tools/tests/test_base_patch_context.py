"""Strict base BUILD.gn context shared by the pinned Chromium 152 and 153."""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import apply_restored_patches as arp
import verify_patch_stack as stack

REPO = Path(__file__).resolve().parents[2]
PATCH = REPO / "patches/0001-base-BUILD-gn.patch"
PATCH_BIN = os.environ.get("PATCH_BIN") or shutil.which("gpatch") or shutil.which("patch")
pytestmark = pytest.mark.skipif(PATCH_BIN is None, reason="GNU patch is required")

# Independent excerpts: 152 lines 1011–1018 and 153 lines 1021–1027.
EXCERPTS = {
    "152": (1011, b'''    "types/variant_util.h",
    "types/zip.h",
    "unguessable_token.cc",
    "unguessable_token.h",
    "uuid.cc",
    "uuid.h",
    "value_iterators.cc",
    "value_iterators.h",
'''),
    "153": (1021, b'''    "types/variant_util.h",
    "unguessable_token.cc",
    "unguessable_token.h",
    "uuid.cc",
    "uuid.h",
    "value_iterators.cc",
    "value_iterators.h",
'''),
}


def source_fixture(version):
    first, excerpt = EXCERPTS[version]
    return b"# unrelated source line\n" * (first - 1) + excerpt + b"]\n"


def run_patch(src, patch, *, reverse=False, dry_run=False):
    options = ["--reverse"] if reverse else []
    if dry_run:
        options.append("--dry-run")
    return subprocess.run(
        [PATCH_BIN, *arp.PATCH_OPTIONS, *options, "--input", str(patch)],
        cwd=src, env=dict(os.environ, LC_ALL="C", PATCH_GET="0"),
        capture_output=True, check=False, timeout=30,
    )


@pytest.mark.parametrize("version", EXCERPTS)
@pytest.mark.parametrize("substituted", [False, True])
def test_base_context_applies_and_roundtrips(tmp_path, version, substituted):
    original = source_fixture(version)
    target = tmp_path / "base/BUILD.gn"
    target.parent.mkdir()
    target.write_bytes(original)
    data = PATCH.read_bytes()
    if substituted:
        data, _ = arp.transform_patch(data, {"base/BUILD.gn"}, [])
    patch = tmp_path / "base.patch"
    patch.write_bytes(data)
    applied = run_patch(tmp_path, patch)
    assert applied.returncode == 0, applied.stdout + applied.stderr
    assert b"fuzz" not in applied.stdout.lower()
    if version == "153":
        assert b"offset" not in applied.stdout
    else:
        assert b"offset -9 lines" in applied.stdout
    expected = original.replace(b'    "uuid.cc",\n',
                                b'    "uxr_config.cc",\n    "uxr_config.h",\n    "uuid.cc",\n', 1)
    assert target.read_bytes() == expected
    duplicate = run_patch(tmp_path, patch, dry_run=True)
    assert duplicate.returncode != 0
    assert target.read_bytes() == expected
    reversed_result = run_patch(tmp_path, patch, reverse=True)
    assert reversed_result.returncode == 0, reversed_result.stdout + reversed_result.stderr
    assert target.read_bytes() == original


@pytest.mark.parametrize("version", EXCERPTS)
def test_base_restored_entry_and_freshness_gate(tmp_path, version):
    repo, src, core, tooling = (tmp_path / name for name in ("repo", "src", "core", "tooling"))
    for directory in (repo / "patches", src / "base", core, tooling):
        directory.mkdir(parents=True)
    shutil.copy2(PATCH, repo / "patches" / PATCH.name)
    (repo / "patches/series").write_text(f"patches/{PATCH.name}\n")
    (core / "domain_regex.list").write_bytes(rb"example\.com#blocked.test" + b"\n")
    (core / "domain_substitution.list").write_text("base/BUILD.gn\n")
    original = source_fixture(version) + b"# blocked.test\n"
    (src / "base/BUILD.gn").write_bytes(original)
    result = arp.run_apply(src, repo, core, tooling, "linux", PATCH_BIN)
    assert result["status"] == "applied"
    assert result["patch_count"] == 1
    assert arp.run_apply(src, repo, core, tooling, "linux", PATCH_BIN)["status"] == "skipped"
    assert arp.run_apply(src, repo, core, tooling, "linux", PATCH_BIN, check=True)["status"] == "checked"
    (src / ".chromix-domain-substituted").touch()
    assert stack.verify(src, repo, core=core, tooling=tooling, platform="linux")["status"] == "verified"


def test_base_patch_keeps_balanced_context_and_only_two_additions():
    data = PATCH.read_bytes()
    arp.transform_patch(data, set(), [])
    assert b'@@ -1022,4 +1022,6 @@ component("base") {\n' in data
    body = re.split(rb"^@@[^\n]*\n", data, flags=re.M)[1].splitlines()
    changed = [i for i, line in enumerate(body) if line.startswith((b"+", b"-"))]
    assert changed == [2, 3]
    assert len(body) - changed[-1] - 1 == 2
    assert [body[i] for i in changed] == [b'+    "uxr_config.cc",', b'+    "uxr_config.h",']
    assert b"types/zip.h" not in data


@pytest.mark.parametrize("version", EXCERPTS)
@pytest.mark.parametrize("anchor", [b"unguessable_token.cc", b"unguessable_token.h", b"uuid.cc", b"uuid.h"])
def test_base_patch_rejects_changed_anchor(tmp_path, version, anchor):
    target = tmp_path / "base/BUILD.gn"
    target.parent.mkdir()
    original = source_fixture(version).replace(anchor, b"incompatible_source", 1)
    target.write_bytes(original)
    result = run_patch(tmp_path, PATCH, dry_run=True)
    assert result.returncode != 0
    assert b"FAILED" in result.stdout
    assert target.read_bytes() == original


def test_cold_entry_rejects_fuzzy_context(tmp_path):
    repo = tmp_path / "repo"
    (repo / "build").mkdir(parents=True)
    (repo / "patches").mkdir()
    shutil.copy2(REPO / "build/apply-patches.sh", repo / "build/apply-patches.sh")
    (repo / "patches/series").write_text("patches/context.patch\n")
    patch = repo / "patches/context.patch"
    patch.write_text('''--- a/value.txt
+++ b/value.txt
@@ -1,7 +1,7 @@
 expected leading context
 unchanged one
 unchanged two
-old value
+new value
 unchanged three
 unchanged four
 expected trailing context
''')
    src = tmp_path / "src"
    src.mkdir()
    original = b"different leading context\nunchanged one\nunchanged two\nold value\nunchanged three\nunchanged four\ndifferent trailing context\n"
    (src / "value.txt").write_bytes(original)
    permissive = subprocess.run([PATCH_BIN, "-p1", "--batch", "--forward", "--dry-run", "-i", str(patch)],
                                cwd=src, capture_output=True, check=False, timeout=30)
    assert permissive.returncode == 0
    assert b"fuzz" in permissive.stdout
    strict = subprocess.run(["bash", str(repo / "build/apply-patches.sh"), str(src)],
                            env=dict(os.environ, PATCH_BIN=PATCH_BIN, LC_ALL="C"),
                            capture_output=True, check=False, timeout=30)
    assert strict.returncode != 0
    assert b"FAILED" in strict.stdout
    assert (src / "value.txt").read_bytes() == original
