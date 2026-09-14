"""Strict inspector flag context shared by Chromium 152 and 153."""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

REPO = Path(__file__).resolve().parents[2]
PATCH = REPO / "patches/0063-v8-src-flags-flag-definitions-h.patch"
TARGET = "v8/src/flags/flag-definitions.h"
PATCH_BIN = os.environ.get("PATCH_BIN") or shutil.which("gpatch") or shutil.which("patch")
pytestmark = pytest.mark.skipif(PATCH_BIN is None, reason="GNU patch is required")

# Independent complete-source excerpts, not reconstructed from the patch.
# 152: gate-agent/fixed-working-tree-rerun input-manifest.json.
# Full-file SHA-256: e5184bf1277d8e3a07ebb50639a645714fec67a9fb458ecfd9ccf2a8e30a81be.
# 153: pinned V8 commit f343157cebb388bfa416baccb5d35507e6fe8cc7.
# Full-file SHA-256: 71c907289a46498c2f17040c83b3e3d76837d6b9aff705c45de3241ef306271d.
EXCERPTS = {
    "152": (3211, b'''// disassembler
DEFINE_BOOL(log_colour, ENABLE_LOG_COLOUR,
            "When logging, try to use coloured output.")

// inspector
DEFINE_BOOL(expose_inspector_scripts, false,
            "expose injected-script-source.js for debugging")
DEFINE_BOOL(inspector_live_edit, false,
            "Enable the Debugger.setScriptSource CDP command, otherwise it'll "
            "always fail with an error")

// execution.cc
//
'''),
    "153": (3243, b'''// disassembler
DEFINE_BOOL(log_colour, ENABLE_LOG_COLOUR,
            "When logging, try to use coloured output.")

// inspector
DEFINE_BOOL(expose_inspector_scripts, false,
            "expose injected-script-source.js for debugging")

// execution.cc
//
'''),
}
ADDITION = b'''DEFINE_BOOL(uxr_devtools_runtime_suppression, false,
            "suppress selected Runtime domain observables")
'''


def source_fixture(version):
    first, excerpt = EXCERPTS[version]
    return b"// unrelated source line\n" * (first - 1) + excerpt


def apply_patch(src, *options):
    return subprocess.run(
        [PATCH_BIN, "-p1", "--fuzz=0", "--batch", "--forward", "--binary",
         "--get=0", "--no-backup-if-mismatch", "--reject-file=-", *options,
         "--input", str(PATCH)],
        cwd=src, env=dict(os.environ, LC_ALL="C", PATCH_GET="0"),
        capture_output=True, timeout=30, check=False,
    )


@pytest.mark.parametrize("version", EXCERPTS)
def test_inspector_flag_strict_roundtrip(tmp_path, version):
    original = source_fixture(version)
    target = tmp_path / TARGET
    target.parent.mkdir(parents=True)
    target.write_bytes(original)
    expected = original.replace(b"// inspector\n", b"// inspector\n" + ADDITION, 1)
    for options in (("--dry-run",), ()):
        result = apply_patch(tmp_path, *options)
        output = result.stdout + result.stderr
        assert result.returncode == 0, output
        assert b"fuzz" not in output.lower()
        if version == "153":
            assert b"offset" not in output
        else:
            assert b"offset -32 lines" in output
        assert target.read_bytes() == (original if options else expected)
    assert target.read_bytes().count(ADDITION) == 1
    assert (b"DEFINE_BOOL(inspector_live_edit," in target.read_bytes()) == (version == "152")
    for options in (("--dry-run",), ()):
        result = apply_patch(tmp_path, *options)
        assert result.returncode == 1, result.stdout + result.stderr
        assert target.read_bytes() == expected
    for options in (("--reverse", "--dry-run"), ("--reverse",)):
        result = apply_patch(tmp_path, *options)
        assert result.returncode == 0, result.stdout + result.stderr
        assert b"fuzz" not in (result.stdout + result.stderr).lower()
        assert target.read_bytes() == (expected if "--dry-run" in options else original)


@pytest.mark.parametrize("version", EXCERPTS)
@pytest.mark.parametrize("anchor", range(4), ids=["blank", "inspector", "flag", "description"])
def test_inspector_flag_rejects_changed_anchor(tmp_path, version, anchor):
    first, excerpt = EXCERPTS[version]
    lines = excerpt.splitlines(keepends=True)
    lines[3 + anchor] = b"// incompatible upstream anchor\n"
    original = b"// unrelated source line\n" * (first - 1) + b"".join(lines)
    target = tmp_path / TARGET
    target.parent.mkdir(parents=True)
    target.write_bytes(original)
    for options in (("--dry-run",), ()):
        result = apply_patch(tmp_path, *options)
        assert result.returncode == 1, result.stdout + result.stderr
        assert b"FAILED" in result.stdout
        assert target.read_bytes() == original


def test_inspector_flag_preserves_added_content_and_false_default():
    lines = PATCH.read_bytes().splitlines(keepends=True)
    added = b"".join(line[1:] for line in lines
                     if line.startswith(b"+") and not line.startswith(b"+++"))
    removed = [line for line in lines
               if line.startswith(b"-") and not line.startswith(b"---")]
    assert added == ADDITION
    assert not removed
    assert re.findall(rb"DEFINE_BOOL\((\w+),\s*(\w+),", added) == [
        (b"uxr_devtools_runtime_suppression", b"false"),
    ]


def test_inspector_flag_uses_balanced_stable_context():
    data = PATCH.read_bytes()
    assert re.findall(rb"^@@[^\n]*", data, flags=re.M) == [b"@@ -3246,4 +3246,6 @@"]
    body = re.split(rb"^@@[^\n]*\n", data, flags=re.M)[1].splitlines()
    assert body[:2] == [b" ", b" // inspector"]
    assert body[2:4] == [b"+" + line for line in ADDITION.splitlines()]
    assert body[4:] == [
        b" DEFINE_BOOL(expose_inspector_scripts, false,",
        b'             "expose injected-script-source.js for debugging")',
    ]
    assert b"inspector_live_edit" not in data
