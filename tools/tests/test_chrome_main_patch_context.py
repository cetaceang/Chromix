"""Strict chrome_main.cc context shared by Chromium 152 and 153."""
from __future__ import annotations

import hashlib
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
TARGET = "chrome/app/chrome_main.cc"
PATCH = REPO / "patches/0036-chrome-app-chrome_main-fingerprint-normalize.patch"
PATCH_BIN = os.environ.get("PATCH_BIN") or shutil.which("gpatch") or shutil.which("patch")
pytestmark = pytest.mark.skipif(PATCH_BIN is None, reason="GNU patch is required")

# Independent complete-source excerpts, not reconstructed from the patch.
# 152.0.7977.82: upstream blob f3c06b9e10d09d2c93e44f1f7597e4323b52b538.
# Full-file SHA-256: 7de66ddc2fed0c51d4cc87796555b1c3a887ade67282f889a525352e3719f829.
# 153.0.8010.36: upstream commit 507c6ee3e2f3b2ca0e660547e5b9ea4820c67f4c.
# Full-file SHA-256: 9bca15fa0892300b0696f4fab3d4d6559bd62abaab746be00512a674fc2a1d43.
EXCERPTS = {
    "152": (
        (7, b'''#include <stdint.h>

#include <iostream>
#include <memory>
#include <optional>

#include "base/command_line.h"
#include "base/environment.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/no_destructor.h"
#include "base/sampling_heap_profiler/poisson_allocation_sampler.h"
#include "base/time/time.h"
'''),
        (190, b'''#else
  params.argc = argc;
  params.argv = argv;
  base::CommandLine::Init(params.argc, params.argv);
#endif  // BUILDFLAG(IS_WIN)
  base::CommandLine::Init(0, nullptr);

  base::CommandLine* command_line(base::CommandLine::ForCurrentProcess());

  // Capture the unpolluted command line snapshot in the browser process.
  // This must happen immediately after CommandLine::Init to ensure we capture
  // the state before any internal programmatic mutations.
  if (!command_line->HasSwitch(switches::kProcessType)) {
    GetInitialCommandLineStorage() = *command_line;
  }

'''),
    ),
    "153": (
        (7, b'''#include <stdint.h>

#include <iostream>
#include <memory>
#include <optional>

#include "base/command_line.h"
#include "base/environment.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/logging.h"
#include "base/no_destructor.h"
#include "base/sampling_heap_profiler/poisson_allocation_sampler.h"
#include "base/time/time.h"
'''),
        (159, b'''#else
  params.argc = argc;
  params.argv = argv;
  base::CommandLine::Init(params.argc, params.argv);
#endif  // BUILDFLAG(IS_WIN)

  base::CommandLine* command_line(base::CommandLine::ForCurrentProcess());

  // Capture the unpolluted command line snapshot in the browser process.
  // This must happen immediately after CommandLine::Init to ensure we capture
  // the state before any internal programmatic mutations.
  if (!command_line->HasSwitch(switches::kProcessType)) {
    GetInitialCommandLineStorage() = *command_line;
  }

'''),
    ),
}
BASE_INCLUDES = b'''#include "base/i18n/tag_converters.h"
#include "base/rand_util.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
'''
CAPTURE = b"  // Capture the unpolluted command line snapshot in the browser process.\n"
DOMAIN_RULES = [(re.compile(r"example\.com"), "blocked.test")]


def source_fixture(version):
    lines = []
    for first, excerpt in EXCERPTS[version]:
        lines.extend([b"// unrelated source line\n"] * (first - 1 - len(lines)))
        lines.extend(excerpt.splitlines(keepends=True))
    # A synthetic sentinel exercises substitution outside the independent excerpts.
    return b"".join(lines) + b"// example.com\n"


def effective_inputs(original, substituted):
    data = PATCH.read_bytes()
    if substituted:
        original = arp._substitute(original.decode(), DOMAIN_RULES).encode()
        data, entries = arp.transform_patch(data, {TARGET}, DOMAIN_RULES)
        assert entries == [(TARGET, "modify", None)]
        assert data == PATCH.read_bytes()
    return original, data


def functional_additions():
    added = b"".join(line[1:] for line in PATCH.read_bytes().splitlines(keepends=True)
                     if line.startswith(b"+") and not line.startswith(b"+++"))
    # Pin all 341 added lines from the reviewed pre-context-change patch.
    assert hashlib.sha256(added).hexdigest() == (
        "4ad7777994a5526ccc0bca820d5c103720a9c1cc75902369824610257836c87a")
    includes = b"#include <vector>\n" + BASE_INCLUDES
    assert added.startswith(includes)
    return added[len(includes):]


def expected_source(original):
    expected = original.replace(b"#include <iostream>\n",
                                b"#include <iostream>\n#include <vector>\n", 1)
    expected = expected.replace(b'#include "base/environment.h"\n',
                                b'#include "base/environment.h"\n' + BASE_INCLUDES, 1)
    return expected.replace(CAPTURE, functional_additions() + CAPTURE, 1)


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
@pytest.mark.parametrize("substituted", [False, True], ids=["normal", "domain"])
def test_chrome_main_context_applies_and_roundtrips(tmp_path, version, substituted):
    original, data = effective_inputs(source_fixture(version), substituted)
    assert (b"// blocked.test\n" in original) == substituted
    target = tmp_path / TARGET
    target.parent.mkdir(parents=True)
    target.write_bytes(original)
    patch = tmp_path / "chrome-main.patch"
    patch.write_bytes(data)
    expected = expected_source(original)
    for dry_run in (True, False):
        result = run_patch(tmp_path, patch, dry_run=dry_run)
        output = result.stdout + result.stderr
        assert result.returncode == 0, output
        assert b"fuzz" not in output.lower()
        if version == "153":
            assert b"Hunk #3 succeeded at 170 (offset -32 lines)." in output
        else:
            assert b"offset" not in output
        assert target.read_bytes() == (original if dry_run else expected)
    for dry_run in (True, False):
        duplicate = run_patch(tmp_path, patch, dry_run=dry_run)
        assert duplicate.returncode == 1, duplicate.stdout + duplicate.stderr
        assert target.read_bytes() == expected
    for dry_run in (True, False):
        reverse = run_patch(tmp_path, patch, reverse=True, dry_run=dry_run)
        assert reverse.returncode == 0, reverse.stdout + reverse.stderr
        assert b"fuzz" not in (reverse.stdout + reverse.stderr).lower()
        assert target.read_bytes() == (expected if dry_run else original)


def test_chrome_main_patch_keeps_balanced_include_context():
    data = PATCH.read_bytes()
    arp.transform_patch(data, set(), [])
    assert re.findall(rb"^@@[^\n]*", data, flags=re.M) == [
        b"@@ -8,4 +8,5 @@", b"@@ -13,4 +14,9 @@", b"@@ -196,6 +202,341 @@",
    ]
    bodies = re.split(rb"^@@[^\n]*\n", data, flags=re.M)[1:]
    for body, count, context in zip(bodies, (1, 5, 335), (2, 2, 3)):
        lines = body.splitlines()
        changed = [i for i, line in enumerate(lines) if line.startswith((b"+", b"-"))]
        assert changed == list(range(context, context + count))
        assert len(lines) - changed[-1] - 1 == context
        assert all(lines[i].startswith(b"+") for i in changed)
    assert b'base/logging.h' not in data
    assert b'base/no_destructor.h' not in data


def test_chrome_main_patch_preserves_functional_additions():
    added = functional_additions()
    assert len(added.splitlines()) == 335
    assert b'if (!command_line->HasSwitch(switches::kProcessType)) {' in added
    for feature in (b'"fingerprint-platform"', b'"uxr-fingerprint-seed"',
                    b'"uxr-disable-fingerprint-noise"', b'"uxr-fingerprint-off"',
                    b'LanguageTagConverter::GetInstance().FromString(value)',
                    b'AppendSwitchASCII(switches::kAcceptLang, normalized)',
                    b'"window-size"', b'"window-position"', b'"uxr-allow-3p-cookies"'):
        assert feature in added
    assert added.index(b'"uxr-fingerprint-off"') < added.index(b'std::vector<std::string> languages;')


@pytest.mark.parametrize("version", EXCERPTS)
@pytest.mark.parametrize("substituted", [False, True], ids=["normal", "domain"])
@pytest.mark.parametrize("anchor", range(14))
def test_chrome_main_patch_rejects_changed_anchor(tmp_path, version, substituted, anchor):
    original, data = effective_inputs(source_fixture(version), substituted)
    first = 196 if version == "152" else 164
    anchors = [8, 9, 10, 11, 13, 14, 15, 16, *range(first, first + 6)]
    lines = original.splitlines(keepends=True)
    lines[anchors[anchor] - 1] = b"// incompatible upstream anchor\n"
    original = b"".join(lines)
    target = tmp_path / TARGET
    target.parent.mkdir(parents=True)
    target.write_bytes(original)
    patch = tmp_path / "chrome-main.patch"
    patch.write_bytes(data)
    result = run_patch(tmp_path, patch, dry_run=True)
    assert result.returncode == 1, result.stdout + result.stderr
    assert b"FAILED" in result.stdout
    assert target.read_bytes() == original


@pytest.mark.parametrize("version", EXCERPTS)
def test_chrome_main_restored_entry_and_freshness_gate(tmp_path, version):
    repo, src, core, tooling = (tmp_path / name for name in ("repo", "src", "core", "tooling"))
    for directory in (repo / "patches", (src / TARGET).parent, core, tooling):
        directory.mkdir(parents=True)
    shutil.copy2(PATCH, repo / "patches" / PATCH.name)
    (repo / "patches/series").write_text(f"patches/{PATCH.name}\n")
    (core / "domain_regex.list").write_bytes(rb"example\.com#blocked.test" + b"\n")
    (core / "domain_substitution.list").write_text(TARGET + "\n")
    original, _ = effective_inputs(source_fixture(version), True)
    (src / TARGET).write_bytes(original)
    result = arp.run_apply(src, repo, core, tooling, "linux", PATCH_BIN)
    assert result["status"] == "applied"
    assert result["patch_count"] == 1
    assert (src / TARGET).read_bytes() == expected_source(original)
    assert arp.run_apply(src, repo, core, tooling, "linux", PATCH_BIN)["status"] == "skipped"
    assert arp.run_apply(src, repo, core, tooling, "linux", PATCH_BIN, check=True)["status"] == "checked"
    (src / ".chromix-domain-substituted").touch()
    assert stack.verify(src, repo, core=core, tooling=tooling, platform="linux")["status"] == "verified"
