"""Widget state headers remain compatible with Chromium 152 and 153."""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

REPO = Path(__file__).resolve().parents[2]
PATCH = REPO / "patches/0127-display-widget-state.patch"
TARGET = "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
PATCH_BIN = os.environ.get("PATCH_BIN") or shutil.which("gpatch") or shutil.which("patch")
pytestmark = pytest.mark.skipif(PATCH_BIN is None, reason="GNU patch is required")

INCLUDES = '''#include "third_party/blink/renderer/platform/widget/input/widget_base_input_handler.h"
#include "third_party/blink/renderer/platform/widget/widget_base_client.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "ui/base/dragdrop/mojom/drag_drop_types.mojom-shared.h"
#include "ui/base/mojom/menu_source_type.mojom-blink-forward.h"
#include "ui/base/mojom/window_show_state.mojom-blink-forward.h"
#include "ui/gfx/ca_layer_result.h"
'''
STATE = '''  // Used to override values given from the browser such as ScreenInfo,
  // WidgetScreenRect, WindowScreenRect, and the widget's size.
  Member<ScreenMetricsEmulator> device_emulator_;

  Member<AnimationFrameTimingMonitor> animation_frame_timing_monitor_;

'''


def source_fixture(version):
    includes = INCLUDES
    state_start = 1299
    if version == "153":
        includes = includes.replace('#include "ui/base/dragdrop/', '#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"\n#include "ui/base/dragdrop/', 1)
        state_start += 16
    lines = ["// unrelated line\n"] * 90 + includes.splitlines(keepends=True)
    lines += ["// unrelated line\n"] * (state_start - 1 - len(lines))
    return ("".join(lines) + STATE + "// trailing source\n").encode()


def apply_patch(src, *options):
    return subprocess.run([PATCH_BIN, "-p1", "--fuzz=0", "--batch", "--forward",
                           "--binary", "--get=0", "--no-backup-if-mismatch",
                           "--reject-file=-", *options, "-i", str(PATCH)],
                          cwd=src, env=dict(os.environ, LC_ALL="C", PATCH_GET="0"),
                          capture_output=True, timeout=30, check=False)


@pytest.mark.parametrize("version", ["152", "153"])
def test_widget_state_exact_roundtrip(tmp_path, version):
    target = tmp_path / TARGET
    target.parent.mkdir(parents=True)
    original = source_fixture(version)
    target.write_bytes(original)
    result = apply_patch(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert b"fuzz" not in result.stdout
    assert re.findall(rb"offset (-?\d+) lines?", result.stdout) == ([b"-1"] if version == "152" else [b"16"])
    expected = original.replace(b'#include "ui/base/mojom/window_show_state', b'#include "ui/display/screen_infos.h"\n#include "ui/base/mojom/window_show_state', 1)
    expected = expected.replace(b"  Member<ScreenMetricsEmulator> device_emulator_;\n", b"  Member<ScreenMetricsEmulator> device_emulator_;\n  bool uxr_display_initialized_ = false;\n  std::optional<display::ScreenInfos> last_web_exposed_screen_infos_;\n", 1)
    assert target.read_bytes() == expected
    assert apply_patch(tmp_path, "--dry-run").returncode != 0
    assert target.read_bytes() == expected
    result = apply_patch(tmp_path, "--reverse")
    assert result.returncode == 0, result.stdout + result.stderr
    assert target.read_bytes() == original


@pytest.mark.parametrize("version", ["152", "153"])
@pytest.mark.parametrize("anchor", [b"drag_drop_types.mojom-shared.h", b"menu_source_type.mojom-blink-forward.h", b"window_show_state.mojom-blink-forward.h", b"ca_layer_result.h"])
def test_widget_state_changed_include_rejected(tmp_path, version, anchor):
    target = tmp_path / TARGET
    target.parent.mkdir(parents=True)
    original = source_fixture(version).replace(anchor, b"incompatible_header.h", 1)
    target.write_bytes(original)
    result = apply_patch(tmp_path, "--dry-run")
    assert result.returncode != 0
    assert b"Hunk #1 FAILED" in result.stdout
    assert target.read_bytes() == original


def test_widget_state_additions_preserved():
    added = [line[1:] for line in PATCH.read_text().splitlines() if line.startswith("+") and not line.startswith("+++")]
    assert added == ['#include "ui/display/screen_infos.h"', '  bool uxr_display_initialized_ = false;', '  std::optional<display::ScreenInfos> last_web_exposed_screen_infos_;']
