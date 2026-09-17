"""Late patch regressions on independent Chromium 152/153 source excerpts.

0097 uses complete-file preimages after patches 0001-0096, not patch-derived
fixtures. 0111 and 0116 use untouched upstream files. Optional provenance
checks use CHROMIX_LATE_PATCH_PREIMAGE_152 and CHROMIX_LATE_PATCH_PREIMAGE_153,
pointing at independently prepared trees after the first 96 patches.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

REPO = Path(__file__).resolve().parents[2]
PATCH_BIN = os.environ.get("PATCH_BIN") or shutil.which("gpatch") or shutil.which("patch")
pytestmark = pytest.mark.skipif(PATCH_BIN is None, reason="GNU patch is required")
PATCHES = {
    "0097": REPO / "patches/0097-webgl-bridge-policy-cc.patch",
    "0111": REPO / "patches/0111-global-privacy-control.patch",
    "0116": REPO / "patches/0116-audio-persona.patch",
}
TARGETS = {
    "0097": "third_party/blink/renderer/modules/webgl/webgl_rendering_context_base.cc",
    "0111": "third_party/blink/renderer/modules/global_privacy_control/navigator_global_privacy_control.cc",
    "0116": "third_party/blink/renderer/modules/webaudio/audio_context.cc",
}
VERSIONS = ("152", "153")

# 152: gate-agent/fixed-working-tree-rerun/inputs/fixtures/linux/upstream.
# 153: sparse153/resume-official-20260914/baseline-complete/linux/upstream.
PREIMAGE_SHA256 = {
    "152": {
        "0097": "05208a6d832b768e7cfd0b24231b1c6c38d1bccc77fc1408b17d8e36135b6b11",
        "0111": "bf004185a6efa78101635e4ac9237c3702644d5bf92888acca16df2cc2ea96b3",
        "0116": "ee6536bdec4da66d88e50cd0a46a8db225134a4eaf1952e1f86cedc7d24e2beb",
    },
    "153": {
        "0097": "f5313063df1a824a7be81e9998a88ea98c17132b48d44d456f8ac04280abd952",
        "0111": "d89d3ee44a9e44cb9f85cdbb5de11c01b8925040764c8f8777efd33caa4e5655",
        "0116": "a3c32a989f5ec0881c25013afd85507b4d54099f8e9a1d4153a4c7c0129ead47",
    },
}

WEBGL_INCLUDES = b'''#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/string_utf8_adaptor.h"
#include "third_party/skia/include/core/SkColorType.h"
'''
FORMAT_INCLUDE = b'#include "third_party/blink/renderer/platform/wtf/text/format.h"\n'
WEBGL_BRIDGE = b'''bool WebGLRenderingContextBase::ReadBridgePixels(
    std::vector<uint8_t>* out,
    int width,
    int height) {
  auto* bridge = canvas_bridge::CanvasBridgeClient::Get();
  if (!bridge || !bridge->Connected() || bridge_canvas_id_ == 0 ||
      bridge_webgl_unsupported_ || width <= 0 || height <= 0) {
    return false;
  }
  auto pixels = bridge->GetImageDataCacheFirst(
      bridge_canvas_id_, 0, 0, static_cast<uint32_t>(width),
      static_cast<uint32_t>(height));
  if (!pixels || pixels->size() != static_cast<size_t>(width) * height * 4)
    return false;
  out->resize(pixels->size());
  const size_t row_bytes = static_cast<size_t>(width) * 4;
  for (int row = 0; row < height; ++row) {
    std::memcpy(out->data() + static_cast<size_t>(row) * row_bytes,
                pixels->data() + static_cast<size_t>(height - row - 1) * row_bytes,
                row_bytes);
  }
  return true;
}

void WebGLRenderingContextBase::clearDepth(GLfloat depth) {
  if (isContextLost())
    return;
  clear_depth_ = depth;
  ContextGL()->ClearDepthf(depth);
}
'''
WEBGL_READBACK = b'''  {
    ScopedDrawingBufferBinder binder(GetDrawingBuffer(), framebuffer);
    if (!binder.Succeeded()) {
      return;
    }
    ContextGL()->ReadPixels(x, y, width, height, format, type, data);
  }
}

void WebGLRenderingContextBase::RenderbufferStorageImpl(
    GLenum target,
    GLsizei samples,
    GLenum internalformat,
'''
GPC_SOURCE = b'''// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/global_privacy_control/navigator_global_privacy_control.h"

#include "third_party/blink/public/common/global_privacy_control/global_privacy_control_util.h"
#include "third_party/blink/renderer/core/execution_context/navigator_base.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"

namespace blink {
namespace NavigatorGlobalPrivacyControl {

bool globalPrivacyControl(NavigatorBase& navigator) {
  return IsGlobalPrivacyControlEnabled();
}

}  // namespace NavigatorGlobalPrivacyControl
}  // namespace blink
'''
GPC_TODO = b'''  // TODO(crbug.com/40745270): Currently, the GPC signal is controlled by a
  // feature flag, when a user facing setting is added, this should be modified
  // to use frame cached value.
'''
AUDIO_SOURCE = b'''double AudioContext::baseLatency() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);
  DCHECK(destination());

  return base_latency_;
}

double AudioContext::outputLatency() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(main_thread_sequence_checker_);
  DCHECK(destination());

  DeferredTaskHandler::GraphAutoLocker locker(GetDeferredTaskHandler());

  double factor = GetOutputLatencyQuantizingFactor();
  return std::round(output_position_.hardware_output_latency / factor) * factor;
}
'''
SOURCE_SECTIONS = {
    "152": {
        "0097": [(166, WEBGL_INCLUDES), (3129, WEBGL_BRIDGE), (5682, WEBGL_READBACK)],
        "0111": [(1, GPC_SOURCE.replace(b"  return IsGlobalPrivacyControlEnabled();\n",
                                       GPC_TODO + b"  return IsGlobalPrivacyControlEnabled();\n"))],
        "0116": [(1269, AUDIO_SOURCE)],
    },
    "153": {
        "0097": [(166, WEBGL_INCLUDES.replace(
            b'#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"\n',
            FORMAT_INCLUDE + b'#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"\n')),
            (3128, WEBGL_BRIDGE), (5681, WEBGL_READBACK)],
        "0111": [(1, GPC_SOURCE)],
        "0116": [(1241, AUDIO_SOURCE.replace(b"destination()", b"destinationNode()"))],
    },
}
SECURITY_INCLUDE = b'#include "third_party/blink/renderer/platform/weborigin/security_origin.h"\n'
BRIDGE_GUARD = b'''  if (!BridgeAllowedForThisContext())
    return false;
'''
BRIDGE_POLICY = b'''}

bool WebGLRenderingContextBase::BridgeAllowedForThisContext() {
  if (!bridge_policy_checked_) {
    bridge_policy_checked_ = true;
    bridge_policy_allowed_ = false;
    if (auto* bridge = canvas_bridge::CanvasBridgeClient::Get()) {
      std::string etld1;
      if (auto* context = GetExecutionContext();
          context && context->GetSecurityOrigin()) {
        etld1 = context->GetSecurityOrigin()->RegistrableDomain().Utf8();
      }
      bridge_policy_allowed_ = bridge->BridgeEnabledForOrigin(etld1);
    }
  }
  return bridge_policy_allowed_;
'''
READBACK_POLICY = b'''
    if (format == GL_RGBA && type == GL_UNSIGNED_BYTE &&
        bridge_canvas_id_ != 0 && !bridge_webgl_unsupported_ &&
        BridgeAllowedForThisContext()) {
      if (auto* bridge = canvas_bridge::CanvasBridgeClient::Get();
          bridge && bridge->Connected()) {
        auto remote = bridge->GetImageDataCacheFirst(
            bridge_canvas_id_, x, y, static_cast<uint32_t>(width),
            static_cast<uint32_t>(height));
        if (remote &&
            remote->size() == static_cast<size_t>(width) * height * 4) {
          std::memcpy(data, remote->data(), remote->size());
        }
      }
    }
'''
GPC_OVERRIDE = b'''  const std::string value =
      base::UxrConfig::GetInstance().Get("uxr-global-privacy-control");
  if (value == "true" || value == "1")
    return true;
  if (value == "false" || value == "0")
    return false;
'''
GPC_RETURN = b"  return IsGlobalPrivacyControlEnabled();\n"
AUDIO_RETURN = b"  return base_latency_;\n"
AUDIO_ANNOTATED = b"  return base_latency_;  // Latency getters remain derived from the active audio backend.\n"


def source_fixture(number, version, shift=0):
    lines = []
    for first, excerpt in SOURCE_SECTIONS[version][number]:
        assert len(lines) < first + shift
        lines.extend([b"// unrelated source line\n"] * (first + shift - 1 - len(lines)))
        lines.extend(excerpt.splitlines(keepends=True))
    return b"".join(lines) + b"// trailing source, not an EOF hunk\n"


def expected_source(number, original):
    if number == "0097":
        result = original.replace(
            b'#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"\n',
            SECURITY_INCLUDE + b'#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"\n', 1)
        bridge = WEBGL_BRIDGE.replace(
            b"  auto* bridge = canvas_bridge::CanvasBridgeClient::Get();\n",
            BRIDGE_GUARD + b"  auto* bridge = canvas_bridge::CanvasBridgeClient::Get();\n", 1)
        bridge = bridge.replace(b"  return true;\n}\n", b"  return true;\n" + BRIDGE_POLICY + b"}\n", 1)
        assert result.count(WEBGL_BRIDGE) == 1
        result = result.replace(WEBGL_BRIDGE, bridge, 1)
        read = b"    ContextGL()->ReadPixels(x, y, width, height, format, type, data);\n"
        return result.replace(read, read + READBACK_POLICY, 1)
    if number == "0111":
        include = b'#include "third_party/blink/renderer/modules/global_privacy_control/navigator_global_privacy_control.h"\n'
        result = original.replace(include, include + b'\n#include "base/uxr_config.h"\n', 1)
        return result.replace(GPC_RETURN, GPC_OVERRIDE + GPC_RETURN, 1)
    return original.replace(AUDIO_RETURN, AUDIO_ANNOTATED, 1)


def write_source(directory, number, data):
    target = directory / TARGETS[number]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return target


def apply_patch(directory, patch, *options):
    return subprocess.run(
        [PATCH_BIN, "-p1", "--fuzz=0", "--batch", "--forward", "--binary",
         "--get=0", "--no-backup-if-mismatch", "--reject-file=-", *options,
         "--input", str(patch)],
        cwd=directory, env=dict(os.environ, LC_ALL="C", PATCH_GET="0"),
        capture_output=True, timeout=30, check=False,
    )


def patch_hunks(number):
    parts = re.split(rb"(?=^@@ )", PATCHES[number].read_bytes(), flags=re.M)
    return parts[0], parts[1:]


@pytest.mark.parametrize("number", PATCHES)
@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("shift", [0, 23], ids=["pinned-lines", "shifted-lines"])
def test_late_patches_strict_roundtrip_and_duplicate_rejection(tmp_path, number, version, shift):
    original = source_fixture(number, version, shift)
    expected = expected_source(number, original)
    assert expected != original
    target = write_source(tmp_path, number, original)
    for reverse in (False, True):
        options = ("--reverse",) if reverse else ()
        before, after = (expected, original) if reverse else (original, expected)
        for dry_run in (True, False):
            result = apply_patch(tmp_path, PATCHES[number], *options,
                                 *(("--dry-run",) if dry_run else ()))
            output = result.stdout + result.stderr
            assert result.returncode == 0, output
            assert not re.search(rb"fuzz|FAILED", output, re.I), output
            if version == "153" and number != "0097" and not shift:
                assert b"offset" not in output
            assert target.read_bytes() == (before if dry_run else after)
        for dry_run in (True, False):
            result = apply_patch(tmp_path, PATCHES[number], *options,
                                 *(("--dry-run",) if dry_run else ()))
            output = result.stdout + result.stderr
            assert result.returncode == 1, output
            assert b"Skipping patch" in output or b"FAILED" in output, output
            assert target.read_bytes() == after
    assert target.read_bytes() == original


ANCHORS = [
    ("0097", index) for index in range(4)
] + [
    (number, index) for number in ("0111", "0116") for index in range(3)
]


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("number,anchor", ANCHORS)
def test_late_patches_reject_changed_anchor(tmp_path, version, number, anchor):
    original = source_fixture(number, version)
    if number == "0097":
        old = [b"runtime_enabled_features.h", b"post_cross_thread_task.h",
               b"cross_thread_functional.h", b"wtf/functional.h"][anchor]
        changed = original.replace(old, b"incompatible_upstream_anchor.h", 1)
    else:
        old = (GPC_RETURN if number == "0111" else AUDIO_RETURN) + b"}\n\n"
        lines = old.splitlines(keepends=True)
        lines[anchor] = b"// incompatible upstream anchor\n"
        changed = original.replace(old, b"".join(lines), 1)
    assert changed != original
    target = write_source(tmp_path, number, changed)
    result = apply_patch(tmp_path, PATCHES[number], "--dry-run")
    assert result.returncode == 1, result.stdout + result.stderr
    assert b"FAILED" in result.stdout
    assert target.read_bytes() == changed
    # Isolate the changed hunk so other valid hunks cannot partially modify it.
    header, hunks = patch_hunks(number)
    isolated = tmp_path / "changed-hunk.patch"
    isolated.write_bytes(header + hunks[1 if number == "0111" else 0])
    result = apply_patch(tmp_path, isolated)
    assert result.returncode == 1, result.stdout + result.stderr
    assert b"FAILED" in result.stdout
    assert target.read_bytes() == changed


@pytest.mark.parametrize("number", PATCHES)
def test_late_patches_preserve_exact_edits(number):
    lines = PATCHES[number].read_bytes().splitlines(keepends=True)
    added = b"".join(line[1:] for line in lines if line.startswith(b"+") and not line.startswith(b"+++"))
    removed = b"".join(line[1:] for line in lines if line.startswith(b"-") and not line.startswith(b"---"))
    expected = {
        "0097": (SECURITY_INCLUDE + BRIDGE_GUARD + BRIDGE_POLICY + READBACK_POLICY, b""),
        "0111": (b'\n#include "base/uxr_config.h"\n' + GPC_OVERRIDE + GPC_RETURN, GPC_RETURN),
        "0116": (AUDIO_ANNOTATED, AUDIO_RETURN),
    }
    assert (added, removed) == expected[number]
    if number == "0116":
        assert added.split(b"//", 1)[0].strip() == removed.strip()


def test_late_patches_use_only_stable_context():
    _, webgl = patch_hunks("0097")
    assert len(webgl) == 4
    assert webgl[0] == (
        b"@@ -168,4 +168,5 @@\n"
        b' #include "third_party/blink/renderer/platform/runtime_enabled_features.h"\n'
        b' #include "third_party/blink/renderer/platform/scheduler/public/post_cross_thread_task.h"\n'
        b"+" + SECURITY_INCLUDE +
        b' #include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"\n'
        b' #include "third_party/blink/renderer/platform/wtf/functional.h"\n'
    )
    _, gpc = patch_hunks("0111")
    assert len(gpc) == 2
    assert gpc[1] == (b"@@ -17,3 +19,9 @@\n-" + GPC_RETURN +
                      b"".join(b"+" + line for line in (GPC_OVERRIDE + GPC_RETURN).splitlines(keepends=True)) +
                      b" }\n \n")
    _, audio = patch_hunks("0116")
    assert audio == [b"@@ -1245,3 +1245,3 @@\n-" + AUDIO_RETURN + b"+" + AUDIO_ANNOTATED + b" }\n \n"]


@pytest.mark.parametrize("version", VERSIONS)
@pytest.mark.parametrize("number", PATCHES)
def test_late_source_excerpt_provenance(version, number):
    root = os.environ.get(f"CHROMIX_LATE_PATCH_PREIMAGE_{version}")
    if not root:
        pytest.skip(f"set CHROMIX_LATE_PATCH_PREIMAGE_{version} for complete-source provenance")
    data = (Path(root) / TARGETS[number]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == PREIMAGE_SHA256[version][number]
    lines = data.splitlines(keepends=True)
    for first, excerpt in SOURCE_SECTIONS[version][number]:
        assert b"".join(lines[first - 1:first - 1 + len(excerpt.splitlines())]) == excerpt
