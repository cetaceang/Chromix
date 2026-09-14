"""Keep the audio rate annotation independent of destination API changes."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest

REPO = Path(__file__).resolve().parents[2]
PATCH = REPO / "patches/0053-third_party-blink-renderer-modules-webaudio-base_audio_context-h.patch"
TARGET = "third_party/blink/renderer/modules/webaudio/base_audio_context.h"
PATCH_BIN = os.environ.get("PATCH_BIN") or shutil.which("gpatch") or shutil.which("patch")
pytestmark = pytest.mark.skipif(PATCH_BIN is None, reason="GNU patch is required")

# Independent source excerpts at the pinned 152 and 153 revisions.
EXCERPTS = {
    "152": (116, '''  // https://webaudio.github.io/web-audio-api/#BaseAudioContext
  // Cannot be called from the audio thread.
  AudioDestinationNode* destination() const;
  float sampleRate() const { return destination_handler_->SampleRate(); }
  double currentTime() const { return destination_handler_->CurrentTime(); }
  AudioListener* listener() { return listener_.Get(); }
'''),
    "153": (116, '''  // https://webaudio.github.io/web-audio-api/#BaseAudioContext
  //
  // Cannot be called from the audio thread. This method returns a
  // GarbageCollected object, which must not be accessed on the real-time audio
  // thread. For audio thread access, use the corresponding
  // AudioDestinationHandler instead.
  virtual AudioDestinationNode* destinationNode() const;

  float sampleRate() const { return destination_handler_->SampleRate(); }
  double currentTime() const { return destination_handler_->CurrentTime(); }
  AudioListener* listener() { return listener_.Get(); }
'''),
}
ANNOTATION = b"    // Scheduling, decoding and JS must agree with the actual rendering rate.\n"
OLD_GETTER = b"  float sampleRate() const { return destination_handler_->SampleRate(); }\n"
NEW_GETTER = b"  float sampleRate() const {\n" + ANNOTATION + b"    return destination_handler_->SampleRate();\n  }\n"


def source_fixture(version):
    first, excerpt = EXCERPTS[version]
    return b"// unrelated source line\n" * (first - 1) + excerpt.encode() + b"};\n"


def apply_patch(src, patch, *options):
    return subprocess.run(
        [PATCH_BIN, "-p1", "--fuzz=0", "--batch", "--forward", "--binary",
         "--get=0", "--no-backup-if-mismatch", "--reject-file=-", *options,
         "--input", str(patch)],
        cwd=src, env=dict(os.environ, LC_ALL="C", PATCH_GET="0"),
        capture_output=True, timeout=30, check=False,
    )


@pytest.mark.parametrize("version", EXCERPTS)
def test_audio_annotation_strict_roundtrip(tmp_path, version):
    original = source_fixture(version)
    target = tmp_path / TARGET
    target.parent.mkdir(parents=True)
    target.write_bytes(original)
    result = apply_patch(tmp_path, PATCH)
    assert result.returncode == 0, result.stdout + result.stderr
    assert b"fuzz" not in result.stdout
    if version == "153":
        assert b"offset" not in result.stdout
    else:
        assert b"offset -5 lines" in result.stdout
    expected = original.replace(OLD_GETTER, NEW_GETTER, 1)
    assert target.read_bytes() == expected
    assert apply_patch(tmp_path, PATCH, "--dry-run").returncode != 0
    assert target.read_bytes() == expected
    result = apply_patch(tmp_path, PATCH, "--reverse")
    assert result.returncode == 0, result.stdout + result.stderr
    assert target.read_bytes() == original


@pytest.mark.parametrize("version", EXCERPTS)
@pytest.mark.parametrize("anchor", [b"SampleRate()", b"CurrentTime()", b"listener_.Get()"])
def test_audio_annotation_rejects_changed_getter(tmp_path, version, anchor):
    target = tmp_path / TARGET
    target.parent.mkdir(parents=True)
    original = source_fixture(version).replace(anchor, b"ChangedGetter()", 1)
    target.write_bytes(original)
    result = apply_patch(tmp_path, PATCH, "--dry-run")
    assert result.returncode != 0
    assert b"FAILED" in result.stdout
    assert target.read_bytes() == original


def test_audio_annotation_preserves_native_getters():
    lines = PATCH.read_bytes().splitlines(keepends=True)
    assert b"".join(line[1:] for line in lines if line.startswith(b"+") and not line.startswith(b"+++")) == NEW_GETTER
    assert b"".join(line[1:] for line in lines if line.startswith(b"-") and not line.startswith(b"---")) == OLD_GETTER
    assert NEW_GETTER.replace(ANNOTATION, b"").split() == OLD_GETTER.split()
    assert b"destination()" not in PATCH.read_bytes()
    assert b"destinationNode()" not in PATCH.read_bytes()
