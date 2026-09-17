"""Keep widget initialization at the native update tail on Chromium 152/153."""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

REPO = Path(__file__).resolve().parents[2]
PATCH = REPO / "patches/0126-display-widget-initialization.patch"
TARGET = "third_party/blink/renderer/core/frame/web_frame_widget_impl.cc"
PATCH_BIN = os.environ.get("PATCH_BIN") or shutil.which("gpatch") or shutil.which("patch")
pytestmark = pytest.mark.skipif(PATCH_BIN is None, reason="GNU patch is required")

# Independent complete-source excerpts, including the changed unbounded path.
EXCERPTS = {
    "152": (2054, b'''  // TODO(crbug.com/939118): This code path where scroll_focused_node_into_view
  // is set is used only for WebView, crbug 939118 tracks fixing webviews to
  // not use scroll_focused_node_into_view.
  if (visual_properties.scroll_focused_node_into_view)
    ScrollFocusedEditableElementIntoView();

  if (properties_changed && unbounded_surface_state_ &&
      unbounded_surface_state_->host_.is_bound()) {
    CHECK(RuntimeEnabledFeatures::UnboundedElementEnabled());
    if (auto* active_element = GetActiveUnboundedElement()) {
      active_element->GetDocument().UpdateStyleAndLayoutForNode(
          active_element, DocumentUpdateReason::kJavaScript);
      gfx::Rect bounds;
      if (auto* layout_object = active_element->GetLayoutObject()) {
        bounds = layout_object->AbsoluteBoundingBoxRect();
      }
      if (!bounds.IsEmpty()) {
        unbounded_surface_state_->host_->UpdateBounds(bounds);
      }
    }
  }
}

void WebFrameWidgetImpl::ApplyVisualPropertiesSizing(
    const VisualProperties& visual_properties) {
  gfx::Rect new_compositor_viewport_pixel_rect =
      visual_properties.compositor_viewport_pixel_rect;
'''),
    "153": (2072, b'''  // TODO(crbug.com/939118): This code path where scroll_focused_node_into_view
  // is set is used only for WebView, crbug 939118 tracks fixing webviews to
  // not use scroll_focused_node_into_view.
  if (visual_properties.scroll_focused_node_into_view)
    ScrollFocusedEditableElementIntoView();

  if (properties_changed && unbounded_surface_state_ &&
      unbounded_surface_state_->host_.is_bound()) {
    CHECK(RuntimeEnabledFeatures::UnboundedElementEnabled());
    if (auto* active_element = GetActiveUnboundedElement()) {
      active_element->GetDocument().UpdateStyleAndLayoutForNode(
          active_element, DocumentUpdateReason::kJavaScript);
      gfx::Rect bounds;
      if (auto* layout_object = active_element->GetLayoutObject()) {
        bounds = layout_object->AbsoluteBoundingBoxRectForUnboundedElement();
        if (auto* frame = active_element->GetDocument().GetFrame()) {
          if (auto* view = frame->View()) {
            bounds = view->FrameToViewport(bounds);
            if (auto* widget = frame->GetWidgetForLocalRoot()) {
              bounds = gfx::ToRoundedRect(
                  widget->BlinkSpaceToDIPs(gfx::RectF(bounds)));
            }
          }
        }
      }
      // Unbounded elements must have a minimum size of 1x1 to prevent
      // empty-bounds compositor and platform window issues.
      bounds.set_width(std::max(1, bounds.width()));
      bounds.set_height(std::max(1, bounds.height()));
      active_element->SetLastSentUnboundedBounds(bounds);
      unbounded_surface_state_->host_->UpdateBounds(bounds);
    }
  }
}

void WebFrameWidgetImpl::ApplyVisualPropertiesSizing(
    const VisualProperties& visual_properties) {
  gfx::Rect new_compositor_viewport_pixel_rect =
      visual_properties.compositor_viewport_pixel_rect;
'''),
}
INITIALIZATION = b'''  // Configure the existing emulation backend once, after native widget sizing.
  // Subsequent resize/zoom events flow through its normal visual-properties
  // path. Fixed view_size intentionally stays fixed until a CDP update.
  // Remember initialization even when CDP owns the emulator, so clearing CDP
  // emulation cannot cause the launch defaults to be reapplied on the next resize.
  if (ForTopMostMainFrame() && !uxr_display_initialized_) {
    uxr_display_initialized_ = true;
    const auto display = base::UxrConfig::GetInstance().Display();
    if (display.enabled() && !AutoResizeMode() && !DeviceEmulator()) {
      DeviceEmulationParams params;
      params.screen_size = gfx::Size(display.width, display.height);
      params.view_size = gfx::Size(display.viewport_width, display.viewport_height);
      params.device_scale_factor = static_cast<float>(display.device_scale_factor);
      if (display.has_position)
        params.view_position = gfx::Point(display.window_x, display.window_y);
      using Orientation = display::mojom::ScreenOrientation;
      if (display.orientation == "landscape-primary")
        params.screen_orientation_type = Orientation::kLandscapePrimary;
      else if (display.orientation == "landscape-secondary")
        params.screen_orientation_type = Orientation::kLandscapeSecondary;
      else if (display.orientation == "portrait-primary")
        params.screen_orientation_type = Orientation::kPortraitPrimary;
      else if (display.orientation == "portrait-secondary")
        params.screen_orientation_type = Orientation::kPortraitSecondary;
      params.screen_orientation_angle = display.orientation_angle;
      EnableDeviceEmulation(params, mojom::blink::DeviceEmulationCacheBehavior::kClearCache);
    }
  }
'''
BOUNDARY = b'}\n\nvoid WebFrameWidgetImpl::ApplyVisualPropertiesSizing(\n'


def initialization_hunk():
    data = PATCH.read_bytes()
    headers = list(re.finditer(rb"^@@[^\n]*\n", data, flags=re.M))
    assert len(headers) == 5
    return data[:headers[0].start()] + data[headers[1].start():headers[2].start()]


def source_fixture(version, shift=0):
    first, excerpt = EXCERPTS[version]
    return b"// unrelated source line\n" * (first - 1 + shift) + excerpt


def apply_patch(src, patch, *options):
    return subprocess.run(
        [PATCH_BIN, "-p1", "--fuzz=0", "--batch", "--forward", "--binary",
         "--get=0", "--no-backup-if-mismatch", "--reject-file=-", *options,
         "--input", str(patch)],
        cwd=src, env=dict(os.environ, LC_ALL="C", PATCH_GET="0"),
        capture_output=True, timeout=30, check=False,
    )


@pytest.mark.parametrize("version", EXCERPTS)
@pytest.mark.parametrize("shift", [0, -73, 193])
def test_widget_initialization_strict_roundtrip(tmp_path, version, shift):
    original = source_fixture(version, shift)
    target = tmp_path / TARGET
    target.parent.mkdir(parents=True)
    target.write_bytes(original)
    patch = tmp_path / "initialization.patch"
    patch.write_bytes(initialization_hunk())
    assert original.count(BOUNDARY) == 1
    expected = original.replace(BOUNDARY, INITIALIZATION + b"\n" + BOUNDARY, 1)
    for options, rc, contents in [
        (("--dry-run",), 0, original),
        ((), 0, expected),
        (("--dry-run",), 1, expected),
        ((), 1, expected),
        (("--reverse", "--dry-run"), 0, expected),
        (("--reverse",), 0, original),
    ]:
        result = apply_patch(tmp_path, patch, *options)
        output = result.stdout + result.stderr
        assert result.returncode == rc, output
        assert b"fuzz" not in output.lower()
        assert target.read_bytes() == contents
    assert expected.count(INITIALIZATION) == 1
    assert expected.replace(INITIALIZATION + b"\n", b"", 1) == original
    assert expected.index(b"host_->UpdateBounds(bounds);") < expected.index(INITIALIZATION)
    assert expected.index(INITIALIZATION) < expected.index(BOUNDARY)


@pytest.mark.parametrize("version", EXCERPTS)
@pytest.mark.parametrize("anchor", range(5), ids=["inner-close", "outer-close", "function-close", "blank", "sizing-signature"])
def test_widget_initialization_rejects_changed_boundary(tmp_path, version, anchor):
    original = source_fixture(version)
    boundary = b"    }\n  }\n" + BOUNDARY
    assert original.count(boundary) == 1
    lines = boundary.splitlines(keepends=True)
    lines[anchor] = b"// incompatible upstream boundary\n"
    original = original.replace(boundary, b"".join(lines), 1)
    target = tmp_path / TARGET
    target.parent.mkdir(parents=True)
    target.write_bytes(original)
    patch = tmp_path / "initialization.patch"
    patch.write_bytes(initialization_hunk())
    for options in (("--dry-run",), ()):
        result = apply_patch(tmp_path, patch, *options)
        assert result.returncode == 1, result.stdout + result.stderr
        assert b"FAILED" in result.stdout
        assert target.read_bytes() == original


def test_widget_initialization_balanced_context_and_unchanged_logic():
    data = initialization_hunk()
    body = re.split(rb"^@@[^\n]*\n", data, flags=re.M)[1].splitlines(keepends=True)
    assert body[:2] == [b"     }\n", b"   }\n"]
    assert body[-2:] == [b" \n", b" void WebFrameWidgetImpl::ApplyVisualPropertiesSizing(\n"]
    assert b"".join(line[1:] for line in body if line.startswith(b"-")) == b"}\n"
    assert b"".join(line[1:] for line in body if line.startswith(b"+")) == INITIALIZATION + b"\n}\n"
    assert INITIALIZATION.index(b"uxr_display_initialized_ = true;") < INITIALIZATION.index(b"!DeviceEmulator()")
