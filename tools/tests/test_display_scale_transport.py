"""Display transport contracts; real-source tests require receipt-backed inputs."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess

import pytest

REPO = Path(__file__).resolve().parents[2]
FRAME = 'third_party/blink/renderer/core/frame/'
COMMON = 'third_party/blink/public/common/'
COMMIT = '507c6ee3e2f3b2ca0e660547e5b9ea4820c67f4c'


@pytest.fixture(scope='module')
def display_source(tmp_path_factory):
    supplied = os.environ.get('CHROMIX_DISPLAY_153_SOURCE_MANIFEST')
    if not supplied:
        pytest.skip('receipt-backed Chromium153 full preimages not supplied')
    manifest = json.loads(Path(supplied).read_text())
    assert manifest['commit'] == COMMIT
    root = tmp_path_factory.mktemp('display153')
    for record in manifest['sources']:
        data = Path(record['raw']).read_bytes()
        assert record['commit'] == COMMIT
        assert hashlib.sha256(data).hexdigest() == record['sha256']
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        assert blob == record['gitblob'] == record['metadata']['id']
        assert len(data) == record['bytes']
        target = root / record['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    patch_bin = os.environ.get('PATCH_BIN') or shutil.which('gpatch') or shutil.which('patch')
    assert patch_bin, 'GNU patch is required for source verification'
    for number in [125, 126, 127, 128, *range(166, 188)]:
        patch = next((REPO / 'patches').glob(f'{number:04}-*.patch'))
        result = subprocess.run([patch_bin, '-p1', '--fuzz=0', '--batch', '--forward',
                                 '--get=0', '--no-backup-if-mismatch', '-i', str(patch)],
                                cwd=root, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        assert 'fuzz' not in (result.stdout + result.stderr).lower()
    return root


def source(root, relative):
    return (root / relative).read_text()


def test_native_and_emulated_screen_transport_are_separate(display_source):
    root = display_source
    for kind, stem in [('frame', 'frame_visual_properties'), ('widget', 'visual_properties')]:
        header = source(root, COMMON + f'{kind}/{stem}.h')
        assert 'display::ScreenInfos screen_infos;' in header
        assert 'std::optional<display::ScreenInfos> emulated_screen_infos;' in header
        traits = source(root, COMMON + f'{kind}/{stem}_mojom_traits.h')
        assert 'return r.emulated_screen_infos;' in traits
        reader = source(root, f'third_party/blink/common/{kind}/{stem}_mojom_traits.cc')
        assert '!data.ReadEmulatedScreenInfos(&out->emulated_screen_infos)' in reader
        mojom = source(root, f'third_party/blink/public/mojom/{kind}/{stem}.mojom')
        assert 'display.mojom.ScreenInfos? emulated_screen_infos;' in mojom
    remote = source(root, FRAME + 'web_remote_frame_impl.cc')
    assert 'visual_properties.screen_infos = ancestor_widget->GetOriginalScreenInfos();' in remote
    assert 'ancestor_widget->GetEmulatedScreenInfos();' in remote
    connector = source(root, 'content/browser/renderer_host/cross_process_frame_connector.cc')
    assert 'screen_infos_ = visual_properties.screen_infos;' in connector
    assert 'visual_properties.emulated_screen_infos);' in connector


def test_screen_only_changes_and_clear_survive_caches(display_source):
    root = display_source
    remote = source(root, FRAME + 'remote_frame.cc')
    assert 'pending_visual_properties_.emulated_screen_infos = emulated_screen_infos;' in remote
    assert 'sent_visual_properties_->emulated_screen_infos !=' in remote
    browser = source(root, 'content/browser/renderer_host/render_widget_host_impl.cc')
    assert 'old_visual_properties->emulated_screen_infos !=' in browser
    assert 'properties_from_parent_local_root_.emulated_screen_infos' in browser
    equality = source(root, 'third_party/blink/common/widget/visual_properties.cc')
    assert 'emulated_screen_infos == other.emulated_screen_infos' in equality
    widget = source(root, FRAME + 'web_frame_widget_impl.cc')
    clear = widget.split('void WebFrameWidgetImpl::DisableDeviceEmulation()', 1)[1].split('\n}', 1)[0]
    assert clear.index('device_emulator_ = nullptr;') < clear.index('DisableAndApply()')
    assert 'inherited_emulated_screen_infos_ = visual_properties.emulated_screen_infos;' in widget
    assert 'MediaQueryAffectingValueChanged' in widget
    assert 'last_orientation_screen_info_->orientation_type !=' in widget


def test_layout_compositor_and_input_keep_native_scale(display_source):
    root = display_source
    widget = source(root, FRAME + 'web_frame_widget_impl.cc')
    assert '!ForSubframe() || !View()->MainFrameImpl()' in widget
    assert '? GetOriginalScreenInfo().device_scale_factor' in widget
    assert 'new_compositor_viewport_pixel_rect, visual_properties.screen_infos);' in widget
    original = widget.split('const display::ScreenInfos& WebFrameWidgetImpl::GetOriginalScreenInfos()', 1)[1].split('\n}', 1)[0]
    assert 'inherited_emulated_screen_infos_' not in original
    assert 'widget_base_->screen_infos()' in original
    native = source(root, 'third_party/blink/renderer/platform/widget/widget_base.cc')
    assert 'return client_->GetOriginalScreenInfos().current().device_scale_factor;' in native
    tests = source(root, FRAME + 'web_frame_widget_test.cc')
    for name in ['EmulatedScreenPreservesNativeLayoutAndInputScale',
                 'EmulatedScreenMojoRoundTripAndClear',
                 'EmulatedScreenInitialNestedPropagationAndClear']:
        assert name in tests
    assert 'check(300, 150, 1.25f, 1.f)' in tests
    assert 'properties.emulated_screen_infos.reset()' in tests



def test_f1_effective_orientation_is_filtered_before_dispatch(display_source):
    widget = source(display_source, FRAME + 'web_frame_widget_impl.cc')
    callback = widget.split('void WebFrameWidgetImpl::OrientationChanged()', 1)[1].split('\n}', 1)[0]
    assert 'last_orientation_screen_info_' in callback
    assert callback.index('last_orientation_screen_info_ = screen_info;') < callback.index('SendOrientationChangeEvent')
    native = source(display_source, 'third_party/blink/renderer/platform/widget/widget_base.cc')
    assert 'if (client_->FrameWidget())' in native
    assert 'auto weak_this = weak_ptr_factory_.GetWeakPtr();' in native
    did_update = widget.split('void WebFrameWidgetImpl::DidUpdateSurfaceAndScreen(', 1)[1].split('\n}', 1)[0]
    assert 'OrientationChanged();' not in did_update


def test_f2_refresh_never_feeds_inherited_screen_to_native(display_source):
    view = source(display_source, 'third_party/blink/renderer/core/exported/web_view_impl.cc')
    setter = view.split('void WebViewImpl::SetScreenOrientationOverrideForTesting(', 1)[1].split('\n}', 1)[0]
    assert 'widget->RefreshScreenInfo();' in setter
    assert 'UpdateScreenInfo(widget->GetScreenInfos())' not in setter
    widget = source(display_source, FRAME + 'web_frame_widget_impl.cc')
    refresh = widget.split('void WebFrameWidgetImpl::RefreshScreenInfo()', 1)[1].split('\n}', 1)[0]
    assert 'widget_base_->screen_infos()' in refresh
    assert 'GetOriginalScreenInfos()' not in refresh


def test_f3_nested_main_caches_inheritance_before_own_emulator(display_source):
    widget = source(display_source, FRAME + 'web_frame_widget_impl.cc')
    sizing = widget.split('bool WebFrameWidgetImpl::ApplyVisualPropertiesSizing(', 1)[1].split('\n}', 1)[0]
    inherited = sizing.index('inherited_emulated_screen_infos_ = visual_properties.emulated_screen_infos;')
    assert '!ForTopMostMainFrame()' in sizing[:inherited]
    assert inherited < sizing.index('DeviceEmulator()->UpdateVisualProperties')
    getter = widget.split('const display::ScreenInfos& WebFrameWidgetImpl::GetScreenInfos()', 1)[1].split('\n}', 1)[0]
    assert '!device_emulator_ && inherited_emulated_screen_infos_' in getter
    clear = widget.split('void WebFrameWidgetImpl::DisableDeviceEmulation()', 1)[1].split('\n}', 1)[0]
    assert clear.index('device_emulator_ = nullptr;') < clear.index('DisableAndApply()')



def test_real_frame_copy_defaults_and_blink_mojo_dependencies(display_source):
    copy = source(display_source, 'third_party/blink/common/frame/frame_visual_properties.cc')
    assert 'const FrameVisualProperties& other) = default;' in copy
    assert copy.count('const FrameVisualProperties& other) = default;') == 2
    tests = source(display_source, FRAME + 'web_frame_widget_test.cc')
    for token in ('FrameVisualProperties empty_copy(empty_frame)', 'empty_copy = frame;',
                  'empty_copy = empty_frame;', 'widget_copy = empty_widget;',
                  'SerializeAndDeserialize<mojom::blink::VisualProperties>',
                  'frame_visual_properties.mojom-blink.h'):
        assert token in tests
    core_gn = source(display_source, 'third_party/blink/renderer/core/BUILD.gn')
    assert '//mojo/public/cpp/test_support:test_utils' in core_gn
    assert '//third_party/blink/public/mojom:mojom_core_blink' in core_gn


def assert_local_root_address_identity(controller):
    # Chromium153 LocalFrameRoot() returns LocalFrame&, not a pointer.
    visibility = controller.split('void ScreenOrientationController::PageVisibilityChanged()', 1)[1].split('\n}', 1)[0]
    dispatch = controller.split('void ScreenOrientationController::NotifyOrientationChanged()', 1)[1].split('\n}', 1)[0]
    visibility = ' '.join(visibility.split())
    dispatch = ' '.join(dispatch.split())
    assert 'if (&frame == &frame.LocalFrameRoot())' in visibility
    assert 'if (&frame == frame.LocalFrameRoot())' not in visibility
    assert ('&local_frame->LocalFrameRoot() == '
            '&DomWindow()->GetFrame()->LocalFrameRoot()') in dispatch
    assert ('local_frame && local_frame->LocalFrameRoot() == '
            'DomWindow()->GetFrame()->LocalFrameRoot()') not in dispatch


def test_orientation_controller_stays_inside_local_root(display_source):
    controller = source(display_source, 'third_party/blink/renderer/modules/screen_orientation/screen_orientation_controller.cc')
    assert_local_root_address_identity(controller)
    widget = source(display_source, FRAME + 'web_frame_widget_impl.cc')
    assert 'Vector<Persistent<WebLocalFrameImpl>> local_frames;' in widget
    assert 'screen_update_sequence_ == sequence' in widget
    assert 'visual_properties_update_sequence_ != update_sequence' in widget


@pytest.mark.parametrize('correct,incorrect', [
    ('&frame == &frame.LocalFrameRoot()', '&frame == frame.LocalFrameRoot()'),
    ('&local_frame->LocalFrameRoot()', 'local_frame->LocalFrameRoot()'),
    ('&DomWindow()->GetFrame()->LocalFrameRoot()', 'DomWindow()->GetFrame()->LocalFrameRoot()'),
    ('&local_frame->LocalFrameRoot() ==\n                           &DomWindow()->GetFrame()->LocalFrameRoot()',
     'local_frame->LocalFrameRoot() ==\n                           DomWindow()->GetFrame()->LocalFrameRoot()'),
])
def test_local_root_identity_rejects_missing_addresses(display_source, correct, incorrect):
    controller = source(display_source, 'third_party/blink/renderer/modules/screen_orientation/screen_orientation_controller.cc')
    assert_local_root_address_identity(controller)
    assert controller.count(correct) == 1
    with pytest.raises(AssertionError):
        assert_local_root_address_identity(controller.replace(correct, incorrect, 1))


def test_orientation_reentry_has_no_stale_screen_continuation(display_source):
    widget = source(display_source, FRAME + 'web_frame_widget_impl.cc')
    did_update = widget.split('void WebFrameWidgetImpl::DidUpdateSurfaceAndScreen(', 1)[1].split('\n}', 1)[0]
    assert 'const uint64_t update_sequence = ++screen_update_sequence_;' in did_update
    native = source(display_source, 'third_party/blink/renderer/platform/widget/widget_base.cc')
    update = native.split('void WidgetBase::UpdateSurfaceAndScreenInfo(', 1)[1].split('\n}', 1)[0]
    assert update.index('DidUpdateSurfaceAndScreen') < update.rindex('client_->OrientationChanged();')
    assert 'if (!client_->FrameWidget() && orientation_changed)' in update
    assert 'if (!weak_this || will_be_destroyed_)' in update
    assert update.rstrip().endswith('client_->OrientationChanged();\n  }')
    assert 'if (!ApplyVisualPropertiesSizing(visual_properties))' in widget
    assert 'bool WebFrameWidgetImpl::IsScreenUpdateCurrent(' in widget
    tests = source(display_source, FRAME + 'web_frame_widget_test.cc')
    assert 'EmulatedScreenOrientationReentryKeepsLatestSize' in tests
    assert 'EmulatedScreenOrientationDetachDuringNotification' in tests
    assert 'EmulatedScreenOwnOrientationReentry' in tests
    assert 'EmulatedScreenOwnVisualPropertiesReentry' in tests
    emulator = source(display_source, FRAME + 'screen_metrics_emulator.cc')
    assert 'DeviceEmulator() != this' in emulator
    assert 'IsScreenUpdateCurrent(update_sequence + 1)' in emulator
    assert '++frame_widget_->visual_properties_update_sequence_;' in emulator
    controller = source(display_source, 'third_party/blink/renderer/modules/screen_orientation/screen_orientation_controller.cc')
    assert 'previous_type == orientation_->type().AsEnum()' in controller
    assert 'OrientationScreenInfo(GetScreenInfo())' in widget


def test_display_additions_never_transport_scale_in_unrelated_zoom_fields():
    added = '\n'.join(line[1:] for patch in sorted((REPO / 'patches').glob('*.patch'))
                      if 166 <= int(patch.name[:4]) <= 182
                      for line in patch.read_text().splitlines()
                      if line.startswith('+') and not line.startswith('+++'))
    for field in ['css_zoom_factor', 'text_scale_multiplier', 'zoom_level']:
        assert not any(field + ' =' in line for line in added.splitlines())
    assert 'SetCompositorDeviceScaleFactorOverride' in added
    assert 'emulated_screen_infos' in added
