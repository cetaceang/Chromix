"""Final capability/input/clock contracts; dependency shims, not a browser build."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

from test_canvas_native_paths import apply, patch_path
from test_fingerprint_canvas import CXX, sanitizer_env, sanitizer_flags
from test_fingerprint_config import config_binary
from test_fingerprint_features import block

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = json.loads((Path(__file__).with_name('fixtures') / 'backend_completion_sources.json').read_text())


@pytest.fixture(scope='module')
def final_sources(tmp_path_factory):
    result = {}
    for number, item in EVIDENCE['patches'].items():
        directory = tmp_path_factory.mktemp('backend-section-' + number)
        lines = []
        for section in item['sections']:
            start = section['line'] - 1
            assert start >= len(lines)
            lines.extend('// unrelated pinned source line\n' for _ in range(start - len(lines)))
            lines.extend(section['text'].splitlines(True))
        original = ''.join(lines).encode() + b'// not EOF\n'
        path = directory / item['target']
        path.parent.mkdir(parents=True)
        path.write_bytes(original)
        patch = patch_path(number)
        assert hashlib.sha256(patch.read_bytes()).hexdigest() == item['patch_sha256']
        apply(directory, patch)
        result[number] = path.read_text(encoding='utf-8')
        apply(directory, patch, reverse=True)
        assert path.read_bytes() == original
    return result


@pytest.mark.parametrize('number', EVIDENCE['patches'])
def test_zero_fuzz_zero_offset_roundtrip(final_sources, number):
    assert final_sources[number]


def test_independent_source_and_complete_predecessor_chains(tmp_path):
    supplied = os.environ.get('CHROMIX_BACKEND_UPSTREAM_ROOT')
    if not supplied:
        pytest.skip('independently fetched pinned Chromium inputs required')
    assert EVIDENCE['chromium_version'] == (ROOT / 'CHROMIUM_VERSION').read_text().strip()
    targets = {item['target'] for item in EVIDENCE['patches'].values()}
    originals = {}
    for target, item in EVIDENCE['sources'].items():
        data = (Path(supplied) / target).read_bytes()
        assert hashlib.sha256(data).hexdigest() == item['upstream_sha256']
        dest = tmp_path / target
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        originals[target] = data
    core_patches = []
    assert EVIDENCE['core_commit'] == 'e71b91c6e336d0f25cfc6b9ef09298a9d2506e24'
    for index, item in enumerate(EVIDENCE['core_inputs']):
        patch = tmp_path / ('core-' + str(index) + '.patch')
        patch.write_bytes(item['target_fragment'].encode())
        apply(tmp_path, patch)
        core_patches.append(patch)
    applied = []
    names = [name for name in (ROOT / 'patches/series').read_text().splitlines()
             if name and not name.startswith('#')]
    # Pending clock patches are validated before the parent registers them.
    for number in ('0193', '0194'):
        name = str(patch_path(number).relative_to(ROOT))
        if name not in names:
            names.append(name)
    for name in names:
        patch = ROOT / name
        target = re.search(r'^\+\+\+ b/(.*)$', patch.read_text(), re.M)[1]
        if target not in targets:
            continue
        number = patch.name[:4]
        receipt = EVIDENCE['patches'].get(number)
        dest = tmp_path / target
        if receipt:
            assert hashlib.sha256(dest.read_bytes()).hexdigest() == receipt['preimage_sha256']
        apply(tmp_path, patch, allow_offsets=int(number) < 166)
        if receipt:
            assert hashlib.sha256(dest.read_bytes()).hexdigest() == receipt['output_sha256']
        applied.append(patch)
    for item in EVIDENCE['methods'].values():
        assert item['text'] in (tmp_path / item['target']).read_text(encoding='utf-8')
    for patch in reversed(applied):
        apply(tmp_path, patch, reverse=True, allow_offsets=int(patch.name[:4]) < 166)
    for patch in reversed(core_patches):
        apply(tmp_path, patch, reverse=True)
    for target, original in originals.items():
        assert (tmp_path / target).read_bytes() == original
        assert (Path(supplied) / target).read_bytes() == original


SUPPORT = r'''
#include "base/uxr_config.h"
#include <algorithm>
#include <bit>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <thread>
#include <vector>
namespace base {
template<class T, class U> T bit_cast(U value) { return std::bit_cast<T>(value); }
struct Time { static int64_t now; static Time Now() {return {};} };
int64_t Time::now = 0;
struct TimeDelta { int64_t value; int64_t InMicroseconds() const { return value; } };
TimeDelta Microseconds(int64_t value) { return {value}; }
}
namespace blink {
namespace mojom {
enum class PointerType { kPointerNone=1, kPointerCoarseType=2, kPointerFineType=4 };
enum class HoverType { kHoverNone=1, kHoverHoverType=2 };
enum class PreferredColorScheme { kLight, kDark };
enum class PreferredContrast { kNoPreference, kMore, kLess, kCustom };
}
namespace web_pref {
struct WebPreferences {
  bool prefers_reduced_motion=false, prefers_reduced_transparency=false, inverted_colors=false;
  bool in_forced_colors=false, is_forced_colors_disabled=true;
  bool touch_event_feature_detection_enabled=false;
  int pointer_events_max_touch_points=0, available_pointer_types=1, available_hover_types=1;
  mojom::PointerType primary_pointer_type=mojom::PointerType::kPointerNone;
  mojom::HoverType primary_hover_type=mojom::HoverType::kHoverNone;
  mojom::PreferredColorScheme preferred_color_scheme=mojom::PreferredColorScheme::kLight;
  mojom::PreferredColorScheme preferred_root_scrollbar_color_scheme=mojom::PreferredColorScheme::kLight;
  mojom::PreferredContrast preferred_contrast=mojom::PreferredContrast::kNoPreference;
  bool operator==(const WebPreferences&) const = default;
};
}
constexpr int64_t kTenLowerDigitsMod=10000000000;
struct TimeClamper {
  static constexpr int kCoarseResolutionMicroseconds=100, kFineResolutionMicroseconds=5;
  uint64_t secret_=42;
  base::TimeDelta ClampTimeResolution(base::TimeDelta, bool) const;
  double ThresholdFor(int64_t, int) const;
  static double ToDouble(uint64_t);
  static uint64_t MurmurHash3(uint64_t);
};
}
struct V8Platform {
  struct NativeClamper {
    int64_t ClampToMillis(base::Time) const { return base::Time::now; }
    double ClampToMillisHighResolution(base::Time) const { return base::Time::now+0.125; }
  } time_clamper_;
  double CurrentClockTimeMillis();
  int64_t CurrentClockTimeMilliseconds();
  double CurrentClockTimeMillisecondsHighResolution();
};
'''

MAIN = r'''
int main(int argc, char** argv) {
  assert(argc>=2);
  auto& config=base::UxrConfig::GetInstance();
  base::flat_map<std::string, std::string> cfg;
  const std::string mode=argv[1];
  int start=mode=="prefs"?3:2;
  if(mode=="clock") start=3;
  for(int i=start;i<argc;++i) {
    std::string text=argv[i];auto equal=text.find('=');
    cfg[text.substr(0,equal)]=text.substr(equal+1);
  }
  if(mode=="clock") cfg={{"uxr-timer-resolution",argv[2]}};
  bool accepted=config.SetAll(cfg);
  if(mode=="validate") {
    std::cout<<accepted<<' '<<config.IsInitialized();
    if(!accepted) {
      assert(config.Snapshot().empty());assert(config.TimerResolutionMicroseconds()==0);
      assert(!config.ValidationError().empty());assert(config.SetAll({}));
    }
    return 0;
  }
  assert(accepted);
  if(mode=="gpu") {
    auto p=config.GpuBackendPolicy();
    std::cout<<p.native<<' '<<p.canvas_pixel_noise<<' '<<p.canvas_text_noise<<' '
             <<p.canvas_bridge<<' '<<p.capability_overrides;
    return 0;
  }
  if(mode=="freeze") {
    std::vector<std::thread> threads;
    for(int t=0;t<8;++t) threads.emplace_back([&] {
      for(int n=0;n<100;++n) {
        assert(config.SetAll(cfg));
        assert(!config.SetAll({{"uxr-timer-resolution","17"}}));
        assert(config.TimerResolutionMicroseconds()==7000);
      }
    });
    for(auto& t:threads) t.join();
    return 0;
  }
  if(mode=="clock") {
    blink::TimeClamper clamper;V8Platform v8;
    for(int i=3;i<argc;++i) {
      int64_t input=std::stoll(argv[i]);base::Time::now=input;
      const auto micros=config.QuantizeClockMicroseconds(input);
      const auto millis=config.QuantizeClockMilliseconds(input);
      if(std::string(argv[2])!="0") {
        assert(clamper.ClampTimeResolution(base::Microseconds(input),false).value==micros);
        assert(clamper.ClampTimeResolution(base::Microseconds(input),true).value==micros);
        assert(v8.CurrentClockTimeMillisecondsHighResolution()==static_cast<double>(millis));
      } else {
        assert(v8.CurrentClockTimeMillisecondsHighResolution()==input+0.125);
      }
      assert(v8.CurrentClockTimeMilliseconds()==millis);
      assert(v8.CurrentClockTimeMillis()==static_cast<double>(millis));
      std::cout<<micros<<' '<<millis<<'\n';
    }
    return 0;
  }
  assert(mode=="prefs");
  blink::web_pref::WebPreferences prefs;
  const std::string native=argv[2];
  if(native=="mouse"||native=="mixed") {
    prefs.primary_pointer_type=blink::mojom::PointerType::kPointerFineType;
    prefs.available_pointer_types=4;
    prefs.primary_hover_type=blink::mojom::HoverType::kHoverHoverType;
    prefs.available_hover_types=2;
  }
  if(native=="touch"||native=="mixed") {
    prefs.pointer_events_max_touch_points=5;
    prefs.touch_event_feature_detection_enabled=true;
    prefs.available_pointer_types=native=="mixed"?6:2;
    if(native=="touch") prefs.primary_pointer_type=blink::mojom::PointerType::kPointerCoarseType;
  }
  const auto before=prefs;
  blink::ApplyUxrWebPreferences(prefs);
  if(cfg.empty()) assert(prefs==before);
  const auto once=prefs;blink::ApplyUxrWebPreferences(prefs);assert(prefs==once);
  std::cout<<static_cast<int>(prefs.primary_pointer_type)<<' '<<prefs.available_pointer_types<<' '
    <<static_cast<int>(prefs.primary_hover_type)<<' '<<prefs.available_hover_types<<' '
    <<prefs.pointer_events_max_touch_points<<' '<<prefs.touch_event_feature_detection_enabled<<' '
    <<prefs.prefers_reduced_motion<<' '<<prefs.prefers_reduced_transparency<<' '<<prefs.inverted_colors<<' '
    <<static_cast<int>(prefs.preferred_color_scheme)<<' '
    <<static_cast<int>(prefs.preferred_root_scrollbar_color_scheme)<<' '
    <<static_cast<int>(prefs.preferred_contrast)<<' '<<prefs.in_forced_colors<<' '
    <<prefs.is_forced_colors_disabled;
}
'''


@pytest.fixture(scope='module')
def backend_binary(tmp_path_factory, config_binary, final_sources):
    directory = tmp_path_factory.mktemp('backend-cpp') / 'src'
    shutil.copytree(config_binary.parent, directory)
    for target in ('base/uxr_config.h', 'base/uxr_config.cc'):
        path = directory / target
        path.write_bytes(path.read_text().encode())
    for name in (ROOT / 'patches/series').read_text().splitlines():
        if not name or name.startswith('#'):
            continue
        patch = ROOT / name
        target = re.search(r'^\+\+\+ b/(.*)$', patch.read_text(), re.M)[1]
        if target in ('base/uxr_config.h', 'base/uxr_config.cc') and int(patch.name[:4]) > 3:
            apply(directory, patch)
    code = SUPPORT + '\nnamespace blink {\n'
    code += block(final_sources['0170'], 'void ApplyUxrWebPreferences(') + '\n'
    code += '\n'.join(item['text'] for item in EVIDENCE['methods'].values()
                      if item['target'].endswith('/time_clamper.cc')) + '\n}\n'
    code += '\n'.join(block(final_sources['0174'], signature) for signature in (
        'double V8Platform::CurrentClockTimeMillis()',
        'int64_t V8Platform::CurrentClockTimeMilliseconds()',
        'double V8Platform::CurrentClockTimeMillisecondsHighResolution()'))
    source = directory / 'backend.cc'
    source.write_text(code + '\n' + MAIN, encoding='utf-8')
    binary = directory / 'backend'
    result = subprocess.run([CXX, '-std=c++20', '-Wall', '-Wextra', '-Werror', *sanitizer_flags(),
        '-I', str(directory), str(directory / 'base/uxr_config.cc'), str(source), '-o', str(binary)],
        capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


def run(binary, *args):
    result = subprocess.run([str(binary), *args], capture_output=True, text=True,
                            env=sanitizer_env(), timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


@pytest.mark.parametrize('args', [
    ['uxr-timer-resolution=-1'], ['uxr-timer-resolution=1001'], ['uxr-timer-resolution=+1'],
    ['uxr-timer-resolution=1.5'], ['uxr-timer-resolution='], ['uxr-max-touch-points=17'],
    ['uxr-max-touch-points=-1'], ['uxr-reduced-motion=yes'], ['uxr-hdr=high'],
    ['uxr-color-scheme=auto'], ['uxr-preferred-contrast=high'], ['uxr-forced-colors=off'],
    ['uxr-pointer=none', 'uxr-max-touch-points=1'],
    ['uxr-pointer=coarse', 'uxr-max-touch-points=0'],
    ['uxr-pointer=none', 'uxr-hover=hover'], ['uxr-keyboard-layout=us'],
    ['uxr-keyboard-layout=de-DE', 'uxr-synthetic-device-tests=true'],
    ['uxr-audio-render=isolated'], ['uxr-audio-render=other'],
    ['uxr-audio-render=isolated', 'uxr-audio-seed=0'], ['uxr-audio-seed=+1'],
    ['uxr-audio-seed=18446744073709551616'], ['uxr-font-policy=restricted'],
    ['uxr-font-policy=restricted','uxr-font-whitelist=Allowed,'],
    ['uxr-font-policy=restricted','uxr-font-whitelist=,Allowed'],
    ['uxr-codec-h264=smooth'], ['uxr-codec-vp8=supported,unknown'],
    ['uxr-codec-vp9=supported,'], ['uxr-codec-av1= supported'],
])
def test_invalid_snapshot_does_not_publish_partial_policy(backend_binary, args):
    assert run(backend_binary, 'validate', *args) == '0 0'


@pytest.mark.parametrize('args', [[], ['uxr-timer-resolution=0'], ['uxr-timer-resolution=1000'],
    ['uxr-keyboard-layout=native'], ['uxr-keyboard-layout=en-US', 'uxr-synthetic-device-tests=true'],
    ['uxr-pointer=fine', 'uxr-max-touch-points=10'], ['uxr-hdr=native']])
def test_valid_snapshot(backend_binary, args):
    assert run(backend_binary, 'validate', *args) == '1 1'


ANIMATION_SUPPORT = r'''
#include "base/uxr_config.h"
#include <cassert>
#include <compare>
#include <cstdint>
#include <limits>
#include <string>
#define DCHECK_GE(a, b) assert((a) >= (b))
namespace base {
struct TimeDelta {
  int64_t value = 0;
  int64_t InMicroseconds() const { return value; }
  TimeDelta operator%(TimeDelta other) const { return {value % other.value}; }
};
TimeDelta Microseconds(int64_t value) { return {value}; }
struct TimeTicks {
  int64_t value = 0;
  TimeDelta since_origin() const { return {value}; }
  auto operator<=>(const TimeTicks&) const = default;
  TimeTicks operator+(TimeDelta delta) const { return {value + delta.value}; }
  TimeTicks operator-(TimeDelta delta) const { return {value - delta.value}; }
  TimeDelta operator-(TimeTicks other) const { return {value - other.value}; }
};
struct TickClock { TimeTicks now; TimeTicks NowTicks() const { return now; } };
}
namespace blink {
constexpr base::TimeDelta kApproximateFrameTime{16666};
struct AnimationClock {
  base::TimeTicks time_;
  bool can_dynamically_update_time_ = false;
  base::TickClock* clock_;
  unsigned task_for_which_time_was_calculated_ = std::numeric_limits<unsigned>::max();
  static unsigned currently_running_task_;
  void UpdateTime(base::TimeTicks);
  base::TimeTicks CurrentTime();
};
unsigned AnimationClock::currently_running_task_ = 0;
struct Timing {
  base::TimeTicks reference;
  base::TimeTicks ReferenceMonotonicTime() const { return reference; }
  Timing& GetTiming() { return *this; }
};
struct Document { Timing* loader; Timing* Loader() { return loader; } };
struct DocumentTimeline {
  Document* document_;
  base::TimeDelta origin_time_;
  base::TimeTicks zero_time_;
  bool zero_time_initialized_ = false;
  base::TimeTicks CalculateZeroTime();
};
'''


@pytest.fixture(scope='module')
def animation_binary(tmp_path_factory, backend_binary):
    code = ANIMATION_SUPPORT
    for signature in ('void AnimationClock::UpdateTime(', 'base::TimeTicks AnimationClock::CurrentTime()',
                      'base::TimeTicks DocumentTimeline::CalculateZeroTime()'):
        code += EVIDENCE['methods'][signature]['text'] + '\n'
    code += r'''
}
int main(int argc, char** argv) {
  assert(argc == 2);
  auto& config = base::UxrConfig::GetInstance();
  assert(config.SetAll({{"uxr-timer-resolution", argv[1]}}));
  const int64_t quantum = config.TimerResolutionMicroseconds();
  const auto q = [&](int64_t value) { return config.QuantizeClockMicroseconds(value); };
  for (int64_t origin : {INT64_C(999996), INT64_C(1000003), INT64_C(1700000000000003)}) {
    blink::Timing loader{{origin}};
    blink::Document document{&loader};
    blink::DocumentTimeline timeline{&document, {}, {}, false};
    const auto zero = timeline.CalculateZeroTime();
    assert(zero.value == q(origin));
    loader.reference.value += 12345;
    assert(timeline.CalculateZeroTime() == zero);
    base::TickClock ticks{{origin}};
    blink::AnimationClock clock{{}, false, &ticks};
    int64_t previous = 0;
    for (int i = 0; i < 300; ++i) {
      const int64_t frame = origin + 288996 + i * 16666;
      // PageAnimator adds the clamped frame delta to CalculateZeroTime().
      clock.can_dynamically_update_time_ = false;
      clock.UpdateTime(zero + base::Microseconds(q(frame - zero.value)));
      const auto delivered = clock.CurrentTime();
      const int64_t raf = delivered.value - zero.value;
      assert(raf >= previous);
      if (quantum) {
        assert(raf % quantum == 0);
        assert(delivered.value == q(frame));
        assert(raf == q(frame) - q(origin));
      } else {
        assert(delivered.value == frame);
      }
      ticks.now.value = frame + 20000;
      clock.can_dynamically_update_time_ = true;
      assert(clock.CurrentTime() == delivered);
      ++blink::AnimationClock::currently_running_task_;
      const auto advanced = clock.CurrentTime();
      const auto predicted = ticks.now.value - (ticks.now.value - delivered.value) % 16666;
      assert(advanced.value == q(predicted));
      assert(advanced >= delivered);
      if (quantum) assert((advanced.value - zero.value) % quantum == 0);
      assert(advanced.value <= q(ticks.now.value));
      ticks.now.value += 100000;
      assert(clock.CurrentTime() == advanced);
      clock.UpdateTime({frame - 100000});
      assert(clock.CurrentTime() == advanced);
      clock.can_dynamically_update_time_ = false;
      ++blink::AnimationClock::currently_running_task_;
      assert(clock.CurrentTime() == advanced);
      previous = raf;
    }
    blink::DocumentTimeline shifted{&document, {1234}, {}, false};
    assert(shifted.CalculateZeroTime().value == q(loader.reference.value) + 1234);
  }
}
'''
    directory = tmp_path_factory.mktemp('animation-clock')
    source = directory / 'clock.cc'
    source.write_text(code, encoding='utf-8')
    binary = directory / 'clock'
    result = subprocess.run([CXX, '-std=c++20', '-Wall', '-Wextra', '-Werror', *sanitizer_flags(),
        '-I', str(backend_binary.parent), str(backend_binary.parent / 'base/uxr_config.cc'), str(source),
        '-o', str(binary)], capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


@pytest.mark.parametrize('resolution', [0, 1, 7, 11, 1000])
def test_animation_frames_dynamic_updates_and_origin_share_monotone_grid(animation_binary, resolution):
    run(animation_binary, str(resolution))


def test_clock_policy_is_immutable_under_concurrent_reads(backend_binary):
    run(backend_binary, 'freeze', 'uxr-timer-resolution=7')


@pytest.mark.parametrize('resolution', [0, 1, 3, 7, 1000])
def test_shared_clock_grid_signed_boundaries_and_native_mode(backend_binary, resolution):
    minimum, maximum = -(1 << 63), (1 << 63) - 1
    values = [minimum, minimum + 1, -1700000000000000, -10001, -7001, -1, 0, 1,
              6999, 7000, 7001, 1000001, 1700000000000000, maximum - 1, maximum]
    rows = run(backend_binary, 'clock', str(resolution), *map(str, values)).splitlines()
    def expected(value, quantum):
        if quantum <= 1 or value in (minimum, maximum):
            return value
        return max(minimum, (value // quantum) * quantum)
    assert [list(map(int, row.split())) for row in rows] == [
        [expected(v, resolution * 1000), expected(v, resolution)] for v in values]


@pytest.mark.parametrize('native,flags,expected', [
    ('none', [], [1, 1, 1, 1, 0, 0]), ('mouse', [], [4, 4, 2, 2, 0, 0]),
    ('touch', [], [2, 2, 1, 1, 5, 1]), ('mixed', [], [4, 6, 2, 2, 5, 1]),
    ('none', ['uxr-max-touch-points=5'], [2, 2, 1, 1, 5, 1]),
    ('mouse', ['uxr-max-touch-points=5'], [4, 6, 2, 2, 5, 1]),
    ('touch', ['uxr-max-touch-points=0'], [1, 1, 1, 1, 0, 0]),
    ('mixed', ['uxr-max-touch-points=0'], [4, 4, 2, 2, 0, 0]),
    ('mouse', ['uxr-pointer=coarse'], [2, 2, 1, 1, 1, 1]),
    ('mixed', ['uxr-pointer=none'], [1, 1, 1, 1, 0, 0]),
    ('mouse', ['uxr-pointer=fine', 'uxr-max-touch-points=10'], [4, 6, 2, 2, 10, 1]),
])
def test_input_preferences_are_coherent_and_idempotent(backend_binary, native, flags, expected):
    values = list(map(int, run(backend_binary, 'prefs', native, *flags).split()))
    assert values[:6] == expected


def test_real_style_and_scrollbar_settings_share_preferences(backend_binary):
    flags = ['uxr-reduced-motion=true', 'uxr-reduced-transparency=1', 'uxr-inverted-colors=true',
             'uxr-color-scheme=dark', 'uxr-preferred-contrast=more', 'uxr-forced-colors=active']
    assert list(map(int, run(backend_binary, 'prefs', 'mouse', *flags).split()))[6:] == [1, 1, 1, 1, 1, 1, 1, 0]


def test_media_queries_use_effective_settings_and_real_display(final_sources):
    assert 'base::UxrConfig' not in final_sources['0171']
    assert 'CalculateMaxTouchPoints' not in final_sources['0171']
    assert 'web_preferences_ = preferences;\n  ApplyUxrWebPreferences(web_preferences_);' in final_sources['0170']


@pytest.mark.parametrize('flags,expected', [
    ([], '1 0 0 0 0'), (['uxr-canvas-seed=42'], '1 0 0 0 0'),
    (['uxr-gpu-backend=compatibility'], '0 0 1 0 1'),
    (['uxr-synthetic-device-tests=true'], '0 1 1 1 1'),
    (['uxr-synthetic-device-tests=true','uxr-gpu-backend=native'], '1 0 0 0 0'),
])
def test_public_gpu_default_is_native_and_compatibility_remains_explicit(backend_binary, flags, expected):
    assert run(backend_binary, 'gpu', *flags) == expected
