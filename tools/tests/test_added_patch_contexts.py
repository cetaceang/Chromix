"""Added-patch chains against independent Chromium 152 source excerpts.

Optional provenance uses CHROMIX_ADDED_BASELINE_ROOT, a pre-Chromix tree,
and CHROMIX_ADDED_API_ROOT for the local Chromium 152 headers.
Executable probes compile applied source excerpts with interface stubs only.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

import test_fingerprint_media_audio as media
import test_restored_patch_contexts as restored

ROOT = Path(__file__).resolve().parents[2]
NUMBERS = tuple(f"{number:04d}" for number in range(111, 121))
CXX = os.environ.get("CXX") or shutil.which("clang++") or shutil.which("g++")

SOURCE_SECTIONS = {
    "0111": [(3, '''// found in the LICENSE file.

#include "third_party/blink/renderer/modules/global_privacy_control/navigator_global_privacy_control.h"

#include "third_party/blink/public/common/global_privacy_control/global_privacy_control_util.h"
#include "third_party/blink/renderer/core/execution_context/navigator_base.h"
'''), (14, '''namespace NavigatorGlobalPrivacyControl {

bool globalPrivacyControl(NavigatorBase& navigator) {
  // TODO(crbug.com/40745270): Currently, the GPC signal is controlled by a
  // feature flag, when a user facing setting is added, this should be modified
  // to use frame cached value.
  return IsGlobalPrivacyControlEnabled();
}

''')],
    "0112": [(26, '''#include "third_party/blink/renderer/core/layout/layout_theme_font_provider.h"

#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/platform/fonts/font_cache.h"
#include "third_party/blink/renderer/platform/fonts/font_description.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

// static
const AtomicString& LayoutThemeFontProvider::SystemFontFamily(
    CSSValueID system_font_id) {
  return DefaultGUIFont();
}
''')],
    "0113": [(25, '''
#include "third_party/blink/renderer/modules/webgl/webgl_debug_shaders.h"

#include "third_party/blink/renderer/modules/webgl/gl_string_query.h"
#include "third_party/blink/renderer/modules/webgl/webgl_rendering_context_base.h"
#include "third_party/blink/renderer/modules/webgl/webgl_shader.h"
'''), (44, '''}

String WebGLDebugShaders::getTranslatedShaderSource(WebGLShader* shader) {
  WebGLExtensionScopedContext scoped(this);
  if (scoped.IsLost())
    return String();
''')],
    "0114": [(4, '''
#include "third_party/blink/renderer/modules/webgpu/gpu.h"

#include <utility>

#include "base/feature_list.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
'''), (417, '''}

wgpu::TextureFormat GPU::GetPreferredCanvasFormat() {
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_LINUX)
  // Interop of vulkan and GL has mesa driver bugs for BGRA format
  // See anglebug.com/40644739
  return wgpu::TextureFormat::RGBA8Unorm;
#else
  return wgpu::TextureFormat::BGRA8Unorm;
#endif
}
''')],
    "0115": [(13, '''#include "third_party/blink/renderer/core/frame/navigator.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/modules/battery/battery_dispatcher.h"

namespace blink {

'''), (100, '''
  BatteryStatus old_status = battery_status_;
  battery_status_ = *battery_dispatcher_->LatestData();

  if (battery_property_->GetState() == BatteryProperty::kPending) {
    battery_property_->Resolve(this);
''')],
    "0116": [(11, '''#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/strcat.h"
#include "base/strings/to_string.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
'''), (1269, '''double AudioContext::baseLatency() const {
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
''')],
    "0117": [(6, '''
#include "base/feature_list.h"
#include "base/metrics/histogram_macros.h"
#include "media/base/output_device_info.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/platform/modules/webrtc/webrtc_logging.h"
'''), (206, '''}

uint32_t RealtimeAudioDestinationHandler::MaxChannelCount() const {
  return platform_destination_->MaxChannelCount();
}

double RealtimeAudioDestinationHandler::SampleRate() const {
  // This can be accessed from both threads (main and audio), so it is
  // possible that `platform_destination_` is not fully functional when it
  // is accssed by the audio thread.
  return platform_destination_ ? platform_destination_->SampleRate() : 0;
}
''')],
    "0118": restored.SOURCE_SECTIONS["0047"] + [(229, '''const SimpleFontData* FontCache::FallbackFontForCharacter(
    const FontDescription& description,
    UChar32 lookup_char,
    const SimpleFontData* font_data_to_substitute,
    FontFallbackPriority fallback_priority) {
  TRACE_EVENT0("fonts", "FontCache::FallbackFontForCharacter");

  // In addition to PUA, do not perform fallback for non-characters either. Some
  // of these are sentinel characters to detect encodings and do appear on
  // websites. More details on
  // http://www.unicode.org/faq/private_use.html#nonchar1 - See also
  // crbug.com/862352 where performing fallback for U+FFFE causes a memory
  // regression.
  if (Character::IsPrivateUse(lookup_char) ||
      Character::IsNonCharacter(lookup_char))
    return nullptr;
  base::ElapsedTimer timer;
  const SimpleFontData* result = PlatformFallbackFontForCharacter(
      description, lookup_char, font_data_to_substitute, fallback_priority);
  base::TimeDelta elapsed = timer.Elapsed();
  bool is_emoji = IsNonTextFallbackPriority(fallback_priority);
  UErrorCode err = U_ZERO_ERROR;
  UScriptCode script = uscript_getScript(lookup_char, &err);
  if (U_FAILURE(err)) {
    script = USCRIPT_INVALID_CODE;
  }
  FontPerformance::AddSystemFallbackFontTime(script, is_emoji, elapsed);
  return result;
}
''')],
    "0119": [(6, '''
#include "base/bit_cast.h"
#include "base/rand_util.h"

#include <cmath>

namespace blink {

namespace {
const int64_t kTenLowerDigitsMod = 10000000000;
}  // namespace

TimeClamper::TimeClamper() : secret_(base::RandUint64()) {}

// This is using int64 for timestamps, because https://bit.ly/doubles-are-bad
base::TimeDelta TimeClamper::ClampTimeResolution(
''')],
    "0120": media.SOURCE_SECTIONS["0022"],
}


def source_fixture(number):
    lines = []
    for first, text in SOURCE_SECTIONS[number]:
        assert len(lines) < first
        lines.extend("// unrelated source line\n" for _ in range(first - 1 - len(lines)))
        lines.extend(text.splitlines(keepends=True))
    return "".join(lines) + "// not EOF\n// trailing source\n"


@pytest.fixture(scope="module")
def patched_sources(tmp_path_factory):
    directory = tmp_path_factory.mktemp("added-patch-chains")
    sources = {}
    for number in NUMBERS:
        patch = media.patch_path(number)
        path = directory / restored.target_path(patch.read_bytes())
        path.parent.mkdir(parents=True, exist_ok=True)
        original = source_fixture(number)
        path.write_bytes(original.encode("utf-8"))
        chain = {"0118": ("0047", "0118"), "0120": ("0022", "0120")}.get(number, (number,))
        for step in chain:
            result = restored.apply_patch(directory, media.patch_path(step))
            assert result.returncode == 0, result.stdout.decode()
            assert b"fuzz" not in result.stdout
            offsets = re.findall(rb"offset (-?\d+) lines?", result.stdout)
            assert offsets == {"0111": [b"3"], "0116": [b"28"]}.get(step, [])
        sources[number] = path.read_text()
        for step in reversed(chain):
            result = restored.apply_patch(directory, media.patch_path(step), reverse=True)
            assert result.returncode == 0, result.stdout.decode()
        assert path.read_text() == original
    return sources


@pytest.mark.parametrize("number", NUMBERS)
def test_added_patch_applies_and_chain_reverses(patched_sources, number):
    assert patched_sources[number] != source_fixture(number)


@pytest.mark.parametrize("number", NUMBERS)
def test_fixture_matches_local_chromium_152(number):
    baseline = os.environ.get("CHROMIX_ADDED_BASELINE_ROOT")
    if not baseline:
        pytest.skip("set CHROMIX_ADDED_BASELINE_ROOT to verify fixture provenance")
    path = Path(baseline) / media.target_path(number)
    lines = path.read_text().splitlines(keepends=True)
    for first, text in SOURCE_SECTIONS[number]:
        assert "".join(lines[first - 1:first - 1 + len(text.splitlines())]) == text


def test_media_chain_preserves_browser_enumeration(patched_sources):
    strip_comments = lambda text: "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("//"))
    assert strip_comments(patched_sources["0120"]) == strip_comments(source_fixture("0120"))


def test_webgpu_native_fallback_and_single_declarations(patched_sources):
    source = patched_sources["0114"]
    assert "command_line" not in source
    assert "uxr-webgpu-canvas-format" not in source
    assert "base::UxrConfig" not in source
    assert source[source.index("#if BUILDFLAG(IS_ANDROID)"):] == source_fixture("0114")[
        source_fixture("0114").index("#if BUILDFLAG(IS_ANDROID)"):]


def test_realtime_sample_rate_remains_native(patched_sources):
    marker = "double RealtimeAudioDestinationHandler::SampleRate() const"
    assert patched_sources["0117"].split(marker)[1] == source_fixture("0117").split(marker)[1]
    assert 'uxr-audio-sample-rate' not in media.patch_path("0116").read_text()
    assert 'uxr-audio-sample-rate' not in media.patch_path("0117").read_text()


def compile_probe(tmp_path, text, *flags):
    if CXX is None:
        pytest.skip("a local C++20 compiler is required")
    source = tmp_path / "added-interfaces.cc"
    source.write_text(text)
    binary = tmp_path / "added-interfaces"
    result = subprocess.run([CXX, "-std=c++20", "-Wall", "-Wextra", "-Werror", *flags,
                             str(source), "-o", str(binary)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


def test_battery_interface_probe(tmp_path, patched_sources):
    battery = media.excerpt(patched_sources["0115"], "  auto& config =",
                            "\n  if (battery_property_")
    binary = compile_probe(tmp_path, CPP_SUPPORT + "\nvoid ProbeBattery() {\n" + battery + "}\n" + CPP_TESTS)
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


def test_latency_patch_changes_only_an_invariant_comment(patched_sources):
    def without_comments(source):
        return "\n".join(line.split("//", 1)[0].rstrip() for line in source.splitlines()
                         if not line.lstrip().startswith("//"))
    assert without_comments(patched_sources["0116"]) == without_comments(source_fixture("0116"))
    assert "uxr-audio-" not in patched_sources["0116"]
    assert "uxr-audio-" not in patched_sources["0117"]


def test_font_candidates_are_unique_and_bundled(patched_sources):
    source = patched_sources["0118"]
    candidates = media.excerpt(source, "kPersonaFallbackFamilies[] = {", "    for (const char* family")
    families = re.findall(r'"([^"]+)"', candidates)
    bundled = media.excerpt(source, "kBundledWindowsFamilies[] = {", "  for (const char* allowed")
    assert len(families) == len(set(families))
    assert set(families) <= set(re.findall(r'"([^"]+)"', bundled))
    assert "SimSun" not in families


@pytest.mark.parametrize(("path", "declaration"), [
    ("base/strings/string_number_conversions.h",
     "BASE_EXPORT bool StringToUint64(std::string_view input, uint64_t* output);"),
    ("third_party/blink/renderer/platform/fonts/simple_font_data.h",
     "  Glyph GlyphForCharacter(UChar32) const;"),
    ("third_party/blink/renderer/core/timing/time_clamper.h", "  const uint64_t secret_;"),
    ("third_party/blink/renderer/modules/webaudio/audio_context.h", "  double baseLatency() const;"),
    ("third_party/blink/renderer/modules/webaudio/audio_context.h", "  double outputLatency() const;"),
    ("third_party/blink/renderer/modules/webaudio/realtime_audio_destination_handler.h",
     "  uint32_t MaxChannelCount() const override;"),
])
def test_local_chromium_152_api(path, declaration):
    root = os.environ.get("CHROMIX_ADDED_API_ROOT")
    if not root:
        pytest.skip("set CHROMIX_ADDED_API_ROOT to verify local Chromium 152 declarations")
    assert declaration in (Path(root) / path).read_text()


@pytest.fixture(scope="module", params=["linux", "other"])
def native_binary(tmp_path_factory, patched_sources, request):
    sources = [
        media.excerpt(patched_sources["0114"], "wgpu::TextureFormat GPU::GetPreferredCanvasFormat()", "// not EOF"),
        media.excerpt(patched_sources["0116"], "double AudioContext::baseLatency()", "// not EOF"),
        media.excerpt(patched_sources["0117"], "uint32_t RealtimeAudioDestinationHandler::MaxChannelCount()", "// not EOF"),
        media.excerpt(patched_sources["0118"], "const SimpleFontData* FontCache::FallbackFontForCharacter(", "// not EOF"),
        media.excerpt(patched_sources["0119"], "TimeClamper::TimeClamper()", "// This is using int64"),
    ]
    directory = tmp_path_factory.mktemp(f"native-added-{request.param}")
    return compile_probe(directory, CPP_SUPPORT + CPP_NATIVE_SUPPORT + "\n".join(sources) + CPP_NATIVE_TESTS,
                         f"-DIS_LINUX={int(request.param == 'linux')}")


@pytest.mark.parametrize("case", ["webgpu", "audio", "font"])
def test_extracted_native_contracts(native_binary, case):
    result = subprocess.run([str(native_binary), case], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("seed", ["", "0", "-1", "abc", "42x", " 42", "42 ", "18446744073709551616"])
def test_invalid_timer_seed_uses_random_secret(native_binary, seed):
    result = subprocess.run([str(native_binary), "timer", seed], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.split() == ["1", "2", "2"]


@pytest.mark.parametrize("seed", ["1", "4294967295", "4294967296", "1099511627776", "18446744073709551615"])
def test_full_uint64_timer_seed_is_deterministic(native_binary, seed):
    value = int(seed)
    for multiplier in (0xff51afd7ed558ccd, 0xc4ceb9fe1a85ec53):
        value = ((value ^ (value >> 33)) * multiplier) & ((1 << 64) - 1)
    value ^= value >> 33
    result = subprocess.run([str(native_binary), "timer", seed], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.split() == [str(value), str(value), "0"]


CPP_SUPPORT = r'''
#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <map>
#include <string>
namespace base {
struct UxrConfig {
  std::map<std::string, std::string> values;
  static UxrConfig& GetInstance() { static UxrConfig config; return config; }
  std::string Get(const std::string& name) { return values[name]; }
};
bool EqualsCaseInsensitiveASCII(const std::string& a, const std::string& b) { return a == b; }
bool StringToDouble(const std::string& input, double* output) {
  char* end = nullptr;
  *output = std::strtod(input.c_str(), &end);
  return !input.empty() && end == input.c_str() + input.size();
}
struct TimeDelta { double value; double InSecondsF() const { return value; } };
TimeDelta Seconds(double value) { return {value}; }
}
struct BatteryStatus {
  bool charging; base::TimeDelta charge; base::TimeDelta discharge; double level;
  bool Charging() const { return charging; }
  base::TimeDelta charging_time() const { return charge; }
  base::TimeDelta discharging_time() const { return discharge; }
  double Level() const { return level; }
};
BatteryStatus battery_status_{false, {10.0}, {20.0}, 0.75};
'''

CPP_TESTS = r'''
int main() {
  auto& config = base::UxrConfig::GetInstance();
  for (const std::string value : {"", "bad", "0.4junk"}) {
    config.values["uxr-battery-level"] = value;
    ProbeBattery();
    assert(battery_status_.Level() == 0.75);
  }
  config.values["uxr-battery-level"] = "0.5";
  ProbeBattery();
  assert(battery_status_.Level() == 0.5);
  config.values["uxr-battery-level"] = "2";
  ProbeBattery();
  assert(battery_status_.Level() == 1.0);
}
'''

CPP_NATIVE_SUPPORT = r'''
#include <charconv>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <limits>
#include <vector>
#define BUILDFLAG(flag) (flag)
#define IS_ANDROID 0
#define DCHECK(condition) assert(condition)
#define DCHECK_CALLED_ON_VALID_SEQUENCE(sequence) ((void)0)
#define TRACE_EVENT0(category, name) ((void)0)
namespace base {
uint64_t random_calls = 0;
uint64_t RandUint64() { return ++random_calls; }
bool StringToUint64(std::string_view text, uint64_t* output) {
  *output = 0;
  auto converted = std::from_chars(text.data(), text.data() + text.size(), *output);
  if (converted.ec == std::errc::result_out_of_range)
    *output = std::numeric_limits<uint64_t>::max();
  return converted.ec == std::errc() && converted.ptr == text.data() + text.size();
}
struct ElapsedTimer { TimeDelta Elapsed() const { return {0.01}; } };
}
namespace wgpu { enum class TextureFormat { RGBA8Unorm, BGRA8Unorm }; }
struct GPU { static wgpu::TextureFormat GetPreferredCanvasFormat(); };
struct DeferredTaskHandler {
  static int lock_count;
  struct GraphAutoLocker {
    explicit GraphAutoLocker(DeferredTaskHandler&) { ++lock_count; }
    ~GraphAutoLocker() { --lock_count; }
  };
};
int DeferredTaskHandler::lock_count = 0;
struct AudioContext {
  double base_latency_ = 0;
  struct { double hardware_output_latency = 0; } output_position_;
  double factor = 0.001;
  DeferredTaskHandler& GetDeferredTaskHandler() const { static DeferredTaskHandler handler; return handler; }
  double GetOutputLatencyQuantizingFactor() const {
    assert(DeferredTaskHandler::lock_count == 1);
    return factor;
  }
  bool destination() const { return true; }
  double baseLatency() const;
  double outputLatency() const;
};
struct Destination {
  uint32_t channels;
  double rate;
  uint32_t MaxChannelCount() const { return channels; }
  double SampleRate() const { return rate; }
};
struct RealtimeAudioDestinationHandler {
  Destination* platform_destination_;
  uint32_t MaxChannelCount() const;
  double SampleRate() const;
};
using AtomicString = std::string;
using UChar32 = int;
using FontDescription = int;
using FontFallbackPriority = int;
using UErrorCode = int;
using UScriptCode = int;
constexpr int U_ZERO_ERROR = 0;
constexpr int USCRIPT_INVALID_CODE = -1;
bool U_FAILURE(int error) { return error != 0; }
int uscript_getScript(int, int*) { return 0; }
bool IsNonTextFallbackPriority(int priority) { return priority != 0; }
struct Character {
  static bool IsPrivateUse(int value) { return value == 0xe000; }
  static bool IsNonCharacter(int value) { return value == 0xffff; }
};
struct SimpleFontData {
  bool contains_glyph = true;
  unsigned short GlyphForCharacter(int) const { return contains_glyph ? 1 : 0; }
};
SimpleFontData persona_font;
SimpleFontData native_font;
std::map<std::string, const SimpleFontData*> available_fonts;
std::vector<std::string> queried_families;
int native_fallback_calls = 0;
int fallback_metrics = 0;
struct FontPerformance {
  static void AddSystemFallbackFontTime(int, bool, base::TimeDelta) { ++fallback_metrics; }
};
struct FontCache {
  const SimpleFontData* GetFontData(int, const AtomicString& family) {
    queried_families.push_back(family);
    auto found = available_fonts.find(family);
    return found == available_fonts.end() ? nullptr : found->second;
  }
  const SimpleFontData* PlatformFallbackFontForCharacter(int description, int character,
                                                        const SimpleFontData* original, int priority) {
    assert(description == 7 && character == 65 && original == &native_font && priority == 3);
    ++native_fallback_calls;
    return &native_font;
  }
  const SimpleFontData* FallbackFontForCharacter(const FontDescription&, UChar32,
                                                const SimpleFontData*, FontFallbackPriority);
};
struct TimeClamper {
  TimeClamper();
  const uint64_t secret_;
};
'''

CPP_NATIVE_TESTS = r'''
int main(int argc, char** argv) {
  assert(argc >= 2);
  auto& config = base::UxrConfig::GetInstance();
  const std::string test = argv[1];
  if (test == "webgpu") {
    const auto native = IS_LINUX ? wgpu::TextureFormat::RGBA8Unorm : wgpu::TextureFormat::BGRA8Unorm;
    for (const std::string value : {"", "invalid", "RGBA8Unorm", "rgba8unorm", "bgra8unorm"}) {
      config.values["uxr-webgpu-canvas-format"] = value;
      assert(GPU::GetPreferredCanvasFormat() == native);
    }
  } else if (test == "audio") {
    config.values["uxr-audio-base-latency"] = "999";
    config.values["uxr-audio-output-latency"] = "999";
    config.values["uxr-audio-max-channel-count"] = "999";
    config.values["uxr-audio-sample-rate"] = "12345";
    AudioContext context;
    for (double latency : {0.0, 0.003, 0.1}) {
      context.base_latency_ = latency;
      context.output_position_.hardware_output_latency = latency + 0.0007;
      assert(context.baseLatency() == latency);
      assert(context.outputLatency() == std::round((latency + 0.0007) / context.factor) * context.factor);
      assert(DeferredTaskHandler::lock_count == 0);
    }
    for (uint32_t channels : {0u, 1u, 2u, 8u}) {
      Destination destination{channels, 48000.0};
      RealtimeAudioDestinationHandler handler{&destination};
      assert(handler.MaxChannelCount() == channels);
      assert(handler.SampleRate() == 48000.0);
    }
    RealtimeAudioDestinationHandler missing{nullptr};
    assert(missing.MaxChannelCount() == 0);
    assert(missing.SampleRate() == 0);
  } else if (test == "font") {
    FontCache cache;
    config.values["uxr-platform"] = "windows";
    available_fonts["Arial"] = &persona_font;
    assert(cache.FallbackFontForCharacter(7, 65, &native_font, 3) == &native_font);
    assert(queried_families.empty());
    assert(native_fallback_calls == 1 && fallback_metrics == 1);
    native_fallback_calls = fallback_metrics = 0;
    config.values["uxr-synthetic-device-tests"] = "true";
    assert(cache.FallbackFontForCharacter(7, 65, &native_font, 3) == &persona_font);
    assert(native_fallback_calls == 0);
    persona_font.contains_glyph = false;
    assert(cache.FallbackFontForCharacter(7, 65, &native_font, 3) == &native_font);
    assert(native_fallback_calls == 1 && fallback_metrics == 1);
    available_fonts.clear();
    assert(cache.FallbackFontForCharacter(7, 65, &native_font, 3) == &native_font);
    assert(native_fallback_calls == 2 && fallback_metrics == 2);
    queried_families.clear();
    config.values["uxr-font-whitelist"] = "custom";
    assert(cache.FallbackFontForCharacter(7, 65, &native_font, 3) == &native_font);
    assert(queried_families.empty());
    config.values["uxr-font-whitelist"] = "";
    config.values["uxr-platform"] = "linux";
    assert(cache.FallbackFontForCharacter(7, 65, &native_font, 3) == &native_font);
    assert(queried_families.empty());
    assert(native_fallback_calls == 4 && fallback_metrics == 4);
    assert(cache.FallbackFontForCharacter(7, 0xe000, &native_font, 3) == nullptr);
    assert(cache.FallbackFontForCharacter(7, 0xffff, &native_font, 3) == nullptr);
    assert(native_fallback_calls == 4);
  } else if (test == "timer") {
    assert(argc == 3);
    config.values["uxr-canvas-seed"] = argv[2];
    TimeClamper first, second;
    std::cout << first.secret_ << ' ' << second.secret_ << ' ' << base::random_calls;
  } else {
    return 1;
  }
}
'''
