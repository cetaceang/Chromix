"""Chromium 152 media/audio regressions, with executable C++ readback stubs.

Source excerpts are independent Chromium 152.0.7977.82 fixtures, not generated
from patch additions. CHROMIX_MEDIA_AUDIO_BASELINE_ROOT optionally checks them
against a local pre-Chromix tree. No source/browser downloads or Chromium build
are performed. The stubs do not exercise Mojo, a device backend or the DSP graph.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
PATCHES = ROOT / "patches"
PATCH_BIN = shutil.which("gpatch") or shutil.which("patch")
CXX = shutil.which("clang++") or shutil.which("g++")
NUMBERS = ("0022", "0026", "0027", "0028", "0050", "0051", "0053")


def patch_path(number):
    matches = list(PATCHES.glob(f"{number}-*.patch"))
    assert len(matches) == 1
    return matches[0]


def target_path(number):
    return re.search(r"^\+\+\+ b/(.*)$", patch_path(number).read_text(), re.M)[1]


def source_fixture(number):
    lines = []
    for first, text in SOURCE_SECTIONS[number]:
        assert len(lines) < first
        lines.extend("// unrelated source line\n" for _ in range(first - 1 - len(lines)))
        lines.extend(text.splitlines(keepends=True))
    lines.extend(["// not EOF\n", "// trailing context\n"])
    return "".join(lines)


def apply_patch(directory, number, reverse=False):
    if not PATCH_BIN:
        pytest.skip("GNU patch is required")
    command = [PATCH_BIN, "-p1", "--fuzz=0", "--batch", "--forward", "--get=0",
               "--no-backup-if-mismatch", "--reject-file=-", "-i", str(patch_path(number))]
    if reverse:
        command.append("--reverse")
    result = subprocess.run(command, cwd=directory, text=True, capture_output=True,
                            timeout=15, env={**os.environ, "LC_ALL": "C", "PATCH_GET": "0"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "fuzz" not in result.stdout
    offsets = re.findall(r"offset (-?\d+) lines?", result.stdout)
    assert offsets == (["-5"] if number == "0053" else [])


@pytest.fixture(scope="module")
def patched_sources(tmp_path_factory):
    directory = tmp_path_factory.mktemp("media-audio-sources")
    sources = {}
    for number in NUMBERS:
        path = directory / target_path(number)
        path.parent.mkdir(parents=True, exist_ok=True)
        original = source_fixture(number)
        path.write_text(original)
        apply_patch(directory, number)
        sources[number] = path.read_text()
        apply_patch(directory, number, reverse=True)
        assert path.read_text() == original
    return sources


@pytest.mark.parametrize("number", NUMBERS)
def test_patch_applies_exactly_and_reverses(patched_sources, number):
    assert patched_sources[number] != source_fixture(number)


@pytest.mark.parametrize("number", NUMBERS)
def test_fixture_matches_local_chromium_152(number):
    baseline = os.environ.get("CHROMIX_MEDIA_AUDIO_BASELINE_ROOT")
    if not baseline:
        pytest.skip("set CHROMIX_MEDIA_AUDIO_BASELINE_ROOT to verify fixture provenance")
    lines = (Path(baseline) / target_path(number)).read_text().splitlines(keepends=True)
    for first, text in SOURCE_SECTIONS[number]:
        assert "".join(lines[first - 1:first - 1 + len(text.splitlines())]) == text


@pytest.mark.parametrize("number", NUMBERS)
def test_unsafe_renderer_overrides_are_retired(number):
    # Static guard only; runtime assertions are in the compiled harness below.
    patch = patch_path(number).read_text()
    additions = [line[1:] for line in patch.splitlines()
                 if line.startswith("+") and not line.startswith("+++")]
    assert additions
    removals = [line[1:] for line in patch.splitlines()
                if line.startswith("-") and not line.startswith("---")]
    if number == "0053":
        expected = "float sampleRate() const { return destination_handler_->SampleRate(); }".split()
        code = "\n".join(line for line in additions if not line.lstrip().startswith("//"))
        assert code.split() == expected
        assert "\n".join(removals).split() == expected
    else:
        assert all(not line.strip() or line.lstrip().startswith("//") for line in additions)
        assert not removals


def excerpt(source, start, end):
    begin = source.index(start)
    return source[begin:source.index(end, begin)]


@pytest.fixture(scope="module")
def runtime_binary(tmp_path_factory, patched_sources):
    if not CXX:
        pytest.skip("a local C++20 compiler is required for the executable stub")
    sources = patched_sources
    buffer_methods = excerpt(sources["0026"], "NotShared<DOMFloat32Array> AudioBuffer::getChannelData(",
                             "std::unique_ptr<SharedAudioBuffer>")
    analyser_methods = excerpt(sources["0028"], "void RealtimeAnalyser::GetFloatFrequencyData(",
                               "void RealtimeAnalyser::WriteInput(")
    media_body = excerpt(sources["0022"], "  MediaDeviceInfoVector media_devices;", "\nvoid MediaDevices::OnDispatcher")
    permission_body = excerpt(sources["0051"], "void Permissions::TaskComplete(", "\nvoid Permissions::VerifyPermission")
    notification_methods = excerpt(sources["0050"], "V8NotificationPermission::Enum Notification::PermissionToV8Enum(",
                                   "ScriptPromise<V8NotificationPermission> Notification::requestPermission(")
    sample_rate = excerpt(sources["0053"], "  float sampleRate() const", "  AudioListener* listener()")
    directory = tmp_path_factory.mktemp("media-audio-runtime")
    source = directory / "readbacks.cc"
    source.write_text(CPP_SUPPORT + "\n" + buffer_methods + "\n" + analyser_methods + "\n" +
                      "std::vector<MediaDeviceInfo*> Enumerate(const std::vector<std::vector<WebMediaDeviceInfo>>& enumeration,\n"
                      "    std::vector<int> audio_input_capabilities = {}, std::vector<int> video_input_capabilities = {}) {\n"
                      "  assert(enumeration.size() == 3);\n"
                      "  assert(audio_input_capabilities.empty() || audio_input_capabilities.size() == enumeration[0].size());\n"
                      "  assert(video_input_capabilities.empty() || video_input_capabilities.size() == enumeration[1].size());\n"
                      "  Tracker tracker; Tracker* result_tracker = &tracker; Tracer trace; Tracer* tracer = &trace;\n" +
                      media_body.replace("  tracer->End();", "  tracer->End();\n  return tracker.result;") + "\n" +
                      permission_body + "\n" + notification_methods + "\n" +
                      "struct BaseAudioContext { Destination* destination_handler_;\n" + sample_rate + "};\n" +
                      CPP_TESTS)
    binary = directory / "readbacks"
    result = subprocess.run([CXX, "-std=c++20", "-O0", "-Wall", "-Wextra", "-Werror",
                             str(source), "-o", str(binary)], text=True, capture_output=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


@pytest.mark.parametrize("case", ["media", "media-capabilities", "permissions", "permissions-isolation",
                                  "notification-contexts", "buffer-silence",
                                  "buffer-writes", "buffer-boundaries", "buffer-special-values",
                                  "analyser-silence", "analyser-projections", "sample-rate"])
def test_executable_readback_contract(runtime_binary, case):
    result = subprocess.run([str(runtime_binary), case], text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


SOURCE_SECTIONS = {
    "0022": [(1450, r'''  MediaDeviceInfoVector media_devices;
  bool result_contains_nonempty_input_device_ids = false;
  for (wtf_size_t i = 0;
       i < static_cast<wtf_size_t>(
               mojom::blink::MediaDeviceType::kNumMediaDeviceTypes);
       ++i) {
    for (wtf_size_t j = 0; j < enumeration[i].size(); ++j) {
      mojom::blink::MediaDeviceType device_type =
          static_cast<mojom::blink::MediaDeviceType>(i);
      WebMediaDeviceInfo device_info = enumeration[i][j];
      String device_label = String::FromUtf8(device_info.label);
      if (device_type == mojom::blink::MediaDeviceType::kMediaAudioInput ||
          device_type == mojom::blink::MediaDeviceType::kMediaVideoInput) {
        if (!device_info.device_id.empty()) {
          result_contains_nonempty_input_device_ids = true;
        }
        InputDeviceInfo* input_device_info =
            MakeGarbageCollected<InputDeviceInfo>(
                String::FromUtf8(device_info.device_id), device_label,
                String::FromUtf8(device_info.group_id), device_type);
        if (device_type == mojom::blink::MediaDeviceType::kMediaVideoInput &&
            !video_input_capabilities.empty()) {
          input_device_info->SetVideoInputCapabilities(
              std::move(video_input_capabilities[j]));
        }
        if (device_type == mojom::blink::MediaDeviceType::kMediaAudioInput &&
            !audio_input_capabilities.empty()) {
          input_device_info->SetAudioInputCapabilities(
              std::move(audio_input_capabilities[j]));
        }
        media_devices.push_back(input_device_info);
      } else {
        media_devices.push_back(MakeGarbageCollected<MediaDeviceInfo>(
            String::FromUtf8(device_info.device_id), device_label,
            String::FromUtf8(device_info.group_id), device_type));
      }
    }
  }

  ReportCompletedEnumerateDevices(result_contains_nonempty_input_device_ids);
  result_tracker->Resolve(media_devices);
  tracer->End();
}

void MediaDevices::OnDispatcherHostConnectionError() {
''')],
    "0026": [(204, r'''NotShared<DOMFloat32Array> AudioBuffer::getChannelData(
    unsigned channel_index,
    ExceptionState& exception_state) {
  if (channel_index >= channels_.size()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        StrCat({"channel index (", String::Number(channel_index),
                ") exceeds number of channels (",
                String::Number(channels_.size()), ")"}));
    return NotShared<DOMFloat32Array>(nullptr);
  }

  return getChannelData(channel_index);
}

NotShared<DOMFloat32Array> AudioBuffer::getChannelData(unsigned channel_index) {
  if (channel_index >= channels_.size()) {
    return NotShared<DOMFloat32Array>(nullptr);
  }

  return NotShared<DOMFloat32Array>(channels_[channel_index].Get());
}

void AudioBuffer::copyFromChannel(NotShared<DOMFloat32Array> destination,
                                  int32_t channel_number,
                                  ExceptionState& exception_state) {
  return copyFromChannel(destination, channel_number, 0, exception_state);
}

void AudioBuffer::copyFromChannel(NotShared<DOMFloat32Array> destination,
                                  int32_t channel_number,
                                  size_t buffer_offset,
                                  ExceptionState& exception_state) {
  if (!destination->length()) {
    return;
  }

  if (channel_number < 0 ||
      static_cast<uint32_t>(channel_number) >= channels_.size()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        ExceptionMessages::IndexOutsideRange(
            "channelNumber", channel_number, 0,
            ExceptionMessages::kInclusiveBound,
            static_cast<int32_t>(channels_.size() - 1),
            ExceptionMessages::kInclusiveBound));

    return;
  }

  base::span<const float> src = channels_[channel_number].Get()->AsSpan();
  base::span<float> dst = destination->AsSpan();

  // We don't need to copy anything if a) the buffer offset is past the end of
  // the AudioBuffer or b) the internal `Data()` of is a zero-length
  // `Float32Array`, which can result a nullptr.
  if (buffer_offset >= src.size() || dst.empty()) {
    return;
  }

  size_t count = std::min(dst.size(), src.size() - buffer_offset);

  DCHECK(src.data());
  DCHECK(dst.data());

  dst.first(count).copy_from(src.subspan(buffer_offset, count));
}

void AudioBuffer::copyToChannel(NotShared<DOMFloat32Array> source,
                                int32_t channel_number,
                                ExceptionState& exception_state) {
  return copyToChannel(source, channel_number, 0, exception_state);
}

void AudioBuffer::copyToChannel(NotShared<DOMFloat32Array> source,
                                int32_t channel_number,
                                size_t buffer_offset,
                                ExceptionState& exception_state) {
  if (!source->length()) {
    return;
  }

  if (channel_number < 0 ||
      static_cast<uint32_t>(channel_number) >= channels_.size()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        ExceptionMessages::IndexOutsideRange(
            "channelNumber", channel_number, 0,
            ExceptionMessages::kInclusiveBound,
            static_cast<int32_t>(channels_.size() - 1),
            ExceptionMessages::kInclusiveBound));
    return;
  }

  base::span<float> dst = channels_[channel_number].Get()->AsSpan();

  if (buffer_offset >= dst.size()) {
    // Nothing to copy if the buffer offset is past the end of the AudioBuffer.
    return;
  }

  size_t count = dst.size() - buffer_offset;

  base::span<const float> src = source->AsSpan();
  count = std::min(src.size(), count);

  DCHECK(src.data());
  DCHECK(dst.data());

  dst.subspan(buffer_offset, count).copy_from(src.first(count));
}

void AudioBuffer::Zero() {
  for (unsigned i = 0; i < channels_.size(); ++i) {
    if (NotShared<DOMFloat32Array> array = getChannelData(i)) {
      std::ranges::fill(array->AsSpan(), 0.0f);
    }
  }
}

std::unique_ptr<SharedAudioBuffer> AudioBuffer::CreateSharedAudioBuffer() {
''')],
    "0027": [(122, r'''  float sample_rate_;
  uint32_t length_;

  HeapVector<Member<DOMFloat32Array>> channels_;
};

// Shared data that audio threads can hold onto.
''')],
    "0028": [(98, r'''  return true;
}

void RealtimeAnalyser::GetFloatFrequencyData(DOMFloat32Array* destination_array,
                                             double current_time) {
  DCHECK(IsMainThread());
  DCHECK(destination_array);

  if (current_time > last_analysis_time_) {
    // Time has advanced since the last call; update the FFT data.
    last_analysis_time_ = current_time;
    DoFFTAnalysis();
  }

  // Convert from linear magnitude to floating-point decibels.
  const size_t source_length = magnitude_buffer_.size();
  const size_t len = std::min(source_length, destination_array->length());
  if (len > 0) {
    base::span<float> destination = destination_array->AsSpan();
    for (unsigned i = 0; i < len; ++i) {
      const float linear_value = magnitude_buffer_[i];
      const double db_mag = audio_utilities::LinearToDecibels(linear_value);
      destination[i] = static_cast<float>(db_mag);
    }
  }
}

void RealtimeAnalyser::GetByteFrequencyData(DOMUint8Array* destination_array,
                                            double current_time) {
  DCHECK(IsMainThread());
  DCHECK(destination_array);

  if (current_time > last_analysis_time_) {
    // Time has advanced since the last call; update the FFT data.
    last_analysis_time_ = current_time;
    DoFFTAnalysis();
  }

  // FIXME: Is it worth caching the data so we don't have to do the conversion
  // every time?  Perhaps not, since we expect many calls in the same
  // rendering quantum.

  // Convert from linear magnitude to unsigned-byte decibels.
  const size_t source_length = magnitude_buffer_.size();
  const size_t len = std::min(source_length, destination_array->length());
  if (len > 0) {
    const double range_scale_factor =
        max_decibels_ == min_decibels_ ? 1.0
                                       : 1.0 / (max_decibels_ - min_decibels_);
    const double min_decibels = min_decibels_;

    base::span<unsigned char> destination = destination_array->AsSpan();
    for (unsigned i = 0; i < len; ++i) {
      const float linear_value = magnitude_buffer_[i];
      const double db_mag = audio_utilities::LinearToDecibels(linear_value);

      // The range m_minDecibels to m_maxDecibels will be scaled to byte values
      // from 0 to UCHAR_MAX.
      const double scaled_value =
          UCHAR_MAX * (db_mag - min_decibels) * range_scale_factor;

      // Clip to valid range.
      destination[i] =
          static_cast<unsigned char>(ClampTo(scaled_value, 0, UCHAR_MAX));
    }
  }
}

void RealtimeAnalyser::GetFloatTimeDomainData(
    DOMFloat32Array* destination_array) {
  DCHECK(IsMainThread());
  DCHECK(destination_array);

  const unsigned fft_size = FftSize();
  const size_t len =
      std::min(static_cast<size_t>(fft_size), destination_array->length());
  if (len > 0) {
    DCHECK_EQ(input_buffer_.size(), kInputBufferSize);
    DCHECK_GT(input_buffer_.size(), fft_size);

    const unsigned write_index = GetWriteIndex();

    base::span<float> destination = destination_array->AsSpan();
    for (unsigned i = 0; i < len; ++i) {
      // Buffer access is protected due to modulo operation.
      float value =
          input_buffer_[(i + write_index - fft_size + kInputBufferSize) %
                        kInputBufferSize];

      destination[i] = value;
    }
  }
}

void RealtimeAnalyser::GetByteTimeDomainData(DOMUint8Array* destination_array) {
  DCHECK(IsMainThread());
  DCHECK(destination_array);

  const unsigned fft_size = FftSize();
  const size_t len =
      std::min(static_cast<size_t>(fft_size), destination_array->length());
  if (len > 0) {
    DCHECK_EQ(input_buffer_.size(), kInputBufferSize);
    DCHECK_GT(input_buffer_.size(), fft_size);

    const unsigned write_index = GetWriteIndex();

    base::span<unsigned char> destination = destination_array->AsSpan();
    for (unsigned i = 0; i < len; ++i) {
      // Buffer access is protected due to modulo operation.
      const float value =
          input_buffer_[(i + write_index - fft_size + kInputBufferSize) %
                        kInputBufferSize];

      // Scale from nominal -1 -> +1 to unsigned byte.
      const double scaled_value = 128 * (value + 1);

      // Clip to valid range.
      destination[i] =
          static_cast<unsigned char>(ClampTo(scaled_value, 0, UCHAR_MAX));
    }
  }
}

void RealtimeAnalyser::WriteInput(AudioBus* bus, uint32_t frames_to_process) {
''')],
    "0050": [(408, r'''V8NotificationPermission::Enum Notification::PermissionToV8Enum(
    mojom::blink::PermissionStatus permission) {
  switch (permission) {
    case mojom::blink::PermissionStatus::GRANTED:
      return V8NotificationPermission::Enum::kGranted;
    case mojom::blink::PermissionStatus::DENIED:
      return V8NotificationPermission::Enum::kDenied;
    case mojom::blink::PermissionStatus::ASK:
      return V8NotificationPermission::Enum::kDefault;
  }
  NOTREACHED();
}

V8NotificationPermission Notification::permission(ExecutionContext* context) {
  // Permission is always denied for insecure contexts. Skip the sync IPC call.
  if (!context->IsSecureContext()) {
    return V8NotificationPermission(V8NotificationPermission::Enum::kDenied);
  }

  // If the current global object's browsing context is a prerendering browsing
  // context, then return "default".
  // https://wicg.github.io/nav-speculation/prerendering.html#patch-notifications
  if (auto* window = DynamicTo<LocalDOMWindow>(context)) {
    if (Document* document = window->document(); document->IsPrerendering()) {
      return V8NotificationPermission(V8NotificationPermission::Enum::kDefault);
    }
  }

  mojom::blink::PermissionStatus status =
      NotificationManager::From(context)->GetPermissionStatus();

  // Permission can only be requested from top-level frames and same-origin
  // iframes. This should be reflected in calls getting permission status.
  //
  // TODO(crbug.com/758603): Move this check to the browser process when the
  // NotificationService connection becomes frame-bound.
  if (status == mojom::blink::PermissionStatus::ASK) {
    auto* window = DynamicTo<LocalDOMWindow>(context);
    LocalFrame* frame = window ? window->GetFrame() : nullptr;
    if (!frame || frame->IsCrossOriginToOutermostMainFrame())
      status = mojom::blink::PermissionStatus::DENIED;
  }

  return V8NotificationPermission(PermissionToV8Enum(status));
}

ScriptPromise<V8NotificationPermission> Notification::requestPermission(
''')],
    "0051": [(271, r'''void Permissions::TaskComplete(
    ScriptPromiseResolver<PermissionStatus>* resolver,
    mojom::blink::PermissionDescriptorPtr descriptor,
    mojom::blink::PermissionStatusWithDetailsPtr result) {
  if (!resolver->GetExecutionContext() ||
      resolver->GetExecutionContext()->IsContextDestroyed())
    return;

  PermissionStatusListener* listener = GetOrCreatePermissionStatusListener(
      std::move(result), std::move(descriptor));
  if (listener)
    resolver->Resolve(PermissionStatus::Take(listener, resolver));
}

void Permissions::VerifyPermissionAndReturnStatus(
''')],
    "0053": [(116, r'''  // https://webaudio.github.io/web-audio-api/#BaseAudioContext
  // Cannot be called from the audio thread.
  AudioDestinationNode* destination() const;
  float sampleRate() const { return destination_handler_->SampleRate(); }
  double currentTime() const { return destination_handler_->CurrentTime(); }
  AudioListener* listener() { return listener_.Get(); }
  // Virtual so AudioContext::state() can add UseCounters.
''')],
}


CPP_SUPPORT = r'''
#include <algorithm>
#include <bit>
#include <cassert>
#include <climits>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <limits>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>
#define DCHECK(x) assert(x)
#define DCHECK_EQ(a, b) assert((a) == (b))
#define DCHECK_GT(a, b) assert((a) > (b))
#define NOTREACHED() std::abort()
bool IsMainThread() { return true; }
namespace base {
template<class T> struct span : std::span<T> {
  using std::span<T>::span;
  span(std::span<T> value) : std::span<T>(value) {}
  span<T> first(size_t count) const { return std::span<T>::first(count); }
  span<T> subspan(size_t start, size_t count) const {
    return std::span<T>::subspan(start, count);
  }
  template<class U> void copy_from(span<U> other) const {
    assert(this->size() == other.size());
    std::copy(other.begin(), other.end(), this->begin());
  }
};
}
template<class T> struct Array {
  std::vector<T> values;
  explicit Array(size_t size) : values(size) {}
  Array(size_t size, T value) : values(size, value) {}
  size_t length() const { return values.size(); }
  base::span<T> AsSpan() { return {values.data(), values.size()}; }
};
using DOMFloat32Array = Array<float>;
using DOMUint8Array = Array<unsigned char>;
template<class T> struct NotShared {
  T* value;
  explicit NotShared(T* input) : value(input) {}
  T* operator->() const { return value; }
  explicit operator bool() const { return value != nullptr; }
};
template<class T> struct Member {
  std::shared_ptr<T> value;
  T* Get() const { return value.get(); }
};
struct String {
  std::string value;
  String(std::string input) : value(std::move(input)) {}
  operator std::string() const { return value; }
  static std::string FromUtf8(const std::string& value) { return value; }
  template<class T> static std::string Number(T value) { return std::to_string(value); }
};
std::string StrCat(std::initializer_list<std::string> parts) {
  std::string result;
  for (const auto& part : parts) result += part;
  return result;
}
enum class DOMExceptionCode { kIndexSizeError };
struct ExceptionState {
  bool threw = false;
  void ThrowDOMException(DOMExceptionCode code, const std::string&) {
    assert(code == DOMExceptionCode::kIndexSizeError);
    threw = true;
  }
};
namespace ExceptionMessages {
constexpr int kInclusiveBound = 0;
template<class... T> std::string IndexOutsideRange(T...) { return "range"; }
}
struct AudioBuffer {
  std::vector<Member<DOMFloat32Array>> channels_;
  AudioBuffer(size_t channels, size_t frames) {
    for (size_t i = 0; i < channels; ++i)
      channels_.push_back({std::make_shared<DOMFloat32Array>(frames)});
  }
  NotShared<DOMFloat32Array> getChannelData(unsigned, ExceptionState&);
  NotShared<DOMFloat32Array> getChannelData(unsigned);
  void copyFromChannel(NotShared<DOMFloat32Array>, int32_t, ExceptionState&);
  void copyFromChannel(NotShared<DOMFloat32Array>, int32_t, size_t, ExceptionState&);
  void copyToChannel(NotShared<DOMFloat32Array>, int32_t, ExceptionState&);
  void copyToChannel(NotShared<DOMFloat32Array>, int32_t, size_t, ExceptionState&);
  void Zero();
};
namespace audio_utilities {
double LinearToDecibels(double value) { return 20 * std::log10(value); }
}
template<class T> T ClampTo(T value, int low, int high) {
  return std::clamp(value, static_cast<T>(low), static_cast<T>(high));
}
constexpr unsigned kInputBufferSize = 64;
struct RealtimeAnalyser {
  std::vector<float> input_buffer_ = std::vector<float>(kInputBufferSize, 0);
  std::vector<float> magnitude_buffer_ = std::vector<float>(8, 0);
  unsigned fft_size = 16;
  unsigned write_index = 0;
  double last_analysis_time_ = 0;
  double max_decibels_ = -30;
  double min_decibels_ = -100;
  int fft_calls = 0;
  unsigned FftSize() const { return fft_size; }
  unsigned GetWriteIndex() const { return write_index; }
  void DoFFTAnalysis() { ++fft_calls; }
  void GetFloatFrequencyData(DOMFloat32Array*, double);
  void GetByteFrequencyData(DOMUint8Array*, double);
  void GetFloatTimeDomainData(DOMFloat32Array*);
  void GetByteTimeDomainData(DOMUint8Array*);
};
namespace mojom::blink {
enum class MediaDeviceType { kMediaAudioInput, kMediaVideoInput, kMediaAudioOutput, kNumMediaDeviceTypes };
enum class PermissionStatus { GRANTED, DENIED, ASK };
enum class PermissionName { NOTIFICATIONS, AUDIO_CAPTURE, VIDEO_CAPTURE };
struct PermissionDescriptor { PermissionName name; };
struct PermissionStatusWithDetails { PermissionStatus status; int detail; };
using PermissionDescriptorPtr = std::unique_ptr<PermissionDescriptor>;
using PermissionStatusWithDetailsPtr = std::unique_ptr<PermissionStatusWithDetails>;
}
using DeviceType = mojom::blink::MediaDeviceType;
using Status = mojom::blink::PermissionStatus;
struct WebMediaDeviceInfo { std::string device_id, label, group_id; };
struct MediaDeviceInfo {
  std::string device_id, label, group_id;
  DeviceType type;
  MediaDeviceInfo(std::string id, std::string name, std::string group, DeviceType kind)
      : device_id(id), label(name), group_id(group), type(kind) {}
  virtual ~MediaDeviceInfo() = default;
};
struct InputDeviceInfo : MediaDeviceInfo {
  using MediaDeviceInfo::MediaDeviceInfo;
  int video_capability = 0;
  int audio_capability = 0;
  int video_set_calls = 0;
  int audio_set_calls = 0;
  void SetVideoInputCapabilities(int value) {
    assert(type == DeviceType::kMediaVideoInput);
    video_capability = value;
    ++video_set_calls;
  }
  void SetAudioInputCapabilities(int value) {
    assert(type == DeviceType::kMediaAudioInput);
    audio_capability = value;
    ++audio_set_calls;
  }
};
template<class T, class... Args> T* MakeGarbageCollected(Args&&... args) {
  return new T(std::forward<Args>(args)...);
}
using wtf_size_t = size_t;
using MediaDeviceInfoVector = std::vector<MediaDeviceInfo*>;
struct Tracker {
  MediaDeviceInfoVector result;
  void Resolve(const MediaDeviceInfoVector& value) { result = value; }
};
struct Tracer { void End() {} };
bool reported_ids = false;
void ReportCompletedEnumerateDevices(bool value) { reported_ids = value; }
struct ExecutionContext {
  bool destroyed = false;
  bool secure = true;
  Status browser_status = Status::ASK;
  virtual ~ExecutionContext() = default;
  bool IsContextDestroyed() const { return destroyed; }
  bool IsSecureContext() const { return secure; }
};
struct Document {
  bool prerender = false;
  bool IsPrerendering() const { return prerender; }
};
struct LocalFrame {
  bool cross_origin = false;
  bool IsCrossOriginToOutermostMainFrame() const { return cross_origin; }
};
struct LocalDOMWindow : ExecutionContext {
  Document doc;
  LocalFrame frame;
  Document* document() { return &doc; }
  LocalFrame* GetFrame() { return &frame; }
};
template<class T> T* DynamicTo(ExecutionContext* context) { return dynamic_cast<T*>(context); }
struct PermissionStatusListener {
  mojom::blink::PermissionName name = mojom::blink::PermissionName::NOTIFICATIONS;
  Status status = Status::ASK;
  int detail = 0;
  int updates = 0;
};
template<class T> struct ScriptPromiseResolver {
  ExecutionContext* context;
  bool resolved = false;
  Status status = Status::ASK;
  PermissionStatusListener* listener = nullptr;
  ExecutionContext* GetExecutionContext() { return context; }
  void Resolve(PermissionStatusListener* value) {
    assert(value);
    listener = value;
    status = value->status;
    resolved = true;
  }
};
struct PermissionStatus {
  static PermissionStatusListener* Take(PermissionStatusListener* listener, ScriptPromiseResolver<PermissionStatus>*) {
    return listener;
  }
};
struct Permissions {
  std::map<mojom::blink::PermissionName, PermissionStatusListener> listeners;
  bool no_listener = false;
  PermissionStatusListener* GetOrCreatePermissionStatusListener(
      mojom::blink::PermissionStatusWithDetailsPtr result,
      mojom::blink::PermissionDescriptorPtr descriptor) {
    assert(result && descriptor);
    const auto name = descriptor->name;
    assert(name == mojom::blink::PermissionName::NOTIFICATIONS ||
           name == mojom::blink::PermissionName::AUDIO_CAPTURE ||
           name == mojom::blink::PermissionName::VIDEO_CAPTURE);
    if (no_listener) return nullptr;
    auto& listener = listeners[name];
    listener.name = name;
    listener.status = result->status;
    listener.detail = result->detail;
    ++listener.updates;
    return &listener;
  }
  void TaskComplete(ScriptPromiseResolver<PermissionStatus>*,
                    mojom::blink::PermissionDescriptorPtr,
                    mojom::blink::PermissionStatusWithDetailsPtr);
};
struct V8NotificationPermission {
  enum class Enum { kGranted, kDenied, kDefault };
  Enum value;
  explicit V8NotificationPermission(Enum input) : value(input) {}
};
struct NotificationManager {
  Status status;
  static NotificationManager* From(ExecutionContext* context) {
    static NotificationManager manager;
    manager.status = context->browser_status;
    return &manager;
  }
  Status GetPermissionStatus() const { return status; }
};
struct Notification {
  static V8NotificationPermission::Enum PermissionToV8Enum(Status);
  static V8NotificationPermission permission(ExecutionContext*);
};
struct Destination {
  float rate;
  double time;
  float SampleRate() const { return rate; }
  double CurrentTime() const { return time; }
};
'''


CPP_TESTS = r'''
int main(int argc, char** argv) {
  assert(argc == 2);
  const std::string test = argv[1];
  if (test == "media") {
    std::vector<std::vector<WebMediaDeviceInfo>> devices(3);
    assert(Enumerate(devices).empty());
    assert(!reported_ids);
    devices[0].push_back({"", "", ""});
    auto hidden = Enumerate(devices);
    assert(hidden.size() == 1 && hidden[0]->type == DeviceType::kMediaAudioInput);
    assert(dynamic_cast<InputDeviceInfo*>(hidden[0]));
    assert(hidden[0]->device_id.empty() && hidden[0]->label.empty() && hidden[0]->group_id.empty());
    assert(!reported_ids);
    delete hidden[0];
    devices = {{{"default", "Default mic", "origin-a-group"}, {"salted-a", "Mic", "origin-a-group"}},
               {{"salted-camera", "Camera", "origin-a-camera"}},
               {{"default", "Default speaker", "origin-a-group"}}};
    auto exposed = Enumerate(devices);
    assert(exposed.size() == 4 && reported_ids);
    size_t index = 0;
    for (size_t kind = 0; kind < devices.size(); ++kind) {
      for (const auto& device : devices[kind]) {
        auto* actual = exposed[index++];
        assert(actual->device_id == device.device_id && actual->label == device.label);
        assert(actual->group_id == device.group_id && actual->type == static_cast<DeviceType>(kind));
        assert((dynamic_cast<InputDeviceInfo*>(actual) != nullptr) == (kind != 2));
        delete actual;
      }
    }
  } else if (test == "media-capabilities") {
    const std::vector<std::vector<WebMediaDeviceInfo>> devices = {
        {{"mic-a", "Mic A", "group-a"}, {"mic-b", "Mic B", "group-b"}},
        {{"cam-a", "Camera A", "group-c"}, {"cam-b", "Camera B", "group-d"}},
        {{"speaker", "Speaker", "group-e"}}};
    for (bool audio : {false, true}) {
      for (bool video : {false, true}) {
        const std::vector<int> audio_caps = audio ? std::vector<int>{101, 202} : std::vector<int>{};
        const std::vector<int> video_caps = video ? std::vector<int>{303, 404} : std::vector<int>{};
        auto exposed = Enumerate(devices, audio_caps, video_caps);
        assert(exposed.size() == 5 && reported_ids);
        size_t index = 0;
        for (size_t kind = 0; kind < devices.size(); ++kind) {
          for (size_t j = 0; j < devices[kind].size(); ++j) {
            auto* actual = exposed[index++];
            const auto& expected = devices[kind][j];
            assert(actual->device_id == expected.device_id && actual->label == expected.label);
            assert(actual->group_id == expected.group_id && actual->type == static_cast<DeviceType>(kind));
            auto* input = dynamic_cast<InputDeviceInfo*>(actual);
            assert((input != nullptr) == (kind != 2));
            if (input) {
              assert(input->audio_set_calls == (kind == 0 && audio ? 1 : 0));
              assert(input->video_set_calls == (kind == 1 && video ? 1 : 0));
              assert(input->audio_capability == (kind == 0 && audio ? audio_caps[j] : 0));
              assert(input->video_capability == (kind == 1 && video ? video_caps[j] : 0));
            }
            delete actual;
          }
        }
      }
    }
  } else if (test == "permissions") {
    Permissions permissions;
    LocalDOMWindow context;
    for (auto name : {mojom::blink::PermissionName::NOTIFICATIONS,
                      mojom::blink::PermissionName::AUDIO_CAPTURE,
                      mojom::blink::PermissionName::VIDEO_CAPTURE}) {
      for (Status status : {Status::ASK, Status::GRANTED, Status::DENIED}) {
        ScriptPromiseResolver<PermissionStatus> resolver{&context};
        auto descriptor = std::make_unique<mojom::blink::PermissionDescriptor>();
        descriptor->name = name;
        auto result = std::make_unique<mojom::blink::PermissionStatusWithDetails>();
        result->status = status;
        result->detail = 42;
        permissions.TaskComplete(&resolver, std::move(descriptor), std::move(result));
        assert(resolver.resolved && resolver.status == status);
        assert(resolver.listener == &permissions.listeners.at(name));
        assert(resolver.listener->name == name && resolver.listener->detail == 42);
        context.browser_status = status;
        assert(Notification::permission(&context).value == Notification::PermissionToV8Enum(status));
      }
    }
    ScriptPromiseResolver<PermissionStatus> missing{nullptr};
    permissions.TaskComplete(&missing, nullptr, nullptr);
    assert(!missing.resolved);
    context.destroyed = true;
    ScriptPromiseResolver<PermissionStatus> destroyed{&context};
    permissions.TaskComplete(&destroyed, nullptr, nullptr);
    assert(!destroyed.resolved);
    context.destroyed = false;
    permissions.no_listener = true;
    auto descriptor = std::make_unique<mojom::blink::PermissionDescriptor>();
    descriptor->name = mojom::blink::PermissionName::NOTIFICATIONS;
    auto result = std::make_unique<mojom::blink::PermissionStatusWithDetails>();
    result->status = Status::ASK;
    result->detail = 99;
    permissions.TaskComplete(&destroyed, std::move(descriptor), std::move(result));
    assert(!destroyed.resolved);
  } else if (test == "permissions-isolation") {
    using Name = mojom::blink::PermissionName;
    Permissions permissions;
    LocalDOMWindow context;
    std::map<Name, PermissionStatusListener> expected;
    std::map<Name, PermissionStatusListener*> identities;
    std::vector<ScriptPromiseResolver<PermissionStatus>> resolved;
    auto complete = [&](Name name, Status status, int detail) {
      ScriptPromiseResolver<PermissionStatus> resolver{&context};
      auto descriptor = std::make_unique<mojom::blink::PermissionDescriptor>();
      descriptor->name = name;
      auto result = std::make_unique<mojom::blink::PermissionStatusWithDetails>();
      result->status = status;
      result->detail = detail;
      permissions.TaskComplete(&resolver, std::move(descriptor), std::move(result));
      assert(resolver.resolved && resolver.status == status && resolver.listener);
      assert(resolver.listener->name == name && resolver.listener->detail == detail);
      auto [identity, inserted] = identities.emplace(name, resolver.listener);
      assert(identity->second == resolver.listener);
      if (inserted) {
        for (const auto& [other_name, other] : identities)
          assert(other_name == name || other != resolver.listener);
      }
      auto& value = expected[name];
      value.name = name;
      value.status = status;
      value.detail = detail;
      ++value.updates;
      resolved.push_back(resolver);
      assert(permissions.listeners.size() == expected.size());
      for (const auto& [key, wanted] : expected) {
        const auto& actual = permissions.listeners.at(key);
        assert(&actual == identities.at(key) && actual.name == key);
        assert(actual.status == wanted.status && actual.detail == wanted.detail);
        assert(actual.updates == wanted.updates);
      }
      for (const auto& previous : resolved) {
        const auto& wanted = expected.at(previous.listener->name);
        assert(previous.listener->status == wanted.status);
        assert(previous.listener->detail == wanted.detail);
      }
    };
    complete(Name::VIDEO_CAPTURE, Status::DENIED, 301);
    complete(Name::NOTIFICATIONS, Status::ASK, 101);
    complete(Name::AUDIO_CAPTURE, Status::GRANTED, 201);
    complete(Name::VIDEO_CAPTURE, Status::GRANTED, 302);
    complete(Name::AUDIO_CAPTURE, Status::DENIED, 202);
    complete(Name::NOTIFICATIONS, Status::GRANTED, 102);
    complete(Name::AUDIO_CAPTURE, Status::DENIED, 203);
    complete(Name::VIDEO_CAPTURE, Status::ASK, 303);
    complete(Name::NOTIFICATIONS, Status::DENIED, 103);
  } else if (test == "notification-contexts") {
    using Permission = V8NotificationPermission::Enum;
    LocalDOMWindow context;
    context.secure = false;
    context.browser_status = Status::GRANTED;
    assert(Notification::permission(&context).value == Permission::kDenied);
    context.secure = true;
    context.doc.prerender = true;
    assert(Notification::permission(&context).value == Permission::kDefault);
    context.doc.prerender = false;
    context.frame.cross_origin = true;
    context.browser_status = Status::ASK;
    assert(Notification::permission(&context).value == Permission::kDenied);
    context.browser_status = Status::GRANTED;
    assert(Notification::permission(&context).value == Permission::kGranted);
    ExecutionContext worker;
    assert(Notification::permission(&worker).value == Permission::kDenied);
    worker.browser_status = Status::GRANTED;
    assert(Notification::permission(&worker).value == Permission::kGranted);
  } else if (test == "buffer-silence") {
    AudioBuffer buffer(2, 64);
    ExceptionState exception;
    auto graph = buffer.getChannelData(0);
    auto js = buffer.getChannelData(0, exception);
    assert(graph.value == js.value && !exception.threw);
    DOMFloat32Array copied(64, 3);
    buffer.copyFromChannel(NotShared(&copied), 1, exception);
    for (float sample : copied.values) assert(sample == 0);
    for (float sample : graph->values) assert(sample == 0);
    assert(buffer.getChannelData(0, exception).value == js.value);
  } else if (test == "buffer-writes") {
    AudioBuffer buffer(2, 64);
    DOMFloat32Array input(64);
    for (size_t i = 0; i < input.length(); ++i) input.values[i] = (int(i) - 32) / 64.0f;
    ExceptionState exception;
    buffer.copyToChannel(NotShared(&input), 0, exception);
    auto graph = buffer.getChannelData(0);
    auto js = buffer.getChannelData(0, exception);
    assert(js->values == input.values && graph.value == js.value);
    js->values[7] = 0.25f;
    DOMFloat32Array copied(5, 9);
    buffer.copyFromChannel(NotShared(&copied), 0, 7, exception);
    assert(copied.values[0] == 0.25f && graph->values[7] == 0.25f);
    buffer.copyToChannel(NotShared(&input), 0, exception);
    buffer.copyFromChannel(NotShared(&copied), 0, 7, exception);
    assert(copied.values[0] == input.values[7]);
    buffer.Zero();
    for (float sample : js->values) assert(sample == 0);
    assert(!exception.threw);
  } else if (test == "buffer-boundaries") {
    AudioBuffer buffer(1, 8);
    ExceptionState exception;
    DOMFloat32Array source(4, 0.5f), target(4, 9), empty(0);
    buffer.copyToChannel(NotShared(&source), 0, 7, exception);
    buffer.copyFromChannel(NotShared(&target), 0, 7, exception);
    assert(target.values == std::vector<float>({0.5f, 9, 9, 9}));
    auto before = buffer.getChannelData(0)->values;
    buffer.copyFromChannel(NotShared(&target), 0, 100, exception);
    buffer.copyToChannel(NotShared(&source), 0, 100, exception);
    assert(buffer.getChannelData(0)->values == before && !exception.threw);
    buffer.copyFromChannel(NotShared(&target), -1, exception);
    assert(exception.threw);
    exception.threw = false;
    assert(!buffer.getChannelData(9, exception) && exception.threw);
    assert(!buffer.getChannelData(9));
    exception.threw = false;
    buffer.copyToChannel(NotShared(&source), 1, exception);
    assert(exception.threw);
    exception.threw = false;
    buffer.copyFromChannel(NotShared(&empty), -1, exception);
    buffer.copyToChannel(NotShared(&empty), -1, exception);
    assert(!exception.threw);
    buffer.getChannelData(0)->values.clear();
    buffer.copyFromChannel(NotShared(&target), 0, exception);
    buffer.copyToChannel(NotShared(&source), 0, exception);
    assert(!exception.threw);
  } else if (test == "buffer-special-values") {
    AudioBuffer buffer(1, 5);
    DOMFloat32Array source(5), copied(5);
    source.values = {-0.0f, std::numeric_limits<float>::denorm_min(),
                     std::numeric_limits<float>::infinity(),
                     -std::numeric_limits<float>::infinity(), std::bit_cast<float>(0x7fc12345u)};
    ExceptionState exception;
    buffer.copyToChannel(NotShared(&source), 0, exception);
    auto js = buffer.getChannelData(0, exception);
    buffer.copyFromChannel(NotShared(&copied), 0, exception);
    for (size_t i = 0; i < source.length(); ++i) {
      assert(std::bit_cast<uint32_t>(source.values[i]) == std::bit_cast<uint32_t>(js->values[i]));
      assert(std::bit_cast<uint32_t>(source.values[i]) == std::bit_cast<uint32_t>(copied.values[i]));
    }
  } else if (test == "analyser-silence") {
    RealtimeAnalyser analyser;
    DOMFloat32Array time(20, 9), frequency(12, 9);
    DOMUint8Array bytes(20, 42), bins(12, 42);
    analyser.GetFloatTimeDomainData(&time);
    analyser.GetByteTimeDomainData(&bytes);
    analyser.GetFloatFrequencyData(&frequency, 1);
    analyser.GetByteFrequencyData(&bins, 1);
    assert(analyser.fft_calls == 1);
    for (size_t i = 0; i < 16; ++i) assert(time.values[i] == 0 && bytes.values[i] == 128);
    for (size_t i = 0; i < 8; ++i) {
      assert(frequency.values[i] == -std::numeric_limits<float>::infinity());
      assert(bins.values[i] == 0);
    }
    assert(time.values[16] == 9 && bytes.values[16] == 42);
    assert(frequency.values[8] == 9 && bins.values[8] == 42);
  } else if (test == "analyser-projections") {
    RealtimeAnalyser analyser;
    analyser.write_index = 5;
    const std::vector<float> samples = {-2, -1, -0.5f, -0.0078125f, 0, 0.0078125f, 0.5f, 1, 2};
    for (size_t i = 0; i < analyser.fft_size; ++i)
      analyser.input_buffer_[(i + analyser.write_index - analyser.fft_size + kInputBufferSize) % kInputBufferSize] = samples[i % samples.size()];
    auto original = analyser.input_buffer_;
    DOMFloat32Array time(16), frequency(8);
    DOMUint8Array bytes(16), bins(8);
    analyser.GetByteTimeDomainData(&bytes);
    analyser.GetFloatTimeDomainData(&time);
    for (size_t i = 0; i < 16; ++i) {
      assert(time.values[i] == samples[i % samples.size()]);
      assert(bytes.values[i] == static_cast<unsigned char>(std::clamp(128.0 * (time.values[i] + 1), 0.0, 255.0)));
    }
    assert(analyser.input_buffer_ == original);
    analyser.magnitude_buffer_ = {0, 1e-6f, 1e-5f, 0.0001f, 0.001f, 0.01f, 0.1f, 1};
    analyser.GetByteFrequencyData(&bins, 1);
    analyser.GetFloatFrequencyData(&frequency, 1);
    auto repeated = frequency.values;
    analyser.GetFloatFrequencyData(&frequency, 1);
    assert(repeated == frequency.values && analyser.fft_calls == 1);
    for (size_t i = 0; i < 8; ++i) {
      double db = 20 * std::log10(static_cast<double>(analyser.magnitude_buffer_[i]));
      assert(frequency.values[i] == static_cast<float>(db));
      assert(bins.values[i] == static_cast<unsigned char>(std::clamp(255 * (db + 100) / 70, 0.0, 255.0)));
    }
    DOMFloat32Array empty(0);
    DOMUint8Array empty_bytes(0);
    analyser.GetFloatTimeDomainData(&empty);
    analyser.GetByteTimeDomainData(&empty_bytes);
    analyser.GetFloatFrequencyData(&empty, 1);
    analyser.GetByteFrequencyData(&empty_bytes, 1);
  } else if (test == "sample-rate") {
    for (float rate : {8000.0f, 44100.0f, 48000.0f, 96000.0f}) {
      Destination destination{rate, 0.5};
      BaseAudioContext context{&destination};
      assert(context.sampleRate() == rate);
      assert(context.currentTime() == destination.CurrentTime());
      assert(rate / context.sampleRate() == 1);
    }
  } else {
    return 2;
  }
}
'''
