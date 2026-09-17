"""Resource timing regressions using pinned native getters and a standalone C++ harness."""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

REPO = Path(__file__).resolve().parents[2]
PATCH = REPO / "patches/0045-third_party-blink-renderer-core-timing-performance_resource_timing-cc.patch"
TARGET = Path("third_party/blink/renderer/core/timing/performance_resource_timing.cc")
BASELINES = REPO / ".chromix-build-verify/sparse-real110-81cwzua4/context-repair"
PATCH_BIN = shutil.which("gpatch") or shutil.which("patch")

# These sections are from the independent pre-Chromix Chromium 152 source.
SOURCE_SECTIONS = [
    (31, '''
#include "third_party/blink/renderer/core/timing/performance_resource_timing.h"

#include "base/containers/fixed_flat_set.h"
#include "base/notreached.h"
#include "services/network/public/mojom/service_worker_router_info.mojom-blink-forward.h"
#include "third_party/blink/public/common/features_generated.h"
#include "third_party/blink/public/mojom/fetch/fetch_api_request.mojom-blink.h"
'''),
    (88, '''  }
  return fetch_initiator_type_names::kOther;
}
}  // namespace

using network::mojom::blink::NavigationDeliveryType;
'''),
    (277, '''DOMHighResTimeStamp PerformanceResourceTiming::WorkerReady() const {
  if (!info_->timing || info_->timing->service_worker_ready_time.is_null()) {
    return 0.0;
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), info_->timing->service_worker_ready_time,
      info_->allow_negative_values, CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceResourceTiming::redirectStart() const {
  if (info_->last_redirect_end_time.is_null()) {
    return 0.0;
  }

  if (DOMHighResTimeStamp worker_ready_time = WorkerReady())
    return worker_ready_time;

  return PerformanceEntry::startTime();
}

DOMHighResTimeStamp PerformanceResourceTiming::redirectEnd() const {
  if (info_->last_redirect_end_time.is_null()) {
    return 0.0;
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), info_->last_redirect_end_time, info_->allow_negative_values,
      CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceResourceTiming::fetchStart() const {
  if (!info_->timing) {
    return PerformanceEntry::startTime();
  }

  if (!info_->last_redirect_end_time.is_null()) {
    return Performance::MonotonicTimeToDOMHighResTimeStamp(
        TimeOrigin(), info_->timing->request_start,
        info_->allow_negative_values, CrossOriginIsolatedCapability());
  }

  if (DOMHighResTimeStamp worker_ready_time = WorkerReady())
    return worker_ready_time;

  // If the fetch came from service worker static routing API and the actual
  // source type is cache, we will not have a fetch start. For compatibility,
  // we set this to responseStart (as written in explainer
  // https://github.com/WICG/service-worker-static-routing-api/blob/main/resource-timing-api.md
  // ).
  if (RuntimeEnabledFeatures::ServiceWorkerStaticRouterTimingInfoEnabled(
          DynamicTo<LocalDOMWindow>(source())) &&
      info_->service_worker_router_info &&
      info_->service_worker_router_info->actual_source_type ==
          network::mojom::ServiceWorkerRouterSourceType::kCache) {
    return responseStart();
  }

  return PerformanceEntry::startTime();
}

DOMHighResTimeStamp PerformanceResourceTiming::domainLookupStart() const {
  if (!info_->allow_timing_details) {
    return 0.0;
  }
  if (!info_->timing || !info_->timing->connect_timing ||
      info_->timing->connect_timing->domain_lookup_start.is_null()) {
    return fetchStart();
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), info_->timing->connect_timing->domain_lookup_start,
      info_->allow_negative_values, CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceResourceTiming::domainLookupEnd() const {
  if (!info_->allow_timing_details) {
    return 0.0;
  }
  if (!info_->timing || !info_->timing->connect_timing ||
      info_->timing->connect_timing->domain_lookup_end.is_null()) {
    return domainLookupStart();
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), info_->timing->connect_timing->domain_lookup_end,
      info_->allow_negative_values, CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceResourceTiming::connectStart() const {
  if (!info_->allow_timing_details) {
    return 0.0;
  }
  // connectStart will be zero when a network request is not made.
  if (!info_->timing || !info_->timing->connect_timing ||
      info_->timing->connect_timing->connect_start.is_null() ||
      info_->did_reuse_connection) {
    return domainLookupEnd();
  }

  // connectStart includes any DNS time, so we may need to trim that off.
  base::TimeTicks connect_start = info_->timing->connect_timing->connect_start;
  if (!info_->timing->connect_timing->domain_lookup_end.is_null()) {
    connect_start = info_->timing->connect_timing->domain_lookup_end;
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), connect_start, info_->allow_negative_values,
      CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceResourceTiming::connectEnd() const {
  if (!info_->allow_timing_details) {
    return 0.0;
  }
  // connectStart will be zero when a network request is not made.
  if (!info_->timing || !info_->timing->connect_timing ||
      info_->timing->connect_timing->connect_end.is_null() ||
      info_->did_reuse_connection) {
    return connectStart();
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), info_->timing->connect_timing->connect_end,
      info_->allow_negative_values, CrossOriginIsolatedCapability());
}

DOMHighResTimeStamp PerformanceResourceTiming::secureConnectionStart() const {
  if (!info_->allow_timing_details || !info_->is_secure_transport) {
    return 0.0;
  }

  // Step 2 of
  // https://w3c.github.io/resource-Timing()/#dom-performanceresourceTiming()-secureconnectionstart.
  if (info_->did_reuse_connection) {
    return fetchStart();
  }

  if (info_->timing && info_->timing->connect_timing &&
      !info_->timing->connect_timing->ssl_start.is_null()) {
    return Performance::MonotonicTimeToDOMHighResTimeStamp(
        TimeOrigin(), info_->timing->connect_timing->ssl_start,
        info_->allow_negative_values, CrossOriginIsolatedCapability());
  }
  // We would add a DCHECK(false) here but this case may happen, for instance on
  // SXG where the behavior has not yet been properly defined. See
  // https://github.com/w3c/navigation-timing/issues/107. Therefore, we return
  // fetchStart() for cases where SslStart() is not provided.
  return fetchStart();
}

DOMHighResTimeStamp PerformanceResourceTiming::requestStart() const {
  if (!info_->allow_timing_details) {
    return 0.0;
  }
  if (!info_->timing || info_->timing->send_start.is_null()) {
    return connectEnd();
  }

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), info_->timing->send_start, info_->allow_negative_values,
      CrossOriginIsolatedCapability());
}
'''),
    (476, '''DOMHighResTimeStamp PerformanceResourceTiming::responseStart() const {
  if (!info_->allow_timing_details) {
    return 0.0;
  }
  if (!info_->timing) {
    return requestStart();
  }

  base::TimeTicks response_start = info_->timing->receive_headers_start;
  if (response_start.is_null())
    response_start = info_->timing->receive_headers_end;
  if (response_start.is_null())
    return requestStart();

  return Performance::MonotonicTimeToDOMHighResTimeStamp(
      TimeOrigin(), response_start, info_->allow_negative_values,
      CrossOriginIsolatedCapability());
}
'''),
]


def native_fixture():
    lines = []
    for first, section in SOURCE_SECTIONS:
        assert len(lines) < first
        lines.extend("// unrelated native source\n" for _ in range(first - 1 - len(lines)))
        lines.extend(section.splitlines(keepends=True))
    lines.append("// trailing native source\n")
    return "".join(lines)


def apply_patch(root, *, reverse=False, dry_run=False):
    if PATCH_BIN is None:
        pytest.skip("GNU patch is required")
    command = [PATCH_BIN, "-p1", "--fuzz=0", "--batch", "--binary", "--get=0",
               "--no-backup-if-mismatch", "--reject-file=-", "--input", str(PATCH)]
    command.append("--reverse" if reverse else "--forward")
    if dry_run:
        command.append("--dry-run")
    return subprocess.run(command, cwd=root, env=dict(os.environ, LC_ALL="C", PATCH_GET="0"),
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)


def assert_strict(result):
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert not re.search(r"fuzz|offset|FAILED|Reversed", output, re.I), output


@pytest.fixture(scope="module")
def patched_source(tmp_path_factory):
    root = tmp_path_factory.mktemp("timing-patch")
    target = root / TARGET
    target.parent.mkdir(parents=True)
    target.write_text(native_fixture())
    assert_strict(apply_patch(root))
    return target.read_text()


def method(source, name):
    match = re.search(r"DOMHighResTimeStamp PerformanceResourceTiming::" + name + r"\(\) const \{", source)
    assert match, name
    start = match.start()
    pos = match.end()
    depth = 1
    while depth:
        depth += (source[pos] == "{") - (source[pos] == "}")
        pos += 1
    return source[start:pos]


def test_no_eager_recursive_getter_arguments():
    additions = "\n".join(line[1:] for line in PATCH.read_text().splitlines()
                          if line.startswith("+") and not line.startswith("+++"))
    assert "requestStart()" not in additions
    assert "ph_busy" not in additions
    calls = re.findall(r"const PersonaNetPhases ph = ComputePersonaNetPhases\((.*?)\);", additions, re.S)
    assert len(calls) == 3
    assert all(call.strip() == "*this, *info_, TimeOrigin(), CrossOriginIsolatedCapability()"
               for call in calls)
    helper = additions[additions.index("PersonaNetPhases ComputePersonaNetPhases("):
                       additions.index("const PersonaNetPhases ph =")]
    fetch = helper.index("entry.fetchStart()")
    for guard in ('!ph_cfg.Has("uxr-net-timing")', '!info.allow_timing_details',
                  'info.did_reuse_connection', '!info.timing',
                  'info.timing->send_start.is_null()', '!info.timing->connect_timing',
                  'connect.connect_start.is_null()', 'connect.connect_end.is_null()'):
        assert helper.index(guard) < fetch
    assert "conn_start <= conn_end" in helper
    assert "conn_end <= send_start" in helper
    assert not re.search(r"(?:info_|info)[.>\w-]*\s*=(?!=)", additions)


def test_native_network_getters_unchanged(patched_source):
    for name in ("WorkerReady", "connectStart", "connectEnd", "requestStart", "responseStart"):
        assert method(patched_source, name) == method(native_fixture(), name)


def test_fetch_start_only_guards_static_cache_cycle(patched_source):
    original = method(native_fixture(), "fetchStart")
    actual = method(patched_source, "fetchStart")
    prefix, suffix = original.split("    return responseStart();", 1)
    assert actual.startswith(prefix)
    assert actual.endswith("    return responseStart();" + suffix)
    guard = actual[len(prefix):actual.index("    return responseStart();")]
    assert "!info_->allow_timing_details" in guard
    assert "return PerformanceEntry::startTime();" in guard
    assert not re.search(r"\b(?:fetchStart|responseStart|requestStart)\(\);", guard)
    assert "uxr-net-timing" not in guard


def test_fixture_applies_and_reverses_exactly(tmp_path):
    target = tmp_path / TARGET
    target.parent.mkdir(parents=True)
    original = native_fixture()
    target.write_text(original)
    assert_strict(apply_patch(tmp_path, dry_run=True))
    assert_strict(apply_patch(tmp_path))
    assert_strict(apply_patch(tmp_path, reverse=True))
    assert target.read_text() == original


@pytest.mark.parametrize("context", [
    '#include "base/notreached.h"',
    '  return fetch_initiator_type_names::kOther;',
    '          network::mojom::ServiceWorkerRouterSourceType::kCache) {',
    '      info_->timing->connect_timing->domain_lookup_start.is_null()) {',
    '      info_->timing->connect_timing->domain_lookup_end.is_null()) {',
    '  // We would add a DCHECK(false) here but this case may happen, for instance on',
])
def test_incompatible_context_rejected(tmp_path, context):
    target = tmp_path / TARGET
    target.parent.mkdir(parents=True)
    original = native_fixture()
    assert original.count(context) == 1
    original = original.replace(context, "// incompatible native context")
    target.write_text(original)
    result = apply_patch(tmp_path, dry_run=True)
    assert result.returncode != 0
    assert "FAILED" in result.stdout
    assert target.read_text() == original


@pytest.mark.parametrize("platform", ["linux", "macos", "windows"])
def test_independent_real_baseline(tmp_path, platform):
    root = Path(os.environ.get("CHROMIX_TIMING_BASELINES", BASELINES))
    source = root / platform / "upstream" / TARGET
    if not source.is_file():
        pytest.skip("independent pre-Chromix source not supplied")
    original = source.read_bytes()
    before_stat = source.stat().st_mtime_ns
    lines = original.decode().splitlines(keepends=True)
    for first, section in SOURCE_SECTIONS:
        assert "".join(lines[first - 1:first - 1 + len(section.splitlines())]) == section
    target = tmp_path / TARGET
    target.parent.mkdir(parents=True)
    target.write_bytes(original)
    assert_strict(apply_patch(tmp_path, dry_run=True))
    assert_strict(apply_patch(tmp_path))
    assert_strict(apply_patch(tmp_path, reverse=True))
    assert target.read_bytes() == original
    assert source.read_bytes() == original
    assert source.stat().st_mtime_ns == before_stat


# Only Blink/base plumbing is stubbed; both sets of getter bodies are compiled verbatim.
CPP_SUPPORT = r'''
#include <algorithm>
#include <array>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
namespace base {
struct TimeTicks {
  double value = 0;
  bool is_null() const { return value == 0; }
  auto operator<=>(const TimeTicks&) const = default;
};
struct UxrConfig {
  bool enabled = false;
  std::string seed = "0";
  static UxrConfig& GetInstance() { static UxrConfig cfg; return cfg; }
  bool Has(const std::string& key) const {
    return key == "uxr-net-timing" ? enabled : key == "uxr-canvas-seed";
  }
  std::string Get(const std::string&) const { return seed; }
};
bool StringToUint(const std::string& text, uint32_t* value) {
  try {
    size_t end;
    auto parsed = std::stoull(text, &end);
    if (end != text.size() || parsed > UINT32_MAX) return false;
    *value = static_cast<uint32_t>(parsed);
    return true;
  } catch (...) { return false; }
}
}
struct String {
  std::string value = "https://example.test/resource";
  std::string Utf8() const { return value; }
};
using DOMHighResTimeStamp = double;
namespace network::mojom {
enum class ServiceWorkerRouterSourceType { kCache, kNetwork };
}
struct ConnectTiming {
  base::TimeTicks domain_lookup_start, domain_lookup_end;
  base::TimeTicks connect_start{1020}, connect_end{1040}, ssl_start, ssl_end;
  bool operator==(const ConnectTiming&) const = default;
};
struct LoadTiming {
  ConnectTiming* connect_timing = nullptr;
  base::TimeTicks send_start{1060}, request_start{1005}, service_worker_ready_time;
  base::TimeTicks receive_headers_start, receive_headers_end;
  bool operator==(const LoadTiming&) const = default;
};
struct RouterInfo {
  network::mojom::ServiceWorkerRouterSourceType actual_source_type =
      network::mojom::ServiceWorkerRouterSourceType::kCache;
};
namespace mojom::blink {
struct ResourceTimingInfo {
  LoadTiming* timing = nullptr;
  bool allow_timing_details = true, did_reuse_connection = false;
  bool is_secure_transport = true, allow_negative_values = false;
  base::TimeTicks last_redirect_end_time;
  RouterInfo* service_worker_router_info = nullptr;
  bool operator==(const ResourceTimingInfo&) const = default;
};
}
struct LocalDOMWindow {};
template <typename T> T* DynamicTo(void*) { return nullptr; }
struct RuntimeEnabledFeatures {
  static inline bool static_router_timing = true;
  static bool ServiceWorkerStaticRouterTimingInfoEnabled(LocalDOMWindow*) {
    return static_router_timing;
  }
};
struct Performance {
  static double MonotonicTimeToDOMHighResTimeStamp(base::TimeTicks origin,
      base::TimeTicks value, bool negative, bool isolated) {
    if (origin.is_null() || value.is_null()) return 0;
    const double quantum = isolated ? 0.005 : 0.1;
    double result = std::floor(value.value / quantum) * quantum -
                    std::floor(origin.value / quantum) * quantum;
    return negative ? result : std::max(0.0, result);
  }
};
struct PerformanceEntry {
  double start = 1.0;
  double startTime() const { return start; }
};
'''

CPP_CLASS = r'''
struct PerformanceResourceTiming : PerformanceEntry {
  mojom::blink::ResourceTimingInfo* info_;
  base::TimeTicks origin{1000};
  bool isolated = false;
  String resource;
  explicit PerformanceResourceTiming(mojom::blink::ResourceTimingInfo* info) : info_(info) {}
  base::TimeTicks TimeOrigin() const { return origin; }
  bool CrossOriginIsolatedCapability() const { return isolated; }
  const String& name() const { return resource; }
  void* source() const { return nullptr; }
  double WorkerReady() const;
  double fetchStart() const;
  double domainLookupStart() const;
  double domainLookupEnd() const;
  double connectStart() const;
  double connectEnd() const;
  double secureConnectionStart() const;
  double requestStart() const;
  double responseStart() const;
};
'''

CPP_MAIN = r'''
template <typename T> auto read(const T& entry) {
  return std::array<double, 8>{entry.fetchStart(), entry.domainLookupStart(),
      entry.domainLookupEnd(), entry.connectStart(), entry.secureConnectionStart(),
      entry.connectEnd(), entry.requestStart(), entry.responseStart()};
}
void test_cache_fallbacks() {
  auto& config = base::UxrConfig::GetInstance();
  size_t cases = 0, cycles = 0;
  for (bool enabled : {false, true}) {
    config.enabled = enabled;
    for (bool reused : {false, true}) {
      for (bool allowed : {false, true}) {
        for (int gate = 0; gate < 8; ++gate) {
          for (int mask = 0; mask < 129; ++mask) {
            for (int clock = 0; clock < 3; ++clock) {
              for (bool isolated : {false, true}) {
                RuntimeEnabledFeatures::static_router_timing = gate != 1;
                ConnectTiming connect;
                LoadTiming timing;
                RouterInfo router;
                mojom::blink::ResourceTimingInfo info;
                info.timing = gate == 4 ? nullptr : &timing;
                info.service_worker_router_info = gate == 2 ? nullptr : &router;
                if (gate == 3) {
                  router.actual_source_type = network::mojom::ServiceWorkerRouterSourceType::kNetwork;
                }
                info.allow_timing_details = allowed;
                info.did_reuse_connection = reused;
                info.allow_negative_values = clock == 2;
                info.is_secure_transport = isolated;
                // A null connection and an allocated all-null connection both occur.
                timing.connect_timing = mask == 0 ? nullptr : &connect;
                const double origin = clock == 0 ? 1000 : 930;
                const auto tick = [&](int bit, double offset) {
                  return base::TimeTicks{mask & (1 << bit) ? origin + offset : 0};
                };
                connect.domain_lookup_start = tick(0, 10);
                connect.domain_lookup_end = tick(1, 20);
                connect.connect_start = tick(2, 30);
                connect.connect_end = tick(3, 40);
                timing.send_start = tick(4, 50);
                timing.receive_headers_end = tick(5, 70);
                timing.receive_headers_start = tick(6, 60);
                if (gate == 5) info.last_redirect_end_time = {1004};
                if (gate == 6) timing.service_worker_ready_time = {1008};
                if (gate == 7) timing.service_worker_ready_time = {1000};
                native::PerformanceResourceTiming original(&info);
                persona::PerformanceResourceTiming actual(&info);
                original.isolated = actual.isolated = isolated;
                original.start = actual.start = clock == 2 ? -80 : 1;
                const auto convert = [&](base::TimeTicks value) {
                  return Performance::MonotonicTimeToDOMHighResTimeStamp(
                      actual.TimeOrigin(), value, info.allow_negative_values, isolated);
                };
                // Independent timestamp oracle: never call native getters for cyclic inputs.
                base::TimeTicks terminal;
                for (auto candidate : {timing.receive_headers_start, timing.receive_headers_end,
                                       timing.send_start, reused ? base::TimeTicks{} : connect.connect_end,
                                       reused ? base::TimeTicks{} : connect.connect_start,
                                       connect.domain_lookup_end, connect.domain_lookup_start}) {
                  if (!candidate.is_null()) { terminal = candidate; break; }
                }
                if (timing.receive_headers_start.is_null() && timing.receive_headers_end.is_null() &&
                    timing.send_start.is_null() && (reused || connect.connect_end.is_null()) &&
                    !reused && !connect.connect_start.is_null() && !connect.domain_lookup_end.is_null()) {
                  terminal = connect.domain_lookup_end;
                }
                const bool cache_branch = gate == 0 || gate == 7;
                const bool native_cycle = cache_branch && allowed && terminal.is_null();
                double expected_fetch = actual.start;
                if (gate == 5) expected_fetch = convert(timing.request_start);
                else if (gate == 6) expected_fetch = convert(timing.service_worker_ready_time);
                else if (cache_branch) {
                  if (!allowed) expected_fetch = 0;
                  else if (!terminal.is_null()) expected_fetch = convert(terminal);
                }
                const auto saved_info = info;
                const auto saved_timing = timing;
                const auto saved_connect = connect;
                const double response_first = actual.responseStart();
                const auto got = read(actual);
                assert(got[0] == expected_fetch);
                assert(got[7] == response_first);
                if (native_cycle) {
                  for (size_t index = 0; index < got.size(); ++index) {
                    assert(got[index] == (index == 4 && !info.is_secure_transport ? 0 : actual.start));
                  }
                  ++cycles;
                } else if (!enabled || cache_branch) {
                  assert(got == read(original));
                }
                for (double value : got) assert(std::isfinite(value));
                assert(actual.requestStart() == got[6]);
                assert(actual.connectEnd() == got[5]);
                assert(actual.secureConnectionStart() == got[4]);
                assert(actual.connectStart() == got[3]);
                assert(actual.domainLookupEnd() == got[2]);
                assert(actual.domainLookupStart() == got[1]);
                assert(actual.fetchStart() == got[0]);
                assert(read(actual) == got);
                assert(info == saved_info && timing == saved_timing && connect == saved_connect);
                ++cases;
              }
            }
          }
        }
      }
    }
  }
  assert(cycles > 0);
  std::cout << "cache-fallbacks: " << cases << " cases passed\n";
}
void test_cache_connection_edges() {
  auto& config = base::UxrConfig::GetInstance();
  RuntimeEnabledFeatures::static_router_timing = true;
  size_t cases = 0;
  for (int flags = 0; flags < 32; ++flags) {
    config.enabled = flags & 1;
    const bool reused = flags & 2, allowed = flags & 4;
    const bool isolated = flags & 8, secure = flags & 16;
    for (bool has_connect : {false, true}) {
      for (int phases = 0; phases < 8; ++phases) {
        for (int tls = 0; tls < 4; ++tls) {
          ConnectTiming connect;
          connect.connect_start = connect.connect_end = {};
          connect.ssl_start = {tls & 1 ? 1025.0 : 0};
          connect.ssl_end = {tls & 2 ? 1035.0 : 0};
          LoadTiming timing;
          timing.connect_timing = has_connect ? &connect : nullptr;
          timing.send_start = {phases & 1 ? 1050.0 : 0};
          timing.receive_headers_end = {phases & 2 ? 1070.0 : 0};
          timing.receive_headers_start = {phases & 4 ? 1060.0 : 0};
          RouterInfo router;
          mojom::blink::ResourceTimingInfo info;
          info.timing = &timing;
          info.service_worker_router_info = &router;
          info.allow_timing_details = allowed;
          info.did_reuse_connection = reused;
          info.is_secure_transport = secure;
          native::PerformanceResourceTiming original(&info);
          persona::PerformanceResourceTiming actual(&info);
          original.isolated = actual.isolated = isolated;
          const auto convert = [&](base::TimeTicks value) {
            return Performance::MonotonicTimeToDOMHighResTimeStamp(
                actual.TimeOrigin(), value, false, isolated);
          };
          const double fetch = !allowed ? 0 : phases & 4 ? convert(timing.receive_headers_start)
              : phases & 2 ? convert(timing.receive_headers_end)
              : phases & 1 ? convert(timing.send_start) : actual.start;
          const double ssl = !allowed || !secure ? 0
              : !reused && has_connect && (tls & 1) ? convert(connect.ssl_start) : fetch;
          const double request = !allowed ? 0 : phases & 1 ? convert(timing.send_start) : fetch;
          const std::array<double, 8> expected{fetch, fetch, fetch, fetch, ssl, fetch, request, fetch};
          const auto saved_info = info;
          const auto saved_timing = timing;
          const auto saved_connect = connect;
          assert(actual.secureConnectionStart() == ssl);
          assert(read(actual) == expected);
          if (!allowed || phases) assert(read(actual) == read(original));
          assert(read(actual) == expected);
          assert(info == saved_info && timing == saved_timing && connect == saved_connect);
          ++cases;
        }
      }
    }
  }
  std::cout << "cache-connection-edges: " << cases << " cases passed\n";
}
int main(int argc, char** argv) {
  assert(argc == 2);
  const std::string scenario = argv[1];
  if (scenario == "cache-connection-edges") {
    test_cache_connection_edges();
    return 0;
  }
  if (scenario == "cache-fallbacks") {
    test_cache_fallbacks();
    return 0;
  }
  auto& config = base::UxrConfig::GetInstance();
  size_t cases = 0;
  for (bool enabled : {false, true}) {
    config.enabled = enabled;
    for (int seed = 0; seed < 32; ++seed) {
      config.seed = std::to_string(seed);
      for (int variant = 0; variant < 16; ++variant) {
        ConnectTiming connect;
        LoadTiming timing;
        timing.connect_timing = &connect;
        mojom::blink::ResourceTimingInfo info;
        info.timing = &timing;
        RouterInfo router;
        native::PerformanceResourceTiming original(&info);
        persona::PerformanceResourceTiming actual(&info);
        original.isolated = actual.isolated = variant & 1;
        original.resource.value = actual.resource.value =
            "https://example.test/" + std::to_string(variant);
        bool unchanged = !enabled;
        if (scenario == "missing") {
          unchanged = true;
          switch (variant % 8) {
            case 0: info.timing = nullptr; break;
            case 1: timing.connect_timing = nullptr; break;
            case 2: timing.send_start = {}; break;
            case 3: connect.connect_start = {}; break;
            case 4: connect.connect_end = {}; break;
            case 5: timing.send_start = {}; connect.connect_start = {};
                    connect.connect_end = {}; break;
            case 6: connect.domain_lookup_start = {1005}; timing.send_start = {}; break;
            case 7: connect.domain_lookup_end = {1010}; timing.send_start = {}; break;
          }
        } else if (scenario == "gates") {
          unchanged = true;
          switch (variant % 4) {
            case 0: info.allow_timing_details = false; break;
            case 1: info.did_reuse_connection = true; break;
            case 2: info.did_reuse_connection = true;
                    connect.ssl_start = {1025}; break;
            case 3: info.allow_timing_details = false; info.timing = nullptr; break;
          }
        } else if (scenario == "partial-dns") {
          unchanged = true;
          if (variant & 2) connect.domain_lookup_start = {1005};
          else connect.domain_lookup_end = {1010};
        } else if (scenario == "native-phases") {
          unchanged = true;
          connect.domain_lookup_start = {1005};
          connect.domain_lookup_end = {1030};
          connect.ssl_start = {1035};
        } else if (scenario == "invalid-order") {
          unchanged = true;
          switch (variant % 4) {
            case 0: connect.connect_end = {1010}; break;
            case 1: timing.send_start = {1030}; break;
            case 2: original.start = actual.start = 50; break;
            case 3: connect.domain_lookup_start = {1028};
                    connect.domain_lookup_end = {1025}; break;
          }
        } else if (scenario == "fresh") {
          connect.connect_start = {1001 + variant * 0.25};
          connect.connect_end = {1001 + variant * 0.5};
          timing.send_start = {1001 + variant * 0.75};
        } else if (scenario == "dns-only") {
          info.is_secure_transport = false;
        } else if (scenario == "tls-only") {
          connect.domain_lookup_start = {1005};
          connect.domain_lookup_end = {1030};
          if (variant & 2) connect.ssl_end = {1032};
        } else if (scenario == "existing-tls") {
          connect.ssl_start = {1035};
        } else if (scenario == "redirect-worker") {
          switch (variant % 4) {
            case 0: info.last_redirect_end_time = {1004}; break;
            case 1: timing.service_worker_ready_time = {1008}; break;
            case 2: info.service_worker_router_info = &router;
                    timing.receive_headers_start = {1080}; unchanged = true; break;
            case 3: info.service_worker_router_info = &router; unchanged = true; break;
          }
        } else if (scenario == "negative") {
          info.allow_negative_values = variant & 2;
          original.start = actual.start = info.allow_negative_values ? -40 : 0;
          connect.connect_start = {980}; connect.connect_end = {990};
          timing.send_start = {995};
        } else {
          assert(false);
        }
        const auto saved_info = info;
        const auto saved_timing = timing;
        const auto saved_connect = connect;
        const auto expected = read(original);
        const auto got = read(actual);
        if (unchanged) assert(got == expected);
        assert(got[0] == expected[0]);
        assert(got[3] == expected[3]);
        assert(got[5] == expected[5]);
        assert(got[6] == expected[6]);
        if (!unchanged) {
          assert(got[0] <= got[1] && got[1] <= got[2]);
          assert(got[2] <= got[3] && got[3] <= got[5] && got[5] <= got[6]);
          if (info.is_secure_transport && got[4] != expected[4]) {
            assert(got[3] <= got[4] && got[4] <= got[5]);
            if (!connect.ssl_end.is_null()) {
              assert(got[4] <= Performance::MonotonicTimeToDOMHighResTimeStamp(
                  actual.TimeOrigin(), connect.ssl_end, info.allow_negative_values, actual.isolated));
            }
          }
          if (!info.is_secure_transport) assert(got[4] == 0);
          if (!connect.ssl_start.is_null()) assert(got[4] == expected[4]);
          if (scenario == "dns-only") assert(got[2] > got[0]);
          if (scenario == "tls-only") assert(got[4] > got[3]);
        }
        // Getter order and repeated reads must not affect the entry or network data.
        assert(actual.requestStart() == got[6]);
        assert(actual.secureConnectionStart() == got[4]);
        assert(actual.connectEnd() == got[5]);
        assert(actual.domainLookupEnd() == got[2]);
        assert(read(actual) == got);
        assert(info == saved_info && timing == saved_timing && connect == saved_connect);
        ++cases;
      }
    }
  }
  std::cout << scenario << ": " << cases << " cases passed\n";
}
'''


@pytest.fixture(scope="module", params=["-O0", "-O2"], ids=["debug", "optimized"])
def timing_executable(tmp_path_factory, patched_source, request):
    compiler = shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")
    if compiler is None:
        pytest.skip("a C++20 compiler is required for the standalone timing harness")
    names = ("WorkerReady", "fetchStart", "domainLookupStart", "domainLookupEnd",
             "connectStart", "connectEnd", "secureConnectionStart", "requestStart", "responseStart")
    helper_start = patched_source.index("struct PersonaNetPhases")
    helper_end = patched_source.index("}  // namespace", helper_start)
    helper = patched_source[helper_start:helper_end]
    source = CPP_SUPPORT
    for namespace, text in (("native", native_fixture()), ("persona", patched_source)):
        source += "\nnamespace " + namespace + " {\n" + CPP_CLASS
        if namespace == "persona":
            source += helper
        source += "\n".join(method(text, name) for name in names) + "\n}\n"
    source += CPP_MAIN
    root = tmp_path_factory.mktemp("timing-cpp")
    cpp, exe = root / "timing.cc", root / "timing"
    cpp.write_text(source)
    result = subprocess.run([compiler, "-std=c++20", request.param, "-Wall", "-Wextra", "-Werror",
                             str(cpp), "-o", str(exe)], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    return exe


@pytest.mark.parametrize("scenario", [
    "missing", "gates", "partial-dns", "native-phases", "invalid-order", "fresh",
    "dns-only", "tls-only", "existing-tls", "redirect-worker", "negative",
])
def test_standalone_native_and_persona_behavior(timing_executable, scenario):
    result = subprocess.run([str(timing_executable), scenario], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == f"{scenario}: 1024 cases passed\n"


@pytest.mark.parametrize("scenario,cases", [
    ("cache-fallbacks", 49536), ("cache-connection-edges", 2048),
])
def test_static_router_cache_fallbacks(timing_executable, scenario, cases):
    result = subprocess.run([str(timing_executable), scenario], capture_output=True,
                            text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == f"{scenario}: {cases} cases passed\n"
