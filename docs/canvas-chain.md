# Canvas Chain Audit

## Shared Native GPU Policy (2026-09-14)

Patches `0158`–`0164` add `--uxr-gpu-backend=native`: one immutable UXR
policy now gates Canvas readback/export/text noise, Canvas Bridge, WebGL persona
capabilities and WebGPU feature negotiation. It overrides conflicting synthetic
flags without forcing GPU-off or a particular adapter. The current 216-patch
stack makes native the ordinary default. Explicit compatibility, or synthetic
tests without a policy, keep the earlier behavior below. This is a shared **native contract**, not a
common cross-platform privacy rasterizer.

`0165` additionally repairs lazy opaque Canvas readback: no snapshot must still
produce opaque-black pixels inside the canvas. It shares the existing upload
RGBA/BGRA8/F16/F32 alpha encoding, clips with 64-bit arithmetic and leaves OOB,
stride padding and lost-context behavior intact. The helper is tested with
dependency shims, not yet a matching new Chromium build.

The new GPU audit/complete collector still reject stock Chrome 153. The former
reports opaque HTML Canvas resize failures; the latter also retains the existing
lossless/alpha/OOB failures. No qualified device record has been produced, no
GPU-off workaround is admitted, and existing Canvas thresholds are unchanged.
See [GPU backend and real-device matrix evidence](gpu-backend.md).

## Default Policy

Patches 0020 and 0031 retain native Canvas readback and export pixels by default:
legacy seed/persona noise requires `--uxr-synthetic-device-tests=true`.
Patch 0069 also requires that flag before parsing an endpoint or constructing a
Canvas Bridge client. Existing bridge and unsafe opt-ins are still required.
This disables incomplete remote substitutions across text, readback and export
in ordinary launches; it does not complete the bridge's color/codec protocol.

Synthetic tests are not measured-device emulation. Their old 8-bit noise and
bridge paths do not implement a common F16/ImageBitmap/GPU rendering backend.
The older fingerprint smoke runner explicitly opts its non-native scenarios
into synthetic mode to retain the meaning of its seed-effect tests. Its native
control and this audit do not enable the synthetic flag.

The 2026-09-13 `0031` correction skips private copying and extra alpha
normalization whenever 8-bit synthetic noise does not apply, including F16,
disabled/invalid seeds and ordinary public mode. Borrowed pixmaps retain their
native alpha type. The upstream image constructor's own required readback and
unpremultiplication are unchanged; failed native conversions still fail.

## Native Upload And Readback Repair (2026-09-14)

The source series now includes `0149` and `0150`. They repair native pixel
contracts independently of persona/seed settings; no synthetic flag is needed.

### Cause and implementation

- **Opaque uploads:** upstream `PutByteArray` changes the image's alpha metadata
  to `kOpaque` without replacing the actual ImageData alpha bytes. CPU/GPU/export
  paths can subsequently disagree about premultiplication. `0149` privately
  copies only the clipped dirty rectangle, preserves RGB/color-space bits, and
  physically sets alpha to 255, half-float 1, or float 1 for RGBA/BGRA8, F16 and
  F32. The script-owned input is unchanged. Source/destination coordinates are
  rebased before existing format conversion; allocation failure remains a
  RangeError and alpha-enabled uploads retain the native path.
- **GPU readback geometry:** upstream `MailboxTextureBacking::readPixels`
  substitutes `dst_info.minRowBytes()` for the supplied stride and forwards
  negative/OOB origins to RasterInterface. `0150` validates buffer geometry and
  byte-size limits, intersects source bounds using 64-bit arithmetic, offsets a
  destination pixmap subset, and passes the original stride to RasterInterface.
  Nonintersecting requests make no GPU call; untouched padding stays unchanged
  (Canvas zero-initializes it). Native success/failure and pixel metadata remain.

These are correctness repairs, not a new cross-platform rasterizer, encoder,
GPU capability simulator, or per-profile pixel generator.

### Independent minimal control

The reusable diagnostic uses plain Playwright, no Chromix SDK/persona arguments,
and fresh canvases for each OOB history/options case. It records raw pixels and
the explicit executable/probe hashes. It covers RGBA8 HTML/Offscreen canvases
with omitted/false/true `willReadFrequently`; it is not the complete audit below.

```powershell
python -X utf8 tools/canvas_native_diagnostic.py --browser "C:/Program Files/Google/Chrome/Application/chrome.exe" --compare-software --output control-native.json
python -X utf8 tools/canvas_native_diagnostic.py --browser C:/matching-chromix/chrome.exe --compare-software --output patched-native.json
python -X utf8 tools/canvas_chain_audit.py --browser C:/matching-chromix/chrome.exe --output patched-chain.json
```

Output paths must be new. The diagnostic exits nonzero on missing/malformed
observations or a mismatch. `--compare-software` makes a separate diagnostic
launch with `--disable-gpu`; it does not change either acceptance oracle.

The 2026-09-14 stock Chrome **153.0.8010.37** run remains **failed**:
`tmp_build/canvas-control-followup/native-diagnostic-stock-01.json` contains
44 default-path failed checks (20 OOB) and 24 software-requested failed checks
(0 OOB). The opaque-upload failures persist when GPU is disabled. These are
check counts, not unique defects. Earlier independent controls also reproduced
the issues on installed Chromium 138, 149 and 151. No stock binary was modified.

### Source and test evidence

- Upstream `chromium-152.0.7977.82-lite.tar.xz` SHA-256:
  `67ac37f365dfdac763c428862e5e460e5948940b3d6f856374da2ce219981417`.
- Core revision `e71b91c6e336d0f25cfc6b9ef09298a9d2506e24`, Windows revision
  `333bc7dfff72ff4abc4d9cc76bc41de300a46e06`. All 108 needed archive files were
  independently extracted; a further input is created by the core patch layer.
  Both core Canvas predecessors, then `0020`, `0076`, `0146`, are included.
- All **150** patches apply to the prepared affected-file tree with `--fuzz=0`.
  Existing predecessor offsets are retained in the log; new `0149`/`0150`
  apply and reverse with **zero offsets and zero fuzz**. The whole current
  stack also passes the read-only reverse/forward verifier. Reports are under
  `tmp_build/canvas-control-followup/sparse-win-final/`. This is affected-file
  patch evidence, not a full source preparation or Chromium compilation.
- Native-method contracts: **47 passed**, including independent upstream hash
  and preimage checks. Full extracted `putImageData`, `PutByteArray`, and
  `MailboxTextureBacking::readPixels` plus the added helper run under ASan/UBSan.
  Dependency shims model storage, geometry, allocation and GPU calls, not real
  Skia color management or GPU drivers. Baseline code demonstrates both defects.
- The diagnostic oracle has **24 passing** synthetic-fixture tests. Related
  Canvas/UA/render/patch-application suites total **312 passed, 37 skipped** on
  the integrated source; skipped cases are not passes or device evidence.
- Concurrent `main` fixes are preserved: `6d4ae3b` repairs `0005`'s asymmetric
  interior hunk and `0146`'s missing bridge predecessor context; `7b98822` adds
  explicit creation metadata to `0103`–`0106` for Git source-freshness checks.

Run the new contracts with LLVM/ASan/UBSan available:

```powershell
python -X utf8 -m pytest tools/tests/test_canvas_native_paths.py tools/tests/test_native_patch_context_repairs.py tools/tests/test_canvas_native_diagnostic.py -q
```

Optional `CHROMIX_CANVAS_UPSTREAM_ROOT` and `CHROMIX_NATIVE_PATCH_PREIMAGES`
enable independently acquired source/provenance checks. Without them those
checks skip, rather than use a patched reference tree as clean upstream.

**Matching Chromium 152 browser integration remains pending.** The stock
control still fails, no admission thresholds were relaxed, and no qualified
measured-device record was created. See the pinned
[CloakBrowser functionality comparison](cloakbrowser-functionality-comparison.md)
for implemented interfaces, deliberate differences and remaining gaps.

## Run

Requires Python, Playwright and Pillow with WebP and LittleCMS support. No
browser is downloaded. Use an explicit executable and a new output filename:

```powershell
python -X utf8 tools/canvas_chain_audit.py --browser C:/path/to/chrome.exe --output .chromix-local-build/device-pool-canvas/report.json
```

Two loopback servers provide a same-origin probe and a non-CORS image for taint
tests. The runner reuses the device collector's five-context launch harness:
window, iframe, dedicated worker, shared worker and service worker. It launches
profile A twice and fresh profile B once. Temporary profiles and servers are
closed even on failure. It uses `NATIVE_ARGS` from `_device_launch.py`, not an OS
network sandbox. Browser/probe hashes, browser and decoder versions, launch
arguments, raw pixels, encoded images and per-comparison metrics are recorded.

Canonical source now ships as `sdk/python/chromix/canvas_chain_probe.js`; the
independent oracle is `chromix._canvas_chain`. The standalone runner uses these
same implementations instead of maintaining another probe copy. Its source
hash is that standalone asset; the measured-device probe hashes all five
concatenated assets, as described in [device-pool.md](device-pool.md).

Exit 0 requires all tested paths to pass without unavailable optional cases.
Missing optional P3/F16 support produces `incomplete` and a nonzero exit; a
mismatch produces `failed`. Exceptions and incomplete matrices never pass.

## Coverage

- HTML Canvas in window/iframe and OffscreenCanvas in all five contexts.
- sRGB/Display-P3 and alpha true/false, actual context attributes, deterministic
  RGBA input, same-space and sRGB readback, crops, transparent out-of-bounds
  regions, zero-size reads and source stability after export.
- Independent fresh/full-read/crop-read OOB cases with omitted versus explicit
  colorSpace options. These preserve options/history-specific failures.
- Canvas-to-ImageBitmap, premultiplyAlpha none/premultiply/default, a separate
  colorSpaceConversion none case, bitmap close, Offscreen transfer and reset.
- F16 readback type/metadata, bounded values and actual F16 ImageData input.
- PNG/JPEG/WebP blob export at quality 0.92, repeated exports, HTML data URL/blob
  agreement, browser bitmap decoding and independent Pillow/ICC decoding.
- Unsupported MIME fallback, empty HTML callbacks/data URLs, Offscreen empty
  rejection and cross-origin read/export SecurityError behavior.
- Same-kind cross-context pixel/codec comparisons and full raw-observation
  signatures across restarts/profiles. Independent decoder annotations do not
  mutate those observations.

Comparisons use visible premultiplied RGB rather than undefined RGB at alpha
zero. Lossless maximum/mean differences are 2/0.6 in 8-bit units; lossy bounds
are 36/7. Alpha error is at most 1. JPEG expectations composite onto black.
Lossy bounds are engineering quality thresholds, not Web-platform conformance
limits: chroma subsampling can fail them without a fingerprint patch defect.
PNG independent color-managed comparison uses the lossless bounds; decoder
rounding differences remain reported instead of being silently accepted.

Schema-v2 measured admission embeds this oracle in probe v4 across all five
scopes. It keeps individual lossless/alpha/OOB contracts, records lossy quality
failures as diagnostics and permits different native backends between contexts.
Embedded taint is explicitly `not_collected`; the standalone runner still
requires taint, cross-context comparison and its stricter optional-case result.
Neither mode creates profile-distinct pixels or labels a fixture as hardware.

## Evidence And Limits

The 2026-09-10 local run uses installed Chrome 153.0.8010.37, not a verified
Chromix executable built from the target Chromium 152 patch series. Reports in
`.chromix-local-build/device-pool-canvas/` are local, ignored artifacts. Earlier
failed runs are retained. The audit is **not passing**: alpha:false read/export
differences, options/history-dependent Offscreen OOB results and cross-run
differences require investigation on a matching build. Error totals include
multiple checks of the same underlying mismatch, not unique defects.

Final local artifact: `audit-final.json`, 3 launches, 28 main rows per launch,
42 fresh/history edge cases per launch, 828 failed checks in total, no skipped
capabilities. Per-launch errors: 276/275/276, plus one restart/profile signature
mismatch. Independent decoders: Pillow 12.2.0, LittleCMS 2.18, WebP 1.6.0.
Same-kind cross-context comparisons pass in this final run; earlier failed
artifacts also include intermediate validator behavior and are not final results.

Final targeted regression: 395 passed, 29 skipped across the new audit,
Canvas C++/extended tests, smoke/surface validators and WebGL correctness tests.
The new audit module alone has 48 passing tests. The 124-patch linter, JS syntax
and `git diff --check` pass. Compiled Canvas harnesses use LLVM 22 with ASan/UBSan;
skips include absent local Chromium source prerequisites and a Linux-only Node
path. A broader run including CI-stage tests has one separate reproducible
failure: the Rust missing-bundle test invokes `python3` on this Windows host and
receives no expected diagnostic. That test was not changed or counted as passing.

The newer stock Chrome 153 control (`tmp_build/render-v3/control-02/`,
2026-09-13) passes the added rich-scene/GPU matrix and CDP font-face collection,
but still fails shared-chain alpha:false/OOB/history checks: 258 failed checks
and 18 lossy quality diagnostics per launch. All three launches are retained;
no qualified pool record is produced. This is not a patched Chromium 152 test.
Current offline counts are recorded in `FINGERPRINT_STATUS.md`; the counts above
describe the earlier standalone run only.

Passing offline tests only validate the oracle, malformed-evidence rejection
and extracted C++ contracts. Their generated codec fixtures are not physical
device samples. The affected-file 150-patch preparation and reverse/forward
checks above now pass. A full native Chromium build and matching runtime audit
have not completed for these latest Canvas changes.

The packaged integration companion now exercises bitmaprenderer, transferred
OffscreenCanvas ownership, concurrent call-time exports and context
loss/restoration. The scene companion adds GPU/bitmap roundtrips with explicit
orientation. These bounded probes do not complete ImageBitmap crop/resize/flip
coverage, wide-gamut/HDR F16, software-versus-hardware validation, encoder quality
boundaries or a shared backend-level privacy policy. All still require acceptance
on matching builds; native fallback does not provide profile-distinct pixels.
