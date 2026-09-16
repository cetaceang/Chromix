# Windows renderer crashes and issue #3

## Resource Timing recursion

[Issue #3](https://github.com/xiaozhou26/Chromix/issues/3) reports renderer stack
overflow after reloading `https://www.s7.ru/ru/` in the Windows x64
`152.0.7977.82` release. The reported `0xC00000FD` exception comes from an
externally captured dump. The tab's `Crashpad_NotConnectedToHandler` code is a
separate failure to collect that crash, not its original exception code.

Two source-level recursion paths matter:

- The `v152.0.7977.82` tag's patch `0045` passes `fetchStart()` and
  `requestStart()` as arguments to `ComputePersonaNetPhases()`. C++ evaluates
  those arguments before entering the helper, so its configuration check and
  re-entry guard cannot prevent recursion through `requestStart()`'s fallbacks.
  This can happen without `--uxr-net-timing` or the static-router feature. The
  existing source fix in commit `17ce724` replaces these eager getter arguments
  with the entry and its raw timing data, and checks prerequisites first.
- Chromium's static-router cache path can independently form this cycle when
  timing details are allowed and all usable phase timestamps are absent:
  `fetchStart → responseStart → requestStart → connectEnd → connectStart →
  domainLookupEnd → domainLookupStart → fetchStart`. Patch `0045` now detects
  this state before calling `responseStart()` and returns
  `PerformanceEntry::startTime()`. It handles both a missing connection record
  and an allocated empty record, including connection reuse. Entries with a
  usable timestamp retain the native fallback chain. Hidden timing details
  still return zero in the cache branch; redirect and worker-ready precedence
  remain unchanged. No feature flag is required for this guard.

Returning the entry's start follows the ordinary `fetchStart()` fallback and
keeps the empty chain consistent, rather than introducing a global recursion
counter or changing the underlying timing record.

The standalone C++ regression harness reproduced a process crash before the
cache-cycle guard. With the guard it checks 49,536 cache/fallback combinations
per build, both with and without optimization, plus 2,048 combinations covering
missing connection records, TLS-only records and independent security/precision
settings, and the existing network-phase cases. The tests also verify repeated
reads, getter ordering, privacy gates, negative/clamped timestamps, and unchanged
input data. Patch application and
reversal were checked against the official `152.0.7977.82` and `153.0.8010.36`
source files and the available pre-Chromix platform baselines.

These are source and standalone-harness results, not a Windows browser build or
a verified reproduction of the live site's exact trigger. The two reported
DLL offsets have not been symbolicated. Existing release ZIPs are unchanged;
a matching rebuilt browser is required to use the fixes.

## Crashpad behavior in the Windows package

The release inherits ungoogled's
[`disable-crash-reporter.patch`](https://github.com/ungoogled-software/ungoogled-chromium/blob/e71b91c6e336d0f25cfc6b9ef09298a9d2506e24/patches/core/ungoogled-chromium/disable-crash-reporter.patch).
It returns `false` from `InitializeCrashpadImpl()` on non-Linux platforms,
including Windows. The 153 core commit `dd8fb9b5c837982faf41ba58cd30a5664e77c329`
retains this behavior as well. This prevents
normal Crashpad initialization and automatic dump collection. The patch also
disables crash uploads; this timing fix does not change either setting.

| Setting or file | Windows package expectation |
|---|---|
| `--enable-crash-reporter` | Cannot override the compiled initialization return. |
| `--enable-crash-reporter-for-testing` | A POSIX switch in Chromium 152, not a Windows enablement option. |
| `--crash-dumps-dir=…` | Not the dump-directory switch consumed by the Windows Chrome client; it does not enable this package's handler. |
| `BREAKPAD_DUMP_LOCATION` | Upstream Windows client's Crashpad database directory override, effective only if initialization is enabled in a different build. |
| `--user-data-dir=…` | Selects the browser profile, but does not enable crash collection. Normally enabled upstream Windows builds use its `Crashpad` subdirectory. |
| `chrome_crashpad_handler.exe` | Optionally copied by the packager when present. Windows Chrome normally uses the embedded `chrome.exe --type=crashpad-handler`; copying a separate executable does not undo the initialization patch. |

`-36861` / `0xFFFF7003` is Crashpad's
`kTerminationCodeNotConnectedToHandler`. An external debugger is needed to
capture the original exception in this configuration. Browser logs and Windows
Error Reporting are not substitutes for that exception record.

## Capture the original exception

Use the x64 Windows SDK debugger for the reported x64 package. Start a fresh
profile with the minimal arguments from the issue, select the relevant renderer
PID, and attach before reloading. For example, in PowerShell:

```powershell
New-Item -ItemType Directory -Force C:\chromix-diagnostics | Out-Null
$rendererPid = 12345 # Replace with the target renderer PID.
cdb.exe -p $rendererPid -logo C:\chromix-diagnostics\renderer.txt -c 'sxe c00000fd; g'
```

At the **first-chance stack-overflow exception** breakpoint, record the exception,
stack, and module, then save the dump and detach:

```text
.exr -1
.ecxr
k
lmvm chrome
.dump /ma C:\chromix-diagnostics\renderer.dmp
qd
```

Confirm `lmvm chrome` refers to `chrome.dll`. Renderer replacement or process
swaps require attaching to the new target PID. A second-chance-only breakpoint
may miss the original exception because Chromium's own handler terminates the
process first. Full-memory dumps can contain page data and credentials; share
them privately after checking their contents.

Record the package version, launcher arguments, renderer PID, reload number,
exception code, module base and relative virtual addresses (RVAs). Include both
binary hashes:

```powershell
Get-FileHash .\chrome.exe, .\chrome.dll -Algorithm SHA256
```

## Symbolicating the reported RVAs

The published ZIP contains no PDB symbol files. The current workspace has no
matching `chrome.dll.pdb`, so the function names at `0x0E051850` and
`0x0E0511E0` remain unverified. Source inspection alone does not name those
binary addresses.

Look for `src\out\Chromix\chrome.dll.pdb` in the **original Windows build's**
outputs or retained build snapshots. Although the release uses zero symbol
levels, Chromium's Windows linker can still produce a function-name PDB.
Match its GUID and age to the DLL's CodeView record; an official Chrome PDB or
a new build with the same version number is not a substitute.

With the matching DLL, dump and PDB loaded in WinDbg/CDB:

```text
.sympath+ C:\chromix-symbols
.reload /f chrome.dll
lmvm chrome
ln chrome+0x0E051850
ln chrome+0x0E0511E0
uf chrome+0x0E051850
```

Use the module name shown by the debugger and the current module base, not the
ASLR base from another process. Check symbol matching and function boundaries;
a nearest-symbol result alone is not confirmation. A symbol-rich rebuild can
help diagnose a new crash but cannot symbolicate the old DLL's offsets.

## Native release verification still required

On a rebuilt Windows package, repeat the issue's protocol: ten fresh profiles,
wait for the first load to finish, then allow up to three reloads with at least
30 seconds of observation after each. Monitor browser-level CDP
`Target.targetCrashed` events and record the exact executable hashes. Test
`s7.ru/ru/` and the `easyjet.com/en/` control, with no fingerprint flags, then
with network timing enabled. Keep the proxy configuration identical between
comparisons. Record service-worker control and resource timing state rather
than assuming a successful navigation exercised the failing path.
