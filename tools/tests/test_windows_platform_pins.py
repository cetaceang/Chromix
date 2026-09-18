"""Windows overrides reach PowerShell callers, cache identities, and ready markers."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from tools import platform_pins as pins
from tools import restore_upstream_cache as restore

REPO = Path(__file__).resolve().parents[2]
WINDOWS = "153.0.8010.47"
SHARED = "153.0.8010.36"
MACOS = "152.0.7977.82"
CALLERS = ("ci-stage.ps1", "prepare-ungoogled.ps1", "build.ps1")
PWSH = shutil.which("pwsh") or shutil.which("powershell")


def save(repo, values):
    (repo / "build/ungoogled-revisions.psd1").write_text(
        "@{\n" + "".join(f'  {key} = "{value}"\n' for key, value in values.items()) + "}\n")


@pytest.fixture
def repository(tmp_path):
    repo = tmp_path / "repo with spaces"
    (repo / "build/windows").mkdir(parents=True)
    (repo / "tools").mkdir()
    values = {
        "ChromiumVersion": SHARED, "UngoogledVersion": SHARED + "-1", "UngoogledCommit": "a" * 40,
        "UngoogledLinuxVersion": SHARED + "-1", "UngoogledLinuxCommit": "b" * 40,
        "WindowsChromiumVersion": WINDOWS, "WindowsUngoogledVersion": WINDOWS + "-1",
        "WindowsUngoogledCommit": "c" * 40, "UngoogledWindowsVersion": WINDOWS + "-1.1",
        "UngoogledWindowsCommit": "d" * 40,
        "MacOSChromiumVersion": MACOS, "MacOSUngoogledVersion": MACOS + "-1",
        "MacOSUngoogledCommit": "e" * 40, "UngoogledMacOSVersion": MACOS + "-1.1",
        "UngoogledMacOSCommit": "f" * 40,
    }
    for name, version in (("CHROMIUM_VERSION", SHARED), ("CHROMIUM_WINDOWS_VERSION", WINDOWS),
                          ("CHROMIUM_MACOS_VERSION", MACOS)):
        (repo / name).write_text(version + "\n")
    save(repo, values)
    shutil.copyfile(REPO / "tools/platform_pins.py", repo / "tools/platform_pins.py")
    for name in (*CALLERS, "read-platform-pins.ps1"):
        shutil.copyfile(REPO / "build/windows" / name, repo / "build/windows" / name)
    return repo


def run_ps(repo, code, **environment):
    if not PWSH:
        pytest.skip("PowerShell is unavailable")
    return subprocess.run(
        [PWSH, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
         '$ErrorActionPreference = "Stop"\n$ErrorView = "NormalView"\n' + code],
        env={**os.environ, "TEST_REPO": str(repo), "TEST_PYTHON": sys.executable,
             "TEST_WORK": str(repo.parent / "work"), "CHROMIX_TARGET_ARCH": "x64",
             "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", ""),
             **environment}, capture_output=True, text=True, timeout=30)


HELPER_CALL = r'''
$result = & (Join-Path $env:TEST_REPO 'build/windows/read-platform-pins.ps1') -Repo $env:TEST_REPO
if ($result -isnot [hashtable]) { throw 'helper did not return one hashtable' }
$result | ConvertTo-Json -Compress
'''


@pytest.mark.parametrize("platform,version", [("windows", WINDOWS), ("linux", SHARED), ("macos", MACOS)])
def test_scoped_override_and_json_cli_leave_other_platforms_unchanged(repository, platform, version):
    before = {path: path.read_bytes() for path in repository.rglob("*") if path.is_file()}
    result = subprocess.run([sys.executable, str(repository / "tools/platform_pins.py"),
                             "--repo", str(repository), "--platform", platform, "--json"],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == pins.load_pins(repository, platform)
    assert json.loads(result.stdout)["ChromiumVersion"] == version
    assert pins.load_shared_pins(repository)["ChromiumVersion"] == SHARED
    assert {path: path.read_bytes() for path in before} == before


def test_powershell_helper_returns_resolved_windows_pins(repository):
    result = run_ps(repository, HELPER_CALL)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == pins.load_pins(repository, "windows")
    assert json.loads(result.stdout)["ChromiumVersion"] == WINDOWS


def test_legacy_windows_without_overrides_remains_supported(repository):
    values = pins.load_shared_pins(repository)
    for key in pins.WINDOWS_OVERRIDES:
        values.pop(key)
    values["UngoogledWindowsVersion"] = SHARED + "-1.1"
    save(repository, values)
    (repository / pins.WINDOWS_VERSION_FILE).unlink()
    result = run_ps(repository, HELPER_CALL)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["ChromiumVersion"] == SHARED


def invalidate(repo, problem):
    values = pins.load_shared_pins(repo)
    if problem in pins.WINDOWS_OVERRIDES:
        values.pop(problem)
        save(repo, values)
    elif problem == "missing-file":
        (repo / pins.WINDOWS_VERSION_FILE).unlink()
    elif problem == "file-only":
        for key in pins.WINDOWS_OVERRIDES:
            values.pop(key)
        save(repo, values)
    elif problem == "duplicate":
        path = repo / "build/ungoogled-revisions.psd1"
        path.write_text(path.read_text().replace("}\n", f'  WindowsUngoogledCommit = "{"c" * 40}"\n}}\n'))
    elif problem == "mismatch":
        (repo / pins.WINDOWS_VERSION_FILE).write_text(SHARED + "\n")
    else:
        field, value = {
            "core": ("WindowsUngoogledVersion", SHARED + "-1"),
            "overlay": ("UngoogledWindowsVersion", WINDOWS + "-2.1"),
            "commit": ("WindowsUngoogledCommit", "invalid"),
        }[problem]
        values[field] = value
        save(repo, values)


@pytest.mark.parametrize("caller", CALLERS)
@pytest.mark.parametrize("problem", [*pins.WINDOWS_OVERRIDES, "missing-file", "file-only",
                                     "duplicate", "mismatch", "core", "overlay", "commit"])
def test_invalid_pins_stop_real_callers_before_fetch_or_preparation(repository, caller, problem):
    invalidate(repository, problem)
    before = {path: path.read_bytes() for path in repository.rglob("*") if path.is_file()}
    result = run_ps(repository, r'''
function git { throw 'UNEXPECTED FETCH' }
function curl.exe { throw 'UNEXPECTED FETCH' }
$script = Join-Path $env:TEST_REPO ('build/windows/' + $env:CALLER)
if ($env:CALLER -eq 'prepare-ungoogled.ps1') {
  & $script -Repo $env:TEST_REPO -Root $env:TEST_WORK
} elseif ($env:CALLER -eq 'build.ps1') {
  & $script -WorkDir $env:TEST_WORK
} else {
  & $script -UseUpstreamCache -ValidateOnly
}
Write-Output 'CONTINUED'
''', CALLER=caller)
    assert result.returncode != 0
    assert "platform pin" in result.stderr.lower(), result.stderr
    assert "UNEXPECTED FETCH" not in result.stderr
    assert "CONTINUED" not in result.stdout
    assert not (repository.parent / "work").exists()
    assert {path: path.read_bytes() for path in before} == before
    assert pins.load_pins(repository, "linux")["ChromiumVersion"] == SHARED
    assert pins.load_pins(repository, "macos")["ChromiumVersion"] == MACOS


@pytest.mark.parametrize("payload,exit_code", [
    ("", 0), ("not-json", 0), ("null", 0), ("[]", 0), ('[{"ChromiumVersion":"153.0.8010.47"}]', 0),
    ("{}", 0), ('{"ChromiumVersion":153}', 0), ('{"ChromiumVersion":"153.0.8010.47"}', 0),
    ('{"ChromiumVersion":', 0), ("{}\n{}", 0), ("valid", 7),
    ("bad-version", 0), ("bad-overlay", 0), ("bad-commit", 0), ("bad-type", 0),
])
def test_helper_rejects_failed_or_malformed_resolver_output(repository, payload, exit_code):
    values = pins.load_pins(repository, "windows")
    if payload in ("valid", "bad-version", "bad-overlay", "bad-commit", "bad-type"):
        if payload == "bad-version":
            values["ChromiumVersion"] = "153"
        elif payload == "bad-overlay":
            values["UngoogledWindowsVersion"] = WINDOWS + "-2.1"
        elif payload == "bad-commit":
            values["UngoogledCommit"] = "A" * 40
        elif payload == "bad-type":
            values["UngoogledCommit"] = ["c" * 40]
        payload = json.dumps(values)
    (repository / "tools/platform_pins.py").write_text(
        f"import sys\nprint({payload!r})\nraise SystemExit({exit_code})\n")
    result = run_ps(repository, HELPER_CALL)
    assert result.returncode != 0, result.stdout
    assert not result.stdout.strip()


def test_helper_missing_python_and_missing_resolver_fail_closed(repository):
    missing_python = run_ps(repository, "function Get-Command {}\n" + HELPER_CALL)
    assert missing_python.returncode != 0
    assert "Python 3 is required" in missing_python.stderr
    (repository / "tools/platform_pins.py").unlink()
    missing_resolver = run_ps(repository, HELPER_CALL)
    assert missing_resolver.returncode != 0
    assert not missing_resolver.stdout.strip()


@pytest.mark.parametrize("caller", CALLERS)
def test_callers_resolve_before_side_effects_and_helper_uses_ps51_syntax(caller):
    source = (REPO / "build/windows" / caller).read_text()
    invocation = '$Revisions = & "$PSScriptRoot\\read-platform-pins.ps1" -Repo $Repo'
    assert invocation in source
    assert "Import-PowerShellDataFile" not in source
    assert source.index(invocation) < source.index('"$PSScriptRoot\\assert-target-arch.ps1"')
    helper = (REPO / "build/windows/read-platform-pins.ps1").read_text()
    assert "#requires -Version 5.1" in helper
    assert "--platform windows --json" in helper
    for unsupported in ("-AsHashtable", "??", "&&", "||"):
        assert unsupported not in helper


def synthetic_manifest(repo):
    sources = {}
    for platform, (suffix, commit, roots) in restore.fetcher.SOURCES.items():
        values = pins.load_pins(repo, platform)
        sources[platform] = {
            "chromium_version": values["ChromiumVersion"], "ungoogled_commit": values["UngoogledCommit"],
            "repository": "ungoogled-software/ungoogled-chromium-" + suffix, "repository_id": 1,
            "head_sha": values[commit], "head_branch": values[commit.replace("Commit", "Version")],
            "event": "push", "workflow_path": ".github/workflows/build-x64.yml" if platform == "windows"
            else ".github/workflows/build.yml", "source_roots": roots, "available": False,
        }
    sources["windows"].pop("available")
    sources["windows"].update(run_id=101, artifacts={"x64": {
        "id": 102, "name": "synthetic-windows-donor", "size_in_bytes": 100,
        "digest": "sha256:" + "1" * 64, "expires_at": "2099-01-01T00:00:00Z", "inner_archive": "artifacts.zip",
    }})
    shared = pins.load_shared_pins(repo)
    (repo / "build/upstream-cache.json").write_text(json.dumps({
        "schema_version": 1, "chromium_version": SHARED, "ungoogled_commit": shared["UngoogledCommit"],
        "sources": sources,
    }))


@pytest.mark.parametrize("stale", [False, True])
def test_ready_source_markers_and_cache_identity_use_same_windows_override(repository, stale):
    synthetic_manifest(repository)
    values = pins.load_pins(repository, "windows")
    identity, donor, manifest = restore.identities(repository, "windows", "x64")
    assert identity["chromium_version"] == donor["chromium_version"] == manifest["chromium_version"] == WINDOWS
    assert identity["ungoogled_commit"] == values["UngoogledCommit"]
    assert identity["head_sha"] == values["UngoogledWindowsCommit"]
    (repository / "patches").mkdir()
    (repository / "patches/series").write_text("")
    src = repository.parent / "work/src"
    src.mkdir(parents=True)
    patch_key = hashlib.sha256(b"").hexdigest()
    version = SHARED if stale else WINDOWS
    ready = "|".join((version, values["UngoogledCommit"], values["UngoogledWindowsCommit"], patch_key))
    markers = {
        ".chromix-source-ready": ready, ".chromix-source-unpacked": version,
        ".chromix-ungoogled-core": values["UngoogledCommit"],
        ".chromix-ungoogled-windows": values["UngoogledWindowsCommit"],
        ".chromix-binaries-pruned": values["UngoogledCommit"], ".chromix-patches": patch_key,
    }
    for name, value in markers.items():
        (src / name).write_text(value)
    before = {path: path.read_bytes() for path in src.iterdir()}
    result = run_ps(repository, r'''
function Get-Command {
  [CmdletBinding()]
  param([string[]]$Name, [string]$CommandType)
  if ($Name -contains 'python.exe') { return [pscustomobject]@{ Source = $env:TEST_PYTHON } }
  Microsoft.PowerShell.Core\Get-Command @PSBoundParameters
}
function git { throw 'UNEXPECTED FETCH' }
& (Join-Path $env:TEST_REPO 'build/windows/prepare-ungoogled.ps1') -Repo $env:TEST_REPO -Root $env:TEST_WORK
''')
    if stale:
        assert result.returncode != 0
        assert "prepared source key" in result.stderr
    else:
        assert result.returncode == 0, result.stderr
        assert "source layers already prepared and verified: " + ready in result.stdout
    assert "UNEXPECTED FETCH" not in result.stderr
    assert {path: path.read_bytes() for path in src.iterdir()} == before
