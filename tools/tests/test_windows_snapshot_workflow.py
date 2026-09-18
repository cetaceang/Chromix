"""Explicit Windows snapshot migration stays opt-in and precedes preparation."""
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/build-win-x64-github.yml"
ACTION = ROOT / ".github/actions/restore-windows-snapshot/action.yml"
STAGE = ROOT / "build/windows/ci-stage.ps1"


def test_exact_migration_inputs_and_restore_are_isolated_to_selected_stage():
    workflow = yaml.safe_load(WORKFLOW.read_text())
    events = workflow.get("on", workflow.get(True))
    for event in ("workflow_call", "workflow_dispatch"):
        for name in ("resume_source_sha", "resume_artifact_ids"):
            assert events[event]["inputs"][name]["type"] == "string"
            assert events[event]["inputs"][name]["default"] == ""
    for index in range(1, 13):
        job = workflow["jobs"][f"build-{index}"]
        steps = job["steps"]
        guard = next(s for s in steps if s.get("name") == "Check explicit snapshot migration inputs")
        restore = next(s for s in steps if s.get("name") == "Restore exact source-migration snapshot")
        stage = next(s for s in steps if s.get("id") == "stage")
        assert steps.index(guard) < steps.index(restore) < steps.index(stage)
        assert "[bool]$env:RESUME_SOURCE_SHA -ne [bool]$env:RESUME_ARTIFACT_IDS" in guard["run"]
        assert "$env:RESUME_TREE_STAGE" in guard["run"]
        assert "$env:UPSTREAM_RUN_ID" in guard["run"]
        assert restore["if"] == "${{ inputs.resume_source_sha != '' && github.job == format('build-{0}', inputs.resume_stage) }}"
        assert restore["uses"] == "./.github/actions/restore-windows-snapshot"
        assert restore["with"]["artifact-ids"] == "${{ inputs.resume_artifact_ids }}"
        assert restore["with"]["source-sha"] == "${{ inputs.resume_source_sha }}"
        if index > 1:
            legacy = next(s for s in steps if s.get("name") == "Download tree from previous run")
            assert "inputs.resume_source_sha == ''" in legacy["if"]
            previous = next(s for s in steps if s.get("name") == "Download tree from previous stage")
            assert "resume_source_sha" not in previous["if"]
        assert "continue-on-error" not in stage
        assert all("snapshot_safe == 'true'" in s["if"] for s in steps
                   if s.get("name", "").startswith("Upload tree part"))


def test_action_uses_validated_commit_and_enables_migration_only_after_download():
    steps = yaml.safe_load(ACTION.read_text())["runs"]["steps"]
    validation = next(s for s in steps if s.get("id") == "donor")
    checkout = next(s for s in steps if s.get("uses") == "actions/checkout@v4")
    isolate = next(s for s in steps if s.get("name", "").startswith("Isolate previous"))
    download = next(s for s in steps if "download_windows_snapshot.py" in s.get("run", ""))
    enable = steps[-1]
    assert steps.index(validation) < steps.index(checkout) < steps.index(isolate) < steps.index(download) < steps.index(enable)
    assert checkout["with"]["ref"] == "${{ steps.donor.outputs.head_sha }}"
    assert checkout["with"]["persist-credentials"] is False
    assert "Join-Path $env:RUNNER_TEMP 'chromix-previous-repo'" in isolate["run"]
    assert "if ($LASTEXITCODE -ne 0)" in validation["run"]
    assert "if ($LASTEXITCODE -ne 0)" in download["run"]
    assert "CHROMIX_WINDOWS_MIGRATION_REPO=" in enable["run"]
    assert "CHROMIX_WINDOWS_MIGRATION_SHA=" in enable["run"]
    assert "${{" not in validation["run"] + download["run"] + enable["run"]


def migration_block():
    source = STAGE.read_text()
    start = source.index("if ($env:CHROMIX_WINDOWS_MIGRATION_REPO -or")
    end = source.index('& "$PSScriptRoot\\assert-target-arch.ps1" -WorkDir $WorkDir', start)
    return source[start:end]


def test_migration_preserves_normal_checks_and_fails_snapshot_closed():
    source = STAGE.read_text()
    block = migration_block()
    assert source.index('throw "7z restore failed"') < source.index(block)
    assert source.index(block) < source.index('$domainProgress = Join-Path')
    assert source.index(block) < source.index('& "$PSScriptRoot\\prepare-ungoogled.ps1"')
    assert block.index("Write-OutVar snapshot_safe false") < block.index("migrate_windows_snapshot.py")
    assert block.index("if ($LASTEXITCODE -ne 0)") < block.index("Write-OutVar snapshot_safe true")
    assert "third_party" not in block
    assert ".chromix-source-ready" not in block
    assert 'tools\\verify_patch_stack.py' in source
    assert 'throw "required upstream cache: restore receipt missing;' in source


@pytest.mark.parametrize("mode", ["disabled", "success", "failure", "missing_sha", "not_artifact", "arm64", "upstream", "patch_failure", "mingw_layout"])
def test_powershell_migration_guard_and_failure(mode, tmp_path):
    powershell = shutil.which("pwsh") or shutil.which("powershell") or "/opt/pwsh/pwsh"
    if not Path(powershell).is_file():
        pytest.skip("PowerShell is unavailable")
    script = tmp_path / "exercise.ps1"
    script.write_text(r'''
$ErrorActionPreference = 'Stop'
$script:events = [Collections.Generic.List[string]]::new()
function Write-OutVar($key, $value) { $script:events.Add("$key=$value") }
function Get-Command { [pscustomobject]@{Source=(Join-Path $env:TEST_ROOT $(if ($env:TEST_MODE -eq 'mingw_layout') { 'host/mingw64/bin/git.exe' } else { 'host/cmd/git.exe' }))} }
function python {
  if ($args -contains '--select-patch-bin') {
    $script:events.Add('probe')
    $global:LASTEXITCODE = $(if ($env:TEST_MODE -eq 'patch_failure') { 1 } else { 0 })
    Join-Path $env:TEST_ROOT 'host/usr/bin/patch.exe'
  } else {
    $script:events.Add('python:' + ($args -join ' '))
    $global:LASTEXITCODE = $(if ($env:TEST_MODE -eq 'failure') { 1 } else { 0 })
  }
}
$WorkDir = Join-Path $env:TEST_ROOT 'work'
$Repo = Join-Path $env:TEST_ROOT 'repo'
$FromArtifact = $env:TEST_MODE -ne 'not_artifact'
$Arch = $(if ($env:TEST_MODE -eq 'arm64') { 'arm64' } else { 'x64' })
$RequireUpstreamCache = $env:TEST_MODE -eq 'upstream'
$env:CHROMIX_WINDOWS_MIGRATION_REPO = $(if ($env:TEST_MODE -ne 'disabled') { Join-Path $env:TEST_ROOT 'previous' } else { '' })
$env:CHROMIX_WINDOWS_MIGRATION_SHA = $(if ($env:TEST_MODE -notin @('disabled', 'missing_sha')) { '97f2881b0e5f43b7e9563569d92dfe702ed1df0b' } else { '' })
$failed = $false
try {
''' + migration_block() + r'''
} catch { $failed = $true }
[pscustomobject]@{failed=$failed; events=@($script:events)} | ConvertTo-Json -Compress
''')
    patch = tmp_path / "host/usr/bin/patch.exe"
    patch.parent.mkdir(parents=True)
    patch.write_bytes(b"fixture")
    result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-File", str(script)],
                            env={**os.environ, "TEST_ROOT": str(tmp_path), "TEST_MODE": mode},
                            text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
    state = json.loads(result.stdout)
    assert state["failed"] is (mode not in ("disabled", "success", "mingw_layout"))
    if mode == "disabled":
        assert state["events"] == []
    elif mode in ("success", "failure", "patch_failure", "mingw_layout"):
        assert state["events"][:2] == ["snapshot_safe=false", "probe"]
        if mode == "patch_failure":
            assert state["events"] == ["snapshot_safe=false", "probe"]
        else:
            assert state["events"][2].startswith("python:-X utf8 ")
            assert "--expected-previous-sha 97f2881" in state["events"][2]
            assert ("snapshot_safe=true" in state["events"]) is (mode in ("success", "mingw_layout"))
    else:
        assert state["events"] == []


STAGE9_SHA = "30dbab28692793fa311c82ae639186003f3a67d9"
LEGACY_SHA = "97f2881b0e5f43b7e9563569d92dfe702ed1df0b"


def test_all_windows_migration_guards_pin_both_profiles_without_broadening_restore():
    workflow = yaml.safe_load(WORKFLOW.read_text())
    profile = workflow["env"]["CHROMIX_WINDOWS_MIGRATION_PROFILE"]
    assert STAGE9_SHA in profile and "windows-152-x64-stage9" in profile
    assert "windows-152-x64-legacy-0152" in profile
    guards = []
    for index in range(1, 13):
        steps = workflow["jobs"][f"build-{index}"]["steps"]
        guard = next(s for s in steps if s.get("name") == "Check explicit snapshot migration inputs")
        restore = next(s for s in steps if s.get("name") == "Restore exact source-migration snapshot")
        assert guard["env"]["RESUME_ATTEMPT"] == "${{ inputs.resume_attempt }}"
        for value in (STAGE9_SHA, LEGACY_SHA, "35315624638", "10536907942,10536997738",
                      "$env:RESUME_TREE_STAGE -cne '9'", "$env:RESUME_ATTEMPT -cne '1'",
                      "$env:CHROMIX_BUILD_PROFILE -cne 'native'"):
            assert value in guard["run"]
        branch = restore["with"]["recovery-branch"]
        assert STAGE9_SHA in branch
        assert "fix/issue3-font-resume-20260917" in branch
        assert "fix/issue3-resource-timing-20260916" in branch
        guards.append(guard["run"])
    assert len(set(guards)) == 1


@pytest.mark.parametrize("mutation", ["valid", "reverse-artifacts", "legacy", "sha", "uppercase", "run", "stage", "attempt",
                                      "profile", "extra-artifact", "duplicate-artifact", "missing-artifact", "upstream"])
def test_historical152_workflow_guard_executes_exact_profile_checks(tmp_path, mutation):
    powershell = shutil.which("pwsh") or shutil.which("powershell") or "/opt/pwsh/pwsh"
    if not Path(powershell).is_file():
        pytest.skip("PowerShell is unavailable")
    (tmp_path / "CHROMIUM_VERSION").write_text("152.0.7977.82\n")
    (tmp_path / "build").mkdir()
    (tmp_path / "build/ungoogled-revisions.psd1").write_text('@{\n  ChromiumVersion = "152.0.7977.82"\n}\n')
    steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["build-9"]["steps"]
    guard = next(s for s in steps if s.get("name") == "Check explicit snapshot migration inputs")["run"]
    env = dict(os.environ, RESUME_SOURCE_SHA=STAGE9_SHA, RESUME_RUN_ID="35315624638", RESUME_TREE_STAGE="9",
               RESUME_ATTEMPT="1", RESUME_ARTIFACT_IDS="10536907942,10536997738", CHROMIX_BUILD_PROFILE="native",
               USE_UPSTREAM_CACHE="false", UPSTREAM_RUN_ID="", GITHUB_WORKSPACE=str(tmp_path))
    overrides = {
        "valid": {}, "reverse-artifacts": {"RESUME_ARTIFACT_IDS": "10536997738, 10536907942"},
        "legacy": {"RESUME_SOURCE_SHA": LEGACY_SHA, "RESUME_RUN_ID": "35054494898", "RESUME_TREE_STAGE": "3",
                   "RESUME_ARTIFACT_IDS": "10462681393,10462257055"},
        "sha": {"RESUME_SOURCE_SHA": "a" * 40}, "uppercase": {"RESUME_SOURCE_SHA": STAGE9_SHA.upper()},
        "run": {"RESUME_RUN_ID": "35315624639"}, "stage": {"RESUME_TREE_STAGE": "8"},
        "attempt": {"RESUME_ATTEMPT": "2"}, "profile": {"CHROMIX_BUILD_PROFILE": "fast"},
        "extra-artifact": {"RESUME_ARTIFACT_IDS": "10536907942,10536997738,1"},
        "duplicate-artifact": {"RESUME_ARTIFACT_IDS": "10536907942,10536907942"},
        "missing-artifact": {"RESUME_ARTIFACT_IDS": "10536907942"}, "upstream": {"USE_UPSTREAM_CACHE": "true"},
    }
    env.update(overrides[mutation])
    script = tmp_path / "guard.ps1"
    script.write_text("$ErrorActionPreference = 'Stop'\ntry {\n" + guard + "\n} catch { exit 1 }\nexit 0\n")
    result = subprocess.run([powershell, "-NoProfile", "-NonInteractive", "-File", str(script)],
                            env=env, cwd=tmp_path, text=True, capture_output=True, timeout=30)
    assert result.returncode == (0 if mutation in ("valid", "reverse-artifacts", "legacy") else 1), result.stderr


@pytest.mark.parametrize('version,pin,enabled,expected', [
    ('153.0.8010.36', '153.0.8010.36', True, 1),
    ('152.0.7977.82', '153.0.8010.36', True, 1),
    ('153.0.8010.36', '152.0.7977.82', True, 1),
    ('153.0.8010.36', '153.0.8010.36', False, 0),
])
def test_historical_migration_guard_rejects_new_target_before_restore(tmp_path, version, pin, enabled, expected):
    powershell = shutil.which('pwsh') or shutil.which('powershell') or '/opt/pwsh/pwsh'
    if not Path(powershell).is_file():
        pytest.skip('PowerShell is unavailable')
    (tmp_path / 'CHROMIUM_VERSION').write_text(version + '\n')
    (tmp_path / 'build').mkdir()
    (tmp_path / 'build/ungoogled-revisions.psd1').write_text('@{ ChromiumVersion = "' + pin + '" }\n')
    steps = yaml.safe_load(WORKFLOW.read_text())['jobs']['build-9']['steps']
    guard = next(s for s in steps if s.get('name') == 'Check explicit snapshot migration inputs')['run']
    env = dict(os.environ, RESUME_SOURCE_SHA=STAGE9_SHA if enabled else '',
               RESUME_ARTIFACT_IDS='10536907942,10536997738' if enabled else '',
               RESUME_RUN_ID='35315624638', RESUME_TREE_STAGE='9', RESUME_ATTEMPT='1',
               CHROMIX_BUILD_PROFILE='native', USE_UPSTREAM_CACHE='false', UPSTREAM_RUN_ID='',
               GITHUB_WORKSPACE=str(tmp_path))
    script = tmp_path / 'guard.ps1'
    script.write_text("$ErrorActionPreference = 'Stop'\ntry {\n" + guard + '\n} catch { exit 1 }\nexit 0\n')
    result = subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-File', str(script)],
                            env=env, cwd=tmp_path, text=True, capture_output=True, timeout=30)
    assert result.returncode == expected, result.stderr
