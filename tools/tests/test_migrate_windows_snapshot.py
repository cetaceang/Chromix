"""Real Git/GNU patch tests for the one-shot Windows cold-source migration."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import migrate_windows_snapshot as migration

ROOT = Path(__file__).resolve().parents[2]
PATCH_BIN = shutil.which("gpatch") or shutil.which("patch")
pytestmark = pytest.mark.skipif(not PATCH_BIN or not shutil.which("git"), reason="host Git and GNU patch required")
LITE = migration.arp.LITE + "/v8/test/torque/test-torque.tq"
OTHER = "third_party/blink/other.cc"


def put(root, name, data):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    return path


def git(root, *args):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    return subprocess.run([shutil.which("git"), "-c", "core.hooksPath=" + os.devnull,
                           "-C", str(root), *args], env=env, check=True, capture_output=True).stdout


def commit(root):
    if not (root / ".git").exists():
        git(root, "init", "-q")
    git(root, "add", ".")
    git(root, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
    return git(root, "rev-parse", "HEAD").decode().strip()


def patch(target=migration.SOURCE, old="base example.com", new="old example.com"):
    return (f"diff --git a/{target} b/{target}\n--- a/{target}\n+++ b/{target}\n"
            f"@@ -1,3 +1,3 @@\n context\n-{old}\n+{new}\n tail\n").encode()


def snapshot(root):
    return {path.relative_to(root).as_posix(): (path.read_bytes(), path.stat().st_mtime_ns,
                                               stat.S_IMODE(path.stat().st_mode))
            for path in root.rglob("*") if path.is_file()}


class Fixture:
    def __init__(self, root, monkeypatch):
        self.root = root
        self.previous, self.repo, self.work = (root / name for name in ("previous", "current", "work"))
        self.src = self.work / "src"
        self.core = self.work / "tooling/ungoogled-chromium"
        self.tooling = self.work / "tooling/ungoogled-chromium-windows"
        put(self.core, "domain_regex.list", rb"example\.com#blocked.test" + b"\n")
        put(self.core, "chromium_version.txt", migration.VERSION + "\n")
        put(self.core, "revision.txt", "1\n")
        put(self.core, "utils/domain_substitution.py", "raise RuntimeError('never execute donor Python')\n")
        script = put(self.core, "utils/prepare.sh", "#!/bin/sh\nexit 99\n")
        script.chmod(0o755)
        core_sha = commit(self.core)
        put(self.tooling, "domain_substitution.list", migration.SOURCE + "\n")
        put(self.tooling, "revision.txt", "1\n")
        put(self.tooling, "download.py", "raise RuntimeError('never execute donor Python')\n")
        commit(self.tooling)
        git(self.tooling, "update-index", "--add", "--cacheinfo", f"160000,{core_sha},ungoogled-chromium")
        git(self.tooling, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "submodule")
        platform_sha = git(self.tooling, "rev-parse", "HEAD").decode().strip()
        for name in migration.PROTECTED_FILES:
            put(self.previous, name, (ROOT / name).read_bytes().replace(b"\r\n", b"\n"))
        for name in ("build/windows/prepare-ungoogled.ps1", "build/windows/prep_rust_toolchain.py",
                     "build/ungoogled-revisions.psd1", "build/upstream-cache.json"):
            put(self.previous, name, (ROOT / name).read_bytes().replace(b"\r\n", b"\n"))
        pins = (self.previous / "build/ungoogled-revisions.psd1").read_text()
        pins = pins.replace("e71b91c6e336d0f25cfc6b9ef09298a9d2506e24", core_sha)
        pins = pins.replace("333bc7dfff72ff4abc4d9cc76bc41de300a46e06", platform_sha)
        put(self.previous, "build/ungoogled-revisions.psd1", pins)
        put(self.previous, "assets/fixture.dat", b"untouched asset\x00")
        put(self.previous, LITE, "lite payload\n")
        put(self.previous, "patches/series", "patches/0001-other.patch\n" + migration.PATCH + "\n")
        put(self.previous, "patches/0001-other.patch", patch(OTHER, "other base", "other patched"))
        put(self.previous, migration.PATCH, patch())
        self.sha = commit(self.previous)
        shutil.copytree(self.previous, self.repo)
        put(self.repo, migration.PATCH, patch(new="new example.com"))
        monkeypatch.setattr(migration, "DONOR_SHA", self.sha)
        monkeypatch.setattr(migration, "TRUSTED_REPO", self.repo)
        self.monkeypatch = monkeypatch
        put(self.src, migration.SOURCE, "context\nold blocked.test\ntail\n")
        put(self.src, OTHER, "context\nother patched\ntail\n")
        put(self.src, "v8/test/torque/test-torque.tq", "lite payload\n")
        put(self.src, "chrome/VERSION", "MAJOR=152\nMINOR=0\nBUILD=7977\nPATCH=82\n")
        pins = migration._pins(self.previous)
        old_key = migration.source_ready_key(self.previous)
        for name, value in {
            ".chromix-source-unpacked": migration.VERSION,
            ".chromix-ungoogled-core": core_sha,
            ".chromix-ungoogled-windows": platform_sha,
            ".chromix-binaries-pruned": core_sha,
            ".chromix-domain-substituted": core_sha,
            migration.PATCH_MARKER: old_key.rsplit("|", 1)[1], migration.READY: old_key,
        }.items():
            put(self.src, name, value + "\n")
        put(self.src, "out/Chromix/args.gn", 'target_cpu = "x64"\ntarget_os = "win"\n')
        put(self.src, "out/Chromix/build.ninja", "untouched graph\n")
        put(self.src, "out/Chromix/.ninja_log", "# ninja log v5\n")
        put(self.src, "out/Chromix/.ninja_deps", b"# ninjadeps\n\x04\0\0\0")
        put(self.src, "out/Chromix/obj/cached.obj", b"cached object\0")
        put(self.src, "out/Chromix/ninja.exe", b"do not execute")
        put(self.work, "domain_substitution_cache.tar.gz", b"unchanged cached domains\0")
        put(self.work, "download_cache/toolchain.tar.xz", b"unchanged download\0")

    def run(self, **kwargs):
        return migration.migrate(self.work, self.previous, self.repo, kwargs.pop("sha", self.sha),
                                 patch_bin=kwargs.pop("patch_bin", PATCH_BIN), **kwargs)

    def repin(self):
        self.sha = commit(self.previous)
        self.monkeypatch.setattr(migration, "DONOR_SHA", self.sha)
        key = migration.source_ready_key(self.previous)
        put(self.src, migration.PATCH_MARKER, key.rsplit("|", 1)[1] + "\n")
        put(self.src, migration.READY, key + "\n")


@pytest.fixture
def fx(tmp_path, monkeypatch):
    return Fixture(tmp_path, monkeypatch)


@pytest.mark.parametrize("crlf", [False, True])
@pytest.mark.parametrize("marker_bom", [False, True])
def test_real_full_stack_transaction_changes_one_file_and_preserves_caches(fx, crlf, marker_bom):
    source = fx.src / migration.SOURCE
    if crlf:
        source.write_bytes(source.read_bytes().replace(b"\n", b"\r\n"))
    if marker_bom:
        for path in fx.src.glob(".chromix-*"):
            path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes().replace(b"\n", b"\r\n"))
    future = source.stat().st_mtime_ns + 60_000_000_000
    os.utime(source, ns=(future, future))
    before = snapshot(fx.work)
    result = fx.run()
    assert result["status"] == "migrated"
    assert result["changed_files"] == [migration.SOURCE]
    assert result["old_verification"]["patch_count"] == result["new_verification"]["patch_count"] == 2
    newline = b"\r\n" if crlf else b"\n"
    assert source.read_bytes() == newline.join([b"context", b"new blocked.test", b"tail", b""])
    assert source.stat().st_mtime_ns >= future + 1_000_000_000
    after = snapshot(fx.work)
    changed = {"src/" + name for name in (migration.SOURCE, migration.READY, migration.PATCH_MARKER)}
    for name, value in before.items():
        if name not in changed:
            assert after[name] == value, name
    assert set(after) - set(before) == {"src/" + migration.RECEIPT}
    assert not (fx.work / migration.BLOCKER).exists()
    assert not (fx.src / ".chromix-upstream-restored.json").exists()
    assert not (fx.src / migration.arp.MARKER).exists()
    receipt = json.loads((fx.src / migration.RECEIPT).read_bytes())
    assert receipt == result
    assert receipt["previous_sha"] == fx.sha
    assert receipt["source_change"]["diff"].count("+new blocked.test") == 1
    assert receipt["previous_key"] != receipt["key"] == migration.source_ready_key(fx.repo)
    assert migration._verify(fx.src, fx.repo, fx.core, fx.tooling)["status"] == "verified"
    repeated = snapshot(fx.work)
    with pytest.raises(migration.arp.ApplyError, match="explicit repeat"):
        fx.run()
    assert snapshot(fx.work) == repeated


def test_windows_patch_set_key_is_independent_recipe_not_posix_hash(fx):
    series = (fx.previous / "patches/series").read_text().splitlines()
    raw = b"".join((fx.previous / name).read_bytes() for name in series)
    raw += b"v8/test/torque/test-torque.tq" + (fx.previous / LITE).read_bytes()
    expected = hashlib.sha256(raw).hexdigest()
    assert migration.patch_set_key(fx.previous) == expected
    put(fx.previous, "patches/series", "# this is not hashed by PowerShell\n" + "\n".join(series) + "\n")
    assert migration.patch_set_key(fx.previous) == expected
    assert migration.source_ready_key(fx.previous).endswith("|" + expected)


@pytest.mark.parametrize("mutation", ["sha", "head", "old-patch", "old-script", "pins", "series", "other-patch",
    "new-asset", "asset", "lite", "lite-extra", "source", "other-source", "version", "core-version",
    "tooling", "tooling-head", "core-pin", "windows-pin", "default", "arch", "args", "repeat", "upstream", "manifest"])
def test_preflight_rejection_does_not_write(fx, mutation):
    kwargs = {}
    if mutation == "sha":
        kwargs["sha"] = "0" * 40
    elif mutation == "head":
        put(fx.previous, "unrelated", "changed")
        commit(fx.previous)
    elif mutation in ("old-patch", "old-script"):
        put(fx.previous, migration.PATCH if mutation == "old-patch" else "tools/apply_restored_patches.py", "tampered\n")
    elif mutation == "pins":
        put(fx.repo, "CHROMIUM_VERSION", "0.0.0.0\n")
    elif mutation == "series":
        put(fx.repo, "patches/series", migration.PATCH + "\n")
    elif mutation == "other-patch":
        put(fx.repo, "patches/0001-other.patch", patch(OTHER, "other base", "extra change"))
    elif mutation in ("new-asset", "asset"):
        put(fx.repo, "assets/new.dat" if mutation == "new-asset" else "assets/fixture.dat", "different")
    elif mutation in ("lite", "lite-extra"):
        put(fx.repo, LITE if mutation == "lite" else migration.arp.LITE + "/extra", "different")
    elif mutation in ("source", "other-source"):
        put(fx.src, migration.SOURCE if mutation == "source" else OTHER, "unrecognized source\n")
    elif mutation == "version":
        put(fx.src, "chrome/VERSION", "MAJOR=1\n")
    elif mutation == "core-version":
        put(fx.core, "chromium_version.txt", "0.0.0.0\n")
    elif mutation == "tooling":
        put(fx.tooling, "domain_substitution.list", "unknown\n")
    elif mutation == "tooling-head":
        put(fx.core, "extra", "changed")
        commit(fx.core)
    elif mutation in ("core-pin", "windows-pin"):
        name = ".chromix-ungoogled-core" if mutation == "core-pin" else ".chromix-ungoogled-windows"
        put(fx.src, name, "0" * 40)
    elif mutation == "default":
        put(fx.src, "out/Default/args.gn", 'target_cpu = "x64"\n')
    elif mutation == "arch":
        put(fx.work, ".chromix-target-arch", "arm64\n")
    elif mutation == "args":
        put(fx.src, "out/Chromix/args.gn", 'target_cpu = "arm64"\n')
    elif mutation == "repeat":
        put(fx.src, migration.RECEIPT, "{}")
    elif mutation == "upstream":
        put(fx.src, ".chromix-upstream-restored.json", "{}")
    elif mutation == "manifest":
        put(fx.src, migration.arp.MARKER, "{}")
    before = snapshot(fx.work)
    with pytest.raises((migration.arp.ApplyError, ValueError)):
        fx.run(**kwargs)
    assert snapshot(fx.work) == before
    assert not (fx.work / migration.BLOCKER).exists()


@pytest.mark.parametrize("name", [migration.READY, migration.PATCH_MARKER, ".chromix-source-unpacked",
    ".chromix-ungoogled-core", ".chromix-ungoogled-windows", ".chromix-binaries-pruned", ".chromix-domain-substituted"])
@pytest.mark.parametrize("action", ["missing", "mismatch"])
def test_all_layer_markers_required(fx, name, action):
    if action == "missing":
        (fx.src / name).unlink()
    else:
        put(fx.src, name, "forged\n")
    before = snapshot(fx.work)
    with pytest.raises(migration.arp.ApplyError, match="missing|mismatch"):
        fx.run()
    assert snapshot(fx.work) == before


@pytest.mark.parametrize("name", [".chromix-domain-substitution-in-progress", ".chromix-restored-patches-in-progress",
    ".chromix-layer-in-progress", ".chromix-patch-in-progress", ".chromix-unknown-inprogress",
    ".chromix-unknown-in_progress", migration.BLOCKER])
def test_unknown_and_recognized_blockers_never_removed(fx, name):
    if name == migration.BLOCKER:
        (fx.work / name).mkdir()
    else:
        put(fx.src, name, "interrupted\n")
    before = snapshot(fx.work)
    with pytest.raises(migration.arp.ApplyError, match="in-progress"):
        fx.run()
    assert snapshot(fx.work) == before
    assert (fx.work / name if name == migration.BLOCKER else fx.src / name).exists()


@pytest.mark.parametrize("target", [OTHER, "out/Chromix/obj/cached.obj", "../escape", "third_party/unknown.cc"])
def test_new_0152_cannot_touch_other_targets(fx, target):
    put(fx.repo, migration.PATCH, patch(target, "base", "new"))
    before = snapshot(fx.work)
    with pytest.raises(migration.arp.ApplyError, match="single approved|unsafe path|object cache"):
        fx.run()
    assert snapshot(fx.work) == before


def test_0152_extra_file_is_rejected(fx):
    path = fx.repo / migration.PATCH
    path.write_bytes(path.read_bytes() + patch(OTHER, "other patched", "changed"))
    with pytest.raises(migration.arp.ApplyError, match="single approved"):
        fx.run()


@pytest.mark.parametrize("kind", ["source", "marker", "old-patch", "tooling", "asset", "out", "work"])
@pytest.mark.parametrize("link", ["symlink", "hardlink"])
def test_links_cannot_escape_or_alias_source_and_inputs(fx, kind, link):
    paths = {"source": fx.src / migration.SOURCE, "marker": fx.src / migration.READY,
             "old-patch": fx.previous / migration.PATCH, "tooling": fx.core / "domain_regex.list",
             "asset": fx.repo / "assets/fixture.dat", "out": fx.src / "out/Chromix/args.gn", "work": fx.work}
    path = paths[kind]
    if kind == "work" and link == "hardlink":
        pytest.skip("directories cannot be hardlinked")
    outside = fx.root / "external"
    path.rename(outside)
    try:
        if link == "symlink":
            path.symlink_to(outside, target_is_directory=kind == "work")
        else:
            os.link(outside, path)
    except OSError:
        pytest.skip("link creation unavailable")
    before = snapshot(fx.src)
    with pytest.raises(migration.arp.ApplyError, match="symlink/reparse|single-link"):
        fx.run()
    assert snapshot(fx.src) == before


def test_reparse_attribute_rejected_without_following_it(fx, monkeypatch):
    target = fx.src / migration.SOURCE
    original = Path.lstat

    def lstat(path, *args, **kwargs):
        value = original(path, *args, **kwargs)
        if path == target:
            return SimpleNamespace(st_mode=value.st_mode, st_file_attributes=0x400, st_nlink=1)
        return value

    monkeypatch.setattr(Path, "lstat", lstat)
    with pytest.raises(migration.arp.ApplyError, match="reparse"):
        fx.run()


@pytest.mark.parametrize("windows", [False, True])
def test_windows_checkout_executable_bits_not_misread_as_git_identity(fx, monkeypatch, windows):
    monkeypatch.setattr(migration, "WINDOWS", windows)
    (fx.core / "utils/prepare.sh").chmod(0o644)
    (fx.repo / "tools/verify_patch_stack.py").chmod(0o755)
    if windows:
        assert fx.run()["status"] == "migrated"
    else:
        with pytest.raises(migration.arp.ApplyError, match="mode"):
            fx.run()


def test_git_tree_executable_mode_change_rejected_even_on_windows(fx, monkeypatch):
    monkeypatch.setattr(migration, "WINDOWS", True)
    git(fx.repo, "update-index", "--chmod=+x", "tools/verify_patch_stack.py")
    git(fx.repo, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "mode")
    with pytest.raises(migration.arp.ApplyError, match="Git mode"):
        fx.run()


@pytest.mark.parametrize("point", ["reverse", "apply", "candidate", "publish", "final", "patch-marker", "ready", "receipt"])
def test_failures_keep_recognized_blocker_and_never_touch_caches(fx, monkeypatch, point):
    before = snapshot(fx.work)
    if point in ("reverse", "apply"):
        apply = migration._apply

        def fail(*args, **kwargs):
            if kwargs["reverse"] == (point == "reverse"):
                raise migration.arp.ApplyError("injected scratch failure")
            return apply(*args, **kwargs)

        monkeypatch.setattr(migration, "_apply", fail)
    elif point in ("candidate", "final"):
        verify = migration._verify

        def fail(src, repo, *args):
            if repo == fx.repo and (src == fx.src) == (point == "final"):
                assert (fx.work / migration.BLOCKER).is_dir()
                assert (fx.src / migration.READY).read_bytes() == before["src/" + migration.READY][0]
                raise ValueError("injected verification failure")
            return verify(src, repo, *args)

        monkeypatch.setattr(migration, "_verify", fail)
    else:
        write = migration._write
        name = {"publish": migration.SOURCE, "patch-marker": migration.PATCH_MARKER,
                "ready": migration.READY, "receipt": migration.RECEIPT}[point]

        def fail(path, *args, **kwargs):
            if path == fx.src / name:
                assert (fx.work / migration.BLOCKER).is_dir()
                raise OSError("injected publication failure")
            return write(path, *args, **kwargs)

        monkeypatch.setattr(migration, "_write", fail)
    with pytest.raises((migration.arp.ApplyError, OSError, ValueError), match="injected"):
        fx.run()
    assert (fx.work / migration.BLOCKER).is_dir()
    with pytest.raises(migration.arp.ApplyError, match="in-progress"):
        fx.run()
    after = snapshot(fx.work)
    for name, value in before.items():
        if name.startswith("src/out/") or name.startswith("download_cache/") or "domain_substitution_cache" in name:
            assert after[name] == value
    if point in ("reverse", "apply", "candidate", "publish"):
        assert after["src/" + migration.SOURCE] == before["src/" + migration.SOURCE]
    if point in ("reverse", "apply", "candidate", "publish", "final"):
        assert after["src/" + migration.READY] == before["src/" + migration.READY]
        assert after["src/" + migration.PATCH_MARKER] == before["src/" + migration.PATCH_MARKER]
    assert not list(fx.src.rglob("*.rej"))
    assert not list(fx.src.rglob("*.orig"))


@pytest.mark.parametrize("mutation", ["source-content", "source-stat", "source-replace", "marker", "previous", "previous-head",
                                      "repo", "asset-extra", "tooling", "unknown-progress"])
def test_concurrent_changes_fail_closed(fx, monkeypatch, mutation):
    apply = migration._apply

    def change(*args, **kwargs):
        result = apply(*args, **kwargs)
        if not kwargs["reverse"]:
            if mutation.startswith("source-"):
                path = fx.src / migration.SOURCE
                if mutation == "source-content":
                    path.write_bytes(path.read_bytes() + b"// concurrent edit\n")
                elif mutation == "source-stat":
                    stamp = path.stat().st_mtime_ns + 1_000_000_000
                    os.utime(path, ns=(stamp, stamp))
                else:
                    copy = fx.root / "replacement"
                    shutil.copy2(path, copy)
                    os.replace(copy, path)
            elif mutation == "marker":
                put(fx.src, migration.READY, "changed")
            elif mutation == "previous":
                put(fx.previous, migration.PATCH, patch(new="changed"))
            elif mutation == "previous-head":
                put(fx.previous, "unrelated", "changed")
                commit(fx.previous)
            elif mutation == "repo":
                put(fx.repo, migration.PATCH, patch(new="other target"))
            elif mutation == "asset-extra":
                put(fx.repo, "assets/concurrent.dat", "new")
            elif mutation == "tooling":
                put(fx.core, "domain_regex.list", "changed#bad\n")
            else:
                put(fx.src, ".chromix-unknown-inprogress", "concurrent")
        return result

    monkeypatch.setattr(migration, "_apply", change)
    with pytest.raises(migration.arp.ApplyError, match="concurrent|preparation input|in-progress|HEAD"):
        fx.run()
    assert (fx.work / migration.BLOCKER).is_dir()


def test_fuzz_zero_rejects_changed_context_instead_of_using_loose_hunks(fx):
    put(fx.repo, migration.PATCH, patch().replace(b" context\n", b" absent context\n").replace(b"+old", b"+new"))
    before = snapshot(fx.src)
    with pytest.raises(migration.arp.ApplyError, match="scratch apply failed"):
        fx.run()
    assert snapshot(fx.src) == before
    assert (fx.work / migration.BLOCKER).is_dir()


def test_no_donor_scripts_filters_or_executables_are_run(fx, monkeypatch):
    sentinel = fx.root / "executed"
    for root in (fx.previous, fx.core, fx.tooling):
        for key in ("filter.evil.clean", "filter.evil.smudge", "filter.evil.process",
                    "diff.evil.command", "diff.evil.textconv", "core.fsmonitor"):
            git(root, "config", key, f"touch {sentinel}; exit 99")
        put(root, ".git/info/attributes", "* filter=evil diff=evil\n")
    monkeypatch.setenv("GIT_DIR", str(fx.previous / ".git"))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.fsmonitor")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", f"touch {sentinel}")
    run = migration.subprocess.run
    commands = []

    def capture(command, **kwargs):
        binary = Path(shutil.which(str(command[0])) or command[0]).resolve()
        assert not any(binary.is_relative_to(root) for root in (fx.work, fx.previous, fx.repo))
        assert binary.name in ("git", "git.exe", "patch", "gpatch", "patch.exe")
        assert "--filters" not in command
        if "--input" in command:
            assert "--fuzz=0" in command
            assert "--binary" in command
            path = Path(command[-1])
            assert not any(path.is_relative_to(root) for root in (fx.work, fx.previous, fx.repo))
        commands.append(command)
        return run(command, **kwargs)

    monkeypatch.setattr(migration.subprocess, "run", capture)
    fx.run()
    assert not sentinel.exists()
    assert any("ls-tree" in command for command in commands)
    assert any("--reverse" in command and "--input" in command for command in commands)


@pytest.mark.parametrize("kind", ["work-patch", "previous-patch", "work-git", "temporary", "trusted-repo"])
def test_rejects_untrusted_execution_and_unsafe_workspace(fx, monkeypatch, kind):
    kwargs = {}
    if kind.endswith("patch"):
        root = fx.work if kind == "work-patch" else fx.previous
        fake = put(root, "fake-patch", "#!/bin/sh\nexit 99\n")
        fake.chmod(0o755)
        kwargs["patch_bin"] = str(fake)
    elif kind == "work-git":
        fake = put(fx.work, "git", "#!/bin/sh\nexit 99\n")
        fake.chmod(0o755)
        monkeypatch.setenv("PATH", str(fx.work) + os.pathsep + os.environ["PATH"])
    elif kind == "temporary":
        monkeypatch.setattr(migration.tempfile, "gettempdir", lambda: str(fx.src))
    else:
        monkeypatch.setattr(migration, "TRUSTED_REPO", ROOT)
    before = snapshot(fx.work)
    with pytest.raises(migration.arp.ApplyError, match="donor|executable|temporary directory|trusted helper"):
        fx.run(**kwargs)
    assert snapshot(fx.work) == before


def test_real_ninja_preserves_objects_and_rebuilds_only_changed_dependency(fx):
    ninja = shutil.which("ninja")
    if not ninja or os.name == "nt":
        pytest.skip("POSIX Ninja/cp harness required")
    out = fx.src / "out/Chromix"
    put(out, "build.ninja", "rule copy\n  command = cp $in $out\n"
        f"build changed.obj: copy ../../{migration.SOURCE}\n"
        f"build unchanged.obj: copy ../../{OTHER}\n"
        "default changed.obj unchanged.obj\n")
    for name in (migration.SOURCE, OTHER):
        os.utime(fx.src / name, ns=(1_700_000_000_000_000_000,) * 2)
    subprocess.run([ninja, "-C", str(out)], check=True, capture_output=True)
    before = snapshot(out)
    fx.run()
    assert snapshot(out) == before
    plan = subprocess.run([ninja, "-C", str(out), "-n"], check=True, capture_output=True, text=True)
    assert "changed.obj" in plan.stdout
    assert "unchanged.obj" not in plan.stdout


def test_cli_report_success_failure_and_required_contract(fx, tmp_path, capsys):
    report = tmp_path / "migration-report.json"
    args = ["--workdir", str(fx.work), "--previous-repo", str(fx.previous), "--repo", str(fx.repo),
            "--expected-previous-sha", fx.sha, "--patch-bin", PATCH_BIN, "--report", str(report)]
    assert migration.main(args) == 0
    assert json.loads(report.read_bytes())["status"] == "migrated"
    assert json.loads(capsys.readouterr().out)["status"] == "migrated"
    failed = tmp_path / "repeat-report.json"
    assert migration.main([*args[:-1], str(failed)]) == 1
    assert "explicit repeat" in json.loads(failed.read_bytes())["error"]
    before = report.read_bytes()
    assert migration.main(args) == 1
    assert report.read_bytes() == before
    with pytest.raises(SystemExit):
        migration.main([])


def test_actual_old_and_current_0152_roundtrip_on_hunk_complete_preimage(fx, tmp_path):
    old = git(ROOT, "show", "97f2881b0e5f43b7e9563569d92dfe702ed1df0b:" + migration.PATCH)
    new = (ROOT / migration.PATCH).read_bytes()
    if old == new:
        pytest.skip("target 0152 API fix is not present in this checkout")
    lines = old.splitlines(keepends=True)
    preimage = []
    index = 0
    while index < len(lines):
        match = migration.arp.HUNK.fullmatch(lines[index])
        if not match:
            index += 1
            continue
        start, remaining = int(match[1]), int(match[2] or 1)
        while len(preimage) < start - 1:
            preimage.append(f"// fixture padding {len(preimage)}\n".encode())
        assert len(preimage) == start - 1
        index += 1
        while remaining:
            if lines[index][:1] in (b" ", b"-"):
                preimage.append(lines[index][1:])
                remaining -= 1
            index += 1
    preimage.extend([b"// fixture untouched tail\n"] * 10)
    put(fx.previous, migration.PATCH, old)
    put(fx.repo, migration.PATCH, new)
    fx.repin()
    put(fx.src, migration.SOURCE, b"".join(preimage))
    subprocess.run(migration.arp._patch_command(PATCH_BIN, fx.previous / migration.PATCH),
                   cwd=fx.src, check=True, capture_output=True)
    before = (fx.src / migration.SOURCE).read_bytes()
    result = fx.run()
    after = (fx.src / migration.SOURCE).read_bytes()
    assert before != after
    assert b"getTableTags" in before and b"getTableTags" not in after
    assert b"readTableTags" in after
    assert b"FromUtf8" in after and b".empty()" in after
    assert result["changed_files"] == [migration.SOURCE]
    assert result["new_verification"]["status"] == "verified"


def test_false_git_replacement_cannot_forge_expected_head(fx):
    put(fx.previous, "new-head", "different commit")
    wrong = commit(fx.previous)
    git(fx.previous, "replace", wrong, fx.sha)
    with pytest.raises(migration.arp.ApplyError, match="HEAD"):
        fx.run()


def test_source_readonly_mode_preserved_on_posix_harness(fx):
    if os.name == "nt":
        pytest.skip("Windows read-only replace must be verified natively")
    source = fx.src / migration.SOURCE
    source.chmod(0o444)
    assert fx.run()["status"] == "migrated"
    assert stat.S_IMODE(source.stat().st_mode) == 0o444


def test_report_io_failure_leaves_successful_source_blocked(fx):
    class BrokenReport:
        def write(self, data):
            assert (fx.work / migration.BLOCKER).is_dir()
            raise OSError("injected report write failure")

    with pytest.raises(OSError, match="report write"):
        fx.run(report_stream=BrokenReport())
    assert (fx.work / migration.BLOCKER).is_dir()
    assert (fx.src / migration.RECEIPT).is_file()
    with pytest.raises(migration.arp.ApplyError, match="in-progress"):
        fx.run()


def test_receipt_cannot_appear_concurrently(fx, monkeypatch):
    verify = migration._verify

    def inject(src, repo, *args):
        result = verify(src, repo, *args)
        if repo == fx.repo and src != fx.src:
            put(fx.src, migration.RECEIPT, "forged concurrent receipt")
        return result

    monkeypatch.setattr(migration, "_verify", inject)
    with pytest.raises(migration.arp.ApplyError, match="receipt.*concurrent"):
        fx.run()
    assert (fx.work / migration.BLOCKER).is_dir()
    assert (fx.src / migration.RECEIPT).read_text() == "forged concurrent receipt"


def test_windows_crlf_tracked_scripts_are_verified_without_filters(fx, monkeypatch):
    monkeypatch.setattr(migration, "WINDOWS", True)
    for root in (fx.previous, fx.repo):
        path = root / "build/windows/prepare-ungoogled.ps1"
        path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    path = fx.core / "utils/domain_substitution.py"
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    assert fx.run()["status"] == "migrated"


def test_mixed_crlf_cannot_hide_modified_tracked_content(fx, monkeypatch):
    monkeypatch.setattr(migration, "WINDOWS", True)
    path = fx.previous / "build/windows/prepare-ungoogled.ps1"
    raw = path.read_bytes().replace(b"\r\n", b"\n")
    path.write_bytes(raw.replace(b"\n", b"\r\n", 1))
    with pytest.raises(migration.arp.ApplyError, match="tracked content"):
        fx.run()


def test_old_and_new_checkout_preparation_bytes_must_match_even_on_windows(fx, monkeypatch):
    monkeypatch.setattr(migration, "WINDOWS", True)
    path = fx.previous / "build/windows/prepare-ungoogled.ps1"
    path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    with pytest.raises(migration.arp.ApplyError, match="preparation/assets"):
        fx.run()


def test_cli_cannot_write_report_into_source(fx):
    report = fx.src / "out/Chromix/unsafe.json"
    args = ["--workdir", str(fx.work), "--previous-repo", str(fx.previous), "--repo", str(fx.repo),
            "--expected-previous-sha", fx.sha, "--patch-bin", PATCH_BIN, "--report", str(report)]
    before = snapshot(fx.work)
    assert migration.main(args) == 1
    assert snapshot(fx.work) == before


def test_blocker_contract_is_already_recognized_without_prepare_changes():
    prepare = (ROOT / "build/windows/prepare-ungoogled.ps1").read_text()
    ci = (ROOT / "build/windows/ci-stage.ps1").read_text()
    for script in (prepare, ci):
        assert '-Directory -Filter ".chromix-upstream-restore-*"' in script
    assert migration.BLOCKER.startswith(".chromix-upstream-restore-")
    assert migration.DONOR_SHA == "97f2881b0e5f43b7e9563569d92dfe702ed1df0b"
