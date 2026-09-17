"""Test optional cache wiring without downloading or compiling Chromium."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]
BASH32 = Path.home() / ".local/bash-3.2-for-ci/bash"


class PosixUpstreamCacheTest(unittest.TestCase):
    def test_all_five_targets_receive_cache_option(self):
        for platform in ('linux', 'macos'):
            for arch in ('x64', 'arm64'):
                caller = (REPO / f'.github/workflows/build-{platform}-{arch}.yml').read_text()
                self.assertEqual(caller.count("use_upstream_cache: ${{"), 1)
                self.assertIn("'tools/*upstream_cache.py'", caller)
        windows = (REPO / '.github/workflows/build-win-x64-github.yml').read_text()
        self.assertIn("CHROMIX_PREFER_UPSTREAM_CACHE: ${{ github.event_name == 'push'", windows)
        self.assertIn("CHROMIX_USE_UPSTREAM_CACHE: ${{ (inputs.use_upstream_cache", windows)
        workflow = (REPO / ".github/workflows/build-posix-github.yml").read_text()
        self.assertIn("UPSTREAM_ACTIONS_TOKEN:", workflow)
        self.assertIn("secrets.UPSTREAM_ACTIONS_TOKEN || github.token", workflow)
        self.assertIn("upstream-cache-import.json", workflow)
        self.assertIn("upstream-cache-plan.log", workflow)

    def test_restore_precedes_source_preparation_only_on_fresh_first_stage(self):
        stage = (REPO / "build/posix/ci-stage.sh").read_text()
        self.assertLess(stage.index('"$REPO/build/posix/fetch-upstream-cache.sh"'),
                        stage.index('"$REPO/tools/restore_upstream_cache.py"'))
        self.assertLess(stage.index('"$REPO/tools/restore_upstream_cache.py"'),
                        stage.index('"$REPO/build/prepare-ungoogled.sh"'))
        self.assertIn('[ "$STAGE_INDEX" -eq 1 ] && [ -z "$FROM_SNAPSHOT" ]', stage)
        self.assertIn('[ "$(remaining_min)" -ge "$CACHE_REQUIRED_MINUTES" ]', stage)
        self.assertIn('[ ! -e "$SRC" ]', stage)
        self.assertNotIn('export CHROMIX_UPSTREAM_CACHE_DIR=', stage)

    def test_builders_keep_restored_output_and_regenerate_chromix_graph(self):
        for platform, script in (("linux", "build/build.sh"), ("macos", "build/macos/build.sh")):
            with self.subTest(platform=platform):
                source = (REPO / script).read_text()
                self.assertLess(source.index('utils/domain_substitution.py" apply'),
                                source.index('"$OUT/gn" gen'))
                self.assertLess(source.index('"$OUT/gn" gen'),
                                source.index("chromix_report_upstream_plan"))
                self.assertIn('OUT="$SRC/out/Chromix"', source)
                self.assertIn('OUT="$SRC/out/Default"', source)
                self.assertIn('.chromix-upstream-restored.json', source)
                self.assertNotIn('chromix_import_upstream_cache objects', source)
                self.assertNotIn('chromix_configure_upstream_objects', source)
                self.assertIn('"$REPO/tools/merge_gn_args.py"', source)
                self.assertIn('--fail-on-unused-args', source)

    def run_restored_builder(self, platform, arch, *, fail_tools=False, host_arch=None,
                             restored=True, system=None, missing_gn=False, incompatible_gn=False,
                             incomplete_tools=False, build_profile=None, fail_source=False):
        with tempfile.TemporaryDirectory(prefix="restored build ") as directory:
            root = Path(directory)
            repo, work, binaries = root / "repo", root / "work", root / "bin"
            src, out = work / "src", work / "src/out/Default"
            out.mkdir(parents=True)
            binaries.mkdir()
            log = root / "calls"

            def script(path, body):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("#!/bin/sh\n" + body)
                path.chmod(0o755)

            builder = "build/build.sh" if platform == "linux" else "build/macos/build.sh"
            for relative in (builder, "build/posix/upstream-cache.sh", "tools/bootstrap_gn.py",
                             "tools/merge_gn_args.py", "tools/macos_runtime.py"):
                target = repo / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(REPO / relative, target)
            # The production source gate predates this shell fixture. Model its
            # CLI/result explicitly, never bypass it in the real build script.
            (repo / "tools/verify_patch_stack.py").write_text(f'''import json, os, sys
from pathlib import Path
args = sys.argv[1:]
tooling = 'ungoogled-chromium-' + ('portablelinux' if {platform!r} == 'linux' else 'macos')
assert args[:-1] == ['--src', {str(src)!r}, '--repo', {str(repo)!r},
                    '--core', {str(work / 'tooling/ungoogled-chromium')!r},
                    '--platform-tooling', str(Path({str(work)!r}) / 'tooling' / tooling),
                    '--platform', {platform!r}, '--output']
report = Path(args[-1])
assert report.parent == Path({str(work)!r}) / 'fingerprint-diagnostics'
assert report.name.startswith('source-') and report.suffix == '.json'
with open(os.environ['CALL_LOG'], 'a') as output:
    output.write('source-check\\n')
if {fail_source!r}:
    raise SystemExit(23)
report.write_text(json.dumps({{'fixture_only': True, 'status': 'simulated-source-check'}}))
''')
            # Selection is explicit here; these shell fixtures do not contain native binaries or real logs.
            (repo / "tools/restore_ninja.py").write_text(f'''import os, sys
from pathlib import Path
assert sys.argv[1:] == ['--workdir', {str(work)!r}, '--platform', {platform!r}, '--arch', {arch!r}]
assert (Path({str(src)!r}) / '.chromix-upstream-restored.json').is_file()
with open(os.environ['CALL_LOG'], 'a') as output:
    output.write('ninja-guard\\n')
print(os.environ['SELECTED_NINJA'])
''')
            (repo / "tools/restored_reuse_evidence.py").write_text('''import os, sys
from pathlib import Path
args = sys.argv[1:]
phase = args[args.index('--phase') + 1]
assert args[args.index('--ninja') + 1] == os.environ['SELECTED_NINJA']
assert args[args.index('--arch') + 1] == os.environ['TARGET_ARCH']
if phase == 'after':
    assert args[args.index('--exit-code') + 1] == '0'
with open(os.environ['CALL_LOG'], 'a') as output:
    output.write('evidence-' + phase + '\\n')
''')
            script(repo / "build/prepare-ungoogled.sh",
                   f'test "$2:$3" = "{platform}:{arch}" || exit 96\n'
                   'printf "prepare\\n" >> "$CALL_LOG"\n')
            script(repo / "build/posix/prepare-restored-tools.sh",
                   f'test "$2:$3" = "{platform}:{arch}" || exit 96\n'
                   'printf "tools\\n" >> "$CALL_LOG"\n' +
                   ('exit 19\n' if fail_tools else 'exit 0\n' if incomplete_tools else
                    'touch "$1/src/.chromix-toolchain-ready"\n'))
            script(repo / "build/macos/select-xcode.sh", 'select_macos_xcode() { :; }\n')
            (src / ".chromix-domain-substituted").touch()
            if restored:
                (src / ".chromix-upstream-restored.json").touch()
            else:
                (src / ".chromix-toolchain-ready").touch()
            overlay = "args.gn" if platform == "linux" else "args.macos.gn"
            (repo / "build" / overlay).write_text('symbol_level = 0\nchrome_pgo_phase = 0\n')
            platform_repo = "ungoogled-chromium-" + ("portablelinux" if platform == "linux" else "macos")
            for name, flag in (("ungoogled-chromium", "flags.gn"), (platform_repo, f"flags.{platform}.gn")):
                path = work / "tooling" / name / flag
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('symbol_level = 1\n')
            (out / "args.gn").write_text('symbol_level = 2\nchrome_pgo_phase = 2\nupstream_extra = true\n')
            for name in (".ninja_deps", ".ninja_log", "build.ninja", "retained.o"):
                (out / name).write_text(name)
            gn_script = '#!/bin/sh\n[ "$1" != --version ] || exit 0\nprintf "gn\\n" >> "$CALL_LOG"\n'
            if missing_gn or incompatible_gn:
                bootstrap = src / "tools/gn/bootstrap/bootstrap.py"
                bootstrap.parent.mkdir(parents=True)
                bootstrap.write_text(f'''import os, sys
from pathlib import Path
if {platform!r} == 'linux':
    assert os.environ['CXX'] == {str(src / 'third_party/llvm-build/Release+Asserts/bin/clang++')!r}
build = Path.cwd() / sys.argv[sys.argv.index('--build-path') + 1]
assert build.parent == Path({str(src)!r}) / 'out'
assert not list(build.iterdir())
assert sys.argv[-1] == '--skip-generate-buildfiles'
with open(os.environ['CALL_LOG'], 'a') as output:
    output.write('bootstrap-gn\\n')
path = Path(sys.argv[sys.argv.index('-o') + 1])
path.write_text({gn_script!r})
path.chmod(0o755)
''')
                if incompatible_gn:
                    script(out / "gn", 'exit 126\n')
            else:
                script(out / "gn", gn_script.split('\n', 1)[1])
            script(out / "chrome", 'printf "chrome-version\\n" >> "$CALL_LOG"\n'
                   'printf "Chromium fixture\\n"\n' + ('exit 99\n' if host_arch and host_arch != arch else ''))
            for name in ("node", "go", "gperf", "clang-format"):
                script(binaries / name, "exit 0\n")
            selected_ninja = root / "selected tools/ninja"
            script(binaries / "ninja", 'printf "unselected-ninja\\n" >> "$CALL_LOG"\nexit 97\n')
            script(selected_ninja, 'test "$NINJA" = "$0" || exit 98\n'
                   'printf "ninja\\n" >> "$CALL_LOG"\n')
            host_arch = host_arch or arch
            machine = {"x64": "x86_64", "arm64": "aarch64" if platform == "linux" else "arm64"}.get(host_arch, host_arch)
            system = system or ("Linux" if platform == "linux" else "Darwin")
            script(binaries / "uname", f'case "$1" in -m) printf "{machine}\\n";; -s) printf "{system}\\n";; esac\n')
            script(binaries / "sysctl", 'printf "2\\n"\n')
            env = {**os.environ, "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
                   "CHROMIX_SKIP_DEPS": "1", "CHROMIX_JOBS": "2", "CALL_LOG": str(log),
                   "SELECTED_NINJA": str(selected_ninja), "TARGET_ARCH": arch}
            env.pop("CHROMIX_UPSTREAM_CACHE_DIR", None)
            env.pop("CHROMIX_BUILD_PROFILE", None)
            env.pop("GITHUB_OUTPUT", None)
            if build_profile is not None:
                env["CHROMIX_BUILD_PROFILE"] = build_profile
            rejected = platform == "linux" and (
                system != "Linux" or (host_arch, arch) not in (("x64", "x64"), ("arm64", "arm64"), ("x64", "arm64"))
                or (host_arch != arch and not restored))
            expected_rc = 2 if rejected else 19 if fail_tools else 1 if incomplete_tools else 23 if fail_source else 0
            for _ in range(1 if expected_rc else 2):
                result = subprocess.run([str(BASH32 if BASH32.exists() else shutil.which("bash")),
                                         str(repo / builder), str(work), arch],
                                        env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, expected_rc, result.stdout + result.stderr)
            if rejected:
                self.assertFalse(log.exists())
                self.assertIn("cold cross builds are unsupported" if (host_arch, arch) == ("x64", "arm64") and not restored
                              else "unsupported Linux", result.stderr)
                self.assertFalse((work / "tmp").exists())
            elif fail_tools or incomplete_tools:
                self.assertEqual(log.read_text().splitlines(), ["prepare", "ninja-guard", "tools"])
                if incomplete_tools:
                    self.assertIn("cold cross builds are unsupported", result.stderr)
            elif fail_source:
                self.assertEqual(log.read_text().splitlines(), ["prepare", "ninja-guard", "tools", "source-check"])
                self.assertFalse((work / "fingerprint-diagnostics/source-final.json").exists())
                self.assertEqual((out / "args.gn").read_text(),
                                 'symbol_level = 2\nchrome_pgo_phase = 2\nupstream_extra = true\n')
                if missing_gn:
                    self.assertFalse((out / "gn").exists())
            else:
                iteration = ["prepare", "ninja-guard", "tools", "source-check", "gn", "ninja", "evidence-before", "ninja", "evidence-after"]
                if platform == "linux" and host_arch == arch:
                    iteration.append("chrome-version")
                expected_calls = iteration * 2
                if missing_gn or incompatible_gn:
                    expected_calls.insert(4, "bootstrap-gn")
                self.assertEqual(log.read_text().splitlines(), expected_calls)
                self.assertEqual(json.loads((work / "fingerprint-diagnostics/source-final.json").read_text()),
                                 {"fixture_only": True, "status": "simulated-source-check"})
                self.assertEqual((out / "gn").read_text(), gn_script)
                if host_arch != arch:
                    self.assertIn("runtime validation deferred to the required native ARM64 job", result.stdout)
                    self.assertIn("runtime is not verified", result.stdout)
                    self.assertNotIn("Chromium fixture", result.stdout)
                    for relative, tool in (("third_party/node/linux/node-linux-x64/bin/node", "node"),
                                           ("third_party/dawn/tools/golang/linux-amd64/bin/go", "go")):
                        self.assertEqual((src / relative).resolve(), binaries / tool)
                    self.assertFalse((src / "third_party/dawn/tools/golang/linux-arm64").exists())
                elif platform == "linux":
                    self.assertIn("Chromium fixture", result.stdout)
                    self.assertNotIn("runtime validation deferred", result.stdout)
                args = (out / "args.gn").read_text()
                self.assertIn("upstream_extra = true", args)
                self.assertIn("symbol_level = 0", args)
                self.assertIn("chrome_pgo_phase = 0", args)
                self.assertIn(f'target_cpu = "{arch}"', args)
                self.assertIn(f'v8_target_cpu = "{arch}"', args)
                self.assertNotIn("symbol_level = 2", args)
                self.assertIn("thin_lto_enable_optimizations = " +
                              ("false" if build_profile == "fast" else "true"), args)
                self.assertIn("Build profile: " + (build_profile or "release"), result.stdout)
            for name in (".ninja_deps", ".ninja_log", "build.ninja", "retained.o"):
                self.assertEqual((out / name).read_text(), name)
            self.assertFalse((src / "out/Chromix").exists())

    def test_four_restored_builders_prepare_tools_on_every_resume_and_keep_args(self):
        for platform in ("linux", "macos"):
            for arch in ("x64", "arm64"):
                with self.subTest(platform=platform, arch=arch):
                    self.run_restored_builder(platform, arch)

    def test_source_verification_failure_blocks_gn_bootstrap_and_all_four_builders(self):
        for platform in ("linux", "macos"):
            for arch in ("x64", "arm64"):
                with self.subTest(platform=platform, arch=arch):
                    self.run_restored_builder(platform, arch, fail_source=True, missing_gn=True)

    def test_fast_profile_reaches_gn_on_both_builds_and_resumes(self):
        for platform, arch, host in (("linux", "x64", "x64"), ("linux", "arm64", "x64"),
                                     ("macos", "x64", "x64"), ("macos", "arm64", "arm64")):
            with self.subTest(platform=platform, arch=arch):
                self.run_restored_builder(platform, arch, host_arch=host, build_profile="fast")

    def test_restored_linux_x64_to_arm64_preserves_host_gn_and_defers_runtime(self):
        self.run_restored_builder("linux", "arm64", host_arch="x64")

    def test_restored_linux_cross_bootstraps_missing_native_gn_once(self):
        self.run_restored_builder("linux", "arm64", host_arch="x64", missing_gn=True)

    def test_restored_posix_rebuilds_unrunnable_gn_once(self):
        for platform in ("linux", "macos"):
            for arch in ("x64", "arm64"):
                with self.subTest(platform=platform, arch=arch):
                    self.run_restored_builder(platform, arch, incompatible_gn=True)

    def test_restored_macos_bootstraps_missing_gn_once(self):
        self.run_restored_builder("macos", "x64", missing_gn=True)

    def test_linux_cross_requires_full_restore_before_preparing_source(self):
        self.run_restored_builder("linux", "arm64", host_arch="x64", restored=False)

    def test_linux_cross_never_falls_back_to_cold_compiler_setup(self):
        self.run_restored_builder("linux", "arm64", host_arch="x64", incomplete_tools=True)

    def test_linux_rejects_other_host_target_pairs(self):
        for host, target, system in (("arm64", "x64", "Linux"), ("riscv64", "arm64", "Linux"),
                                     ("x64", "x64", "Darwin")):
            with self.subTest(host=host, target=target, system=system):
                self.run_restored_builder("linux", target, host_arch=host, system=system)

    def test_restored_tool_failure_stops_before_gn_and_ninja(self):
        for platform in ("linux", "macos"):
            with self.subTest(platform=platform):
                self.run_restored_builder(platform, "x64", fail_tools=True)

    def cross_tools_fixture(self, *, restored=True):
        from tools.tests import test_prepare_restored_tools
        fixture = test_prepare_restored_tools.PrepareRestoredToolsTest()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        src = fixture.work / "src"
        if restored:
            (src / ".chromix-upstream-restored.json").touch()
        linux = src / "build/linux"
        (linux / "sysroot_scripts").mkdir(parents=True)
        entries = {f"bullseye_{arch}": {"SysrootDir": f"debian_bullseye_{arch}-sysroot",
                                       "URL": "https://example.invalid/sysroot", "Sha256Sum": arch + "-digest"}
                   for arch in ("amd64", "arm64")}
        (linux / "sysroot_scripts/sysroots.json").write_text(json.dumps(entries))
        for arch in ("amd64", "arm64"):
            entry = entries[f"bullseye_{arch}"]
            root = linux / entry["SysrootDir"]
            root.mkdir()
            (root / ".stamp").write_text(entry["URL"] + "/" + entry["Sha256Sum"])
        return fixture

    def test_cross_tools_reuse_native_compilers_and_install_both_sysroots(self):
        fixture = self.cross_tools_fixture()
        result, commands = fixture.run_helper("linux", "arm64", machine="x86_64", compatible=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        installations = [command for command in commands if command[0].endswith("install-sysroot.py")]
        self.assertEqual(installations, [["build/linux/sysroot_scripts/install-sysroot.py", "--arch=amd64"],
                                         ["build/linux/sysroot_scripts/install-sysroot.py", "--arch=arm64"]])
        self.assertLess(commands.index(["restore-known-endpoints"]), commands.index(installations[0]))
        self.assertEqual(commands[-1][1:3], ["--phase", "finish"])
        for command in commands:
            if "--arch" in command:
                self.assertEqual(command[command.index("--arch") + 1], "arm64")
            self.assertNotIn(command[0], ("tools/clang/scripts/build.py", "tools/rust/build_rust.py",
                                          "tools/rust/build_bindgen.py", "repair-linux-arm64-tool-script"))
        self.assertTrue((fixture.work / "src/.chromix-toolchain-ready").exists())

    @unittest.skipUnless(BASH32.exists(), "Bash 3.2 required")
    def test_cross_tools_bash32_installs_host_and_target_sysroots(self):
        fixture = self.cross_tools_fixture()
        result, commands = fixture.run_helper("linux", "arm64", machine="x86_64", compatible=True, bash=BASH32)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(["build/linux/sysroot_scripts/install-sysroot.py", "--arch=amd64"], commands)
        self.assertIn(["build/linux/sysroot_scripts/install-sysroot.py", "--arch=arm64"], commands)

    def test_cross_tools_compiler_fallback_downloads_host_x64_packages(self):
        fixture = self.cross_tools_fixture()
        fixture.x64_package_fixture()
        result, commands = fixture.run_helper("linux", "arm64", machine="x86_64", package_bindgen=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(["tools/rust/update_rust.py"], commands)
        self.assertIn(["tools/clang/scripts/update.py"], commands)
        for command in commands:
            self.assertNotIn(command[0], ("tools/clang/scripts/build.py", "tools/rust/build_rust.py",
                                          "tools/rust/build_bindgen.py", "repair-linux-arm64-tool-script"))
            if "--arch" in command:
                self.assertEqual(command[command.index("--arch") + 1], "arm64")
        self.assertEqual((fixture.work / "src/out/Default/obj/keep.o").read_text(), "retained object")
        self.assertEqual(commands[-1][1:3], ["--phase", "finish"])

    def test_cross_tools_missing_host_bindgen_cannot_use_arm_rebuild(self):
        fixture = self.cross_tools_fixture()
        fixture.x64_package_fixture()
        result, commands = fixture.run_helper("linux", "arm64", machine="x86_64", package_bindgen=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Linux x64 Rust package lacks executable bindgen", result.stderr)
        self.assertNotIn(["tools/rust/build_bindgen.py", "--skip-test"], commands)
        self.assertNotIn(["repair-linux-arm64-tool-script"], commands)
        self.assertFalse(any("finish" in command for command in commands))
        self.assertFalse((fixture.work / "src/.chromix-toolchain-ready").exists())

    def test_cross_tools_local_resume_checks_sysroots_without_installing(self):
        fixture = self.cross_tools_fixture()
        for _ in range(2):
            result, commands = fixture.run_helper("linux", "arm64", machine="x86_64", compatible=True, ci=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(any(command[0].endswith("install-sysroot.py") for command in commands))
            self.assertEqual(commands[-1][1:3], ["--phase", "finish"])

    def test_cross_tools_reject_missing_or_stale_host_and_target_sysroot(self):
        for ci in (False, True):
            for arch in ("amd64", "arm64"):
                for state in ("missing", "stale", "first-class"):
                    with self.subTest(ci=ci, arch=arch, state=state):
                        fixture = self.cross_tools_fixture()
                        root = fixture.work / f"src/build/linux/debian_bullseye_{arch}-sysroot"
                        if state == "missing":
                            (root / ".stamp").unlink()
                        elif state == "stale":
                            (root / ".stamp").write_text("stale")
                        else:
                            (root / ".fixture_is_first_class_gcs").touch()
                        result, commands = fixture.run_helper("linux", "arm64", machine="x86_64", compatible=True, ci=ci)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn(f"missing or stale {arch} sysroot", result.stderr)
                        self.assertFalse(any("finish" in command for command in commands))
                        self.assertFalse((fixture.work / "src/.chromix-toolchain-ready").exists())

    def test_cross_tools_no_local_compiler_downloads(self):
        fixture = self.cross_tools_fixture()
        result, commands = fixture.run_helper("linux", "arm64", machine="x86_64", ci=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("restricted to GitHub Actions", result.stderr)
        self.assertEqual(len(commands), 1)

    def test_restored_tools_cross_guard_rejects_cold_and_unsupported_pairs(self):
        for platform, arch, machine, restored in (("linux", "arm64", "x86_64", False),
                                                   ("linux", "x64", "aarch64", True),
                                                   ("macos", "arm64", "x86_64", True),
                                                   ("macos", "x64", "arm64", True),
                                                   ("linux", "arm64", "riscv64", True)):
            with self.subTest(platform=platform, arch=arch, machine=machine, restored=restored):
                fixture = self.cross_tools_fixture(restored=restored)
                result, commands = fixture.run_helper(platform, arch, machine=machine, compatible=True)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(commands, [])
                self.assertIn("cold cross builds are unsupported" if not restored else "native", result.stderr)

    def run_restored_target(self, *, before_rc=0, ninja_rc=0, after_rc=0, platform="linux",
                            arch="x64", targets=("chrome",), chrome="created", github_output=True,
                            bash=None):
        with tempfile.TemporaryDirectory(prefix="reuse shell ") as directory:
            root = Path(directory)
            src = root / "work/src"
            out = src / "out/Default"
            out.mkdir(parents=True)
            (src / ".chromix-upstream-restored.json").touch()
            (root / "tools").mkdir()
            calls, output = root / "calls", root / "github output"
            observations = root / "observations"
            observations.mkdir()
            if chrome in ("executable", "nonexecutable", "other-output"):
                binary = (src / "out/Chromix" if chrome == "other-output" else out) / "chrome"
                binary.parent.mkdir(parents=True, exist_ok=True)
                binary.write_text('#!/bin/sh\nexit 99\n')
                binary.chmod(0o644 if chrome == "nonexecutable" else 0o755)
            (root / "tools/restored_reuse_evidence.py").write_text('''import os, sys
from pathlib import Path
args = sys.argv[1:]
phase = args[args.index('--phase') + 1]
output = Path(os.environ['OUTPUT_PATH'])
(Path(os.environ['OBSERVATIONS']) / phase).write_text(output.read_text() if output.exists() else '')
with open(os.environ['CALLS'], 'a') as stream:
    stream.write(phase + (' ' + args[args.index('--exit-code') + 1] if phase == 'after' else '') + '\\n')
sys.exit(int(os.environ['BEFORE_RC' if phase == 'before' else 'AFTER_RC']))
''')
            ninja = root / "selected ninja"
            ninja.write_text('''#!/bin/sh
printf "ninja\\n" >> "$CALLS"
if [ "$NINJA_RC" -eq 0 ] && [ "$CHROME_STATE" = created ]; then
  printf '#!/bin/sh\\nexit 99\\n' > "$OUT/chrome"
  chmod +x "$OUT/chrome"
fi
exit "$NINJA_RC"
''')
            ninja.chmod(0o755)
            env = {**os.environ, "REPO": str(root), "WORK": str(src.parent), "SRC": str(src),
                   "OUT": str(out), "ARCH": arch, "CHROMIX_NINJA": str(ninja),
                   "CALLS": str(calls), "BEFORE_RC": str(before_rc), "AFTER_RC": str(after_rc),
                   "NINJA_RC": str(ninja_rc), "CHROME_STATE": chrome,
                   "OUTPUT_PATH": str(output), "OBSERVATIONS": str(observations)}
            env.pop("GITHUB_OUTPUT", None)
            if github_output:
                env["GITHUB_OUTPUT"] = str(output)
            elif github_output == "":
                env["GITHUB_OUTPUT"] = ""
            result = subprocess.run(
                [str(bash or (BASH32 if BASH32.exists() else shutil.which("bash"))),
                 "-euo", "pipefail", "-c",
                 'source "$1"; shift; chromix_build_restored_target "$@"', "fixture",
                 str(REPO / "build/posix/upstream-cache.sh"), platform, "2", *targets],
                env=env, capture_output=True, text=True, timeout=15)
            return (result, calls.read_text().splitlines(), output.read_text() if output.exists() else "",
                    {path.name: path.read_text() for path in observations.iterdir()})

    def test_actual_build_evidence_gates_and_preserves_ninja_failure(self):
        for before_rc, ninja_rc, after_rc, expected in ((0, 0, 0, 0), (7, 0, 0, 1),
                                                       (0, 1, 0, 1), (0, 13, 0, 13),
                                                       (0, 0, 1, 1), (0, 0, 8, 8), (0, 13, 8, 13)):
            with self.subTest(before=before_rc, ninja=ninja_rc, after=after_rc):
                result, calls, output, observed = self.run_restored_target(
                    before_rc=before_rc, ninja_rc=ninja_rc, after_rc=after_rc, chrome="executable")
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                self.assertEqual(calls, ["before"] if before_rc else
                                 ["before", "ninja", f"after {ninja_rc}"])
                compiled = "compiled_ready=true\n" if not before_rc and not ninja_rc else ""
                self.assertEqual(output, compiled)
                self.assertEqual(observed, {"before": ""} if before_rc else {"before": "", "after": compiled})

    def test_successful_linux_compile_is_reported_before_failed_evidence(self):
        shells = [shutil.which("bash")]
        if BASH32.exists():
            shells.append(BASH32)
        for bash in shells:
            for arch in ("x64", "arm64"):
                with self.subTest(bash=bash, arch=arch):
                    result, calls, output, observed = self.run_restored_target(
                        after_rc=1, arch=arch, targets=("chrome_crashpad_handler", "chrome", "chrome_sandbox"),
                        bash=bash)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertEqual(calls, ["before", "ninja", "after 0"])
                    self.assertEqual(output, "compiled_ready=true\n")
                    self.assertEqual(observed, {"before": "", "after": output})
                    for claim in ("finished", "package_ready", "runtime_verified"):
                        self.assertNotIn(claim, output)

    def test_compiled_progress_requires_linux_chrome_target_and_current_executable(self):
        for kwargs in ({"platform": "macos", "chrome": "executable"},
                       {"targets": ("chrome_sandbox",), "chrome": "executable"},
                       {"targets": ("chrome_crashpad_handler",), "chrome": "executable"},
                       {"targets": (), "chrome": "executable"},
                       {"chrome": "missing"}, {"chrome": "nonexecutable"}, {"chrome": "other-output"}):
            with self.subTest(**kwargs):
                result, calls, output, observed = self.run_restored_target(after_rc=1, **kwargs)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(calls, ["before", "ninja", "after 0"])
                self.assertEqual(output, "")
                self.assertEqual(observed, {"before": "", "after": ""})

    def test_local_compile_without_github_output_keeps_evidence_result(self):
        for github_output in (False, ""):
            for after_rc in (0, 1):
                with self.subTest(github_output=github_output, after=after_rc):
                    result, calls, output, observed = self.run_restored_target(
                        after_rc=after_rc, github_output=github_output)
                    self.assertEqual(result.returncode, after_rc, result.stdout + result.stderr)
                    self.assertEqual(calls, ["before", "ninja", "after 0"])
                    self.assertEqual(output, "")
                    self.assertEqual(observed, {"before": "", "after": ""})

    def run_helper(self, bash, enabled):
        with tempfile.TemporaryDirectory(prefix="cache shell ") as directory:
            root = Path(directory)
            repo = root / "repo"
            (repo / "tools").mkdir(parents=True)
            log = root / "args"
            (repo / "tools/import_upstream_cache.py").write_text(
                'import os, sys\nfrom pathlib import Path\n'
                'Path(os.environ["TEST_CACHE_LOG"]).write_text("\\n".join(sys.argv[1:]))\n')
            env = {**os.environ, "REPO": str(repo), "WORK": str(root / "work"),
                   "ARCH": "arm64", "TEST_CACHE_LOG": str(log)}
            env.pop("CHROMIX_UPSTREAM_CACHE_DIR", None)
            if enabled:
                env["CHROMIX_UPSTREAM_CACHE_DIR"] = str(root / "cache with spaces")
            result = subprocess.run(
                [str(bash), "-euo", "pipefail", "-c",
                 'source "$1"; chromix_import_upstream_cache toolchain linux',
                 "fixture", str(REPO / "build/posix/upstream-cache.sh")],
                capture_output=True, text=True, env=env, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            if enabled:
                self.assertEqual(log.read_text().splitlines(), [
                    "--phase", "toolchain", "--platform", "linux", "--arch", "arm64",
                    "--workdir", str(root / "work"), "--cache-dir", str(root / "cache with spaces")])
            else:
                self.assertFalse(log.exists())

    def test_object_wrapper_survives_stage_resume_without_donor_environment(self):
        with tempfile.TemporaryDirectory(prefix="object wrapper ") as directory:
            root = Path(directory)
            out = root / "src/out/Chromix"
            out.mkdir(parents=True)
            args = out / "args.gn"
            (root / "cache").mkdir()
            (root / "cache/result.json").write_text(json.dumps({"status": "hit", "extraction_scope": "source-and-objects"}))
            env = {**os.environ, "REPO": str(root / "repo with spaces"),
                   "WORK": str(root), "OUT": str(out), "CHROMIX_UPSTREAM_CACHE_DIR": str(root / "cache")}
            for resumed in (False, True):
                if resumed:
                    env.pop("CHROMIX_UPSTREAM_CACHE_DIR")
                args.write_text('is_debug = false\n')
                result = subprocess.run(
                    [str(BASH32 if BASH32.exists() else shutil.which("bash")), "-euo", "pipefail", "-c",
                     'source "$1"; chromix_configure_upstream_objects', "fixture",
                     str(REPO / "build/posix/upstream-cache.sh")],
                    env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                lines = args.read_text().splitlines()
                self.assertEqual(lines[0], "is_debug = false")
                command = json.loads(lines[1].split(" = ", 1)[1])
                self.assertEqual(command, "python3 '" + str(root / "repo with spaces/tools/upstream_object_cache.py") + "' compile --")
                self.assertTrue((root / ".chromix-object-wrapper").is_file())

    def test_failed_download_does_not_enable_compiler_wrapper(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            out = root / "src/out/Chromix"
            out.mkdir(parents=True)
            (out / "args.gn").write_text('is_debug = false\n')
            result = subprocess.run(
                [shutil.which("bash"), "-euo", "pipefail", "-c",
                 'source "$1"; chromix_configure_upstream_objects', "fixture",
                 str(REPO / "build/posix/upstream-cache.sh")],
                env={**os.environ, "WORK": str(root), "OUT": str(out), "REPO": str(REPO),
                     "CHROMIX_UPSTREAM_CACHE_DIR": str(root / "absent")},
                capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("cc_wrapper", (out / "args.gn").read_text())
            self.assertFalse((root / ".chromix-object-wrapper").exists())

    def test_restore_diagnostic_is_finalized_before_handoff(self):
        source = (REPO / "build/posix/ci-stage.sh").read_text()
        self.assertIn("upstream-cache-restore.json", (REPO / ".github/workflows/build-posix-github.yml").read_text())
        self.assertLess(source.index("--phase restore"), source.index('"$TIMEOUT" -k 7m'))
        self.assertIn(".chromix-upstream-restored.json", source)

    def test_disabled_cache_is_noop(self):
        self.run_helper(shutil.which("bash"), False)

    def test_cache_paths_are_quoted(self):
        self.run_helper(shutil.which("bash"), True)

    @unittest.skipUnless(BASH32.exists(), "Bash 3.2 required")
    def test_bash32_enabled_and_disabled(self):
        self.run_helper(BASH32, False)
        self.run_helper(BASH32, True)


if __name__ == "__main__":
    unittest.main()
