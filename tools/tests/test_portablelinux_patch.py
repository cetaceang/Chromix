"""Exercise the pinned Linux patch repair with GNU patch, not Chromium builds."""
import ast
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
PREPARE = REPO / "build/prepare-ungoogled.sh"
PATCH_REL = "ungoogled-chromium/portablelinux/fix-compiling-on-arm64.patch"
RECOVERY_REL = "build/linux/recovery/153.0.8010.36-1-arm64.patch"
EXACT_153 = {
    "version": "153.0.8010.36",
    "core": "dd8fb9b5c837982faf41ba58cd30a5664e77c329",
    "commit": "a5ffa5e4a9fb722b97a5cf7966e29450a150c3dd",
    "platform_version": "153.0.8010.36-1",
}
ORIGINAL_153_SHA256 = "4a848abdacb9b677b3d309a8a8b6597250aeaf4c1b4a009f16faf490e55103ad"
RECOVERY_153_SHA256 = "b27db03071f007b40af4861b73a40af7c73c5d8cb2be3f6aada471b1fa2cbb1a"

# Verbatim from ungoogled-chromium-portablelinux 02c59ed68d1963a647bb478064823d114e466ffb.
PINNED_PATCH = '''\
--- a/build/toolchain/linux/BUILD.gn
+++ b/build/toolchain/linux/BUILD.gn
@@ -179,6 +179,13 @@ clang_v8_toolchain("clang_x64_v8_loong64
   }
 }
\x20
+clang_v8_toolchain("clang_arm64_v8_x64") {
+  toolchain_args = {
+    current_cpu = "arm64"
+    v8_current_cpu = "x64"
+  }
+}
+
 gcc_toolchain("x64") {
   cc = "gcc"
   cxx = "g++"
--- a/tools/rust/build_rust.py
+++ b/tools/rust/build_rust.py
@@ -55,7 +55,7 @@ sys.path.append(
                  'scripts'))
\x20
 from build import (AddCMakeToPath, AddZlibToPath, CheckoutGitRepo, CopyFile,
                   DownloadDebianSysroot, FetchUrl, GetLibXml2Dirs,
-                  GitCherryPick, GitRevert, LLVM_DIR, IsGitAncestorToHead,
+                  GetHostSysrootPlatform, GitRevert, LLVM_DIR, IsGitAncestorToHead,
                   LLVM_BUILD_TOOLS_DIR, RunCommand,
                   DEFAULT_MACOSX_DEPLOYMENT_TARGET, GetLatestCommit)
 from update import (CHROMIUM_DIR, DownloadAndUnpack, EnsureDirExists,
@@ -161,8 +161,8 @@ def AddOpenSSLToEnv():
         ssl_url = (f'{CIPD_DOWNLOAD_URL}/{OPENSSL_CIPD_WIN_AMD_PATH}'
                    f'/+/version:2@{OPENSSL_CIPD_WIN_AMD_VERSION}')
     else:
-        ssl_url = (f'{CIPD_DOWNLOAD_URL}/{OPENSSL_CIPD_LINUX_AMD_PATH}'
-                   f'/+/version:2@{OPENSSL_CIPD_LINUX_AMD_VERSION}')
+            ssl_url = (f'{CIPD_DOWNLOAD_URL}/{OPENSSL_CIPD_LINUX_AMD_PATH.replace("amd64", GetHostSysrootPlatform())}'
+                    f'/+/version:2@{OPENSSL_CIPD_LINUX_AMD_VERSION}')
\x20
     if os.path.exists(ssl_dir):
         RmTree(ssl_dir)
@@ -515,7 +515,7 @@ def RustTargetTriple():
     elif sys.platform == 'win32':
         return 'x86_64-pc-windows-msvc'
     else:
-        return 'x86_64-unknown-linux-gnu'
+        return f'{platform.machine()}-unknown-linux-gnu'
\x20
\x20
 # Build the LLVM libraries and install them .
@@ -526,6 +526,9 @@ def BuildLLVMLibraries(skip_build):
             sys.executable,
             os.path.join(CLANG_SCRIPTS_DIR, 'build.py'),
             '--disable-asserts',
+            '--use-system-cmake',
+            '--host-cc=clang',
+            '--host-cxx=clang++',
             '--no-tools',
             '--no-runtimes',
             # PIC needed for Rust build (links LLVM into shared object)
@@ -678,7 +681,8 @@ def main():
         # Fetch sysroot we build rustc against. This ensures a minimum supported
         # host (not Chromium target). Since the rustc linux package is for
         # x86_64 only, that is the sole needed sysroot.
-        debian_sysroot = DownloadDebianSysroot('amd64', args.skip_checkout)
+        debian_sysroot = DownloadDebianSysroot(
+            GetHostSysrootPlatform(), args.skip_checkout)
\x20
     # Require zlib compression.
     if sys.platform == 'win32':
--- a/tools/rust/cargo-config.toml.template
+++ b/tools/rust/cargo-config.toml.template
@@ -21,3 +21,8 @@ host-config = true
 # Use the same sysroot for host artifacts as target artifacts. Target rustflags
 # are configured via environment variables.
 rustflags = ["-Clink-arg=--sysroot=$DEBIAN_SYSROOT"]
+
+[host.aarch64-unknown-linux-gnu]
+# Use the same sysroot for host artifacts as target artifacts. Target rustflags
+# are configured via environment variables.
+rustflags = ["-Clink-arg=--sysroot=$DEBIAN_SYSROOT"]
--- a/tools/rust/config.toml.template
+++ b/tools/rust/config.toml.template
@@ -87,3 +87,12 @@ cc = "$LLVM_BIN/clang"
 cxx = "$LLVM_BIN/clang++"
 linker = "$LLVM_BIN/clang"
\x20
+[target.aarch64-unknown-linux-gnu]
+llvm-config = "$LLVM_BIN/llvm-config"
+# TODO(danakj): We don't ship this in the clang toolchain package.
+# ranlib = "$LLVM_BIN/llvm-ranlib"
+ar = "$LLVM_BIN/llvm-ar"
+cc = "$LLVM_BIN/clang"
+cxx = "$LLVM_BIN/clang++"
+linker = "$LLVM_BIN/clang"
+
--- a/tools/rust/build_bindgen.py
+++ b/tools/rust/build_bindgen.py
@@ -23,7 +23,7 @@ sys.path.append(
                  'scripts'))
\x20
 from build import (CheckoutGitRepo, DownloadAndUnpack, LLVM_BUILD_TOOLS_DIR,
-                   DownloadDebianSysroot, RunCommand)
+                   DownloadDebianSysroot, GetHostSysrootPlatform, RunCommand)
 from update import (RmTree)
\x20
 # The git hash to use.
@@ -66,7 +66,7 @@ def InstallRustBetaSysroot(rust_git_hash
 def FetchNcurseswLibrary():
     assert sys.platform.startswith('linux')
     ncursesw_dir = os.path.join(LLVM_BUILD_TOOLS_DIR, 'ncursesw')
-    ncursesw_url = (f'{CIPD_DOWNLOAD_URL}/{NCURSESW_CIPD_LINUX_AMD_PATH}'
+    ncursesw_url = (f'{CIPD_DOWNLOAD_URL}/{NCURSESW_CIPD_LINUX_AMD_PATH.replace("amd64", GetHostSysrootPlatform())}'
                     f'/+/version:2@{NCURSESW_CIPD_LINUX_AMD_VERSION}')
\x20
     if os.path.exists(ncursesw_dir):
@@ -146,7 +146,7 @@ def RunCargo(cargo_args):
\x20
     if sys.platform.startswith('linux'):
         # We use these flags to avoid linking with the system libstdc++.
-        sysroot = DownloadDebianSysroot('amd64')
+        sysroot = DownloadDebianSysroot(GetHostSysrootPlatform())
         sysroot_flag = f'--sysroot={sysroot}'
         env['CFLAGS'] += f' {sysroot_flag}'
         env['CXXFLAGS'] += f' {sysroot_flag}'
--- a/tools/clang/scripts/build.py
+++ b/tools/clang/scripts/build.py
@@ -483,6 +483,21 @@ def DownloadPinnedClang():
                            PINNED_CLANG_VERSION)
\x20
\x20
+def GetHostSysrootPlatform():
+  assert sys.platform == 'linux', \\
+    "This patch only applies to Linux, where platform.machine() is predictable"
+
+  arch = platform.machine()
+  return {
+    "aarch64": "arm64",
+    "aarch64_be": "arm64",
+    "armv7l": "arm",
+    "armv8b": "arm64",
+    "armv8l": "arm64",
+    "x86_64": "amd64",
+  }.get(arch, arch)
+
+
 def VerifyVersionOfBuiltClangMatchesVERSION():
   """Checks that `clang --version` outputs RELEASE_VERSION. If this
   fails, update.RELEASE_VERSION is out-of-date and needs to be updated (possibly
'''
CORRECTED_PATCH = PINNED_PATCH.replace("@@ -55,7 +55,7 @@", "@@ -55,8 +55,8 @@", 1)


# Verbatim portablelinux a5ffa5e4a9fb722b97a5cf7966e29450a150c3dd payload.
PINNED_PATCH_153 = '''\
--- a/build/toolchain/linux/BUILD.gn
+++ b/build/toolchain/linux/BUILD.gn
@@ -179,6 +179,13 @@ clang_v8_toolchain("clang_x64_v8_loong64
   }
 }
\x20
+clang_v8_toolchain("clang_arm64_v8_x64") {
+  toolchain_args = {
+    current_cpu = "arm64"
+    v8_current_cpu = "x64"
+  }
+}
+
 gcc_toolchain("x64") {
   cc = "gcc"
   cxx = "g++"
--- a/tools/rust/build_rust.py
+++ b/tools/rust/build_rust.py
@@ -65,7 +65,7 @@
     DownloadDebianSysroot,
     FetchUrl,
     GetLibXml2Dirs,
-    GitCherryPick,
+    GetHostSysrootPlatform,
     GitRevert,
     LLVM_DIR,
     IsGitAncestorToHead,
@@ -254,7 +254,7 @@
         )
     else:
         ssl_url = (
-            f'{CIPD_DOWNLOAD_URL}/{OPENSSL_CIPD_LINUX_AMD_PATH}'
+            f'{CIPD_DOWNLOAD_URL}/{OPENSSL_CIPD_LINUX_AMD_PATH.replace("amd64", GetHostSysrootPlatform()}'
             f'/+/version:2@{OPENSSL_CIPD_LINUX_AMD_VERSION}'
         )
\x20
     if os.path.exists(ssl_dir):
         RmTree(ssl_dir)
@@ -515,7 +515,7 @@ def RustTargetTriple():
     elif sys.platform == 'win32':
         return 'x86_64-pc-windows-msvc'
     else:
-        return 'x86_64-unknown-linux-gnu'
+        return f'{platform.machine()}-unknown-linux-gnu'
\x20
\x20
 # Build the LLVM libraries and install them .
@@ -526,6 +526,9 @@ def BuildLLVMLibraries(skip_build):
             sys.executable,
             os.path.join(CLANG_SCRIPTS_DIR, 'build.py'),
             '--disable-asserts',
+            '--use-system-cmake',
+            '--host-cc=clang',
+            '--host-cxx=clang++',
             '--no-tools',
             '--no-runtimes',
             # PIC needed for Rust build (links LLVM into shared object)
@@ -678,7 +681,8 @@ def main():
         # Fetch sysroot we build rustc against. This ensures a minimum supported
         # host (not Chromium target). Since the rustc linux package is for
         # x86_64 only, that is the sole needed sysroot.
-        debian_sysroot = DownloadDebianSysroot('amd64', args.skip_checkout)
+        debian_sysroot = DownloadDebianSysroot(
+            GetHostSysrootPlatform(), args.skip_checkout)
\x20
     # Require zlib compression.
     if sys.platform == 'win32':
--- a/tools/rust/cargo-config.toml.template
+++ b/tools/rust/cargo-config.toml.template
@@ -21,3 +21,8 @@ host-config = true
 # Use the same sysroot for host artifacts as target artifacts. Target rustflags
 # are configured via environment variables.
 rustflags = ["-Clink-arg=--sysroot=$DEBIAN_SYSROOT"]
+
+[host.aarch64-unknown-linux-gnu]
+# Use the same sysroot for host artifacts as target artifacts. Target rustflags
+# are configured via environment variables.
+rustflags = ["-Clink-arg=--sysroot=$DEBIAN_SYSROOT"]
--- a/tools/rust/config.toml.template
+++ b/tools/rust/config.toml.template
@@ -87,3 +87,12 @@ cc = "$LLVM_BIN/clang"
 cxx = "$LLVM_BIN/clang++"
 linker = "$LLVM_BIN/clang"
\x20
+[target.aarch64-unknown-linux-gnu]
+llvm-config = "$LLVM_BIN/llvm-config"
+# TODO(danakj): We don't ship this in the clang toolchain package.
+# ranlib = "$LLVM_BIN/llvm-ranlib"
+ar = "$LLVM_BIN/llvm-ar"
+cc = "$LLVM_BIN/clang"
+cxx = "$LLVM_BIN/clang++"
+linker = "$LLVM_BIN/clang"
+
--- a/tools/rust/build_bindgen.py
+++ b/tools/rust/build_bindgen.py
@@ -35,6 +35,7 @@
     DownloadAndUnpack,
     LLVM_BUILD_TOOLS_DIR,
     DownloadDebianSysroot,
+    GetHostSysrootPlatform,
     RunCommand,
 )
 from update import RmTree

\x20
 # The git hash to use.
@@ -78,7 +78,7 @@
     assert sys.platform.startswith('linux')
     ncursesw_dir = os.path.join(LLVM_BUILD_TOOLS_DIR, 'ncursesw')
     ncursesw_url = (
-        f'{CIPD_DOWNLOAD_URL}/{NCURSESW_CIPD_LINUX_AMD_PATH}'
+        f'{CIPD_DOWNLOAD_URL}/{NCURSESW_CIPD_LINUX_AMD_PATH.replace("amd64", GetHostSysrootPlatform()}'
         f'/+/version:2@{NCURSESW_CIPD_LINUX_AMD_VERSION}'
     )
\x20
     if os.path.exists(ncursesw_dir):
@@ -146,7 +146,7 @@ def RunCargo(cargo_args):
\x20
     if sys.platform.startswith('linux'):
         # We use these flags to avoid linking with the system libstdc++.
-        sysroot = DownloadDebianSysroot('amd64')
+        sysroot = DownloadDebianSysroot(GetHostSysrootPlatform())
         sysroot_flag = f'--sysroot={sysroot}'
         env['CFLAGS'] += f' {sysroot_flag}'
         env['CXXFLAGS'] += f' {sysroot_flag}'
--- a/tools/clang/scripts/build.py
+++ b/tools/clang/scripts/build.py
@@ -483,6 +483,21 @@ def DownloadPinnedClang():
                            PINNED_CLANG_VERSION)
\x20
\x20
+def GetHostSysrootPlatform():
+  assert sys.platform == 'linux', \\
+    "This patch only applies to Linux, where platform.machine() is predictable"
+
+  arch = platform.machine()
+  return {
+    "aarch64": "arm64",
+    "aarch64_be": "arm64",
+    "armv7l": "arm",
+    "armv8b": "arm64",
+    "armv8l": "arm64",
+    "x86_64": "amd64",
+  }.get(arch, arch)
+
+
 def VerifyVersionOfBuiltClangMatchesVERSION():
   """Checks that `clang --version` outputs RELEASE_VERSION. If this
   fails, update.RELEASE_VERSION is out-of-date and needs to be updated (possibly
'''


def source_fixture(patched=False):
    """Build sparse file contents from every hunk, ignoring the broken count."""
    files = {}
    for section in PINNED_PATCH.split("--- a/")[1:]:
        name, _, body = section.partition("\n")
        lines = []
        delta = 0
        hunks = re.split(r"^@@ -(\d+),\d+ \+\d+,\d+ @@[^\n]*\n", body,
                         flags=re.MULTILINE)
        for index in range(1, len(hunks), 2):
            start = int(hunks[index]) - 1
            hunk = hunks[index + 1].splitlines(keepends=True)
            old = [line[1:] for line in hunk if line.startswith((" ", "-"))]
            new = [line[1:] for line in hunk if line.startswith((" ", "+"))]
            old_end = len(lines) - (delta if patched else 0)
            lines.extend(f"# fixture line {i + 1}\n" for i in range(old_end, start))
            lines.extend(new if patched else old)
            delta += len(new) - len(old)
        files[name] = "".join(lines)
    return files


class PortableLinuxPatchTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="chromix portablelinux patch ")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.patches = self.root / "patches"
        self.patch = self.patches / PATCH_REL
        self.patch.parent.mkdir(parents=True)
        self.patch.write_text(PINNED_PATCH)
        self.repo = self.root / "repo"
        self.recovery = self.repo / RECOVERY_REL
        self.recovery.parent.mkdir(parents=True)
        shutil.copy2(REPO / RECOVERY_REL, self.recovery)
        script = PREPARE.read_text()
        start = script.index('if [ "$PLATFORM" = linux ]; then\n')
        end = script.index('\nPATCH_BIN=', start)
        self.repair = script[start:end]

    def run_repair(self, platform="linux", *, version="152.0.7977.82",
                   core="e71b91c6e336d0f25cfc6b9ef09298a9d2506e24",
                   commit="02c59ed68d1963a647bb478064823d114e466ffb",
                   platform_version="152.0.7977.82-1.1"):
        env = dict(os.environ, PLATFORM=platform, PLATFORM_PATCHES=str(self.patches),
                   CHROMIUM_VERSION=version, CORE_COMMIT=core, PLATFORM_COMMIT=commit,
                   PLATFORM_VERSION=platform_version, REPO=str(self.repo))
        env.pop("BASH_ENV", None)
        return subprocess.run(["bash", "-euo", "pipefail", "-c", self.repair],
                              env=env, capture_output=True, text=True, timeout=15)

    def apply_patch(self):
        patch_bin = shutil.which("gpatch") or shutil.which("patch")
        if not patch_bin:
            self.skipTest("GNU patch is required")
        version = subprocess.run([patch_bin, "--version"], capture_output=True,
                                 text=True, timeout=15)
        if "GNU patch" not in version.stdout:
            self.skipTest("GNU patch is required")
        src = self.root / "src"
        for name, content in source_fixture().items():
            path = src / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        result = subprocess.run(
            [patch_bin, "-p1", "--ignore-whitespace", "--forward", "--batch",
             "--no-backup-if-mismatch", "-i", str(self.patch), "-d", str(src)],
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return src

    def test_malformed_patch_succeeds_but_silently_skips_four_rust_hunks(self):
        src = self.apply_patch()
        rust_name = "tools/rust/build_rust.py"
        expected = source_fixture()[rust_name].replace(
            "GitCherryPick, GitRevert", "GetHostSysrootPlatform, GitRevert", 1)
        rust = (src / rust_name).read_text()
        self.assertEqual(rust, expected)
        self.assertIn("return 'x86_64-unknown-linux-gnu'", rust)
        self.assertIn("DownloadDebianSysroot('amd64', args.skip_checkout)", rust)
        for name, content in source_fixture(patched=True).items():
            if name != rust_name:
                self.assertEqual((src / name).read_text(), content, name)

    def test_repaired_patch_applies_all_hunks_in_all_six_files(self):
        result = self.run_repair()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.patch.read_text(), CORRECTED_PATCH)
        src = self.apply_patch()
        expected = source_fixture(patched=True)
        self.assertEqual(len(expected), 6)
        for name, content in expected.items():
            self.assertEqual((src / name).read_text(), content, name)

    def test_already_corrected_patch_is_not_rewritten(self):
        self.patch.write_text(CORRECTED_PATCH)
        before = self.patch.stat().st_mtime_ns
        for _ in range(2):
            result = self.run_repair()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.patch.read_text(), CORRECTED_PATCH)
            self.assertEqual(self.patch.stat().st_mtime_ns, before)

    def test_unexpected_payload_fails_without_modification(self):
        variants = {
            "missing header": PINNED_PATCH.replace("@@ -55,7 +55,7 @@", "@@ -56,7 +56,7 @@"),
            "changed import": PINNED_PATCH.replace("GitCherryPick", "ChangedImport"),
            "changed later hunk": PINNED_PATCH.replace("platform.machine()", "platform.processor()"),
            "changed corrected patch": CORRECTED_PATCH.replace("platform.machine()", "platform.processor()"),
            "duplicate payload": PINNED_PATCH + PINNED_PATCH,
            "empty patch": "",
        }
        for name, content in variants.items():
            with self.subTest(name=name):
                self.patch.write_text(content)
                result = self.run_repair()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("unexpected portablelinux ARM64 patch", result.stderr)
                self.assertEqual(self.patch.read_text(), content)

    def test_unverified_pin_fails_closed_without_reusing_old_repair(self):
        for pins in (
            {"version": "153.0.8010.36", "core": "dd8fb9b5c837982faf41ba58cd30a5664e77c329",
             "commit": "a5ffa5e4a9fb722b97a5cf7966e29450a150c3dd"},
            {"version": "153.0.8010.36"}, {"core": "a" * 40}, {"commit": "b" * 40},
        ):
            with self.subTest(pins=pins):
                before = self.patch.read_bytes(), self.patch.stat().st_mtime_ns
                result = self.run_repair(**pins)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("repair is unverified", result.stderr)
                self.assertIn("refusing cold preparation", result.stderr)
                self.assertEqual((self.patch.read_bytes(), self.patch.stat().st_mtime_ns), before)

    def test_153_exact_original_is_replaced_and_repaired_payload_is_idempotent(self):
        self.assertEqual(hashlib.sha256(PINNED_PATCH_153.encode()).hexdigest(), ORIGINAL_153_SHA256)
        self.assertEqual(hashlib.sha256(self.recovery.read_bytes()).hexdigest(), RECOVERY_153_SHA256)
        self.patch.write_text(PINNED_PATCH_153)
        result = self.run_repair(**EXACT_153)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.patch.read_bytes(), self.recovery.read_bytes())
        before = self.patch.read_bytes(), self.patch.stat().st_mtime_ns
        for _ in range(2):
            result = self.run_repair(**EXACT_153)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((self.patch.read_bytes(), self.patch.stat().st_mtime_ns), before)

    def test_153_payload_and_tuple_mismatches_fail_without_modification(self):
        corrected = self.recovery.read_text()
        cases = [
            (PINNED_PATCH_153, {**EXACT_153, field: value}, "repair is unverified")
            for field, value in (
                ("version", "154.0.8010.36"), ("core", "a" * 40), ("commit", "b" * 40),
                ("platform_version", "153.0.8010.36-1.1"), ("platform_version", "153.0.8010.36-2"),
            )
        ]
        cases += [(text, EXACT_153, "unexpected portablelinux ARM64 patch") for text in (
            "", PINNED_PATCH, CORRECTED_PATCH, PINNED_PATCH_153 + "\n",
            PINNED_PATCH_153.replace("@@ -254,7 +254,7 @@", "@@ -254,9 +254,9 @@"),
            corrected.replace("platform.machine()", "platform.processor()"),
        )]
        cases.append((corrected, {}, "unexpected portablelinux ARM64 patch"))
        for content, pins, message in cases:
            with self.subTest(pins=pins, content_hash=hashlib.sha256(content.encode()).hexdigest()):
                self.patch.write_text(content)
                before = self.patch.read_bytes(), self.patch.stat().st_mtime_ns
                result = self.run_repair(**pins)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)
                self.assertEqual((self.patch.read_bytes(), self.patch.stat().st_mtime_ns), before)

    def test_153_missing_or_tampered_recovery_fails_before_rewriting(self):
        for recovery in (None, b"", self.recovery.read_bytes() + b"\n"):
            for content in (PINNED_PATCH_153, (REPO / RECOVERY_REL).read_text()):
                with self.subTest(recovery=recovery is None, original=content == PINNED_PATCH_153):
                    self.patch.write_text(content)
                    before = self.patch.read_bytes(), self.patch.stat().st_mtime_ns
                    if recovery is None:
                        self.recovery.unlink(missing_ok=True)
                    else:
                        self.recovery.write_bytes(recovery)
                    result = self.run_repair(**EXACT_153)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("portablelinux ARM64", result.stderr)
                    self.assertEqual((self.patch.read_bytes(), self.patch.stat().st_mtime_ns), before)
        self.patch.unlink()
        result = self.run_repair(**EXACT_153)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing portablelinux ARM64 patch", result.stderr)
        self.assertFalse(self.patch.exists())

    def test_152_does_not_need_153_recovery(self):
        self.recovery.unlink()
        result = self.run_repair()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.patch.read_text(), CORRECTED_PATCH)

    def test_153_all_hunk_counts_and_zero_fuzz_roundtrip(self):
        # Synthetic old sides check parser behavior, not real-source qualification.
        payload = self.recovery.read_text()
        originals, expected = {}, {}
        counts = []
        for section in payload.split("--- a/")[1:]:
            name, _, body = section.partition("\n")
            lines = []
            changed = []
            hunks = re.split(r"^@@ -(\d+),(\d+) \+(\d+),(\d+) @@[^\n]*\n", body,
                             flags=re.MULTILINE)
            count = 0
            for index in range(1, len(hunks), 5):
                old_start, old_count, new_start, new_count = map(int, hunks[index:index + 4])
                hunk = hunks[index + 4].splitlines(keepends=True)
                self.assertTrue(all(line.startswith((" ", "+", "-")) for line in hunk))
                old = [line[1:] for line in hunk if line.startswith((" ", "-"))]
                new = [line[1:] for line in hunk if line.startswith((" ", "+"))]
                self.assertEqual((len(old), len(new)), (old_count, new_count))
                padding = [f"# synthetic line {n + 1}\n" for n in range(len(lines), old_start - 1)]
                lines.extend(padding)
                changed.extend(padding)
                self.assertEqual(len(changed), new_start - 1)
                lines.extend(old)
                changed.extend(new)
                count += 1
            originals[name], expected[name] = "".join(lines), "".join(changed)
            counts.append(count)
        self.assertEqual(counts, [1, 5, 1, 1, 3, 1])
        patch_bin = shutil.which("gpatch") or shutil.which("patch")
        if not patch_bin:
            self.skipTest("GNU patch is required")
        src = self.root / "src153"
        for name, content in originals.items():
            path = src / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        for reverse, contents in ((False, expected), (True, originals)):
            result = subprocess.run(
                [patch_bin, "-p1", "--fuzz=0", "--batch", "--verbose", "--no-backup-if-mismatch",
                 "--reverse" if reverse else "--forward", "-i", str(self.recovery)],
                cwd=src, capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotRegex(result.stdout + result.stderr, r"FAILED|offset|with fuzz|malformed|Skipping")
            self.assertEqual(len(re.findall(r"^Hunk #\d+ succeeded", result.stdout, re.MULTILINE)), 12)
            for name, content in contents.items():
                self.assertEqual((src / name).read_text(), content, name)
        added = [line[1:] for line in payload.splitlines() if line.startswith("+") and not line.startswith("+++")]
        expressions = [line.strip() for line in added if '.replace("amd64", GetHostSysrootPlatform())' in line]
        self.assertEqual(len(expressions), 2)
        for expression in expressions:
            ast.parse(expression, mode="eval")
        self.assertNotIn("-    GitCherryPick,", payload)
        self.assertIn("     GitCherryPick,", payload)
        self.assertFalse(list(src.rglob("*.rej")))

    def test_missing_patch_fails_without_creating_it(self):
        self.patch.unlink()
        result = self.run_repair()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing portablelinux ARM64 patch", result.stderr)
        self.assertFalse(self.patch.exists())

    def test_macos_does_not_read_or_modify_linux_patch(self):
        self.patch.write_text("not a Linux patch")
        result = self.run_repair("macos")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.patch.read_text(), "not a Linux patch")
        self.patch.unlink()
        result = self.run_repair("macos")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.patch.exists())

    def test_repair_precedes_application_and_preserves_layer_order_and_hash(self):
        script = PREPARE.read_text()
        steps = [
            'checkout_pinned "https://github.com/ungoogled-software/$PLATFORM_NAME.git"',
            self.repair,
            'python3 "$CORE_REPO/utils/patches.py" apply "$SRC" "$CORE_REPO/patches"',
            'python3 "$CORE_REPO/utils/patches.py" apply "$SRC" "$PLATFORM_PATCHES"',
            'python3 "$CORE_REPO/utils/prune_binaries.py"',
            'cp -R "$REPO/build/windows/lite-tarball-files/." "$SRC/"',
            '"$REPO/build/apply-patches.sh" "$SRC"',
        ]
        positions = [script.index(step) for step in steps]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("paths = [repo / 'build/prepare-ungoogled.sh'", script)
        result = subprocess.run(["bash", "-n", str(PREPARE)], capture_output=True,
                                text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)


class PreparationPinsTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="chromix preparation pins ")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.repo = self.root / "repo"
        self.work = self.root / "work"
        for name in ("build/prepare-ungoogled.sh", "tools/platform_pins.py", RECOVERY_REL):
            target = self.repo / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / name, target)
        (self.repo / "build/apply-patches.sh").write_text("#!/bin/sh\nexit 0\n")
        (self.repo / "build/windows/lite-tarball-files").mkdir(parents=True)
        (self.repo / "patches").mkdir()
        (self.repo / "patches/series").write_text("# fixture\npatches/one.patch\n")
        (self.repo / "patches/one.patch").write_text("fixture payload\n")
        (self.repo / "CHROMIUM_VERSION").write_text("152.0.7977.82\n")
        (self.repo / "CHROMIUM_LINUX_VERSION").write_text("153.0.8010.36\n")
        self.pins = self.repo / "build/ungoogled-revisions.psd1"
        self.pins.write_text('@{\n'
            '  ChromiumVersion = "152.0.7977.82"\n'
            '  UngoogledVersion = "152.0.7977.82-1"\n'
            '  UngoogledCommit = "e71b91c6e336d0f25cfc6b9ef09298a9d2506e24"\n'
            '  LinuxChromiumVersion = "153.0.8010.36"\n'
            '  LinuxUngoogledVersion = "153.0.8010.36-1"\n'
            '  LinuxUngoogledCommit = "dd8fb9b5c837982faf41ba58cd30a5664e77c329"\n'
            '  UngoogledLinuxVersion = "153.0.8010.36-1"\n'
            '  UngoogledLinuxCommit = "a5ffa5e4a9fb722b97a5cf7966e29450a150c3dd"\n'
            '  UngoogledMacOSVersion = "152.0.7977.82-1.1"\n'
            '  UngoogledMacOSCommit = "038db2b41f7aeb00bbceb2f5a56912b26eb5b284"\n}\n')
        self.env = dict(os.environ)
        self.env.pop("BASH_ENV", None)
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        git = bin_dir / "git"
        git.write_text('#!/bin/sh\nexit 97\n')
        git.chmod(0o755)
        self.env["PATH"] = str(bin_dir) + os.pathsep + self.env["PATH"]

    def run_prepare(self, platform="linux", arch="arm64"):
        return subprocess.run(["bash", str(self.repo / "build/prepare-ungoogled.sh"),
                               str(self.work), platform, arch], env=self.env,
                              capture_output=True, text=True, timeout=15)

    def test_preparation_and_migration_ready_keys_match_for_each_platform(self):
        from tools.migrate_restored_snapshot import source_ready_key

        src = self.work / "src"
        src.mkdir(parents=True)
        for platform in ("linux", "macos"):
            for arch in ("x64", "arm64"):
                with self.subTest(platform=platform, arch=arch):
                    key = source_ready_key(self.repo, platform, arch)
                    version = "153.0.8010.36" if platform == "linux" else "152.0.7977.82"
                    core = ("dd8fb9b5c837982faf41ba58cd30a5664e77c329" if platform == "linux"
                            else "e71b91c6e336d0f25cfc6b9ef09298a9d2506e24")
                    self.assertTrue(key.startswith(f"{platform}|{arch}|{version}|{core}|"))
                    (src / ".chromix-source-ready").write_text(key + "\n")
                    result = self.run_prepare(platform, arch)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("already prepared: " + key, result.stdout)
                    self.assertFalse((self.work / "tooling").exists())
        (src / ".chromix-source-ready").write_text(source_ready_key(self.repo, "linux", "arm64"))
        (self.repo / "patches/one.patch").write_text("changed fixture payload\n")
        result = self.run_prepare()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("use a clean work directory", result.stderr)

    def test_workflow_resolves_current_platform_pins_and_fails_before_export_on_bad_pins(self):
        import yaml

        workflow = yaml.safe_load((REPO / ".github/workflows/build-posix-github.yml").read_text())
        step = next(step for step in workflow["jobs"]["posix-1"]["steps"]
                    if step.get("name") == "Resolve platform Chromium version")
        output = self.root / "github-env"
        for platform, version in (("linux", "153.0.8010.36"), ("macos", "152.0.7977.82")):
            with self.subTest(platform=platform):
                output.write_text("")
                env = dict(self.env, BUILD_PLATFORM=platform, GITHUB_ENV=str(output))
                result = subprocess.run(["bash", "-c", step["run"]], cwd=self.repo,
                                        env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output.read_text(), f"CHROMIUM_VERSION={version}\n")
        (self.repo / "CHROMIUM_LINUX_VERSION").unlink()
        output.write_text("")
        result = subprocess.run(["bash", "-c", step["run"]], cwd=self.repo,
                                env=dict(self.env, BUILD_PLATFORM="linux", GITHUB_ENV=str(output)),
                                capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_text(), "")

    def test_partial_linux_overrides_fail_before_checkout(self):
        (self.repo / "CHROMIUM_LINUX_VERSION").unlink()
        result = self.run_prepare()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must all be present", result.stderr)
        self.assertFalse((self.work / "tooling").exists())

    def test_cold_153_preparation_repairs_both_arches_before_downloader(self):
        core = self.work / "tooling/ungoogled-chromium"
        portable = self.work / "tooling/ungoogled-chromium-portablelinux"
        for path in (core, portable):
            (path / ".git").mkdir(parents=True)
        (core / "chromium_version.txt").write_text("153.0.8010.36\n")
        (core / "revision.txt").write_text("1\n")
        log = self.root / "git-calls"
        git = self.root / "bin/git"
        git.write_text('#!/usr/bin/env python3\n'
                       'import os, sys\n'
                       'from pathlib import Path\n'
                       'assert sys.argv[1] == "-C"\n'
                       'name = Path(sys.argv[2]).name\n'
                       'commit = {"ungoogled-chromium": "dd8fb9b5c837982faf41ba58cd30a5664e77c329",\n'
                       '          "ungoogled-chromium-portablelinux": "a5ffa5e4a9fb722b97a5cf7966e29450a150c3dd"}[name]\n'
                       'args = sys.argv[3:]\n'
                       'if args == ["rev-parse", "HEAD"]:\n'
                       '    print(commit)\n'
                       'else:\n'
                       '    assert args in (["fetch", "--depth", "1", "origin", commit],\n'
                       '                    ["checkout", "--detach", "--force", commit]), args\n'
                       'with open(os.environ["PIN_GIT_LOG"], "a") as stream:\n'
                       '    stream.write(name + " " + " ".join(args) + "\\n")\n')
        self.env["PIN_GIT_LOG"] = str(log)
        patch = portable / "patches" / PATCH_REL
        patch.parent.mkdir(parents=True)
        downloads = core / "utils/downloads.py"
        downloads.parent.mkdir()
        downloads.write_text('import sys\nraise SystemExit("offline downloader sentinel")\n')
        for arch in ("x64", "arm64"):
            for valid in (False, True):
                with self.subTest(arch=arch, valid=valid):
                    log.write_text("")
                    patch.write_text(PINNED_PATCH_153 if valid else "unexpected payload")
                    result = self.run_prepare(arch=arch)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(len(log.read_text().splitlines()), 6)
                    self.assertEqual(list((self.work / "download_cache").iterdir()), [])
                    self.assertFalse((self.work / "src/.chromix-source-ready").exists())
                    if valid:
                        self.assertIn("offline downloader sentinel", result.stderr)
                        self.assertEqual(patch.read_bytes(), (REPO / RECOVERY_REL).read_bytes())
                        self.assertTrue((self.work / "src").is_dir())
                        (self.work / "src").rmdir()
                    else:
                        self.assertIn("unexpected portablelinux ARM64 patch", result.stderr)
                        self.assertNotIn("offline downloader sentinel", result.stderr)
                        self.assertEqual(patch.read_text(), "unexpected payload")
                        self.assertFalse((self.work / "src").exists())

    def test_core_checkout_validation_accepts_platform_core_or_suffix(self):
        script = PREPARE.read_text()
        resolution = script[script.index("revision() {"):script.index("PATCH_HASH=")]
        start = script.index('test "$(cat "$CORE_REPO/chromium_version.txt")"')
        validation = script[start:script.index('if [ "$RESTORED" -eq 1 ]; then', start)]
        core = self.root / "core"
        core.mkdir()
        (core / "chromium_version.txt").write_text("153.0.8010.36\n")
        (core / "revision.txt").write_text("1\n")
        env = dict(self.env, REPO=str(self.repo), PLATFORM="linux", PLATFORM_KEY="UngoogledLinux",
                   CORE_REPO=str(core))
        original = self.pins.read_text()
        for revision in ("153.0.8010.36-1", "153.0.8010.36-1.1", "153.0.8010.36-10"):
            with self.subTest(revision=revision):
                self.pins.write_text(original.replace('UngoogledLinuxVersion = "153.0.8010.36-1"',
                                                     f'UngoogledLinuxVersion = "{revision}"'))
                result = subprocess.run(["bash", "-euo", "pipefail", "-c", resolution + validation],
                                        env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode == 0, revision != "153.0.8010.36-10", result.stderr)
        self.pins.write_text(original)
        (core / "revision.txt").write_text("2\n")
        result = subprocess.run(["bash", "-euo", "pipefail", "-c", resolution + validation],
                                env=env, capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
