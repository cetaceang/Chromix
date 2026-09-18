import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import zipfile
import zlib
from unittest import mock

from tools import download_posix_snapshot as base
from tools import download_windows_snapshot as snapshot
from tools.tests.test_download_posix_snapshot import (
    HTTPSFixture, REPO, SHA, SIGNED, TOKEN, Response, digest, zip_bytes,
)


class DownloadWindowsSnapshotTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.destination = self.root / "restore"
        self.report_path = self.root / "report.json"
        self.manifest_path = self.root / "manifest.json"
        self.data = zip_bytes([("tree.7z.001", "file", b"volume-one")])
        self.manifest = {"repository": REPO, "head_sha": SHA, "run_id": 34572987341,
                         "platform": "windows", "arch": "arm64", "artifacts": []}
        self.set_artifacts([self.data])
        self.client = snapshot.GitHub(TOKEN)
        self.requests = []
        self.responses = []
        self.queue(Response(self.data))

    def set_artifacts(self, bodies):
        self.manifest["artifacts"] = [
            {"id": 101 + index, "name": f"snapshot-part{index + 1}",
             "size_in_bytes": len(body), "expired": False, "digest": digest(body)}
            for index, body in enumerate(bodies)]
        self.save_manifest()

    def save_manifest(self):
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")

    def queue(self, *events, on_request=None):
        events = iter(events)

        def open_request(request, timeout):
            self.requests.append(request)
            self.assertEqual(request.get_method(), "GET")
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, base.TIMEOUT)
            if on_request is not None:
                on_request(request)
            event = next(events)
            if isinstance(event, BaseException):
                raise event
            self.responses.append(event)
            return event

        self.client.opener.open = mock.Mock(side_effect=open_request)

    def download(self, **kwargs):
        return snapshot.download_snapshot(self.manifest_path, self.destination,
                                          self.report_path, client=self.client, **kwargs)

    def report(self):
        return json.loads(self.report_path.read_text(encoding="utf-8"))

    def assert_redacted(self, value):
        for secret in (TOKEN, SIGNED, "fixture-signed-secret", "sig="):
            self.assertNotIn(secret, value)

    def assert_clean_failure(self, reason, **kwargs):
        with self.assertRaises(snapshot.SnapshotError) as raised:
            self.download(**kwargs)
        self.assertEqual(str(raised.exception), reason)
        self.assertFalse(os.path.lexists(self.destination))
        self.assertEqual(list(self.root.glob(".restore.staging-*")), [])
        self.assertEqual(list(self.root.glob(".snapshot-report-*")), [])
        self.assertEqual(self.report()["status"], "failed")
        self.assertEqual(self.report()["reason"], reason)
        self.assert_redacted(str(raised.exception))
        self.assert_redacted(self.report_path.read_text())

    def cli(self, *extra):
        with mock.patch.object(snapshot, "GitHub", return_value=self.client), \
                mock.patch("sys.stdout", new=io.StringIO()) as stdout, \
                mock.patch("sys.stderr", new=io.StringIO()) as stderr:
            code = snapshot.main(["--manifest", str(self.manifest_path),
                                  "--destination", str(self.destination),
                                  "--report", str(self.report_path), *extra])
        self.assert_redacted(stdout.getvalue() + stderr.getvalue())
        return code, stdout.getvalue(), stderr.getvalue()

    def test_stage9_manifest_preserves_exact_donor_and_artifact_identity(self):
        self.manifest.update(head_sha='30dbab28692793fa311c82ae639186003f3a67d9',
                             run_id=35315624638, stage=9, attempt=1, arch='x64')
        second = zip_bytes([('tree.7z.002', 'file', b'volume-two')])
        self.set_artifacts([self.data, second])
        for index, identifier in enumerate((10536907942, 10536997738)):
            self.manifest['artifacts'][index].update(id=identifier, name=f'tree-s9-attempt-1-part{index + 1}')
        self.save_manifest()
        self.queue(Response(self.data), Response(second))
        self.download()
        self.assertEqual((self.destination / 'tree.7z.001').read_bytes(), b'volume-one')
        self.assertEqual((self.destination / 'tree.7z.002').read_bytes(), b'volume-two')
        self.assertEqual(self.report()['status'], 'success')
        self.assertIn('10536907942', self.requests[0].full_url)
        self.assertIn('10536997738', self.requests[1].full_url)

    def test_reuses_client_and_helpers_without_modifying_posix_globals(self):
        globals_before = dict(vars(base))
        self.assertIs(snapshot.GitHub, base.GitHub)
        self.assertIs(snapshot.require_space, base.require_space)
        self.assertIs(snapshot.remaining, base.remaining)
        self.download()
        self.assertEqual(globals_before.keys(), vars(base).keys())
        for name, value in globals_before.items():
            self.assertIs(vars(base)[name], value, name)

    def test_four_artifacts_eight_volumes_and_report_publication_order(self):
        bodies = [zip_bytes([(f"part/tree.7z.{index:03d}", "file", str(index).encode()),
                             (f"tree.7z.{index + 1:03d}", "file", str(index + 1).encode())],
                            zipfile.ZIP_DEFLATED) for index in (7, 3, 1, 5)]
        self.set_artifacts(bodies)
        order = []

        def hidden(request):
            self.assertFalse(self.destination.exists())
            self.assertEqual(list(self.root.glob(".restore.staging-*/*.zip")), [])

        self.queue(*(Response(body, short_read=5) for body in bodies), on_request=hidden)
        original = snapshot.publish

        def publish(staging, destination):
            order.append("publish")
            self.assertEqual(staging.parent, destination.parent)
            self.assertEqual(self.report()["status"], "verified")
            self.assertEqual(self.report()["publication"], "unconfirmed")
            self.assertEqual(len(self.report()["volumes"]), 8)
            original(staging, destination)

        original_write = snapshot.write_report

        def write(path, result):
            order.append(result["status"])
            original_write(path, result)

        with mock.patch.object(snapshot, "publish", side_effect=publish), \
                mock.patch.object(snapshot, "write_report", side_effect=write):
            result = self.download()
        self.assertEqual(order, ["verified", "publish", "success"])
        self.assertEqual(result, self.report())
        self.assertEqual((result["status"], result["publication"], result["phase"]),
                         ("success", "published", "complete"))
        self.assertEqual(result["total_size_in_bytes"], 8)
        self.assertEqual((result["repository"], result["head_sha"], result["run_id"]),
                         (REPO, SHA, self.manifest["run_id"]))
        self.assertEqual({path.name for path in self.destination.iterdir()},
                         {f"tree.7z.{index:03d}" for index in range(1, 9)})
        for index, volume in enumerate(result["volumes"], 1):
            content = str(index).encode()
            self.assertEqual((self.destination / volume["name"]).read_bytes(), content)
            self.assertEqual(volume["sha256"], hashlib.sha256(content).hexdigest())
            self.assertEqual(volume["size_in_bytes"], 1)
            self.assertEqual(volume["artifact_id"], {1: 103, 2: 103, 3: 102, 4: 102,
                                                     5: 104, 6: 104, 7: 101, 8: 101}[index])
        for artifact in result["artifacts"]:
            attempt = artifact["attempts"][0]
            self.assertEqual(attempt["status"], "success")
            self.assertEqual(attempt["content_length"], artifact["size_in_bytes"])
            self.assertEqual("sha256:" + attempt["sha256"], artifact["digest"])
        self.assertTrue(all(response.closed for response in self.responses))
        self.assertEqual(list(self.root.glob(".restore.staging-*")), [])

    def test_manifest_strictness_before_network(self):
        saved = copy.deepcopy(self.manifest)
        changes = [
            (None, "repository", "../repo", "invalid_repository"),
            (None, "head_sha", "bad", "invalid_head_sha"),
            (None, "run_id", True, "invalid_run_id"),
            (None, "artifacts", [], "invalid_artifact_set"),
            (0, "id", True, "invalid_or_duplicate_artifact_id"),
            (0, "name", "", "invalid_or_duplicate_artifact_name"),
            (0, "size_in_bytes", False, "invalid_artifact_size"),
            (0, "size_in_bytes", 0, "invalid_artifact_size"),
            (0, "expired", True, "expired_artifact"),
            (0, "digest", None, "missing_or_invalid_artifact_digest"),
            (0, "digest", "sha256:" + "z" * 64, "missing_or_invalid_artifact_digest"),
            (0, "digest", "sha1:" + "a" * 40, "missing_or_invalid_artifact_digest"),
        ]
        for item, field, value, reason in changes:
            with self.subTest(field=field, value=value):
                self.manifest = copy.deepcopy(saved)
                target = self.manifest if item is None else self.manifest["artifacts"][item]
                target[field] = value
                self.save_manifest()
                self.assert_clean_failure(reason)
        self.client.opener.open.assert_not_called()

    def test_manifest_count_duplicate_ids_and_names(self):
        for count in (5, 9):
            self.set_artifacts([self.data] * count)
            self.assert_clean_failure("invalid_artifact_set")
        for field, reason in (("id", "invalid_or_duplicate_artifact_id"),
                              ("name", "invalid_or_duplicate_artifact_name")):
            self.set_artifacts([self.data] * 2)
            self.manifest["artifacts"][1][field] = self.manifest["artifacts"][0][field]
            self.save_manifest()
            self.assert_clean_failure(reason)
        self.client.opener.open.assert_not_called()

    def test_manifest_malformed_and_size_limited(self):
        for content, reason in ((b"{invalid", "invalid_manifest_json"),
                                (b"[]", "invalid_manifest"),
                                (b" " * (base.MANIFEST_LIMIT + 1), "manifest_too_large")):
            self.manifest_path.write_bytes(content)
            self.assert_clean_failure(reason)
        self.client.opener.open.assert_not_called()

    def test_missing_token_fails_before_network(self):
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "not-used"}, clear=True), \
                self.assertRaisesRegex(snapshot.SnapshotError, "missing_or_invalid_gh_token"):
            snapshot.download_snapshot(self.manifest_path, self.destination, self.report_path)
        self.assertEqual(self.report()["reason"], "missing_or_invalid_gh_token")

    def test_gh_token_sent_only_to_api_with_real_redirect_handler(self):
        with mock.patch.dict(os.environ, {"GH_TOKEN": TOKEN}, clear=True):
            self.client = snapshot.GitHub()
        redirected = Response(status=302, headers={"Location": SIGNED})
        second = Response(status=307, headers={"Location": "/new.zip?sig=another-secret"})
        body = Response(self.data)
        handler = HTTPSFixture([redirected, second, body])
        self.client.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), base.NoRedirect(), handler)
        self.download()
        self.assertEqual(handler.requests[0].full_url,
                         f"{base.API}/repos/{REPO}/actions/artifacts/101/zip")
        self.assertEqual(handler.requests[0].get_header("Authorization"), "Bearer " + TOKEN)
        for request in handler.requests[1:]:
            self.assertIsNone(request.get_header("Authorization"))
            self.assertIsNone(request.get_header("X-github-api-version"))
        self.assertTrue(all(response.closed for response in (redirected, second, body)))
        self.assert_redacted(self.report_path.read_text())
        self.assertNotIn("another-secret", self.report_path.read_text())

    def test_unsafe_redirects_fail_closed(self):
        for url in ("http://fixture.blob.core.windows.net/a", "https://evil.example/a",
                    "https://fixture.blob.core.windows.net.evil.example/a",
                    "https://api.github.com/other", "https://[malformed/a", "\n" + SIGNED,
                    "https://user:password@fixture.blob.core.windows.net/a", SIGNED + TOKEN):
            with self.subTest(url=url):
                self.queue(Response(status=302, headers={"Location": url}))
                self.assert_clean_failure("unsafe_redirect")
                self.assertEqual(self.client.opener.open.call_count, 1)

    def test_redirect_limit_and_nonretryable_http_errors(self):
        self.queue(*(Response(status=302, headers={"Location": SIGNED}) for _ in range(6)))
        self.assert_clean_failure("too_many_redirects")
        for status in (401, 403, 404, 410):
            self.queue(urllib.error.HTTPError(SIGNED, status, TOKEN, {}, None))
            self.assert_clean_failure(f"http_{status}")
            self.assertEqual(self.client.opener.open.call_count, 1)

    def test_retry_starts_api_again_and_cleans_incomplete_zip(self):
        headers = {"Content-Length": str(len(self.data))}
        self.queue(Response(status=302, headers={"Location": SIGNED}),
                   Response(self.data[:10], headers=headers),
                   Response(status=302, headers={"Location": SIGNED + "-new"}),
                   Response(self.data, short_read=1), on_request=lambda request:
                   self.assertEqual(list(self.root.glob(".restore.staging-*/*.zip")), []))
        result = self.download()
        self.assertEqual(self.requests[0].full_url, self.requests[2].full_url)
        self.assertEqual([request.get_header("Authorization") for request in self.requests],
                         ["Bearer " + TOKEN, None, "Bearer " + TOKEN, None])
        attempts = result["artifacts"][0]["attempts"]
        self.assertEqual([item["status"] for item in attempts], ["failed", "success"])
        self.assertEqual(attempts[0]["reason"], "download_truncated")
        self.assertEqual(attempts[1]["size_in_bytes"], len(self.data))

    def test_network_error_is_bounded_and_redacted(self):
        self.queue(*(urllib.error.URLError(SIGNED + TOKEN) for _ in range(3)))
        self.assert_clean_failure("network_error")
        self.assertEqual(self.client.opener.open.call_count, 3)

    def test_content_length_encoding_and_body_limits(self):
        headers_and_reasons = [
            ({}, "invalid_content_length"),
            ({"Content-Length": "-1"}, "invalid_content_length"),
            ({"Content-Length": str(len(self.data) + 1)}, "content_length_mismatch"),
            ({"Content-Length": str(len(self.data)), "Content-Encoding": "gzip"},
             "unexpected_content_encoding"),
            ({"Content-Length": str(len(self.data)), "Transfer-Encoding": "chunked"},
             "unexpected_transfer_encoding"),
        ]
        for headers, reason in headers_and_reasons:
            with self.subTest(headers=headers):
                self.queue(Response(self.data, headers=headers))
                self.assert_clean_failure(reason)
        response = Response(self.data)
        response.headers["Content-Length"] = str(len(self.data))
        self.queue(response)
        self.assert_clean_failure("invalid_content_length")
        self.queue(Response(self.data + b"extra", headers={"Content-Length": str(len(self.data))}))
        self.assert_clean_failure("download_size_mismatch")

    def test_digest_mismatch_prevents_zip_open(self):
        self.queue(Response(bytes([self.data[0] ^ 1]) + self.data[1:]))
        with mock.patch.object(snapshot, "ZipFile") as archive:
            self.assert_clean_failure("checksum_mismatch")
        archive.assert_not_called()
        self.assertEqual(self.client.opener.open.call_count, 1)

    def test_failed_second_artifact_never_publishes_first(self):
        second = zip_bytes([("tree.7z.002", "file", b"two")])
        for failure in ("checksum_mismatch", "http_404", "http_410", "volume_count_limit"):
            with self.subTest(failure=failure):
                body = zip_bytes([]) if failure == "volume_count_limit" else second
                self.set_artifacts([self.data, body])
                if failure == "checksum_mismatch":
                    self.manifest["artifacts"][1]["digest"] = digest(b"wrong")
                    self.save_manifest()
                event = (Response(status=int(failure[5:]), headers={})
                         if failure.startswith("http_") else Response(body))
                self.queue(Response(self.data), event)
                with mock.patch.object(snapshot, "publish") as publish:
                    self.assert_clean_failure(failure)
                publish.assert_not_called()
                self.assertEqual([volume["name"] for volume in self.report()["volumes"]],
                                 ["tree.7z.001"])

    def test_duplicate_volumes_within_and_across_artifacts(self):
        for bodies in ([zip_bytes([("tree.7z.001", "file", b"a"),
                                  ("tree.7z.001", "file", b"b")])],
                       [zip_bytes([("a/tree.7z.001", "file", b"a"),
                                   ("b/tree.7z.001", "file", b"b")])],
                       [self.data, self.data]):
            self.set_artifacts(bodies)
            self.queue(*(Response(body) for body in bodies))
            self.assert_clean_failure("duplicate_volume")

    def test_missing_first_middle_zero_and_out_of_range_volume(self):
        for indices in ((2,), (1, 3), (0, 1), (1, 999)):
            with self.subTest(indices=indices):
                body = zip_bytes([(f"tree.7z.{index:03d}", "file", b"v") for index in indices])
                self.set_artifacts([body])
                self.queue(Response(body))
                self.assert_clean_failure("noncontiguous_volumes")

    def test_nine_volumes_empty_zip_and_empty_volume_rejected(self):
        for bodies, reason in (([zip_bytes([])], "volume_count_limit"),
                               ([zip_bytes([("tree.7z.001", "file", b"")])], "volume_size_limit"),
                               ([zip_bytes([(f"tree.7z.{index:03d}", "file", b"v")
                                            for index in range(1, 10)])], "volume_count_limit"),
                               ([zip_bytes([(f"tree.7z.{index:03d}", "file", b"v")
                                            for index in range(1, 9)]),
                                 zip_bytes([("tree.7z.009", "file", b"v")])], "volume_count_limit")):
            self.set_artifacts(bodies)
            self.queue(*(Response(body) for body in bodies))
            self.assert_clean_failure(reason)

    def test_volume_and_total_size_caps_without_large_allocations(self):
        self.assertEqual(snapshot.MAX_VOLUME_BYTES, 9 * 1024**3)
        self.assertEqual(snapshot.MAX_TOTAL_BYTES, 72 * 1024**3)
        with mock.patch.object(snapshot, "MAX_VOLUME_BYTES", 3):
            self.assert_clean_failure("volume_size_limit")
        self.queue(Response(self.data))
        with mock.patch.object(snapshot, "MAX_TOTAL_BYTES", 3):
            self.assert_clean_failure("total_size_limit")
        info = zipfile.ZipInfo("tree.7z.001")
        info.file_size = snapshot.MAX_VOLUME_BYTES + 1
        archive = mock.MagicMock()
        archive.__enter__.return_value = archive
        archive.infolist.return_value = [info]
        self.queue(Response(self.data))
        with mock.patch.object(snapshot, "ZipFile", return_value=archive):
            self.assert_clean_failure("volume_size_limit")
        archive.open.assert_not_called()

    def test_traversal_and_unexpected_members_rejected(self):
        unsafe = ["/tree.7z.001", "../tree.7z.001", "a/../tree.7z.001",
                  r"a\tree.7z.001", r"..\tree.7z.001", "C:/tree.7z.001",
                  "./tree.7z.001", "a//tree.7z.001", "a/b/tree.7z.001",
                  "//host/tree.7z.001", "a:/tree.7z.001", "tree.7z.001/", "part/",
                  "tree.7z.001:stream"]
        for name in unsafe + ["tree.tar.zst.001", "tree.7z.01", "tree.7z.001.exe", "README"]:
            with self.subTest(name=name):
                body = zip_bytes([(name, "file", b"v")])
                self.set_artifacts([body])
                self.queue(Response(body))
                self.assert_clean_failure("unsafe_zip_name" if name in unsafe
                                          else "unexpected_zip_member")
        body = zip_bytes([("tree.7z.001x", "file", b"v")]).replace(b"tree.7z.001x", b"tree.7z.001\0")
        self.set_artifacts([body])
        self.queue(Response(body))
        self.assert_clean_failure("unsafe_zip_name")
        self.assertFalse((self.root / "tree.7z.001").exists())

    def test_nonregular_and_reparse_members_rejected(self):
        for kind in ("sym", "dir", "fifo"):
            body = zip_bytes([("tree.7z.001", kind, b"v")])
            self.set_artifacts([body])
            self.queue(Response(body))
            self.assert_clean_failure("non_regular_zip_member")
        for attributes in (0x10, 0x400):
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as archive:
                info = zipfile.ZipInfo("tree.7z.001")
                info.create_system = 0
                info.external_attr = attributes
                archive.writestr(info, b"v")
            body = output.getvalue()
            self.set_artifacts([body])
            self.queue(Response(body))
            self.assert_clean_failure("non_regular_zip_member")

    def test_encryption_and_unsupported_compression_rejected(self):
        for flag in (1, 0x40):
            body = bytearray(self.data)
            central = body.index(b"PK\x01\x02")
            for offset in (6, central + 8):
                struct.pack_into("<H", body, offset, struct.unpack_from("<H", body, offset)[0] | flag)
            body = bytes(body)
            self.set_artifacts([body])
            self.queue(Response(body))
            self.assert_clean_failure("non_regular_zip_member")
        body = zip_bytes([("tree.7z.001", "file", b"v")], zipfile.ZIP_BZIP2)
        self.set_artifacts([body])
        self.queue(Response(body))
        self.assert_clean_failure("unsupported_zip_compression")

    def test_windows_attributes_and_zip64_headers_are_supported(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            info = zipfile.ZipInfo("tree.7z.001")
            info.create_system = 0
            info.external_attr = 0x20
            archive.writestr(info, b"one")
            with archive.open("tree.7z.002", "w", force_zip64=True) as member:
                member.write(b"two")
        body = output.getvalue()
        self.set_artifacts([body])
        self.queue(Response(body))
        self.download()
        self.assertEqual((self.destination / "tree.7z.002").read_bytes(), b"two")

    def test_corrupt_crc_after_partial_write_and_invalid_zip(self):
        body = bytearray(zip_bytes([("tree.7z.001", "file", b"v" * 20000)]))
        name_length, extra_length = struct.unpack_from("<HH", body, 26)
        body[30 + name_length + extra_length + 19999] ^= 1
        for body in (bytes(body), b"not-a-zip"):
            self.set_artifacts([body])
            self.queue(Response(body))
            with mock.patch.object(snapshot, "CHUNK", 1024), \
                    mock.patch.object(snapshot, "publish") as publish:
                self.assert_clean_failure("zip_integrity_error")
            publish.assert_not_called()
            self.assertEqual(self.report()["phase"], "extract_zip")
            self.assertEqual(self.report()["artifacts"][0]["attempts"][0]["status"], "success")

    def test_every_zip_exception_is_redacted_in_report_and_cli(self):
        errors = (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError, UnicodeError,
                  zlib.error, NotImplementedError, RuntimeError, ValueError, struct.error,
                  OverflowError, IndexError, OSError)
        for error in errors:
            with self.subTest(error=error.__name__):
                self.queue(Response(self.data))
                with mock.patch.object(snapshot, "ZipFile", side_effect=error(SIGNED + TOKEN)):
                    code, stdout, stderr = self.cli()
                self.assertEqual(code, 1)
                self.assertEqual(stdout, "")
                reason = "local_io_error" if error is OSError else "zip_integrity_error"
                self.assertIn(reason, stderr)
                self.assertEqual(self.report()["reason"], reason)
                self.assert_redacted(self.report_path.read_text())
                self.assertFalse(self.destination.exists())
                self.assertEqual(list(self.root.glob(".restore.staging-*")), [])

    def test_zip_read_runtime_error_and_actual_size_mismatch(self):
        info = zipfile.ZipInfo("tree.7z.001")
        info.file_size = 2
        for data, reason in ((b"v", "volume_size_mismatch"), (b"vvv", "volume_size_mismatch"),
                             (None, "zip_integrity_error")):
            archive = mock.MagicMock()
            archive.__enter__.return_value = archive
            archive.infolist.return_value = [info]
            if data is None:
                source = mock.MagicMock()
                source.__enter__.return_value.read.side_effect = RuntimeError(SIGNED + TOKEN)
            else:
                source = io.BytesIO(data)
            archive.open.return_value = source
            self.queue(Response(self.data))
            with mock.patch.object(snapshot, "ZipFile", return_value=archive):
                self.assert_clean_failure(reason)

    def test_download_space_checked_before_network(self):
        free = base.shutil.disk_usage(self.root).free
        self.manifest["artifacts"][0]["size_in_bytes"] = free + 1024**3
        self.save_manifest()
        self.assert_clean_failure("insufficient_disk_space")
        self.client.opener.open.assert_not_called()

    def test_extraction_space_accounts_for_retained_zip(self):
        def no_space(path, additional):
            files = list(path.glob("*.zip"))
            self.assertEqual(len(files), 1)
            self.assertEqual(files[0].stat().st_size, len(self.data))
            self.assertEqual(additional, len(b"volume-one"))
            raise snapshot.SnapshotError("insufficient_disk_space")

        with mock.patch.object(snapshot, "require_space", side_effect=no_space):
            self.assert_clean_failure("insufficient_disk_space")
        self.assertEqual(self.report()["phase"], "extract_zip")

    def test_existing_destination_file_and_directories_are_untouched(self):
        for kind in ("file", "directory", "empty-directory"):
            self.destination = self.root / kind
            if kind == "file":
                self.destination.write_bytes(b"important")
            else:
                self.destination.mkdir()
                if kind == "directory":
                    (self.destination / "sentinel").write_bytes(b"important")
            before = self.destination.lstat()
            with self.assertRaisesRegex(snapshot.SnapshotError, "destination_exists"):
                self.download()
            self.assertEqual(self.destination.lstat(), before)
        self.client.opener.open.assert_not_called()

    def test_report_symlink_inserted_during_download_is_not_followed(self):
        target = self.root / "other-report"
        target.write_text("important")
        try:
            self.report_path.symlink_to(target)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error.__class__.__name__}")
        self.report_path.unlink()
        self.queue(Response(self.data), on_request=lambda request: self.report_path.symlink_to(target))
        with self.assertRaisesRegex(snapshot.SnapshotError, "report_write_failed"):
            self.download()
        self.assertEqual(target.read_text(), "important")
        self.assertTrue(self.report_path.is_symlink())
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob(".restore.staging-*")), [])

    def test_manifest_cannot_be_inside_destination(self):
        self.destination.mkdir()
        manifest = self.destination / "manifest.json"
        manifest.write_bytes(self.manifest_path.read_bytes())
        with self.assertRaisesRegex(snapshot.SnapshotError, "output_overlaps_manifest"):
            snapshot.download_snapshot(manifest, self.destination, self.report_path, client=self.client)
        self.assertEqual(manifest.read_bytes(), self.manifest_path.read_bytes())
        self.client.opener.open.assert_not_called()

    def test_symlink_paths_and_dangling_destination_rejected(self):
        target = self.root / "target"
        target.mkdir()
        link = self.root / "link"
        try:
            link.symlink_to(target, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error.__class__.__name__}")
        for manifest, destination, report in (
                (self.manifest_path, link / "restore", self.report_path),
                (self.manifest_path, self.destination, link / "report.json"),
                (link / "manifest.json", self.destination, self.report_path)):
            with self.assertRaisesRegex(snapshot.SnapshotError, "output_path_is_reparse_point"):
                snapshot.download_snapshot(manifest, destination, report, client=self.client)
        self.destination.symlink_to(self.root / "missing")
        with self.assertRaisesRegex(snapshot.SnapshotError, "output_path_is_reparse_point"):
            self.download()
        self.assertTrue(self.destination.is_symlink())
        self.assertEqual(list(target.iterdir()), [])
        self.client.opener.open.assert_not_called()

    def test_reparse_metadata_and_ancestor_checks(self):
        path = mock.Mock()
        for mode, attributes, expected in ((stat.S_IFDIR, 0x400, True),
                                            (stat.S_IFREG, 0x400, True),
                                            (stat.S_IFLNK, 0, True),
                                            (stat.S_IFDIR, 0, False)):
            path.lstat.return_value = mock.Mock(st_mode=mode, st_file_attributes=attributes)
            with mock.patch.object(snapshot, "Path", return_value=path):
                self.assertEqual(snapshot._reparse("fixture"), expected)
        for bad in (self.destination, self.report_path, self.root):
            with mock.patch.object(snapshot, "_reparse", side_effect=lambda path: path == bad), \
                    self.assertRaisesRegex(snapshot.SnapshotError, "output_path_is_reparse_point"):
                self.download()
        self.client.opener.open.assert_not_called()

    def test_output_overlap_rejected_before_network(self):
        original = self.manifest_path.read_bytes()
        for report, reason in ((self.destination, "report_inside_destination"),
                               (self.destination / "report.json", "report_inside_destination"),
                               (self.manifest_path, "report_overwrites_manifest"),
                               (self.root, "output_overlap")):
            with self.subTest(report=report), self.assertRaisesRegex(snapshot.SnapshotError, reason):
                snapshot.download_snapshot(self.manifest_path, self.destination, report, client=self.client)
        hardlink = self.root / "manifest-hardlink"
        os.link(self.manifest_path, hardlink)
        with self.assertRaisesRegex(snapshot.SnapshotError, "report_overwrites_manifest"):
            snapshot.download_snapshot(self.manifest_path, self.destination, hardlink, client=self.client)
        self.assertEqual(self.manifest_path.read_bytes(), original)
        self.client.opener.open.assert_not_called()

    def test_destination_created_during_download_is_preserved(self):
        def create_destination(request):
            self.destination.mkdir()
            (self.destination / "sentinel").write_text("other-owner")

        self.queue(Response(self.data), on_request=create_destination)
        with self.assertRaisesRegex(snapshot.SnapshotError, "destination_exists"):
            self.download()
        self.assertEqual((self.destination / "sentinel").read_text(), "other-owner")
        self.assertEqual(list(self.root.glob(".restore.staging-*")), [])
        self.assertEqual(self.report()["publication"], "unconfirmed")

    def test_windows_publish_uses_rename_and_redacts_os_errors(self):
        staging = self.root / "staging"
        staging.mkdir()
        rename = mock.Mock()
        snapshot.publish(staging, self.destination, platform="win32", rename=rename)
        rename.assert_called_once_with(staging, self.destination)
        for error, reason in ((FileExistsError(SIGNED + TOKEN), "destination_exists"),
                              (PermissionError(SIGNED + TOKEN), "atomic_publish_failed")):
            with self.assertRaisesRegex(snapshot.SnapshotError, reason):
                snapshot.publish(staging, self.destination, platform="win32",
                                 rename=mock.Mock(side_effect=error))
        self.assertTrue(staging.exists())

    def test_windows_publish_race_keeps_existing_empty_directory(self):
        staging = self.root / "staging"
        staging.mkdir()
        (staging / "volume").write_bytes(b"owned")
        inode = []

        def raced_rename(source, destination):
            destination.mkdir()
            inode.append(destination.stat().st_ino)
            raise PermissionError(SIGNED + TOKEN)

        with self.assertRaisesRegex(snapshot.SnapshotError, "destination_exists"):
            snapshot.publish(staging, self.destination, platform="win32", rename=raced_rename)
        self.assertEqual(self.destination.stat().st_ino, inode[0])
        self.assertEqual(list(self.destination.iterdir()), [])
        self.assertEqual((staging / "volume").read_bytes(), b"owned")

    def test_fallback_does_not_replace_existing_empty_directory(self):
        staging = self.root / "staging"
        staging.mkdir()
        (staging / "volume").write_bytes(b"owned")
        self.destination.mkdir()
        before = self.destination.stat().st_ino
        with self.assertRaisesRegex(snapshot.SnapshotError, "destination_exists"):
            snapshot.publish(staging, self.destination)
        self.assertEqual(self.destination.stat().st_ino, before)
        self.assertEqual(list(self.destination.iterdir()), [])
        self.assertEqual((staging / "volume").read_bytes(), b"owned")

    def test_report_failure_prevents_publish_and_preserves_other_staging(self):
        other = self.root / ".restore.staging-other-owner"
        other.mkdir()
        (other / "sentinel").write_text("important")
        with mock.patch.object(snapshot, "write_report", side_effect=OSError(SIGNED + TOKEN)), \
                mock.patch.object(snapshot, "publish") as publish, \
                self.assertRaisesRegex(snapshot.SnapshotError, "report_write_failed"):
            self.download()
        publish.assert_not_called()
        self.assertEqual(list(self.root.glob(".restore.staging-*")), [other])
        self.assertEqual((other / "sentinel").read_text(), "important")
        self.assertFalse(self.destination.exists())

    def test_publish_error_rewrites_verified_report_to_failed(self):
        with mock.patch.object(snapshot, "publish", side_effect=snapshot.SnapshotError("atomic_publish_failed")):
            self.assert_clean_failure("atomic_publish_failed")
        self.assertEqual(self.report()["phase"], "publish")
        self.assertEqual(self.report()["publication"], "unconfirmed")

    def test_publish_and_failure_report_errors_leave_only_verified_report(self):
        original = snapshot.write_report

        def write(path, result):
            if result["status"] == "failed":
                raise OSError(SIGNED + TOKEN)
            original(path, result)

        with mock.patch.object(snapshot, "write_report", side_effect=write), \
                mock.patch.object(snapshot, "publish", side_effect=snapshot.SnapshotError("atomic_publish_failed")), \
                self.assertRaisesRegex(snapshot.SnapshotError, "report_write_failed"):
            self.download()
        self.assertEqual(self.report()["status"], "verified")
        self.assertEqual(self.report()["publication"], "unconfirmed")
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob(".restore.staging-*")), [])

    def test_final_report_failure_preserves_published_volumes(self):
        original = snapshot.write_report
        statuses = []

        def write(path, result):
            statuses.append(result["status"])
            if result["status"] != "verified":
                self.assertTrue(self.destination.is_dir())
                raise OSError(SIGNED + TOKEN)
            self.assertFalse(self.destination.exists())
            original(path, result)

        with mock.patch.object(snapshot, "write_report", side_effect=write), \
                self.assertRaisesRegex(snapshot.SnapshotError, "published_report_write_failed"):
            self.download()
        self.assertEqual(statuses, ["verified", "success", "failed"])
        self.assertEqual(self.report()["status"], "verified")
        self.assertEqual(self.report()["publication"], "unconfirmed")
        self.assertEqual((self.destination / "tree.7z.001").read_bytes(), b"volume-one")

    def test_final_report_failure_records_publication_if_failure_report_succeeds(self):
        original = snapshot.write_report

        def write(path, result):
            if result["status"] == "success":
                raise OSError(SIGNED + TOKEN)
            original(path, result)

        with mock.patch.object(snapshot, "write_report", side_effect=write), \
                self.assertRaisesRegex(snapshot.SnapshotError, "published_report_write_failed"):
            self.download()
        self.assertEqual(self.report()["status"], "failed")
        self.assertEqual(self.report()["publication"], "published")
        self.assertEqual((self.destination / "tree.7z.001").read_bytes(), b"volume-one")

    def test_timeout_during_http_read_is_checked_before_writing(self):
        response = Response(self.data)
        original = response.read1

        def slow_read(size):
            chunk = original(size)
            time.sleep(0.06)
            return chunk

        response.read1 = slow_read
        self.queue(response)
        self.assert_clean_failure("total_timeout", timeout_seconds=0.04)
        self.assertEqual(self.report()["artifacts"][0]["attempts"][0]["size_in_bytes"], 0)

    def test_timeout_during_retry_does_not_issue_another_request(self):
        self.queue(Response(self.data[:10], headers={"Content-Length": str(len(self.data))}))
        self.assert_clean_failure("total_timeout", timeout_seconds=0.1)
        self.assertEqual(self.client.opener.open.call_count, 1)

    def test_timeout_after_zip_read_rejects_unwritten_chunk(self):
        info = zipfile.ZipInfo("tree.7z.001")
        info.file_size = 1
        archive = mock.MagicMock()
        archive.__enter__.return_value = archive
        archive.infolist.return_value = [info]
        read_done = [False]

        def read(size):
            read_done[0] = True
            return b"v"

        archive.open.return_value.__enter__.return_value.read.side_effect = read
        original = snapshot.remaining

        def remaining(deadline):
            if read_done[0]:
                outputs = list(self.root.glob(".restore.staging-*/tree.7z.001"))
                self.assertEqual(len(outputs), 1)
                self.assertEqual(outputs[0].stat().st_size, 0)
                raise snapshot.SnapshotError("total_timeout")
            return original(deadline)

        with mock.patch.object(snapshot, "ZipFile", return_value=archive), \
                mock.patch.object(snapshot, "remaining", side_effect=remaining):
            self.assert_clean_failure("total_timeout")
        self.assertEqual(self.report()["volumes"], [])

    def test_invalid_timeout_and_expired_deadline_fail_before_network(self):
        for value in (0, -1, True, None, "bad", float("inf"), float("nan")):
            with self.subTest(timeout=value):
                self.assert_clean_failure("invalid_timeout", timeout_seconds=value)
                self.assertIsNone(self.report()["timeout_seconds"])
        self.assert_clean_failure("total_timeout", timeout_seconds=1e-100)
        self.client.opener.open.assert_not_called()

    def test_all_artifacts_share_one_deadline(self):
        second = zip_bytes([("tree.7z.002", "file", b"two")])
        self.set_artifacts([self.data, second])
        self.queue(Response(self.data), Response(second))
        original = self.client.download
        deadlines = []

        def download(repository, artifact, staging, deadline, record):
            deadlines.append(deadline)
            return original(repository, artifact, staging, deadline, record)

        with mock.patch.object(self.client, "download", side_effect=download):
            self.download(timeout_seconds=30)
        self.assertEqual(len(deadlines), 2)
        self.assertEqual(deadlines[0], deadlines[1])
        self.assertLessEqual(deadlines[0], time.monotonic() + 30)

    def test_timeout_during_extraction_and_after_verified_report_prevents_publish(self):
        original = snapshot.remaining
        for stage in ("extract", "report"):
            self.queue(Response(self.data))

            def remaining(deadline):
                if ((stage == "extract" and list(self.root.glob(".restore.staging-*/*.zip")))
                        or (stage == "report" and self.report_path.exists()
                            and self.report()["status"] == "verified")):
                    raise snapshot.SnapshotError("total_timeout")
                return original(deadline)

            with mock.patch.object(snapshot, "remaining", side_effect=remaining), \
                    mock.patch.object(snapshot, "publish") as publish:
                self.assert_clean_failure("total_timeout")
            publish.assert_not_called()
            self.assertEqual(self.report()["phase"], "extract_zip" if stage == "extract" else "publish")

    def test_interrupt_cleans_staging_and_returns_130(self):
        response = Response(self.data)
        response.read1 = mock.Mock(side_effect=[self.data[:10], KeyboardInterrupt()])
        self.queue(response)
        code, stdout, stderr = self.cli()
        self.assertEqual(code, 130)
        self.assertEqual(stdout, "")
        self.assertIn("interrupted", stderr)
        self.assertTrue(response.closed)
        self.assertEqual(self.report()["reason"], "interrupted")
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.root.glob(".restore.staging-*")), [])

    def test_interrupt_after_publication_preserves_destination(self):
        original = snapshot.publish

        def publish(staging, destination):
            original(staging, destination)
            raise KeyboardInterrupt

        with mock.patch.object(snapshot, "publish", side_effect=publish), self.assertRaises(KeyboardInterrupt):
            self.download()
        self.assertEqual((self.destination / "tree.7z.001").read_bytes(), b"volume-one")
        self.assertEqual(self.report()["publication"], "unconfirmed")
        self.assertEqual(list(self.root.glob(".restore.staging-*")), [])

    def test_cli_flags_default_timeout_and_direct_script(self):
        code, stdout, stderr = self.cli()
        self.assertEqual(code, 0)
        self.assertIn("1 verified volumes", stdout)
        self.assertEqual(stderr, "")
        self.assertEqual(self.report()["timeout_seconds"], 3600)
        self.destination = self.root / "second"
        self.queue(Response(self.data))
        self.assertEqual(self.cli("--timeout-seconds", "30")[0], 0)
        self.assertEqual(self.report()["timeout_seconds"], 30)
        completed = subprocess.run([sys.executable, str(Path(snapshot.__file__).resolve()), "--help"],
                                   cwd=self.root, capture_output=True, text=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        for flag in ("--manifest", "--destination", "--report", "--timeout-seconds"):
            self.assertIn(flag, completed.stdout)


if __name__ == "__main__":
    unittest.main()
