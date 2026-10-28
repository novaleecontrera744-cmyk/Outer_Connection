"""Release verification tests; all network and system operations are mocked."""

import io
import json
import stat
import tarfile
import unittest
import zipfile
from unittest import mock

import outer


class DownloadTests(unittest.TestCase):
    def test_declined_confirmation_never_downloads(self):
        with mock.patch("builtins.input", return_value="no"), \
             mock.patch.object(outer, "_verified_download") as download:
            with self.assertRaises(outer.OuterError):
                outer.download_binaries()
        download.assert_not_called()

    def test_wrong_archive_checksum_is_rejected(self):
        with mock.patch.object(outer, "release_asset", return_value=("https://example.test", "0" * 64)), \
             mock.patch.object(outer, "_get_bytes", return_value=b"modified release"):
            with self.assertRaises(outer.OuterError):
                outer._verified_download("owner/project", "v1", "archive")

    def test_official_metadata_must_match_pinned_digest_and_url(self):
        name = "Xray-linux-64.zip"
        expected = outer.RELEASE_SHA256[name]
        url = f"https://github.com/XTLS/Xray-core/releases/download/v{outer.XRAY_VERSION}/{name}"
        metadata = {"tag_name": f"v{outer.XRAY_VERSION}", "prerelease": False, "draft": False,
                    "assets": [{"name": name, "digest": "sha256:" + expected, "browser_download_url": url}]}
        with mock.patch.object(outer, "_get_bytes", return_value=json.dumps(metadata).encode()):
            self.assertEqual(outer.release_asset("XTLS/Xray-core", f"v{outer.XRAY_VERSION}", name), (url, expected))
        metadata["assets"][0]["digest"] = "sha256:" + "0" * 64
        with mock.patch.object(outer, "_get_bytes", return_value=json.dumps(metadata).encode()):
            with self.assertRaises(outer.OuterError):
                outer.release_asset("XTLS/Xray-core", f"v{outer.XRAY_VERSION}", name)

    def test_extracts_only_expected_regular_binaries(self):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as tar:
            member = tarfile.TarInfo("sing-box-release/sing-box")
            member.size = len(b"binary")
            tar.addfile(member, io.BytesIO(b"binary"))
        self.assertEqual(outer._extract_sing(archive.getvalue()), b"binary")
        zipped = io.BytesIO()
        with zipfile.ZipFile(zipped, "w") as archive_file:
            archive_file.writestr("xray", b"binary")
            archive_file.writestr("../../other", b"ignored")
        self.assertEqual(outer._extract_xray(zipped.getvalue()), b"binary")
        bad = io.BytesIO()
        with zipfile.ZipFile(bad, "w") as archive_file:
            archive_file.writestr("../xray", b"not extracted")
        with self.assertRaises(outer.OuterError):
            outer._extract_xray(bad.getvalue())
        link = io.BytesIO()
        with zipfile.ZipFile(link, "w") as archive_file:
            info = zipfile.ZipInfo("xray")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive_file.writestr(info, "some-other-path")
        with self.assertRaises(outer.OuterError):
            outer._extract_xray(link.getvalue())


if __name__ == "__main__":
    unittest.main()
