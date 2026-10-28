"""Repeated lifecycle commands use isolated files and mocked system services."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import outer


class FakeSystemd:
    def __init__(self):
        self.calls = []

    def run(self, args, **kwargs):
        command = [str(item) for item in args]
        self.calls.append(command)
        if command[:3] == ["systemctl", "is-active", "--quiet"]:
            return SimpleNamespace(returncode=3, stdout="", stderr="")
        if command[:2] == ["systemctl", "is-enabled"]:
            return SimpleNamespace(returncode=1, stdout="disabled\n", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")


class RepeatedLifecycleTests(unittest.TestCase):
    def setUp(self):
        for patcher in (
            mock.patch.object(outer, "require_root"),
            mock.patch.object(outer.os, "geteuid", return_value=1000),
            mock.patch.object(outer.subprocess, "run", side_effect=AssertionError("real command")),
            mock.patch.object(outer.subprocess, "Popen", side_effect=AssertionError("real process")),
            mock.patch.object(outer.socket, "socket", side_effect=AssertionError("real socket")),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_lock_rejects_a_symlink_without_touching_its_target(self):
        with tempfile.TemporaryDirectory() as root:
            paths = outer.Paths(Path(root))
            paths.lock.parent.mkdir(parents=True)
            target = Path(root) / "unrelated"
            target.write_bytes(b"unchanged")
            paths.lock.symlink_to(target)
            with self.assertRaises(OSError):
                with outer.operation_lock(paths):
                    self.fail("a symlink must not be locked")
            self.assertEqual(target.read_bytes(), b"unchanged")

    def test_start_is_a_noop_when_already_active(self):
        runner = FakeSystemd()
        with tempfile.TemporaryDirectory() as root, \
             mock.patch.object(outer, "systemd_active", return_value=True), \
             mock.patch.object(outer, "dependencies_ok") as dependencies:
            outer.start(outer.Paths(Path(root)), runner)
            outer.start(outer.Paths(Path(root)), runner)
        dependencies.assert_not_called()
        self.assertEqual(runner.calls, [])

    def test_stop_is_a_noop_when_already_absent(self):
        runner = FakeSystemd()
        with tempfile.TemporaryDirectory() as root:
            paths = outer.Paths(Path(root))
            outer.stop(paths, runner)
            outer.stop(paths, runner)
        self.assertEqual(runner.calls, [])

    def test_uninstall_can_be_repeated_and_retains_backups(self):
        runner = FakeSystemd()
        with tempfile.TemporaryDirectory() as root:
            paths = outer.Paths(Path(root))
            paths.unit.parent.mkdir(parents=True)
            paths.unit.write_text(outer.service_unit(), encoding="utf-8")
            paths.prefix.mkdir(parents=True)
            paths.script.write_bytes(b"fake script")
            paths.sing.write_bytes(b"fake sing")
            paths.xray.write_bytes(b"fake xray")
            paths.manifest.write_bytes(b"{}")
            paths.env.parent.mkdir(parents=True)
            paths.env.write_bytes(b"fake private config")
            outer.uninstall(paths, runner)
            call_count = len(runner.calls)
            backups = list(paths.backups.iterdir())
            self.assertEqual(len(backups), 1)
            self.assertTrue((backups[0] / "manifest.json").exists())
            self.assertFalse(paths.unit.exists())
            self.assertFalse(paths.env.exists())
            outer.uninstall(paths, runner)
            self.assertEqual(len(runner.calls), call_count)
            self.assertEqual(list(paths.backups.iterdir()), backups)


if __name__ == "__main__":
    unittest.main()
