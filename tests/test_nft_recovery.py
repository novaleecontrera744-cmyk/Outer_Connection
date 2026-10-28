"""Failed-start recovery scenarios using an in-memory system-command runner."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import outer


SETTINGS = {
    "vless": {"port": 443, "uuid": "01234567-89ab-cdef-0123-456789abcdef", "public_key": "A" * 43},
    "endpoints": ["198.51.100.42"], "interface": "proton0", "dns": "1.1.1.1", "strict": False,
}
OLD_ROUTE = {"dst": "default", "gateway": "192.0.2.1", "dev": "wlp5s0", "metric": 600}


class SimulatedSystem:
    def __init__(self, paths):
        self.paths = paths
        self.tables = set()
        self.default_present = True
        self.commands = []
        self.secrets = {"fake-private-secret"}

    def json(self, args):
        command = list(map(str, args))
        if command[:2] == ["nft", "-j"]:
            return {"nftables": [{"table": {"family": family, "name": name}} for family, name in self.tables]}
        if command[:5] == ["ip", "-j", "-4", "route", "get"]:
            return [{"dev": "wlp5s0", "gateway": "192.0.2.1"}]
        if command[:8] == ["ip", "-j", "-4", "route", "show", "table", "main", "default"]:
            return [OLD_ROUTE] if self.default_present else []
        return []

    def run(self, args, *, input_text=None, check=True, timeout=30):
        command = list(map(str, args))
        self.commands.append(command)
        if command == ["nft", "-f", "-"] and "outer_vpn_transition" in (input_text or ""):
            self.tables.add(("inet", "outer_vpn_transition"))
        elif command == ["systemctl", "start", outer.UNIT_NAME]:
            state = outer.load_state(self.paths)
            outer.journal_action(state, ["nft", "delete", "table", "inet", "outer_vpn_guard"],
                                 protected=True, paths=self.paths)
            outer.journal_action(state, ["nft", "delete", "table", "ip", "outer_vpn_nat"], paths=self.paths)
            outer.journal_action(state, OLD_ROUTE, kind="restore_route", paths=self.paths)
            self.tables.update({("inet", "outer_vpn_guard"), ("ip", "outer_vpn_nat")})
            self.default_present = False
            failure = outer.command_failure(["/usr/sbin/nft", "-f", "-"], 1,
                                            "invalid set; token=fake-private-secret", secrets=self.secrets)
            outer.journal_failure(state, failure, paths=self.paths, runner=self)
            raise outer.command_failure(["/usr/bin/systemctl", "start", outer.UNIT_NAME], 1,
                                        "service failed", secrets=self.secrets)
        elif command[:3] == ["nft", "delete", "table"]:
            self.tables.discard((command[3], command[4]))
        elif command[:4] == ["ip", "-4", "route", "add"]:
            self.default_present = True
        return SimpleNamespace(returncode=0, stdout="", stderr="", args=command)


class RecoveryTests(unittest.TestCase):
    def test_cleanup_treats_already_absent_nft_table_as_success(self):
        class MissingTableRunner:
            def run(self, args, **kwargs):
                return SimpleNamespace(returncode=1, stdout="", args=args,
                                       stderr="Error: Could not process rule: No such file or directory\n")

        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            state = {"version": 1, "phase": "failed-guarded", "undo": [
                {"kind": "command", "value": ["nft", "delete", "table", "inet", "outer_vpn_guard"],
                 "protected": True},
            ]}
            outer.save_state(state, paths)
            outer.cleanup(paths=paths, runner=MissingTableRunner())
            self.assertFalse(paths.state.exists())

    def test_install_validates_nft_before_download_or_file_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            runner = SimulatedSystem(paths)
            original_run = runner.run

            def fail_check(args, **kwargs):
                if list(args) == ["nft", "-c", "-f", "-"]:
                    raise outer.command_failure(["/usr/sbin/nft", "-c", "-f", "-"], 1,
                                                "invalid rule")
                return original_run(args, **kwargs)

            with mock.patch.object(outer, "require_root"), \
                 mock.patch.object(outer, "systemd_active", return_value=False), \
                 mock.patch.object(outer, "read_settings", return_value=SETTINGS), \
                 mock.patch.object(outer, "checked_server", return_value="203.0.113.10"), \
                 mock.patch.object(outer, "download_binaries") as download, \
                 mock.patch.object(runner, "run", side_effect=fail_check):
                with self.assertRaisesRegex(outer.OuterError, "invalid rule"):
                    outer.install(paths, runner, confirmed=True)
            download.assert_not_called()
            self.assertFalse(paths.prefix.exists())
            self.assertFalse(paths.unit.exists())
            self.assertFalse(paths.backups.exists())
            self.assertEqual(runner.tables, set())

    def test_failed_dynamic_update_and_stop_restore_journaled_system_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            runner = SimulatedSystem(paths)
            with mock.patch.object(outer, "require_root"), \
                 mock.patch.object(outer, "systemd_active", return_value=False), \
                 mock.patch.object(outer, "dependencies_ok"), \
                 mock.patch.object(outer, "read_settings_and_data", return_value=(SETTINGS, b"fake config")), \
                 mock.patch.object(outer, "checked_server", return_value="203.0.113.10"), \
                 mock.patch.object(outer, "validate_configs"), \
                 mock.patch.object(outer, "legacy_paths", return_value=[]):
                with self.assertRaises(outer.OuterError) as error:
                    outer.start(paths, runner)
                self.assertIn("/usr/sbin/nft -f -", str(error.exception))
                self.assertIn("invalid set", str(error.exception))
                self.assertNotIn("fake-private-secret", str(error.exception))
                self.assertTrue(paths.state.exists())
                self.assertTrue(runner.default_present)
                self.assertTrue(outer._active_guards(runner))
                self.assertNotIn("fake-private-secret", paths.state.read_text())
                outer.stop(paths, runner)
                self.assertTrue(runner.default_present)
                self.assertEqual(runner.tables, set())
                self.assertFalse(paths.state.exists())
                outer.stop(paths, runner)

    def test_untracked_guard_is_reported_and_not_deleted(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            runner = SimulatedSystem(paths)
            runner.tables.add(("inet", "outer_vpn_transition"))
            stream = io.StringIO()
            with mock.patch.object(outer, "require_root"), \
                 mock.patch.object(outer, "systemd_active", return_value=False), \
                 contextlib.redirect_stdout(stream):
                outer.status(paths, runner)
                with self.assertRaisesRegex(outer.OuterError, "without a recovery journal"):
                    outer.stop(paths, runner)
            self.assertIn("Gateway traffic guard: present", stream.getvalue())
            self.assertIn("Recovery journal: not present", stream.getvalue())
            self.assertIn(("inet", "outer_vpn_transition"), runner.tables)
            self.assertFalse(any(command[:3] == ["nft", "delete", "table"] for command in runner.commands))

    def test_stop_reports_systemd_failure_and_preserves_journal(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            state = {"version": 1, "phase": "failed-guarded", "undo": [
                {"kind": "command", "value": ["nft", "delete", "table", "inet", "outer_vpn_guard"],
                 "protected": True},
            ]}
            outer.save_state(state, paths)

            class FailingSystemd:
                def run(self, args, **kwargs):
                    return SimpleNamespace(returncode=1, stdout="", args=["/usr/bin/" + args[0], *args[1:]],
                                           stderr="Failed to contact system manager")

            with mock.patch.object(outer, "require_root"):
                with self.assertRaises(outer.OuterError) as error:
                    outer.stop(paths, FailingSystemd())
            self.assertIn("/usr/bin/systemctl stop", str(error.exception))
            self.assertIn("Failed to contact system manager", str(error.exception))
            self.assertTrue(paths.state.exists())

    def test_status_still_reports_guard_and_journal_when_systemd_is_unavailable(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            outer.save_state({"version": 1, "phase": "failed-guarded", "undo": []}, paths)
            runner = SimulatedSystem(paths)
            runner.tables.add(("inet", "outer_vpn_guard"))
            output = io.StringIO()
            with mock.patch.object(outer, "systemd_active", side_effect=outer.OuterError("system manager unavailable")), \
                 contextlib.redirect_stdout(output):
                outer.status(paths, runner)
            self.assertIn("Gateway service: unknown", output.getvalue())
            self.assertIn("Recovery journal: present", output.getvalue())
            self.assertIn("Gateway traffic guard: present", output.getvalue())


if __name__ == "__main__":
    unittest.main()
