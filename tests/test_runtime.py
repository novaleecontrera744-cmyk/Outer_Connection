"""Isolated runtime and rollback tests for outer.py."""

from __future__ import annotations

import hashlib
import os
import socket
import stat
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import outer


TEST_UUID = "01234567-89ab-cdef-0123-456789abcdef"
TEST_PUBLIC_KEY = "A" * 43
TEST_SERVER_IPV4 = "198.51.100.42"
TEST_ENDPOINTS = ["8.8.8.8", "9.9.9.9"]
VALID_VLESS_URL = (
    f"vless://{TEST_UUID}@edge.example.test:8443"
    "?encryption=none&type=tcp&security=reality&flow=xtls-rprx-vision"
    "&sni=front.example.net&fp=chrome"
    f"&pbk={TEST_PUBLIC_KEY}&sid=deadbeef&spx=%2Fprobe"
)
ENV_TEXT = (
    f"VLESS_URL={VALID_VLESS_URL}\n"
    f"PROTON_ENDPOINTS={','.join(TEST_ENDPOINTS)}\n"
    "PROTON_INTERFACE=proton0\n"
    "DNS_SERVER=1.1.1.1\n"
)


class FakeRunner:
    """Record commands and return controlled results without executing them."""

    def __init__(self, failures=()):
        self.calls = []
        self.json_calls = []
        self.failures = {tuple(command) for command in failures}

    def run(self, args, *, input_text=None, check=True, timeout=30):
        command = [str(value) for value in args]
        self.calls.append((command, input_text, check, timeout))
        failed = tuple(command) in self.failures
        result = SimpleNamespace(
            returncode=1 if failed else 0,
            stdout="0\n" if command[:2] == ["sysctl", "-n"] else "",
            stderr="operation not permitted" if failed else "",
        )
        if check and result.returncode:
            raise outer.OuterError(f"{command[0]} failed (exit 1).")
        return result

    def json(self, args):
        command = [str(value) for value in args]
        self.json_calls.append(command)
        return {"nftables": []}

    @property
    def commands(self):
        return [call[0] for call in self.calls]


class IsolatedRuntimeTest(unittest.TestCase):
    def setUp(self):
        root_check = mock.patch.object(outer, "require_root")
        root_check.start()
        self.addCleanup(root_check.stop)
        blockers = (
            mock.patch.object(outer.os, "geteuid", return_value=1000),
            mock.patch.object(
                outer.os, "chown",
                side_effect=AssertionError("real ownership changes are blocked"),
            ),
            mock.patch.object(
                outer.subprocess, "run",
                side_effect=AssertionError("real subprocess execution is blocked"),
            ),
            mock.patch.object(
                outer.subprocess, "Popen",
                side_effect=AssertionError("real process creation is blocked"),
            ),
            mock.patch.object(
                outer.socket, "socket",
                side_effect=AssertionError("real sockets are blocked"),
            ),
            mock.patch.object(
                outer.socket, "create_connection",
                side_effect=AssertionError("real network connections are blocked"),
            ),
            mock.patch.object(
                outer.socket, "getaddrinfo",
                side_effect=AssertionError("real DNS lookups are blocked"),
            ),
        )
        for patcher in blockers:
            patcher.start()
            self.addCleanup(patcher.stop)


class FileTransactionTests(IsolatedRuntimeTest):
    def test_rollback_restores_files_directories_and_symlinks_atomically(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = outer.Paths(root)

            file_path = paths.at("/etc/outer-vpn/settings.conf")
            file_path.parent.mkdir(parents=True)
            file_path.write_bytes(b"old settings\n")
            file_path.chmod(0o640)

            directory = paths.at("/etc/outer-gateway")
            (directory / "nested").mkdir(parents=True)
            (directory / "nested" / "config").write_bytes(b"old legacy data\n")

            link = paths.at("/usr/local/bin/outer-vpn-toggle")
            link.parent.mkdir(parents=True)
            link.symlink_to("old-toggle-target")

            created_path = paths.at("/etc/outer-vpn/new.conf")
            transaction = outer.FileTransaction(paths, "runtime-rollback-test")
            backup_directory = transaction.directory
            transaction.write(file_path, b"replacement settings\n", 0o600)
            transaction.remove(directory)
            transaction.remove(link)
            link.symlink_to("new-toggle-target")
            transaction.write(created_path, b"created during transaction\n")

            with mock.patch.object(outer.os, "replace", wraps=os.replace) as replace:
                transaction.rollback()

            self.assertGreaterEqual(replace.call_count, 3)
            self.assertTrue((backup_directory / "manifest.json").is_file())
            self.assertEqual(file_path.read_bytes(), b"old settings\n")
            self.assertEqual(stat.S_IMODE(file_path.stat().st_mode), 0o640)
            self.assertEqual(
                (directory / "nested" / "config").read_bytes(), b"old legacy data\n"
            )
            self.assertTrue(link.is_symlink())
            self.assertEqual(os.readlink(link), "old-toggle-target")
            self.assertFalse(created_path.exists())
            self.assertFalse(any(root.rglob(".outer-vpn-restore-*")))


    def test_rollback_is_idempotent_after_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            target = paths.at("/etc/outer-gateway/config")
            target.parent.mkdir(parents=True)
            target.write_text("before")
            transaction = outer.FileTransaction(paths, "repeated-rollback")
            transaction.write(target, b"during")
            transaction.rollback()
            self.assertEqual(target.read_text(), "before")
            target.write_text("later update")
            transaction.rollback()
            self.assertEqual(target.read_text(), "later update")

    def test_untouched_snapshots_never_overwrite_concurrent_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            target = paths.at("/etc/outer-gateway/config")
            target.parent.mkdir(parents=True)
            target.write_text("original")
            transaction = outer.FileTransaction(paths, "snapshot-only")
            transaction.snapshot(target)
            target.write_text("concurrent update")
            with self.assertRaises(outer.OuterError):
                transaction.remove(target)
            transaction.rollback()
            self.assertEqual(target.read_text(), "concurrent update")


class InstallationAndApplyTests(IsolatedRuntimeTest):
    def test_install_is_idempotent_and_does_not_download_current_binaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            source = Path(outer.__file__).resolve()
            paths.script.parent.mkdir(parents=True)
            paths.script.write_bytes(source.read_bytes())
            paths.unit.parent.mkdir(parents=True)
            paths.unit.write_bytes(outer.service_unit().encode("utf-8"))
            sing_bytes = b"fake sing-box executable"
            xray_bytes = b"fake Xray executable"
            paths.sing.write_bytes(sing_bytes)
            paths.xray.write_bytes(xray_bytes)
            outer.atomic_json(paths.manifest, {
                "sing_version": outer.SING_VERSION,
                "xray_version": outer.XRAY_VERSION,
                "sing_sha256": hashlib.sha256(sing_bytes).hexdigest(),
                "xray_sha256": hashlib.sha256(xray_bytes).hexdigest(),
            })
            self.assertTrue(outer.installed_binary_integrity(paths))
            runner = FakeRunner()

            with (
                mock.patch.object(outer, "legacy_paths", return_value=[]),
                mock.patch.object(
                    outer, "download_binaries",
                    side_effect=AssertionError("current installation must not download"),
                ) as download,
            ):
                outer.install(paths=paths, runner=runner, source=source)
                outer.install(paths=paths, runner=runner, source=source)

            download.assert_not_called()
            self.assertEqual(runner.calls, [])
            self.assertFalse(paths.backups.exists())

    def test_apply_is_idempotent_for_an_unchanged_secure_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            paths.env.parent.mkdir(parents=True)
            paths.env.write_text(ENV_TEXT, encoding="utf-8")
            paths.env.chmod(0o600)
            runner = FakeRunner()
            real_stat = os.stat

            def report_root_owner(path, *args, **kwargs):
                result = real_stat(path, *args, **kwargs)
                try:
                    is_target = Path(path) == paths.env
                except TypeError:
                    is_target = False
                if is_target:
                    return SimpleNamespace(st_mode=result.st_mode, st_uid=0)
                return result

            with (
                mock.patch.object(outer, "resolve_ipv4", return_value=TEST_SERVER_IPV4),
                mock.patch.object(outer, "validate_configs") as validate,
                mock.patch.object(
                    outer, "systemd_active",
                    side_effect=AssertionError("an unchanged config needs no service query"),
                ),
                mock.patch.object(outer.os, "stat", side_effect=report_root_owner),
            ):
                outer.apply_config(paths.env, paths, runner)
                outer.apply_config(paths.env, paths, runner)

            self.assertEqual(validate.call_count, 2)
            self.assertEqual(paths.env.read_text(encoding="utf-8"), ENV_TEXT)
            self.assertEqual(stat.S_IMODE(paths.env.stat().st_mode), 0o600)
            self.assertEqual(runner.calls, [])
            self.assertFalse(paths.backups.exists())

    def test_apply_validation_failure_leaves_existing_target_untouched(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            paths.env.parent.mkdir(parents=True)
            original = b"existing applied config\n"
            paths.env.write_bytes(original)
            paths.env.chmod(0o640)
            submitted = paths.at("/tmp/submitted.env")
            submitted.parent.mkdir(parents=True)
            submitted.write_text(ENV_TEXT, encoding="utf-8")
            runner = FakeRunner()

            with (
                mock.patch.object(outer, "resolve_ipv4", return_value=TEST_SERVER_IPV4),
                mock.patch.object(
                    outer, "validate_configs",
                    side_effect=outer.OuterError("mock binary validation failure"),
                ),
                mock.patch.object(outer, "systemd_active", return_value=False),
                mock.patch.object(outer, "FileTransaction") as transaction,
            ):
                with self.assertRaisesRegex(outer.OuterError, "validation failure"):
                    outer.apply_config(submitted, paths, runner)

            transaction.assert_not_called()
            self.assertEqual(paths.env.read_bytes(), original)
            self.assertEqual(stat.S_IMODE(paths.env.stat().st_mode), 0o640)
            self.assertEqual(runner.calls, [])
            self.assertFalse(paths.backups.exists())


class EarlyStartFailureTests(IsolatedRuntimeTest):
    def test_preparation_failure_leaves_network_untouched(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            runner = FakeRunner()
            with mock.patch.object(outer, "systemd_active", return_value=False), \
                 mock.patch.object(outer, "dependencies_ok", side_effect=outer.OuterError("unavailable")):
                with self.assertRaisesRegex(outer.OuterError, "unavailable"):
                    outer.start(paths, runner)
            self.assertIsNone(outer.load_state(paths))
            self.assertEqual(runner.commands, [])

    def test_nft_prevalidation_failure_does_not_install_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            runner = FakeRunner()
            with mock.patch.object(outer, "systemd_active", return_value=False), \
                 mock.patch.object(outer, "dependencies_ok"), \
                 mock.patch.object(outer, "read_settings_and_data", return_value=({}, ENV_TEXT.encode())), \
                 mock.patch.object(outer, "checked_server", return_value=TEST_SERVER_IPV4), \
                 mock.patch.object(outer, "validate_configs"), \
                 mock.patch.object(outer, "prepare_nft_rules", side_effect=outer.OuterError("nft pre-validation failed")):
                with self.assertRaisesRegex(outer.OuterError, "nft pre-validation failed"):
                    outer.start(paths, runner)
            self.assertIsNone(outer.load_state(paths))
            self.assertNotIn(["nft", "-f", "-"], runner.commands)


class JournalCleanupTests(IsolatedRuntimeTest):
    def test_cleanup_is_idempotent_and_removes_journal_entries_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            normal_undo = ["ip", "link", "delete", "ogw-host"]
            guard_undo = ["nft", "delete", "table", "inet", "outer_vpn_guard"]
            state = {
                "version": 1,
                "phase": "running",
                "undo": [
                    {"kind": "command", "value": normal_undo, "protected": False},
                    {"kind": "command", "value": guard_undo, "protected": True},
                ],
            }
            runner = FakeRunner()

            outer.cleanup(state, paths=paths, runner=runner)
            first_pass = list(runner.commands)
            outer.cleanup(state, paths=paths, runner=runner)

            self.assertEqual(first_pass.count(normal_undo), 1)
            self.assertEqual(first_pass.count(guard_undo), 1)
            self.assertEqual(runner.commands, first_pass)
            self.assertEqual(state["undo"], [])
            self.assertFalse(paths.state.exists())

    def test_cleanup_failure_retains_protected_traffic_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            failed_undo = ["ip", "route", "del", "default"]
            guard_undo = ["nft", "delete", "table", "inet", "outer_vpn_guard"]
            state = {
                "version": 1,
                "phase": "running",
                "undo": [
                    {"kind": "command", "value": failed_undo, "protected": False},
                    {"kind": "command", "value": guard_undo, "protected": True},
                ],
            }
            runner = FakeRunner(failures=[failed_undo])

            with self.assertRaisesRegex(outer.OuterError, "Cleanup was incomplete"):
                outer.cleanup(state, paths=paths, runner=runner)

            self.assertEqual(state["phase"], "cleanup-incomplete")
            self.assertIn(guard_undo, [item["value"] for item in state["undo"]])
            self.assertNotIn(guard_undo, runner.commands)
            self.assertEqual(outer.load_state(paths)["phase"], "cleanup-incomplete")


class MigrationTests(IsolatedRuntimeTest):
    def test_failed_systemd_start_restores_legacy_files_and_service(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            legacy_unit = paths.at("/etc/systemd/system/outer-gateway.service")
            legacy_unit.parent.mkdir(parents=True)
            original = b"legacy service contents\n"
            legacy_unit.write_bytes(original)
            failed_start = ["systemctl", "start", outer.UNIT_NAME]
            runner = FakeRunner(failures=[failed_start])

            def active(_runner, unit=outer.UNIT_NAME):
                return unit == outer.LEGACY_UNIT

            with (
                mock.patch.object(outer, "systemd_active", side_effect=active),
                mock.patch.object(outer, "systemd_enabled", return_value="enabled"),
                mock.patch.object(outer, "dependencies_ok"),
                mock.patch.object(
                    outer, "read_settings_and_data", return_value=({}, ENV_TEXT.encode())
                ),
                mock.patch.object(outer, "checked_server", return_value=TEST_SERVER_IPV4),
                mock.patch.object(outer, "validate_configs"),
                mock.patch.object(outer, "prepare_nft_rules", return_value="wlp5s0"),
                mock.patch.object(outer, "legacy_paths", return_value=[legacy_unit]),
            ):
                with self.assertRaisesRegex(outer.OuterError, "previous legacy gateway was restored"):
                    outer.start(paths, runner)

            self.assertEqual(legacy_unit.read_bytes(), original)
            failed_index = runner.commands.index(failed_start)
            restored_start = ["systemctl", "start", outer.LEGACY_UNIT]
            self.assertEqual(runner.commands.count(failed_start), 1)
            self.assertLess(failed_index, runner.commands.index(restored_start))
            self.assertFalse(paths.state.exists())


    def test_stop_recovers_an_interrupted_legacy_migration_before_releasing_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            legacy_unit = paths.at("/etc/systemd/system/outer-gateway.service")
            legacy_unit.parent.mkdir(parents=True)
            legacy_unit.write_bytes(b"previous service")
            transaction = outer.FileTransaction(paths, "interrupted-migration")
            transaction.remove(legacy_unit)
            outer.atomic_json(transaction.directory / "legacy-systemd.json", {"active": True, "enabled": "enabled"})
            state = {"version": 1, "phase": "transition", "migration_backup": str(transaction.directory),
                     "undo": [{"kind": "command", "value": ["nft", "delete", "table", "inet", "outer_vpn_transition"],
                               "protected": True}]}
            outer.save_state(state, paths)
            runner = FakeRunner()
            with mock.patch.object(outer, "systemd_active", return_value=False):
                outer.stop(paths, runner)
            self.assertEqual(legacy_unit.read_bytes(), b"previous service")
            self.assertFalse(paths.state.exists())
            self.assertTrue((transaction.directory / "migration-complete").is_file())
            self.assertLess(runner.commands.index(["systemctl", "start", outer.LEGACY_UNIT]),
                            runner.commands.index(["nft", "delete", "table", "inet", "outer_vpn_transition"]))

    def test_missing_migration_backup_does_not_release_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            state = {"version": 1, "phase": "transition", "migration_backup": "/invalid/location",
                     "undo": [{"kind": "command", "value": ["nft", "delete", "table", "inet", "outer_vpn_guard"],
                               "protected": True}]}
            outer.save_state(state, paths)
            runner = FakeRunner()
            with self.assertRaises(outer.OuterError):
                outer.stop(paths, runner)
            self.assertEqual(runner.commands, [])
            self.assertTrue(paths.state.exists())

    def test_stop_does_not_undo_a_running_successful_migration(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            legacy_unit = paths.at("/etc/systemd/system/outer-gateway.service")
            legacy_unit.parent.mkdir(parents=True)
            legacy_unit.write_bytes(b"previous service")
            transaction = outer.FileTransaction(paths, "completed-migration")
            transaction.remove(legacy_unit)
            outer.atomic_json(transaction.directory / "legacy-systemd.json", {"active": True, "enabled": "enabled"})
            state = {"version": 1, "phase": "running", "migration_backup": str(transaction.directory),
                     "undo": [{"kind": "command", "value": ["nft", "delete", "table", "inet", "outer_vpn_guard"],
                               "protected": True}]}
            outer.save_state(state, paths)
            runner = FakeRunner()
            with mock.patch.object(outer, "systemd_active", return_value=True):
                outer.stop(paths, runner)
            self.assertFalse(legacy_unit.exists())
            self.assertNotIn(["systemctl", "start", outer.LEGACY_UNIT], runner.commands)
            self.assertEqual((transaction.directory / "migration-complete").read_text(), "committed\n")


class NetworkOrderingTests(IsolatedRuntimeTest):
    def test_network_routes_and_dns_are_installed_in_fail_closed_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            runner = FakeRunner()
            state = {"version": 1, "phase": "transition", "undo": []}
            settings = {
                "vless": outer.parse_vless_url(VALID_VLESS_URL),
                "endpoints": TEST_ENDPOINTS,
                "interface": "proton0",
                "dns": "1.1.1.1",
            }
            inventory = {
                "physical": "eth0",
                "gateway": "192.0.2.1",
                "outer_route_exists": False,
                "defaults": [{
                    "dst": "default",
                    "gateway": "192.0.2.1",
                    "dev": "eth0",
                    "protocol": "dhcp",
                    "metric": 100,
                }],
            }

            outer._network_before_cores(
                state, settings, TEST_SERVER_IPV4, inventory, paths, runner
            )
            outer._network_after_probe(state, settings, inventory, paths, runner)
            commands = runner.commands

            def index(command):
                try:
                    return commands.index(command)
                except ValueError:
                    self.fail(f"expected fake command was not issued: {command!r}")

            outer_route = [
                "ip", "-4", "route", "add", f"{TEST_SERVER_IPV4}/32",
                "via", inventory["gateway"], "dev", inventory["physical"],
                "metric", "0", "proto", outer.MANAGED_ROUTE_PROTO,
            ]
            guard = ["nft", "-f", "-"]
            default_via_namespace = [
                "ip", "-4", "route", "add", "default", "via", outer.NS_IP,
                "dev", outer.HOST_IF, "metric", outer.GATEWAY_METRIC,
                "proto", outer.MANAGED_ROUTE_PROTO,
            ]
            old_default = [
                "ip", "-4", "route", "del", "default", "via", "192.0.2.1",
                "dev", "eth0", "proto", "dhcp", "metric", "100",
            ]
            dns_route = ["resolvectl", "dns", outer.HOST_IF, settings["dns"]]

            self.assertLess(index(outer_route), index(guard))
            for endpoint in TEST_ENDPOINTS:
                fallback = [
                    "ip", "-4", "route", "add", "blackhole", f"{endpoint}/32",
                    "metric", outer.BLACKHOLE_METRIC,
                ]
                tunnel_route = [
                    "ip", "-4", "route", "add", f"{endpoint}/32", "via",
                    outer.NS_IP, "dev", outer.HOST_IF, "metric", "0", "proto", outer.MANAGED_ROUTE_PROTO,
                ]
                self.assertLess(index(guard), index(fallback))
                self.assertLess(index(fallback), index(tunnel_route))
                self.assertLess(index(tunnel_route), index(default_via_namespace))

            ipv6_blackhole = [
                "ip", "-6", "route", "add", "blackhole", "default",
                "table", outer.IPV6_TABLE,
            ]
            ipv6_rule = [
                "ip", "-6", "rule", "add", "priority", outer.RULE_IPV6,
                "lookup", outer.IPV6_TABLE,
            ]
            self.assertLess(index(ipv6_blackhole), index(default_via_namespace))
            self.assertLess(index(ipv6_rule), index(default_via_namespace))
            self.assertLess(index(default_via_namespace), index(old_default))
            self.assertLess(index(old_default), index(dns_route))

            protected_values = [
                item["value"] for item in state["undo"] if item.get("protected")
            ]
            self.assertIn(
                ["nft", "delete", "table", "inet", "outer_vpn_guard"], protected_values
            )
            self.assertIn(
                [
                    "ip", "-4", "route", "del", "blackhole",
                    f"{TEST_ENDPOINTS[0]}/32", "metric", outer.BLACKHOLE_METRIC,
                ],
                protected_values,
            )


class DnsProbeTests(IsolatedRuntimeTest):
    def test_probe_uses_mocked_udp_and_tcp_dns_sockets(self):
        class DnsSocket:
            def __init__(self, *, tcp):
                self.tcp = tcp
                self.buffer = b""
                self.peer = None

            def __enter__(self):
                return self

            def __exit__(self, *_exc):
                return False

            def settimeout(self, _timeout):
                pass

            def connect(self, peer):
                self.peer = peer

            def sendall(self, data):
                query = data[2:] if self.tcp else data
                query_id = struct.unpack("!H", query[:2])[0]
                response = struct.pack("!HHHHHH", query_id, 0x8180, 1, 0, 0, 0)
                self.buffer = (
                    struct.pack("!H", len(response)) + response if self.tcp else response
                )

            def recv(self, length):
                amount = min(length, 3) if self.tcp else length
                data, self.buffer = self.buffer[:amount], self.buffer[amount:]
                return data

        udp_socket = DnsSocket(tcp=False)
        tcp_socket = DnsSocket(tcp=True)
        with (
            mock.patch.object(outer.socket, "socket", return_value=udp_socket) as udp_create,
            mock.patch.object(
                outer.socket, "create_connection", return_value=tcp_socket
            ) as tcp_create,
        ):
            outer.probe_tunnel("1.1.1.1")

        udp_create.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
        tcp_create.assert_called_once_with(("1.1.1.1", 53), timeout=8)
        self.assertEqual(udp_socket.peer, ("1.1.1.1", 53))
