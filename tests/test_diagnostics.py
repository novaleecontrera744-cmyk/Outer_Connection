"""Isolated diagnostics and nftables recovery tests for outer.py."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import outer


TEST_UUID = "01234567-89ab-cdef-0123-456789abcdef"
TEST_PUBLIC_KEY = "A" * 43
TEST_SERVER = "198.51.100.42"
TEST_VLESS_URL = (
    f"vless://{TEST_UUID}@edge.example.test:8443"
    "?encryption=none&type=tcp&security=reality&flow=xtls-rprx-vision"
    "&sni=front.example.net&fp=chrome"
    f"&pbk={TEST_PUBLIC_KEY}&sid=deadbeef&spx=%2Fprobe"
)
TEST_ENV = (
    f"VLESS_URL={TEST_VLESS_URL}\n"
    "PROTON_ENDPOINTS=8.8.8.8,9.9.9.9\n"
    "PROTON_INTERFACE=proton0\n"
    "DNS_SERVER=1.1.1.1\n"
)


def _tool(command):
    return Path(str(command[0])).name


class RecordingRunner:
    """A command sink with deterministic route and nft responses."""

    def __init__(self, fail_when=None, failure_stderr="Operation not permitted."):
        self.calls = []
        self.json_calls = []
        self.fail_when = fail_when
        self.failure_stderr = failure_stderr

    def run(self, args, *, input_text=None, check=True, timeout=30):
        command = [str(value) for value in args]
        call = {"args": command, "input_text": input_text, "check": check, "timeout": timeout}
        self.calls.append(call)
        failed = bool(self.fail_when and self.fail_when(command, input_text))
        stdout, stderr = "", self.failure_stderr if failed else ""
        if _tool(command) == "ip":
            args = command[1:]
            if args == ["netns", "list"]:
                stdout = ""
            elif args[:3] == ["link", "show", "dev"]:
                return SimpleNamespace(returncode=1, stdout="", stderr="Device does not exist.")
            elif args[:1] == ["-j"] and "route" in args:
                stdout = "[]"
            elif args[:1] == ["-j"] and "address" in args:
                stdout = "[]"
        elif _tool(command) == "sysctl" and command[1:2] == ["-n"]:
            stdout = "0\n"
        result = SimpleNamespace(returncode=1 if failed else 0, stdout=stdout, stderr=stderr)
        if failed and check:
            raise outer.OuterError(f"fake command failed: {stderr}")
        return result

    def json(self, args):
        command = [str(value) for value in args]
        self.json_calls.append(command)
        tool, args = _tool(command), command[1:]
        if tool == "nft":
            return {"nftables": []}
        if tool == "ip":
            if args == ["-j", "-4", "route", "show", "table", "main"]:
                return [{"dst": "default", "gateway": "192.0.2.1", "dev": "wlp5s0", "metric": 600}]
            if args[:4] == ["-j", "-4", "route", "get"]:
                return [{"dst": TEST_SERVER, "gateway": "192.0.2.1", "dev": "wlp5s0"}]
        return []


def _mutates_network(call):
    command = call["args"]
    tool, args = _tool(command), command[1:]
    if tool == "nft":
        return "-c" not in args and not ("list" in args or "-j" in args)
    if tool == "sysctl":
        return "-w" in args
    if tool == "systemctl":
        return bool(args and args[0] in {"start", "stop", "enable", "disable", "daemon-reload"})
    if tool == "resolvectl":
        return bool(args and args[0] not in {"status", "query"})
    if tool == "ip":
        return any(word in args for word in ("add", "del", "delete", "replace", "change", "flush"))
    return False


@contextlib.contextmanager
def _fake_system_binaries():
    names = ("ip", "nft", "sysctl", "wg", "systemctl", "resolvectl")
    with tempfile.TemporaryDirectory(prefix="outer-fake-tools-") as temporary:
        mapping = {}
        for name in names:
            executable = Path(temporary) / name
            executable.write_text("mock executable\n", encoding="utf-8")
            executable.chmod(0o700)
            mapping[name] = (str(executable),)
        with mock.patch.dict(outer.SYSTEM_TOOLS, mapping, clear=True):
            with mock.patch.dict(os.environ, {"PATH": ""}):
                yield mapping


class CommandDiagnosticsTests(unittest.TestCase):
    def test_outer_error_and_service_stderr_keep_argv_and_stderr_but_redact_secrets(self):
        secret = "sensitive-token-value"
        with _fake_system_binaries() as tools:
            with mock.patch.object(
                outer.subprocess,
                "run",
                return_value=SimpleNamespace(
                    returncode=2,
                    stdout="",
                    stderr=f"permission denied for token={secret}",
                ),
            ):
                with self.assertRaises(outer.OuterError) as caught:
                    outer.Runner().run(["nft", "--token", secret, "list", "tables"])

            message = str(caught.exception)
            self.assertIn("argv:", message)
            self.assertIn(tools["nft"][0], message)
            self.assertIn("--token", message)
            self.assertIn("stderr:", message)
            self.assertIn("permission denied", message)
            self.assertIn("[redacted]", message)
            self.assertNotIn(secret, message)

            stderr = io.StringIO()
            with mock.patch.object(outer, "require_root"), \
                 mock.patch.object(outer, "operation_lock", return_value=contextlib.nullcontext()), \
                 mock.patch.object(outer, "start", side_effect=caught.exception), \
                 contextlib.redirect_stderr(stderr):
                result = outer.main(["start"])
            self.assertEqual(result, 1)
            journal_stream = stderr.getvalue()
            self.assertIn("argv:", journal_stream)
            self.assertIn("stderr:", journal_stream)
            self.assertNotIn(secret, journal_stream)

    def test_runner_uses_trusted_absolute_paths_with_an_empty_path(self):
        with _fake_system_binaries() as tools:
            fake_process = mock.Mock(
                return_value=SimpleNamespace(returncode=0, stdout="", stderr="")
            )
            with mock.patch.object(outer.subprocess, "run", fake_process):
                runner = outer.Runner()
                for name, (expected_path,) in tools.items():
                    runner.run([name, "--version"])
                    command = fake_process.call_args.args[0]
                    self.assertEqual(command[0], expected_path)
                    self.assertTrue(Path(command[0]).is_absolute())

                runner.run(["ip", "netns", "exec", "outer-vpn", "sysctl", "-n", "net.ipv4.ip_forward"])
                nested_command = fake_process.call_args.args[0]
                self.assertEqual(nested_command[0], tools["ip"][0])
                self.assertEqual(nested_command[4], tools["sysctl"][0])


class IsolatedLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="outer-diagnostics-")
        self.addCleanup(self.temporary.cleanup)
        self.paths = outer.Paths(Path(self.temporary.name))
        self.paths.env.parent.mkdir(parents=True)
        self.paths.env.write_text(TEST_ENV, encoding="utf-8")

    def _start_patches(self):
        return contextlib.ExitStack()

    def _start(self, runner):
        patches = self._start_patches()
        patches.enter_context(mock.patch.object(outer, "require_root"))
        patches.enter_context(mock.patch.object(outer, "dependencies_ok", return_value=None))
        patches.enter_context(mock.patch.object(outer, "validate_configs", return_value=None))
        patches.enter_context(mock.patch.object(outer, "resolve_ipv4", return_value=TEST_SERVER))
        patches.enter_context(mock.patch.object(outer, "systemd_active", return_value=False))
        try:
            outer.start(self.paths, runner)
        finally:
            patches.close()

    def _stop_twice(self, runner):
        with mock.patch.object(outer, "require_root"):
            outer.stop(self.paths, runner)
            calls_after_first_stop = len(runner.calls)
            outer.stop(self.paths, runner)
        self.assertFalse(self.paths.state.exists())
        self.assertEqual(len(runner.calls), calls_after_first_stop)

    def test_nft_validation_failure_aborts_before_mutation_and_stop_is_safe(self):
        runner = RecordingRunner(
            fail_when=lambda command, script: (
                _tool(command) == "nft"
                and "-c" in command
                and "outer_vpn_nat" in (script or "")
            )
        )
        with self.assertRaises(outer.OuterError):
            self._start(runner)

        checks = [
            call for call in runner.calls
            if _tool(call["args"]) == "nft" and "-c" in call["args"]
        ]
        self.assertTrue(checks, "start must validate its nft scripts with nft -c")
        self.assertTrue(any("outer_vpn_nat" in (call["input_text"] or "") for call in checks))
        self.assertFalse(
            any(_mutates_network(call) for call in runner.calls),
            "a failed nft -c must leave networking untouched",
        )
        self.assertFalse(self.paths.state.exists(), "validation failure must not leave a recovery journal")
        self._stop_twice(runner)

    def test_every_nft_script_is_checked_before_the_first_install(self):
        runner = RecordingRunner()
        self._start(runner)

        checks = [
            (index, call) for index, call in enumerate(runner.calls)
            if _tool(call["args"]) == "nft" and "-c" in call["args"]
        ]
        self.assertGreaterEqual(len(checks), 3, "transition, guard/NAT, and dynamic scripts need validation")
        scripts = "\n".join(call["input_text"] or "" for _, call in checks)
        for required in (
            "outer_vpn_transition",
            "outer_vpn_guard",
            "outer_vpn_nat",
            "flush set inet outer_vpn_guard proton_ifaces",
        ):
            self.assertIn(required, scripts)

        mutations = [index for index, call in enumerate(runner.calls) if _mutates_network(call)]
        self.assertTrue(mutations, "start should install its transition guard")
        self.assertLess(max(index for index, _ in checks), min(mutations))
        self._stop_twice(runner)

    def test_guard_creation_failure_is_cleared_by_repeated_stop(self):
        runner = RecordingRunner(
            fail_when=lambda command, script: (
                _tool(command) == "nft" and "-f" in command and "-c" not in command
            )
        )
        with self.assertRaises(outer.OuterError):
            self._start(runner)
        self.assertTrue(
            any(_tool(call["args"]) == "nft" and "-f" in call["args"] for call in runner.calls),
            "the test must fail during guard installation, not validation",
        )
        self._stop_twice(runner)

    def test_dynamic_nft_update_failure_remains_recoverable_and_idempotent(self):
        guard_undo = ["nft", "delete", "table", "inet", "outer_vpn_guard"]
        state = {
            "version": 1,
            "phase": "failed-guarded",
            "undo": [{"kind": "command", "value": guard_undo, "protected": True}],
        }
        outer.save_state(state, self.paths)
        runner = RecordingRunner(
            fail_when=lambda command, script: (
                _tool(command) == "nft"
                and "-f" in command
                and "-c" not in command
                and "flush set inet outer_vpn_guard" in (script or "")
            )
        )
        settings = {
            "interface": "proton0",
            "endpoints": ["8.8.8.8", "9.9.9.9"],
            "dns": "1.1.1.1",
            "strict": False,
        }
        with mock.patch.object(outer, "_proton_peers", return_value=()), \
             mock.patch.object(outer, "_proton_handshake_recent", return_value=False):
            with self.assertRaises(outer.OuterError):
                outer.update_proton_guard(state, settings, None, paths=self.paths, runner=runner)

        self.assertTrue(any("flush set inet outer_vpn_guard" in (call["input_text"] or "")
                            for call in runner.calls))
        self.assertIn(guard_undo, [item["value"] for item in outer.load_state(self.paths)["undo"]])
        self._stop_twice(runner)


class DebugRulesTests(unittest.TestCase):
    def test_debug_rules_cli_shows_scripts_commands_and_detected_physical_interface(self):
        with tempfile.TemporaryDirectory(prefix="outer-debug-rules-") as temporary:
            env_path = Path(temporary) / ".env"
            env_path.write_text(TEST_ENV, encoding="utf-8")
            subprocess_calls = []

            def fake_subprocess(command, **kwargs):
                command = [str(value) for value in command]
                subprocess_calls.append(command)
                tool, args = _tool(command), command[1:]
                stdout, stderr, returncode = "", "", 0
                if tool == "ip":
                    if args == ["netns", "list"]:
                        pass
                    elif args[:3] == ["link", "show", "dev"]:
                        returncode, stderr = 1, "Device does not exist."
                    elif args == ["-j", "-4", "route", "show", "table", "main"]:
                        stdout = json.dumps([
                            {"dst": "default", "gateway": "192.0.2.1", "dev": "wlp5s0", "metric": 600}
                        ])
                    elif args[:4] == ["-j", "-4", "route", "get"]:
                        stdout = json.dumps([{"dst": TEST_SERVER, "gateway": "192.0.2.1", "dev": "wlp5s0"}])
                    elif args[:1] == ["-j"]:
                        stdout = "[]"
                elif tool == "nft":
                    stdout = json.dumps({"nftables": []})
                return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

            stdout = io.StringIO()
            with _fake_system_binaries() as tools, \
                 mock.patch.object(outer.subprocess, "run", side_effect=fake_subprocess), \
                 mock.patch.object(outer, "dependencies_ok", return_value=None), \
                 mock.patch.object(outer, "validate_configs", return_value=None), \
                 mock.patch.object(outer, "resolve_ipv4", return_value=TEST_SERVER), \
                 mock.patch.object(outer, "systemd_active", return_value=False), \
                 contextlib.redirect_stdout(stdout):
                result = outer.main(["debug-rules", "--env", str(env_path)])

            self.assertEqual(result, 0)
            output = stdout.getvalue()
            self.assertIn("wlp5s0", output)
            for script in (
                "table inet outer_vpn_transition",
                "table inet outer_vpn_guard",
                "table ip outer_vpn_nat",
                "flush set inet outer_vpn_guard proton_ifaces",
            ):
                self.assertIn(script, output)
            nft_command_lines = [
                line for line in output.splitlines()
                if "nft" in line.lower() and ("-c" in line or "-f" in line)
            ]
            self.assertGreaterEqual(len(nft_command_lines), 3)
            self.assertTrue(any("-c" in line for line in nft_command_lines))
            self.assertTrue(any("-f" in line for line in nft_command_lines))
            self.assertNotIn(TEST_UUID, output)
            self.assertNotIn(TEST_VLESS_URL, output)
            self.assertTrue(all(Path(command[0]).is_absolute() for command in subprocess_calls))
            self.assertTrue(all(path[0] in {call[0] for call in subprocess_calls}
                                for path in tools.values() if Path(path[0]).name in {"ip", "nft"}))


class StatusReportingTests(unittest.TestCase):
    def _assert_status(self, output, *, guard, journal):
        lines = [line.lower() for line in output.splitlines()]
        guard_lines = [line for line in lines if "guard" in line]
        journal_lines = [line for line in lines if "journal" in line]
        self.assertTrue(guard_lines, f"status omitted guard state: {output}")
        self.assertTrue(journal_lines, f"status omitted journal state: {output}")
        if guard:
            self.assertTrue(any("present" in line or "active" in line for line in guard_lines), output)
        else:
            self.assertTrue(any(term in line for line in guard_lines for term in ("not present", "absent", "none")), output)
        if journal:
            self.assertTrue(any(term in line for line in journal_lines for term in ("present", "found", "loaded")), output)
        else:
            self.assertTrue(any(term in line for line in journal_lines for term in ("not present", "absent", "none")), output)

    def test_status_distinguishes_guard_presence_from_journal_presence(self):
        with tempfile.TemporaryDirectory(prefix="outer-status-") as temporary:
            paths = outer.Paths(Path(temporary))
            route_only = {
                "version": 1,
                "phase": "cleanup-incomplete",
                "undo": [{"kind": "restore_sysctl", "value": ["net.ipv4.ip_forward", "0"]}],
            }
            outer.save_state(route_only, paths)
            output = io.StringIO()
            with mock.patch.object(outer, "systemd_active", return_value=False), \
                 contextlib.redirect_stdout(output):
                outer.status(paths, RecordingRunner())
            self._assert_status(output.getvalue(), guard=False, journal=True)

            with_guard = {
                "version": 1,
                "phase": "failed-guarded",
                "undo": [{
                    "kind": "command",
                    "value": ["nft", "delete", "table", "inet", "outer_vpn_guard"],
                    "protected": True,
                }],
            }
            outer.save_state(with_guard, paths)
            output = io.StringIO()
            with mock.patch.object(outer, "systemd_active", return_value=False), \
                 contextlib.redirect_stdout(output):
                outer.status(paths, RecordingRunner())
            self._assert_status(output.getvalue(), guard=True, journal=True)

            paths.state.unlink()
            output = io.StringIO()
            with mock.patch.object(outer, "systemd_active", return_value=False), \
                 contextlib.redirect_stdout(output):
                outer.status(paths, RecordingRunner())
            self._assert_status(output.getvalue(), guard=False, journal=False)


if __name__ == "__main__":
    unittest.main()
