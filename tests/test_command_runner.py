"""External-command safety checks; all subprocesses are mocked."""

import os
import subprocess
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import outer


class RunnerTests(unittest.TestCase):
    def test_uses_trusted_absolute_path_and_reports_argv_and_stderr(self):
        runner = outer.Runner()
        result = subprocess.CompletedProcess([], 1, "", "Could not process rule: Invalid argument\n")
        with mock.patch.object(outer.os.path, "isfile", return_value=True), \
             mock.patch.object(outer.os, "access", return_value=True), \
             mock.patch.object(outer.subprocess, "run", return_value=result) as run:
            with self.assertRaises(outer.OuterError) as error:
                runner.run(["nft", "-f", "-"], input_text="irrelevant")
        self.assertEqual(run.call_args.args[0], ["/usr/sbin/nft", "-f", "-"])
        self.assertIn("/usr/sbin/nft -f -", str(error.exception))
        self.assertIn("Could not process rule: Invalid argument", str(error.exception))

    def test_nested_namespace_command_is_also_absolute(self):
        runner = outer.Runner()
        result = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(outer.os.path, "isfile", return_value=True), \
             mock.patch.object(outer.os, "access", return_value=True), \
             mock.patch.object(outer.subprocess, "run", return_value=result) as run:
            runner.run(["ip", "netns", "exec", "outer-vpn", "sysctl", "-w", "net.ipv4.ip_forward=1"])
        self.assertEqual(run.call_args.args[0][:5], ["/usr/sbin/ip", "netns", "exec", "outer-vpn", "/usr/sbin/sysctl"])

    def test_sensitive_argv_and_stderr_are_redacted(self):
        runner = outer.Runner()
        password = "fake-sensitive-password"
        key = "fake-sensitive-reality-key"
        identifier = "01234567-89ab-cdef-0123-456789abcdef"
        runner.add_secrets(password, key, identifier)
        stderr = f"password={password} publicKey={key} id={identifier} error: invalid setting"
        result = subprocess.CompletedProcess([], 1, "", stderr)
        with mock.patch.object(outer.subprocess, "run", return_value=result):
            with self.assertRaises(outer.OuterError) as error:
                runner.run(["/usr/local/bin/xray", "--password", password, "run"])
        message = str(error.exception)
        self.assertIn("/usr/local/bin/xray", message)
        self.assertIn("error: invalid setting", message)
        for secret in (password, key, identifier):
            self.assertNotIn(secret, message)

    def test_path_environment_is_never_used(self):
        runner = outer.Runner()
        result = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.dict(os.environ, {"PATH": "/tmp/fake"}), \
             mock.patch.object(outer.os.path, "isfile", return_value=True), \
             mock.patch.object(outer.os, "access", return_value=True), \
             mock.patch.object(outer.subprocess, "run", return_value=result) as run:
            runner.run(["sysctl", "-n", "net.ipv4.ip_forward"])
        self.assertEqual(run.call_args.args[0][0], "/usr/sbin/sysctl")

    def test_spawned_core_uses_absolute_ip_and_absolute_binary(self):
        with mock.patch.object(outer.os.path, "isfile", return_value=True), \
             mock.patch.object(outer.os, "access", return_value=True), \
             mock.patch.object(outer.subprocess, "Popen") as popen:
            outer._spawn_core(["ip", "netns", "exec", "outer-vpn",
                               "/usr/local/lib/outer-vpn/xray", "run"])
        command = popen.call_args.args[0]
        self.assertEqual(command[0], "/usr/sbin/ip")
        self.assertEqual(command[4], "/usr/local/lib/outer-vpn/xray")

    def test_failed_core_reports_bounded_redacted_stderr_and_argv(self):
        secret = "fake-core-secret"
        process = mock.Mock()
        process.stderr = io.BytesIO(("x" * 9000 + "\nfatal password=" + secret).encode())
        process.poll.return_value = 17
        runner = outer.Runner()
        runner.add_secrets(secret)
        with mock.patch.object(outer.os.path, "isfile", return_value=True), \
             mock.patch.object(outer.os, "access", return_value=True), \
             mock.patch.object(outer.subprocess, "Popen", return_value=process):
            child = outer._spawn_core(["ip", "netns", "exec", "outer-vpn", "/usr/local/bin/xray", "run"])
        error = child.failure("Core failed", runner)
        self.assertIn("/usr/sbin/ip netns exec outer-vpn /usr/local/bin/xray run", str(error))
        self.assertIn("fatal password=", str(error))
        self.assertNotIn(secret, str(error))
        self.assertLess(len(str(error)), 8500)

    def test_missing_tool_failure_also_reports_argv_and_error(self):
        with mock.patch.object(outer.os.path, "isfile", return_value=False):
            with self.assertRaises(outer.OuterError) as error:
                outer.Runner().run(["nft", "-f", "-"])
        self.assertIn("/usr/sbin/nft -f -", str(error.exception))
        self.assertIn("stderr:", str(error.exception))

    def test_unknown_relative_external_commands_are_rejected(self):
        with self.assertRaises(outer.OuterError):
            outer.command_argv(["custom-tool", "--version"])
        with self.assertRaises(outer.OuterError):
            outer.command_argv(["./custom-tool", "--version"])

    def test_cli_writes_redacted_failure_to_system_journal_and_stderr(self):
        secret = "synthetic-private-value"
        runner = outer.RUNNER
        previous = set(runner.secrets)
        runner.add_secrets(secret)
        self.addCleanup(lambda: setattr(runner, "secrets", previous))
        failure = outer.command_failure(["/usr/sbin/nft", "-f", "-"], 1,
                                        f"bad rule; password={secret}", secrets=runner.secrets)
        stream = io.StringIO()
        with mock.patch.object(outer, "require_root"), \
             mock.patch.object(outer, "operation_lock", return_value=contextlib.nullcontext()), \
             mock.patch.object(outer, "start", side_effect=failure), \
             mock.patch.object(outer.syslog, "openlog"), \
             mock.patch.object(outer.syslog, "syslog") as journal, \
             contextlib.redirect_stderr(stream):
            self.assertEqual(outer.main(["start"]), 1)
        message = journal.call_args.args[1]
        for output in (stream.getvalue(), message):
            self.assertIn("/usr/sbin/nft -f -", output)
            self.assertIn("bad rule", output)
            self.assertNotIn(secret, output)

    def test_failed_action_records_sanitized_details_in_recovery_journal(self):
        class FailingRunner:
            secrets = {"sensitive-password"}

            def run(self, command, **kwargs):
                raise outer.command_failure(["/usr/sbin/nft", "-f", "-"], 1,
                                            "invalid password=sensitive-password", secrets=self.secrets)

        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            state = {"version": 1, "phase": "transition", "undo": []}
            with self.assertRaises(outer.OuterError):
                outer._action(state, ["nft", "-f", "-"],
                              ["nft", "delete", "table", "inet", "outer_vpn_transition"],
                              protected=True, paths=paths, runner=FailingRunner())
            error = outer.load_state(paths)["last_error"]
            self.assertIn("/usr/sbin/nft -f -", error)
            self.assertIn("invalid password=", error)
            self.assertNotIn("sensitive-password", error)


if __name__ == "__main__":
    unittest.main()
