"""Policy-route and firewall tests using simulated command results only."""

import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import outer


class RecordingRunner:
    def __init__(self, route_dev="ogw-host"):
        self.calls = []
        self.route_dev = route_dev

    def run(self, args, **kwargs):
        args = [str(value) for value in args]
        self.calls.append((args, kwargs.get("input_text")))
        out = ""
        if args[:5] == ["ip", "-d", "-j", "link", "show"]:
            out = json.dumps([{"flags": ["UP"], "linkinfo": {"info_kind": "wireguard"}}])
        elif args[:3] == ["wg", "show", "proton0"]:
            out = "public-key\t198.51.100.10:443\n" if args[-1] == "endpoints" else "0xca6c\n"
        elif args[:5] == ["ip", "-j", "-4", "route", "get"]:
            out = json.dumps([{"dev": self.route_dev}])
        return subprocess.CompletedProcess(args, 0, out, "")


class RouteSafetyTests(unittest.TestCase):
    def test_wireguard_peer_requires_allowlisted_address_and_marked_veth_route(self):
        settings = {"interface": "proton0", "endpoints": ["198.51.100.10"]}
        good = RecordingRunner()
        self.assertEqual(outer._proton_peers(settings, good), (("198.51.100.10", 443),))
        self.assertIn("mark", good.calls[-1][0])
        self.assertEqual(outer._proton_peers(settings, RecordingRunner("eth0")), ())
        self.assertEqual(outer._proton_peers({"interface": "proton0", "endpoints": ["198.51.100.11"]}, good), ())

    def test_endpoint_policy_table_and_blackhole_are_journaled(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            state = {"version": 1, "phase": "preparing", "undo": []}
            runner = RecordingRunner()
            outer._network_after_probe(state, {"endpoints": ["198.51.100.10"], "dns": "1.1.1.1"},
                                       {"defaults": []}, paths, runner)
            commands = [args for args, _ in runner.calls]
            self.assertTrue(any(outer.PROTON_TABLE in args and "blackhole" in args for args in commands))
            self.assertTrue(any(outer.PROTON_TABLE in args and "rule" in args and "198.51.100.10/32" in args for args in commands))
            protected = [item for item in state["undo"] if item["protected"]]
            self.assertTrue(any(outer.PROTON_TABLE in item["value"] and "blackhole" in item["value"] for item in protected))
            self.assertTrue(any(outer.PROTON_TABLE in item["value"] and "rule" in item["value"] for item in protected))

    def test_guard_only_exempts_wireguard_peer_payload_and_not_ipv6(self):
        rules = outer._guard_script({"vless": {"port": 443}}, "203.0.113.10", "eth0")
        self.assertIn("meta nfproto ipv6 counter drop", rules)
        self.assertIn("ip daddr . udp dport @proton_peers @th,64,32", rules)
        self.assertIn("0x01000000", rules)
        self.assertIn("0x04000000", rules)
        self.assertIn("type filter hook output", rules)
        self.assertIn('oifname @bootstrap_ifaces fib daddr . mark oifname "ogw-host" accept', rules)
        self.assertIn('set bootstrap_ifaces { type ifname; elements = { "ogw-host" }; }', rules)
        strict_rules = outer._guard_script({"vless": {"port": 443}, "strict": True}, "203.0.113.10", "eth0")
        self.assertNotIn('elements = { "ogw-host" }', strict_rules)

    def test_bootstrap_is_limited_to_the_outer_veth_until_a_handshake(self):
        settings = {"interface": "proton0", "endpoints": ["198.51.100.10"], "dns": "1.1.1.1", "strict": False}
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            state = {"version": 1, "phase": "running", "undo": [], "proton_latched": False}
            runner = RecordingRunner()
            with mock.patch.object(outer, "_proton_peers", return_value=()):
                previous = outer.update_proton_guard(state, settings, None, paths=paths, runner=runner)
            initial = next(text for args, text in runner.calls if args == ["nft", "-f", "-"])
            self.assertIn('add element inet outer_vpn_guard bootstrap_ifaces { "ogw-host" }', initial)
            self.assertFalse(state["proton_latched"])
            peers = (("198.51.100.10", 443),)
            runner.calls.clear()
            with mock.patch.object(outer, "_proton_peers", return_value=peers), \
                 mock.patch.object(outer, "_proton_handshake_recent", return_value=True):
                previous = outer.update_proton_guard(state, settings, previous, paths=paths, runner=runner)
            connected = next(text for args, text in runner.calls if args == ["nft", "-f", "-"])
            self.assertIn("flush set inet outer_vpn_guard bootstrap_ifaces", connected)
            self.assertNotIn("add element inet outer_vpn_guard bootstrap_ifaces", connected)
            self.assertTrue(state["proton_latched"])
            runner.calls.clear()
            with mock.patch.object(outer, "_proton_peers", return_value=()):
                outer.update_proton_guard(state, settings, previous, paths=paths, runner=runner)
            disconnected = next(text for args, text in runner.calls if args == ["nft", "-f", "-"])
            self.assertNotIn("add element inet outer_vpn_guard bootstrap_ifaces", disconnected)
            self.assertTrue(state["proton_latched"])

    def test_interface_without_handshake_keeps_default_bootstrap_enabled(self):
        settings = {"interface": "proton0", "endpoints": ["198.51.100.10"], "dns": "1.1.1.1", "strict": False}
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            state = {"version": 1, "phase": "running", "undo": [], "proton_latched": False}
            runner = RecordingRunner()
            with mock.patch.object(outer, "_proton_peers", return_value=(("198.51.100.10", 443),)), \
                 mock.patch.object(outer, "_proton_handshake_recent", return_value=False):
                outer.update_proton_guard(state, settings, None, paths=paths, runner=runner)
            script = next(text for args, text in runner.calls if args == ["nft", "-f", "-"])
            self.assertIn('add element inet outer_vpn_guard bootstrap_ifaces { "ogw-host" }', script)
            self.assertFalse(state["proton_latched"])

    def test_first_handshake_latches_even_when_peer_address_is_unchanged(self):
        peers = (("198.51.100.10", 443),)
        settings = {"interface": "proton0", "endpoints": ["198.51.100.10"], "dns": "1.1.1.1", "strict": False}
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            state = {"version": 1, "phase": "running", "undo": [], "proton_latched": False}
            runner = RecordingRunner()
            with mock.patch.object(outer, "_proton_peers", return_value=peers), \
                 mock.patch.object(outer, "_proton_handshake_recent", return_value=True):
                outer.update_proton_guard(state, settings, peers, paths=paths, runner=runner)
            script = next(text for args, text in runner.calls if args == ["nft", "-f", "-"])
            self.assertNotIn("add element inet outer_vpn_guard bootstrap_ifaces", script)
            self.assertTrue(state["proton_latched"])

    def test_strict_mode_never_enables_outer_bootstrap(self):
        settings = {"interface": "proton0", "endpoints": ["198.51.100.10"], "dns": "1.1.1.1", "strict": True}
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            state = {"version": 1, "phase": "running", "undo": [], "proton_latched": False}
            runner = RecordingRunner()
            with mock.patch.object(outer, "_proton_peers", return_value=()):
                outer.update_proton_guard(state, settings, None, paths=paths, runner=runner)
            script = next(text for args, text in runner.calls if args == ["nft", "-f", "-"])
            self.assertNotIn("add element inet outer_vpn_guard bootstrap_ifaces", script)

    def test_handshake_check_requires_a_recent_wireguard_timestamp(self):
        settings = {"interface": "proton0"}
        runner = RecordingRunner()
        with mock.patch.object(outer.time, "time", return_value=1000):
            with mock.patch.object(runner, "run", return_value=subprocess.CompletedProcess([], 0, "key\t950\n", "")):
                self.assertTrue(outer._proton_handshake_recent(settings, runner))
            with mock.patch.object(runner, "run", return_value=subprocess.CompletedProcess([], 0, "key\t0\n", "")):
                self.assertFalse(outer._proton_handshake_recent(settings, runner))
            with mock.patch.object(runner, "run", return_value=subprocess.CompletedProcess([], 0, "key\t700\n", "")):
                self.assertFalse(outer._proton_handshake_recent(settings, runner))

    def test_default_route_comparison_includes_saved_attributes(self):
        old = {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "metric": 100,
               "protocol": "dhcp", "prefsrc": "192.0.2.2", "flags": ["onlink"]}
        self.assertTrue(outer._same_route(old, dict(old)))
        self.assertFalse(outer._same_route(old, {**old, "protocol": "static"}))
        self.assertFalse(outer._same_route(old, {**old, "prefsrc": "192.0.2.3"}))
        self.assertFalse(outer._same_route(old, {**old, "flags": []}))

    def test_outer_failure_removes_routes_but_retains_direct_egress_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            guard = ["nft", "delete", "table", "inet", "outer_vpn_guard"]
            veth = ["ip", "link", "delete", "ogw-host"]
            state = {"version": 1, "phase": "running", "undo": [
                {"kind": "command", "value": guard, "protected": True},
                {"kind": "command", "value": veth, "protected": False},
            ]}
            outer.save_state(state, paths)
            runner = RecordingRunner()
            outer.cleanup(paths=paths, runner=runner, preserve_guard=True)
            self.assertIn(veth, [args for args, _ in runner.calls])
            self.assertNotIn(guard, [args for args, _ in runner.calls])
            self.assertEqual(outer.load_state(paths)["phase"], "failed-guarded")
            rules = outer._guard_script({"vless": {"port": 443}}, "203.0.113.10", "eth0")
            output_chain = rules.split("chain output", 1)[1].split("chain forward", 1)[0]
            self.assertNotIn('oifname "eth0" accept', output_chain)
            self.assertIn("counter drop", output_chain)

    def test_failure_hold_survives_post_stop_until_explicit_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            state = {"version": 1, "phase": "transition", "undo": [{
                "kind": "command", "value": ["nft", "delete", "table", "inet", "outer_vpn_transition"],
                "protected": True,
            }]}
            outer.save_state(state, paths)
            (paths.runtime / "hold-guard").write_text("hold\n")
            runner = RecordingRunner()
            outer.cleanup(paths=paths, runner=runner)
            self.assertTrue(paths.state.exists())
            self.assertFalse(runner.calls)
            (paths.runtime / "hold-guard").unlink()
            outer.cleanup(paths=paths, runner=runner)
            self.assertFalse(paths.state.exists())
            self.assertEqual(runner.calls[-1][0], ["nft", "delete", "table", "inet", "outer_vpn_transition"])

    def test_inactive_service_does_not_report_a_stale_peer_as_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = outer.Paths(Path(temporary))
            outer.save_state({"version": 1, "phase": "failed-guarded", "undo": [], "proton_ready": True}, paths)
            output = io.StringIO()
            with mock.patch.object(outer, "systemd_active", return_value=False), mock.patch("sys.stdout", output):
                outer.status(paths, RecordingRunner())
            self.assertIn("Proton WireGuard: not verified", output.getvalue())

    def test_unit_is_one_notifying_supervisor_with_cgroup_cleanup(self):
        unit = outer.service_unit()
        self.assertIn("Type=notify", unit)
        self.assertIn("NotifyAccess=main", unit)
        self.assertIn("KillMode=mixed", unit)
        self.assertEqual(unit.count("ExecStart="), 1)


if __name__ == "__main__":
    unittest.main()
