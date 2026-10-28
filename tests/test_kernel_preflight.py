"""Kernel nftables preflight tests using simulated command runners only."""

import json
import re
import subprocess
import unittest
from types import SimpleNamespace
from unittest import mock

import outer


SETTINGS = {
    "vless": {"port": 443},
    "endpoints": ["198.51.100.10"],
    "interface": "proton0",
    "strict": False,
}
SERVER = "203.0.113.10"
PHYSICAL = "wlp5s0"
TOKENS = ("a" * 32, "b" * 32)
PROBE_GATE = "meta mark 0x0 meta mark != 0x0 "


class RecordingRunner:
    def __init__(self, *, fail_apply_at=None, existing_tables=()):
        self.calls = []
        self.fail_apply_at = fail_apply_at
        self.apply_count = 0
        self.existing_tables = set(existing_tables)

    def run(self, args, *, input_text=None, check=True, timeout=30):
        args = [str(value) for value in args]
        self.calls.append({"args": args, "input_text": input_text, "check": check, "timeout": timeout})
        if args == ["nft", "-f", "-"]:
            self.apply_count += 1
            if self.fail_apply_at == self.apply_count:
                raise outer.OuterError("simulated kernel rejection")
        return subprocess.CompletedProcess(args, 0, "", "")

    def json(self, args):
        return {"nftables": [{"table": {"family": family, "name": name}}
                             for family, name in self.existing_tables]}


def _chain_blocks(script):
    blocks = []
    active = None
    for line in script.splitlines():
        stripped = line.strip()
        if active is None:
            match = re.fullmatch(r"chain\s+(\S+)\s*\{", stripped)
            if match:
                active = (match.group(1), [])
            continue
        if stripped == "}":
            blocks.append(active)
            active = None
        else:
            active[1].append(stripped)
    return blocks


def _chain_rules(script):
    return [line for _, block in _chain_blocks(script) for line in block
            if line and not line.startswith("type ")]


def _chain_policies(script):
    return [line for _, block in _chain_blocks(script) for line in block
            if line.startswith("type ")]


class KernelPreflightTests(unittest.TestCase):
    def test_output_bootstrap_rule_avoids_fib_oif_results(self):
        scripts = (_guard := outer._guard_script(SETTINGS, SERVER, PHYSICAL), outer._transition_script())
        bad_fib_result = r"\bfib\b[^;\n]*\b(?:oif|oifname)\b"
        for script in scripts:
            for name, body in _chain_blocks(script):
                if name == "output":
                    self.assertNotRegex("\n".join(body), bad_fib_result)
        self.assertIn("oifname @bootstrap_ifaces accept", _guard)
        for result in ("oif", "oifname"):
            self.assertRegex(f'fib daddr . mark {result} "ogw-host" accept', bad_fib_result)

    def test_probe_plan_uses_temporary_tables_and_inert_exact_rules(self):
        live = outer.nft_rule_plan(SETTINGS, SERVER, PHYSICAL)
        probe = outer.nft_kernel_plan(SETTINGS, SERVER, PHYSICAL, TOKENS[0])
        guard_table = f"ogw_probe_g_{TOKENS[0]}"
        expected_tables = [
            ("inet", f"ogw_probe_t_{TOKENS[0]}"),
            ("inet", guard_table),
            ("ip", f"ogw_probe_n_{TOKENS[0]}"),
        ]
        reserved = {
            ("inet", "outer_vpn_transition"),
            ("inet", "outer_vpn_guard"),
            ("ip", "outer_vpn_nat"),
        }
        self.assertEqual(probe["tables"], expected_tables)
        self.assertFalse(reserved.intersection(probe["tables"]))
        for _, name in probe["tables"]:
            self.assertIn(TOKENS[0], name)
        for family, name in probe["tables"]:
            self.assertIn(f"table {family} {name} {{", probe["setup"])
        for name in ("outer_vpn_transition", "outer_vpn_guard", "outer_vpn_nat"):
            self.assertNotIn(name, probe["setup"])

        expected_rules = [
            re.sub(r"\bdrop$", "accept", rule)
            for rule in _chain_rules(live["transition"] + live["guard"])
        ]
        actual_rules = _chain_rules(probe["setup"])
        self.assertTrue(actual_rules)
        for rule in actual_rules:
            self.assertTrue(rule.startswith(PROBE_GATE), rule)
            self.assertNotRegex(rule, r"\bdrop\b")
        self.assertEqual([rule[len(PROBE_GATE):] for rule in actual_rules], expected_rules)
        self.assertTrue(any("masquerade" in rule for rule in actual_rules))
        self.assertTrue(any("meta nfproto ipv6 counter accept" in rule for rule in actual_rules))
        policies = _chain_policies(probe["setup"])
        self.assertTrue(policies)
        self.assertTrue(all("policy accept;" in policy for policy in policies))

        self.assertEqual([label for label, _ in probe["updates"]],
                         [label for label, _ in live["updates"]])
        for (label, live_update), (probe_label, probe_update) in zip(live["updates"], probe["updates"]):
            self.assertEqual(probe_label, label)
            self.assertEqual(probe_update, live_update.replace("inet outer_vpn_guard", f"inet {guard_table}"))

    def test_probe_refuses_a_non_accept_chain_policy(self):
        original = outer._transition_script().replace("policy accept;", "policy drop;")
        with self.assertRaisesRegex(outer.OuterError, "accept chain policy"):
            outer._inert_nft_script(original, {})

    def test_probe_uses_current_strict_bootstrap_configuration(self):
        settings = {**SETTINGS, "strict": True}
        probe = outer.nft_kernel_plan(settings, SERVER, PHYSICAL, TOKENS[0])
        self.assertNotIn('elements = { "ogw-host" }', probe["setup"])
        self.assertNotIn("add element inet " + f"ogw_probe_g_{TOKENS[0]} bootstrap_ifaces", probe["updates"][0][1])

    def test_validate_uses_unique_probe_names_in_an_isolated_namespace(self):
        plans = [outer.nft_kernel_plan(SETTINGS, SERVER, PHYSICAL, token) for token in TOKENS]
        collisions = {tuple(table) for plan in plans for table in plan["tables"]}
        runner = RecordingRunner(existing_tables=collisions)
        uuids = [SimpleNamespace(hex=token) for token in TOKENS]

        with mock.patch.object(outer.uuid, "uuid4", side_effect=uuids):
            outer.validate_nft_rules(SETTINGS, SERVER, PHYSICAL, runner)
            outer.validate_nft_rules(SETTINGS, SERVER, PHYSICAL, runner)

        launches = [call for call in runner.calls if call["args"][:1] == ["unshare"]]
        self.assertEqual(len(launches), 2)
        payloads = [json.loads(call["input_text"]) for call in launches]
        self.assertEqual([set(map(tuple, payload["tables"])) for payload in payloads],
                         [set(map(tuple, plan["tables"])) for plan in plans])
        self.assertTrue(set(map(tuple, payloads[0]["tables"])).isdisjoint(
            set(map(tuple, payloads[1]["tables"]))))
        self.assertTrue(all(set(map(tuple, payload["tables"])) <= runner.existing_tables
                            for payload in payloads))
        for call in launches:
            self.assertEqual(call["args"][:3], ["unshare", "--net", "--"])
            self.assertEqual(call["args"][-1], "_nft-kernel-probe")
            self.assertEqual(call["timeout"], 90)

        checks = [call for call in runner.calls if call["args"] == ["nft", "-c", "-f", "-"]]
        expected_checks = [script for _, script in outer.nft_rule_plan(SETTINGS, SERVER, PHYSICAL)["checks"]]
        self.assertEqual([call["input_text"] for call in checks], expected_checks * 2)
        self.assertFalse(any(call["args"][0] == "nft" and "-c" not in call["args"]
                             for call in runner.calls), "host namespace must not load or delete probe tables")

    def test_probe_deletes_only_its_tables_after_success(self):
        plan = outer.nft_kernel_plan(SETTINGS, SERVER, PHYSICAL, TOKENS[0])
        runner = RecordingRunner()

        with mock.patch.object(outer, "_require_new_network_namespace"):
            outer.run_nft_kernel_probe(plan, runner)

        loads = [call for call in runner.calls if call["args"] == ["nft", "-f", "-"]]
        self.assertEqual([call["input_text"] for call in loads],
                         [plan["setup"], *(script for _, script in plan["updates"])])
        deletes = [call["args"] for call in runner.calls
                   if call["args"][:3] == ["nft", "delete", "table"]]
        expected = [["nft", "delete", "table", family, name]
                    for family, name in reversed(plan["tables"])]
        self.assertEqual(deletes, expected)

    def test_probe_deletes_only_its_tables_after_an_update_fails(self):
        plan = outer.nft_kernel_plan(SETTINGS, SERVER, PHYSICAL, TOKENS[0])
        runner = RecordingRunner(fail_apply_at=2)

        with mock.patch.object(outer, "_require_new_network_namespace"):
            with self.assertRaisesRegex(outer.OuterError, "simulated kernel rejection"):
                outer.run_nft_kernel_probe(plan, runner)

        deletes = [call["args"] for call in runner.calls
                   if call["args"][:3] == ["nft", "delete", "table"]]
        expected = [["nft", "delete", "table", family, name]
                    for family, name in reversed(plan["tables"])]
        self.assertEqual(deletes, expected)
        self.assertEqual(runner.apply_count, 2)

    def test_kernel_rejection_during_initial_commit_still_attempts_cleanup(self):
        plan = outer.nft_kernel_plan(SETTINGS, SERVER, PHYSICAL, TOKENS[0])
        runner = RecordingRunner(fail_apply_at=1)
        with mock.patch.object(outer, "_require_new_network_namespace"):
            with self.assertRaisesRegex(outer.OuterError, "simulated kernel rejection"):
                outer.run_nft_kernel_probe(plan, runner)
        deletes = [call["args"] for call in runner.calls if call["args"][:3] == ["nft", "delete", "table"]]
        self.assertEqual(deletes, [["nft", "delete", "table", family, name]
                                   for family, name in reversed(plan["tables"])])

    def test_interrupted_probe_still_attempts_table_cleanup(self):
        plan = outer.nft_kernel_plan(SETTINGS, SERVER, PHYSICAL, TOKENS[0])

        class InterruptedRunner(RecordingRunner):
            def run(self, args, **kwargs):
                if args == ["nft", "-f", "-"]:
                    raise KeyboardInterrupt
                return super().run(args, **kwargs)

        runner = InterruptedRunner()
        with mock.patch.object(outer, "_require_new_network_namespace"):
            with self.assertRaises(KeyboardInterrupt):
                outer.run_nft_kernel_probe(plan, runner)
        deletes = [call["args"] for call in runner.calls if call["args"][:3] == ["nft", "delete", "table"]]
        self.assertEqual(deletes, [["nft", "delete", "table", family, name]
                                   for family, name in reversed(plan["tables"])])

    def test_kernel_probe_preserves_failed_cleanup_details_and_attempts_all_tables(self):
        plan = outer.nft_kernel_plan(SETTINGS, SERVER, PHYSICAL, TOKENS[0])

        class FailedCleanup(RecordingRunner):
            def run(self, args, **kwargs):
                result = super().run(args, **kwargs)
                if args[:3] == ["nft", "delete", "table"]:
                    return subprocess.CompletedProcess(args, 1, "", "permission denied")
                return result

        runner = FailedCleanup()
        with mock.patch.object(outer, "_require_new_network_namespace"):
            with self.assertRaisesRegex(outer.OuterError, "permission denied"):
                outer.run_nft_kernel_probe(plan, runner)
        deletes = [call for call in runner.calls if call["args"][:3] == ["nft", "delete", "table"]]
        self.assertEqual(len(deletes), len(plan["tables"]))

    def test_collision_inside_probe_namespace_is_rejected_without_modifying_tables(self):
        plan = outer.nft_kernel_plan(SETTINGS, SERVER, PHYSICAL, TOKENS[0])
        runner = RecordingRunner(existing_tables=[plan["tables"][0]])
        with mock.patch.object(outer, "_require_new_network_namespace"):
            with self.assertRaisesRegex(outer.OuterError, "already exists"):
                outer.run_nft_kernel_probe(plan, runner)
        self.assertEqual(runner.calls, [])

    def test_probe_refuses_to_run_in_the_parent_network_namespace(self):
        same_namespace = SimpleNamespace(st_dev=1, st_ino=7)
        other_namespace = SimpleNamespace(st_dev=1, st_ino=8)
        with mock.patch.object(outer.os, "stat", side_effect=[same_namespace, same_namespace]):
            with self.assertRaises(outer.OuterError):
                outer._require_new_network_namespace()
        with mock.patch.object(outer.os, "stat", side_effect=[same_namespace, other_namespace]):
            outer._require_new_network_namespace()


if __name__ == "__main__":
    unittest.main()
