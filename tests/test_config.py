"""Unit tests for the pure configuration helpers in outer.py."""

from __future__ import annotations

import ipaddress
import tempfile
import unittest
from pathlib import Path

import outer


TEST_UUID = "01234567-89ab-cdef-0123-456789abcdef"
TEST_PUBLIC_KEY = "A" * 43
TEST_SERVER_IPV4 = "198.51.100.42"
TEST_SOCKS_PORT = 10808

VALID_VLESS_URL = (
    f"vless://{TEST_UUID}@edge.example.test:8443"
    "?encryption=none&type=tcp&security=reality&flow=xtls-rprx-vision"
    "&sni=front%2Eexample%2Enet&fp=chrome"
    f"&pbk={TEST_PUBLIC_KEY}&sid=deadbeef"
    "&spx=%2Fprobe%3Fedge%3Done%26mode%3Dvision"
    "#profile%20%23one"
)


def parse_env_text(contents: str) -> dict[str, str]:
    with tempfile.TemporaryDirectory() as directory:
        env_path = Path(directory) / ".env"
        env_path.write_text(contents, encoding="utf-8")
        return outer.parse_env_file(env_path)


class ParseVlessUrlTests(unittest.TestCase):
    def test_valid_reality_tcp_vision_with_escaped_query_and_fragment(self):
        parsed = outer.parse_vless_url(VALID_VLESS_URL)

        self.assertEqual(
            {key: parsed[key] for key in (
                "server", "port", "uuid", "public_key", "server_name",
                "short_id", "fingerprint", "spider_x",
            )},
            {
                "server": "edge.example.test",
                "port": 8443,
                "uuid": TEST_UUID,
                "public_key": TEST_PUBLIC_KEY,
                "server_name": "front.example.net",
                "short_id": "deadbeef",
                "fingerprint": "chrome",
                "spider_x": "/probe?edge=one&mode=vision",
            },
        )

    def test_tcp_is_the_default_and_raw_is_its_xray_alias(self):
        omitted = VALID_VLESS_URL.replace("&type=tcp", "")
        raw = VALID_VLESS_URL.replace("type=tcp", "type=raw")
        self.assertEqual(outer.parse_vless_url(omitted)["server"], "edge.example.test")
        self.assertEqual(outer.parse_vless_url(raw)["server"], "edge.example.test")

    def test_tcp_share_link_accepts_only_no_obfuscation_header(self):
        ordinary = VALID_VLESS_URL.replace("type=tcp", "type=tcp&headerType=none")
        self.assertEqual(outer.parse_vless_url(ordinary)["server"], "edge.example.test")
        with self.assertRaises(ValueError):
            outer.parse_vless_url(ordinary.replace("headerType=none", "headerType=http"))

    def test_rejects_invalid_or_malicious_uri_forms(self):
        before_fragment, fragment = VALID_VLESS_URL.split("#", 1)
        invalid_urls = (
            VALID_VLESS_URL.replace("vless://", "https://", 1),
            VALID_VLESS_URL.replace("type=tcp", "type=ws", 1),
            VALID_VLESS_URL.replace("security=reality", "security=tls", 1),
            VALID_VLESS_URL.replace(
                "flow=xtls-rprx-vision", "flow=", 1,
            ),
            before_fragment + "&security=reality#" + fragment,
            before_fragment + "&exec=%24%28touch%20%2Ftmp%2Fnot-created%29#" + fragment,
            VALID_VLESS_URL.replace(f"{TEST_UUID}@", f"{TEST_UUID}:password@", 1),
            VALID_VLESS_URL.replace(":8443?", ":65536?", 1),
        )

        for url in invalid_urls:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    outer.parse_vless_url(url)


class ParseEnvFileTests(unittest.TestCase):
    def test_env_values_are_data_not_shell_or_interpolation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "command-ran"
            env_path = root / ".env"
            command_value = f"$(touch {marker})"
            env_path.write_text(
                f"VLESS_URL={command_value}\nPROTON_ENDPOINTS=${{HOME}}\n",
                encoding="utf-8",
            )

            parsed = outer.parse_env_file(env_path)

            self.assertEqual(parsed["VLESS_URL"], command_value)
            self.assertEqual(parsed["PROTON_ENDPOINTS"], "${HOME}")
            self.assertFalse(marker.exists())

    def test_duplicate_keys_and_malformed_entries_are_rejected(self):
        invalid_documents = (
            "VLESS_URL=first\nVLESS_URL=second\n",
            "VLESS_URL=value\nmalformed-line\n",
            "VLESS_URL=value\nBAD-KEY=value\n",
        )

        for contents in invalid_documents:
            with self.subTest(contents=contents):
                with self.assertRaises(ValueError):
                    parse_env_text(contents)


class StrictModeTests(unittest.TestCase):
    def test_strict_mode_defaults_off_and_accepts_explicit_true(self):
        values = {"VLESS_URL": VALID_VLESS_URL, "PROTON_ENDPOINTS": "198.51.100.10"}
        self.assertFalse(outer._settings_from_values(values)["strict"])
        self.assertTrue(outer._settings_from_values({**values, "STRICT_MODE": "true"})["strict"])
        self.assertFalse(outer._settings_from_values({**values, "STRICT_MODE": "false"})["strict"])
        with self.assertRaises(ValueError):
            outer._settings_from_values({**values, "STRICT_MODE": "maybe"})


class ParseProtonEndpointsTests(unittest.TestCase):
    def test_validates_ipv4_and_deduplicates_endpoints(self):
        endpoints = outer.parse_proton_endpoints(
            "1.1.1.1, 8.8.8.8,1.1.1.1"
        )

        self.assertIsInstance(endpoints, list)
        self.assertEqual(len(endpoints), 2)
        self.assertEqual(set(endpoints), {"1.1.1.1", "8.8.8.8"})
        for endpoint in endpoints:
            self.assertIsInstance(ipaddress.IPv4Address(endpoint), ipaddress.IPv4Address)

    def test_rejects_non_ipv4_or_non_literal_endpoints(self):
        invalid_values = (
            "not-an-ip",
            "2001:db8::1",
            "1.1.1.1:51820",
            "256.1.1.1",
            "1.1.1.1,not-an-ip",
        )

        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    outer.parse_proton_endpoints(value)


class ConfigGenerationTests(unittest.TestCase):
    def setUp(self):
        self.vless = outer.parse_vless_url(VALID_VLESS_URL)

    def test_xray_config_uses_loopback_socks_udp_and_veth_reality_outbound(self):
        config = outer.make_xray_config(
            self.vless,
            TEST_SERVER_IPV4,
            ns_interface="ogw-ns",
            socks_port=TEST_SOCKS_PORT,
        )

        socks_inbounds = [
            item for item in config.get("inbounds", [])
            if item.get("protocol") == "socks"
        ]
        self.assertEqual(len(socks_inbounds), 1)
        socks_inbound = socks_inbounds[0]
        listen = socks_inbound.get("listen")
        if listen == "localhost":
            is_loopback = True
        else:
            is_loopback = ipaddress.ip_address(listen).is_loopback
        self.assertTrue(is_loopback)
        self.assertEqual(socks_inbound.get("port"), TEST_SOCKS_PORT)
        self.assertIs(socks_inbound.get("settings", {}).get("udp"), True)

        vless_outbounds = [
            item for item in config.get("outbounds", [])
            if item.get("protocol") == "vless"
        ]
        self.assertEqual(len(vless_outbounds), 1)
        stream = vless_outbounds[0].get("streamSettings", {})
        self.assertEqual(stream.get("method"), "raw")
        self.assertEqual(stream.get("security"), "reality")
        self.assertEqual(stream.get("sockopt", {}).get("interface"), "ogw-ns")
        reality = stream.get("realitySettings", {})
        self.assertEqual(reality.get("password"), TEST_PUBLIC_KEY)
        self.assertEqual(vless_outbounds[0]["settings"]["flow"], "xtls-rprx-vision-udp443")
        self.assertFalse(vless_outbounds[0].get("mux", {}).get("enabled", False))
        self.assertEqual(reality.get("serverName"), "front.example.net")

    def test_sing_config_routes_tun_and_loopback_socks_outbound(self):
        config = outer.make_sing_config(
            TEST_SERVER_IPV4,
            socks_port=TEST_SOCKS_PORT,
        )

        tun_inbounds = [
            item for item in config.get("inbounds", [])
            if item.get("type") == "tun"
        ]
        self.assertTrue(tun_inbounds)
        tun = tun_inbounds[0]
        self.assertIs(tun.get("auto_route"), True)
        self.assertIs(tun.get("auto_redirect"), True)
        excluded = tun.get("route_exclude_address", [])
        self.assertTrue(
            any(
                ipaddress.ip_network(address, strict=False).prefixlen == 32
                and ipaddress.ip_network(address, strict=False).network_address
                == ipaddress.IPv4Address(TEST_SERVER_IPV4)
                for address in excluded
            ),
            f"outer server {TEST_SERVER_IPV4} must be excluded from TUN routes",
        )

        self.assertIn(outer.VETH_NET, excluded)

        socks_outbounds = [
            item for item in config.get("outbounds", [])
            if item.get("type") == "socks"
        ]
        self.assertTrue(socks_outbounds)
        socks_outbound = socks_outbounds[0]
        self.assertEqual(socks_outbound.get("bind_interface"), "lo")
        server = socks_outbound.get("server")
        self.assertIsInstance(server, str)
        if server == "localhost":
            is_loopback = True
        else:
            is_loopback = ipaddress.ip_address(server).is_loopback
        self.assertTrue(is_loopback)
        self.assertEqual(socks_outbound.get("server_port"), TEST_SOCKS_PORT)


if __name__ == "__main__":
    unittest.main()
