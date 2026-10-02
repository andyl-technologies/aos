"""Checks network lowering and replay without changing the host network."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

SOURCE = Path(sys.argv.pop(1)).resolve()
specification = importlib.util.spec_from_file_location("network_handler", SOURCE)
handler = importlib.util.module_from_spec(specification)
specification.loader.exec_module(handler)


def physical(name="eth0"):
    return {
        "name": name,
        "kind": "ethernet",
        "selector": {"kind": "name", "value": name},
        "addressing": {"dhcp": False, "addresses": ["192.0.2.5/24"], "gateway": "192.0.2.1", "dns": ["192.0.2.53"]},
    }


def policy(links):
    return {"authority": "operator", "mtu": 9000, "links": links, "resolver": {"enabled": True, "nameservers": ["192.0.2.53"], "search": ["example.test"], "dnssec": "yes"}}


class NativeNetworkTests(unittest.TestCase):
    def test_default_dhcp_preserves_ethernet_names_and_lease_policy(self):
        link = {
            "name": "default-dhcp", "kind": "ethernet",
            "selector": {"kind": "ethernet", "value": "en*"},
            "addressing": {
                "dhcp": True, "addresses": [], "dns": [],
                "dhcp_use_dns": True, "dhcp_use_ntp": True, "dhcp_use_domains": "yes",
            },
        }

        files = handler.render(policy([link]))
        text = next(content for name, content in files.items() if name.endswith(".network"))

        self.assertIn('[Match]\nName="en*"\nType=ether\n', text)
        self.assertIn("[Network]\nDHCP=yes\n", text)
        self.assertIn("[DHCPv4]\nUseDNS=yes\nUseNTP=yes\nUseDomains=yes\n", text)

    def test_explicit_selectors_and_unconfigured_dhcp_options_are_unchanged(self):
        self.assertEqual(handler.selector({"kind": "ethernet", "value": ""}), "Type=ether\n")
        self.assertEqual(handler.selector({"kind": "name", "value": "eth0"}), 'Name="eth0"\n')
        self.assertEqual(handler.selector({"kind": "mac", "value": "52:54:00:12:00:01"}), 'MACAddress=52:54:00:12:00:01\n')
        link = physical()
        link["addressing"]["dhcp"] = True

        files = handler.render(policy([link]))

        self.assertFalse(any("[DHCPv4]" in text for text in files.values()))

    def test_dhcp_policy_does_not_capture_vlan_attachment_directives(self):
        link = physical()
        link["addressing"].update(dhcp=True, dhcp_use_dns=False, dhcp_use_ntp=False, dhcp_use_domains="route")
        vlan = {"name": "vlan10", "kind": "vlan", "parent": link["selector"], "id": 10, "addressing": {"dhcp": True, "addresses": [], "dns": []}}

        files = handler.render(policy([link, vlan]))
        text = next(content for name, content in files.items() if 'Name="eth0"' in content)

        self.assertLess(text.index('VLAN="vlan10"'), text.index("[DHCPv4]"))
        self.assertIn("UseDNS=no\nUseNTP=no\nUseDomains=route", text)

    def test_default_matching_and_dhcp_policies_reject_invalid_values(self):
        with self.assertRaisesRegex(ValueError, "Ethernet name pattern"):
            handler.selector({"kind": "ethernet", "value": "en*\nName=eth0"})
        for field, invalid in (("dhcp_use_dns", "yes"), ("dhcp_use_ntp", 1), ("dhcp_use_domains", "invalid")):
            with self.subTest(field=field):
                link = physical()
                link["addressing"][field] = invalid
                with self.assertRaisesRegex(ValueError, "DHCPv4"):
                    handler.render(policy([link]))

    def test_vlan_parent_preserves_static_addressing_and_mtu(self):
        vlan = {"name": "vlan10", "kind": "vlan", "parent": {"kind": "name", "value": "eth0"}, "id": 10, "addressing": {"dhcp": True, "addresses": [], "dns": []}}
        files = handler.render(policy([physical(), vlan]))
        parent = next(text for text in files.values() if 'Name="eth0"' in text)
        self.assertIn('Address="192.0.2.5/24"', parent)
        self.assertIn('VLAN="vlan10"', parent)
        self.assertIn("MTUBytes=9000", parent)
        self.assertEqual(parent.count("[Network]"), 1)
        self.assertTrue(any("[VLAN]\nId=10" in text for text in files.values()))

    def test_bond_members_and_mode_are_retained(self):
        bond = {"name": "bond0", "kind": "bond", "members": [{"kind": "name", "value": "eth0"}, {"kind": "name", "value": "eth1"}], "mode": "802.3ad", "addressing": {"dhcp": True, "addresses": [], "dns": []}}
        files = handler.render(policy([bond]))
        self.assertEqual(sum('Bond="bond0"' in text for text in files.values()), 2)
        self.assertTrue(any("Mode=802.3ad" in text for text in files.values()))

    def test_metadata_route_remains_after_network_directives(self):
        link = physical()
        link["addressing"].update(link_local="ipv4", ipv4_link_local_route=True)
        files = handler.render(policy([link]))
        text = next(content for name, content in files.items() if name.endswith(".network"))
        self.assertIn("LinkLocalAddressing=ipv4", text)
        self.assertIn("[Route]\nDestination=169.254.0.0/16\nScope=link", text)
        self.assertLess(text.index("DNS="), text.index("[Route]"))

    def test_disabled_resolver_retains_explicit_libc_dns(self):
        configuration = policy([])
        configuration["resolver"]["enabled"] = False
        files = handler.render(configuration)
        self.assertEqual(files["etc/resolv.conf"], "nameserver 192.0.2.53\nsearch example.test\n")
        self.assertFalse(any("resolved.conf" in path for path in files))

    def test_renderer_rejects_directive_injection(self):
        configuration = policy([physical()])
        configuration["resolver"]["search"] = ["example.test\nDNSSEC=no"]
        with self.assertRaises(ValueError):
            handler.render(configuration)

    def test_replay_accepts_only_receipted_partial_files(self):
        receipt = {"desired": {"files": {"etc/systemd/network/unit": "new"}}, "previous": {"files": {"etc/systemd/network/unit": "old"}}}
        with patch.object(handler, "link_at", return_value=None), patch.object(handler, "read", return_value="old"):
            self.assertFalse(handler.checked(receipt))
        with patch.object(handler, "link_at", return_value=None), patch.object(handler, "read", return_value="foreign"):
            with self.assertRaises(ValueError):
                handler.checked(receipt)

    def test_empty_bootstrap_uses_native_invocation_and_observation(self):
        invocation = {"id": "fixture", "revision": "0" * 64, "effect": {"identity": ["fixture", "network", "bootstrap", "empty"]}, "input": {"configuration": None}, "action": "apply", "previous": None}
        result = subprocess.run([sys.executable, str(SOURCE), "observe"], input=json.dumps(invocation), capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(result.stdout), {"status": "current", "outputs": {"resource": "systemd-network-bootstrap-empty"}})


if __name__ == "__main__":
    unittest.main()
