"""Checks network lowering and replay without changing the host network."""

import ctypes
import importlib.util
import json
import os
from contextlib import ExitStack, contextmanager
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

SOURCE = Path(sys.argv.pop(1)).resolve()
RESOLVER_POLICY = Path(sys.argv.pop(1)).resolve(strict=True)
specification = importlib.util.spec_from_file_location("network_handler", SOURCE)
handler = importlib.util.module_from_spec(specification)
specification.loader.exec_module(handler)


def vendor_resolver_link():
    entries = [
        line.split() for line in RESOLVER_POLICY.read_text().splitlines()
        if line.startswith("L!") and line.split()[1] == "/etc/resolv.conf"
    ]
    if len(entries) != 1:
        raise ValueError("expected one installed vendor resolver link")
    return Path(entries[0][1]), entries[0][-1]


@contextmanager
def isolated_network():
    with tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
        root = Path(directory).resolve(strict=True)
        (root / "etc").mkdir()
        state_path = root / "state"
        state_path.mkdir(mode=0o700)
        # Host tests retain real file/link/receipt IO without requiring root.
        # Only the private state directory's owner metadata is simulated.
        state = MagicMock(wraps=state_path)
        state.__truediv__.side_effect = state_path.__truediv__
        state.stat.return_value = SimpleNamespace(st_uid=0, st_mode=state_path.stat().st_mode)
        stack.enter_context(patch.object(handler, "STATE", state))
        stack.enter_context(patch.object(handler, "Path", side_effect=lambda path: root if path == "/" else Path(path)))
        stack.enter_context(patch.object(handler, "units", return_value={}))
        commands = stack.enter_context(patch.object(handler, "command"))
        args = SimpleNamespace(action="apply", systemctl="fixture-systemctl")
        invocation = {
            "id": "resolver-fixture", "revision": "0" * 64,
            "effect": {"identity": ["fixture", "network", "configure", "resolver"]},
            "input": policy([]), "action": "apply", "previous": None,
        }
        yield root, args, invocation, commands


def physical(name="eth0"):
    return {
        "name": name,
        "kind": "ethernet",
        "selector": {"kind": "name", "value": name},
        "addressing": {"dhcp": False, "addresses": ["192.0.2.5/24"], "gateway": "192.0.2.1", "dns": ["192.0.2.53"]},
    }


def policy(links):
    return {"authority": "operator", "mtu": 9000, "links": links, "resolver": {"enabled": True, "nameservers": ["192.0.2.53"], "search": ["example.test"], "dnssec": "yes"}}


class SystemdNetworkParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Use the same selected source-built systemd output as the vendor
        # resolver fixture. These are the parsers used by networkd/resolved,
        # not a Python model that silently strips quotes from INI values.
        libraries = list((RESOLVER_POLICY.parents[2] / "lib/systemd").glob("libsystemd-shared-*.so"))
        if len(libraries) != 1:
            raise ValueError("expected one selected systemd shared library")
        cls.library = ctypes.CDLL(str(libraries[0]))
        cls.free = ctypes.CDLL(None).free
        cls.free.argtypes = [ctypes.c_void_p]
        cls.free.restype = None
        cls.library.extract_first_word.argtypes = [
            ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_char_p, ctypes.c_int,
        ]
        cls.library.extract_first_word.restype = ctypes.c_int
        cls.library.in_addr_from_string_auto.argtypes = [
            ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_void_p,
        ]
        cls.library.in_addr_from_string_auto.restype = ctypes.c_int
        cls.library.in_addr_prefix_from_string_auto_full.argtypes = [
            ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_int),
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte),
        ]
        cls.library.in_addr_prefix_from_string_auto_full.restype = ctypes.c_int
        cls.library.config_parse_ifname.argtypes = [
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint, ctypes.c_char_p,
            ctypes.c_uint, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
            ctypes.c_void_p, ctypes.c_void_p,
        ]
        cls.library.config_parse_ifname.restype = ctypes.c_int

    def words(self, value, flags=0):
        remaining = ctypes.c_char_p(value.encode())
        words = []
        while True:
            word = ctypes.c_void_p()
            result = self.library.extract_first_word(ctypes.byref(remaining), ctypes.byref(word), None, flags)
            self.assertGreaterEqual(result, 0)
            if result == 0:
                return words
            try:
                words.append(ctypes.string_at(word).decode())
            finally:
                self.free(word)

    def test_rendered_ipv4_and_ipv6_are_accepted_without_unquoting(self):
        for address, gateway, dns in [
            ("192.168.50.11/24", "192.168.50.1", "192.168.50.53"),
            ("2001:db8::11/64", "2001:db8::1", "2001:db8::53"),
        ]:
            with self.subTest(address=address):
                link = physical()
                link["addressing"].update(addresses=[address], gateway=gateway, dns=[dns])
                configuration = policy([link])
                configuration["resolver"]["nameservers"] = [dns]
                files = handler.render(configuration)
                network = next(text for path, text in files.items() if path.endswith(".network"))
                values = dict(line.split("=", 1) for line in network.splitlines() if "=" in line)
                family = ctypes.c_int()
                storage = (ctypes.c_uint32 * 4)()
                prefix = ctypes.c_ubyte()
                self.assertEqual(values["Address"], address)
                self.assertEqual(values["Gateway"], gateway)
                self.assertGreaterEqual(self.library.in_addr_prefix_from_string_auto_full(
                    values["Address"].encode(), 1, ctypes.byref(family), storage, ctypes.byref(prefix),
                ), 0)
                self.assertLess(self.library.in_addr_prefix_from_string_auto_full(
                    ('"' + address + '"').encode(), 1, ctypes.byref(family), storage, ctypes.byref(prefix),
                ), 0)
                self.assertGreaterEqual(self.library.in_addr_from_string_auto(
                    values["Gateway"].encode(), ctypes.byref(family), storage,
                ), 0)
                resolver = files["etc/systemd/resolved.conf.d/50-aos-native.conf"]
                resolved_dns = next(line[4:] for line in resolver.splitlines() if line.startswith("DNS="))
                for rendered in [values["DNS"], resolved_dns]:
                    self.assertEqual(self.words(rendered), [dns])
                    for word in self.words(rendered):
                        self.assertGreaterEqual(self.library.in_addr_from_string_auto(
                            word.encode(), ctypes.byref(family), storage,
                        ), 0)
                self.assertLess(self.library.in_addr_from_string_auto(
                    ('"' + gateway + '"').encode(), ctypes.byref(family), storage,
                ), 0)

    def test_netdev_and_attachment_names_have_the_exact_parser_identity(self):
        vlan = {"name": "vlan10", "kind": "vlan", "id": 10, "parent": physical()["selector"], "addressing": {"dhcp": True, "addresses": [], "dns": []}}
        bond = {"name": "bond0", "kind": "bond", "mode": "active-backup", "members": [{"kind": "name", "value": "eth1"}], "addressing": {"dhcp": True, "addresses": [], "dns": []}}
        files = handler.render(policy([physical(), vlan, bond]))
        parsed = []
        for path, text in files.items():
            for line in text.splitlines():
                key, separator, value = line.partition("=")
                if not separator or not (key in ("VLAN", "Bond") or (key == "Name" and path.endswith(".netdev"))):
                    continue
                output = ctypes.c_void_p()
                self.assertEqual(self.library.config_parse_ifname(
                    None, path.encode(), 1, b"Network", 1, key.encode(), 0,
                    value.encode(), ctypes.byref(output), None,
                ), 1)
                try:
                    parsed.append((key, ctypes.string_at(output).decode()))
                finally:
                    self.free(output)
        self.assertCountEqual(parsed, [("Name", "vlan10"), ("VLAN", "vlan10"), ("Name", "bond0"), ("Bond", "bond0")])

    def test_quoted_match_names_and_search_domains_remain_valid(self):
        match = handler.selector({"kind": "ethernet", "value": "en*"})
        name = next(line[5:] for line in match.splitlines() if line.startswith("Name="))
        self.assertEqual(self.words(name, flags=1 << 5), ["en*"])
        files = handler.render(policy([]))
        resolver = files["etc/systemd/resolved.conf.d/50-aos-native.conf"]
        domains = next(line[8:] for line in resolver.splitlines() if line.startswith("Domains="))
        self.assertEqual(self.words(domains, flags=1 << 5), ["example.test"])


class NetworkReadinessTests(unittest.TestCase):
    def invocation(self, scope):
        return {
            "id": "readiness-fixture", "revision": "0" * 64,
            "effect": {"identity": ["fixture", "network", "ready", "daemon"]},
            "input": {"required": True, "scope": scope, "families": ["ipv4", "ipv6"]},
            "action": "apply", "previous": None,
        }

    def arguments(self, action):
        return SimpleNamespace(
            action=action, systemctl="fixture-systemctl", wait_online="fixture-wait-online",
        )

    def test_prepared_stack_remains_ready_without_configured_addresses(self):
        def manager_command(arguments):
            if arguments[0] == "fixture-wait-online":
                raise ValueError("no configured addresses")

        for action in ("observe", "apply"):
            with self.subTest(action=action), patch.object(handler, "command", side_effect=manager_command) as commands:
                result = handler.converge(self.arguments(action), self.invocation("stack-prepared"))

                expected = {"resource": "systemd-networkd.service"}
                self.assertEqual(result, {"status": "current", "outputs": expected} if action == "observe" else expected)
                commands.assert_called_once_with([
                    "fixture-systemctl", "is-active", "--quiet", "systemd-networkd.service",
                ])

    def test_prepared_stack_still_requires_its_manager(self):
        invocation = self.invocation("stack-prepared")
        with patch.object(handler, "command", side_effect=ValueError("network manager unavailable")):
            self.assertEqual(handler.converge(self.arguments("observe"), invocation), {"status": "retry-safe"})

            with self.assertRaisesRegex(ValueError, "network manager unavailable"):
                handler.converge(self.arguments("apply"), invocation)

    def test_address_readiness_keeps_the_requested_family_checks(self):
        invocation = self.invocation("address-configured")
        with patch.object(handler, "command") as commands:
            result = handler.converge(self.arguments("apply"), invocation)

            self.assertEqual(result, {"resource": "systemd-networkd.service"})
            self.assertEqual(commands.call_args_list[-1].args[0], [
                "fixture-wait-online", "--any", "--timeout=30", "--ipv4", "--ipv6",
            ])

    def test_missing_required_addresses_remain_a_failed_apply(self):
        def manager_command(arguments):
            if arguments[0] == "fixture-wait-online":
                raise ValueError("Timeout occurred while waiting for network connectivity.")

        invocation = self.invocation("address-configured")
        with patch.object(handler, "command", side_effect=manager_command):
            self.assertEqual(handler.converge(self.arguments("observe"), invocation), {"status": "retry-safe"})

            with self.assertRaisesRegex(ValueError, "waiting for network connectivity"):
                handler.converge(self.arguments("apply"), invocation)

    def test_optional_readiness_does_not_require_a_network_manager(self):
        invocation = self.invocation("address-configured")
        invocation["input"]["required"] = False
        with patch.object(handler, "command") as commands:
            self.assertEqual(handler.converge(self.arguments("apply"), invocation), {"resource": "sysinit.target"})
            commands.assert_not_called()

    def test_removing_readiness_does_not_wait_for_connectivity(self):
        invocation = self.invocation("address-configured")
        invocation["action"] = "remove"
        with patch.object(handler, "command") as commands:
            self.assertEqual(handler.converge(self.arguments("observe"), invocation), {"status": "absent"})
            self.assertEqual(handler.converge(self.arguments("remove"), invocation), {})
            commands.assert_not_called()


class NativeNetworkTests(unittest.TestCase):
    def test_installed_vendor_link_has_the_desired_lexical_identity(self):
        path, target = vendor_resolver_link()
        expected = handler.link_identity(path, target)
        self.assertTrue(target.startswith("../"))

        with (
            patch.object(handler, "safe_path"),
            patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=0o120777)),
            patch.object(handler.os, "readlink", return_value=target),
        ):
            self.assertEqual(handler.link_at(path), expected)

        with isolated_network() as (root, args, invocation, commands):
            handler.converge(args, invocation)
            receipt = json.loads(next((root / "state").glob("*.json")).read_text())
            self.assertEqual(receipt["desired"]["symlinks"][str(path).lstrip("/")], expected)

    def test_relative_and_absolute_links_apply_observe_and_remove(self):
        vendor_path, vendor_target = vendor_resolver_link()
        expected = handler.link_identity(vendor_path, vendor_target)
        for relative in [False, True]:
            with self.subTest(relative=relative), isolated_network() as (root, args, invocation, commands):
                path = root / "etc/resolv.conf"
                # Anchor equivalent relative spelling to this private fixture's
                # real parent; the installed /etc spelling is checked above.
                target = os.path.relpath(expected, path.parent) if relative else expected
                path.symlink_to(target)

                handler.converge(args, invocation)
                self.assertEqual(os.readlink(path), target)
                receipt_path = next((root / "state").glob("*.json"))
                receipt = receipt_path.read_bytes()
                self.assertEqual(json.loads(receipt)["desired"]["symlinks"]["etc/resolv.conf"], expected)
                args.action = "observe"
                self.assertEqual(handler.converge(args, invocation)["status"], "current")
                self.assertEqual(receipt_path.read_bytes(), receipt)

                args.action = invocation["action"] = "remove"
                handler.converge(args, invocation)
                self.assertFalse(path.is_symlink())
                self.assertFalse(receipt_path.exists())

    def test_unowned_foreign_links_and_regular_files_are_not_adopted(self):
        for target in ["/run/foreign.conf", "../../outside", None]:
            with self.subTest(target=target), isolated_network() as (root, args, invocation, commands):
                path = root / "etc/resolv.conf"
                if target is None:
                    path.write_text("administrator resolver\n")
                else:
                    path.symlink_to(target)

                with self.assertRaisesRegex(ValueError, "unowned resolver"):
                    handler.converge(args, invocation)

                self.assertEqual(list((root / "state").glob("*.json")), [])
                commands.assert_not_called()
                if target is None:
                    self.assertEqual(path.read_text(), "administrator resolver\n")
                else:
                    self.assertEqual(os.readlink(path), target)

    def test_receipted_conflicts_preserve_receipts_for_all_actions(self):
        for replacement in ["/run/foreign.conf", "../../outside", None]:
            with self.subTest(replacement=replacement), isolated_network() as (root, args, invocation, commands):
                handler.converge(args, invocation)
                receipt_path = next((root / "state").glob("*.json"))
                before = receipt_path.read_bytes()
                path = root / "etc/resolv.conf"
                path.unlink()
                if replacement is None:
                    path.write_text("foreign resolver\n")
                else:
                    path.symlink_to(replacement)
                commands.reset_mock()

                for action in ["apply", "observe", "remove"]:
                    args.action = action
                    with self.assertRaisesRegex(ValueError, "outside its receipt"):
                        handler.converge(args, invocation)
                    self.assertEqual(receipt_path.read_bytes(), before)
                    commands.assert_not_called()

    def test_interrupted_symlink_apply_recovers_equivalent_relative_target(self):
        with isolated_network() as (root, args, invocation, commands):
            commands.side_effect = RuntimeError("interrupted after link publication")
            with self.assertRaisesRegex(RuntimeError, "interrupted"):
                handler.converge(args, invocation)
            receipt_path = next((root / "state").glob("*.json"))
            pending = receipt_path.read_bytes()
            receipt = json.loads(pending)
            self.assertFalse(receipt["complete"])
            expected = receipt["desired"]["symlinks"]["etc/resolv.conf"]
            path = root / "etc/resolv.conf"
            path.unlink()
            path.symlink_to("../../outside")

            with self.assertRaisesRegex(ValueError, "outside its receipt"):
                handler.converge(args, invocation)
            self.assertEqual(receipt_path.read_bytes(), pending)
            path.unlink()
            path.symlink_to(os.path.relpath(expected, path.parent))
            commands.side_effect = None
            args.action = "observe"
            self.assertEqual(handler.converge(args, invocation)["status"], "retry-safe")
            self.assertEqual(receipt_path.read_bytes(), pending)

            args.action = "apply"
            handler.converge(args, invocation)
            self.assertTrue(json.loads(receipt_path.read_text())["complete"])
            args.action = "observe"
            self.assertEqual(handler.converge(args, invocation)["status"], "current")
            args.action = invocation["action"] = "remove"
            handler.converge(args, invocation)
            self.assertFalse(path.is_symlink())

    def test_resolver_link_parent_symlinks_remain_forbidden(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "actual").mkdir()
            (root / "etc").symlink_to("actual", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "contains symlink"):
                handler.link_at(root / "etc/resolv.conf")

    def test_interrupted_resolver_disable_retains_previous_link_custody(self):
        with isolated_network() as (root, args, invocation, commands):
            handler.converge(args, invocation)
            invocation["input"]["resolver"]["enabled"] = False
            invocation["revision"] = "1" * 64

            def interrupt_reload(argv):
                if argv[1] == "daemon-reload":
                    raise RuntimeError("interrupted resolver update")

            commands.side_effect = interrupt_reload
            with self.assertRaisesRegex(RuntimeError, "interrupted resolver update"):
                handler.converge(args, invocation)
            receipt_path = next((root / "state").glob("*.json"))
            pending = receipt_path.read_bytes()
            receipt = json.loads(pending)
            self.assertFalse(receipt["complete"])
            self.assertTrue(receipt["previous"]["resolved"])
            path = root / "etc/resolv.conf"
            expected = path.read_text()
            path.write_text("foreign resolver\n")

            with self.assertRaisesRegex(ValueError, "outside its receipt"):
                handler.converge(args, invocation)
            self.assertEqual(receipt_path.read_bytes(), pending)
            path.write_text(expected)
            commands.side_effect = None
            args.action = "observe"
            self.assertEqual(handler.converge(args, invocation)["status"], "retry-safe")
            args.action = "apply"
            handler.converge(args, invocation)
            self.assertIsNone(json.loads(receipt_path.read_text())["previous"])
            args.action = invocation["action"] = "remove"
            handler.converge(args, invocation)
            self.assertFalse(path.exists())

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

        self.assertLess(text.index('VLAN=vlan10'), text.index("[DHCPv4]"))
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
        self.assertIn('Address=192.0.2.5/24', parent)
        self.assertIn('VLAN=vlan10', parent)
        self.assertIn("MTUBytes=9000", parent)
        self.assertEqual(parent.count("[Network]"), 1)
        self.assertTrue(any("[VLAN]\nId=10" in text for text in files.values()))

    def test_bond_members_and_mode_are_retained(self):
        bond = {"name": "bond0", "kind": "bond", "members": [{"kind": "name", "value": "eth0"}, {"kind": "name", "value": "eth1"}], "mode": "802.3ad", "addressing": {"dhcp": True, "addresses": [], "dns": []}}
        files = handler.render(policy([bond]))
        self.assertEqual(sum('Bond=bond0' in text for text in files.values()), 2)
        self.assertTrue(any("Mode=802.3ad" in text for text in files.values()))

    def test_metadata_route_remains_after_network_directives(self):
        link = physical()
        link["addressing"].update(link_local="ipv4", ipv4_link_local_route=True)
        files = handler.render(policy([link]))
        text = next(content for name, content in files.items() if name.endswith(".network"))
        self.assertIn("LinkLocalAddressing=ipv4", text)
        self.assertIn("[Route]\nDestination=169.254.0.0/16\nScope=link", text)
        self.assertLess(text.index("DNS="), text.index("[Route]"))

    def test_resolver_preserves_transport_and_local_discovery_policy(self):
        for dnssec in ("yes", "no", "allow-downgrade"):
            with self.subTest(dnssec=dnssec):
                configuration = policy([])
                configuration["resolver"]["dnssec"] = dnssec

                files = handler.render(configuration)

                self.assertEqual(
                    files["etc/systemd/resolved.conf.d/50-aos-native.conf"],
                    '[Resolve]\nDNS=192.0.2.53\nDomains="example.test"\n'
                    f"DNSSEC={dnssec}\nDNSOverTLS=opportunistic\n"
                    "MulticastDNS=no\nLLMNR=no\n",
                )

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
