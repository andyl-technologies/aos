"""Checks fleet network separation when sandbox drivers have equal PIDs."""

import ipaddress
import json
import socket
import subprocess
import sys
import unittest
from unittest.mock import patch

from aos_test_driver import qemu
from aos_test_driver.network import configure_multicast_buffers, filter_unicast


class FleetNetworkIsolationTests(unittest.TestCase):
    def test_equal_sandbox_pids_do_not_select_the_same_fleet_network(self):
        with patch.object(qemu.os, "getpid", return_value=5), \
                patch.object(qemu.secrets, "randbits", side_effect=[1, 2]), \
                patch.object(qemu.secrets, "randbelow", side_effect=[3, 4]):
            first = qemu._mcast_endpoint()
            second = qemu._mcast_endpoint()

        self.assertNotEqual(first, second)
        for group, port in (first, second):
            self.assertIn(ipaddress.ip_address(group), ipaddress.ip_network("239.0.0.0/8"))
            self.assertGreaterEqual(port, 10000)
            self.assertLess(port, 60000)

    @unittest.skipUnless(sys.platform == "linux", "pidfd socket adjustment is Linux-specific")
    def test_owned_child_uses_larger_buffers_without_replacing_its_socket(self):
        program = """
import json, socket, sys
network = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
network.bind(('127.0.0.1', 0))
other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
other.bind(('127.0.0.1', 0))
print(json.dumps({'endpoint': network.getsockname(),
    'receive': network.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
    'otherReceive': other.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)}), flush=True)
sys.stdin.readline()
print(json.dumps({'endpoint': network.getsockname(),
    'receive': network.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
    'send': network.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF),
    'otherReceive': other.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)}), flush=True)
"""
        child = subprocess.Popen([sys.executable, "-c", program], text=True,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            assert child.stdout is not None
            assert child.stdin is not None
            before = json.loads(child.stdout.readline())

            receive, send = configure_multicast_buffers(child.pid, tuple(before["endpoint"]))
            child.stdin.write("\n")
            child.stdin.flush()
            after = json.loads(child.stdout.readline())
            child.wait(timeout=5)

            self.assertEqual(after["endpoint"], before["endpoint"])
            self.assertEqual((after["receive"], after["send"]), (receive, send))
            self.assertGreaterEqual(after["receive"], before["receive"])
            if before["receive"] < 4 * 1024 * 1024:
                self.assertGreater(after["receive"], before["receive"])
            self.assertEqual(after["otherReceive"], before["otherReceive"])
            self.assertEqual(child.returncode, 0)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            for stream in [child.stdin, child.stdout, child.stderr]:
                if stream is not None:
                    stream.close()

    @unittest.skipUnless(sys.platform == "linux", "pidfd socket adjustment is Linux-specific")
    def test_filter_applies_only_to_the_selected_owned_socket(self):
        program = """
import json, socket, sys
network = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
network.bind(('127.0.0.1', 0))
network.settimeout(2)
other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
other.bind(('127.0.0.1', 0))
other.settimeout(2)
print(json.dumps([network.getsockname(), other.getsockname()]), flush=True)
sys.stdin.readline()
print(json.dumps({'selected': network.recv(4096).hex(),
    'other': other.recv(4096).hex()}), flush=True)
"""
        child = subprocess.Popen([sys.executable, "-c", program], text=True,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        own = bytes.fromhex("5254001200015254001200030800") + b"own"
        foreign = bytes.fromhex("5254001200025254001200030800") + b"foreign"
        try:
            assert child.stdout is not None
            assert child.stdin is not None
            selected, other = json.loads(child.stdout.readline())

            configure_multicast_buffers(
                child.pid, tuple(selected), destination_mac="52:54:00:12:00:01"
            )
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                sender.sendto(foreign, tuple(selected))
                sender.sendto(foreign, tuple(other))
                sender.sendto(own, tuple(selected))
            child.stdin.write("\n")
            child.stdin.flush()
            received = json.loads(child.stdout.readline())
            child.wait(timeout=5)

            self.assertEqual(received, {"selected": own.hex(), "other": foreign.hex()})
            self.assertEqual(child.returncode, 0)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            for stream in [child.stdin, child.stdout, child.stderr]:
                if stream is not None:
                    stream.close()


@unittest.skipUnless(sys.platform == "linux", "UDP socket filtering is Linux-specific")
class FleetReceiveFilterTests(unittest.TestCase):
    address = "52:54:00:12:00:01"

    def frame(self, destination: str, payload: bytes = b"fixed-test-payload") -> bytes:
        return (
            bytes.fromhex(destination.replace(":", ""))
            + bytes.fromhex("525400120003")
            + b"\x08\x00"
            + payload
        )

    def test_delivers_exact_own_broadcast_and_multicast_frames(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            receiver.bind(("127.0.0.1", 0))
            receiver.settimeout(1)
            filter_unicast(receiver, self.address)

            for destination in [self.address, "ff:ff:ff:ff:ff:ff", "33:33:00:00:00:01"]:
                with self.subTest(destination=destination):
                    frame = self.frame(destination)

                    sender.sendto(frame, receiver.getsockname())

                    self.assertEqual(receiver.recv(4096), frame)

    def test_foreign_bulk_cannot_fill_an_unrelated_receive_queue(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            receiver.bind(("127.0.0.1", 0))
            receiver.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
            receiver.settimeout(1)
            filter_unicast(receiver, self.address)
            foreign = self.frame("52:54:00:12:00:02", b"x" * 1400)
            own = self.frame(self.address)

            for _ in range(2000):
                sender.sendto(foreign, receiver.getsockname())
            sender.sendto(own, receiver.getsockname())

            self.assertEqual(receiver.recv(4096), own)

    def test_short_frames_and_other_unicast_are_rejected(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            receiver.bind(("127.0.0.1", 0))
            receiver.settimeout(0.05)
            filter_unicast(receiver, self.address)

            for frame in [
                b"",
                bytes.fromhex("525400120001"),
                self.frame("52:54:00:12:00:02"),
                self.frame("52:54:00:13:00:01"),
            ]:
                with self.subTest(length=len(frame)):
                    sender.sendto(frame, receiver.getsockname())

                    with self.assertRaises(TimeoutError):
                        receiver.recv(4096)

    def test_rejects_invalid_or_group_destination_addresses(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
            for address in ["52:54:00:12:00", "52:54:00:12:00:gg", "33:33:00:00:00:01"]:
                with self.subTest(address=address), self.assertRaises(ValueError):
                    filter_unicast(receiver, address)


if __name__ == "__main__":
    unittest.main()
