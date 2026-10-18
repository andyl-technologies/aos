"""Checks fleet network separation when sandbox drivers have equal PIDs."""

import ipaddress
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

from aos_test_driver import qemu
from aos_test_driver.network import configure_multicast_buffers


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


if __name__ == "__main__":
    unittest.main()
