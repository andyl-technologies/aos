"""Checks fleet network separation when sandbox drivers have equal PIDs."""

import ipaddress
import unittest
from unittest.mock import patch

from aos_test_driver import qemu


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


if __name__ == "__main__":
    unittest.main()
