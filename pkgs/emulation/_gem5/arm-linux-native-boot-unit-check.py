# SPDX-License-Identifier: MIT
"""Tests ARM UART predicates with modeled clock data, without importing m5."""

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("checked_linux_boot", Path(sys.argv[1]) / "linux-native-boot-common.py")
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


class ConsoleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.tick = 10
        self.console = boot.Console(Path(self.directory.name) / "console.bin",
                                    lambda: self.tick, "system.terminal", 3_000_000_000_000)
        self.addCleanup(self.console.stream.close)

    def publication(self, byte):
        return {"output_id": str(self.console.last_identifier + 1), "tick": "10",
                "event_ordinal": "20", "tick_ordinal": "1", "causal_parent": "17",
                "facet": "serial", "terminal": "system.terminal", "payload": [byte]}

    def feed(self, data):
        for byte in data:
            self.console.consume(self.publication(byte))

    def test_both_complete_lines_and_crlf(self):
        self.feed(b"Linux\nGEM5_LINUX_INIT_READY\r\nGEM5_LINUX_PROBE_COMPLETE\n")
        self.assertEqual(self.console.required, set(boot.REQUIRED_LINES))
        self.assertEqual(self.console.bytes, self.console.last_identifier)

    def test_partial_or_embedded_marker_refuses_completion(self):
        self.feed(b"prefix GEM5_LINUX_INIT_READY\nGEM5_LINUX_PROBE_COMPLETE")
        self.assertEqual(self.console.required, set())

    def test_owner_parent_and_facet_refuse_before_byte(self):
        for name, value in (("terminal", "system.pc.com_1.device"),
                            ("causal_parent", "18"), ("facet", "net")):
            row = self.publication(65)
            row[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.console.consume(row)
            self.assertEqual(self.console.bytes, 0)

    def test_fifo_and_canonical_birth_refuse(self):
        self.feed(b"A")
        for name, value in (("output_id", "1"), ("output_id", "3"), ("output_id", "02"),
                            ("tick", "11"), ("event_ordinal", "0"), ("tick_ordinal", "0")):
            row = self.publication(65)
            row[name] = value
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                self.console.consume(row)
            self.assertEqual(self.console.bytes, 1)

    def test_payload_and_credit_refuse_before_byte(self):
        for payload in ([True], [256], [], [65, 66]):
            row = self.publication(65)
            row["payload"] = payload
            with self.assertRaises(ValueError):
                self.console.consume(row)
        self.console.bytes = boot.MAX_TRANSCRIPT_BYTES
        with self.assertRaises(ValueError):
            self.feed(b"A")
        self.assertEqual(self.console.last_identifier, 0)

    def test_failure_and_line_extent_remain_failures(self):
        with self.assertRaises(ValueError):
            self.feed(b"GEM5_DEVICE_FAILURE")
        self.assertEqual(self.console.bytes, len(b"GEM5_DEVICE_FAILURE"))
        self.console.line = bytearray(b"A" * 4096)
        with self.assertRaises(ValueError):
            self.feed(b"B")

    def test_exclusive_arm_boundary_and_fixed_other_credits(self):
        maximum = 3_000_000_000_000
        self.assertEqual(boot.horizon_tick("3", ("3",)), maximum)
        for value in ("2", "4", "03", "3.0", 3, True, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                boot.horizon_tick(value, ("3",))
        self.tick = maximum + 1
        for value in (maximum, maximum + 1):
            row = self.publication(65)
            row["tick"] = str(value)
            with self.assertRaises(ValueError):
                self.console.consume(row)
        self.assertEqual(self.console.bytes, 0)
        self.assertEqual(boot.MAX_EVENTS, 500_000_000)
        self.assertEqual(boot.MAX_TRANSCRIPT_BYTES, 256 * 1024)
        self.assertEqual(boot.EVENT_BATCH, 128)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
