# SPDX-License-Identifier: MIT
"""Exercises UART transcript validation with a deliberately modeled m5 clock.

These controls do not instantiate or execute a simulator or guest. The separate
native boot phase must produce both PID1 lines from the actual PC UART.
"""

import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest


sys.modules["m5"] = types.SimpleNamespace(curTick=lambda: 10)
specification = importlib.util.spec_from_file_location("checked_x86_boot", sys.argv[1])
boot = importlib.util.module_from_spec(specification)
specification.loader.exec_module(boot)


class ConsoleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.console = boot.Console(Path(self.directory.name) / "console.bin")
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(self.console.stream.close)

    def publication(self, byte):
        return {"output_id": str(self.console.last_identifier + 1), "tick": "10",
                "event_ordinal": "20", "tick_ordinal": "1", "causal_parent": "17",
                "facet": "serial", "terminal": "system.pc.com_1.device", "payload": [byte]}

    def feed(self, data):
        for byte in data:
            self.console.consume(self.publication(byte))

    def test_two_actual_line_shapes_and_crlf(self):
        self.feed(b"Linux version diagnostic\nGEM5_LINUX_INIT_READY\r\n")
        self.assertEqual(self.console.required, {boot.REQUIRED_LINES[0]})
        self.feed(b"GEM5_LINUX_PROBE_COMPLETE\n")
        self.assertEqual(self.console.required, set(boot.REQUIRED_LINES))
        self.assertEqual(self.console.last_identifier, self.console.bytes)

    def test_partial_or_embedded_marker_does_not_complete(self):
        self.feed(b"prefix GEM5_LINUX_INIT_READY\nGEM5_LINUX_PROBE_COMPLETE")
        self.assertEqual(self.console.required, set())

    def test_foreign_terminal_and_parent_refuse_before_byte(self):
        for key, value in (("terminal", "system.terminal"), ("causal_parent", "18")):
            publication = self.publication(65)
            publication[key] = value
            with self.assertRaises(ValueError):
                self.console.consume(publication)
            self.assertEqual(self.console.bytes, 0)

    def test_duplicate_or_skipped_fifo_identity(self):
        self.feed(b"A")
        for value in ("1", "3", "02"):
            publication = self.publication(66)
            publication["output_id"] = value
            with self.assertRaises(ValueError):
                self.console.consume(publication)
        self.assertEqual(self.console.bytes, 1)

    def test_future_or_missing_birth(self):
        for key, value in (("tick", "11"), ("event_ordinal", "0"), ("tick_ordinal", "0")):
            publication = self.publication(65)
            publication[key] = value
            with self.assertRaises(ValueError):
                self.console.consume(publication)
        self.assertEqual(self.console.bytes, 0)

    def test_nonbyte_and_boolean_payload(self):
        for payload in ([256], [True], [], [65, 66]):
            publication = self.publication(65)
            publication["payload"] = payload
            with self.assertRaises(ValueError):
                self.console.consume(publication)
        self.assertEqual(self.console.bytes, 0)

    def test_guest_failure_marker_is_retained_and_refused(self):
        with self.assertRaises(ValueError):
            self.feed(b"GEM5_DEVICE_FAILURE")
        self.assertEqual(self.console.bytes, len(b"GEM5_DEVICE_FAILURE"))

    def test_console_bounds_preserve_original_credit(self):
        self.console.bytes = boot.MAX_TRANSCRIPT_BYTES
        with self.assertRaises(ValueError):
            self.feed(b"A")
        self.assertEqual(self.console.bytes, boot.MAX_TRANSCRIPT_BYTES)
        self.assertEqual(self.console.last_identifier, 0)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
