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


class HorizonTests(unittest.TestCase):
    def test_only_named_finite_cases_are_accepted(self):
        self.assertEqual(boot.horizon_tick("2"), 2_000_000_000_000)
        self.assertEqual(boot.horizon_tick("4"), 4_000_000_000_000)
        for value in ("0", "3", "5", "04", "4.0", "-4", 4, True, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                boot.horizon_tick(value)

    def test_uart_birth_refuses_the_exclusive_boundary_in_both_cases(self):
        original_clock = boot.m5.curTick
        self.addCleanup(setattr, boot.m5, "curTick", original_clock)
        with tempfile.TemporaryDirectory() as directory:
            for seconds in ("2", "4"):
                limit = boot.horizon_tick(seconds)
                boot.m5.curTick = lambda: limit + 1
                console = boot.Console(Path(directory) / (seconds + ".bin"), seconds)
                self.addCleanup(console.stream.close)
                publication = {"output_id": "1", "tick": str(limit - 1),
                               "event_ordinal": "20", "tick_ordinal": "1",
                               "causal_parent": "17", "facet": "serial",
                               "terminal": "system.pc.com_1.device", "payload": [65]}
                console.consume(publication)
                for tick in (limit, limit + 1):
                    publication.update(output_id="2", tick=str(tick))
                    with self.subTest(seconds=seconds, tick=tick), self.assertRaises(ValueError):
                        console.consume(publication)
                    self.assertEqual(console.bytes, 1)
                    self.assertEqual(console.last_identifier, 1)

    def test_four_seconds_does_not_expand_other_credits(self):
        with tempfile.TemporaryDirectory() as directory:
            console = boot.Console(Path(directory) / "console.bin", "4")
            self.addCleanup(console.stream.close)
            self.assertEqual(console.maximum_tick, 4_000_000_000_000)
            self.assertEqual(boot.MAX_EVENTS, 500_000_000)
            self.assertEqual(boot.MAX_TRANSCRIPT_BYTES, 256 * 1024)
            self.assertEqual(boot.EVENT_BATCH, 128)
            self.assertEqual(boot.REQUIRED_LINES,
                             (b"GEM5_LINUX_INIT_READY", b"GEM5_LINUX_PROBE_COMPLETE"))


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
