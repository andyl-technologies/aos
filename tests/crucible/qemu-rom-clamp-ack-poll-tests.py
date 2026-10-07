"""Refusals for retained real-flight results, independent of host timing."""

import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "ack_poll", Path(__file__).with_name("qemu-rom-clamp-ack-poll.py")
)
parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parser)

RESULT = """initial_ps=1000
final_ps=20001000
initial_raw=20
final_raw=400020
experiment_ack_poll_us=1000
host_drive_elapsed_us=40000000
qemu_cpu_time=unavailable
PASS
completed_quantum_clamps=20000
step_ps=1000
clamp_guard_ms=1000
guest_profile=busy-firmware-no-network
owned_cleanup=complete
"""


class RefusalTests(unittest.TestCase):
    def test_host_duration_is_advisory_even_without_improvement(self):
        baseline = parser.read_result(RESULT)
        candidate = parser.read_result(
            RESULT.replace("poll_us=1000", "poll_us=100")
            .replace("elapsed_us=40000000", "elapsed_us=50000000")
        )
        self.assertTrue(parser.compare(baseline, candidate)["canonical_results_equal"])

    def test_changed_authorities_and_incomplete_results_refuse(self):
        mutations = (
            ("clamps=20000", "clamps=19999"),
            ("guard_ms=1000", "guard_ms=2000"),
            ("cleanup=complete", "cleanup=leaked"),
            ("final_ps=20001000", "final_ps=20001001"),
            ("final_raw=400020", "final_raw=400021"),
            ("qemu_cpu_time=unavailable", "qemu_cpu_time=0"),
            ("PASS\n", "PASS\nPASS\n"),
            ("step_ps=1000\n", ""),
            ("initial_raw=20", "initial_raw=18446744073709551616"),
        )
        for before, after in mutations:
            with self.subTest(before=before), self.assertRaises(ValueError):
                parser.read_result(RESULT.replace(before, after))
        with self.assertRaises(ValueError):
            parser.read_result(RESULT + "x" * 16384)

    def test_retained_pair_order_and_unique_delimiters(self):
        baseline = (
            "CRUCIBLE_ACK_POLL_RESULT_BEGIN baseline\n" + RESULT
            + "CRUCIBLE_ACK_POLL_RESULT_END baseline\n"
        )
        candidate = (
            "CRUCIBLE_ACK_POLL_RESULT_BEGIN ack-poll-100us\n"
            + RESULT.replace("poll_us=1000", "poll_us=100")
            + "CRUCIBLE_ACK_POLL_RESULT_END ack-poll-100us\n"
        )
        self.assertEqual(len(parser.serial_results(baseline + candidate)), 2)
        for serial in (candidate + baseline, baseline + baseline + candidate, baseline):
            with self.subTest(serial=serial), self.assertRaises(ValueError):
                parser.serial_results(serial)

    def test_different_fresh_coordinates_and_wrong_modes_refuse(self):
        baseline = parser.read_result(RESULT)
        candidate = parser.read_result(RESULT.replace("poll_us=1000", "poll_us=100"))
        candidate["initial_ps"] += 50
        candidate["final_ps"] += 50
        with self.assertRaises(ValueError):
            parser.compare(baseline, candidate)
        with self.assertRaises(ValueError):
            parser.compare(baseline, baseline)


if __name__ == "__main__":
    unittest.main()
