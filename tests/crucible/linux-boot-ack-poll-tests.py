"""Refusal contracts for the retained Linux ACK pair parser."""

import importlib.util
from pathlib import Path
import unittest
import sys

parser_path = (
    Path(sys.argv.pop(1))
    if len(sys.argv) > 1
    else Path(__file__).with_name("linux-boot-ack-poll.py")
)
spec = importlib.util.spec_from_file_location("linux_ack_poll", parser_path)
parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parser)


def body(interval, elapsed):
    values = dict(parser.FIXED)
    values.update({
        "experiment_ack_poll_us": interval,
        "host_segment_elapsed_us": elapsed,
        "grants": 20000,
        "step_ps": 10000000,
        "initial_ps": 8000000,
        "final_scheduler_ps": 200008000000,
        "final_physical_ps": 200008000000,
        "initial_raw": 160000,
        "final_raw": 4000160000,
        "control_returns": 20000,
        "projected_grants": 0,
        "clamp_guard_ms": 1000,
        "advance_guard_s": 300,
    })
    values.update({name: "1" * 64 for name in parser.DIGESTS})
    return "PASS\n" + "".join(f"{key}={values[key]}\n" for key in sorted(values))


def pair_text(original=None, changed=None):
    original = body(1000, 2) if original is None else original
    changed = body(100, 1) if changed is None else changed
    return (
        "CRUCIBLE_LINUX_ACK_POLL_RESULT_BEGIN baseline\n"
        + original
        + "CRUCIBLE_LINUX_ACK_POLL_RESULT_END baseline\n"
        + "CRUCIBLE_LINUX_ACK_POLL_RESULT_BEGIN ack-poll-100us\n"
        + changed
        + "CRUCIBLE_LINUX_ACK_POLL_RESULT_END ack-poll-100us\n"
    )


class PairContracts(unittest.TestCase):
    def test_complete_pair_accepts_either_timing_order(self):
        for elapsed in (0, 3, 2 ** 128 - 1):
            with self.subTest(elapsed=elapsed):
                values = parser.pair(pair_text(changed=body(100, elapsed)))
                self.assertEqual(values[1][2]["host_segment_elapsed_us"], elapsed)

    def test_missing_repeated_reversed_and_oversized_pairs_refuse(self):
        complete = pair_text()
        invalid = [
            complete.split("CRUCIBLE_LINUX_ACK_POLL_RESULT_BEGIN ack-poll-100us")[0],
            complete + complete,
            complete.replace("END baseline", "BEGIN baseline"),
            complete.replace("PASS\n", "PASS\nPASS\n", 1),
            pair_text(changed=body(100, 1) + "x" * 16384),
        ]
        for text in invalid:
            with self.subTest(text=text[:80]):
                with self.assertRaises(ValueError):
                    parser.pair(text)

    def test_changed_coordinates_grants_guards_or_owner_refuse(self):
        original = body(100, 1)
        mutations = [
            ("grants=20000", "grants=19999"),
            ("clamp_guard_ms=1000", "clamp_guard_ms=1001"),
            ("advance_guard_s=300", "advance_guard_s=301"),
            ("final_raw=4000160000", "final_raw=4000160001"),
            ("owned_cleanup=complete", "owned_cleanup=incomplete"),
            ("control_returns=20000", "control_returns=40001"),
            ("transcript_blake3=" + "1" * 64, "transcript_blake3=" + "2" * 64),
        ]
        for old, new in mutations:
            with self.subTest(field=old):
                with self.assertRaises(ValueError):
                    parser.pair(pair_text(changed=original.replace(old, new)))

    def test_projection_keeps_physical_coordinate_and_requires_proof(self):
        def projected(interval):
            return body(interval, 1).replace(
                "final_physical_ps=200008000000", "final_physical_ps=200007000000"
            ).replace("projected_grants=0", "projected_grants=1")

        values = parser.pair(pair_text(projected(1000), projected(100)))
        self.assertLess(
            values[0][2]["final_physical_ps"], values[0][2]["final_scheduler_ps"]
        )
        with self.assertRaises(ValueError):
            parser.result(projected(100).replace("projected_grants=1", "projected_grants=0"))

    def test_noncanonical_fields_and_no_retirement_refuse(self):
        original = body(100, 1)
        invalid = [
            original + "grants=20000\n",
            original + "unknown=true\n",
            original.replace("initial_raw=160000", "initial_raw=0160000"),
            original.replace("final_raw=4000160000", "final_raw=160000"),
            original.replace("initial_fingerprint=" + "1" * 64, "initial_fingerprint=bad"),
            original.replace("host_segment_elapsed_us=1", "host_segment_elapsed_us=" + str(2 ** 128)),
        ]
        for text in invalid:
            with self.subTest(text=text[:80]):
                with self.assertRaises(ValueError):
                    parser.result(text)


if __name__ == "__main__":
    unittest.main()
