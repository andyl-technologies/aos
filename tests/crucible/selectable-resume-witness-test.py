"""Controls the actual bounded extractor; no native callback qualification."""

import importlib.util
import io
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "selectable_resume_witness", Path(__file__).with_name("selectable-resume-witness.py")
)
WITNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WITNESS)
ROW = (
    b"CRUCIBLE-SELECTABLE-RESUME-V1 phase=reply-return pid=42 sequence=2 "
    b"request_vcpu=0 vcpu=0 raw=Some(3) ps=Some(150) read=Some(1) write=Some(1) native=None\n"
)


class ExtractionTests(unittest.TestCase):
    def capture(self, data):
        output = io.BytesIO()
        WITNESS.retain(io.BytesIO(data), output)
        return output.getvalue()

    def test_early_witness_survives_a_larger_unrelated_stderr_tail(self):
        output = self.capture(ROW + b"unrelated host wait\n" * 4096)
        self.assertTrue(output.startswith(ROW))
        self.assertIn(b"rows=1 ", output)
        self.assertNotIn(b"unrelated host wait", output)

    def test_count_cap_never_forwards_more_than_the_native_stream(self):
        output = self.capture(ROW * (WITNESS.ROW_COUNT + 1))
        self.assertEqual(output.count(ROW), WITNESS.ROW_COUNT)
        self.assertIn(b"output_capped=1", output)
        self.assertLessEqual(len(output), WITNESS.OUTPUT_LIMIT + 256)

    def test_input_cap_does_not_read_a_later_record(self):
        output = self.capture(b"x" * WITNESS.INPUT_LIMIT + b"\n" + ROW)
        self.assertNotIn(ROW, output)
        self.assertIn(b"input_capped=1", output)

    def test_malformed_oversized_and_fragmented_rows_cannot_be_forwarded(self):
        malformed = ROW.replace(b"phase=reply-return", b"phase=unknown")
        oversized = WITNESS.PREFIX + b"x" * 512 + b"\n"
        output = self.capture(malformed + oversized + ROW[:-1])
        self.assertNotIn(ROW, output)
        self.assertIn(b"malformed=1", output)
        self.assertIn(b"oversized=1", output)

    def test_changed_ring_indices_and_native_state_preserve_original_order(self):
        before = ROW.replace(b"phase=reply-return", b"phase=reply-enter").replace(
            b"read=Some(1)", b"read=Some(0)"
        )
        native = ROW.replace(
            b"native=None", b"native=Some((7, 0, 10, 0, 0, -1))"
        )
        output = self.capture(before + ROW + native)
        self.assertTrue(output.startswith(before + ROW + native))

    def test_broken_sink_error_is_advisory_to_the_original_caller(self):
        class BrokenSink:
            def write(self, _data):
                raise BrokenPipeError()

        with self.assertRaises(BrokenPipeError):
            WITNESS.retain(io.BytesIO(ROW), BrokenSink())


if __name__ == "__main__":
    unittest.main()
