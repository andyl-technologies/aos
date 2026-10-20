"""Corrupt source-built paused VMState streams at each projection boundary."""

import json
import os
import runpy
import unittest
from pathlib import Path


PARSER = runpy.run_path(os.environ.get(
    "QEMU_INERT_MIGRATION_PARSER",
    str(Path(__file__).with_name("qemu-inert-migration.py")),
))
MigrationMismatch = PARSER["MigrationMismatch"]
verify_pair = PARSER["verify_pair"]
split_stream = PARSER["split_stream"]
WIDE = PARSER["WIDE"]


def fixture(name):
    key = "QEMU_INERT_MIGRATION_" + name.upper()
    path = os.environ.get(key)
    if not path:
        raise RuntimeError(f"{key} must name the source-built paused stream")
    return Path(path).read_bytes()


def mutate(data, offset, replacement):
    return data[:offset] + replacement + data[offset + len(replacement):]


class MigrationProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference = fixture("reference")
        cls.patched = fixture("patched")

    def rejects(self, patched=None, reference=None, patched_b=None, reference_b=None):
        reference = self.reference if reference is None else reference
        patched = self.patched if patched is None else patched
        with self.assertRaises(MigrationMismatch):
            verify_pair(reference, reference if reference_b is None else reference_b,
                        patched, patched if patched_b is None else patched_b)

    def frame(self, index):
        _, name, version, size, _ = WIDE[index]
        prefix = b"\x05" + bytes([len(name)]) + name.encode()
        offset = self.patched.index(prefix)
        length = len(prefix) + 4 + size
        return offset, length, version

    def test_all_ten_real_frames_project_exactly(self):
        result = verify_pair(self.reference, self.reference,
                             self.patched, self.patched)
        self.assertEqual(result["timer_subsection_count"], 10)
        self.assertEqual(result["timer_frame_bytes"], 1027)
        self.assertEqual(result["pit_fractional_phase_ps"], 578)
        self.assertEqual(result["section_id_changes"], 66)

    def test_each_added_frame_is_required(self):
        for index in range(len(WIDE)):
            with self.subTest(name=WIDE[index][1]):
                offset, length, _ = self.frame(index)
                self.rejects(patched=self.patched[:offset] +
                             self.patched[offset + length:])

    def test_duplicate_and_unknown_frame_are_rejected(self):
        offset, length, _ = self.frame(7)
        frame = self.patched[offset:offset + length]
        self.rejects(patched=self.patched[:offset] + frame + self.patched[offset:])
        unknown = frame.replace(b"i8254/timer-wide", b"i8254/timer-widx")
        self.rejects(patched=self.patched[:offset] + unknown +
                     self.patched[offset + length:])

    def test_frame_version_mode_and_coordinate_corruption_are_rejected(self):
        offset, length, _ = self.frame(0)
        version = offset + 2 + len(WIDE[0][1])
        self.rejects(patched=mutate(self.patched, version + 3, b"\x02"))
        self.rejects(patched=mutate(self.patched, version + 4, b"\x02"))

        pit_offset, _, _ = self.frame(7)
        pit_payload = pit_offset + 2 + len(WIDE[7][1]) + 4
        # Change the signed high word while preserving the unsigned low word.
        self.rejects(patched=mutate(self.patched, pit_payload + 4 + 3 * 8,
                                    b"\xff" * 8))
        self.rejects(patched=self.patched[:pit_payload + 25] +
                     self.patched[pit_payload + 26:])

    def test_legacy_body_and_section_identity_are_not_stripped(self):
        body, _, _ = split_stream(self.patched)
        # A byte in unrelated RAM and a PIT legacy count are outside the allowlist.
        self.rejects(patched=mutate(self.patched, 4096,
                                    bytes([self.patched[4096] ^ 1])))
        pit_header = body.index(b"\x05i8254") - 5
        self.rejects(patched=mutate(self.patched, pit_header + 19 + 4,
                                    bytes([self.patched[pit_header + 23] ^ 1])))
        # Header ID is checked together with its corresponding footer.
        self.rejects(patched=mutate(self.patched, pit_header + 4,
                                    bytes([self.patched[pit_header + 4] ^ 1])))

    def test_payload_lookalike_cannot_replace_a_genuine_section_id(self):
        # This ICH9 payload contains 01 00 00 00 00, which resembles a
        # migration START marker and ID. The old byte-shape scan accepted a
        # +1 here if one genuine shifted ID was changed back to its stock ID.
        payload_offset = 795671 + sum(self.frame(index)[1] for index in (0, 1))
        self.assertEqual(self.patched[payload_offset - 4:payload_offset + 1],
                         b"\x01\x00\x00\x00\x00")
        corrupted = bytearray(self.patched)
        corrupted[28] = self.reference[28]
        corrupted[payload_offset] = 1
        self.rejects(patched=bytes(corrupted))

    def test_vmdescription_field_and_unrelated_device_corruption_are_rejected(self):
        body, raw, descriptor = split_stream(self.patched)
        self.assertIn(b'"wide_time_hi"', raw)
        self.rejects(patched=self.patched.replace(b'"wide_time_hi"',
                                                  b'"wide_time_hx"'))
        self.assertIn(b'"page_size": 4096', raw)
        self.rejects(patched=self.patched.replace(b'"page_size": 4096',
                                                  b'"page_size": 8192'))
        self.assertEqual(len(descriptor["devices"]), 30)
        self.rejects(patched=self.patched[:len(body) - 1] +
                     self.patched[len(body):])

    def test_repeatability_and_truncation(self):
        self.rejects(reference_b=self.reference + b"x")
        self.rejects(patched_b=self.patched + b"x")
        self.rejects(patched=self.patched[:-1])


if __name__ == "__main__":
    unittest.main()
