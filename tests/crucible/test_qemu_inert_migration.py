"""Corruption controls for the pinned sim-off migration projection."""

import copy
import json
import os
import runpy
import struct
import unittest
from pathlib import Path


PARSER_PATH = Path(
    os.environ.get(
        "QEMU_INERT_MIGRATION_PARSER",
        Path(__file__).with_name("qemu-inert-migration.py"),
    )
)
MODULE = runpy.run_path(str(PARSER_PATH))
MigrationMismatch = MODULE["MigrationMismatch"]
verify_pair = MODULE["verify_pair"]
EXPECTED_SUBSECTION_SCHEMA = MODULE["EXPECTED_SUBSECTION_SCHEMA"]


def frame(descriptor, body):
    encoded = json.dumps(descriptor).encode("ascii")
    return body + b"\x06" + len(encoded).to_bytes(4, "big") + encoded


def streams():
    pit = {
        "name": "i8254",
        "instance_id": 0,
        "vmsd_name": "i8254",
        "version": 3,
        "fields": [{"name": "legacy", "size": 108, "type": "buffer"}],
    }
    other = {"fields": [], "name": "other", "version": 1}
    reference_desc = {"devices": [pit, other], "page_size": 4096}
    patched_desc = copy.deepcopy(reference_desc)
    patched_desc["devices"][0]["subsections"] = [EXPECTED_SUBSECTION_SCHEMA]
    # QEMU emits the subsection member after the legacy fields.
    patched_pit = patched_desc["devices"][0]
    patched_desc["devices"][0] = {
        "name": "i8254",
        "instance_id": 0,
        "vmsd_name": "i8254",
        "version": 3,
        "fields": patched_pit["fields"],
        "subsections": patched_pit["subsections"],
    }

    section_id = b"\x00\x00\x00\x13"
    header = b"\x04" + section_id + b"\x05i8254" + b"\x00" * 4 + b"\x00\x00\x00\x03"
    legacy = bytes(range(108))
    footer = b"\x7e" + section_id
    prefix = b"QEVM\x00\x00\x00\x03\x07\x00\x00"
    subsection = (
        b"\x05\x14i8254/crucible-clock\x00\x00\x00\x03"
        + struct.pack(">4H3Q", 0, 0, 0, 578, 0, 0, 0)
    )
    reference = frame(reference_desc, prefix + header + legacy + footer + b"\x00")
    patched = frame(patched_desc, prefix + header + legacy + subsection + footer + b"\x00")
    return reference, patched, subsection


class MigrationProjectionTests(unittest.TestCase):
    def setUp(self):
        self.reference, self.patched, self.subsection = streams()

    def rejects(self, reference=None, patched=None, reference_b=None, patched_b=None):
        with self.assertRaises(MigrationMismatch):
            verify_pair(
                self.reference if reference is None else reference,
                self.reference if reference_b is None else reference_b,
                self.patched if patched is None else patched,
                self.patched if patched_b is None else patched_b,
            )

    def test_exact_phase_subsection_preserves_every_legacy_byte(self):
        result = verify_pair(self.reference, self.reference, self.patched, self.patched)
        self.assertEqual(result["pit_phase_ps"], (0, 0, 0, 578))
        self.assertEqual(result["pit_owner_fields"], (0, 0, 0))

    def test_legacy_pit_base_mutation_is_not_projected_away(self):
        offset = self.patched.index(bytes(range(108))) + 61
        corrupted = bytearray(self.patched)
        corrupted[offset] ^= 1
        self.rejects(patched=bytes(corrupted))

    def test_unknown_or_duplicate_subsection_is_rejected(self):
        unknown = self.subsection.replace(b"crucible-clock", b"crucible-clocx")
        self.rejects(patched=self.patched.replace(self.subsection, unknown))
        self.rejects(patched=self.patched.replace(self.subsection, self.subsection * 2))

    def test_bad_subsection_version_length_and_phase_are_rejected(self):
        self.rejects(patched=self.patched.replace(self.subsection[:26], self.subsection[:22] + b"\x00\x00\x00\x04"))
        self.rejects(patched=self.patched.replace(b"\x05\x14i8254/crucible-clock", b"\x05\x13i8254/crucible-clock"))
        bad_phase = self.subsection[:32] + struct.pack(">H", 1000) + self.subsection[34:]
        self.rejects(patched=self.patched.replace(self.subsection, bad_phase))

        owned_timer = self.subsection[:34] + struct.pack(">Q", 1) + self.subsection[42:]
        self.rejects(patched=self.patched.replace(self.subsection, owned_timer))

    def test_truncation_and_other_vmdesc_change_are_rejected(self):
        self.rejects(patched=self.patched[:-1])
        self.rejects(patched=self.patched.replace(b'"page_size": 4096', b'"page_size": 8192'))

    def test_same_binary_repeat_difference_is_rejected(self):
        self.rejects(patched_b=self.patched + b"x")
        self.rejects(reference_b=self.reference + b"x")


if __name__ == "__main__":
    unittest.main()
