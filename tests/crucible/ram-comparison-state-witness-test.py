# SPDX-License-Identifier: Apache-2.0
"""Format, coverage and independent byte-mutation controls for stopped captures."""

import copy
import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("witness", Path(__file__).with_name("ram-comparison-state-witness.py"))
witness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(witness)


def region(name, kind, length):
    return struct.pack(">I", len(name)) + name + bytes((kind, 7 if kind < 3 else 6)) + struct.pack(">Q", length)


def paged(payloads, generation=7, versions=1, root_byte=42, initial=1):
    descriptors = [(b"main", 1, len(payloads[0])), (b"rom", 3, len(payloads[1]))]
    root = b"CRUCRR01" + struct.pack(">III", 1, 4096, 5) + b"exact" + struct.pack(">I", len(descriptors))
    root += b"".join(region(*descriptor) for descriptor in descriptors)
    root += struct.pack(">I", len(descriptors))
    root += b"".join(region(*descriptor) + bytes((root_byte,)) * 32 for descriptor in descriptors)
    records = sum((len(body) + 4095) // 4096 for body in payloads)
    header = struct.pack(">8sIIQQII", b"CRURCP01", 1, initial, generation, records, len(root), 0) + bytes((root_byte,)) * 32
    data = header + root
    for ordinal, body in enumerate(payloads):
        for page, offset in enumerate(range(0, len(body), 4096)):
            valid = body[offset:offset + 4096]
            data += struct.pack(">IIQQ", ordinal, len(valid), page, versions) + valid
    return data


class CompleteStateWitnessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.sequence = 0
        self.payloads = [bytes(range(256)) * 32, b"immutable-short-tail"]

    def tearDown(self):
        self.directory.cleanup()

    def artifact(self, data):
        path = self.root / str(self.sequence)
        self.sequence += 1
        path.write_bytes(data)
        return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest()}

    def capture(self, payloads=None, generation=7, root_byte=42, versions=1):
        return {"boundary": {"seed": 1000, "node": "node", "logical_icount": 9000,
                             "capture_generation": generation},
                "ram": self.artifact(paged(payloads or self.payloads, generation, versions, root_byte)),
                "device": self.artifact(b"QEVM\0\0\0\3full-device-state"),
                "host_io": self.artifact(witness.HOST_MAGIC + b"full-host-state"),
                "node": self.artifact(witness.NODE_MAGIC + b"full-node-state")}

    def test_common_bytes_ignore_only_ram_operational_metadata(self):
        result = witness.compare_pair(self.capture(), self.capture(generation=23, versions=51, root_byte=99))
        self.assertTrue(result["complete_capture_bytes_equal"])
        self.assertFalse(result["physical_origin_verified"])
        self.assertFalse(result["performance_qualified"])
        self.assertEqual(result["common_witness"]["ram"]["logical_bytes"], sum(map(len, self.payloads)))

    def test_mutations_anywhere_in_main_or_immutable_region_refuse(self):
        for ordinal, offset in ((0, 0), (0, 4096), (0, 8191), (1, 0), (1, len(self.payloads[1]) - 1)):
            changed = list(self.payloads)
            value = bytearray(changed[ordinal]); value[offset] ^= 1
            changed[ordinal] = bytes(value)
            with self.subTest(ordinal=ordinal, offset=offset), self.assertRaises(ValueError):
                witness.compare_pair(self.capture(), self.capture(payloads=changed))

    def test_each_complete_nonram_artifact_and_coordinate_must_match(self):
        for role in witness.STATE_ROLES:
            changed = self.capture()
            path = Path(changed[role]["path"])
            changed[role] = self.artifact(path.read_bytes() + b"changed")
            with self.subTest(role=role), self.assertRaises(ValueError):
                witness.compare_pair(self.capture(), changed)
        changed = self.capture(); changed["boundary"]["logical_icount"] += 1
        with self.assertRaises(ValueError): witness.compare_pair(self.capture(), changed)

    def test_missing_delta_duplicate_truncated_trailing_pages_refuse(self):
        original = paged(self.payloads)
        variants = [paged(self.payloads, initial=0), original[:-1], original + b"trailing"]
        changed = bytearray(original); changed[24:32] = struct.pack(">Q", 2)
        variants.append(bytes(changed))
        root_length = struct.unpack(">I", original[32:36])[0]
        page_start = 72 + root_length
        changed = bytearray(original)
        changed[page_start + 24 + 4096 + 8:page_start + 24 + 4096 + 16] = struct.pack(">Q", 0)
        variants.append(bytes(changed))
        for raw in variants:
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                witness.complete_ram(self.artifact(raw), 7)

    def test_exact_edition_inventory_and_generation_are_required(self):
        original = paged(self.payloads)
        for offset, replacement in ((8, struct.pack(">I", 2)), (36, struct.pack(">I", 1))):
            changed = bytearray(original); changed[offset:offset + 4] = replacement
            with self.assertRaises(ValueError): witness.complete_ram(self.artifact(bytes(changed)), 7)
        with self.assertRaises(ValueError): witness.complete_ram(self.artifact(original), 8)

    def test_pins_and_nonregular_or_symlink_inputs_fail_closed(self):
        capture = self.capture(); path = Path(capture["ram"]["path"])
        path.write_bytes(path.read_bytes() + b"changed")
        with self.assertRaises(ValueError): witness.capture_witness(capture)
        artifact = self.artifact(paged(self.payloads)); link = self.root / "link"
        link.symlink_to(artifact["path"]); artifact["path"] = str(link)
        with self.assertRaises(OSError): witness.complete_ram(artifact, 7)

    def test_appending_after_admission_refuses_with_a_bounded_second_pass(self):
        artifact = self.artifact(b"initial")
        with self.assertRaisesRegex(ValueError, "bounded hash extent"):
            with witness.pinned_file(artifact, 64) as (stream, admitted):
                self.assertEqual(admitted, 7)
                self.assertEqual(stream.read(), b"initial")
                with Path(artifact["path"]).open("ab") as writer:
                    writer.write(b"x" * 65536)
        # The hash helper refuses after maximum+1 bytes, not after the new EOF.
        class GrowingReader:
            def __init__(self):
                self.observed = 0

            def read(self, size):
                self.observed += size
                return b"x" * size

        reader = GrowingReader()
        with self.assertRaisesRegex(ValueError, "bounded hash extent"):
            witness.bounded_digest(reader, 7)
        self.assertEqual(reader.observed, 8)

    def test_master_direct_is_read_from_actual_old_format_and_remains_incomplete(self):
        data = b"m" * 8192
        header = struct.pack("<8sIIIIQQ", b"CRUCRAM2", 2, 1, 4096, 1, 1, len(data)) + b"i" * 96 + bytes(96)
        topology = struct.pack("<QQQI", len(data), len(data), 4096, 4) + b"main"
        record = struct.pack("<IIQ", 0, len(data), 0) + data
        observed = witness.legacy_direct_ram(self.artifact(header + topology + record))
        self.assertEqual(observed["logical_bytes"], 8192)
        self.assertFalse(observed["complete_guest_ram"])
        with self.assertRaises(ValueError): witness.complete_ram(self.artifact(header + topology + record), 7)
        mutated = bytearray(header + topology + record); mutated[-1] ^= 1
        self.assertNotEqual(observed["sha256"], witness.legacy_direct_ram(self.artifact(bytes(mutated)))["sha256"])


if __name__ == "__main__":
    unittest.main()
