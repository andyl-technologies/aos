# SPDX-License-Identifier: MIT
"""Adversarial format tests; native process closure is verified separately."""

import importlib.util
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest


spec = importlib.util.spec_from_file_location("image_inventory", sys.argv[1])
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


def header():
    value = bytearray(4096)
    value[:len(inventory.SIGNATURE)] = inventory.SIGNATURE
    struct.pack_into("<I", value, 132, 1)
    value[1280:1285] = b"gem5\0"
    return bytes(value)


def area(start=0x10000, size=4096, properties=0, file_bytes=-1):
    value = bytearray(4096)
    struct.pack_into("<9QqQ", value, 0, start, start + size, size,
                     0, 3, 0x32, 0, 0, 0, file_bytes, properties)
    return bytes(value)


def terminal():
    value = bytearray(4096)
    struct.pack_into("<Q", value, 16, (1 << 64) - 1)
    return bytes(value)


class ImageFormatTests(unittest.TestCase):
    def parse(self, body, second=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.dmtcp"
            path.write_bytes(header() + (second or header()) + body)
            return inventory.parse_image(path)

    def test_signed_unused_file_extent_and_native_payload(self):
        result = self.parse(area() + b"x" * 4096 + terminal())
        self.assertEqual(result["source_executable"], "gem5")
        self.assertEqual(result["mappings"][0]["size"], 4096)

    def test_parent_zero_and_content_runs_cover_region(self):
        result = self.parse(area(size=8192, properties=2)
                            + area(properties=5)
                            + area(start=0x11000, properties=4)
                            + b"x" * 4096 + terminal())
        self.assertEqual(len(result["mappings"]), 1)
        self.assertEqual(len(result["spans"]), 2)

    def test_truncated_payload_refused(self):
        with self.assertRaises(ValueError):
            self.parse(area() + b"x")

    def test_duplicate_header_mismatch_refused(self):
        changed = bytearray(header())
        changed[2000] = 1
        with self.assertRaises(ValueError):
            self.parse(terminal(), bytes(changed))

    def test_overlapping_child_refused(self):
        with self.assertRaises(ValueError):
            self.parse(area(size=8192, properties=2)
                       + area(properties=5) + area(properties=5) + terminal())

    def test_incomplete_parent_refused(self):
        with self.assertRaises(ValueError):
            self.parse(area(size=8192, properties=2)
                       + area(properties=5) + terminal())

    def test_child_without_parent_refused(self):
        with self.assertRaises(ValueError):
            self.parse(area(properties=5) + terminal())

    def test_terminal_trailing_bytes_refused(self):
        with self.assertRaises(ValueError):
            self.parse(terminal() + b"extra")

    def test_unrecognized_properties_refused(self):
        with self.assertRaises(ValueError):
            self.parse(area(properties=8) + b"x" * 4096 + terminal())

    def test_shared_or_symbolic_supplementary_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "target").write_bytes(b"owned")
            (path / "alias").symlink_to(path / "target")
            with self.assertRaises(ValueError):
                inventory.owned_tree(directory)

    def file_map_receipt(self, change=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guest = root / "guest.elf"
            guest.write_bytes(b"owned-guest-ELF".ljust(8192, b"!"))
            supplementary = root / "image_files"
            supplementary.mkdir()
            saved = supplementary / "guest.saved"
            saved.write_bytes(guest.read_bytes())
            metadata = guest.stat()
            original = bytearray(1112)
            struct.pack_into("<9QqQ", original, 0, 0x20000, 0x22000, 8192,
                             0, 1, 1, os.major(metadata.st_dev), os.minor(metadata.st_dev),
                             metadata.st_ino, 8192, 0)
            name = os.fsencode(guest)
            original[88:88 + len(name)] = name
            receipt = bytearray(5224)
            receipt[:1112] = original
            path = os.fsencode(saved)
            receipt[1112:1112 + len(path)] = path
            struct.pack_into("<QQ", receipt, 5208, 1, 5)
            placeholder = {"start": 0x20000, "end": 0x22000, "permissions": "---p",
                           "name": "", "offset": 0, "device": [0, 0], "inode": 0}
            if change:
                change(receipt, saved, placeholder)
            image = root / "image.dmtcp"
            image.write_bytes(header() * 2 + area(size=8192)
                              + bytes(receipt).ljust(8192, b"\0") + terminal())
            parsed = inventory.parse_image(image)
            record = {"address": str(0x10000), "bytes_hex": receipt.hex()}
            digest, size = inventory.digest_file(guest)
            return inventory.verify_file_map_receipts(
                image, parsed["spans"], [record], [placeholder], str(supplementary),
                str(guest), {str(guest): {"sha256": digest, "bytes": str(size)}}, str(root))

    def test_native_file_transformation_has_exact_saved_custody(self):
        result = self.file_map_receipt()
        self.assertEqual(result[0]["original_map"]["permissions"], "r--s")
        self.assertEqual(result[0]["saved_relative_path"], "guest.saved")

    def test_uncheckpointed_native_file_transformation_refused(self):
        with self.assertRaises(ValueError):
            self.file_map_receipt(lambda receipt, saved, placeholder:
                                  struct.pack_into("<Q", receipt, 5208, 0))

    def test_mutable_shared_file_transformation_refused(self):
        with self.assertRaises(ValueError):
            self.file_map_receipt(lambda receipt, saved, placeholder:
                                  struct.pack_into("<Q", receipt, 32, 3))

    def test_changed_native_file_copy_refused(self):
        with self.assertRaises(ValueError):
            self.file_map_receipt(lambda receipt, saved, placeholder: saved.write_bytes(b"changed"))

    def test_forged_placeholder_refused(self):
        with self.assertRaises(ValueError):
            self.file_map_receipt(lambda receipt, saved, placeholder:
                                  placeholder.update(permissions="rw-p"))

    def test_wrong_native_original_inode_refused(self):
        with self.assertRaises(ValueError):
            self.file_map_receipt(lambda receipt, saved, placeholder:
                                  struct.pack_into("<Q", receipt, 64, 1))

    def test_context_reads_zero_and_native_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.dmtcp"
            path.write_bytes(header() * 2 + area(size=8192, properties=2)
                             + area(properties=5)
                             + area(start=0x11000, properties=4)
                             + b"x" * 4096 + terminal())
            parsed = inventory.parse_image(path)
            value = inventory.captured_bytes(path, parsed["spans"], 0x10ffe, 4)
            self.assertEqual(value, b"\0\0xx")
            with self.assertRaises(ValueError):
                inventory.captured_bytes(path, parsed["spans"], 0x12000, 1)

    def test_noncanonical_integers_refused(self):
        for value in ("01", "-1", "١", True, 1):
            with self.assertRaises(ValueError):
                inventory.integer(value)

    def test_postcapture_owner_allocation_is_separate_from_saved_map(self):
        original = [{"start": 8192, "end": 16384, "permissions": "rw-p",
                     "name": "", "offset": 0, "device": [0, 0], "inode": 0}]
        current = [{**original[0], "start": 4096}]
        extra = inventory.verify_retained_maps(original, current)
        self.assertEqual([(item["start"], item["end"]) for item in extra], [(4096, 8192)])
        self.assertEqual(extra[0]["coverage"], "operational-owner-allocation-after-capture")

    def test_postcapture_external_mapping_is_refused(self):
        current = [{"start": 4096, "end": 8192, "permissions": "rw-s",
                    "name": "/external", "offset": 0, "device": [0, 0], "inode": 0}]
        with self.assertRaises(ValueError):
            inventory.verify_retained_maps([], current)

    def test_original_mapped_custody_change_is_refused(self):
        original = [{"start": 4096, "end": 8192, "permissions": "rw-p",
                     "name": "", "offset": 0, "device": [0, 0], "inode": 0}]
        with self.assertRaises(ValueError):
            inventory.verify_retained_maps(original, [{**original[0], "permissions": "rw-s"}])

    def test_released_owner_arena_does_not_describe_original_capture_bytes(self):
        original = [{"start": 4096, "end": 12288, "permissions": "rw-p",
                     "name": "", "offset": 0, "device": [0, 0], "inode": 0}]
        current = [{**original[0], "end": 8192}]
        changes = inventory.verify_retained_maps(original, current)
        self.assertEqual([(item["start"], item["end"]) for item in changes], [(8192, 12288)])
        self.assertEqual(changes[0]["coverage"], "operational-owner-release-after-capture")

    def test_original_file_mapping_cannot_disappear(self):
        original = [{"start": 4096, "end": 8192, "permissions": "r--p",
                     "name": "/nix/store/immutable/code", "offset": 0,
                     "device": [8, 1], "inode": 123}]
        with self.assertRaises(ValueError):
            inventory.verify_retained_maps(original, [])


unittest.main(argv=[sys.argv[0]])
