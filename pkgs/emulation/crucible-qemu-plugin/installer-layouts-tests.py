"""Checks final ELF extraction and rejection without loading plugin constructors."""
# SPDX-License-Identifier: Apache-2.0

import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location(
    "installer_layouts", Path(__file__).with_name("installer-layouts.py")
)
EXTRACTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXTRACTOR)


def requests():
    record = bytearray(b"CRUCCTL1" + struct.pack(">IIII", 1, 248, 62, 7))
    for role in range(1, 8):
        record.extend(struct.pack(">IIQQQ", role, 0, role * 8, 8, 1))
    return record


def plugin(record=None):
    """Builds a closed numeric ELF fixture with a real dynamic data export."""
    record = requests() if record is None else record
    names = b"\0.shstrtab\0" + EXTRACTOR.SECTION + b".dynstr\0.dynsym\0"
    strings = b"\0" + EXTRACTOR.SYMBOL
    names_offset = 64 + 2 * 56
    record_offset = names_offset + len(names)
    strings_offset = record_offset + len(record)
    symbols_offset = strings_offset + len(strings)
    table_offset = symbols_offset + 48
    address = 0x1000 + record_offset
    symbols = bytes(24) + struct.pack("<IBBHQQ", 1, 0x11, 0, 2, address, 248)
    sections = [
        bytes(64),
        struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0),
        struct.pack("<IIQQQQIIQQ", 11, 1, 2, address, record_offset, 248, 0, 0, 1, 0),
        struct.pack("<IIQQQQIIQQ", 11 + len(EXTRACTOR.SECTION), 3, 0, 0,
                    strings_offset, len(strings), 0, 0, 1, 0),
        struct.pack("<IIQQQQIIQQ", 11 + len(EXTRACTOR.SECTION) + 8, 11, 2, 0,
                    symbols_offset, len(symbols), 3, 1, 8, 24),
    ]
    header = bytearray(64)
    header[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", header, 16, 3, 62, 1)
    struct.pack_into("<Q", header, 32, 64)
    struct.pack_into("<Q", header, 40, table_offset)
    struct.pack_into("<HHHHHH", header, 52, 64, 56, 1, 64, 5, 1)
    length = table_offset + 5 * 64
    load = struct.pack("<IIQQQQQQ", 1, 4, 0, 0x1000, 0, length, length, 0x1000)
    return bytearray(header + load + bytes(56) + names + record + strings + symbols + b"".join(sections))


class InstallerLayouts(unittest.TestCase):
    def extract(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plugin.so"
            path.write_bytes(data)
            return EXTRACTOR.extract(path)

    def test_complete_final_bytes_bind_numeric_record(self):
        data = plugin()
        identity = self.extract(data)
        self.assertEqual(identity[:248], requests())
        self.assertEqual(identity[248:280], hashlib.sha256(data).digest())
        self.assertEqual(len(identity), 280)
        changed = data + b"post-fixup bytes"
        self.assertNotEqual(identity[248:280], self.extract(changed)[248:280])

    def test_missing_or_duplicate_section_refuses(self):
        data = plugin()
        data[64 + 2 * 56 + 11] ^= 1
        with self.assertRaises(ValueError):
            self.extract(data)
        data = plugin()
        table = struct.unpack_from("<Q", data, 40)[0]
        data[table + 3 * 64:table + 4 * 64] = data[table + 2 * 64:table + 3 * 64]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.extract(data)

    def test_mutable_executable_tls_or_unknown_flags_refuse(self):
        for flags in (3, 6, 0x402, 0x802):
            data = plugin()
            table = struct.unpack_from("<Q", data, 40)[0]
            struct.pack_into("<Q", data, table + 2 * 64 + 8, flags)
            with self.assertRaises(ValueError):
                self.extract(data)

    def test_missing_wrong_or_non_object_export_refuses(self):
        for offset, value in ((0, 0), (4, 0x12), (5, 2), (6, 1), (8, 1), (16, 1)):
            data = plugin()
            table = struct.unpack_from("<Q", data, 40)[0]
            symbols = struct.unpack_from("<Q", data, table + 4 * 64 + 24)[0]
            data[symbols + 24 + offset] = value
            with self.assertRaises(ValueError):
                self.extract(data)

    def test_writable_executable_unmapped_or_misaligned_load_refuses(self):
        for offset, value in ((68, 6), (68, 5), (80, 0x2000), (72, 1)):
            data = plugin()
            struct.pack_into("<Q" if offset >= 72 else "<I", data, offset, value)
            with self.assertRaises(ValueError):
                self.extract(data)
        data = plugin()
        struct.pack_into("<H", data, 56, 2)
        data[120:176] = data[64:120]
        struct.pack_into("<I", data, 124, 6)
        with self.assertRaises(ValueError):
            self.extract(data)
        data = plugin()
        struct.pack_into("<I", data, 64, 0)
        with self.assertRaises(ValueError):
            self.extract(data)

    def test_adjacent_writable_load_in_record_page_refuses(self):
        data = plugin()
        table = struct.unpack_from("<Q", data, 40)[0]
        offset, size = struct.unpack_from("<QQ", data, table + 2 * 64 + 24)
        next_offset = offset + size
        # This second LOAD has no byte overlap with the record, but Linux maps
        # its writable tail onto the same page as the immutable record.
        struct.pack_into("<H", data, 56, 2)
        struct.pack_into("<IIQQQQQQ", data, 120, 1, 6, next_offset,
                         0x1000 + next_offset, 0, 1, 1, 1)
        with self.assertRaisesRegex(ValueError, "page.*permissions"):
            self.extract(data)

    def test_adjacent_readonly_load_with_different_file_page_refuses(self):
        data = plugin()
        table = struct.unpack_from("<Q", data, 40)[0]
        offset, size = struct.unpack_from("<QQ", data, table + 2 * 64 + 24)
        next_offset = offset + size
        data.extend(bytes(4096))
        struct.pack_into("<H", data, 56, 2)
        # This adjacent readable mapping replaces the record page from a
        # different file page. Read-only flags alone do not preserve the bytes.
        struct.pack_into("<IIQQQQQQ", data, 120, 1, 4, next_offset + 4096,
                         0x1000 + next_offset, 0, 1, 1, 1)
        with self.assertRaisesRegex(ValueError, "mapping.*ambiguous"):
            self.extract(data)

    def test_elf_extent_and_target_mismatches_refuse(self):
        for offset, fmt, value in ((18, "H", 3), (40, "Q", 1 << 63),
                                   (58, "H", 32), (60, "H", 65535)):
            data = plugin()
            struct.pack_into("<" + fmt, data, offset, value)
            with self.assertRaises(ValueError):
                self.extract(data)
        with self.assertRaises(ValueError):
            self.extract(plugin()[:-1])

    def test_every_request_canonical_field_refuses(self):
        for role in range(7):
            for offset, value in ((3, 0), (7, 1), (15, 0), (23, 3), (31, 2)):
                record = requests()
                record[24 + 32 * role + offset] = value
                if offset == 15:
                    record[24 + 32 * role + 8:24 + 32 * role + 16] = bytes(8)
                with self.assertRaises(ValueError):
                    self.extract(plugin(record))
        for offset in (0, 11, 15, 19, 23):
            record = requests()
            record[offset] ^= 1
            with self.assertRaises(ValueError):
                self.extract(plugin(record))

    def test_final_machine_must_match_record_and_legacy_record_refuses(self):
        record = requests()
        struct.pack_into(">I", record, 16, 183)
        with self.assertRaisesRegex(ValueError, "machine differs"):
            self.extract(plugin(record))
        with self.assertRaises(ValueError):
            EXTRACTOR.validate_requests(bytes(240))

    def test_finalization_stamps_only_zero_and_hashes_the_reread_final_file(self):
        record = requests()
        struct.pack_into(">I", record, 16, 0)
        data = plugin(record)
        table = struct.unpack_from("<Q", data, 40)[0]
        record_offset = struct.unpack_from("<Q", data, table + 2 * 64 + 24)[0]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plugin.so"
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                EXTRACTOR.extract(path)
            identity = EXTRACTOR.extract(path, stamp=True)
            final = path.read_bytes()
            expected = bytearray(data)
            struct.pack_into(">I", expected, record_offset + 16, 62)
            self.assertEqual(final, expected)
            self.assertEqual(identity[:248], requests())
            self.assertEqual(identity[248:], hashlib.sha256(final).digest())
            self.assertEqual(EXTRACTOR.extract(path), identity)
            self.assertEqual(EXTRACTOR.extract(path, stamp=True), identity)

    def test_finalization_never_repairs_a_mismatch_or_unmapped_record(self):
        record = requests()
        struct.pack_into(">I", record, 16, 183)
        for data in (plugin(record), plugin()):
            if data == plugin():
                struct.pack_into("<I", data, 68, 6)
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "plugin.so"
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    EXTRACTOR.extract(path, stamp=True)
                self.assertEqual(path.read_bytes(), data)

    def test_total_overflow_refuses(self):
        record = requests()
        for role in range(7):
            struct.pack_into(">QQ", record, 24 + 32 * role + 8, (1 << 63) - 1, 1)
        with self.assertRaisesRegex(ValueError, "overflow"):
            self.extract(plugin(record))


if __name__ == "__main__":
    unittest.main()
