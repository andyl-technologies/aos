"""Checks BTF decoding and the deliberately narrow source-location allowance."""

import struct
import unittest

from bpf_object import btf_extensions, btf_types


def extension(source="./pkgs/security/example.bpf.c"):
    """Creates independent function, source-line, and nonempty CO-RE records."""
    strings = b"\0"
    offsets = []
    for name in ["lsm/example", source, "return ctx->value;", "0:1"]:
        offsets.append(len(strings))
        strings += name.encode() + b"\0"
    section, filename, line, access = offsets
    functions = struct.pack("<IIIII", 8, section, 1, 0, 7)
    lines = struct.pack("<IIIIIII", 16, section, 1, 0, filename, line, (42 << 10) | 3)
    core = struct.pack("<IIIIIII", 16, section, 1, 8, 9, access, 0)
    header = struct.pack("<HBBIIIIIII", 0xEB9F, 1, 0, 32,
                         0, len(functions), len(functions), len(lines),
                         len(functions) + len(lines), len(core))
    return header + functions + lines + core, strings


class BpfObjectTests(unittest.TestCase):
    def test_type_names_resolve_without_changing_layout_fields(self):
        strings = b"\0value\0"
        integer = struct.pack("<IIII", 1, 1 << 24, 4, (1 << 24) | 32)
        header = struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(integer), len(integer), len(strings))
        types, actual_strings = btf_types(header + integer + strings)
        self.assertEqual(actual_strings, strings)
        self.assertEqual(types, [{"name": "value", "info": 1 << 24,
                                  "size_or_type": 4, "payload": [(1 << 24) | 32]}])

    def test_line_path_allowance_keeps_core_relocations_exact(self):
        bazel, strings = extension()
        actual, paths = btf_extensions(bazel, strings, "example.bpf.c")
        original, original_strings = extension("/build/example.bpf.c")
        before, _ = btf_extensions(original, original_strings, "example.bpf.c")
        self.assertEqual(actual, before)
        self.assertEqual(paths, ["./pkgs/security/example.bpf.c"])
        self.assertEqual(actual["core"], [{"section": "lsm/example", "records": [[8, 9, "0:1", 0]]}])
        self.assertEqual(actual["lines"][0]["records"], [[0, "example.bpf.c", "return ctx->value;", (42 << 10) | 3]])

    def test_unknown_source_directory_fails(self):
        data, strings = extension("/private/sandbox/example.bpf.c")
        with self.assertRaisesRegex(ValueError, "unexpected BTF source-file"):
            btf_extensions(data, strings, "example.bpf.c")

    def test_truncated_core_records_fail(self):
        data, strings = extension()
        with self.assertRaisesRegex(ValueError, "truncated BTF extension"):
            btf_extensions(data[:-4], strings, "example.bpf.c")

    def test_unknown_core_record_size_fails(self):
        data, strings = extension()
        damaged = bytearray(data)
        struct.pack_into("<I", damaged, len(data) - 28, 20)
        with self.assertRaisesRegex(ValueError, "unsupported BTF extension record"):
            btf_extensions(damaged, strings, "example.bpf.c")

    def test_overlapping_record_groups_fail(self):
        data, strings = extension()
        damaged = bytearray(data)
        struct.pack_into("<I", damaged, 24, 0)
        with self.assertRaisesRegex(ValueError, "unsupported BTF extension layout"):
            btf_extensions(damaged, strings, "example.bpf.c")

    def test_extra_unaccounted_bytes_fail(self):
        data, strings = extension()
        with self.assertRaisesRegex(ValueError, "BPF object omits"):
            btf_extensions(data + b"\0", strings, "example.bpf.c")


if __name__ == "__main__":
    unittest.main()
