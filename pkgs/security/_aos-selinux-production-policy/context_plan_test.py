"""Regression tests for deterministic AOS SELinux context planning."""

from __future__ import annotations

import os
import struct
import tempfile
import unittest
from pathlib import Path

import context_plan


def elf64(
    object_type: int,
    *,
    interpreter: bool = False,
    flags_1: int = 0,
) -> bytes:
    """Builds the minimal ELF64 metadata consumed by ``inspect_elf``."""

    segments: list[tuple[int, bytes]] = []
    if interpreter:
        segments.append((context_plan.PT_INTERP, b"/lib/ld.so\x00"))
    if flags_1:
        dynamic = struct.pack(
            "<QQQQ",
            context_plan.DT_FLAGS_1,
            flags_1,
            context_plan.DT_NULL,
            0,
        )
        segments.append((context_plan.PT_DYNAMIC, dynamic))

    header_size = 64
    program_header_size = 56
    payload_offset = header_size + program_header_size * len(segments)
    image = bytearray(payload_offset)
    image[0:16] = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<H", image, 16, object_type)
    struct.pack_into("<Q", image, 32, header_size)
    struct.pack_into("<H", image, 52, header_size)
    struct.pack_into("<H", image, 54, program_header_size)
    struct.pack_into("<H", image, 56, len(segments))

    for index, (program_type, payload) in enumerate(segments):
        header_offset = header_size + index * program_header_size
        struct.pack_into("<I", image, header_offset, program_type)
        struct.pack_into("<Q", image, header_offset + 8, payload_offset)
        struct.pack_into("<Q", image, header_offset + 32, len(payload))
        image.extend(payload)
        payload_offset += len(payload)
    return bytes(image)


class ElfClassificationTest(unittest.TestCase):
    """Covers executable, PIE, static PIE, DSO, and malformed ELF cases."""

    def classify(self, image: bytes, mode: int, relative: str = "bin/program") -> str:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary, "image")
            source.write_bytes(image)
            source.chmod(mode)
            return context_plan.classify_store_regular(
                f"/nix/store/hash-package/{relative}", source, source.stat().st_mode
            )

    def test_et_exec_is_executable(self) -> None:
        self.assertEqual(self.classify(elf64(context_plan.ET_EXEC), 0o755), "bin_t")

    def test_dynamic_pie_has_interpreter(self) -> None:
        self.assertEqual(
            self.classify(elf64(context_plan.ET_DYN, interpreter=True), 0o755),
            "bin_t",
        )

    def test_static_pie_uses_df_1_pie_without_interpreter(self) -> None:
        self.assertEqual(
            self.classify(
                elf64(context_plan.ET_DYN, flags_1=context_plan.DF_1_PIE),
                0o755,
            ),
            "bin_t",
        )

    def test_executable_dso_under_library_role_is_library(self) -> None:
        self.assertEqual(
            self.classify(elf64(context_plan.ET_DYN), 0o755, "lib/libsample.so"),
            "lib_t",
        )

    def test_ambiguous_executable_et_dyn_is_rejected(self) -> None:
        with self.assertRaisesRegex(context_plan.PlanError, "ambiguous executable ET_DYN"):
            self.classify(elf64(context_plan.ET_DYN), 0o755)

    def test_executable_script_is_executable(self) -> None:
        self.assertEqual(self.classify(b"#!/bin/sh\nexit 0\n", 0o755), "bin_t")

    def test_non_executable_data_is_usr_data(self) -> None:
        self.assertEqual(self.classify(b"configuration\n", 0o644), "usr_t")

    def test_sparse_non_elf_is_classified_without_reading_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary, "sparse-data")
            with source.open("wb") as file:
                file.seek(8 * 1024 * 1024 * 1024)
                file.write(b"\x00")
            source.chmod(0o644)
            self.assertEqual(
                context_plan.classify_store_regular(
                    "/nix/store/hash-package/share/sparse-data",
                    source,
                    source.stat().st_mode,
                ),
                "usr_t",
            )

    def test_truncated_elf_is_rejected(self) -> None:
        with self.assertRaisesRegex(context_plan.PlanError, "truncated ELF"):
            self.classify(b"\x7fELF\x02\x01", 0o755)

    def test_out_of_range_program_table_is_rejected(self) -> None:
        image = bytearray(elf64(context_plan.ET_EXEC))
        struct.pack_into("<Q", image, 32, len(image) + 1)
        struct.pack_into("<H", image, 56, 1)
        with self.assertRaisesRegex(context_plan.PlanError, "program-header table"):
            self.classify(bytes(image), 0o755)


class PlanSemanticsTest(unittest.TestCase):
    """Covers alias authority, conflicts, hardlinks, and deterministic output."""

    def test_generated_context_preserves_non_mls_policy_shape(self) -> None:
        self.assertEqual(
            context_plan._context_with_type(
                ["system_u:object_r:default_t"], "bin_t", "/nix/store/program"
            ),
            "system_u:object_r:bin_t",
        )

    def test_generated_context_preserves_mls_range(self) -> None:
        self.assertEqual(
            context_plan._context_with_type(
                ["system_u:object_r:default_t:s0"], "lib_t", "/nix/store/library"
            ),
            "system_u:object_r:lib_t:s0",
        )

    def test_generated_context_requires_one_authoritative_shape(self) -> None:
        with self.assertRaisesRegex(context_plan.PlanError, "conflicting context templates"):
            context_plan._context_with_type(
                [
                    "system_u:object_r:default_t",
                    "system_u:object_r:default_t:s0",
                ],
                "usr_t",
                "/nix/store/data",
            )

    def test_specific_alias_overrides_generic_context(self) -> None:
        selected = context_plan._choose_alias_context(
            "/nix/store/hash-systemd/lib/systemd/systemd",
            [
                "system_u:object_r:default_t:s0",
                "system_u:object_r:bin_t:s0",
                "system_u:object_r:init_exec_t:s0",
            ],
        )
        self.assertEqual(selected, "system_u:object_r:init_exec_t:s0")

    def test_conflicting_specific_aliases_are_rejected(self) -> None:
        with self.assertRaisesRegex(context_plan.PlanError, "conflicting specific"):
            context_plan._choose_alias_context(
                "/nix/store/hash-package/bin/program",
                [
                    "system_u:object_r:init_exec_t:s0",
                    "system_u:object_r:udev_exec_t:s0",
                ],
            )

    def test_dynamic_loader_authority_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            loader = root / "nix/store/hash-glibc/lib/ld-linux.so.2"
            loader.parent.mkdir(parents=True)
            loader.write_bytes(elf64(context_plan.ET_DYN))
            loader.chmod(0o755)

            relative = "/nix/store/hash-glibc/lib/ld-linux.so.2"
            self.assertEqual(
                context_plan.classify_store_regular(relative, loader, loader.stat().st_mode),
                "lib_t",
            )

    def test_directory_alias_propagates_specific_descendant_context(self) -> None:
        class Resolver:
            def lookup(
                self, path: str, _kind: context_plan.InodeKind
            ) -> str | None:
                if path == "/usr/lib/ld-aarch64.so.1":
                    return "system_u:object_r:ld_so_t:s0"
                if path.startswith(("/nix", "/nix.lower")):
                    return "system_u:object_r:default_t:s0"
                return "system_u:object_r:root_t:s0"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            loader = root / "nix.lower/store/hash-glibc/lib/ld-aarch64.so.1"
            loader.parent.mkdir(parents=True)
            loader.write_bytes(elf64(context_plan.ET_DYN))
            loader.chmod(0o755)
            (root / "nix").mkdir()
            (root / "usr").mkdir()
            (root / "usr/lib").symlink_to("/nix/store/hash-glibc/lib")

            labels = context_plan.plan_labels(
                context_plan.inventory_tree(root), Resolver()
            )
            by_path = {label.path: label.context for label in labels}
            self.assertEqual(
                by_path["/nix.lower/store/hash-glibc/lib/ld-aarch64.so.1"],
                "system_u:object_r:ld_so_t:s0",
            )

    def test_dotdot_is_applied_after_intermediate_symlink_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "b/c").mkdir(parents=True)
            target = root / "b/d"
            target.write_text("actual target", encoding="utf-8")
            (root / "d").write_text("lexical decoy", encoding="utf-8")
            (root / "a").symlink_to("/b/c")
            (root / "alias").symlink_to("/a/../d")

            entries = context_plan.inventory_tree(root)
            entries_by_path = {entry.path: entry for entry in entries}
            resolved = context_plan._resolve_symlink_target(
                entries_by_path["/alias"], entries_by_path
            )
            self.assertIsNotNone(resolved)
            self.assertEqual(resolved.path, "/b/d")

    def test_finite_repeated_symlink_visit_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "directory").mkdir()
            target = root / "target"
            target.write_text("target", encoding="utf-8")
            (root / "link").symlink_to("directory")
            (root / "directory/back").symlink_to("..")
            (root / "alias").symlink_to("/link/back/link/back/target")

            entries = context_plan.inventory_tree(root)
            entries_by_path = {entry.path: entry for entry in entries}
            resolved = context_plan._resolve_symlink_target(
                entries_by_path["/alias"], entries_by_path
            )
            self.assertIsNotNone(resolved)
            self.assertEqual(resolved.path, "/target")

    def test_special_store_inode_is_rejected_even_with_a_context(self) -> None:
        class Resolver:
            def lookup(
                self, _path: str, _kind: context_plan.InodeKind
            ) -> str | None:
                return "system_u:object_r:usr_t:s0"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fifo = root / "nix/store/hash-package/fifo"
            fifo.parent.mkdir(parents=True)
            os.mkfifo(fifo)
            with self.assertRaisesRegex(context_plan.PlanError, "special inode"):
                context_plan.plan_labels(
                    context_plan.inventory_tree(root), Resolver()
                )

    def test_inventory_is_independent_of_creation_order(self) -> None:
        inventories: list[list[tuple[str, str]]] = []
        for order in (("z", "a"), ("a", "z")):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for name in order:
                    Path(root, name).write_text(name, encoding="utf-8")
                inventories.append(
                    [
                        (entry.path, entry.kind.name)
                        for entry in context_plan.inventory_tree(root)
                    ]
                )
        self.assertEqual(inventories[0], inventories[1])

    def test_hardlinks_share_an_inode_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            first.write_text("same inode", encoding="utf-8")
            os.link(first, second)
            entries = {
                entry.path: entry for entry in context_plan.inventory_tree(root)
            }
            self.assertEqual(entries["/first"].inode_key, entries["/second"].inode_key)

    def test_regular_file_context_qualifier_is_double_dash(self) -> None:
        self.assertEqual(
            context_plan.InodeKind.regular.file_context_qualifier,
            "--",
        )

    def test_file_context_path_uses_byte_exact_pcre_escapes(self) -> None:
        self.assertEqual(
            context_plan._escape_file_context_path("/etc/space name\t.+/é"),
            r"/etc/space\x20name\x09\x2e\x2b/\xc3\xa9",
        )


class ComposefsPlanningTest(unittest.TestCase):
    """Covers exact dump inventory and runtime mount-prefix semantics."""

    def write_dump(self, directory: str, contents: str) -> Path:
        path = Path(directory, "input.dump")
        path.write_text(contents, encoding="ascii")
        return path

    def test_runtime_lookup_prefix_preserves_image_map_paths(self) -> None:
        class Resolver:
            def __init__(self) -> None:
                self.paths: list[str] = []

            def lookup(
                self, path: str, _kind: context_plan.InodeKind
            ) -> str | None:
                self.paths.append(path)
                contexts = {
                    "/etc": "system_u:object_r:etc_t",
                    "/etc/sample": "system_u:object_r:selinux_config_t",
                    "/etc/link": "system_u:object_r:etc_t",
                    "/etc/store-link": "system_u:object_r:etc_t",
                }
                return contexts[path]

        with tempfile.TemporaryDirectory() as temporary:
            dump = self.write_dump(
                temporary,
                "/ 4096 40755 1 0 0 0 0.0 - - -\n"
                "/link 100 120777 1 0 0 0 1.0 sample - -\n"
                "/sample 4 100644 1 0 0 0 1.0 sample - -\n"
                "/store-link 100 120777 1 0 0 0 1.0 "
                "/nix/store/hash-package/etc/config - -\n",
            )
            entries = context_plan.inventory_composefs_dump(dump)
            resolver = Resolver()
            labels = context_plan.plan_labels(
                entries,
                resolver,
                lookup_prefix="/etc",
            )

            self.assertEqual(
                resolver.paths,
                ["/etc", "/etc/link", "/etc/sample", "/etc/store-link"],
            )
            self.assertEqual(
                [label.path for label in labels],
                ["/", "/link", "/sample", "/store-link"],
            )

            base = Path(temporary, "base-file-contexts")
            output = Path(temporary, "exact-file-contexts")
            context_map = Path(temporary, "contexts.json")
            base.write_text("/base system_u:object_r:etc_t\n", encoding="utf-8")
            context_plan.write_outputs(
                base,
                labels,
                output,
                context_map,
                lookup_prefix="/etc",
            )

            exact = output.read_text(encoding="utf-8")
            self.assertIn(
                "/etc\t-d\tsystem_u:object_r:etc_t\n",
                exact,
            )
            self.assertIn(
                "/etc/sample\t--\tsystem_u:object_r:selinux_config_t\n",
                exact,
            )
            self.assertNotIn("/etc/etc", exact)

    def test_invalid_lookup_prefixes_are_rejected(self) -> None:
        for prefix in ("etc", "/etc/", "/etc//lower", "/etc/../var", "/etc/."):
            with self.subTest(prefix=prefix):
                with self.assertRaises(context_plan.PlanError):
                    context_plan.normalize_lookup_prefix(prefix)

    def test_default_lookup_prefix_preserves_image_path(self) -> None:
        self.assertEqual(context_plan.normalize_lookup_prefix("/"), "/")
        self.assertEqual(context_plan.runtime_lookup_path("/", "/"), "/")
        self.assertEqual(
            context_plan.runtime_lookup_path("/nix/store/package", "/"),
            "/nix/store/package",
        )

    def test_composefs_hardlink_identity_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dump = self.write_dump(
                temporary,
                "/ 4096 40755 2 0 0 0 0.0 - - -\n",
            )
            with self.assertRaisesRegex(context_plan.PlanError, "hard-link identity"):
                context_plan.inventory_composefs_dump(dump)

    def test_prefixed_internal_nix_subtree_is_not_store_content(self) -> None:
        class Resolver:
            def __init__(self) -> None:
                self.paths: list[str] = []

            def lookup(
                self, path: str, _kind: context_plan.InodeKind
            ) -> str | None:
                self.paths.append(path)
                return "system_u:object_r:etc_t"

        with tempfile.TemporaryDirectory() as temporary:
            dump = self.write_dump(
                temporary,
                "/ 4096 40755 1 0 0 0 0.0 - - -\n"
                "/alias 100 120777 1 0 0 0 1.0 nix/store/config - -\n"
                "/nix 4096 40755 1 0 0 0 0.0 - - -\n"
                "/nix/store 4096 40755 1 0 0 0 0.0 - - -\n"
                "/nix/store/config 4 100644 1 0 0 0 1.0 config - -\n",
            )
            resolver = Resolver()
            labels = context_plan.plan_labels(
                context_plan.inventory_composefs_dump(dump),
                resolver,
                lookup_prefix="/etc",
            )
            self.assertEqual(
                [label.path for label in labels],
                ["/", "/alias", "/nix", "/nix/store", "/nix/store/config"],
            )
            self.assertEqual(
                resolver.paths,
                [
                    "/etc",
                    "/etc/alias",
                    "/etc/nix",
                    "/etc/nix/store",
                    "/etc/nix/store/config",
                ],
            )

    def test_dynamic_loader_authority_uses_runtime_path(self) -> None:
        class Resolver:
            def lookup(
                self, path: str, _kind: context_plan.InodeKind
            ) -> str | None:
                if path == "/etc":
                    return "system_u:object_r:etc_t"
                return "system_u:object_r:lib_t"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            loader = root / "loader"
            loader.write_bytes(elf64(context_plan.ET_DYN))
            loader.chmod(0o755)

            labels = context_plan.plan_labels(
                context_plan.inventory_tree(root),
                Resolver(),
                dynamic_loaders=["/etc/loader"],
                lookup_prefix="/etc",
            )
            contexts = {label.path: label.context for label in labels}
            self.assertEqual(
                contexts["/loader"],
                "system_u:object_r:ld_so_t",
            )

    def test_prefixed_proc_path_is_not_a_pseudo_filesystem_mountpoint(self) -> None:
        class Resolver:
            def lookup(
                self, path: str, _kind: context_plan.InodeKind
            ) -> str | None:
                if path == "/etc":
                    return "system_u:object_r:etc_t"
                return None

        with tempfile.TemporaryDirectory() as temporary:
            dump = self.write_dump(
                temporary,
                "/ 4096 40755 1 0 0 0 0.0 - - -\n"
                "/proc 4096 40755 1 0 0 0 0.0 - - -\n",
            )
            with self.assertRaisesRegex(context_plan.PlanError, "no SELinux label"):
                context_plan.plan_labels(
                    context_plan.inventory_composefs_dump(dump),
                    Resolver(),
                    lookup_prefix="/etc",
                )

    def test_default_prefix_store_regular_requires_authoritative_source(self) -> None:
        class Resolver:
            def lookup(
                self, path: str, _kind: context_plan.InodeKind
            ) -> str | None:
                if path == "/":
                    return "system_u:object_r:root_t"
                return "system_u:object_r:default_t"

        with tempfile.TemporaryDirectory() as temporary:
            dump = self.write_dump(
                temporary,
                "/ 4096 40755 1 0 0 0 0.0 - - -\n"
                "/nix 4096 40755 1 0 0 0 0.0 - - -\n"
                "/nix/store 4096 40755 1 0 0 0 0.0 - - -\n"
                "/nix/store/program 4 100755 1 0 0 0 1.0 program - -\n",
            )
            with self.assertRaisesRegex(
                context_plan.PlanError, "store regular inode has no authoritative source"
            ):
                context_plan.plan_labels(
                    context_plan.inventory_composefs_dump(dump),
                    Resolver(),
                )

    def test_prefixed_absolute_symlink_resolves_inside_runtime_mount(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dump = self.write_dump(
                temporary,
                "/ 4096 40755 1 0 0 0 0.0 - - -\n"
                "/alias 100 120777 1 0 0 0 1.0 /etc/target - -\n"
                "/target 4 100644 1 0 0 0 1.0 target - -\n",
            )
            entries = context_plan.inventory_composefs_dump(dump)
            entries_by_path = {entry.path: entry for entry in entries}
            resolved = context_plan._resolve_symlink_target(
                entries_by_path["/alias"],
                entries_by_path,
                lookup_prefix="/etc",
            )
            self.assertIsNotNone(resolved)
            self.assertEqual(resolved.path, "/target")

    def test_prefixed_absolute_symlink_outside_mount_is_external(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dump = self.write_dump(
                temporary,
                "/ 4096 40755 1 0 0 0 0.0 - - -\n"
                "/alias 100 120777 1 0 0 0 1.0 /nix/store/config - -\n"
                "/nix 4096 40755 1 0 0 0 0.0 - - -\n"
                "/nix/store 4096 40755 1 0 0 0 0.0 - - -\n"
                "/nix/store/config 4 100644 1 0 0 0 1.0 config - -\n",
            )
            entries = context_plan.inventory_composefs_dump(dump)
            entries_by_path = {entry.path: entry for entry in entries}
            resolved = context_plan._resolve_symlink_target(
                entries_by_path["/alias"],
                entries_by_path,
                lookup_prefix="/etc",
            )
            self.assertIsNone(resolved)

    def test_malformed_dump_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            dump = self.write_dump(
                temporary,
                "/ 4096 40755 1 0 0 0 0.0 - - -\n"
                + r"/bad\xzz 1 100644 1 0 0 0 0.0 - - -"
                + "\n",
            )
            with self.assertRaisesRegex(context_plan.PlanError, "invalid composefs dump"):
                context_plan.inventory_composefs_dump(dump)


if __name__ == "__main__":
    unittest.main()
