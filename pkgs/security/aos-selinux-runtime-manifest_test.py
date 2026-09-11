"""Source-level tests for the immutable runtime-closure manifest builder."""

from pathlib import Path
import importlib.util
import tempfile
import unittest
from unittest import mock

module_path = Path(__file__).with_name("aos-selinux-runtime-manifest.py")
module_spec = importlib.util.spec_from_file_location("aos_runtime_manifest", module_path)
assert module_spec is not None and module_spec.loader is not None
manifest = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(manifest)


class ClosureOwnerTests(unittest.TestCase):
    def test_accepts_member_beneath_exact_store_root(self) -> None:
        closure = {"/nix/store/0123456789abcdfghijklmnpqrsvwxyz-systemd"}
        member = next(iter(closure)) + "/lib/systemd/systemd"

        self.assertEqual(manifest.closure_owner(member, closure), next(iter(closure)))

    def test_rejects_prefix_collision_and_non_store_path(self) -> None:
        root = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-systemd"
        closure = {root}

        self.assertIsNone(manifest.closure_owner(root + "-shadow/lib/libc.so", closure))
        self.assertIsNone(manifest.closure_owner("/usr/lib/libc.so", closure))


class SymlinkTests(unittest.TestCase):
    def test_rejects_absolute_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store_root = Path(directory) / "0123456789abcdfghijklmnpqrsvwxyz-fixture"
            store_root.mkdir()
            (store_root / "escape").symlink_to("/etc/passwd")

            with self.assertRaises(SystemExit):
                manifest.validate_symlinks([store_root])


class StructuredGraphTests(unittest.TestCase):
    def test_store_path_grammar_rejects_controls_and_ambiguous_hash_alphabet(self) -> None:
        valid = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-fixture+1.0"

        self.assertIsNotNone(manifest.STORE_PATH.fullmatch(valid))
        self.assertIsNone(manifest.STORE_PATH.fullmatch(valid + "\nshadow"))
        self.assertIsNone(
            manifest.STORE_PATH.fullmatch(
                "/nix/store/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-fixture"
            )
        )

    def test_rejects_duplicate_entries_before_canonical_sort(self) -> None:
        store_path = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-fixture"
        entry = {"path": store_path, "references": [], "narHash": "sha256-x", "narSize": 1}
        with tempfile.TemporaryDirectory() as directory:
            attributes = Path(directory) / "attrs.json"
            attributes.write_text(__import__("json").dumps({"runtime": [entry, entry]}))

            with self.assertRaises(SystemExit):
                manifest.graph_paths(attributes, "runtime")


class DlopenInventoryTests(unittest.TestCase):
    def test_rejects_missing_reviewed_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store_root = Path(directory) / "0123456789abcdfghijklmnpqrsvwxyz-fixture"
            store_root.mkdir()

            with mock.patch.object(manifest, "run_patchelf", return_value=None):
                with self.assertRaises(SystemExit):
                    manifest.validate_dlopen_inventory(
                        [store_root], Path("/patchelf"), ["libmissing.so.1"]
                    )

    def test_elf_string_candidates_separate_soname_and_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / "synthetic.elf"
            elf.write_bytes(
                b"\x7fELF\0libaudit.so.1\0"
                b"/nix/store/0123456789abcdfghijklmnpqrsvwxyz-systemd/lib/"
                b"libnss_systemd.so.2\0/usr/lib/libshadow.so.1\0"
                b"not-a-soname.so suffix\0"
            )

            bare, absolute = manifest.elf_string_candidates(elf)

        self.assertEqual(bare, {"libaudit.so.1"})
        self.assertEqual(
            absolute,
            {
                "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-systemd/lib/"
                "libnss_systemd.so.2",
                "/usr/lib/libshadow.so.1",
            },
        )

    def test_rejects_absolute_dso_outside_store(self) -> None:
        with self.assertRaises(SystemExit):
            manifest.validate_absolute_dlopen_paths(
                {"/usr/lib/libshadow.so.1"},
                {"/nix/store/0123456789abcdfghijklmnpqrsvwxyz-systemd"},
            )

    def test_absolute_dso_path_must_be_bytewise_canonical(self) -> None:
        store_root = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-systemd"
        canonical = Path(store_root) / "lib/libaudit.so.1"
        aliases = {
            store_root + "//lib/libaudit.so.1",
            store_root + "/lib/../lib/libaudit.so.1",
        }

        with (
            mock.patch.object(Path, "resolve", return_value=canonical),
            mock.patch.object(Path, "is_file", return_value=True),
        ):
            manifest.validate_absolute_dlopen_paths({str(canonical)}, {store_root})

            for alias in aliases:
                with self.subTest(alias=alias), self.assertRaises(SystemExit):
                    manifest.validate_absolute_dlopen_paths({alias}, {store_root})

    def test_needed_graph_audits_external_dso_selectors_per_caller(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            systemd_root = root / "systemd-output"
            dependency_root = root / "dependency-output"
            systemd = systemd_root / "lib/systemd/systemd"
            external = dependency_root / "lib/libexternal.so.1"
            anchor = dependency_root / "lib/libanchor.so.1"
            leaf = dependency_root / "lib/libleaf.so.1"
            for elf in (systemd, external, anchor, leaf):
                elf.parent.mkdir(parents=True, exist_ok=True)
                elf.write_bytes(b"\x7fELF")

            needed = {
                systemd: ["libexternal.so.1", "libanchor.so.1"],
                external: ["libleaf.so.1"],
                anchor: [],
                leaf: [],
            }
            sonames = {
                systemd: [],
                external: ["libexternal.so.1"],
                anchor: ["libanchor.so.1"],
                leaf: ["libleaf.so.1"],
            }

            def patchelf_output(_tool: Path, option: str, elf: Path) -> list[str]:
                if option == "--print-needed":
                    return needed[elf]
                if option == "--print-rpath":
                    return [str(dependency_root / "lib")] if elf == systemd else []
                if option == "--print-soname":
                    return sonames[elf]
                raise AssertionError(f"unexpected patchelf option: {option}")

            def strings(elf: Path) -> tuple[set[str], set[str]]:
                # libanchor is linked by systemd but is an optional-load string
                # in a different closure DSO, so classification must be local.
                if elf == external:
                    return {"libanchor.so.1", "libtss2-tcti-default.so"}, set()
                return set(), set()

            with (
                mock.patch.object(manifest, "run_patchelf", side_effect=patchelf_output),
                mock.patch.object(
                    manifest,
                    "validate_search_directories",
                    return_value=[dependency_root / "lib"],
                ),
                mock.patch.object(
                    manifest, "elf_string_candidates", side_effect=strings
                ) as selector_scan,
                mock.patch.object(
                    manifest,
                    "dynamic_search_tags",
                    side_effect=lambda _readelf, elf: (elf == systemd, False),
                ),
                mock.patch.object(
                    manifest, "closure_owner", return_value=str(dependency_root)
                ),
                mock.patch.object(
                    manifest, "require_search_resolution"
                ) as require_resolution,
            ):
                inventory = {
                    "libanchor.so.1": anchor,
                    "libexternal.so.1": external,
                    "libleaf.so.1": leaf,
                }
                manifest.validate_compiled_dlopen_contract(
                    [systemd_root, dependency_root],
                    systemd,
                    Path("/patchelf"),
                    Path("/readelf"),
                    ["libanchor.so.1"],
                    ["libtss2-tcti-default.so"],
                    [],
                    [],
                    inventory,
                )

            scanned = {call.args[0] for call in selector_scan.call_args_list}
            self.assertEqual(scanned, {systemd, external, anchor, leaf})
            require_resolution.assert_called_once_with(
                external,
                "libanchor.so.1",
                [dependency_root / "lib"],
                inventory,
            )

    def test_needed_resolution_checks_canonical_symlink_target_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            search = root / "search"
            real = root / "owner/lib/libexternal.so.1"
            alias = search / "libexternal.so.1"
            search.mkdir()
            real.parent.mkdir(parents=True)
            real.write_bytes(b"\x7fELF")
            alias.symlink_to(real)

            inspected: list[str] = []

            def owner(path: str, _closure: set[str]) -> str:
                inspected.append(path)
                return str(real.parents[1])

            with mock.patch.object(manifest, "closure_owner", side_effect=owner):
                resolved = manifest.resolve_needed_dso(
                    root / "caller",
                    "libexternal.so.1",
                    [search],
                    {str(real.parents[1])},
                    {"libexternal.so.1": real},
                )

            self.assertEqual(resolved, real)
            self.assertEqual(inspected, [str(real)])

            wrong = root / "owner/lib/libwrong.so.1"
            wrong.write_bytes(b"\x7fELF")
            with (
                mock.patch.object(manifest, "closure_owner", return_value=str(real.parents[1])),
                self.assertRaises(SystemExit),
            ):
                manifest.resolve_needed_dso(
                    root / "caller",
                    "libexternal.so.1",
                    [search],
                    {str(real.parents[1])},
                    {"libexternal.so.1": wrong},
                )

    def test_rejects_arbitrary_real_rpath_outside_closure(self) -> None:
        inside = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-systemd"
        outside = "/nix/store/11111111111111111111111111111111-unreviewed/lib"

        with mock.patch.object(
            manifest, "canonical_search_directory", return_value=Path(outside)
        ):
            with self.assertRaises(SystemExit):
                manifest.validate_search_directories(
                    [outside], Path(inside) / "lib/systemd/systemd", {inside}
                )

    def test_rejects_rpath_traversal_and_compound_origin_token(self) -> None:
        elf = Path("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-systemd/bin/systemd")

        for directory in (
            "$ORIGIN/../../../../tmp",
            "$ORIGIN-shadow/lib",
            "$ORIGIN/${PLATFORM}",
            "$ORIGIN//lib",
        ):
            with self.subTest(directory=directory), self.assertRaises(SystemExit):
                manifest.canonical_search_directory(directory, elf)

    def test_rejects_absent_and_symlinked_rpath_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            alias = root / "alias"
            real.mkdir()
            alias.symlink_to(real, target_is_directory=True)
            elf = root / "systemd"

            for search in (root / "absent", alias):
                with self.subTest(search=search), self.assertRaises(SystemExit):
                    manifest.canonical_search_directory(str(search), elf)

    def test_closure_scan_leaves_dependency_resolution_to_fixed_point(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            systemd = root / "systemd"
            unreachable = root / "unreachable.so"
            systemd.write_bytes(b"\x7fELF")
            unreachable.write_bytes(b"\x7fELF")
            interpreter = Path(
                "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-glibc/lib/ld.so"
            )
            original_is_file = Path.is_file
            original_resolve = Path.resolve

            def is_file(path: Path) -> bool:
                return path == interpreter or original_is_file(path)

            def resolve(path: Path, strict: bool = False) -> Path:
                if path == interpreter:
                    return interpreter
                return original_resolve(path, strict=strict)

            def patchelf_output(_tool: Path, option: str, elf: Path) -> list[str]:
                if option == "--print-interpreter":
                    self.assertEqual(elf, systemd)
                    return [str(interpreter)]
                if option == "--print-needed":
                    return ["libmissing.so.1"]
                if option == "--print-rpath":
                    return []
                self.fail(f"closure-wide scan unexpectedly requested {option}")

            with (
                mock.patch.object(manifest, "run_patchelf", side_effect=patchelf_output),
                mock.patch.object(manifest, "closure_owner", return_value=str(root)),
                mock.patch.object(Path, "is_file", autospec=True, side_effect=is_file),
                mock.patch.object(Path, "resolve", autospec=True, side_effect=resolve),
            ):
                resolved = manifest.validate_elf_closure(
                    [root], systemd, Path("/tools/patchelf")
                )

        self.assertEqual(resolved, str(interpreter))


class ManifestEncodingTests(unittest.TestCase):
    def test_manifest_and_header_use_exact_physical_lower_store_paths(self) -> None:
        systemd_root = Path(
            "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-systemd"
        )
        glibc_root = Path("/nix/store/11111111111111111111111111111111-glibc")
        systemd = systemd_root / "lib/systemd/systemd"
        interpreter = str(glibc_root / "lib/ld-linux.so.2")

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "manifest.bin"
            header = Path(directory) / "manifest.h"
            policy_digest = "a" * 64
            digest = manifest.write_manifest(
                output,
                systemd,
                interpreter,
                systemd,
                policy_digest,
                [systemd_root, glibc_root],
            )
            manifest.write_header(
                header, systemd, interpreter, systemd, policy_digest, 2, digest
            )

            fields = output.read_bytes().split(b"\0")
            header_text = header.read_text(encoding="ascii")

        physical_systemd = b"/nix.lower/store/" + systemd_root.name.encode() + b"/lib/systemd/systemd"
        physical_interpreter = (
            b"/nix.lower/store/" + glibc_root.name.encode() + b"/lib/ld-linux.so.2"
        )
        self.assertEqual(
            fields[2:7],
            [
                physical_systemd,
                physical_interpreter,
                physical_systemd,
                policy_digest.encode(),
                b"2",
            ],
        )
        self.assertIn(
            f'#define AOS_PHYSICAL_SYSTEMD_PATH "{physical_systemd.decode()}"',
            header_text,
        )
        self.assertIn(
            f'#define AOS_PHYSICAL_INTERPRETER_PATH "{physical_interpreter.decode()}"',
            header_text,
        )
        self.assertIn(
            f'#define AOS_RUNTIME_ROOTS_PATH "{systemd}"',
            header_text,
        )
        self.assertIn(
            f'#define AOS_PHYSICAL_RUNTIME_ROOTS_PATH "{physical_systemd.decode()}"',
            header_text,
        )
        self.assertIn(
            f'#define AOS_EXPECTED_POLICY_SHA256 "{policy_digest}"', header_text
        )
        self.assertNotIn("/nix.lower/nix/store/", header_text)

        lower_store = Path("/nix.lower/store")
        self.assertEqual(
            manifest.physical_lower_path(systemd_root),
            str(lower_store / systemd_root.name),
        )
        self.assertTrue(
            Path(physical_systemd.decode()).is_relative_to(lower_store / systemd_root.name)
        )

        for invalid in (
            "/usr/lib/systemd/systemd",
            str(systemd_root) + "//lib/systemd/systemd",
            str(systemd_root) + "/lib/../lib/systemd/systemd",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(SystemExit):
                manifest.physical_lower_path(invalid)

    def test_v1_validator_rejects_v2_mixed_layout_and_tamper(self) -> None:
        policy_digest = "b" * 64
        roots = [b"0123456789abcdfghijklmnpqrsvwxyz-root"]

        def encode(fields: list[bytes]) -> bytes:
            payload = b"\0".join(fields) + b"\0"
            return payload + __import__("hashlib").sha256(payload).hexdigest().encode() + b"\0"

        valid_fields = [
            manifest.MAGIC,
            manifest.VERSION,
            b"/nix.lower/store/systemd/lib/systemd/systemd",
            b"/nix.lower/store/glibc/lib/ld.so",
            b"/nix.lower/store/helper/bin/helper",
            policy_digest.encode(),
            b"1",
            *roots,
        ]
        manifest.validate_manifest_v1(encode(valid_fields), policy_digest)

        future_v2 = valid_fields.copy()
        future_v2[1] = b"2"
        mixed = valid_fields.copy()
        del mixed[5]
        tampered = bytearray(encode(valid_fields))
        tampered[-2] ^= 1
        invalid_encodings = {
            "future-v2": encode(future_v2),
            "mixed-layout": encode(mixed),
            "tampered-digest": bytes(tampered),
        }
        for case, encoded in invalid_encodings.items():
            with self.subTest(case=case), self.assertRaises(SystemExit):
                manifest.validate_manifest_v1(encoded, policy_digest)

    def test_stage0_requires_v1_and_policy_identity_before_root_count(self) -> None:
        source = module_path.with_name("aos-selinux-stage0.c").read_text(
            encoding="utf-8"
        )
        pin_start = source.index("static void pin_runtime_closure(")
        pin_end = source.index("\n}\n", pin_start)
        pin = source[pin_start:pin_end]

        self.assertIn('#define AOS_MANIFEST_VERSION "1"', source)
        version = pin.index("AOS_MANIFEST_VERSION")
        policy = pin.index("AOS_EXPECTED_POLICY_SHA256")
        count = pin.index("count = strtoul")
        self.assertLess(version, policy)
        self.assertLess(policy, count)

    def test_runtime_roots_launcher_custodies_physical_fd_in_private_namespace(self) -> None:
        source = module_path.with_name("aos-selinux-stage0.c").read_text(
            encoding="utf-8"
        )
        launcher_start = source.index("static void run_runtime_roots_launcher(")
        launcher_end = source.index("\n}\n", launcher_start)
        launcher = source[launcher_start:launcher_end]

        isolate = launcher.index("isolate_root_handoff_mount_namespace();")
        verify = launcher.index("require_filesystem(root_prefix")
        open_fd = launcher.index("open_verified_physical_store_target(")
        execute_fd = launcher.index("execveat(provisioner_fd")
        self.assertLess(isolate, verify)
        self.assertLess(verify, open_fd)
        self.assertLess(open_fd, execute_fd)
        self.assertIn("AT_EMPTY_PATH", launcher)


class StaticExecutableTests(unittest.TestCase):
    def test_rejects_interpreter_or_needed_entry(self) -> None:
        root = Path("/nix/store/0123456789abcdfghijklmnpqrsvwxyz-helper")
        executable = root / "bin/helper"

        def completed(output: str, returncode: int = 0) -> mock.Mock:
            return mock.Mock(returncode=returncode, stdout=output, stderr="")

        for invocation, output in ((1, " INTERP "), (2, " (NEEDED) ")):
            responses = [
                completed("Type: EXEC"),
                completed(output if invocation == 1 else ""),
                completed(output if invocation == 2 else ""),
            ]
            with (
                self.subTest(output=output),
                mock.patch.object(Path, "resolve", return_value=executable),
                mock.patch.object(Path, "is_file", return_value=True),
                mock.patch.object(manifest.subprocess, "run", side_effect=responses),
                self.assertRaises(SystemExit),
            ):
                manifest.validate_static_executable(
                    executable,
                    [root],
                    Path("/readelf"),
                )


if __name__ == "__main__":
    unittest.main()
