"""Source-only producer helpers; no image/startup/MAC qualification."""

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), Path(__file__).with_name(f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROFILE = load("aos-normal-root-profile")


class ProducerTests(unittest.TestCase):
    def test_cache_gid_is_explicit_and_can_differ_from_uid_and_socket_gid(self):
        PROFILE.require_configured_identities([811, 812, 813, 814], 947)
        PROFILE.require_configured_identities([811, 812, 0, 814], 0)

        for identities, gid in (
            ([811, 812, 813, 814], 0), ([811, 812, 0, 814], 947),
            ([811, 812, 813, 814], True), ([811, 812, 813, 814], -1),
            ([811, 812, 813, 814], 1 << 32), ([811, 812, 813, 814], "947"),
        ):
            with self.subTest(identities=identities, gid=gid):
                with self.assertRaises(ValueError):
                    PROFILE.require_configured_identities(identities, gid)

    def test_context_is_exact_non_mls_root_subject(self):
        self.assertEqual(PROFILE.CONTEXT, "system_u:system_r:aos_sandbox_policy_authority_t")
        self.assertEqual(len(PROFILE.CONTEXT.split(":")), 3)

    def test_exact_self_reference_only(self):
        path = "/nix/store/fixture/profile.json"
        original = f"OpenFile={path}:aos-normal-root-profile:read-only\n".encode()
        unit = b"[Service]\nExecStart=original\n" + original + b"NoNewPrivileges=true\n"
        normalized = PROFILE.normalize_unit(unit, path)
        self.assertEqual(normalized, unit.replace(original, f"OpenFile={PROFILE.PROFILE_PLACEHOLDER}:aos-normal-root-profile:read-only\n".encode()))
        for mutant in (unit.replace(b"original", b"substitute"), unit + b"Environment=LD_PRELOAD=/tmp/foreign.so\n"):
            self.assertNotEqual(hashlib.sha256(normalized).digest(), hashlib.sha256(PROFILE.normalize_unit(mutant, path)).digest())

    def test_missing_duplicate_commented_or_writable_profile_rejected(self):
        path = "/nix/store/fixture/profile.json"
        original = f"OpenFile={path}:aos-normal-root-profile:read-only\n".encode()
        for bad in (b"[Service]\n", original * 2, b"# " + original, original.replace(b"read-only", b"graceful")):
            with self.assertRaises(ValueError):
                PROFILE.normalize_unit(bad, path)

    def test_file_pin_uses_actual_bytes_and_canonical_name(self):
        with tempfile.TemporaryDirectory(prefix="aos-normal-root-profile-") as directory:
            path = Path(directory) / "image"
            path.write_bytes(b"actual artifact bytes")
            pinned = PROFILE.pin(path)
            self.assertEqual(pinned["path"], str(path.resolve(strict=True)))
            self.assertEqual(bytes(pinned["sha256"]), hashlib.sha256(path.read_bytes()).digest())
            path.write_bytes(b"substituted artifact bytes")
            self.assertNotEqual(pinned, PROFILE.pin(path))

    def test_environment_binding_is_versioned_exact_and_read_only(self):
        root = Path("/nix/store/" + "1" * 32 + "-aos-environment-provision-1")
        binding = f"ReadOnlyPaths={root}\n".encode()
        PROFILE.require_environment_provision_binding(root, binding)

        for bad in (b"", binding * 2, b"# " + binding,
                    binding.replace(b"ReadOnlyPaths", b"ReadWritePaths")):
            with self.subTest(unit=bad), self.assertRaises(ValueError):
                PROFILE.require_environment_provision_binding(root, bad)

        for path in (root / "objects", Path(str(root) + "-alias"),
                     Path(str(root).replace("provision-1", "provision-2")),
                     Path(str(root).replace("/nix/store/", "/usr/lib/aos/nix/store/"))):
            with self.subTest(path=path), self.assertRaises(ValueError):
                PROFILE.require_environment_provision_binding(path, f"ReadOnlyPaths={path}\n".encode())

    def test_runtime_resolution_reuses_actual_existing_manifest_helpers(self):
        helpers = PROFILE.load_runtime_helpers(Path(__file__).with_name("aos-selinux-runtime-manifest.py"))
        self.assertTrue(callable(helpers.graph_paths))
        self.assertTrue(callable(helpers.validate_elf_closure))
        self.assertTrue(callable(helpers.resolve_needed_dso))
        # No alternate serializer or wrapper validator is introduced.
        root = "00000000000000000000000000000000-image"
        self.assertEqual(helpers.physical_lower_path(f"/nix/store/{root}/bin/root"), f"/usr/lib/aos/nix/store/{root}/bin/root")

    def test_runpath_graph_reuses_mapped_libraries_and_the_exact_selected_interpreter(self):
        helpers = PROFILE.load_runtime_helpers(Path(__file__).with_name("aos-selinux-runtime-manifest.py"))
        with tempfile.TemporaryDirectory(prefix="aos-runtime-loader-") as directory:
            root = Path(directory)
            executable = root / "bin/program"
            libc = root / "lib/libc.so.6"
            libm = root / "lib/libm.so.6"
            loader = root / "lib/ld-linux.so.2"
            foreign = root / "lib/libforeign.so.1"
            restricted_search = root / "restricted"
            restricted_search.mkdir()
            for path in (executable, libc, libm, loader, foreign):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"\x7fELF" + path.name.encode())

            inventory = {"libc.so.6": libc, "libm.so.6": libm, "ld-linux.so.2": loader}
            needed = {
                executable: ["libm.so.6", "libc.so.6"],
                libc: ["ld-linux.so.2"],
                libm: ["libc.so.6"],
            }
            search_tags = {executable: (False, True)}
            search_paths = {executable: str(libc.parent)}

            def patchelf_output(_tool, option, elf):
                if option == "--print-needed":
                    return needed[elf]
                if option == "--print-rpath":
                    return [search_paths[elf]] if elf in search_paths else []
                if option == "--print-soname" and elf == loader:
                    return ["ld-linux.so.2"]
                if option == "--print-soname":
                    return [elf.name]
                raise AssertionError((option, elf))

            with (
                mock.patch.object(helpers, "validate_dlopen_inventory", return_value=inventory),
                mock.patch.object(helpers, "validate_elf_closure", return_value=str(loader)),
                mock.patch.object(helpers, "run_patchelf", side_effect=patchelf_output),
                mock.patch.object(helpers, "dynamic_search_tags", side_effect=lambda _tool, elf: search_tags.get(elf, (False, False))),
                mock.patch.object(helpers, "validate_search_directories", side_effect=lambda entries, *_: list(map(Path, entries))),
                mock.patch.object(helpers, "closure_owner", return_value=str(root)),
            ):
                selected_loader, files = PROFILE.runtime_files(helpers, [root], executable, Path("patchelf"), Path("readelf"))
                self.assertEqual(selected_loader, loader)
                self.assertEqual({entry["path"] for entry in files}, set(map(str, (executable, libc, libm, loader))))

                inventory["ld-linux.so.2"] = foreign
                with self.assertRaisesRegex(ValueError, "interpreter differs"):
                    PROFILE.runtime_files(helpers, [root], executable, Path("patchelf"), Path("readelf"))

                inventory["ld-linux.so.2"] = loader
                inventory["libforeign.so.1"] = foreign
                needed[libc].append("libforeign.so.1")
                with self.assertRaises(SystemExit):
                    PROFILE.runtime_files(helpers, [root], executable, Path("patchelf"), Path("readelf"))

                # A child's RUNPATH suppresses the ancestor's RPATH for its
                # own fresh lookup, even when the ancestor contains the DSO.
                search_tags[executable] = (True, False)
                search_tags[libc] = (False, True)
                search_paths[libc] = str(restricted_search)
                with self.assertRaises(SystemExit):
                    PROFILE.runtime_files(helpers, [root], executable, Path("patchelf"), Path("readelf"))


if __name__ == "__main__":
    unittest.main()
