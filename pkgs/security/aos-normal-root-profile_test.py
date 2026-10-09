"""Source-only producer helpers; no image/startup/MAC qualification."""

import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), Path(__file__).with_name(f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PROFILE = load("aos-normal-root-profile")


class ProducerTests(unittest.TestCase):
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

    def test_runtime_resolution_reuses_actual_existing_manifest_helpers(self):
        helpers = PROFILE.load_runtime_helpers(Path(__file__).with_name("aos-selinux-runtime-manifest.py"))
        self.assertTrue(callable(helpers.graph_paths))
        self.assertTrue(callable(helpers.validate_elf_closure))
        self.assertTrue(callable(helpers.resolve_needed_dso))
        # No alternate serializer or wrapper validator is introduced.
        root = "00000000000000000000000000000000-image"
        self.assertEqual(helpers.physical_lower_path(f"/nix/store/{root}/bin/root"), f"/nix.lower/store/{root}/bin/root")


if __name__ == "__main__":
    unittest.main()
