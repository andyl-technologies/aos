"""Checks the static guest's installed instruction-ABI metadata contract."""

import importlib.util
from pathlib import Path
import unittest


path = Path(__file__).resolve().parents[1] / "metadata/guest_build_info.py"
specification = importlib.util.spec_from_file_location("guest_build_info", path)
metadata = importlib.util.module_from_spec(specification)
specification.loader.exec_module(metadata)

SOURCE = """pub const WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION: u16 = 4;
pub const WHITEBOX_DOORBELL_ABIS: &[WhiteboxDoorbellAbi] =
    &[WHITEBOX_DOORBELL_X86_64_ABI, WHITEBOX_DOORBELL_AARCH64_ABI];
"""


class GuestBuildInfoTests(unittest.TestCase):
    def test_supported_targets_preserve_shared_abi_identity(self):
        for system in ["x86_64-linux", "aarch64-linux"]:
            with self.subTest(system=system):
                result = metadata.build_info(SOURCE, system)
                self.assertIn("packaged_guest_system=" + system + "\n", result)
                self.assertIn("doorbell_instruction_abi_version=4\n", result)
                self.assertIn("instruction_abi_architectures=x86_64,aarch64\n", result)
                self.assertIn("build_system=Bazel\n", result)

    def test_unknown_target_and_ambiguous_abi_version_fail(self):
        for source, system in [(SOURCE, "unknown-linux"), (SOURCE + SOURCE, "x86_64-linux"),
                               (SOURCE.replace("u16 = 4", "u16 = 65536"), "x86_64-linux")]:
            with self.subTest(source=source, system=system):
                with self.assertRaisesRegex(ValueError, "supported target and one u16 ABI version"):
                    metadata.build_info(source, system)

    def test_changed_canonical_architectures_require_an_explicit_update(self):
        with self.assertRaisesRegex(ValueError, "canonical guest instruction architectures changed"):
            metadata.build_info(SOURCE.replace("WHITEBOX_DOORBELL_AARCH64_ABI", "UNKNOWN_ABI"), "x86_64-linux")


if __name__ == "__main__":
    unittest.main()
