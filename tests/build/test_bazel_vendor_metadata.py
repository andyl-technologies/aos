"""Check Bazel Maven metadata generation from the pinned artifact inventory."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "pkgs/toolchain/generate-bazel-vendor.py"
SPEC = importlib.util.spec_from_file_location("generate_bazel_vendor", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
generator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generator)


class BazelVendorMetadataTests(unittest.TestCase):
    """Exercise complete and explicitly incomplete Maven lock generation."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.maven = self.root / "maven"
        self.lock = self.root / "maven_install.json"
        self.lock.write_text(
            json.dumps(
                {
                    "artifacts": {
                        "example.group:first": {
                            "version": "1.2.0",
                            "shasums": {"jar": "pinned-source-hash"},
                        },
                        "example.group:second": {
                            "version": "2.0",
                            "shasums": {"jar": "pinned-source-hash"},
                        },
                        "example.group:native": {
                            "version": "3.0",
                            "shasums": {"linux-x86_64": "pinned-source-hash"},
                        },
                    },
                    "dependencies": {"example.group:first": ["example.group:second"]},
                }
            )
        )

    def add_jar(self, coordinate, version, classifier=None):
        path = self.maven / generator.jar_path(coordinate, version, classifier)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"source-built fixture")

    def test_complete_lock_emits_imports_dependencies_and_classifier(self):
        self.add_jar("example.group:first", "1.2.0")
        self.add_jar("example.group:second", "2.0")
        self.add_jar("example.group:native", "3.0", "linux-x86_64")

        output = generator.generate(self.lock, self.maven, partial=False)

        self.assertNotIn("NOT FOR RELEASE", output)
        self.assertIn('name = "example_group_first"', output)
        self.assertIn('deps = [":example_group_second"]', output)
        self.assertIn('name = "example_group_native_linux_x86_64_file"', output)
        self.assertIn('name = "example_group_first_1_2_0"', output)
        self.assertIn('name = "srcs"', output)

    def test_missing_classifier_fails_closed(self):
        self.add_jar("example.group:first", "1.2.0")
        self.add_jar("example.group:second", "2.0")

        with self.assertRaisesRegex(ValueError, "example.group:native:linux-x86_64"):
            generator.generate(self.lock, self.maven, partial=False)

        output = generator.generate(self.lock, self.maven, partial=True)
        self.assertIn("NOT FOR RELEASE: 1 locked JAR is absent", output)
        self.assertNotIn('name = "example_group_native_linux_x86_64"', output)


if __name__ == "__main__":
    unittest.main()
