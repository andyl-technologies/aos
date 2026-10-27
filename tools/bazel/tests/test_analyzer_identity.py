"""Preserves distinct compiler units and their dependency identities for editors."""

import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest


path = Path(__file__).resolve().parents[1] / "metadata/patch_analyzer_identity.py"
specification = importlib.util.spec_from_file_location("patch_analyzer_identity", path)
patcher = importlib.util.module_from_spec(specification)
specification.loader.exec_module(patcher)


class AnalyzerIdentityTests(unittest.TestCase):
    def setUp(self):
        self.source = 'def _crate_id(crate_info):\n    return "ID-" + crate_info.root.path\n'
        namespace = {}
        exec(patcher.patch(self.source), namespace)
        self.identity = namespace["_crate_id"]

    def crate(self, root, output):
        return SimpleNamespace(root=SimpleNamespace(path=root), output=SimpleNamespace(path=output))

    def test_external_target_and_execution_units_remain_distinct(self):
        root = "external/serde/src/lib.rs"
        target = self.crate(root, "bazel-out/target/libserde.rlib")
        execution = self.crate(root, "bazel-out/exec/libserde.rlib")

        self.assertNotEqual(self.identity(target), self.identity(execution))
        self.assertIn(root, self.identity(target))

    def test_dependency_aliases_retain_the_compiled_unit_identity(self):
        unit = self.crate("external/serde/src/lib.rs", "bazel-out/target/libserde.rlib")
        alias = self.crate(unit.root.path, unit.output.path)

        self.assertEqual(self.identity(unit), self.identity(alias))

    def test_first_party_library_and_libtest_still_share_an_identity(self):
        root = "crates/example/src/lib.rs"
        library = self.crate(root, "bazel-out/target/libexample.rlib")
        test = self.crate(root, "bazel-out/target/unit_binary")

        self.assertEqual(self.identity(library), self.identity(test))

    def test_unreviewed_upstream_changes_fail_closed(self):
        for source in [self.source.replace('"ID-"', '"crate-"'), self.source + self.source]:
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, "no longer applies"):
                patcher.patch(source)
