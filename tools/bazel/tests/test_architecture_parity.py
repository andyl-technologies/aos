"""Checks the temporary Cargo oracle's all-target production dependency union."""

import copy
from pathlib import Path
import tempfile
import unittest

from verify_architecture import production_dependencies, verify


class ArchitectureParityTests(unittest.TestCase):
    def test_normal_optional_build_and_all_target_dependencies_exclude_dev(self):
        manifest = {"dependencies": {"alias": {"workspace": True}, "optional": {"optional": True}},
                    "build-dependencies": {"generator": "1"}, "dev-dependencies": {"dev": "1"},
                    "target": {"cfg(target_os = 'other')": {"dependencies": {"target": "1"},
                               "build-dependencies": {"target-build": "1"}, "dev-dependencies": {"target-dev": "1"}}}}
        self.assertEqual(production_dependencies(manifest, {"alias": {"package": "original"}}),
                         {"original", "optional", "generator", "target", "target-build"})

    def test_unresolved_workspace_dependency_fails_closed(self):
        with self.assertRaises(KeyError):
            production_dependencies({"dependencies": {"missing": {"workspace": True}}}, {})

    def test_parity_rejects_missing_identity_edges_and_fake_independence(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "app").mkdir()
            (directory / "Cargo.toml").write_text('[workspace]\nmembers = ["app"]\n[workspace.dependencies]\n')
            (directory / "app/Cargo.toml").write_text(
                '[package]\nname = "app"\nversion = "1"\nedition = "2024"\nlicense = "MIT"\n[dependencies]\nupstream = "1"\n')
            graph = {"schema_version": 1, "packages": [{"name": "app", "version": "1", "edition": "2024", "license": "MIT",
                     "directory": "crates/app", "production_dependencies": ["upstream"], "production_targets": ["//crates/app:lib"]}]}
            self.assertEqual(verify(graph, directory)["modeled_packages"], 1)

            for changes in [{"license": "other"}, {"production_dependencies": []}, {"production_targets": []},
                            {"production_dependencies": None}, {"production_dependencies": ["upstream", "upstream"]}]:
                modified = copy.deepcopy(graph)
                modified["packages"][0].update(changes)
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    verify(modified, directory)

            unmodeled = copy.deepcopy(graph)
            unmodeled["packages"][0].update(production_dependencies=None, production_targets=[])
            # A catalogue alone cannot qualify a production graph.
            with self.assertRaisesRegex(ValueError, "requires modeled"):
                verify(unmodeled, directory)

    def test_standalone_workspaces_retain_ownership_and_dependency_checks(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            workspace = directory / "standalone"
            (workspace / "tool").mkdir(parents=True)
            (directory / "Cargo.toml").write_text('[workspace]\nmembers = []\n')
            (workspace / "Cargo.toml").write_text('[workspace]\nmembers = ["tool"]\n')
            (workspace / "tool/Cargo.toml").write_text(
                '[package]\nname = "tool"\nversion = "1"\nedition = "2024"\nlicense = "MIT"\n'
                '[dependencies]\nupstream = "1"\n')
            graph = {"schema_version": 1, "packages": [{
                "name": "tool", "version": "1", "edition": "2024", "license": "MIT",
                "directory": "crates/standalone/tool", "production_dependencies": ["upstream"],
                "production_targets": ["//crates/standalone/tool:lib"],
            }]}

            self.assertEqual(verify(graph, directory, [workspace])["modeled_packages"], 1)
            with self.assertRaisesRegex(ValueError, "inventories differ"):
                verify(graph, directory)
            with self.assertRaisesRegex(ValueError, "duplicate Cargo"):
                verify(graph, directory, [workspace, workspace])

            graph["packages"][0]["production_dependencies"] = []
            with self.assertRaisesRegex(ValueError, "dependencies differ"):
                verify(graph, directory, [workspace])

            with self.assertRaisesRegex(ValueError, "outside"):
                verify(graph, directory, [directory.parent])


if __name__ == "__main__":
    unittest.main()
