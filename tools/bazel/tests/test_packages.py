"""Checks the package trust boundary with malformed and stale build outputs."""

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


def load_metadata(name):
    path = Path(__file__).resolve().parents[1] / "metadata" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


exporter = load_metadata("export_packages")
installer = load_metadata("install_package")


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.manifest = self.root / "fixture.aos-package.json"
        source = self.root / "fixture.files/bin/app"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"current executable")
        self.metadata = {
            "schema_version": 1, "label": "//example:package", "name": "example",
            "version": "1", "license": "Apache-2.0", "license_domain": "apache-host",
            "artifacts": [{
                "source": "fixture.files/bin/app", "destination": "bin/app", "mode": "0755",
            }],
        }
        self.build = self.root / "build"

    def export(self):
        self.manifest.write_text(json.dumps(self.metadata))
        label, identifier = exporter.export_manifest(self.manifest, self.build / "packages")
        (self.build / "packages/index.json").write_text(json.dumps({label: identifier}))
        return self.build / "packages" / identifier

    def install(self):
        installer.install(self.build, "//example:package", "example", "1", self.root / "installed")

    def test_install_only_current_declared_artifacts(self):
        (self.root / "fixture.files/bin/stale").write_bytes(b"old output")
        self.export()
        self.install()
        installed = self.root / "installed/bin/app"
        self.assertEqual(installed.read_bytes(), b"current executable")
        self.assertEqual(installed.stat().st_mode & 0o777, 0o755)
        self.assertFalse((installed.parent / "stale").exists())

    def test_reject_traversal_and_missing_artifact(self):
        for destination in ["/absolute", "../outside", "a/../outside", "a//b", "a/./b", "a\\b", ""]:
            with self.subTest(destination=destination):
                with self.assertRaises(ValueError):
                    exporter.relative_path(destination)
        (self.root / "fixture.files/bin/app").unlink()
        with self.assertRaisesRegex(ValueError, "missing package artifact"):
            self.export()

    def test_reject_changed_artifact_and_mismatched_package(self):
        package = self.export()
        (package / "files/bin/app").write_bytes(b"unexpected bytes")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self.install()
        with self.assertRaisesRegex(ValueError, "identity"):
            installer.install(self.build, "//example:package", "wrong-name", "1", self.root / "wrong")

    def test_export_uses_completed_target_output_groups(self):
        events = [
            {"id": {"namedSet": {"id": "stale"}}, "namedSetOfFiles": {"files": [
                {"name": "stale.aos-package.json", "uri": (self.root / "stale").as_uri()},
            ]}},
            {"id": {"namedSet": {"id": "current"}}, "namedSetOfFiles": {"files": [
                {"name": self.manifest.name, "uri": self.manifest.as_uri()},
            ]}},
            {"id": {"targetCompleted": {"label": "//example:package"}}, "completed": {
                "success": True, "outputGroup": [{"name": "default", "fileSets": [{"id": "current"}]}],
            }},
        ]
        self.assertEqual(exporter.completed_manifests(events), [self.manifest])
        events[-1]["completed"]["success"] = False
        with self.assertRaisesRegex(ValueError, "unsuccessful"):
            exporter.completed_manifests(events)

    def add_tree(self):
        source = self.root / "generated-assets"
        source.mkdir()
        (source / "console-12345678.js").write_bytes(b"content-addressed module")
        nested = source / "fonts"
        nested.mkdir()
        (nested / "font.woff2").write_bytes(b"font bytes")
        self.metadata["artifacts"].append({
            "source": source.name, "destination": "assets", "kind": "directory", "mode": "0644",
        })
        return source

    def test_generated_tree_is_flattened_hashed_and_installed(self):
        self.add_tree()
        package = self.export()
        entries = json.loads((package / "manifest.json").read_text())["artifacts"]
        self.assertEqual({entry["destination"] for entry in entries}, {
            "bin/app", "assets/console-12345678.js", "assets/fonts/font.woff2",
        })
        self.assertTrue(all("sha256" in entry and "kind" not in entry for entry in entries))

        self.install()
        self.assertEqual((self.root / "installed/assets/fonts/font.woff2").read_bytes(), b"font bytes")

    def test_generated_tree_rejects_links(self):
        source = self.add_tree()
        (source / "escape").symlink_to(self.root / "fixture.files/bin/app")
        with self.assertRaisesRegex(ValueError, "nonregular"):
            self.export()

    def test_generated_tree_rejects_special_files(self):
        source = self.add_tree()
        os.mkfifo(source / "pipe")
        with self.assertRaisesRegex(ValueError, "nonregular"):
            self.export()

    def test_generated_tree_cannot_overlap_explicit_files(self):
        self.add_tree()
        self.metadata["artifacts"][0]["destination"] = "assets/fonts"
        with self.assertRaisesRegex(ValueError, "overlapping"):
            self.export()

    def test_generated_tree_alias_is_resolved_before_regular_file_validation(self):
        source = self.add_tree()
        link = self.root / "linked-assets"
        link.symlink_to(source, target_is_directory=True)
        self.metadata["artifacts"][-1]["source"] = link.name
        self.export()
        self.install()
        self.assertEqual((self.root / "installed/assets/fonts/font.woff2").read_bytes(), b"font bytes")


if __name__ == "__main__":
    unittest.main()
