"""Preserves standalone exclusions and inherited policy in editor oracles."""

import tomllib
import unittest

from select_cargo_workspace import select_workspace


class CargoWorkspaceSelectionTests(unittest.TestCase):
    def setUp(self):
        self.manifest = '''[workspace]
resolver = "2"
exclude = ["accache"]
members = [
    "registry/aos-registry-web",
    "core/aos-core",
]
[workspace.package]
license = "Apache-2.0"
[workspace.lints.clippy]
unwrap_used = "deny"
'''

    def test_existing_exclusions_and_workspace_policy_survive_family_selection(self):
        selected = select_workspace(self.manifest, ["registry/aos-registry-web"], ["core/aos-core"])
        value = tomllib.loads(selected)

        self.assertEqual(value["workspace"]["exclude"], ["accache", "core/aos-core"])
        self.assertEqual(value["workspace"]["members"], ["registry/aos-registry-web"])
        self.assertEqual(value["workspace"]["lints"], tomllib.loads(self.manifest)["workspace"]["lints"])
        self.assertEqual(value["workspace"]["package"], {"license": "Apache-2.0"})

    def test_new_exclusions_are_added_when_the_workspace_had_none(self):
        manifest = self.manifest.replace('exclude = ["accache"]\n', "")
        selected = select_workspace(manifest, ["registry/aos-registry-web"], ["core/aos-core"])

        self.assertEqual(tomllib.loads(selected)["workspace"]["exclude"], ["core/aos-core"])

    def test_explicit_exclusions_cannot_become_editor_members(self):
        with self.assertRaisesRegex(ValueError, "overlap excluded"):
            select_workspace(self.manifest, ["accache"], [])
