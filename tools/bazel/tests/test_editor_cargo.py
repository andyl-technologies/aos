"""Checks application feature forwarding without corrupting sysroot queries."""

from pathlib import Path
import tempfile
import unittest

from editor_cargo import forwarded_arguments


class EditorCargoTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "application"
        self.workspace.mkdir()
        (self.workspace / "Cargo.toml").write_text("[workspace]\nmembers = []\n")
        self.flags = ["--features", "release-fleet-fixture"]

    def forward(self, arguments, directory=None):
        return forwarded_arguments(arguments, self.workspace, self.flags, directory or self.workspace)

    def test_workspace_metadata_and_checks_retain_selected_features(self):
        for command in ["metadata", "check"]:
            arguments = [command, "--manifest-path", str(self.workspace / "Cargo.toml"), "--offline"]
            self.assertEqual(self.forward(arguments), arguments + self.flags)

    def test_stdlib_metadata_never_receives_application_features(self):
        manifest = self.root / "rust-src/library/Cargo.toml"
        for selection in [["--manifest-path", str(manifest)], ["--manifest-path=" + str(manifest)]]:
            arguments = ["metadata", *selection, "--format-version=1"]
            self.assertEqual(self.forward(arguments), arguments)

    def test_manifest_can_be_relative_to_cargos_working_directory(self):
        arguments = ["metadata", "--manifest-path=application/Cargo.toml"]
        self.assertEqual(self.forward(arguments, self.root), arguments + self.flags)

    def test_manifest_discovery_uses_the_cargo_working_directory(self):
        directory = self.workspace / "member/src"
        directory.mkdir(parents=True)
        self.assertEqual(self.forward(["check"], directory), ["check", *self.flags])
        self.assertEqual(self.forward(["metadata"], self.root), ["metadata"])

    def test_workspace_name_prefix_does_not_include_a_different_project(self):
        arguments = ["metadata", "--manifest-path", str(self.root / "application-other/Cargo.toml")]
        self.assertEqual(self.forward(arguments), arguments)

    def test_unrelated_commands_retain_all_arguments(self):
        self.assertEqual(self.forward(["--version"]), ["--version"])
        self.assertEqual(self.forward(["rustc", "--", "--print=cfg"]), ["rustc", "--", "--print=cfg"])

    def test_duplicate_manifest_selection_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            self.forward(["metadata", "--manifest-path", "Cargo.toml", "--manifest-path=other/Cargo.toml"])


if __name__ == "__main__":
    unittest.main()
