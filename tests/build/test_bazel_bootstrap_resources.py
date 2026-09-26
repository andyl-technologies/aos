"""Verify that Bazel bootstrap resources are generated from source text."""

import importlib.util
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile


SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "pkgs/toolchain/generate-bazel-bootstrap-resources.py"
)
SPEC = importlib.util.spec_from_file_location("generate_bazel_bootstrap_resources", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
generator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generator)


class BazelBootstrapResourceTests(unittest.TestCase):
    """Exercise the source rules, templates, and deterministic builtins archive."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

        self.write(
            "workspace_deps.bzl",
            'WORKSPACE_REPOS = {"fixture_repo": {"sha256": "abc123", '
            '"urls": ["https://example.invalid/source.tar.gz"]}}\n',
        )
        self.write(
            "src/main/java/com/google/devtools/build/lib/bazel/rules/BUILD",
            'gen_workspace_stanza(out="coverage.WORKSPACE", repos=["fixture_repo"], '
            'preamble="load(\\"@fixture//:repo.bzl\\", \\"maybe\\")", use_maybe=1)\n'
            'gen_workspace_stanza(out="rules_license.WORKSPACE", repos=["fixture_repo"])\n',
        )
        self.write(
            "src/main/java/com/google/devtools/build/lib/bazel/rules/cpp/BUILD",
            'gen_workspace_stanza(out="cc_configure.WORKSPACE", repos=["fixture_repo"])\n',
        )
        self.write(
            "src/main/java/com/google/devtools/build/lib/bazel/rules/java/BUILD",
            'gen_workspace_stanza(out="jdk.WORKSPACE", repos=["fixture_repo"], '
            'template="jdk.WORKSPACE.tmpl")\n',
        )
        self.write(
            "src/main/java/com/google/devtools/build/lib/bazel/rules/java/jdk.WORKSPACE.tmpl",
            "before {fixture_repo} after\n",
        )
        self.write("src/main/starlark/builtins_bzl/exports.bzl", 'load(":java/defs.bzl", "defs")\n')
        self.write("src/main/starlark/builtins_bzl/java/defs.bzl", "defs = []\n")

    def write(self, relative, contents):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)

    def test_generates_workspace_resources_and_source_archive(self):
        workspaces = generator.write_workspace_resources(self.root)
        archive_path = generator.write_builtins_zip(self.root)

        self.assertEqual({path.name for path in workspaces}, generator.WORKSPACE_OUTPUTS)
        coverage = (self.root / generator.RULES_DIRECTORY / "coverage.WORKSPACE").read_text()
        self.assertIn('sha256 = "abc123"', coverage)
        self.assertIn("https://example.invalid/source.tar.gz", coverage)
        jdk = (self.root / generator.RULES_DIRECTORY / "java/jdk.WORKSPACE").read_text()
        self.assertNotIn("{fixture_repo}", jdk)

        with ZipFile(archive_path) as archive:
            self.assertEqual(
                archive.namelist(),
                ["builtins_bzl/exports.bzl", "builtins_bzl/java/defs.bzl"],
            )
            self.assertEqual(
                archive.getinfo("builtins_bzl/exports.bzl").date_time[:3],
                (1980, 1, 1),
            )
            self.assertEqual(archive.read("builtins_bzl/java/defs.bzl"), b"defs = []\n")

        first_archive = archive_path.read_bytes()
        archive_path.unlink()
        self.assertEqual(generator.write_builtins_zip(self.root).read_bytes(), first_archive)

    def test_refuses_to_replace_generated_resource(self):
        generator.write_workspace_resources(self.root)

        with self.assertRaises(FileExistsError):
            generator.write_workspace_resources(self.root)


if __name__ == "__main__":
    unittest.main()
