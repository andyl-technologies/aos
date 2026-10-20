"""Checks migration syntax regions that can otherwise corrupt signed strings."""

from pathlib import Path
import runpy
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "crate-migrate.py"
MIGRATION = runpy.run_path(str(SCRIPT))


class CrateMigrationTests(unittest.TestCase):
    def rewrite(self, source):
        return MIGRATION["rust"](source, Path("crates/aos/src/main.rs"))

    def test_quotes_in_character_literals_do_not_hide_imports(self):
        source = "let quote = '\"';\nlet result = aos_release::Release::new();\n"
        expected = "let quote = '\"';\nlet result = aos_release_format::Release::new();\n"
        self.assertEqual(self.rewrite(source), expected)

    def test_raw_fixture_strings_keep_serialized_names(self):
        source = (
            'let fixture = r###"aos_release::signed-domain\n"quoted fixture""###;\n'
            'let result = aos_release::Release::new();\n'
        )
        rewritten = self.rewrite(source)
        self.assertIn('r###"aos_release::signed-domain\n"quoted fixture""###', rewritten)
        self.assertIn("aos_release_format::Release::new()", rewritten)

    def test_binary_lookup_strings_keep_installed_commands(self):
        source = 'let binary = env!("CARGO_BIN_EXE_aos");\n'
        self.assertEqual(self.rewrite(source), source)

    def test_local_import_alias_keeps_its_namespace(self):
        source = "use crucible_core as crucible;\nlet value = crucible::Configuration::genesis();\n"
        self.assertEqual(self.rewrite(source), source)

    def test_bare_build_source_paths_follow_the_workspace_hierarchy(self):
        source = 'cp aos-hub-core/src/web/static_assets/app.js "$out/assets/app.js"'
        expected = 'cp hub/aos-hub-service/src/web/static_assets/app.js "$out/assets/app.js"'
        self.assertEqual(MIGRATION["source_path"](source), expected)

    def test_installed_license_paths_keep_their_package_labels(self):
        source = 'cp notice "$out/share/licenses/aos-hub-core/src/NOTICE"'
        self.assertEqual(MIGRATION["source_path"](source), source)


if __name__ == "__main__":
    unittest.main()
