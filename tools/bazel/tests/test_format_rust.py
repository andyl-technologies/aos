"""Checks Cargo-independent Rust formatting discovery and formatter execution."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET


SCRIPT = Path(__file__).resolve().parents[1] / "format_rust.py"
SPEC = importlib.util.spec_from_file_location("format_rust", SCRIPT)
FORMAT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FORMAT)


class FormattingTests(unittest.TestCase):
    def setUp(self):
        self.document = ET.Element("query", version="2")
        self.directory = "crates/example"

    def source_owner(self, paths, directory=None, edition="2024", name="example"):
        directory = directory or self.directory
        rule = ET.SubElement(self.document, "rule", {"class": "_source_package", "name": "//" + directory + ":source_package"})
        ET.SubElement(rule, "string", name="identity", value=json.dumps({"name": name, "edition": edition}))
        sources = ET.SubElement(rule, "list", name="srcs")
        for path in paths:
            ET.SubElement(sources, "label", value="//" + directory + ":" + path)
        return rule

    def target(self, name, root=None, sources=(), crate=None, edition="2024"):
        rule = ET.SubElement(self.document, "rule", {"class": "rust_test", "name": "//" + self.directory + ":" + name})
        ET.SubElement(rule, "string", name="edition", value=edition)
        if root:
            ET.SubElement(rule, "label", name="crate_root", value="//" + self.directory + ":" + root)
        if crate:
            ET.SubElement(rule, "label", name="crate", value="//" + self.directory + ":" + crate)
        items = ET.SubElement(rule, "list", name="srcs")
        for source in sources:
            ET.SubElement(items, "label", value="//" + self.directory + ":" + source)
        return rule

    def inventory(self):
        return FORMAT.inventory(ET.tostring(self.document, encoding="unicode"))

    def test_declared_inferred_and_reused_roots_are_deduplicated(self):
        self.source_owner(["standalone.rs", "custom.rs"])
        self.target("library", root="custom.rs")
        self.target("unit", crate="library")
        self.target("standalone", sources=["standalone.rs"])
        result = self.inventory()
        self.assertEqual(result["packages"], 1)
        self.assertEqual(set(result["roots"]), {"crates/example/custom.rs", "crates/example/standalone.rs"})

    def test_owned_conventions_cover_unmigrated_targets_but_exclude_modules(self):
        roots = ["build.rs", "src/lib.rs", "src/main.rs", "src/bin/tool.rs", "src/bin/nested/main.rs",
                 "tests/integration.rs", "tests/nested/main.rs", "examples/example.rs", "benches/benchmark.rs"]
        modules = ["src/module.rs", "tests/support/mod.rs", "examples/support/helper.rs"]
        self.source_owner(roots + modules)
        self.assertEqual(set(self.inventory()["roots"]), {"crates/example/" + root for root in roots})

    def test_package_editions_are_preserved(self):
        self.source_owner(["src/lib.rs"], edition="2021")
        self.target("lib", root="src/lib.rs", edition="2021")
        self.assertEqual(self.inventory()["roots"]["crates/example/src/lib.rs"]["edition"], "2021")

    def test_unknown_or_conflicting_editions_fail(self):
        self.source_owner(["src/lib.rs"])
        self.target("lib", root="src/lib.rs", edition="2021")
        with self.assertRaisesRegex(ValueError, "edition differs"):
            self.inventory()

    def test_unowned_and_ambiguous_roots_fail(self):
        self.source_owner(["src/lib.rs"])
        rule = self.target("lib", root="src/missing.rs")
        with self.assertRaisesRegex(ValueError, "not an owned"):
            self.inventory()
        self.document.remove(rule)
        self.target("lib", sources=["src/lib.rs", "src/module.rs"])
        with self.assertRaisesRegex(ValueError, "unambiguous"):
            self.inventory()

    def test_missing_and_cyclic_crate_references_fail(self):
        self.source_owner(["src/lib.rs"])
        self.target("unit", crate="missing")
        with self.assertRaisesRegex(ValueError, "missing or cyclic"):
            self.inventory()
        self.target("missing", crate="unit")
        with self.assertRaisesRegex(ValueError, "missing or cyclic"):
            self.inventory()

    def test_invalid_documents_and_duplicate_ownership_fail(self):
        for query in ['<other version="2"/>', '<query version="3"/>', '<query version="2"/>']:
            with self.subTest(query=query), self.assertRaises(ValueError):
                FORMAT.inventory(query)
        self.source_owner(["src/lib.rs"])
        self.source_owner(["src/lib.rs"], directory="crates/other")
        with self.assertRaisesRegex(ValueError, "duplicate owner"):
            self.inventory()

    def test_noncanonical_sources_and_owner_paths_fail(self):
        for source in ["../outside.rs", "src/../lib.rs", "src//lib.rs", "/absolute.rs", "src/lib.rs/", "src/lib\\outside.rs"]:
            with self.subTest(source=source), self.assertRaises(ValueError):
                FORMAT.local_source("//crates/example:" + source, "crates/example")
        self.source_owner(["src/lib.rs"], directory="crates/../outside")
        with self.assertRaisesRegex(ValueError, "noncanonical source owner"):
            self.inventory()

    def test_rootless_owner_fails_instead_of_silently_disappearing(self):
        self.source_owner(["src/module.rs"])
        with self.assertRaisesRegex(ValueError, "no formatting root"):
            self.inventory()

    def test_execution_groups_editions_propagates_check_and_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {"crates/old/lib.rs": "2021", "crates/new/src/lib.rs": "2024"}
            for relative in paths:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("pub fn example() {}\n")
            metadata = {"roots": {path: {"edition": edition} for path, edition in paths.items()}}

            results = [subprocess.CompletedProcess([], 1), subprocess.CompletedProcess([], 0)]
            with patch.object(FORMAT.subprocess, "run", side_effect=results) as invoke:
                status = FORMAT.format_sources(root, metadata, Path("/declared/rustfmt"), True)

            self.assertEqual(status, 1)
            self.assertEqual(invoke.call_count, 2)
            for call, edition in zip(invoke.call_args_list, ["2021", "2024"]):
                self.assertEqual(call.args[0][:3], ["/declared/rustfmt", "--edition", edition])
                self.assertIn("--check", call.args[0])
                self.assertNotIn("cargo", call.args[0])

    def test_absent_or_escaping_sources_fail_before_any_formatter_executes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "checkout"
            root.mkdir()
            outside = Path(directory) / "outside.rs"
            outside.write_text("fn outside() {}\n")
            (root / "escape.rs").symlink_to(outside)
            for source in ["missing.rs", "escape.rs"]:
                metadata = {"roots": {source: {"edition": "2024"}}}
                with self.subTest(source=source), patch.object(FORMAT.subprocess, "run") as invoke:
                    with self.assertRaisesRegex(ValueError, "absent or outside"):
                        FORMAT.format_sources(root, metadata, Path("/declared/rustfmt"), False)
                    invoke.assert_not_called()


if __name__ == "__main__":
    unittest.main()
