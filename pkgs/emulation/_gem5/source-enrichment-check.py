# SPDX-License-Identifier: MIT
"""Exercises data-only native/source mirror identity and refusal ordering."""

import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

specification = importlib.util.spec_from_file_location(
    "source_enrichment", Path(__file__).with_name("source-enrichment.py")
)
enrichment = importlib.util.module_from_spec(specification)
specification.loader.exec_module(enrichment)


class SourceEnrichmentCheck(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gem5-source-enrichment-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.native = self.root / "native"
        self.native_source = self.root / "native-source"
        self.out = self.root / "out"
        self.source = self.root / "source"
        self.controls = self.root / "controls"
        (self.native / "bin").mkdir(parents=True)
        (self.native / "bin/gem5").write_bytes(b"source-only-model-bytes")
        (self.native / "share/gem5").mkdir(parents=True)
        (self.native / "share/gem5/source-manifest.json").write_text(
            json.dumps({"recipeSha256": "native-model-recipe"})
        )
        for name in enrichment.NATIVE_FILES:
            target = self.native_source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(name.encode())
        shutil.copytree(self.native, self.out)
        shutil.copytree(self.native_source, self.source)
        (self.source / "build/invoked-enrichment-builder.sh").write_text(
            "# data-only modeled enrichment builder\n"
        )
        shutil.copyfile(self.native / "share/gem5/source-manifest.json",
                        self.source / "build/native-source-manifest.json")
        (self.source / "native-corresponding-source").symlink_to(self.native_source)
        self.controls.mkdir()
        (self.controls / "model.py").write_text("# data-only model\n")
        shutil.copytree(self.controls, self.source / "build/controls")
        self.recipe = self.root / "gem5.nix"
        self.recipe.write_text("# source-only model recipe\n")
        (self.source / "build/recipes").mkdir()
        shutil.copyfile(self.recipe, self.source / "build/recipes" / self.recipe.name)
        self.enrichment_sources = {}
        for field, name in (
            ("source_enrichment_recipe", "source-enrichment.nix"),
            ("source_enrichment_writer", "source-enrichment.py"),
            ("source_enrichment_check", "source-enrichment-check.py"),
        ):
            original = self.root / name
            original.write_text("# data-only modeled source\n")
            shutil.copyfile(original, self.source / "build" / name)
            self.enrichment_sources[field] = str(original)
        self.inputs = self.root / "wrapper-inputs.json"
        self.inputs.write_text(json.dumps({
            "schema": "crucible.gem5.native-wrapper-inputs.v1",
            "native_output": str(self.native),
            "native_source": str(self.native_source),
            "native_derivation": "modeled-producer-not-a-native-build",
            "host_controls": str(self.controls),
            "public_recipe": {"name": self.recipe.name, "sha256": enrichment.measure(self.recipe)["sha256"]},
            "host_recipes": [{"name": self.recipe.name,
                              "sha256": enrichment.measure(self.recipe)["sha256"]}],
            **self.enrichment_sources,
            "node_authority_qualified": False,
        }))

    def bind(self, verify=False):
        enrichment.bind(self.inputs, self.out, self.source, verify)

    def test_exact_mirror_binds_both_outputs_and_source_identity(self):
        self.bind()
        self.bind(verify=True)
        origin = enrichment.document(self.out / "share/gem5/native-origin.json")
        self.assertFalse(origin["wrapper_compiled_native_program"])
        self.assertFalse(origin["node_authority_qualified"])
        self.assertEqual(origin, enrichment.document(self.source / "build/native-origin.json"))
        self.assertEqual(len(origin["host_source_inventory"]), 1)
        public = enrichment.document(self.out / "share/gem5/source-manifest.json")
        native = enrichment.document(self.source / "build/native-source-manifest.json")
        self.assertEqual(public["recipeSha256"], enrichment.measure(self.recipe)["sha256"])
        self.assertEqual(native["recipeSha256"], "native-model-recipe")
        self.assertNotEqual(public["recipeSha256"], native["recipeSha256"])
        self.assertEqual(origin["native_source_manifest"],
                         enrichment.measure(self.source / "build/native-source-manifest.json"))

    def test_changed_elf_refuses_before_origin_publication(self):
        (self.out / "bin/gem5").write_bytes(b"rewritten-model")
        with self.assertRaises(ValueError):
            self.bind()
        self.assertFalse((self.out / "share/gem5/native-origin.json").exists())

    def test_changed_native_archive_refuses_before_origin_publication(self):
        (self.source / "gem5-patched-source.tar").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.bind()
        self.assertFalse((self.out / "share/gem5/native-origin.json").exists())

    def test_foreign_source_symlink_refuses(self):
        link = self.source / "native-corresponding-source"
        link.unlink()
        link.symlink_to(self.controls)
        with self.assertRaises(ValueError):
            self.bind()

    def test_source_manifest_binding_is_required_at_final_fixup(self):
        self.bind()
        (self.out / "share/gem5/source-manifest.json").write_text("{}\n")
        with self.assertRaises(KeyError):
            self.bind(verify=True)

    def test_changed_origin_inputs_refuses_at_final_fixup(self):
        self.bind()
        changed = enrichment.document(self.inputs)
        changed["native_derivation"] = "foreign-modeled-producer"
        self.inputs.write_text(json.dumps(changed))
        with self.assertRaises(ValueError):
            self.bind(verify=True)

    def test_divergent_source_record_refuses_at_final_fixup(self):
        self.bind()
        record = self.source / "build/native-origin.json"
        changed = enrichment.document(record)
        changed["node_authority_qualified"] = True
        record.write_text(json.dumps(changed))
        with self.assertRaises(ValueError):
            self.bind(verify=True)

    def test_changed_host_controls_refuse(self):
        (self.source / "build/controls/model.py").write_text("# changed\n")
        with self.assertRaises(ValueError):
            self.bind()

    def test_changed_host_recipe_refuses(self):
        (self.source / "build/recipes" / self.recipe.name).write_text("# changed\n")
        with self.assertRaises(ValueError):
            self.bind()

    def test_unsupported_source_member_refuses(self):
        (self.native_source / "foreign-link").symlink_to(self.controls)
        with self.assertRaises(ValueError):
            self.bind()

    def test_oversized_metadata_refuses(self):
        self.inputs.write_bytes(b" " * (enrichment.MAX_METADATA_BYTES + 1))
        with self.assertRaises(ValueError):
            self.bind()


if __name__ == "__main__":
    unittest.main()
