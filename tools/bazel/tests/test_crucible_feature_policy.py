"""Keeps production exclusions and live feature-consumer audits fail closed."""

import json
from pathlib import Path
import tempfile
import unittest

from verify_crucible_feature_policy import (
    declarations, feature_consumption, production_closures, verify,
)


PACKAGE = "crucible-fixture"
DIRECTORY = "crates/crucible/" + PACKAGE
ROOT = "//" + DIRECTORY + ":lib"
DEPENDENCY = "//crates/crucible/other:lib"
GUEST = "//crates/crucible/crucible-guest:lib_host"
ENGINE = "//crates/crucible/crucible-engine:lib_test_double"
ROOTS = {PACKAGE: ROOT}


def record(label, dependencies=(), features=()):
    return {"label": label, "dependencies": list(dependencies), "features": list(features), "external": False}


def graph(*records):
    return {"schema_version": 1, "targets": [ROOT], "configured_targets": list(records)}


class ProductionFeaturePolicyTests(unittest.TestCase):
    def test_direct_guest_activation_is_rejected_even_without_a_guest_record(self):
        with self.assertRaisesRegex(ValueError, "production guest dependency"):
            production_closures(graph(record(ROOT, [GUEST])), ROOTS, Path("unused"))

    def test_transitive_guest_activation_is_rejected(self):
        inventory = graph(record(ROOT, [DEPENDENCY]), record(DEPENDENCY, [GUEST]))
        with self.assertRaisesRegex(ValueError, "production guest dependency"):
            production_closures(inventory, ROOTS, Path("unused"))

    def test_production_test_double_is_rejected_by_features(self):
        inventory = graph(record(ROOT, [ENGINE]), record(ENGINE, features=["default", "test-double"]))
        with self.assertRaisesRegex(ValueError, "production engine test double"):
            production_closures(inventory, ROOTS, Path("unused"))

    def test_unreachable_development_test_double_does_not_widen_production(self):
        inventory = graph(record(ROOT), record(ENGINE, features=["default", "test-double"]))
        self.assertEqual(production_closures(inventory, ROOTS, Path("unused")), {PACKAGE: [ROOT]})

    def test_missing_dependency_record_cannot_disappear_from_the_graph(self):
        with self.assertRaisesRegex(ValueError, "missing production dependency"):
            production_closures(graph(record(ROOT, [DEPENDENCY])), ROOTS, Path("unused"))

    def test_incompatible_configurations_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "ambiguous production configuration"):
            production_closures(graph(record(ROOT), record(ROOT, features=["unexpected"])), ROOTS, Path("unused"))

    def test_ordinary_declared_source_files_are_not_missing_rules(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / DIRECTORY / "src/lib.rs"
            source.parent.mkdir(parents=True)
            source.write_text("// Fixture source.\n")
            inventory = graph(record(ROOT, ["//" + DIRECTORY + ":src/lib.rs"]))
            self.assertEqual(production_closures(inventory, ROOTS, root), {PACKAGE: [ROOT]})


class FeatureConsumerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / DIRECTORY / "src/lib.rs"
        self.source.parent.mkdir(parents=True)
        self.source.write_text("// Fixture source.\n")
        self.owners = {DIRECTORY: {DIRECTORY + "/src/lib.rs"}}
        self.rules = {
            ROOT: {"directory": DIRECTORY, "kind": "rust_library", "features": {"default"}, "dependencies": {"base"}},
            ROOT + "_feature": {"directory": DIRECTORY, "kind": "rust_library", "features": {"default", "fixture"}, "dependencies": {"base"}},
        }

    def test_unconsumed_feature_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "no cfg or dependency-forwarding consumer"):
            feature_consumption(self.root, self.rules, self.owners, ROOTS)

    def test_owned_cfg_consumes_a_feature(self):
        self.source.write_text('#[cfg(feature = "fixture")]\nconst FIXTURE: () = ();\n')
        result = feature_consumption(self.root, self.rules, self.owners, ROOTS)
        self.assertEqual(result[PACKAGE]["consumers"]["fixture"], "owned Rust cfg")

    def test_independent_dependency_forwarding_consumes_a_feature(self):
        self.rules[ROOT + "_feature"]["dependencies"].add("forwarded")
        result = feature_consumption(self.root, self.rules, self.owners, ROOTS)
        self.assertEqual(result[PACKAGE]["consumers"]["fixture"], "independent dependency-forwarding variant")

    def test_combined_variant_cannot_hide_an_unused_individual_feature(self):
        self.rules[ROOT + "_feature"]["features"].add("another")
        self.rules[ROOT + "_feature"]["dependencies"].add("forwarded")
        with self.assertRaisesRegex(ValueError, "no cfg or dependency-forwarding consumer"):
            feature_consumption(self.root, self.rules, self.owners, ROOTS)

    def test_new_rust_source_cannot_be_omitted_from_the_audit(self):
        self.source.with_name("new.rs").write_text("// New fixture source.\n")
        with self.assertRaisesRegex(ValueError, "source ownership is incomplete"):
            feature_consumption(self.root, self.rules, self.owners, ROOTS)

    def test_new_engine_feature_is_rejected_even_when_it_has_a_cfg_consumer(self):
        self.source.write_text('#[cfg(feature = "new")]\nconst NEW: () = ();\n')
        self.rules[ROOT + "_feature"]["features"] = {"default", "test-double", "test-support", "new"}
        with self.assertRaisesRegex(ValueError, "feature layout drift"):
            feature_consumption(self.root, self.rules, self.owners, {"crucible-engine": ROOT})

    def test_cargo_metadata_is_rejected_before_auditing(self):
        (self.root / "Cargo.toml").write_text("[workspace]\n")
        with self.assertRaisesRegex(ValueError, "contains Cargo metadata"):
            verify(self.root, ROOTS, "", {})


class DeclarationTests(unittest.TestCase):
    def query(self, extra=""):
        identity = json.dumps({"name": PACKAGE}).replace('"', "&quot;")
        return ('<query version="2"><rule class="_source_package" name="//' + DIRECTORY + ':source_package">'
                '<string name="identity" value="' + identity + '"/>'
                '<list name="srcs"><label value="//' + DIRECTORY + ':src/lib.rs"/></list></rule>'
                '<rule class="rust_library" name="' + ROOT + '"><list name="crate_features">'
                '<string value="default"/></list></rule>' + extra + '</query>')

    def test_live_query_supplies_source_ownership_and_feature_names(self):
        rules, owners = declarations(self.query(), ROOTS)
        self.assertEqual(rules[ROOT]["features"], {"default"})
        self.assertEqual(owners, {DIRECTORY: {DIRECTORY + "/src/lib.rs"}})

    def test_missing_package_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "missing feature-policy package"):
            declarations(self.query(), ROOTS | {"other": DEPENDENCY})

    def test_unselected_feature_variant_is_still_in_the_query(self):
        extra = ('<rule class="rust_library" name="' + ROOT + '_new"><list name="crate_features">'
                 '<string value="new"/></list></rule>')
        rules, _ = declarations(self.query(extra), ROOTS)
        self.assertEqual(rules[ROOT + "_new"]["features"], {"new"})


if __name__ == "__main__":
    unittest.main()
