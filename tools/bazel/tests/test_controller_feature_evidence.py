"""Exercises source and qualification binding for controller feature audits."""

from copy import deepcopy
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from controller_feature_evidence import (
    NEGATIVE_CONTROLS, PRODUCTION_PACKAGES, bundle, main, production_root, verify_bound_sources,
)
from verify_crucible_feature_policy import FEATURE_LAYOUT


class ControllerFeatureEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.policy_root = self.root / "policy"
        self.compilation_root = self.root / "compilation"
        for root in [self.policy_root, self.compilation_root]:
            source = root / "crates/crucible/crucible-engine/src/lib.rs"
            source.parent.mkdir(parents=True)
            source.write_text("pub fn engine() {}\n")

        self.policy = {
            "schema_version": 1,
            "cargo_metadata_absent": True,
            "features": {
                name: {"declared_features": sorted(features)}
                for name, features in FEATURE_LAYOUT.items()
            },
            "production_closures": {
                name: [production_root(name)] for name in PRODUCTION_PACKAGES
            },
            "rejected_negative_controls": sorted(NEGATIVE_CONTROLS),
        }
        self.contract = {
            "schema_version": 1,
            "cases": [{
                "name": "default",
                "package": "crucible-engine",
                "target": "//crates/crucible/crucible-engine:lib",
                "no_default_features": False,
                "requested_features": [],
                "expected_features": ["default"],
                "required_dependencies": [],
                "forbidden_dependencies": [],
            }],
        }
        self.compilation = {
            "schema_version": 1,
            "cases": {"default": {
                "features": ["default"],
                "compilation": {"runner": "linux-sandbox", "cache_hit": False},
            }},
        }

    def evidence(self):
        return bundle(
            self.policy, self.compilation, self.contract,
            self.policy_root, self.compilation_root,
        )

    def test_retains_actual_reports_and_source_hashes(self):
        result = self.evidence()

        self.assertEqual(result["policy"], self.policy)
        self.assertEqual(result["compilation"], self.compilation)
        self.assertEqual(len(result["sources_sha256"]), 1)

    def test_prepares_repository_in_existing_builder_output(self):
        output = self.root / "output"
        output.mkdir()
        arguments = ["controller_feature_evidence.py", "prepare"]
        for name in ["policy", "compilation", "contract"]:
            path = self.root / (name + ".json")
            path.write_text(json.dumps(getattr(self, name)))
            arguments.extend(["--" + name, str(path)])
        arguments.extend([
            "--policy-root", str(self.policy_root),
            "--compilation-root", str(self.compilation_root),
            "--output", str(output),
        ])

        with patch("sys.argv", arguments):
            main()

        self.assertEqual(json.loads((output / "features.json").read_text()), self.evidence())
        self.assertTrue((output / "BUILD.bazel").is_file())
        self.assertTrue((output / "REPO.bazel").is_file())

    def test_all_policy_sources_are_bound_even_if_not_compiled(self):
        source = self.policy_root / "crates/crucible/crucible-engine/src/audit.rs"
        source.write_text("// An owned policy input, outside this compilation.\n")

        self.assertEqual(len(self.evidence()["sources_sha256"]), 2)

    def test_rejects_changed_compiled_source(self):
        source = self.compilation_root / "crates/crucible/crucible-engine/src/lib.rs"
        source.write_text("pub fn changed_engine() {}\n")

        with self.assertRaisesRegex(ValueError, "source trees differ"):
            self.evidence()

    def test_rejects_source_missing_from_policy(self):
        source = self.compilation_root / "crates/crucible/crucible-engine/src/new.rs"
        source.write_text("// Unbound compilation input.\n")

        with self.assertRaisesRegex(ValueError, "source trees differ"):
            self.evidence()

    def test_runtime_rejects_changed_added_and_missing_sources(self):
        evidence = self.evidence()
        cases = {"default": ["default"]}
        verify_bound_sources(evidence, self.policy_root, cases)
        source = self.policy_root / "crates/crucible/crucible-engine/src/lib.rs"

        for contents in ["// Changed source.\n", None]:
            with self.subTest(contents=contents):
                if contents is None:
                    source.unlink()
                else:
                    source.write_text(contents)
                with self.assertRaisesRegex(ValueError, "runtime source tree differs"):
                    verify_bound_sources(evidence, self.policy_root, cases)
        source.write_text("pub fn engine() {}\n")
        source.with_name("new.rs").write_text("// Added source.\n")
        with self.assertRaisesRegex(ValueError, "runtime source tree differs"):
            verify_bound_sources(evidence, self.policy_root, cases)

    def test_runtime_rejects_different_case_selection(self):
        with self.assertRaisesRegex(ValueError, "runtime feature cases differ"):
            verify_bound_sources(self.evidence(), self.policy_root, {"default": []})

    def test_rejects_incomplete_or_different_qualification(self):
        mutations = [
            ("policy", lambda value: value.update(cargo_metadata_absent=False)),
            ("policy", lambda value: value["production_closures"].pop("crucible-engine")),
            ("policy", lambda value: value["production_closures"]["crucible-engine"].clear()),
            ("policy", lambda value: value["production_closures"]["crucible-engine"].append("//crates/crucible/crucible-guest:lib")),
            ("policy", lambda value: value["rejected_negative_controls"].pop()),
            ("policy", lambda value: value["features"]["crucible-device"].update(declared_features=[])),
            ("compilation", lambda value: value["cases"].clear()),
            ("compilation", lambda value: value["cases"]["default"].update(features=[])),
            ("compilation", lambda value: value["cases"]["default"]["compilation"].update(cache_hit=True)),
            ("compilation", lambda value: value["cases"]["default"]["compilation"].update(runner="local")),
        ]
        for name, mutate in mutations:
            with self.subTest(name=name, mutate=mutate):
                original = getattr(self, name)
                changed = deepcopy(original)
                mutate(changed)
                setattr(self, name, changed)
                try:
                    with self.assertRaises(ValueError):
                        self.evidence()
                finally:
                    setattr(self, name, original)


if __name__ == "__main__":
    unittest.main()
