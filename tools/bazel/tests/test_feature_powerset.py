"""Rejects default leakage and incorrect feature dependency artifacts."""

from copy import deepcopy
import unittest

from verify_feature_powerset import validate_case, validate_contract


ROOT = "//crates/crucible/crucible-qemu-host:lib_no_default"
ENGINE = "//crates/crucible/crucible-engine:lib"
DOUBLE = "//crates/crucible/crucible-engine:lib_test_double"


def fixture():
    case = {"name": "production", "package": "crucible-qemu-host", "target": ROOT,
            "no_default_features": True, "requested_features": [], "expected_features": [],
            "required_dependencies": [ENGINE], "forbidden_dependencies": [DOUBLE]}
    records = [{"label": ROOT, "features": [], "dependencies": [ENGINE], "crate_name": "crucible_qemu_host"},
               {"label": ENGINE, "features": ["default"], "dependencies": [], "crate_name": "crucible_engine"},
               {"label": DOUBLE, "features": ["default", "test-double"], "dependencies": [], "crate_name": "crucible_engine"}]
    actions = [{"target_label": ROOT, "arguments": ["rustc", "--extern", "crucible_engine=engine.rlib"]}]
    events = [{"targetLabel": label, "mnemonic": "Rustc", "cacheHit": False,
               "exitCode": 0, "runner": "linux-sandbox", "actualOutputs": [{"path": output}]}
              for label, output in [(ROOT, "host.rlib"), (ENGINE, "engine.rlib"), (DOUBLE, "double.rlib")]]
    return case, records, actions, events


class FeaturePowersetTests(unittest.TestCase):
    def test_no_default_host_keeps_the_dependency_default(self):
        case, records, actions, events = fixture()
        validate_contract({"schema_version": 1, "cases": [case]})
        self.assertEqual(validate_case(case, records, actions, events)["features"], [])

    def test_actual_default_feature_leak_is_rejected(self):
        case, records, actions, events = fixture()
        actions[0]["arguments"].extend(["--cfg", 'feature="default"'])
        with self.assertRaisesRegex(ValueError, "compiled features differ"):
            validate_case(case, records, actions, events)

    def test_wrong_engine_artifact_cannot_hide_behind_correct_metadata(self):
        case, records, actions, events = fixture()
        actions[0]["arguments"][-1] = "crucible_engine=double.rlib"
        with self.assertRaisesRegex(ValueError, "wrong compiled artifact"):
            validate_case(case, records, actions, events)

    def test_missing_forwarded_dependency_is_rejected(self):
        case, records, actions, events = fixture()
        records[0]["dependencies"] = []
        with self.assertRaisesRegex(ValueError, "missing feature dependency"):
            validate_case(case, records, actions, events)

    def test_cached_action_does_not_prove_a_compiler_executed(self):
        case, records, actions, events = fixture()
        events[0].update(cacheHit=True, runner="disk cache hit")
        with self.assertRaisesRegex(ValueError, "unexpected cache result"):
            validate_case(case, records, actions, events)

    def test_duplicate_cases_are_rejected(self):
        case, *_ = fixture()
        with self.assertRaisesRegex(ValueError, "duplicate feature-case"):
            validate_contract({"schema_version": 1, "cases": [case, deepcopy(case)]})

    def test_inconsistent_default_expectation_is_rejected(self):
        case, *_ = fixture()
        case["no_default_features"] = False
        with self.assertRaisesRegex(ValueError, "inconsistent default"):
            validate_contract({"schema_version": 1, "cases": [case]})


if __name__ == "__main__":
    unittest.main()
