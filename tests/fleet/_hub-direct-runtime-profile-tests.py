"""Check current preflight audience and original-file substitutions."""

import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('runtime_profile', Path(__file__).with_name('_hub-direct-runtime-profile.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RuntimeSelectionTests(unittest.TestCase):
    def setUp(self):
        self.identity = {'identity': {'deploymentId': 'selected', 'publicOrigin': 'https://localhost:4673',
            'sourceDigest': 'a' * 64, 'scriptVersion': 'selected-script'}, 'identitySha256': 'b' * 64}
        self.measured = {'installationSha256': 'c' * 64}
        self.selection = {**self.identity['identity'], 'executionKind': 'emulated_external',
            'documents': {'deploymentIdentity': {'sha256': 'b' * 64}, 'installation': {'sha256': 'c' * 64}}}

    def test_actual_originals(self):
        module.check_runtime_profile_selection(self.selection, self.identity, self.measured)

    def test_changed_audience(self):
        for name in self.identity['identity']:
            changed = copy.deepcopy(self.selection)
            changed[name] = 'different'
            with self.subTest(name=name), self.assertRaises(ValueError):
                module.check_runtime_profile_selection(changed, self.identity, self.measured)

    def test_changed_installation(self):
        self.selection['documents']['installation']['sha256'] = 'd' * 64
        with self.assertRaises(ValueError):
            module.check_runtime_profile_selection(self.selection, self.identity, self.measured)

    def test_changed_discovery(self):
        self.selection['documents']['deploymentIdentity']['sha256'] = 'd' * 64
        with self.assertRaises(ValueError):
            module.check_runtime_profile_selection(self.selection, self.identity, self.measured)

    def test_hosted_substitution(self):
        self.selection['executionKind'] = 'hosted_external'
        with self.assertRaises(ValueError):
            module.check_runtime_profile_selection(self.selection, self.identity, self.measured)

    def test_paired_profiles_match_both_current_cohorts_and_runtime(self):
        runtime = {"controlledRuntime": True}
        exports, profiles = [], []
        for identity in ("7", "8"):
            association = {"binding_id": identity, "binding_stable_id": "selected-" + identity}
            read = {"association": association, "purpose": "read"}
            write = {"association": association, "purpose": "write"}
            issuer = {"selectedIssuer": "same-current-issuer"}
            exports.append({"read_cohort": read, "write_cohort": write, "issuer_installation": issuer})
            profiles.append({"profile": {"readCohort": read, "writeCohort": write,
                "issuerInstallation": issuer, "selector": {"association": association}},
                "runtimeQualification": runtime})
        self.assertEqual(module.match_paired_runtime_profiles(list(reversed(profiles)), runtime, exports), profiles)
        for index, section, field, changed in ((0, "profile", "writeCohort", {"changed": True}),
                (1, "profile", "issuerInstallation", {"changed": True}),
                (1, "wrapper", "runtimeQualification", {"changed": True})):
            selected = copy.deepcopy(profiles)
            (selected[index] if section == "wrapper" else selected[index]["profile"])[field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.match_paired_runtime_profiles(selected, runtime, exports)
        with self.assertRaises(ValueError):
            module.match_paired_runtime_profiles(profiles, runtime, [exports[0], exports[0]])


if __name__ == '__main__':
    unittest.main()
