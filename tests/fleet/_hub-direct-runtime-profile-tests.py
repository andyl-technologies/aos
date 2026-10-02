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


if __name__ == '__main__':
    unittest.main()
