# SPDX-License-Identifier: MIT
"""Checks both Root profile qualification parsers without loading a simulator."""

import copy
import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


def load(name, path):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


root = Path(__file__).parent
source_root = Path(sys.argv[1]) if len(sys.argv) == 2 else root
sys.argv[1:] = []
writers = [
    load("arm_qualification_writer", root / "arm-root-model-profile-manifest.py"),
    load("x86_qualification_writer", root / "x86-root-model-profile.py"),
]
# Source-only bytes, never an installed profile or native permission.
controller = hashlib.sha256((source_root / "native-controller.py").read_bytes()).hexdigest()
check = hashlib.sha256((source_root / "native-controller-temporary-root-check.py").read_bytes()).hexdigest()
source = {
    "schema": "crucible.gem5.root-qualification-sources.v1",
    "controller_sha256": controller,
    "checks": {"native-controller-temporary-root-check.py": check},
}


class QualificationInputs(unittest.TestCase):
    def test_both_profile_readers_bind_actual_controller_and_executed_check(self):
        for writer in writers:
            with self.subTest(writer=writer.__name__):
                writer.validate_qualification_document(source, controller, check)

    def test_missing_malformed_or_substituted_receipts_refuse(self):
        cases = [None, [], {}]
        for key in source:
            changed = copy.deepcopy(source)
            del changed[key]
            cases.append(changed)
        for key, value in (("schema", "legacy"), ("controller_sha256", "0" * 64),
                           ("controller_sha256", True), ("checks", {}),
                           ("checks", {"native-controller-temporary-root-check.py": "0" * 64}),
                           ("checks", {"native-controller-temporary-root-check.py": True}),
                           ("checks", {"unknown.py": check}), ("extra", True)):
            changed = copy.deepcopy(source)
            changed[key] = value
            cases.append(changed)
        for writer in writers:
            for changed in cases:
                with self.subTest(writer=writer.__name__, source=changed), self.assertRaises(ValueError):
                    writer.validate_qualification_document(changed, controller, check)
            with self.assertRaises(ValueError):
                writer.validate_qualification_document(source, "0" * 64, check)
            with self.assertRaises(ValueError):
                writer.validate_qualification_document(source, controller, "0" * 64)

    def test_missing_and_unknown_input_rosters_refuse_before_measurement(self):
        for writer in writers:
            for selected in ({}, {"source_manifest": "/absent"},
                             {"temporary_root_check": "/absent"},
                             {"source_manifest": "/absent", "temporary_root_check": "/absent", "extra": "/absent"}):
                with self.subTest(writer=writer.__name__, selected=selected), patch.object(writer, "measure") as measure:
                    with self.assertRaises(ValueError):
                        writer.qualification_inputs(selected, {})
                    measure.assert_not_called()


if __name__ == "__main__":
    unittest.main()
