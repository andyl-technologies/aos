# SPDX-License-Identifier: MIT
"""Tests bounded installed ARM evidence validation without minting admission."""

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("profile_writer", sys.argv[1])
profile = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile)
evidence_path = Path(sys.argv[2])
installed = profile.read_document(evidence_path)
bundle = profile.read_document(sys.argv[3])
sys.argv[1:] = []


class EvidenceTests(unittest.TestCase):
    def test_actual_fixed_witness_remains_mechanism_only(self):
        profile.validate_witness(installed)

    def test_missing_or_changed_each_actual_gate_refuses(self):
        for key in ("source_group_reclaimed", "original_linux_serial_birth_retained",
                    "exclusive_full_position_stop", "original_retry_unchanged",
                    "native_uart_birth_preserved"):
            for value in (False, "true", None):
                changed = copy.deepcopy(installed)
                changed[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    profile.validate_witness(changed)

    def test_each_fresh_branch_requires_all_actual_gates(self):
        for index in range(2):
            for key in ("fresh_capture_byte_closure", "original_held_receipt_unchanged",
                        "exact_suffix", "source_namespace_absent", "group_reclaimed"):
                changed = copy.deepcopy(installed)
                changed["fresh_branches"][index][key] = False
                with self.subTest(index=index, key=key), self.assertRaises(ValueError):
                    profile.validate_witness(changed)

    def test_duplicate_and_missing_independent_branch_refuse(self):
        for branches in ([], installed["fresh_branches"][:1],
                         [installed["fresh_branches"][0]] * 2):
            changed = copy.deepcopy(installed)
            changed["fresh_branches"] = branches
            with self.assertRaises(ValueError):
                profile.validate_witness(changed)

    def test_native_metadata_cannot_self_promote_admission(self):
        for key in ("full_system_qualified", "complete_process_closure_qualified",
                    "guest_readiness_qualified", "cpu_timing_qualified"):
            changed = copy.deepcopy(installed)
            changed[key] = True
            with self.subTest(key=key), self.assertRaises(ValueError):
                profile.validate_witness(changed)

    def test_serial_cannot_be_retagged_as_stdout(self):
        for key, value in (("facet", "console"), ("terminal", "other"),
                           ("payload", [90]), ("guest_fd", "1"), ("guest_pid", "1")):
            changed = copy.deepcopy(installed)
            changed["publications"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                profile.validate_witness(changed)

    def test_serial_birth_position_requires_positive_canonical_finite_scalars(self):
        for key in ("output_id", "tick", "event_ordinal", "tick_ordinal", "causal_parent"):
            for value in ("0", "01", "18446744073709551616", 1, True, None):
                changed = copy.deepcopy(installed)
                changed["publications"][0][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    profile.validate_witness(changed)

    def test_serial_birth_cannot_exceed_fixed_superdense_ceiling(self):
        changed = copy.deepcopy(installed)
        changed["publications"][0]["tick_ordinal"] = "500001"
        with self.assertRaises(ValueError):
            profile.validate_witness(changed)

    def test_immutable_store_roles_refuse_private_files_and_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact"
            path.write_bytes(b"finite")
            path.chmod(0o444)
            with self.assertRaises(ValueError):
                profile.measure(path)
            alias = path.with_name("alias")
            alias.symlink_to(evidence_path)
            with self.assertRaises(ValueError):
                profile.measure(alias)

    def test_read_document_rejects_symbolic_or_hard_link_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "document"
            path.write_text("{}")
            alias = path.with_name("alias")
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                profile.read_document(alias)
            alias.unlink()
            alias.hardlink_to(path)
            with self.assertRaises(ValueError):
                profile.read_document(path)

    def test_document_preflight_credit_before_read(self):
        with patch.object(profile, "MAX_DOCUMENT_BYTES", 1), self.assertRaises(ValueError):
            profile.read_document(evidence_path)

    def test_closed_artifact_roster_precedes_any_measurement(self):
        with patch.object(profile, "measure") as measure:
            with self.assertRaises(ValueError):
                profile.manifest({"artifacts": {}, "configuration_tree": "/nix/store/unknown"})
            measure.assert_not_called()

    def test_changed_source_recipe_helpers_or_terminal_extension_refuse(self):
        specification = {"artifacts": {role: record["path"] for role, record in bundle["artifacts"].items()},
                         "configuration_tree": bundle["configuration_root"]}
        by_path = {record["path"]: record for record in bundle["artifacts"].values()}
        original_read = profile.read_document
        cases = (("source_manifest", "recipe_sha256"),
                 ("terminal_runtime_manifest", "patchSha256"),
                 ("terminal_runtime_manifest", "recipeSha256"),
                 ("terminal_runtime_manifest", "witnessSha256"))
        for role, key in cases:
            target = bundle["artifacts"][role]["path"]

            def changed_document(path):
                observed = original_read(path)
                if str(path) == target:
                    observed[key] = "0" * 64
                return observed

            with self.subTest(role=role, key=key), \
                    patch.object(profile, "measure", side_effect=lambda path: by_path[str(path)]), \
                    patch.object(profile, "read_document", side_effect=changed_document), \
                    self.assertRaises(ValueError):
                profile.manifest(specification)
        target = bundle["artifacts"]["source_manifest"]["path"]

        def changed_helper(path):
            observed = original_read(path)
            if str(path) == target:
                observed["helpers"]["native-controller-arm-model.py"] = "0" * 64
            return observed

        with patch.object(profile, "measure", side_effect=lambda path: by_path[str(path)]), \
                patch.object(profile, "read_document", side_effect=changed_helper), \
                self.assertRaises(ValueError):
            profile.manifest(specification)

    def test_changed_complete_configuration_tree_refuses(self):
        specification = {"artifacts": {role: record["path"] for role, record in bundle["artifacts"].items()},
                         "configuration_tree": bundle["configuration_root"]}
        by_path = {record["path"]: record for record in bundle["artifacts"].values()}
        changed = copy.deepcopy(bundle["model"]["configuration_tree"])
        changed["files"] = "167"
        with patch.object(profile, "measure", side_effect=lambda path: by_path[str(path)]), \
                patch.object(profile, "configuration_tree", return_value=changed), \
                self.assertRaises(ValueError):
            profile.manifest(specification)


if __name__ == "__main__":
    unittest.main()
