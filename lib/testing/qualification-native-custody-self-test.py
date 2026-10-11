"""Tests original executor source custody independently of scenario catalogs."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import unittest
import sys

SPEC = importlib.util.spec_from_file_location("native_custody", Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("qualification-native-custody.py"))
CUSTODY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CUSTODY)
ROOT = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-synthetic-source"
HASH = "sha256:" + "a" * 64


class NativeCustodyTests(unittest.TestCase):
    def setUp(self):
        self.inventory = {"schema": "aos.reference-graph/v1", "roots": [ROOT], "subtractRoots": [],
                          "paths": [{"path": ROOT, "narHash": HASH, "narSize": 42, "references": []}]}
        self.evaluations = {"cohort": {
            "selected_evaluation": {"role": "scenario", "locator": ROOT, "scenario_sources": [ROOT + "/future.nix"]},
            "adoption_evaluation": {"role": "scenario", "locator": ROOT, "scenario_sources": [ROOT + "/inactive.nix"]},
        }}
        self.registry = {"scenarios": {"gate": ROOT + "/bin/run"}, "fixture_inputs": {ROOT + "/bin/run": {"archive": {}, "inventory": {}, "evaluations": {}}}}
        self.request = {"policy_id": "gate", "qualification_case": {"id": "gate/release"}}
        self.paths = {key: Path(ROOT + "/" + key) for key in ("archive", "inventory", "evaluations")}

    def read(self, identity, expected, *, document):
        return json.dumps(self.inventory if expected.name == "inventory" else self.evaluations).encode() if document else None

    def verify(self):
        with patch.object(CUSTODY, "verify_file", side_effect=self.read):
            return CUSTODY.verify_fixture_inputs(self.registry, self.request, self.paths, self.evaluations, lambda value: value)

    def test_original_fixture_inventory_supplies_source_identity(self):
        self.assertEqual(self.verify()[ROOT]["narHash"], HASH)

    def test_cross_role_source_swap_does_not_match_original_executor_commitment(self):
        expected = copy.deepcopy(self.evaluations)
        binding = self.evaluations["cohort"]
        binding["selected_evaluation"], binding["adoption_evaluation"] = binding["adoption_evaluation"], binding["selected_evaluation"]
        with patch.object(CUSTODY, "verify_file", side_effect=self.read):
            with self.assertRaisesRegex(RuntimeError, "exact authored case"):
                CUSTODY.verify_fixture_inputs(self.registry, self.request, self.paths, expected, lambda value: value)

    def test_inactive_adoption_preserves_frozen_catalog_with_distinct_sources(self):
        target = {"library": ROOT + "/lib/default.nix", "libraryNarHash": HASH,
                  "scope": ["profile", "system"], "packages": {"system": "x86_64-linux", "artifacts": []},
                  "configuration": [ROOT + "/future.nix"]}
        baseline = copy.deepcopy(target)
        baseline["configuration"].append(ROOT + "/inactive.nix")
        CUSTODY.validate_evaluation_contexts(target, baseline)

    def test_adoption_cannot_change_library_scope_or_package_selection(self):
        target = {"library": ROOT + "/lib/default.nix", "libraryNarHash": HASH,
                  "scope": ["profile", "system"], "packages": {"system": "x86_64-linux", "artifacts": []}}
        for key, value in (("library", ROOT + "/foreign.nix"), ("libraryNarHash", "sha256:" + "b" * 64),
                           ("scope", ["foreign"]), ("packages", {"system": "aarch64-linux", "artifacts": []})):
            with self.subTest(field=key):
                adopted = target | {key: value}
                with self.assertRaisesRegex(RuntimeError, "selected library or package catalog"):
                    CUSTODY.validate_evaluation_contexts(target, adopted)

    def test_adoption_command_uses_inactive_baseline_and_its_original_receipt(self):
        baseline = ROOT + "-baseline"
        cohort = {"selectedEvaluation": {"locator": ROOT}, "adoptionEvaluation": {"locator": baseline}}
        documents = {ROOT: {"admission.json": b"future target bytes"},
                     baseline: {"admission.json": b"original inactive baseline bytes"}}
        command = CUSTODY.adoption_invocation(cohort, documents, ROOT + "/bin/driver", ROOT + "/bin/nix-store", "/var/lib/profiles/system")
        self.assertEqual(command[2], baseline)
        self.assertEqual(command[3], "sha256:" + hashlib.sha256(documents[baseline]["admission.json"]).hexdigest())
        self.assertEqual(command[1], "adopt-native-fixture")
        self.assertEqual(documents[ROOT]["admission.json"], b"future target bytes")

    def test_adoption_does_not_fall_back_to_selected_future_target(self):
        cohort = {"selectedEvaluation": {"locator": ROOT}, "adoptionEvaluation": {"locator": ROOT + "-baseline"}}
        with self.assertRaisesRegex(RuntimeError, "authenticated documents"):
            CUSTODY.adoption_invocation(cohort, {ROOT: {"admission.json": b"future bytes"}}, ROOT + "/bin/driver", ROOT + "/bin/nix-store", "/var/lib/profiles/system")

    def test_missing_original_executor_binding_fails(self):
        self.registry["fixture_inputs"] = {}
        with self.assertRaises(RuntimeError):
            self.verify()

    def test_duplicate_root_and_missing_reference_fail(self):
        for mutation in (lambda: self.inventory["paths"].append(copy.deepcopy(self.inventory["paths"][0])),
                         lambda: self.inventory["paths"][0].update(references=[ROOT + "-missing"])):
            self.setUp()
            mutation()
            with self.assertRaises(RuntimeError):
                self.verify()

    def test_untrusted_catalog_cannot_change_original_nar_hash(self):
        original = self.verify()
        catalog = {"roots": [{"storePath": ROOT, "narHash": "sha256:" + "b" * 64, "narSize": 42, "references": []}]}
        with self.assertRaises(RuntimeError):
            CUSTODY.verify_admission(catalog, original)

    def test_realized_metadata_mismatch_fails_before_content_validation(self):
        original = self.verify()
        with patch.object(CUSTODY.subprocess, "run", return_value=SimpleNamespace(stdout="sha256:" + "b" * 64)) as run:
            with self.assertRaises(RuntimeError):
                CUSTODY.verify_realized_roots({ROOT}, original, ROOT + "/bin/nix-store", lambda value: value)
            self.assertEqual(run.call_count, 1)

    def test_self_reported_digest_cannot_admit_a_mutable_file(self):
        with self.assertRaises(RuntimeError):
            CUSTODY.verify_file({"path": "/tmp/scenario", "sha256": HASH, "size_bytes": 42}, Path("/tmp/scenario"), document=True)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
