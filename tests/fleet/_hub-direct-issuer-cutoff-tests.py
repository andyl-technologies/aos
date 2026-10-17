"""Check issuer cutoff orchestration with controlled SQL and transport peers.

These tests do not issue root decisions, sign leases, change a provider, wait for
a runtime cutoff or prove persisted state. Actual fleet assertions remain live.
"""

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


specification = importlib.util.spec_from_file_location("issuer_cutoff",
    Path(__file__).with_name("_hub-direct-issuer-cutoff.py"))
cutoff = importlib.util.module_from_spec(specification)
specification.loader.exec_module(cutoff)


class IssuerCutoffOrchestration(unittest.TestCase):
    def run_scenario(self, wrong_conflict=False, changed_head=False, expired=False):
        selected = {"authorityId": "actual-selected", "guardNamespaceId": "selected-namespace"}
        bootstrap = {"clock_uncertainty": "1", "issuer_installation": {},
            "timing_profile": {"maximum_clock_uncertainty": "3"}}
        authority = {"review": {"selection": {"authority": selected}},
            "exported": {"bootstrap": bootstrap}}
        desired = [{"desiredGeneration": str(index), "digest": str(index) * 64,
            "decision": {"state": "STORAGE_AUTHORITY_DESIRED_STATE_ADMITTED",
                "attestationId": "selected-attestation", "associationIds": ["selected-association"]}}
            for index in (1, 2, 3)]
        calls, clocks = [], iter([100, 100, 113] if not expired else [113])
        head_index = iter(range(3))
        class Controls:
            def call(self, service, method, request):
                return {"desiredAdmission": desired[next(head_index)]}
            def authority_decision(self, decision, version, label):
                calls.append((decision, version, label))
        def publication(worker, native, tools, authority, observed, label):
            state = "blocked" if label == "blocked" else "admitted"
            return {"publication": {"generation": int(observed["desiredGeneration"]),
                "digest": observed["digest"], "admission": {"state": state}}, "receipt": {"state": state}}
        def exchange(native, worker, tools, helper, bootstrap, operation, label,
                     previous_observed=0, role="renewal"):
            calls.append((label, role))
            if label == "cutoff-premature":
                raise RuntimeError("controlled actual transport conflict")
            generation = "1" if label == "cutoff-before" else "3" if label == "cutoff-reopened" else "2"
            journal = {"generation": generation, "admission_digest": generation * 64,
                "largest_issued_expiry": "110", "state": "blocked"}
            if changed_head and label == "cutoff-conflict-head":
                journal["generation"] = "9"
            return {"reply": {"current": {"journal": journal}, "applied": {}},
                "verified": {"observedAtSeconds": 100, "journalSha256": "a" * 64}}
        configuration = {"clock_uncertainty": "1", "clock_commit_latency": "1",
            "installation": bootstrap["issuer_installation"], "policy": {"timing_profile": bootstrap["timing_profile"]}}
        bindings = {"read_direct_guest_file": lambda *args: json.dumps(configuration).encode(),
            "exchange_direct_issuer": exchange,
            "export_direct_issuer_control": publication,
            "assert_direct_issuer_published": lambda *args: None,
            "direct_guest_python": lambda *args: str(next(clocks)),
            "retain_direct_flow": lambda *args: None}
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "conflict.json"
            receipt.write_text(json.dumps({"status": 403 if wrong_conflict else 409,
                "exitCode": 0, "stderrBytes": 0, "requestSha256": "a" * 64}))
            prepared = Path(directory) / "prepare.json"
            prepared.write_text(json.dumps({"stdout": json.dumps({
                "observedAtSeconds": 100, "requestSha256": "a" * 64})}))
            original_read = Path.read_bytes
            def read(path):
                if str(path) == "external-direct-flow/issuer-transport-cutoff-premature.json":
                    return original_read(receipt)
                if str(path) == "external-direct-flow/shared-control-issuer-prepare-cutoff-premature.json":
                    return original_read(prepared)
                return original_read(path)
            with patch.multiple(cutoff, **bindings, create=True), patch.object(Path, "read_bytes", read):
                result = cutoff.run_direct_issuer_cutoff(None, None,
                    {"python": "controlled"}, {}, Controls(), authority)
        return result, calls

    def test_actual_predecessor_membership_and_conflict_before_reopen(self):
        result, calls = self.run_scenario()
        decisions = [row for row in calls if isinstance(row[0], dict)]
        self.assertEqual([row[1] for row in decisions], ["1", "2"])
        self.assertEqual(decisions[1][0]["setAdmission"]["associationIds"], ["selected-association"])
        self.assertEqual(result["prematureConflict"]["status"], 409)
        self.assertEqual(result["actualNativeClockObservations"], [113])
        self.assertEqual(result["clockUncertaintySeconds"], 3)
        self.assertFalse(result["installedConsumerProfileAutomaticallyUpdated"])
        self.assertEqual([row for row in calls if row[0] == "cutoff-reopened"],
            [("cutoff-reopened", "publisher")])

    def test_wrong_auth_refusal_or_changed_head_never_reopens(self):
        with self.assertRaisesRegex(RuntimeError, "no fresh exact TLS conflict"):
            self.run_scenario(wrong_conflict=True)
        with self.assertRaisesRegex(ValueError, "signed issuer head changed"):
            self.run_scenario(changed_head=True)

    def test_already_elapsed_floor_cannot_fabricate_a_premature_refusal(self):
        with self.assertRaisesRegex(RuntimeError, "already passed"):
            self.run_scenario(expired=True)

    def test_live_publication_requires_exact_state_generation_digest_and_ack(self):
        publication = {"generation": 2, "digest": "b" * 64, "admission": {"state": "blocked"}}
        exchange = {"reply": {"current": {"journal": {"generation": "2",
            "admission_digest": "b" * 64, "state": "blocked"}}, "applied": {}}}
        cutoff.assert_direct_issuer_published(exchange, publication)
        for field, value in (("generation", "3"), ("admission_digest", "c" * 64), ("state", "admitted")):
            changed = copy.deepcopy(exchange)
            changed["reply"]["current"]["journal"][field] = value
            with self.assertRaises(ValueError):
                cutoff.assert_direct_issuer_published(changed, publication)
        exchange["reply"]["applied"] = None
        with self.assertRaises(ValueError):
            cutoff.assert_direct_issuer_published(exchange, publication)

    def test_expired_original_or_elapsed_floor_cannot_prove_cutoff_rejection(self):
        transport = {"status": 409, "exitCode": 0, "stderrBytes": 0, "requestSha256": "a" * 64}
        prepared = {"observedAtSeconds": 100, "requestSha256": "a" * 64}
        cutoff.assert_direct_issuer_cutoff_conflict(transport, prepared, 101, 120, 1)
        for observed, floor in ((130, 140), (99, 120), (121, 120)):
            with self.assertRaises(RuntimeError):
                cutoff.assert_direct_issuer_cutoff_conflict(transport, prepared, observed, floor, 1)


if __name__ == "__main__":
    unittest.main()
