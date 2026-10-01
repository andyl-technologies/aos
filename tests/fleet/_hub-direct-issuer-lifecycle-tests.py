"""Check issuer observation invariants with controlled signed-reply projections.

The shared Rust verifier authenticates actual replies in the fleet. These source
tests cover caller assertions and generated guest programs only, not signatures,
issuer persistence, process termination or provider qualification.
"""

import ast
import copy
import importlib.util
import json
from pathlib import Path
import textwrap
import unittest
from unittest.mock import patch


specification = importlib.util.spec_from_file_location("issuer_lifecycle",
    Path(__file__).with_name("_hub-direct-issuer-lifecycle.py"))
lifecycle = importlib.util.module_from_spec(specification)
specification.loader.exec_module(lifecycle)


class IssuerLifecycleInvariants(unittest.TestCase):
    def issue(self):
        cohort = {"attestation_valid_until": "200"}
        timing = {"maximum_lifetime": "30"}
        payload = {"cohort": cohort, "timing_profile": timing,
            "issued_at": "100", "not_after": "130", "lease_sequence": "7"}
        exchange = {"verified": {"tokenSha256": "a" * 64},
            "reply": {"lease": json.dumps({"payload": payload}),
                "current": {"journal": {"largest_issued_expiry": "130"}}}}
        return exchange, cohort, timing

    def test_actual_lease_projection_retains_ttl_and_sequence(self):
        result = lifecycle.assert_direct_issuer_issue(*self.issue())
        self.assertEqual(result["lifetimeSeconds"], 30)
        self.assertEqual(result["leaseSequence"], "7")
        self.assertEqual(result["tokenSha256"], "a" * 64)
        self.assertNotIn("lease", result)

    def test_missing_lease_wrong_cohort_and_expiry_floors_refuse(self):
        for field, value in (("cohort", {"attestation_valid_until": "201"}),
                             ("not_after", "131"), ("not_after", "100")):
            exchange, cohort, timing = self.issue()
            payload = json.loads(exchange["reply"]["lease"])
            payload["payload"][field] = value
            exchange["reply"]["lease"] = json.dumps(payload)
            with self.assertRaises(ValueError):
                lifecycle.assert_direct_issuer_issue(exchange, cohort, timing)
        exchange, cohort, timing = self.issue()
        exchange["reply"]["lease"] = None
        with self.assertRaises(ValueError):
            lifecycle.assert_direct_issuer_issue(exchange, cohort, timing)

    def test_cold_resource_epoch_and_history_cannot_change_or_rewind(self):
        journal = {"authority": "a", "executor_identity": "e", "generation": "2",
            "admission_digest": "a" * 64, "publication_digest": "b" * 64,
            "state": "admitted", "policy": {"timing_profile": {}},
            "last_sequence": "7", "largest_issued_expiry": "130", "clock_floor": "100"}
        before = {"reply": {"current": {"installation": {"resource": "retained"},
            "journal": journal}}, "verified": {"journalSha256": "c" * 64}}
        after = copy.deepcopy(before)
        self.assertEqual(lifecycle.assert_direct_issuer_cold_head(before, after)["lastSequence"], "7")
        for field, value in (("generation", "3"), ("last_sequence", "6"),
                             ("largest_issued_expiry", "129"), ("clock_floor", "99")):
            changed = copy.deepcopy(after)
            changed["reply"]["current"]["journal"][field] = value
            with self.assertRaises(ValueError):
                lifecycle.assert_direct_issuer_cold_head(before, changed)

    def test_terminal_cold_refusal_pins_original_and_preserves_unresolved_history(self):
        programs = []
        def guest(machine, python, body, selected, timeout):
            ast.parse(textwrap.dedent(body))
            self.assertGreaterEqual(timeout, 40)
            programs.append((body, selected))
            return json.dumps({"pid": 42})
        with patch.multiple(lifecycle, direct_guest_python=guest,
                retain_direct_flow=lambda *args: None, create=True):
            lifecycle.observe_direct_issuer_cold_refusal(None,
                {"python": "controlled", "authority": "/immutable/aos-hub-authority"},
                {"pid": 41, "startTicks": "10", "executableSha256": "d" * 64},
                {"reply": {"current": {"journal": {}, "installation": {}}}})
        body, selected = programs[0]
        self.assertEqual(selected["original"]["pid"], 41)
        self.assertIn("os.pidfd_open", body)
        self.assertIn("signal.pidfd_send_signal", body)
        self.assertIn("'serve'", body)
        self.assertNotIn("'initialize'", body)
        self.assertNotIn("SIGKILL", body)
        self.assertIn("?mode=ro", body)
        self.assertIn("unresolved clock session requires explicit reviewed operator resolution", body)
        self.assertIn("history() != retained_history", body)
        self.assertNotIn("UPDATE", body)
        self.assertNotIn("DELETE", body)


if __name__ == "__main__":
    unittest.main()
