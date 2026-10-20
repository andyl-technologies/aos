"""Check issuer observation invariants with controlled signed-reply projections.

The shared Rust verifier authenticates actual replies in the fleet. These source
tests cover caller assertions and generated guest programs only, not signatures,
issuer persistence, process termination or provider qualification.
"""

import ast
import copy
import importlib.util
import json
import hashlib
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
        self.assertIn("for name in ('signing-seed.key', 'publisher.key', 'renewal.key'):", body)
        secret_section = body.split("for name in ('signing-seed.key', 'publisher.key', 'renewal.key'):", 1)[1].split(
            "for name in ('configuration.json', 'issuer-public-key.hex'):", 1)[0]
        self.assertIn(".lstat()", secret_section)
        self.assertNotIn("os.open", secret_section)
        self.assertNotIn(".open(", secret_section)
        self.assertNotIn("read", secret_section)
        self.assertNotIn("hashlib", secret_section)


class ColdRecoveryBoundaries(unittest.TestCase):
    def facts(self):
        policy = {"version": 1, "reviewer_key_id": "independent",
            "reviewer_public_key": "a" * 64, "resource_qualification_digest": "b" * 64,
            "clock_qualification_digest": "c" * 64, "maximum_review_seconds": "30",
            "clock_uncertainty": "1", "clock_commit_latency": "1"}
        head = {"installation": {"resource": "original"},
            "journal": {"clock_floor": "100", "largest_issued_expiry": "120"}}
        refusal = {"retainedHistory": {"clockFloor": "100", "clockCeiling": "103",
                "clockSessionSha256": hashlib.sha256(('d' * 64).encode()).hexdigest()},
            "retainedResource": {"journalDevice": 1, "journalInode": 2,
                "journalParentDevice": 3, "journalParentInode": 4}}
        plan = {"version": 1, "file": {"device": "1", "inode": "2", "parent_device": "3", "parent_inode": "4"},
            "expected_head": head, "expected_session": "d" * 64,
            "expected_floor": "100", "expected_ceiling": "103",
            "policy_digest": hashlib.sha256(json.dumps(policy, separators=(',', ':')).encode()).hexdigest(),
            "successor_session": "e" * 64, "nonce": "f" * 64, "issued_at": "123", "expires_at": "153"}
        return policy, {"reply": {"current": head}}, refusal, plan

    def test_actual_plan_joins_original_head_file_policy_session_and_finite_time(self):
        policy, before, refusal, plan = self.facts()
        lifecycle._assert_direct_clock_plan(plan, policy, before, refusal)
        for field, value in (("expected_head", {}), ("version", True), ("expected_ceiling", "102"),
                ("successor_session", "d" * 64), ("expires_at", "154"),
                ("expires_at", "123"), ("issued_at", "0123"), ("expected_session", "0" * 64),
                ("expires_at", str(2**63))):
            changed = copy.deepcopy(plan)
            changed[field] = value
            with self.assertRaises(ValueError):
                lifecycle._assert_direct_clock_plan(changed, policy, before, refusal)
        changed = copy.deepcopy(plan)
        changed["file"]["inode"] = "99"
        with self.assertRaises(ValueError):
            lifecycle._assert_direct_clock_plan(changed, policy, before, refusal)

    def test_signed_review_must_match_exact_compact_source_field_order_without_rewrite(self):
        policy, before, refusal, plan = self.facts()
        plan_bytes = json.dumps(plan, separators=(',', ':')).encode()
        review = {"version": 1, "plan": plan, "plan_digest": hashlib.sha256(plan_bytes).hexdigest(),
            "reviewer_key_id": policy["reviewer_key_id"], "signature": "8" * 128}
        canonical = json.dumps(review, separators=(',', ':')).encode()
        self.assertEqual(lifecycle._assert_direct_clock_review_bytes(canonical, plan_bytes, policy), review)
        noncanonical = [json.dumps(review).encode(), canonical + b'\n',
            json.dumps(dict(reversed(list(review.items()))), separators=(',', ':')).encode()]
        reordered = copy.deepcopy(review)
        reordered['plan'] = dict(reversed(list(plan.items())))
        noncanonical.append(json.dumps(reordered, separators=(',', ':')).encode())
        for body in noncanonical:
            with self.assertRaisesRegex(ValueError, "canonical"):
                lifecycle._assert_direct_clock_review_bytes(body, plan_bytes, policy)
        for field, value in (("version", True), ("reviewer_key_id", "other"),
                ("plan_digest", "0" * 64), ("signature", "8" * 127)):
            changed = copy.deepcopy(review)
            changed[field] = value
            with self.assertRaises(ValueError):
                lifecycle._assert_direct_clock_review_bytes(json.dumps(changed, separators=(',', ':')).encode(),
                    plan_bytes, policy)

    def test_resolve_guest_enforces_original_deadline_and_never_refreshes_or_signs(self):
        programs, retained = [], []
        def guest(machine, python, body, selected, timeout):
            ast.parse(textwrap.dedent(body))
            self.assertEqual(timeout, 10)
            programs.append((body, selected))
            return json.dumps({"category": "deadline_unknown", "exitCode": None})
        with patch.multiple(lifecycle, direct_guest_python=guest,
                retain_direct_flow=lambda name, value: retained.append((name, value)), create=True):
            with self.assertRaisesRegex(RuntimeError, "without retry"):
                lifecycle._run_direct_clock_operator(None, {"python": "unused", "authority": "/immutable/authority"},
                    "resolve", expires_at=153, uncertainty=3)
        body, selected = programs[0]
        self.assertEqual(selected["arguments"][1], "resolve-clock-session")
        self.assertNotIn("sign-clock-resolution", body)
        self.assertNotIn("reviewer-seed", body)
        self.assertIn("selected['expiresAt'] - selected['uncertainty'] - time.time()", body)
        self.assertEqual(len(retained), 1)

    def test_generated_positive_observer_is_readonly_and_joins_single_consumption(self):
        programs = []
        def guest(machine, python, body, selected, timeout):
            ast.parse(textwrap.dedent(body))
            programs.append(body)
            return json.dumps({"version": 1})
        policy, before, refusal, plan = self.facts()
        with patch.multiple(lifecycle, direct_guest_python=guest,
                retain_direct_flow=lambda *args: None, create=True):
            lifecycle._observe_direct_clock_recovery(None, {"python": "unused"}, {}, refusal, plan, "0" * 64)
        body = programs[0]
        self.assertIn("?mode=ro", body)
        self.assertIn("counts != [1, 1]", body)
        self.assertIn("PRAGMA application_id", body)
        self.assertIn("os.O_NOFOLLOW", body)
        self.assertIn("opened.st_nlink != 1", body)
        self.assertIn("not stat.S_ISREG(metadata.st_mode)", body)
        self.assertIn("not stat.S_ISDIR(parent.st_mode)", body)
        self.assertIn("history_digest != selected['history']['historySha256']", body)
        self.assertNotIn("UPDATE", body)
        self.assertNotIn("DELETE", body)
        secret = body.split("if isinstance(expected, dict):", 1)[1].split("else:", 1)[0]
        self.assertNotIn(".open(", secret)
        self.assertNotIn("read", secret)

    def test_positive_recovery_expired_review_stops_before_resolve_or_start(self):
        policy, before, refusal, plan = self.facts()
        authority = {"issuer": {"configuration": {"clock_commit_latency": "1"}},
            "issuerProcess": {"pid": 7}, "exported": {"bootstrap": {
                "timing_profile": {"maximum_lifetime": "120", "maximum_clock_uncertainty": "3"},
                "issuer_key_id": "issuer", "clock_uncertainty": "1", "issuer_public_key": "1" * 64}}}
        operations, starts, clock_samples = [], [], []
        def guest(machine, python, body, selected, timeout):
            ast.parse(textwrap.dedent(body))
            if "maximumWait" in selected:
                clock_samples.append(selected)
                return json.dumps({"observedAt": "123"})
            return "0.0"
        with patch.multiple(lifecycle, validate_direct_clock_recovery_policy=lambda *args: policy,
                exchange_direct_issuer=lambda *args: before,
                observe_direct_issuer_cold_refusal=lambda *args, **kwargs: refusal,
                direct_guest_python=guest, _run_direct_clock_operator=lambda *args, **kwargs: operations.append(args[2]),
                read_direct_guest_file=lambda *args: json.dumps(plan, separators=(',', ':')).encode(),
                start_external_issuer=lambda *args, **kwargs: starts.append(True),
                retain_direct_flow=lambda *args: None, create=True):
            with self.assertRaisesRegex(ValueError, "expired"):
                lifecycle.run_direct_issuer_cold_recovery(None, None, {"python": "unused"}, None,
                    authority, policy, lambda *args: self.fail("expired original cannot reach reviewer"),
                    maximum_wait_seconds=120)
        self.assertEqual(operations, ["inspect"])
        self.assertEqual(starts, [])
        self.assertEqual(clock_samples[0]["eligibleAt"], 123)
        self.assertTrue(authority["issuerProcessStopped"])


    def test_positive_order_requires_review_resolve_consumption_and_both_new_leases(self):
        policy, before, refusal, plan = self.facts()
        refusal.update({"oldPid": 7, "oldStartTicks": "10", "executableSha256": "9" * 64})
        authority = {"issuer": {"configuration": {"clock_commit_latency": "1"}},
            "issuerProcess": {"pid": 7}, "exported": {"bootstrap": {
                "timing_profile": {"maximum_lifetime": "120", "maximum_clock_uncertainty": "3"},
                "issuer_key_id": "issuer", "clock_uncertainty": "1", "issuer_public_key": "1" * 64,
                "read_cohort": {"purpose": "read"}, "write_cohort": {"purpose": "write"}}}}
        plan_bytes = json.dumps(plan, separators=(',', ':')).encode()
        review = {"version": 1, "plan": plan, "plan_digest": hashlib.sha256(plan_bytes).hexdigest(),
            "reviewer_key_id": policy["reviewer_key_id"], "signature": "8" * 128}
        resolution = {"version": 1, "review": review, "observed_at": "124", "uncertainty": "3"}
        process = {"pid": 8, "startTicks": "20", "executableSha256": "9" * 64}
        events = []
        def exchange(*args):
            operation, label = args[5:7]
            events.append(label)
            if operation['kind'] == 'current':
                return {**before, "verified": {"observedAtSeconds": 124}}
            return {"verified": {"observedAtSeconds": 125}}
        def guest(machine, python, body, selected, timeout):
            ast.parse(textwrap.dedent(body))
            if "maximumWait" in selected:
                events.append('wait')
                return json.dumps({"observedAt": "123"})
            return '25.0'
        def read(machine, python, path, limit):
            return plan_bytes if path.endswith('/plan.json') else json.dumps(resolution).encode()
        def review_once(actual_plan, actual_policy, deadline):
            self.assertEqual(actual_plan, plan_bytes)
            self.assertEqual(json.loads(actual_policy), policy)
            self.assertGreater(deadline, 100.0)
            events.append('independent-review')
            return json.dumps(review, separators=(',', ':')).encode()
        def operator(*args, **kwargs):
            events.append(args[2])
        def start(*args, **kwargs):
            self.assertEqual(kwargs['startup_label'], 'cold-recovered')
            self.assertEqual(kwargs['recovery_expires_at'], 153)
            self.assertEqual(kwargs['recovery_uncertainty'], 3)
            events.append('start')
            return process
        def consume(*args):
            events.append('consume')
            return {"resolutionCount": 1, "consumptionCount": 1}
        with patch.multiple(lifecycle, validate_direct_clock_recovery_policy=lambda *args: policy,
                exchange_direct_issuer=exchange, observe_direct_issuer_cold_refusal=lambda *args, **kwargs: refusal,
                direct_guest_python=guest, _run_direct_clock_operator=operator,
                read_direct_guest_file=read, install_direct_guest_file=lambda *args: events.append('install-review'),
                start_external_issuer=start, _observe_direct_clock_recovery=consume,
                assert_direct_issuer_cold_head=lambda *args: {"sameHead": True},
                assert_direct_issuer_issue=lambda exchange, cohort, timing: {"purpose": cohort['purpose']},
                retain_direct_flow=lambda *args: None, create=True), patch('time.monotonic', return_value=100.0):
            result = lifecycle.run_direct_issuer_cold_recovery(None, None, {"python": "unused", "authority": "unused"},
                None, authority, policy, review_once, maximum_wait_seconds=120)
        self.assertEqual(events, ['cold-before', 'wait', 'inspect', 'independent-review', 'install-review',
            'resolve', 'start', 'consume', 'cold-after', 'cold-recovered-read', 'cold-recovered-write'])
        self.assertEqual(result['positiveColdRecovery'], 'observed')
        self.assertEqual([value['purpose'] for value in result['issuedCohorts']], ['read', 'write'])
        self.assertEqual(authority['issuerProcess'], process)
        self.assertFalse(authority['issuerProcessStopped'])


if __name__ == "__main__":
    unittest.main()
