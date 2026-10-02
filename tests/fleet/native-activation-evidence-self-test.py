"""Checks native qualification rejects incomplete or misbound crash evidence."""

import copy
import importlib.util
import sys
import unittest
from pathlib import Path


specification = importlib.util.spec_from_file_location("native_activation_evidence", Path(sys.argv[1]))
if specification is None or specification.loader is None:
    raise RuntimeError("cannot load native activation evidence")
EVIDENCE = importlib.util.module_from_spec(specification)
sys.modules[specification.name] = EVIDENCE
specification.loader.exec_module(EVIDENCE)


class NativeEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.cell = "files/filesystem/entry/apply/durability-recovery/lose-external-result"
        handler = {"kind": "process", "artifact": "/nix/store/exact-handler", "executable": "/nix/store/exact-handler/bin/handler"}
        self.matrix = {
            "cells": [{"id": self.cell, "adapter": "files", "operation": {"ability": "filesystem", "name": "entry"}, "action": "apply", "scenario": {"family": "durability-recovery", "id": "lose-external-result"}}],
            "surface": {"adapters": [{"adapter": "files", "handler": handler}]},
        }
        node = {"identity": ["filesystem", "entry", "owned"], "handler": handler, "revision": "graph-revision", "lifetime": "instance", "dependencies": []}
        self.graph = {"schema": "aos.activation.graph", "nodes": {"owned": node}, "order": ["owned"]}
        self.event = {"schema": "aos.activation.boundary", "transaction": "candidate", "effect": "owned", "revision": "resolved-revision", "action": "apply", "journal_sequence": 2, "boundary": "dispatch-returned"}
        dispatch = {"effect": "owned", "revision": "resolved-revision", "action": "apply", "journalSequence": 2}
        self.before = {
            "schema": "aos.activation.inspection", "liveStateVerified": False, "incompleteTailBytes": 0,
            "transaction": "candidate", "pending": dispatch, "completed": None, "desired": self.graph,
            "retainedOutputs": {}, "retiredEffects": [],
            "records": [{"sequence": 1, "event": "begin", "transaction": "candidate", "dispatch": None}, {"sequence": 2, "event": "started", "transaction": "candidate", "dispatch": dispatch}],
        }
        self.after = {
            **self.before, "transaction": None, "pending": None, "desired": None,
            "completed": {"transaction": "candidate", "content": "checked-content"},
            "retainedOutputs": {"owned": {"path": "/run/owned"}},
            "records": [*self.before["records"], {"sequence": 3, "event": "finished", "transaction": "candidate", "dispatch": dispatch}, {"sequence": 4, "event": "commit", "transaction": "candidate", "dispatch": None}],
        }
        self.boundaries = [self.event, {**self.event, "boundary": "observation-started"}, {**self.event, "boundary": "observation-returned"}]
        self.baseline = {"selected": {"exists": False, "owners": []}, "foreign": {"digest": "unchanged"}}
        self.unsettled = {"selected": {"exists": True, "owners": ["native-handler:owned"]}, "foreign": {"digest": "unchanged"}}
        self.settled = copy.deepcopy(self.unsettled)

    def observation(self):
        return EVIDENCE.NativeObservation(self.graph, self.event, self.before, self.after, self.boundaries, self.baseline, self.unsettled, self.settled, {"exists": True, "owners": ["native-handler:owned"]})

    def builder(self):
        return EVIDENCE.NativeEvidence(self.matrix, [self.cell])

    def retained_transition(self, scenario):
        self.cell = "files/filesystem/entry/remove/retained-state/" + scenario
        self.matrix["cells"][0].update(id=self.cell, action="remove", scenario={"family": "retained-state", "id": scenario})
        self.graph["nodes"]["owned"]["lifetime"] = "persistent"
        before = copy.deepcopy(self.after)
        after = copy.deepcopy(before)
        after["records"].extend([
            {"sequence": 5, "event": "begin", "transaction": "source-transition", "dispatch": None},
            {"sequence": 6, "event": "commit", "transaction": "source-transition", "dispatch": None},
        ])
        after["completed"] = {"transaction": "source-transition", "content": "checked-target-content"}
        after["retiredEffects"] = []
        return EVIDENCE.NativeRetainedTransition(
            self.graph, self.graph, {"schema": "aos.activation.graph", "nodes": {}, "order": []},
            "owned", before, after, self.settled, copy.deepcopy(self.settled), copy.deepcopy(self.settled["selected"]),
            {"unit": "native-transition.service", "result": "success", "execMainCode": 1, "execMainStatus": 0},
        )

    def test_persistent_source_disappearance_preserves_original_apply_receipt(self):
        observation = self.retained_transition("retain-persistent-orphan")
        builder = self.builder()
        builder.retain_transition(self.cell, observation)
        payload = builder.finish()[1][self.cell]
        self.assertIn(b'"kind":"persistent-orphan"', payload)
        self.assertIn(b'"priorReceipt":{"dispatch":{"action":"apply"', payload)
        self.assertIn(b'"transition":{"action":"remove"', payload)

    def test_orphan_transition_cannot_fabricate_a_remove_dispatch(self):
        observation = self.retained_transition("retain-persistent-orphan")
        observation.after["records"].append({"sequence": 7, "event": "started", "transaction": "source-transition", "dispatch": {
            "effect": "owned", "revision": "new-remove", "action": "remove", "journalSequence": 7,
        }})
        with self.assertRaisesRegex(ValueError, "dispatched"):
            self.builder().retain_transition(self.cell, observation)

    def test_orphan_transition_cannot_change_the_live_owner_or_inode(self):
        observation = self.retained_transition("retain-persistent-orphan")
        observation.settled["selected"]["inode"] = "another-inode"
        with self.assertRaisesRegex(ValueError, "live resource identity"):
            self.builder().retain_transition(self.cell, observation)

    def test_explicit_retirement_requires_a_real_remove_outcome(self):
        observation = self.retained_transition("retire-explicit-persistent-target")
        with self.assertRaisesRegex(ValueError, "actual single remove"):
            self.builder().retain_transition(self.cell, observation)

    def pending_control(self, scenario, control):
        self.cell = "files/filesystem/entry/apply/durability-recovery/" + scenario
        self.matrix["cells"][0]["id"] = self.cell
        self.matrix["cells"][0]["scenario"]["id"] = scenario
        self.graph["nodes"]["owned"]["timeout_ms"] = 1000
        held = {**self.event, "boundary": "intent-durable"}
        boundaries = [held]
        if scenario == "expire-invocation-deadline":
            boundaries.append({**held, "boundary": "dispatch-started"})
        return EVIDENCE.NativePendingControl(
            self.graph, held, self.before, copy.deepcopy(self.before), boundaries,
            self.baseline, copy.deepcopy(self.baseline), copy.deepcopy(self.baseline["selected"]),
            {"unit": "native-control.service", "result": "exit-code", "execMainCode": 1, "execMainStatus": 1},
            control,
        )

    def test_requested_signal_preserves_pending_ownership_without_dispatch_claim(self):
        observation = self.pending_control("cancel-pending-invocation", {
            "kind": "signal-cancellation", "signal": "SIGTERM", "processId": 123,
            "executable": "/nix/store/admitted-apm/bin/apm",
        })
        builder = self.builder()
        builder.retain_pending_control(self.cell, observation)
        self.assertIn(b'"dispatchAttemptCount":0', builder.finish()[1][self.cell])

    def test_signal_control_rejects_a_dispatch_after_the_held_intent(self):
        observation = self.pending_control("cancel-pending-invocation", {
            "kind": "signal-cancellation", "signal": "SIGTERM", "processId": 123,
            "executable": "/nix/store/admitted-apm/bin/apm",
        })
        observation.boundaries.append({**observation.held, "boundary": "dispatch-started"})
        with self.assertRaisesRegex(ValueError, "unproved dispatch"):
            self.builder().retain_pending_control(self.cell, observation)

    def test_deadline_requires_the_admitted_timeout_and_one_attempt(self):
        observation = self.pending_control("expire-invocation-deadline", {
            "kind": "invocation-deadline", "timeoutMillis": 1000, "elapsedMillis": 1100,
        })
        builder = self.builder()
        builder.retain_pending_control(self.cell, observation)
        self.assertIn(b'"dispatchAttemptCount":1', builder.finish()[1][self.cell])

    def test_short_elapsed_wait_does_not_prove_an_invocation_deadline(self):
        observation = self.pending_control("expire-invocation-deadline", {
            "kind": "invocation-deadline", "timeoutMillis": 1000, "elapsedMillis": 999,
        })
        with self.assertRaisesRegex(ValueError, "admitted native effect limit"):
            self.builder().retain_pending_control(self.cell, observation)

    def test_exact_intent_recovery_and_foreign_oracle_are_retained(self):
        builder = self.builder()
        builder.retain(self.cell, self.observation())
        subjects, evidence, probes = builder.finish()
        self.assertEqual(subjects[self.cell]["resolvedRevision"], "resolved-revision")
        self.assertEqual(subjects[self.cell]["effect"]["revision"], "graph-revision")
        self.assertEqual(probes[self.cell]["disposition"], "checked")
        self.assertIn(b'"liveStateVerified":false', evidence[self.cell])

    def rejection(self):
        self.cell = "files/filesystem/entry/apply/durability-recovery/reject-uncertain-recovery"
        self.matrix["cells"][0]["id"] = self.cell
        self.matrix["cells"][0]["scenario"]["id"] = "reject-uncertain-recovery"
        held = {**self.event, "boundary": "intent-durable"}
        boundaries = [held, {**held, "boundary": "dispatch-started"},
                      {**held, "boundary": "observation-started"},
                      {**held, "boundary": "observation-returned"}]
        return EVIDENCE.NativeRejection(
            self.graph, held, self.before, copy.deepcopy(self.before), boundaries,
            self.baseline, self.settled, copy.deepcopy(self.settled["selected"]),
            {"unit": "native-rejection.service", "result": "exit-code", "execMainCode": 1, "execMainStatus": 1},
        )

    def test_indeterminate_rejection_preserves_pending_intent_and_attempt_inventory(self):
        observation = self.rejection()
        builder = self.builder()
        builder.retain_rejection(self.cell, observation)
        subjects, evidence, probes = builder.finish()
        self.assertEqual(probes[self.cell]["disposition"], "checked")
        self.assertIn(b'"dispatchAttemptCount":1', evidence[self.cell])
        self.assertEqual(subjects[self.cell]["selectedGraphDigest"], EVIDENCE.digest(self.graph))

    def test_unavailable_observation_preserves_pending_without_a_fabricated_reply(self):
        observation = self.rejection()
        observation.boundaries[:] = [event for event in observation.boundaries if event["boundary"] != "observation-returned"]
        self.builder().retain_rejection(self.cell, observation)

    def foreign_rejection(self):
        observation = self.rejection()
        self.matrix["cells"][0]["scenario"]["id"] = "reject-foreign-resource-mutation"
        observation.boundaries[:] = observation.boundaries[:2]
        observation.baseline["selected"] = {"exists": True, "owners": [], "inode": "actual-foreign"}
        observation.settled["selected"] = copy.deepcopy(observation.baseline["selected"])
        observation.expected.clear()
        observation.expected.update(observation.baseline["selected"])
        return observation

    def test_foreign_target_denial_retains_actual_unchanged_substrate(self):
        self.builder().retain_rejection(self.cell, self.foreign_rejection())

    def test_foreign_target_denial_cannot_modify_the_selected_foreign_inode(self):
        observation = self.foreign_rejection()
        observation.settled["selected"]["inode"] = "modified"
        with self.assertRaisesRegex(ValueError, "live target"):
            self.builder().retain_rejection(self.cell, observation)

    def dependency_block(self):
        observation = self.rejection()
        self.matrix["cells"][0]["scenario"]["id"] = "block-dependent-effect"
        observation.boundaries[:] = observation.boundaries[:2]
        self.graph["nodes"]["child"] = {**copy.deepcopy(self.graph["nodes"]["owned"]), "dependencies": ["owned"]}
        physical = {"selected": {"exists": False, "owners": []}, "foreign": {"digest": "child-foreign"}}
        return EVIDENCE.NativeDependencyBlock(**observation.__dict__, dependent="child", dependent_baseline=physical, dependent_settled=copy.deepcopy(physical))

    def test_dependency_barrier_checks_actual_authored_child_and_live_witness(self):
        observation = self.dependency_block()
        self.builder().retain_dependency_block(self.cell, observation)

    def test_dependency_barrier_rejects_a_child_dispatch(self):
        observation = self.dependency_block()
        observation.after["records"].append({"sequence": 3, "event": "started", "transaction": "candidate", "dispatch": {"effect": "child", "action": "apply"}})
        with self.assertRaisesRegex(ValueError, "dependent acquired"):
            self.builder().retain_dependency_block(self.cell, observation)

    def test_removal_barrier_requires_reverse_retirement_order(self):
        observation = self.dependency_block()
        self.matrix["cells"][0]["action"] = "remove"
        with self.assertRaisesRegex(ValueError, "action ordering"):
            self.builder().retain_dependency_block(self.cell, observation)

    def test_indeterminate_rejection_cannot_hide_a_second_dispatch_attempt(self):
        observation = self.rejection()
        observation.boundaries.append({**observation.held, "boundary": "dispatch-started"})
        with self.assertRaisesRegex(ValueError, "another dispatch"):
            self.builder().retain_rejection(self.cell, observation)

    def test_rejection_cannot_manufacture_an_outcome(self):
        observation = self.rejection()
        observation.after["records"].append({"sequence": 3, "event": "finished", "transaction": "candidate", "dispatch": observation.after["pending"]})
        with self.assertRaisesRegex(ValueError, "outcome"):
            self.builder().retain_rejection(self.cell, observation)

    def test_unexecuted_cells_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "unexecuted"):
            self.builder().finish()

    def test_foreign_substrate_mutation_is_rejected(self):
        self.settled["foreign"]["digest"] = "changed"
        with self.assertRaisesRegex(ValueError, "foreign"):
            self.builder().retain(self.cell, self.observation())

    def test_recovery_must_observe_exact_resolved_intent(self):
        self.boundaries[-1]["revision"] = "another-revision"
        with self.assertRaisesRegex(ValueError, "observed"):
            self.builder().retain(self.cell, self.observation())

    def test_unsettled_dependency_must_not_dispatch(self):
        self.graph["nodes"]["dependent"] = {"dependencies": ["owned"]}
        self.before["records"].append({"sequence": 3, "event": "started", "transaction": "candidate", "dispatch": {"effect": "dependent"}})
        with self.assertRaisesRegex(ValueError, "dependent"):
            self.builder().retain(self.cell, self.observation())

    def test_selected_handler_must_match_native_matrix(self):
        self.graph["nodes"]["owned"]["handler"] = {"kind": "process", "artifact": "foreign", "executable": "foreign/bin/handler"}
        with self.assertRaisesRegex(ValueError, "handler"):
            self.builder().retain(self.cell, self.observation())

    def test_ownership_must_come_from_an_independent_single_owner_inventory(self):
        self.settled["selected"]["owners"].append("other-owner")
        self.settled["selected"]["owners"].sort()
        with self.assertRaisesRegex(ValueError, "multiple owners"):
            self.builder().retain(self.cell, self.observation())

    def test_settled_substrate_must_match_operator_expected_target(self):
        self.settled["selected"]["exists"] = False
        with self.assertRaisesRegex(ValueError, "expected target"):
            self.builder().retain(self.cell, self.observation())

    def test_torn_prefix_does_not_qualify_a_recovery(self):
        self.before["incompleteTailBytes"] = 1
        with self.assertRaisesRegex(ValueError, "complete"):
            self.builder().retain(self.cell, self.observation())


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
