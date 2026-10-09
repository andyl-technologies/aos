"""Exercises native interruption, isolation, custody, and replay rejection."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path


COHORT_PATH = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(COHORT_PATH.parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "qualification/providers"))
SPEC = importlib.util.spec_from_file_location("native_cohort", COHORT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load native cohort validator")
COHORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COHORT)
from native_adapter_evidence_common import canonical, sha256


def fleet_producer():
    producer_path = (
        Path(sys.argv[2]) if len(sys.argv) > 2
        else Path(__file__).resolve().parents[2] / "tests/fleet/native-activation-evidence.py"
    )
    specification = importlib.util.spec_from_file_location("native_fleet_producer", producer_path)
    if specification is None or specification.loader is None:
        raise RuntimeError("cannot load native fleet evidence producer")
    producer = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = producer
    specification.loader.exec_module(producer)
    return producer


class NativeCohortTests(unittest.TestCase):
    def setUp(self):
        self.cell_id = "files/filesystem/entry/apply/durability-recovery/lose-external-result"
        handler = {
            "kind": "process",
            "artifact": "/nix/store/exact-handler",
            "executable": "/nix/store/exact-handler/bin/handler",
        }
        effect = {
            "id": "owned",
            "identity": ["filesystem", "entry", "owned"],
            "revision": "graph-revision",
            "lifetime": "instance",
            "dependencies": [],
        }
        operation = {"ability": "filesystem", "name": "entry"}
        self.cell = {
            "id": self.cell_id,
            "adapter": "files",
            "operation": operation,
            "action": "apply",
            "applicability": {"required_actions": [], "required_resource_lifetimes": [], "requires_state_format": False},
            "scenario": {"family": "durability-recovery", "id": "lose-external-result"},
            "boundary": "after-external-return",
            "failure": "lost-result",
            "candidate": "same",
            "predecessor": "same",
            "disposition": {"kind": "exact", "value": "reconciled-completed"},
            "postconditions": [
                "durable-attempt-state-classified",
                "at-most-one-resource-owner",
                "foreign-resources-unchanged",
                "dependent-effects-not-executed",
            ],
            "postcondition_kinds": {
                "durable-attempt-state-classified": "journal-timeline",
                "at-most-one-resource-owner": "ownership-inventory",
                "foreign-resources-unchanged": "foreign-resource-snapshot",
                "dependent-effects-not-executed": "dependency-barrier",
            },
        }
        adapter = {"adapter": "files", "operation": operation, "handler": handler, "effects": [effect]}
        self.matrix = {
            "schema": "aos.qualification.native-operation-matrix-spec",
            "required_operations": [operation],
            "cells": [self.cell],
            "surface": {
                "adapters": [adapter],
            },
            "applicability": {
                "schema": "aos.qualification.native-operation-matrix-applicability",
                "applicable_cell_ids": [self.cell_id],
                "inapplicable_cells": [],
            },
        }
        node = {key: value for key, value in effect.items() if key != "id"} | {"handler": handler}
        graph = {"schema": "aos.activation.graph", "nodes": {"owned": node}, "order": ["owned"]}
        dispatch = {
            "effect": "owned",
            "revision": "resolved-revision",
            "action": "apply",
            "journalSequence": 2,
        }
        before = {
            "schema": "aos.activation.inspection",
            "liveStateVerified": False,
            "incompleteTailBytes": 0,
            "transaction": "candidate",
            "pending": dispatch,
            "completed": None,
            "desired": graph,
            "retainedOutputs": {},
            "retiredEffects": [],
            "records": [
                {
                    "sequence": 1,
                    "event": "begin",
                    "transaction": "candidate",
                    "dispatch": None,
                },
                {
                    "sequence": 2,
                    "event": "started",
                    "transaction": "candidate",
                    "dispatch": dispatch,
                },
            ],
        }
        after = {
            **before,
            "transaction": None,
            "pending": None,
            "desired": None,
            "completed": {
                "transaction": "candidate",
                "content": "checked-content",
            },
            "records": [
                *before["records"],
                {
                    "sequence": 3,
                    "event": "finished",
                    "transaction": "candidate",
                    "dispatch": dispatch,
                },
                {
                    "sequence": 4,
                    "event": "commit",
                    "transaction": "candidate",
                    "dispatch": None,
                },
            ],
        }
        self.subject = {
            "schema": "aos.qualification.native-operation-subject",
            "cell": self.cell_id,
            "transaction": "candidate",
            "resolvedRevision": "resolved-revision",
            "action": "apply",
            "journalSequence": 2,
            "effect": effect | {"handler": handler},
            "selectedGraphDigest": sha256(graph),
        }
        event = {
            "schema": "aos.activation.boundary",
            "transaction": "candidate",
            "effect": "owned",
            "revision": "resolved-revision",
            "action": "apply",
            "journal_sequence": 2,
        }
        selected = {"exists": True, "owners": ["native-handler:owned"]}
        self.flight = {
            "schema": "aos.qualification.native-operation-flight",
            "subject": self.subject,
            "selectedGraph": graph,
            "journalBefore": before,
            "journalAfter": after,
            "boundaries": [{**event, "boundary": phase} for phase in ["dispatch-returned", "observation-started", "observation-returned"]],
            "baseline": {
                "selected": {
                    "exists": False,
                    "owners": [],
                },
                "foreign": {
                    "digest": "unchanged",
                },
            },
            "unsettled": {
                "selected": selected,
                "foreign": {
                    "digest": "unchanged",
                },
            },
            "settled": {
                "selected": copy.deepcopy(selected),
                "foreign": {
                    "digest": "unchanged",
                },
            },
            "expectedSelected": copy.deepcopy(selected),
        }

    def run_cohort(self, evidence=None):
        package_subject = {
            "schema": COHORT.QUALIFICATION_SUBJECT_SCHEMA,
            "matrixSpecDigest": sha256(self.matrix),
            "operations": self.matrix["surface"]["adapters"],
        }
        return COHORT.build_cells(self.matrix, {
            self.cell_id: {
                "disposition": "checked",
                "evidenceDigest": sha256(self.flight),
            },
        }, [self.cell_id], {
            self.cell_id: self.subject,
        }, {
            self.cell_id: canonical(self.flight) if evidence is None else evidence,
        }, "sha256:" + "a" * 64, "sha256:" + "b" * 64, qualification_subject=package_subject)

    def rejection(self, scenario="reject-uncertain-recovery"):
        self.cell_id = "/".join(self.cell_id.split("/")[:-1] + [scenario])
        self.cell["id"] = self.cell_id
        self.cell["scenario"]["id"] = scenario
        self.cell["disposition"] = {"kind": "exact", "value": "pending-intent-retained"}
        self.matrix["applicability"]["applicable_cell_ids"] = [self.cell_id]
        self.subject["cell"] = self.cell_id
        self.flight["schema"] = "aos.qualification.native-operation-rejection"
        self.flight["journalAfter"] = copy.deepcopy(self.flight["journalBefore"])
        self.flight.pop("unsettled")
        event = self.flight["boundaries"][0]
        self.flight["boundaries"] = [event | {"boundary": phase} for phase in (
            "intent-durable", "dispatch-started", "observation-started", "observation-returned",
        )]
        self.flight["failureReceipt"] = {
            "unit": "native-rejection.service", "result": "exit-code",
            "execMainCode": 1, "execMainStatus": 1,
        }
        self.flight["dispatchInventory"] = {"dispatchAttemptCount": 1}

    def test_native_flight_proves_distinct_semantic_postconditions(self):
        cells, count = self.run_cohort()
        self.assertEqual(count, 4)
        probes = cells[0]["probes"]
        self.assertEqual(len({probe["observation_digest"] for probe in probes.values()}), 4)
        self.assertTrue(all(value["passed"] for value in cells[0]["postconditions"].values()))

    def test_native_rejection_preserves_pending_intent_and_independent_oracle(self):
        self.rejection()
        self.cell["postconditions"].append("uncertain-invocation-not-replayed")
        self.cell["postcondition_kinds"]["uncertain-invocation-not-replayed"] = "native-dispatch-inventory"

        _, count = self.run_cohort()

        self.assertEqual(count, 5)

    def test_failed_observation_transport_preserves_uncertainty_without_replay(self):
        self.rejection()
        self.flight["boundaries"] = [event for event in self.flight["boundaries"]
                                     if event["boundary"] != "observation-returned"]
        self.cell["postconditions"].append("uncertain-invocation-not-replayed")
        self.cell["postcondition_kinds"]["uncertain-invocation-not-replayed"] = "native-dispatch-inventory"
        _, count = self.run_cohort()
        self.assertEqual(count, 5)

    def test_uncertain_recovery_still_requires_actual_observation_attempt(self):
        self.rejection()
        self.flight["boundaries"] = self.flight["boundaries"][:2]
        with self.assertRaisesRegex(RuntimeError, "not observed"):
            self.run_cohort()

    def foreign_rejection(self):
        self.rejection("reject-foreign-resource-mutation")
        self.cell["disposition"] = {"kind": "exact", "value": "foreign-mutation-rejected"}
        self.flight["baseline"] = copy.deepcopy(self.flight["settled"])
        self.cell["postconditions"].append("foreign-attempt-rejected-before-mutation")
        self.cell["postcondition_kinds"]["foreign-attempt-rejected-before-mutation"] = "foreign-resource-snapshot"

    def test_foreign_refusal_preserves_independent_selected_and_foreign_witnesses(self):
        self.foreign_rejection()
        _, count = self.run_cohort()
        self.assertEqual(count, 5)

    def test_foreign_refusal_cannot_mutate_selected_foreign_target(self):
        self.foreign_rejection()
        self.flight["settled"]["selected"]["unexpectedMutation"] = True
        self.flight["expectedSelected"] = copy.deepcopy(self.flight["settled"]["selected"])
        with self.assertRaisesRegex(RuntimeError, "foreign target changed"):
            self.run_cohort()

    def dependency_rejection(self, action="apply"):
        self.rejection("block-dependent-effect")
        self.flight["schema"] = "aos.qualification.native-operation-dependency-block"
        self.cell["disposition"] = {"kind": "exact", "value": "dependent-effect-blocked"}
        self.cell["action"] = action
        self.subject["action"] = action
        graph = self.flight["selectedGraph"]
        blocked = copy.deepcopy(graph["nodes"]["owned"])
        blocked["identity"] = ["filesystem", "entry", "blocked"]
        blocked["dependencies"] = ["owned"] if action == "apply" else []
        graph["nodes"]["blocked"] = blocked
        graph["order"] = ["owned", "blocked"] if action == "apply" else ["blocked", "owned"]
        if action == "remove":
            graph["nodes"]["owned"]["dependencies"] = ["blocked"]
            self.subject["effect"]["dependencies"] = ["blocked"]
            self.matrix["surface"]["adapters"][0]["effects"][0]["dependencies"] = ["blocked"]
        self.subject["selectedGraphDigest"] = sha256(graph)
        for phase in ("journalBefore", "journalAfter"):
            self.flight[phase]["pending"]["action"] = action
            self.flight[phase]["records"][1]["dispatch"]["action"] = action
            self.flight[phase]["desired"] = copy.deepcopy(graph)
        for event in self.flight["boundaries"]:
            event["action"] = action
        reading = {"selected": {"exists": action == "remove", "owners": ["marker:blocked"] if action == "remove" else []},
                   "foreign": {"digest": "independent"}}
        self.flight["dependencyBarrier"] = {"effect": "blocked", "baseline": reading, "settled": copy.deepcopy(reading)}
        self.cell["postconditions"].append("prerequisite-failure-recorded")
        self.cell["postcondition_kinds"]["prerequisite-failure-recorded"] = "dependency-barrier"

    def test_dependency_barrier_respects_apply_and_reversed_remove_order(self):
        for action in ("apply", "remove"):
            with self.subTest(action=action):
                self.setUp()
                self.dependency_rejection(action)
                _, count = self.run_cohort()
                self.assertEqual(count, 5)

    def test_dependency_producer_bytes_match_independent_consumer(self):
        for action in ("apply", "remove"):
            with self.subTest(action=action):
                self.setUp()
                self.dependency_rejection(action)
                producer = fleet_producer()
                barrier = self.flight["dependencyBarrier"]
                observation = producer.NativeDependencyBlock(
                    self.flight["selectedGraph"], self.flight["boundaries"][0],
                    self.flight["journalBefore"], self.flight["journalAfter"], self.flight["boundaries"],
                    self.flight["baseline"], self.flight["settled"], self.flight["expectedSelected"],
                    self.flight["failureReceipt"], barrier["effect"], barrier["baseline"], barrier["settled"],
                )
                builder = producer.NativeEvidence(self.matrix, [self.cell_id])
                builder.retain_dependency_block(self.cell_id, observation)
                subjects, evidence, _ = builder.finish()
                self.subject = subjects[self.cell_id]
                self.flight = json.loads(evidence[self.cell_id])
                _, count = self.run_cohort(evidence[self.cell_id])
                self.assertEqual(count, 5)

    def test_dependency_barrier_requires_actual_graph_relation(self):
        self.dependency_rejection()
        self.flight["selectedGraph"]["nodes"]["blocked"]["dependencies"] = []
        self.subject["selectedGraphDigest"] = sha256(self.flight["selectedGraph"])
        for phase in ("journalBefore", "journalAfter"):
            self.flight[phase]["desired"] = copy.deepcopy(self.flight["selectedGraph"])
        with self.assertRaisesRegex(RuntimeError, "scheduling relation"):
            self.run_cohort()

    def test_dependency_barrier_cannot_hide_physical_child_change(self):
        self.dependency_rejection()
        self.flight["dependencyBarrier"]["settled"]["selected"]["exists"] = True
        with self.assertRaisesRegex(RuntimeError, "dependent or its foreign witness changed"):
            self.run_cohort()

    def read_only_account_precondition(self):
        self.foreign_rejection()
        precondition = {"kind": "read-only-account-database", "path": "/etc/group", "mountId": 123,
                        "device": "0:42", "root": "/etc/group", "mountPoint": "/etc/group",
                        "options": ["ro", "relatime"], "filesystem": "ext4", "source": "/dev/test",
                        "superOptions": ["rw"], "contentSha256": "sha256:" + "d" * 64}
        for phase in ("baseline", "settled"):
            self.flight[phase]["selected"]["precondition"] = copy.deepcopy(precondition)
        self.flight["expectedSelected"] = copy.deepcopy(self.flight["settled"]["selected"])

    def test_read_only_mount_precondition_preserves_exact_physical_witness(self):
        self.read_only_account_precondition()
        self.run_cohort()

    def test_read_only_mount_precondition_rejects_writable_or_unbounded_identity(self):
        self.read_only_account_precondition()
        for field, value in (("options", ["rw"]), ("mountId", True), ("path", "/etc/passwd")):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.flight)
                for phase in ("baseline", "settled"):
                    changed[phase]["selected"]["precondition"][field] = value
                changed["expectedSelected"] = changed["settled"]["selected"]
                with self.assertRaises(RuntimeError):
                    self.run_cohort(canonical(changed))

    def test_native_rejection_cannot_hide_a_second_attempt(self):
        self.rejection()
        self.flight["boundaries"].append(self.flight["boundaries"][1])
        self.flight["dispatchInventory"]["dispatchAttemptCount"] = 2

        with self.assertRaisesRegex(RuntimeError, "attempted a replay"):
            self.run_cohort()

    def test_native_rejection_cannot_claim_a_completed_outcome(self):
        completed = copy.deepcopy(self.flight["journalAfter"])
        self.rejection("fail-manager-after-dispatch-attempt")
        self.flight["journalAfter"] = completed

        with self.assertRaisesRegex(RuntimeError, "pending intent"):
            self.run_cohort()

    def test_real_rejection_producer_bytes_are_accepted_by_independent_consumer(self):
        self.rejection()
        producer = fleet_producer()
        observation = producer.NativeRejection(
            self.flight["selectedGraph"], self.flight["boundaries"][0],
            self.flight["journalBefore"], self.flight["journalAfter"], self.flight["boundaries"],
            self.flight["baseline"], self.flight["settled"], self.flight["expectedSelected"],
            self.flight["failureReceipt"],
        )
        builder = producer.NativeEvidence(self.matrix, [self.cell_id])

        builder.retain_rejection(self.cell_id, observation)
        subjects, evidence, _ = builder.finish()
        _, count = self.run_cohort(evidence[self.cell_id])

        self.assertEqual(subjects[self.cell_id], self.subject)
        self.assertEqual(evidence[self.cell_id], canonical(self.flight))
        self.assertEqual(count, 4)

    def pending_control(self, scenario):
        self.rejection(scenario)
        self.flight["schema"] = "aos.qualification.native-operation-pending-control"
        phases = ["intent-durable"]
        if scenario == "cancel-pending-invocation":
            disposition = "cancelled-retains-pending-intent"
            control = {"kind": "signal-cancellation", "signal": "SIGTERM",
                       "processId": 123, "executable": "/nix/store/exact-manager/bin/apm"}
        else:
            disposition = "deadline-exceeded-retains-ownership"
            control = {"kind": "invocation-deadline", "timeoutMillis": 2000, "elapsedMillis": 2100}
            phases.append("dispatch-started")
            self.flight["selectedGraph"]["nodes"]["owned"]["timeout_ms"] = 2000
            self.flight["journalBefore"]["desired"] = copy.deepcopy(self.flight["selectedGraph"])
            self.flight["journalAfter"] = copy.deepcopy(self.flight["journalBefore"])
            self.subject["selectedGraphDigest"] = sha256(self.flight["selectedGraph"])
        event = self.flight["boundaries"][0]
        self.flight["boundaries"] = [event | {"boundary": phase} for phase in phases]
        self.flight["dispatchInventory"] = {"dispatchAttemptCount": len(phases) - 1}
        self.flight["controlReceipt"] = control
        self.cell["disposition"] = {"kind": "exact", "value": disposition}

    def test_actual_control_producer_bytes_match_independent_consumer(self):
        for scenario in ("cancel-pending-invocation", "expire-invocation-deadline"):
            with self.subTest(scenario=scenario):
                self.setUp()
                self.pending_control(scenario)
                producer = fleet_producer()
                observation = producer.NativePendingControl(
                    self.flight["selectedGraph"], self.flight["boundaries"][0],
                    self.flight["journalBefore"], self.flight["journalAfter"], self.flight["boundaries"],
                    self.flight["baseline"], self.flight["settled"], self.flight["expectedSelected"],
                    self.flight["failureReceipt"], self.flight["controlReceipt"],
                )
                builder = producer.NativeEvidence(self.matrix, [self.cell_id])

                builder.retain_pending_control(self.cell_id, observation)
                subjects, evidence, _ = builder.finish()
                _, count = self.run_cohort(evidence[self.cell_id])

                self.assertEqual(subjects[self.cell_id], self.subject)
                self.assertEqual(evidence[self.cell_id], canonical(self.flight))
                self.assertEqual(count, 4)

    def test_cancellation_rejects_attempt_after_held_intent(self):
        self.pending_control("cancel-pending-invocation")
        self.flight["boundaries"].append(self.flight["boundaries"][0] | {"boundary": "dispatch-started"})
        self.flight["dispatchInventory"]["dispatchAttemptCount"] = 1

        with self.assertRaisesRegex(RuntimeError, "attempted a replay"):
            self.run_cohort()

    def test_deadline_requires_selected_timeout_and_elapsed_limit(self):
        self.pending_control("expire-invocation-deadline")
        for field, value in (("elapsedMillis", 1999), ("timeoutMillis", 1999)):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.flight)
                changed["controlReceipt"][field] = value
                with self.assertRaisesRegex(RuntimeError, "selected timeout"):
                    self.run_cohort(canonical(changed))

    def retained_transition(self, scenario):
        self.cell_id = "files/filesystem/entry/" + ("apply" if scenario == "activate-retained-target" else "remove") + "/retained-state/" + scenario
        action = self.cell_id.split("/")[3]
        dispositions = {"activate-retained-target": "retained-target-activated",
                        "retain-persistent-orphan": "persistent-resource-retained",
                        "retire-explicit-persistent-target": "persistent-resource-retired"}
        self.cell.update(id=self.cell_id, action=action, scenario={"family": "retained-state", "id": scenario},
                         disposition={"kind": "exact", "value": dispositions[scenario]})
        self.matrix["applicability"]["applicable_cell_ids"] = [self.cell_id]
        graph = copy.deepcopy(self.flight["selectedGraph"])
        graph["nodes"]["owned"]["lifetime"] = "persistent"
        self.matrix["surface"]["adapters"][0]["effects"][0]["lifetime"] = "persistent"
        before = copy.deepcopy(self.flight["journalAfter"])
        before["retainedOutputs"] = {"owned": {"path": "/run/owned"}}
        after = copy.deepcopy(before)
        desired_after = graph
        if action == "remove":
            desired_after = {"schema": "aos.activation.graph", "nodes": {}, "order": []}
            after["records"].append({"sequence": 5, "event": "begin", "transaction": "transition", "dispatch": None})
            if scenario == "retire-explicit-persistent-target":
                dispatch = {"effect": "owned", "revision": "remove-revision", "action": "remove", "journalSequence": 6}
                after["records"].extend([
                    {"sequence": 6, "event": "started", "transaction": "transition", "dispatch": dispatch},
                    {"sequence": 7, "event": "finished", "transaction": "transition", "dispatch": dispatch},
                ])
                after["retainedOutputs"] = {}
                after["retiredEffects"] = ["owned"]
            after["records"].append({"sequence": len(after["records"]) + 1, "event": "commit", "transaction": "transition", "dispatch": None})
            after["completed"] = {"transaction": "transition", "content": "committed-target"}
        baseline = self.flight["settled"]
        settled = copy.deepcopy(baseline)
        if scenario == "retire-explicit-persistent-target":
            settled["selected"] = {"exists": False, "owners": []}
        producer = fleet_producer()
        observation = producer.NativeRetainedTransition(
            graph, graph, desired_after, "owned", before, after, baseline, settled, settled["selected"],
            {"unit": "native-retained.service", "result": "success", "execMainCode": 1, "execMainStatus": 0},
        )
        builder = producer.NativeEvidence(self.matrix, [self.cell_id])
        builder.retain_transition(self.cell_id, observation)
        subjects, evidence, _ = builder.finish()
        self.subject = subjects[self.cell_id]
        self.flight = json.loads(evidence[self.cell_id])
        return evidence[self.cell_id]

    def test_retained_producer_bytes_preserve_logical_and_actual_actions(self):
        for scenario in ("activate-retained-target", "retain-persistent-orphan", "retire-explicit-persistent-target"):
            with self.subTest(scenario=scenario):
                self.setUp()
                evidence = self.retained_transition(scenario)
                _, count = self.run_cohort(evidence)
                self.assertEqual(count, 4)
                self.assertEqual(self.flight["priorReceipt"]["dispatch"]["action"], "apply")

    def test_persistent_orphan_cannot_fabricate_remove_receipt(self):
        self.retained_transition("retain-persistent-orphan")
        self.flight["priorReceipt"]["dispatch"]["action"] = "remove"
        with self.assertRaisesRegex(RuntimeError, "fabricates"):
            self.run_cohort()

    def test_retained_target_cannot_change_physical_identity(self):
        self.retained_transition("retain-persistent-orphan")
        self.flight["settled"]["selected"]["changedInode"] = True
        self.flight["expectedSelected"] = self.flight["settled"]["selected"]
        with self.assertRaisesRegex(RuntimeError, "original target"):
            self.run_cohort()

    def cohort_population(self):
        selected = {"role": "scenario", "locator": "/nix/store/fixture-bundle",
                    "scenario_sources": ["/nix/store/fixture-source/module.nix"]}
        spec = {"schema": "aos.qualification.native-operation-spec",
                "required_operations": self.matrix["required_operations"],
                "cohorts": [{"id": name, "matrix_spec": copy.deepcopy(self.matrix),
                             "selected_evaluation": selected | {"locator": "/nix/store/" + name + "-bundle"},
                             "adoption_evaluation": selected | {"locator": "/nix/store/" + name + "-baseline",
                                                               "scenario_sources": ["/nix/store/fixture-source/inactive.nix"]}}
                            for name in ("first", "second")]}
        execution = {"submissions": {self.cell_id: {"disposition": "checked", "evidenceDigest": sha256(self.flight)}},
                     "subjects": {self.cell_id: self.subject}, "evidence": {self.cell_id: canonical(self.flight)},
                     "qualification_subject": {"schema": COHORT.QUALIFICATION_SUBJECT_SCHEMA,
                                               "matrixSpecDigest": sha256(self.matrix),
                                               "operations": self.matrix["surface"]["adapters"]},
                     "candidate_digest": "sha256:" + "c" * 64,
                     "adoption_digest": "sha256:" + "d" * 64}
        return spec, {name: copy.deepcopy(execution) for name in ("first", "second")}

    def test_identical_cell_ids_keep_separate_closed_cohort_contexts(self):
        spec, executions = self.cohort_population()
        observations, count = COHORT.build_cohorts(spec, executions, "sha256:" + "a" * 64, "sha256:" + "b" * 64)
        self.assertEqual(count, 8)
        self.assertEqual([observation["id"] for observation in observations], ["first", "second"])
        self.assertNotEqual(observations[0]["selected_evaluation"], observations[1]["selected_evaluation"])
        self.assertEqual(observations[0]["cells"][0]["id"], observations[1]["cells"][0]["id"])

    def test_adoption_custody_and_digest_cannot_be_omitted(self):
        spec, executions = self.cohort_population()
        del spec["cohorts"][0]["adoption_evaluation"]
        with self.assertRaisesRegex(RuntimeError, "declaration"):
            COHORT.build_cohorts(spec, executions, "sha256:" + "a" * 64, "sha256:" + "b" * 64)
        spec, executions = self.cohort_population()
        del executions["first"]["adoption_digest"]
        with self.assertRaisesRegex(RuntimeError, "commitment"):
            COHORT.build_cohorts(spec, executions, "sha256:" + "a" * 64, "sha256:" + "b" * 64)

    def test_future_target_and_adopted_baseline_keep_distinct_commitments(self):
        spec, executions = self.cohort_population()
        observations, _ = COHORT.build_cohorts(spec, executions, "sha256:" + "a" * 64, "sha256:" + "b" * 64)
        first = observations[0]
        self.assertNotEqual(first["selected_evaluation"], first["adoption_evaluation"])
        self.assertNotEqual(first["candidate_digest"], first["adoption_digest"])
        self.assertEqual(first["adoption_evaluation"], spec["cohorts"][0]["adoption_evaluation"])

    def test_missing_execution_cannot_shrink_closed_cohort_population(self):
        spec, executions = self.cohort_population()
        del executions["second"]
        with self.assertRaisesRegex(RuntimeError, "complete authored cohort"):
            COHORT.build_cohorts(spec, executions, "sha256:" + "a" * 64, "sha256:" + "b" * 64)

    def test_changed_cohort_spec_cannot_reuse_original_operation_subject(self):
        spec, executions = self.cohort_population()
        spec["cohorts"][1]["matrix_spec"]["cells"][0]["failure"] = "different-failure"
        with self.assertRaises(RuntimeError):
            COHORT.build_cohorts(spec, executions, "sha256:" + "a" * 64, "sha256:" + "b" * 64)

    def test_noncanonical_flight_bytes_fail(self):
        with self.assertRaisesRegex(RuntimeError, "canonical"):
            self.run_cohort(json.dumps(self.flight).encode())

    def test_foreign_resource_change_fails(self):
        self.flight["settled"]["foreign"]["digest"] = "changed"
        with self.assertRaisesRegex(RuntimeError, "foreign resource"):
            self.run_cohort()

    def test_multiple_independent_owners_fail(self):
        self.flight["unsettled"]["selected"]["owners"].append("other-owner")
        with self.assertRaisesRegex(RuntimeError, "single-owner"):
            self.run_cohort()

    def test_live_target_mismatch_fails(self):
        self.flight["settled"]["selected"]["exists"] = False
        with self.assertRaisesRegex(RuntimeError, "expected target"):
            self.run_cohort()

    def test_wrong_recovery_revision_fails(self):
        self.flight["boundaries"][-1]["revision"] = "foreign-revision"
        with self.assertRaisesRegex(RuntimeError, "foreign intent"):
            self.run_cohort()

    def test_changed_journal_prefix_fails(self):
        self.flight["journalAfter"]["records"] = copy.deepcopy(self.flight["journalAfter"]["records"])
        self.flight["journalAfter"]["records"][0]["transaction"] = "foreign"
        with self.assertRaises(RuntimeError):
            self.run_cohort()

    def test_unknown_boundary_phase_fails(self):
        self.flight["boundaries"].append(self.flight["boundaries"][-1] | {"boundary": "grant-issued"})

        with self.assertRaisesRegex(RuntimeError, "unsupported phase"):
            self.run_cohort()

    def test_full_callback_prefix_keeps_the_selected_interruption(self):
        event = self.flight["boundaries"][0]
        self.flight["boundaries"][:0] = [
            event | {"boundary": "intent-durable"},
            event | {"boundary": "dispatch-started"},
        ]

        _, count = self.run_cohort()

        self.assertEqual(count, 4)

    def test_dispatch_return_before_attempt_fails(self):
        self.flight["boundaries"].append(self.flight["boundaries"][0] | {"boundary": "dispatch-started"})

        with self.assertRaisesRegex(RuntimeError, "returned before"):
            self.run_cohort()

    def test_torn_prefix_fails(self):
        self.flight["journalBefore"]["incompleteTailBytes"] = 1
        with self.assertRaisesRegex(RuntimeError, "complete journal"):
            self.run_cohort()

    def test_matrix_handler_swap_fails(self):
        self.matrix["surface"]["adapters"][0]["handler"] = {
            "kind": "process",
            "artifact": "foreign",
            "executable": "foreign",
        }
        with self.assertRaisesRegex(RuntimeError, "handler"):
            self.run_cohort()

    def test_subject_replay_under_another_cell_fails(self):
        self.subject["cell"] = "foreign-cell"
        with self.assertRaisesRegex(RuntimeError, "another matrix cell"):
            self.run_cohort()

    def test_legacy_provider_subject_fails(self):
        self.subject["schema"] = "aos.ability.provider-plan/v1"
        with self.assertRaisesRegex(RuntimeError, "unsupported native"):
            self.run_cohort()

    def test_cancellation_or_grant_claim_without_evidence_fails(self):
        self.cell["postconditions"].append("current-grants-reauthorized")
        self.cell["postcondition_kinds"]["current-grants-reauthorized"] = "authority-grants"
        with self.assertRaisesRegex(RuntimeError, "does not prove"):
            self.run_cohort()

    def test_unexecuted_cell_fails(self):
        self.matrix["applicability"]["applicable_cell_ids"].append("foreign-cell")
        with self.assertRaisesRegex(RuntimeError, "partition"):
            self.run_cohort()

    def test_durable_outcome_recovery_does_not_require_pending_observation(self):
        self.cell["scenario"]["id"] = "interrupt-after-durable-outcome"
        self.cell["boundary"] = "after-durable-outcome"
        self.flight["journalBefore"] = copy.deepcopy(self.flight["journalBefore"])
        self.flight["journalBefore"]["records"].append(copy.deepcopy(self.flight["journalAfter"]["records"][2]))
        self.flight["journalBefore"]["pending"] = None
        self.flight["boundaries"] = [self.flight["boundaries"][0] | {"boundary": "outcome-durable"}]
        cells, _ = self.run_cohort()
        self.assertTrue(cells[0]["postconditions"]["durable-attempt-state-classified"]["passed"])

    def test_removal_uses_retained_source_graph_separately_from_candidate(self):
        self.cell["action"] = "remove"
        self.subject["action"] = "remove"
        for phase in ("journalBefore", "journalAfter"):
            self.flight[phase] = copy.deepcopy(self.flight[phase])
            for record in self.flight[phase]["records"]:
                if record["dispatch"] is not None:
                    record["dispatch"]["action"] = "remove"
            if self.flight[phase]["pending"] is not None:
                self.flight[phase]["pending"]["action"] = "remove"
        self.flight["journalAfter"]["retiredEffects"] = ["owned"]
        self.flight["journalBefore"]["desired"] = {"schema": "aos.activation.graph", "nodes": {}, "order": []}
        for event in self.flight["boundaries"]:
            event["action"] = "remove"
        self.flight["settled"]["selected"] = {"exists": False, "owners": []}
        self.flight["expectedSelected"] = copy.deepcopy(self.flight["settled"]["selected"])
        cells, _ = self.run_cohort()
        self.assertTrue(cells[0]["postconditions"]["at-most-one-resource-owner"]["passed"])

    def test_readonly_inspection_never_supplies_live_authority(self):
        self.flight["journalAfter"]["liveStateVerified"] = True
        with self.assertRaisesRegex(RuntimeError, "checked native"):
            self.run_cohort()

    def test_missing_observation_return_rejects_pending_recovery(self):
        self.flight["boundaries"].pop()
        with self.assertRaisesRegex(RuntimeError, "observed before recovery"):
            self.run_cohort()

    def test_outcome_without_matching_durable_intent_fails(self):
        self.flight["journalAfter"] = copy.deepcopy(self.flight["journalAfter"])
        self.flight["journalAfter"]["records"][2]["dispatch"] = self.flight["journalAfter"]["records"][2]["dispatch"] | {
            "revision": "other-intent",
        }
        with self.assertRaisesRegex(RuntimeError, "differs from its durable intent"):
            self.run_cohort()

    def test_removed_framework_audit_argument_has_no_compatibility_route(self):
        with self.assertRaises(TypeError):
            COHORT.build_cells({}, {}, [], {}, {}, "sha256:" + "a" * 64,
                               "sha256:" + "b" * 64,
                               runtime_audit={"cells": {"synthetic": {}}})

    def test_real_fleet_producer_bytes_are_accepted_by_independent_consumer(self):
        producer = fleet_producer()
        observation = producer.NativeObservation(
            self.flight["selectedGraph"], self.flight["boundaries"][0],
            self.flight["journalBefore"], self.flight["journalAfter"], self.flight["boundaries"],
            self.flight["baseline"], self.flight["unsettled"], self.flight["settled"],
            self.flight["expectedSelected"],
        )
        builder = producer.NativeEvidence(self.matrix, [self.cell_id])
        builder.retain(self.cell_id, observation)
        subjects, evidence, probes = builder.finish()

        self.assertEqual(subjects[self.cell_id], self.subject)
        self.assertEqual(evidence[self.cell_id], canonical(self.flight))
        package_subject = {
            "schema": COHORT.QUALIFICATION_SUBJECT_SCHEMA,
            "matrixSpecDigest": sha256(self.matrix),
            "operations": self.matrix["surface"]["adapters"],
        }
        cells, count = COHORT.build_cells(
            self.matrix, probes, [self.cell_id], subjects, evidence,
            "sha256:" + "a" * 64, "sha256:" + "b" * 64,
            qualification_subject=package_subject,
        )
        self.assertEqual(count, 4)
        self.assertEqual(cells[0]["id"], self.cell_id)


class NativeOperationSelectionTests(unittest.TestCase):
    def setUp(self):
        self.spec = {"required_operations": [{"ability": "serviceManagement", "name": "realize"}]}
        self.graph = {"nodes": {
            "parent": {"identity": ["serviceManagement", "realize", "subject"],
                       "handler": {"kind": "composition", "children": ["child"]}},
            "child": {"identity": ["configurationLower", "file", "subject"],
                      "handler": {"kind": "process"}},
            "foreign": {"identity": ["filesystem", "entry", "foreign"],
                        "handler": {"kind": "process"}},
        }}

    def test_composition_selects_actual_terminal_children(self):
        self.assertEqual(COHORT.selected_terminal_effects(self.spec, self.graph), {"child"})

    def test_missing_semantic_operation_fails(self):
        self.spec["required_operations"][0]["name"] = "missing"
        with self.assertRaises(RuntimeError):
            COHORT.selected_terminal_effects(self.spec, self.graph)

    def test_duplicate_operation_selection_fails(self):
        self.spec["required_operations"] *= 2
        with self.assertRaises(RuntimeError):
            COHORT.selected_terminal_effects(self.spec, self.graph)

    def test_cycle_or_missing_child_fails(self):
        for child in ("parent", "absent"):
            with self.subTest(child=child):
                self.graph["nodes"]["parent"]["handler"]["children"] = [child]
                with self.assertRaises(RuntimeError):
                    COHORT.selected_terminal_effects(self.spec, self.graph)

    def test_missing_selection_fails(self):
        with self.assertRaises(RuntimeError):
            COHORT.selected_terminal_effects({}, self.graph)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
