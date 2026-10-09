"""Checks exact domain selection and admitted-input command construction.

These are rendering checks, not simulated runtime qualification evidence.
"""

import importlib.util
import sys
import unittest
from dataclasses import dataclass
from types import SimpleNamespace

specification = importlib.util.spec_from_file_location("native_domain_flights", sys.argv[1])
if specification is None or specification.loader is None:
    raise RuntimeError("cannot load native domain flights")
FLIGHTS = importlib.util.module_from_spec(specification)
specification.loader.exec_module(FLIGHTS)


@dataclass(frozen=True)
class RenderedFlight:
    """Preserves the production flight's immutable selection boundary."""

    cell: dict
    effect: str
    worktree: str
    unit: str
    selected_graph: dict | None = None


class FlightRenderingTests(unittest.TestCase):
    def cell(self, ability="filesystem", operation="directory", action="apply", scenario="lose-external-result"):
        return {"id": "controlled-cell", "operation": {"ability": ability, "name": operation}, "action": action, "scenario": {"id": scenario}}

    def test_only_concrete_domain_operations_are_supported(self):
        for operation in FLIGHTS.DIRECTORY_OPERATIONS:
            self.assertTrue(FLIGHTS.supports(self.cell(operation=operation), {}, {}))
        self.assertFalse(FLIGHTS.supports(self.cell(operation="view"), {}, {}))
        self.assertFalse(FLIGHTS.supports(self.cell(action="observe"), {}, {}))
        self.assertFalse(FLIGHTS.supports(self.cell(scenario="invented-boundary"), {}, {}))

    def test_exact_retained_handler_and_fixture_name_select_the_effect(self):
        graph = {"nodes": {"selected": {"identity": ["package", "name", "filesystem", "entry", "native-qualification"], "handler": {"program": "retained"}}, "foreign": {"identity": ["package", "name", "filesystem", "entry", "unrelated"], "handler": {"program": "retained"}}}}
        adapter = {"handler": {"program": "retained"}}
        self.assertEqual(FLIGHTS.selected_effect(graph, "filesystem", "entry", adapter), "selected")
        with self.assertRaises(RuntimeError):
            FLIGHTS.selected_effect(graph, "filesystem", "entry", {"handler": {"program": "other"}})

    def test_ambiguous_firewall_selection_fails_closed(self):
        node = {"identity": ["networkPolicy", "ruleset", "host"], "handler": "retained"}
        with self.assertRaises(RuntimeError):
            FLIGHTS.selected_effect({"nodes": {"first": node, "second": node}}, "networkPolicy", "ruleset", {"handler": "retained"})

    def render(self, cell):
        sources = {}
        applied = []
        commands = []
        captured = {}
        effect = "exact-retained-effect"
        node = {"identity": ["package", "native", cell["operation"]["ability"], cell["operation"]["name"], "native-qualification"], "handler": "retained", "revision": "original-revision", "input": {"mode": "0750", "allowedTCP": [22, 18190]}}
        operation = cell["operation"]["name"]
        parent = "parent-" + operation
        child = "child-" + operation
        node["dependencies"] = [parent]
        graph = {"nodes": {
            effect: node,
            parent: {"identity": ["nativeDependencyBarrier", "ensure", parent], "dependencies": []},
            child: {"identity": ["nativeDependencyBarrier", "ensure", child], "dependencies": [effect]},
        }}
        baseline = {"exists": True, "owners": [effect], "mode": "0750", "uid": 0, "gid": 0, "kind": "directory", "entries": [], "claimMatches": True}
        if cell["operation"]["ability"] == "networkPolicy":
            baseline = {"exists": True, "owners": [effect], "policies": {"input": "drop"}, "tcp": [22, 18190], "udp": [], "claimMatches": True}
        def write(path, settings=None, extra_module=""):
            self.assertEqual(extra_module, "retained-native-observer")
            sources[path] = settings or {}
            return path
        def retain(flight, builder, observe, expected, *arguments, **keywords):
            captured.update(flight=flight, expected=expected)
            if arguments:
                arguments[0]()
            if keywords.get("prepare_block") is not None:
                keywords["prepare_block"]()
        def observe(request):
            captured["request"] = request
            if request["domain"] == "dependency":
                return {"selected": {"exists": cell["action"] == "remove", "owners": [parent] if cell["action"] == "remove" else []}}
            settings = sources[applied[-1]]
            retired = bool(settings.get("aos", {}).get("activation", {}).get("retire"))
            if cell["scenario"]["id"] == "reject-foreign-resource-mutation" and any(
                "mkdir -m 0711" in command or "foreign-selected-drift" in command or "dport 18192" in command
                for command in commands
            ):
                return {"selected": dict(baseline, owners=[] if retired else [effect], claimMatches=False, device=1, inode=2)}
            return {"selected": {"exists": False, "owners": []} if retired else dict(baseline)}
        FLIGHTS.runtime = SimpleNamespace(succeed=lambda command: commands.append(command), wait_until_succeeds=lambda command, **options: commands.append(command))
        FLIGHTS.COREUTILS = "/source-built/coreutils/bin"
        FLIGHTS.NFT = "/source-built/nft"
        FLIGHTS.PYTHON = "/source-built/python3"
        FLIGHTS.SYSTEMD_RUN = "/source-built/systemd-run"
        FLIGHTS.SYSTEMCTL = "/source-built/systemctl"
        FLIGHTS.OBSERVER_HOST_MODULE = "retained-native-observer"
        FLIGHTS.write_reference_worktree = write
        FLIGHTS.apply_reference = lambda source, label: applied.append(source)
        def current_graph():
            if sources[applied[-1]].get("aos", {}).get("nativeDomainQualification", {}).get("mode"):
                return {"nodes": {effect: dict(node, revision="independently-admitted-old-revision")}}
            return graph
        FLIGHTS.current_reference_graph = current_graph
        FLIGHTS.guest_oracle = observe
        def dependency_block(flight, builder, observe_selected, expected, dependent, observe_dependent, inject):
            captured.update(flight=flight, expected=expected, dependent=dependent)
            captured["dependent_reading"] = observe_dependent()
            inject()
        FLIGHTS.NATIVE_FLIGHT = SimpleNamespace(
            NativeFlight=RenderedFlight,
            run=retain, run_rejection=retain, run_pending_control=retain, run_retained_transition=retain,
            run_dependency_block=dependency_block,
            arm_handler_response=lambda action: captured.setdefault("armed_operation", action),
            captured_handler_response=lambda control: captured.setdefault("captured_operation", control),
        )
        FLIGHTS.NATIVE_BUILDER = object()
        FLIGHTS.run_cell(cell, {"handler": "retained"}, graph)
        return sources, applied, captured, commands

    def test_apply_recreates_original_inputs_after_explicit_retirement(self):
        sources, applied, captured, _ = self.render(self.cell())
        self.assertEqual(sources[captured["flight"].worktree], {})
        removed = next(value for value in sources.values() if value)
        self.assertEqual(removed["aos"]["activation"]["retire"], ["exact-retained-effect"])
        self.assertFalse(removed["aos"]["nativeDomainQualification"]["enabled"]["directory"])
        self.assertEqual(captured["expected"]["owners"], ["exact-retained-effect"])
        self.assertEqual(len(applied), 3)

    def test_remove_carries_authenticated_original_graph(self):
        _, _, captured, _ = self.render(self.cell(action="remove"))
        self.assertIsNotNone(captured["flight"].selected_graph)
        self.assertEqual(captured["expected"], {"exists": False, "owners": []})

    def test_negative_apply_injects_real_unclaimed_inode_conflict(self):
        _, applied, captured, commands = self.render(self.cell(scenario="fail-manager-after-dispatch-attempt"))
        self.assertEqual(captured["expected"]["owners"], [])
        self.assertFalse(captured["expected"]["claimMatches"])
        self.assertTrue(any("mkdir -m 0711" in command for command in commands))
        self.assertEqual(len(applied), 2)  # No attempted repair of the pending journal.


    def test_cancellation_observes_unchanged_substrate_before_dispatch(self):
        for action in ("apply", "remove"):
            _, applied, captured, commands = self.render(self.cell(action=action, scenario="cancel-pending-invocation"))
            expected = {"exists": False, "owners": []} if action == "apply" else {"exists": True, "owners": ["exact-retained-effect"]}
            for key, value in expected.items():
                self.assertEqual(captured["expected"][key], value)
            self.assertEqual(len(applied), 2 if action == "apply" else 1)
            self.assertFalse(any("backend-lock" in command for command in commands))

    def test_deadline_uses_original_wrappers_and_real_response_capture(self):
        for ability, operation in (("filesystem", "directory"), ("configuration", "file"), ("networkPolicy", "ruleset")):
            for action in ("apply", "remove"):
                _, applied, captured, commands = self.render(self.cell(ability=ability, operation=operation, action=action, scenario="expire-invocation-deadline"))
                self.assertEqual(captured["armed_operation"], action)
                self.assertEqual(captured["captured_operation"], action)
                self.assertEqual(captured["expected"]["exists"], action == "apply")
                self.assertFalse(captured["request"]["identity"])
                self.assertFalse(any("backend-lock" in command for command in commands))
                self.assertEqual(len(applied), 2 if action == "apply" else 1)

    def test_retained_activation_preserves_original_target_without_retirement(self):
        sources, applied, captured, _ = self.render(self.cell(scenario="activate-retained-target"))
        self.assertEqual(sources[captured["flight"].worktree], {})
        self.assertEqual(len(applied), 1)
        self.assertEqual(captured["expected"]["owners"], ["exact-retained-effect"])
        self.assertEqual(captured["flight"].selected_graph["nodes"]["exact-retained-effect"]["revision"], "original-revision")

    def test_persistent_orphan_disables_source_without_retire_or_redispatch(self):
        sources, applied, captured, _ = self.render(self.cell(operation="persistentAllocate", action="remove", scenario="retain-persistent-orphan"))
        settings = sources[captured["flight"].worktree]["aos"]
        self.assertFalse(settings["nativeDomainQualification"]["enabled"]["persistentAllocate"])
        self.assertNotIn("activation", settings)
        self.assertEqual(len(applied), 1)
        self.assertEqual(captured["expected"]["owners"], ["exact-retained-effect"])

    def test_explicit_persistent_retirement_begins_with_real_orphan_transition(self):
        sources, applied, captured, _ = self.render(self.cell(operation="persistentAllocate", action="remove", scenario="retire-explicit-persistent-target"))
        self.assertEqual(len(applied), 2)
        self.assertNotIn("activation", sources[applied[1]]["aos"])
        self.assertEqual(sources[captured["flight"].worktree]["aos"]["activation"]["retire"], ["exact-retained-effect"])
        self.assertEqual(captured["expected"], {"exists": False, "owners": []})

    def test_rollout_recovery_changes_only_predecessor_source(self):
        cell = self.cell()
        cell["scenario"]["family"] = "rollout-durability"
        sources, applied, captured, _ = self.render(cell)
        self.assertEqual(sources[captured["flight"].worktree], {})
        self.assertEqual(sources[applied[1]]["aos"]["nativeDomainQualification"]["mode"], "0711")
        self.assertEqual(captured["expected"]["mode"], "0750")
        self.assertEqual(len(applied), 3)

    def test_foreign_mutation_refusal_uses_actual_pre_dispatch_identity(self):
        for ability, operation in (("filesystem", "directory"), ("configuration", "file"), ("networkPolicy", "ruleset")):
            for action in ("apply", "remove"):
                _, applied, captured, _ = self.render(self.cell(ability=ability, operation=operation, action=action, scenario="reject-foreign-resource-mutation"))
                self.assertTrue(captured["request"]["identity"])
                self.assertFalse(captured["expected"]["claimMatches"])
                self.assertEqual(captured["expected"]["inode"], 2)
                self.assertEqual(captured["expected"]["owners"], [] if action == "apply" else ["exact-retained-effect"])
                self.assertEqual(len(applied), 2 if action == "apply" else 1)

    def test_retained_scenario_action_and_lifetime_do_not_expand_applicability(self):
        self.assertFalse(FLIGHTS.supports(self.cell(action="remove", scenario="activate-retained-target"), {}, {}))
        self.assertFalse(FLIGHTS.supports(self.cell(operation="directory", action="remove", scenario="retain-persistent-orphan"), {}, {}))
        self.assertFalse(FLIGHTS.supports(self.cell(operation="persistentAllocate", action="apply", scenario="retire-explicit-persistent-target"), {}, {}))

    def test_dependency_block_preserves_original_graph_and_direction(self):
        for ability, operation in (("filesystem", "directory"), ("configuration", "file"), ("networkPolicy", "ruleset")):
            for action in ("apply", "remove"):
                sources, applied, captured, _ = self.render(self.cell(ability=ability, operation=operation, action=action, scenario="block-dependent-effect"))
                relationship = "child" if action == "apply" else "parent"
                self.assertEqual(captured["dependent"], relationship + "-" + operation)
                self.assertEqual(captured["flight"].selected_graph["nodes"]["exact-retained-effect"]["revision"], "original-revision")
                self.assertEqual(captured["armed_operation"], action)
                self.assertEqual(captured["captured_operation"], action)
                self.assertEqual(len(applied), 2 if action == "apply" else 1)
                candidate = sources[captured["flight"].worktree]
                if action == "apply":
                    self.assertEqual(candidate, {})
                else:
                    self.assertFalse(candidate["aos"]["nativeDomainQualification"]["dependencyParents"][operation])

    def test_dependency_marker_selection_rejects_missing_or_ambiguous_claims(self):
        node = {"identity": ["nativeDependencyBarrier", "ensure", "child-directory"]}
        for nodes in ({}, {"first": node, "second": node}):
            with self.assertRaises(RuntimeError):
                FLIGHTS.dependency_effect({"nodes": nodes}, "directory", "child")


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
