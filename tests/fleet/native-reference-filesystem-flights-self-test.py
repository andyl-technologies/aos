"""Checks exact domain selection and admitted-input command construction.

These are rendering checks, not simulated runtime qualification evidence.
"""

import importlib.util
import sys
import unittest
from types import SimpleNamespace

specification = importlib.util.spec_from_file_location("native_domain_flights", sys.argv[1])
if specification is None or specification.loader is None:
    raise RuntimeError("cannot load native domain flights")
FLIGHTS = importlib.util.module_from_spec(specification)
specification.loader.exec_module(FLIGHTS)


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
        node = {"identity": ["package", "native", cell["operation"]["ability"], cell["operation"]["name"], "native-qualification"], "handler": "retained", "revision": "original-revision"}
        graph = {"nodes": {effect: node}}
        baseline = {"exists": True, "owners": [effect], "mode": "0750", "uid": 0, "gid": 0, "kind": "directory", "entries": [], "claimMatches": True}
        observations = iter([{"selected": baseline}, {"selected": {"exists": False, "owners": []}}])
        def write(path, settings=None):
            sources[path] = settings or {}
            return path
        def retain(flight, builder, observe, expected, *arguments):
            captured.update(flight=flight, expected=expected)
            if arguments:
                arguments[0]()
        FLIGHTS.runtime = SimpleNamespace(succeed=lambda command: commands.append(command))
        FLIGHTS.COREUTILS = "/source-built/coreutils/bin"
        FLIGHTS.NFT = "/source-built/nft"
        FLIGHTS.write_reference_worktree = write
        FLIGHTS.apply_reference = lambda source, label: applied.append(source)
        FLIGHTS.current_reference_graph = lambda: graph
        FLIGHTS.guest_oracle = lambda request: next(observations)
        FLIGHTS.NATIVE_FLIGHT = SimpleNamespace(NativeFlight=lambda *args: SimpleNamespace(worktree=args[2], selected_graph=args[4]), run=retain, run_rejection=retain)
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


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
