"""Controlled public-case ordering and same-Worker-only integration checks."""

import importlib.util
import json
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location("mirror_business", Path(__file__).with_name("_hub-external-mirror-business.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MirrorBusinessTests(unittest.TestCase):
    def setUp(self):
        spec.loader.exec_module(module)

    def test_public_cases_use_two_destinations_one_review_and_successor_process(self):
        events = []
        run = "a" * 32
        original = {"pid": 1}
        successor = {"pid": 2}
        ready = {"backgroundControllers": {"mirrorSync": {"intervalSeconds": 60, "mode": "full"}}}
        selected = {"reservedPlacementRoot": ".aos-mirror-qualification/" + run + "/final"}
        artifact = {"issuedAt": 10, "validUntil": 100,
            "upstreamBase": "https://aos.fleet.test:4778/fleet-mirror/" + run,
            "placementPrefix": selected["reservedPlacementRoot"]}
        config = {"bindings": {"HUB_EXTERNAL_MIRROR_CONSUMER": json.dumps({"version": 1,
            "domains": [{"actualInstalled": True}]})}}
        module.read_direct_guest_file = lambda machine, python, path, maximum: json.dumps(
            config if path == "/config" else artifact).encode()
        module.private_guest_command = lambda *args: "20"
        module.require_mirror_reserved_cohorts = lambda *args: selected
        source = {"runId": run, "upstream": artifact["upstreamBase"],
            "signed": {"trustKey": "actual-controlled-trust", "sourceCommit": "b" * 64},
            "inventory": {"objects": [{"path": "HEAD"}], "pullObjects": [{"path": "governing.narinfo"}]}}
        module.prepare_external_mirror_signed_source = lambda *args: source
        module.install_external_mirror_upstream = lambda *args: {"controlledOwnedUpstream": True}
        installs = {"triplet": {"artifactFile": "/artifact"}, "producer": {"originalPid": 1},
            "installed": {"storedBytesOnly": True}}
        def install(*args):
            events.append("review-and-install-original")
            self.assertEqual(args[4]["native"], original)
            return installs
        def restart(*args):
            events.append("restart-after-install")
            return {"processes": {"native": successor, "worker": {}},
                "helper": {"process": successor, "readiness": ready}}
        module.review_install_external_mirror = install
        module.restart_external_mirror_native = restart
        module.mirror_selection = lambda registry, upstream, run, mode, **kwargs: {
            "mode": mode, "upstream": upstream, "registry": registry}
        module.read_external_oci_sql = lambda native, tools, prepared, process, query, label: {"actualPid": process["pid"]}
        module.observe_mirror_effects = lambda read_sql, selection, configured, label: read_sql("controlled-read-only-query", label)
        def case(controls, selection, rows, readiness, **kwargs):
            events.append("case-" + selection["mode"])
            self.assertEqual(kwargs["cutoff"], 200)
            purpose = kwargs["install_purpose"](selection, {})
            self.assertEqual(purpose["producer"]["originalPid"], 1)
            self.assertEqual(purpose["successor"]["process"], successor)
            self.assertEqual(kwargs["observe_effects"](selection, {}, 1), {"actualPid": 2})
            return {"controlledMode": selection["mode"], "purpose": purpose}
        module.run_external_mirror_case = case
        module.time.monotonic = lambda: 5
        module.retain_direct_flow = lambda *args: "retained"
        class Controls:
            def create_external_registry(self, *args, **kwargs):
                events.append("create-" + args[2])
                self_scope = args[5]
                if not self_scope.startswith(selected["reservedPlacementRoot"] + "/"):
                    raise AssertionError("wrong reserved placement")
                if kwargs["mirror_run_id"] != run:
                    raise AssertionError("wrong run")
                return {"controlledPlacementPrefix": self_scope}
        result = module.run_external_mirror_business(None, None, None, {
            "copyIsolationCase": "same_worker", "mirrorFunctionalReviewer": {"actual": True},
            "fleetCutoffMonotonic": 200, "python": "selected-python"}, {
                "coordinates": {"runId": run, "nativeRoot": "/native", "clientRoot": "/client"},
                "configurationFile": "/config"}, {"native": original, "worker": {}},
            {"process": original, "readiness": ready}, {}, {}, {
                "binding": {"ownerScopeKey": "actual-owner"}}, Controls(), None, None, {}, {})
        self.assertEqual(events, ["create-mirror-full-aaaaaaaa", "create-mirror-pull-through-aaaaaaaa",
            "case-full", "review-and-install-original", "restart-after-install", "case-pull_through"])
        self.assertEqual(result["processes"]["native"], successor)
        self.assertEqual(set(result["evidence"]["cases"]), {"full", "pull_through"})
        self.assertIsNone(result["evidence"]["nativeBulkBytes"])

    def test_source_worker_does_not_enter_mirror_corpus_or_producer(self):
        with self.assertRaisesRegex(ValueError, "same-Worker pair"):
            module.run_external_mirror_business(None, None, None, {
                "copyIsolationCase": "source_worker", "mirrorFunctionalReviewer": {"actual": True}},
                {}, {}, {}, {}, {}, {}, None, None, None, {}, {})


if __name__ == "__main__":
    unittest.main()
