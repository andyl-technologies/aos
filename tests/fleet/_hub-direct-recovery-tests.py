"""Check sparse scheduling and distinct recovery accounting with controlled peers.

No VM, signal, provider transfer, sparse journal or runtime metric is generated
by these orchestration tests. Actual scenario assertions remain mandatory.
"""

import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


def load(name, filename):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


concurrent = load("concurrent", "_hub-direct-concurrent-publications.py")
evidence = load("recovery_evidence", "_hub-direct-recovery-evidence.py")
publisher = load("publisher", "_hub-direct-publisher.py")
for name in ("DIRECT_LARGE_OBJECT_BYTES", "DIRECT_LARGE_OBJECT_COUNT", "DIRECT_METADATA_OBJECT_COUNT"):
    setattr(evidence, name, getattr(publisher, name))
evidence.retain_direct_flow = lambda *args: None


class SparsePublicationOrchestration(unittest.TestCase):
    def run_scenario(self, observe_gap=True):
        calls = []
        sources = {label: {"surfaceRoot": "/controlled/" + label} for label in ("a", "b")}
        registries = {label: {"registry": {"slug": "controlled/" + label}} for label in sources}
        corpus = {"large_objects": [{"path": "web/large", "byte_size": 2147483648, "sha256": "f" * 64}]}
        interrupted = {"admission": {"publication": {"admission": {"publicationId": "1" * 32}}},
            "checkpoint": {"sessions": [{"path": "web/large", "sparseGaps": [{}]}]},
            "result": {"exitCode": -9, "timedOut": False}}
        publications = {label: {"publication_id": str(index) * 32, "state": "ready"}
            for index, label in enumerate(sources, 1)}
        def start(client, tools, slug, signed, token, label, attempt):
            calls.append(("start", label, attempt, token))
            return {"label": label, "attempt": attempt, "directory": "/controlled/" + label + str(attempt)}
        def read(client, python, path, maximum):
            if path.endswith("stderr"):
                return b"retained controlled stderr"
            if observe_gap and path.startswith("/controlled/a1"):
                return b""  # A killed original cannot be parsed as terminal JSON.
            return json.dumps({"data": publications[path[len('/controlled/')]]}).encode()
        def changed(*args):
            calls.append(("changed", args[-1]))
            return {"journalsUnchanged": True}
        bindings = {
            "direct_root_browser_token": lambda *args, **kwargs: "fresh-controlled-token",
            "private_guest_command": lambda *args, **kwargs: None,
            "start_direct_publication": start,
            "observe_direct_sparse_publisher": lambda *args: {"sparse": observe_gap, "state": "live"},
            "interrupt_direct_sparse_publisher": lambda *args: copy.deepcopy(interrupted),
            "probe_direct_changed_source": changed,
            "observe_direct_sparse_completion": lambda *args: {},
            "assert_direct_sparse_resume": lambda *args: {"preservedPositiveParts": 1},
            "direct_visibility_rendezvous": lambda *args: {"event": "controlled"},
            "poll_direct_publication": lambda *args: {"exitCode": 0, "timedOut": False},
            "read_direct_guest_file": read,
            "retain_direct_flow": lambda *args: None,
        }
        with patch.multiple(concurrent, **bindings, create=True):
            result = concurrent.run_direct_concurrent_publications(None, None,
                {"curl": "controlled", "python": "controlled"}, sources, registries,
                {"byteSize": 0}, "a" * 64, corpus)
        return result, calls

    def test_interrupted_empty_stdout_is_not_a_success_or_json_terminal_result(self):
        (publications, observations), calls = self.run_scenario()
        self.assertEqual(set(publications), {"a", "b"})
        self.assertEqual([row[:3] for row in calls if row[0] == "start"],
            [("start", "a", 1), ("start", "a", 2), ("start", "b", 1)])
        self.assertEqual(calls[1], ("changed", "fresh-controlled-token"))
        killed = observations["invocations"][0]
        self.assertEqual(killed["result"]["exitCode"], -9)
        self.assertFalse(killed["terminalCountersAvailable"])
        self.assertEqual(observations["sparseRecovery"]["terminalCountersUnavailable"],
            [{"label": "a", "attempt": 1}])
        self.assertTrue(all(row["terminalCountersAvailable"] for row in observations["invocations"][1:]))
        self.assertEqual(observations["pacing"], "none")

    def test_missing_real_gap_refuses_instead_of_claiming_sparse_resume(self):
        with self.assertRaisesRegex(RuntimeError, "without an observed sparse gap"):
            self.run_scenario(observe_gap=False)


class RecoveryEvidenceCoverage(unittest.TestCase):
    def inputs(self):
        known = {name: 1 for name in publisher.DIRECT_CLIENT_COUNTERS}
        known.update(acknowledged_bytes=evidence.DIRECT_LARGE_OBJECT_BYTES + 37,
            provider_successes=evidence.DIRECT_METADATA_OBJECT_COUNT + 1, max_provider_active=2)
        original = {"sessionDigest": "a" * 64, "originalDigest": "b" * 64,
            "placementDigest": "c" * 64, "byteSize": "64"}
        provider = {"unresolvedReceiptIndexes": [], "unknownCallers": 0, "nativeProviderCalls": 0,
            "classified": [{**original, "caller": "client", "method": "PUT", "location": "stage",
                "status": 200, "objectTransferBytes": 64}]}
        recovery = {"terminalCountersUnavailable": [{"label": "a", "attempt": 1}],
            "interruption": {"result": {"exitCode": -9, "timedOut": False}},
            "continuity": {"preservedPositiveParts": 1}, "changedSource": {"journalsUnchanged": True}}
        routes = ["BeginRegistryPublicationManifest", "AppendRegistryPublicationManifest",
            "AppendRegistryPublicationManifest", "SealRegistryPublicationManifest", "CommitRegistryPublication"]
        requests = [{"procedure": "/aos.hub.v1.PublishService/" + name,
            "method": "POST", "status": 200} for name in routes]
        return known, {"metadata_source_bytes": 37}, recovery, {"originals": [original]}, provider, requests

    def test_full_provider_coverage_does_not_reconstruct_killed_client_counters(self):
        values = self.inputs()
        result = evidence.assert_direct_recovered_activity(*values)
        self.assertFalse(result["clientTerminalCountersComplete"])
        self.assertEqual(result["knownTerminalAcknowledgedBytes"], values[0]["acknowledged_bytes"])
        self.assertEqual(result["positiveClientProviderBodyBytes"], 64)
        self.assertNotIn("reconstructedCounters", result)

    def test_missing_original_provider_or_manifest_receipts_refuse_coverage(self):
        for mutate in (
                lambda value: value[4].update(unresolvedReceiptIndexes=[0]),
                lambda value: value[4].update(unknownCallers=1),
                lambda value: value[4]["classified"][0].update(objectTransferBytes=63),
                lambda value: value[2].update(continuity=None),
                lambda value: value[2]["interruption"]["result"].update(exitCode=0),
                lambda value: value[5].pop(1),
                lambda value: value[0].update(max_provider_active=1)):
            values = copy.deepcopy(self.inputs())
            mutate(values)
            with self.assertRaises(ValueError):
                evidence.assert_direct_recovered_activity(*values)


if __name__ == "__main__":
    unittest.main()
