"""Controlled revision/configuration/ledger gates; no runtime qualification."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
specification = importlib.util.spec_from_file_location(
    "read_faults", Path(__file__).with_name("_hub-direct-read-fault-window.py"))
faults = importlib.util.module_from_spec(specification)
specification.loader.exec_module(faults)


class RevisionFaultTests(unittest.TestCase):
    def setUp(self):
        self.source = "/nix/store/" + "1" * 32 + "-alternate-source"
        self.digest = hashlib.sha256(self.source.encode()).hexdigest()
        self.fixture = {"source": self.source, "distribution": "/nix/store/" + "2" * 32 + "-alternate-worker",
            "purpose": "comment-only-source-revision", "features": ["do-e2e"],
            "sourceDigest": self.digest, "scriptVersion": "emulated-" + self.digest}
        self.configuration = {"scriptPath": "/nix/store/" + "3" * 32 + "-current-worker/shim.mjs",
            "resourcePersistencePath": "/var/lib/hybrid-worker/state", "host": "127.0.0.1", "port": 4443,
            "bindings": {"HUB_DEPLOYMENT_ID": "controlled", "HUB_STORAGE_WORK_KEY": "private-control" * 4,
                "HUB_EXTERNAL_COPY_CONSUMER": "actual installed configuration bytes",
                "HUB_PROVIDER_CAPACITY_POLICY": json.dumps({"version": 1, "deployment_id": "controlled",
                    "source_digest": "a" * 64, "script_version": "emulated-" + "a" * 64,
                    "maximum_provider_requests": 3})},
            "durableObjects": {"EXTERNAL_OBJECT_GUARD": {"className": "ExternalObjectGuard"}},
            "kvNamespaces": {"HUB_DIRECT_UPLOAD_ACCEPTANCE": "actual installed namespace"},
            "queueConsumers": {"bulk": {"maxBatchSize": 2}},
            "namespaceObservationPath": "/var/lib/hybrid-worker/namespace-startup"}
        self.original = json.dumps({"version": 1, "plan_id": "b" * 32,
            "operation": {"kind": "inspect_metadata", "path": "info/refs"}}).encode()
        self.before = {"index": [["fresh", None, "signed-commit", "signed metadata"]],
            "packages": [["actual package"]], "releases": [["actual release"]]}
        self.after = copy.deepcopy(self.before)
        self.after["index"][0][:2] = ["failed", "actual worker refusal"]
        self.installation = {"sourceDigest": self.digest, "scriptVersion": "emulated-" + self.digest,
            "wasmSha256": "c" * 64, "currentWasmSha256": "d" * 64,
            "configurationDelta": ["scriptPath"], "macVerified": True,
            "receivedRequestSha256": hashlib.sha256(self.original).hexdigest()}

    def assess(self, **changes):
        values = {"original": self.original, "received": self.original,
            "response": {"status": 503, "body": b"storage work failed"},
            "runtime_log": "storage_work_failed plan=" + "b" * 32 + " operation=inspect_metadata",
            "before": self.before, "after": self.after, "fixture": self.fixture,
            "installation": self.installation, "provider_rows": []}
        values.update(changes)
        return faults.require_revision_refusal(**values)

    def test_alternate_module_preserves_every_other_configured_authority_and_path(self):
        original = copy.deepcopy(self.configuration)
        result = faults.revision_worker_configuration(self.configuration, self.fixture)
        self.assertEqual(self.configuration, original)
        self.assertEqual(result.pop("scriptPath"), self.fixture["distribution"] + "/shim.mjs")
        original.pop("scriptPath")
        self.assertEqual(result, original)

    def test_fake_revision_same_source_changed_policy_and_missing_feature_refuse(self):
        variants = []
        fixture = copy.deepcopy(self.fixture)
        fixture["sourceDigest"] = "a" * 64
        fixture["scriptVersion"] = "emulated-" + "a" * 64
        variants.append((self.configuration, fixture))
        fixture = copy.deepcopy(self.fixture)
        fixture["features"] = []
        variants.append((self.configuration, fixture))
        configuration = copy.deepcopy(self.configuration)
        policy = json.loads(configuration["bindings"]["HUB_PROVIDER_CAPACITY_POLICY"])
        policy["source_digest"] = self.digest
        policy["script_version"] = self.fixture["scriptVersion"]
        configuration["bindings"]["HUB_PROVIDER_CAPACITY_POLICY"] = json.dumps(policy)
        variants.append((configuration, self.fixture))
        configuration = copy.deepcopy(self.configuration)
        del configuration["bindings"]["HUB_PROVIDER_CAPACITY_POLICY"]
        variants.append((configuration, self.fixture))
        for configuration, fixture in variants:
            with self.subTest(configuration=configuration), self.assertRaises((KeyError, ValueError)):
                faults.revision_worker_configuration(configuration, fixture)

    def test_actual_refusal_requires_exact_handler_mac_module_and_provider_scope(self):
        self.assertEqual(self.assess()["outcome"], "installed_worker_revision_refused")
        changes = [
            {"received": self.original + b" "},
            {"response": {"status": 502, "body": b"storage work failed"}},
            {"response": {"status": 503, "body": b"generic upstream failure"}},
            {"runtime_log": "no actual selected authenticated handler"},
            {"provider_rows": [{"method": "GET", "path": "/selected/info/refs"}]},
            {"installation": {**self.installation, "macVerified": False}},
            {"installation": {**self.installation, "wasmSha256": self.installation["currentWasmSha256"]}},
            {"installation": {**self.installation, "configurationDelta": ["scriptPath", "bindings"]}},
        ]
        for value in changes:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.assess(**value)

    def test_authoritative_contents_or_failed_original_relabel_refuse(self):
        changed = copy.deepcopy(self.after)
        changed["packages"].append(["substituted publication"])
        with self.assertRaises(ValueError):
            self.assess(after=changed)
        changed = copy.deepcopy(self.after)
        changed["index"][0][2] = "different signed commit"
        with self.assertRaises(ValueError):
            self.assess(after=changed)
        with self.assertRaises(ValueError):
            self.assess(after=self.before)

    def test_called_ledger_preserves_distinct_scopes_and_exact_retained_results(self):
        timeout = {"status": "observed_verification_refusal"}
        stale = {"verdict": {"outcome": "native_stale_result_refused"}, "providerRequests": None}
        revision = {"verdict": {"outcome": "installed_worker_revision_refused"}, "restored": True}
        originals = [("verification-timeout-assessment.json", timeout),
            ("actual-stale-index-case.private.json", stale), ("actual-worker-revision-refusal.json", revision)]
        with tempfile.TemporaryDirectory() as directory:
            previous = Path.cwd()
            os.chdir(directory)
            try:
                root = Path("external-direct-flow")
                root.mkdir(mode=0o700)
                for name, value in originals:
                    (root / name).write_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n")
                result = faults.called_read_fault_ledger(timeout, stale, revision)
                self.assertEqual(set(result["cases"]), {"provider_timeout", "stale_placement", "worker_revision"})
                self.assertIn("no Native Stage MAC", result["cases"]["provider_timeout"]["scope"])
                self.assertIn("unknown", result["cases"]["stale_placement"]["scope"])
                with self.assertRaises(ValueError):
                    faults.called_read_fault_ledger(timeout, stale, {**revision, "restored": False})
                (root / originals[0][0]).write_bytes(b"{}\n")
                with self.assertRaisesRegex(ValueError, "changed"):
                    faults.called_read_fault_ledger(timeout, stale, revision)
            finally:
                os.chdir(previous)

    def test_source_abi_and_comment_variant_refuse_other_edits(self):
        with tempfile.TemporaryDirectory() as directory:
            current = Path(directory) / "current"
            alternate = Path(directory) / "alternate"
            names = {
                "crates/aos-hub-worker/src/direct_upload/provider_capacity/policy.rs": "unchanged policy",
                "crates/aos-hub-worker/src/external_object/config.rs": "unchanged configuration",
                "crates/aos-hub-worker/src/external_object/copy/config.rs": "unchanged copy schema",
                "crates/aos-hub-worker/src/hybrid_binding.rs": "unchanged binding lookup",
                "crates/aos-hub-worker/src/hybrid.rs": "async fn execute_storage_work(\nunchanged MAC\n    let operation_kind = 'metadata';",
                "crates/aos-hub-worker/src/external_object/inspection/runtime.rs": (
                    "pub(crate) async fn execute(\nunchanged configuration\n    let domain = 'current';\n"
                    "unchanged source contract and capacity guard\n    let fresh = 'reader current';"),
                "crates/aos-hub-worker/src/lib.rs": "unchanged crate body\n",
            }
            suffix = "\n// This source snapshot belongs to the fleet revision-refusal fixture.\n"
            for name, body in names.items():
                for root in (current, alternate):
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(body + (suffix if root == alternate and name.endswith("/lib.rs") else ""))
            faults.require_revision_source_abi(current, alternate, "comment-only-source-revision")
            path = alternate / "crates/aos-hub-worker/src/hybrid.rs"
            path.write_text(path.read_text().replace("unchanged MAC", "different MAC"))
            with self.assertRaisesRegex(ValueError, "pre-dispatch"):
                faults.require_revision_source_abi(current, alternate, "retained-source-revision")
            path.write_text((current / "crates/aos-hub-worker/src/hybrid.rs").read_text())
            path = alternate / "crates/aos-hub-worker/src/external_object/inspection/runtime.rs"
            path.write_text(path.read_text().replace("unchanged source contract and capacity guard",
                "old versioned semantic mode unsupported"))
            with self.assertRaisesRegex(ValueError, "authentication/configuration ABI"):
                faults.require_revision_source_abi(current, alternate, "retained-source-revision")


class RevisionEpochTests(unittest.TestCase):
    setUp = RevisionFaultTests.setUp

    def run_epoch(self, *, release_failure=False, stop_failure=False):
        events = []
        retained = {}
        with tempfile.TemporaryDirectory() as directory:
            previous = Path.cwd()
            os.chdir(directory)
            try:
                root = Path("external-direct-flow")
                root.mkdir(mode=0o700)
                trust = b"{}"
                (root / "native-trust-read-revision.json").write_bytes(trust)
                provider_file = root / "provider.private.jsonl"
                provider_file.write_bytes(b"")
                rows = [[1, 2, 3, 4, "s3", "binding/placement", "bucket", "binding"]]

                def guest(machine, tools, action, value):
                    kind = value.get("request", {}).get("kind", action)
                    events.append(kind)
                    if kind == "status":
                        return {"state": "held", "requestSha256": hashlib.sha256(self.original).hexdigest()}
                    if kind == "release" and release_failure:
                        raise ValueError("original expired before actual release")
                    if kind == "index-terminal":
                        return {"exitCode": 1, "timedOut": False}
                    return {}

                def start(machine, tools, configuration, generation):
                    events.append("start-" + generation)
                    return {"configurationFile": configuration, "generation": generation}

                def stop(machine, python, process):
                    events.append("stop-" + process["generation"])
                    if stop_failure and process["generation"] == "read-revision":
                        raise ValueError("owned alternate disposal remains unknown")
                    return {"status": "recorded_runner_disposed"}

                controller = SimpleNamespace(_guest=guest, capture_direct_stale_index_environment=lambda *args: {})
                class Query:
                    def __call__(self, query):
                        return copy.deepcopy(rows)
                observed_indexes = iter([self.before, self.after])
                configuration_body = json.dumps(self.configuration).encode()
                bindings = {
                    "read_direct_guest_file": lambda *args: configuration_body,
                    "_closed_review_json": json.loads,
                    "install_direct_guest_file": lambda *args: {"file": "alternate.private.json"},
                    "observe_direct_revision_artifacts": lambda *args: {},
                    "DirectStaleIndexSql": lambda *args, **kwargs: Query(),
                    "registry_index_observations": lambda *args: copy.deepcopy(next(observed_indexes)),
                    "observe_direct_native_trust": lambda *args: hashlib.sha256(trust).hexdigest(),
                    "managed_fixture_module": lambda *args: controller,
                    "stop_direct_worker": stop, "start_direct_worker": start,
                    "wait_worker_transport": lambda *args, **kwargs: events.append("transport-" + kwargs["observation_label"]),
                    "direct_log_position": lambda *args: {},
                    "retain_direct_log_window": lambda *args: (provider_file, {"capturedBytes": 0}),
                    "observe_direct_revision_exchange": lambda *args: {"original": self.original, "received": self.original,
                        "response": {"status": 503, "body": b"storage work failed"}, "runtimeLog":
                            "storage_work_failed plan=" + "b" * 32 + " operation=inspect_metadata",
                        "installation": self.installation, "receipt": {"controlled": True}},
                    "retain_direct_flow": lambda name, value: retained.update({name: value}),
                    "run_direct_revision_restored_index": lambda *args: events.append("new-current-index"),
                }
                tools = {"readRevisionFixture": self.fixture, "python": "controlled-python", "curl": "controlled-curl",
                    "hub": "controlled-hub", "staleIndexController": "controlled-controller",
                    "staleIndexProcess": "controlled-process", "staleIndexInstallation": {"root": "/controlled"},
                    "deploymentId": "controlled"}
                process = {"configurationFile": "current.private.json", "generation": "current"}
                registry = {"registry": {"slug": "controlled/registry"}, "placement": {"name": "primary"}}
                with patch.dict(faults.__dict__, bindings):
                    try:
                        result = faults.run_direct_worker_revision_case(None, None, None, tools, process,
                            registry, {"sourceCommit": "signed-commit"}, {})
                    except ValueError as error:
                        result = error
                return result, events, retained
            finally:
                os.chdir(previous)

    def test_owned_epoch_disposes_in_order_and_restores_before_new_command(self):
        result, events, retained = self.run_epoch()
        self.assertEqual(result[1]["generation"], "read-revision-restored")
        for left, right in (("status", "stop-current"), ("stop-current", "start-read-revision"),
                ("start-read-revision", "release"), ("finish-revision", "stop-read-revision"),
                ("stop-read-revision", "start-read-revision-restored"),
                ("start-read-revision-restored", "new-current-index")):
            self.assertLess(events.index(left), events.index(right))
        self.assertTrue(retained["actual-worker-revision-refusal.json"]["restored"])

    def test_expired_original_is_not_replayed_and_only_owned_epoch_is_cleaned(self):
        result, events, retained = self.run_epoch(release_failure=True)
        self.assertIsInstance(result, ValueError)
        self.assertEqual(events.count("release"), 1)
        self.assertIn("close", events)
        self.assertIn("stop-read-revision", events)
        self.assertIn("start-read-revision-restored", events)
        self.assertNotIn("new-current-index", events)
        self.assertNotIn("actual-worker-revision-refusal.json", retained)
        self.assertIsNone(retained["read-revision-unresolved.json"]["remoteDrain"])

    def test_unknown_disposal_cannot_start_another_owner_or_write_success(self):
        result, events, retained = self.run_epoch(stop_failure=True)
        self.assertIsInstance(result, ValueError)
        self.assertNotIn("start-read-revision-restored", events)
        self.assertNotIn("new-current-index", events)
        self.assertNotIn("actual-worker-revision-refusal.json", retained)


if __name__ == "__main__":
    unittest.main()
