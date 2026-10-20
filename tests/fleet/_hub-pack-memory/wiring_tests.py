"""Check source transport, one-use selectors and fail-closed orchestration.

These local mechanics do not manufacture SQL admissions, provider observations,
Native authentication, actual interval headers or whole-isolate measurements.
The called production fixture remains the integration gate for those facts.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from bridge import checked_request, encoded, read_private, write_private
from callbacks import FreshNativeCallbacks
from files import transfer_chunk
from guest import original_child_cutoff
from transport import checked_root


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fleet = load("pack_controller", ROOT.parent / "_hub-pack-memory-fleet.py")
window = load("oci_window", ROOT.parent / "_hub-external-oci-window.py")
pair_fixture = load("pair_fixture", ROOT.parent / "_hub-external-oci-pair.py")


class WiringTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)

    def test_atomic_publication_hides_paused_writer_and_never_overwrites(self):
        destination = self.root / "request.json"
        selected = {"version": 1, "actual": "complete bounded original"}
        paused = threading.Event()
        release = threading.Event()
        failures = []
        fsync = os.fsync

        def paused_fsync(descriptor):
            if not paused.is_set():
                paused.set()
                if not release.wait(2):
                    raise TimeoutError("controlled paused writer cutoff")
            fsync(descriptor)

        def publish():
            try:
                write_private(destination, selected)
            except BaseException as error:
                failures.append(error)

        with patch("bridge.os.fsync", paused_fsync):
            writer = threading.Thread(target=publish)
            writer.start()
            try:
                self.assertTrue(paused.wait(2))
                with self.assertRaises(FileNotFoundError):
                    read_private(destination, 1024)
            finally:
                release.set()
                writer.join(2)
        self.assertFalse(writer.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(read_private(destination, 1024), encoded(selected))
        self.assertEqual(destination.stat().st_nlink, 1)
        with self.assertRaises(FileExistsError):
            write_private(destination, {"version": 1, "actual": "replacement"})
        self.assertEqual(read_private(destination, 1024), encoded(selected))

    def template(self, root=None):
        return write_private(self.root / "template.json", {"version": 1,
            "helperInputFile": "/selected/helper.json", "helperInputSha256": "b" * 64,
            "outputFile": str((root or self.root) / "result.json"),
            "phase": {"kind": "pack", "registry_id": 1,
                "index_path": "objects/pack/pack-" + "a" * 64 + ".idx", "oid": "c" * 40}})

    def test_selector_gets_actual_dispatch_time_and_never_extends_parent(self):
        callbacks = FreshNativeCallbacks(None, self.root, time.monotonic() + 12)
        actual = callbacks.selection(self.template())
        selection = json.loads(Path(actual["file"]).read_bytes())
        self.assertGreater(selection["cutoffUnixSeconds"], int(time.time()))
        self.assertLessEqual(selection["cutoffUnixSeconds"], int(time.time()) + 12)
        self.assertEqual(callbacks.references[0]["actualSelection"], actual)

    def test_selector_replay_is_refused(self):
        callbacks = FreshNativeCallbacks(None, self.root, time.monotonic() + 20)
        reference = self.template()
        callbacks.selection(reference)
        with self.assertRaises(ValueError):
            callbacks.selection(reference)

    def test_selector_expiry_does_not_create_a_new_plan(self):
        callbacks = FreshNativeCallbacks(None, self.root, time.monotonic() + 2)
        with self.assertRaises(TimeoutError):
            callbacks.selection(self.template())
        self.assertFalse(list(self.root.glob("selected-*.json")))

    def test_selector_wrong_output_root_refuses(self):
        callbacks = FreshNativeCallbacks(None, self.root, time.monotonic() + 20)
        with self.assertRaises(ValueError):
            callbacks.selection(self.template(self.root / "foreign"))

    def test_mailbox_crossed_run_and_boolean_sequence_refuse(self):
        request = {"version": 1, "runId": "a" * 32, "case": "live36", "sequence": 0, "action": "state"}
        for bad in ({**request, "runId": "b" * 32}, {**request, "sequence": False},
                    {**request, "version": True}, {**request, "action": "replace"}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    checked_request(bad, "a" * 32, "live36", 0)

    def test_guest_root_rejects_foreign_scope_and_traversal(self):
        for path in (str(self.root), "/var/lib/hybrid-native/external-oci/" + "a" * 32
                     + "/pack-memory/live36/../semantic32", "/var/lib/hybrid-native/operator/keys"):
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    checked_root(path)

    def chunk(self, data, offset, body, final=True, digest=None):
        import base64
        return {"leaf": "pack.bin", "offset": offset, "body": base64.b64encode(body).decode(),
            "bytes": len(data), "sha256": digest or hashlib.sha256(data).hexdigest(), "final": final}

    def test_chunked_publisher_copy_has_complete_sha_and_single_link(self):
        (self.root / "source").mkdir(mode=0o700)
        data = b"x" * (128 * 1024) + b"actual-tail"
        first = transfer_chunk(self.root, self.chunk(data, 0, data[:128 * 1024], False))
        self.assertIsNone(first["reference"])
        last = transfer_chunk(self.root, self.chunk(data, 128 * 1024, data[128 * 1024:]))
        target = Path(last["reference"]["file"])
        self.assertEqual(target.read_bytes(), data)
        self.assertEqual(target.stat().st_nlink, 1)
        self.assertEqual(last["reference"]["sha256"], hashlib.sha256(data).hexdigest())

    def test_chunk_replay_does_not_replace_source(self):
        (self.root / "source").mkdir(mode=0o700)
        data = b"actual-fixture"
        transfer_chunk(self.root, self.chunk(data, 0, data))
        with self.assertRaises(FileExistsError):
            transfer_chunk(self.root, self.chunk(data, 0, data))
        self.assertEqual((self.root / "source/pack.bin").read_bytes(), data)

    def test_wrong_source_sha_keeps_only_partial_private_file(self):
        (self.root / "source").mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            transfer_chunk(self.root, self.chunk(b"source", 0, b"source", digest="0" * 64))
        self.assertFalse((self.root / "source/pack.bin").exists())
        self.assertTrue((self.root / "source/pack.bin.partial").is_file())

    def test_partial_symlink_refuses_without_writing_target(self):
        (self.root / "source").mkdir(mode=0o700)
        target = self.root / "outside"
        target.write_bytes(b"original")
        (self.root / "source/pack.bin.partial").symlink_to(target)
        with self.assertRaises(OSError):
            transfer_chunk(self.root, self.chunk(b"source", 0, b"source"))
        self.assertEqual(target.read_bytes(), b"original")

    def test_public_projection_excludes_all_secret_roles(self):
        bindings = {name: "public" for name in fleet.PACK_MEMORY_PUBLIC_BINDINGS}
        bindings.update(HUB_STORAGE_WORK_KEY="fixture-not-a-real-key",
            HUB_MIRROR_CANDIDATE_KEY="fixture-not-a-real-key",
            HUB_DIRECT_UPLOAD_R2_SECRET_ACCESS_KEY="fixture-not-a-real-key")
        projected = fleet.pack_memory_public_projection({"bindings": bindings,
            "r2Buckets": {"REGISTRY_BUCKET": "actual-namespace"}})
        self.assertEqual(set(projected["bindings"]), set(fleet.PACK_MEMORY_PUBLIC_BINDINGS))
        self.assertNotIn("fixture-not-a-real-key", json.dumps(projected))

    def test_only_dedicated_candidate_pair_enables_raw_managed_loader(self):
        run = "a" * 32
        original = {"scriptPath": "/nix/store/selected/shim.mjs", "compatibilityDate": "2024-09-23",
            "certificatePath": "/selected/public-test-tls", "privateKeyPath": "/selected/public-test-tls",
            "queueProducers": {"HUB_DIRECT_VERIFY_BULK": "bulk", "HUB_DIRECT_VERIFY_METADATA": "metadata"},
            "queueConsumers": {"bulk": {"maxBatchSize": 1}, "metadata": {"maxBatchSize": 2}},
            "bindings": {"HUB_DIRECT_VERIFY_MAX_PARALLEL_OBJECTS": "3"}}
        tools = {"shim": original["scriptPath"], "externalCopyIsolation": "/nix/store/selected/isolation.cjs",
            "workerSourcePath": "/nix/store/selected/actual-worker-source"}
        clock = {"policy": {"version": 1, "mode": "bounded_utc", "uncertaintySeconds": "1"}, "commitment": "b" * 64}
        for case, enabled in (("same_worker", False), ("source_worker", True), ("same_worker", True)):
            selected_tools = {**tools, "copyIsolationCase": case}
            if enabled:
                selected_tools["packMemoryModules"] = "/nix/store/selected/pack-memory-modules"
            roles = {name: f"{number + 1:064x}" for number, name in enumerate(pair_fixture.external_oci_role_names(selected_tools))}
            configured = pair_fixture.external_oci_initial_configuration(original, selected_tools,
                pair_fixture.external_oci_pair_coordinates(run), roles, clock, "c" * 64)
            self.assertEqual(configured["bindings"]["HUB_DIRECT_UPLOAD_MANAGED_R2"],
                "true" if enabled and case == "same_worker" else "false")
            self.assertEqual(configured["queueConsumers"], {"external-" + run + "-bulk": {"maxBatchSize": 1},
                "external-" + run + "-metadata": {"maxBatchSize": 2}})
            self.assertNotIn("HUB_MIRROR_CANDIDATE_KEY", original["bindings"])

    def test_persistent_sdk_poison_blocks_even_a_known_outer_wait(self):
        with self.assertRaises(RuntimeError):
            fleet.pack_memory_owner_retired({"value": {"ownedChildrenReaped": True,
                "retirementPoisoned": True}}, "native")
        self.assertTrue(fleet.pack_memory_owner_retired({"value": {"ownedChildrenReaped": True,
            "retirementPoisoned": False}}, "native")["ownedChildrenReaped"])

    def test_unknown_child_retirement_is_not_a_positive_path(self):
        for kind, key in (("native", "ownedChildrenReaped"), ("admission", "reaped"), ("source", "reaped")):
            for unknown in (None, False, 1):
                with self.subTest(kind=kind, unknown=unknown):
                    with self.assertRaises(RuntimeError):
                        fleet.pack_memory_owner_retired({"value": {key: unknown}}, kind)

    def test_outer_cleanup_uses_actual_original_child_cutoff(self):
        caller = SimpleNamespace(cutoff=120, process_cutoffs={"a" * 64: {"pid": 123, "cutoffMonotonic": 25}})
        self.assertEqual(original_child_cutoff(caller, SimpleNamespace(pid=123)), 25)
        for records in ({}, {"a" * 64: {"pid": None, "cutoffMonotonic": 25}},
                        {"a" * 64: {"pid": 123, "cutoffMonotonic": 25},
                         "b" * 64: {"pid": 123, "cutoffMonotonic": 26}}):
            with self.subTest(records=records):
                caller.process_cutoffs = records
                with self.assertRaises(RuntimeError):
                    original_child_cutoff(caller, SimpleNamespace(pid=123))

    def test_case_path_keeps_canonical_pack_view_and_publisher_sources(self):
        run = "a" * 32
        pair = {"case": "live36", "indexPath": "objects/pack/pack-" + "b" * 64 + ".idx",
            "packBytes": 4096, "indexBytes": 1024}
        source = {"signed": {"surfaceRoot": "/selected/publisher"}, "inventory": {"objects": [
            {"path": "helper.narinfo", "byteSize": 128, "sha256": "c" * 64},
            {"path": "info/refs", "byteSize": 96, "sha256": "d" * 64}]}}
        actual = fleet.pack_memory_case_inputs(pair, "live36", run, source, 1024 * 1024)
        self.assertEqual(actual["indexPath"], "releases/memory/" + run + "/live36/" + pair["indexPath"])
        self.assertEqual(len(actual["metadata"]), 2)
        self.assertEqual(actual["metadata"][1]["source"]["file"], "/selected/publisher/info/refs")
        with self.assertRaises(ValueError):
            fleet.pack_memory_case_inputs({**pair, "packBytes": 1024 * 1024 + 1}, "live36", run, source, 1024 * 1024)

    def test_unknown_case_stops_next_registry_mutation(self):
        calls = []
        prepared = {"packMemoryMaterial": {}, "coordinates": {"runId": "a" * 32}}
        def failed(*args):
            calls.append(args[-1]["case"])
            raise RuntimeError("controlled unknown retirement")
        with patch.object(fleet, "prepare_pack_memory_export", return_value={"manifest": {"pairs": [
                {"case": case} for case in fleet.PACK_MEMORY_CASES]}}), \
                patch.object(fleet, "prepare_pack_memory_registry", return_value={}), \
                patch.object(fleet, "run_pack_memory_case", side_effect=failed):
            with self.assertRaises(RuntimeError):
                fleet.run_current_pack_memory_window(None, None, None, {"copyIsolationCase": "same_worker"},
                    prepared, {}, {}, {"evidence": {"source": {}}}, None)
        self.assertEqual(calls, ["semantic32"])

    def exercise_outer_order(self, memory_failure=False):
        events = []
        original = {name: getattr(window, name, None) for name in (
            "external_oci_pair_coordinates", "await_direct_review", "direct_guest_python",
            "provision_external_oci_pair", "prepare_external_oci_boundaries", "start_external_oci_pair",
            "select_external_storage_codec", "ExternalOciWorkflowCapture", "run_external_oci_business_lane",
            "managed_fixture_module", "retain_direct_flow", "teardown_external_oci_pair")}
        self.addCleanup(lambda: [setattr(window, name, value) for name, value in original.items()])
        window.external_oci_pair_coordinates = pair_fixture.external_oci_pair_coordinates
        window.await_direct_review = lambda *args: {"selection": {"mirrorReviewerPublicKey": "fixture", "mirrorReviewerKeyId": "fixture"}}
        window.direct_guest_python = lambda *args: json.dumps({"native": "10.0.0.1", "worker": "10.0.0.2"})
        window.provision_external_oci_pair = lambda *args: {"coordinates": pair_fixture.external_oci_pair_coordinates("a" * 32),
            "nativeFiles": {"HUB_STORAGE_WORK_KEY": "/opaque/role", "database": "/opaque/db"}}
        window.prepare_external_oci_boundaries = lambda *args: {}
        window.start_external_oci_pair = lambda *args, **kwargs: {"native": {}, "worker": {}}
        window.select_external_storage_codec = lambda *args: {}
        window.ExternalOciWorkflowCapture = lambda *args: SimpleNamespace(
            complete=lambda *args: events.append("ordinary_capture") or {})
        def business(*args):
            events.append("ordinary_publication")
            ownership = args[-3]
            def memory():
                events.append("supplemental_memory")
                if memory_failure:
                    raise RuntimeError("controlled unknown retirement")
                return {"wholeIsolateBytes": None, "memory128PredicateQualified": False}
            ownership["packMemoryCaller"] = memory
            return {"ordinaryResult": True}
        window.run_external_oci_business_lane = business
        window.managed_fixture_module = lambda *args: SimpleNamespace(
            consume_external_workflow_evidence=lambda *args, **kwargs:
                events.append("ordinary_assessment") or {"complete": True, "capturedObjectByteUpperBound": 0})
        window.retain_direct_flow = lambda *args: "fixed-local-test-reference"
        window.teardown_external_oci_pair = lambda *args: events.append("owned_teardown") or []
        arguments = (None, None, None, None, None, {"python": "selected",
            "externalWorkflowAccounting": "/selected/accounting.py"}, "database", {}, {}, "fixture")
        if memory_failure:
            with self.assertRaises(RuntimeError):
                window.run_external_oci_pair_window(*arguments, planned_run="a" * 32)
        else:
            result = window.run_external_oci_pair_window(*arguments, planned_run="a" * 32)
            self.assertTrue(result["ordinaryResult"])
            self.assertIsNone(result["packMemory"]["wholeIsolateBytes"])
        self.assertEqual(events, ["ordinary_publication", "ordinary_capture", "ordinary_assessment",
            "supplemental_memory", "owned_teardown"])

    def test_main_publication_runs_before_unqualified_memory(self):
        self.exercise_outer_order()

    def test_memory_failure_preserves_main_order_and_owned_teardown(self):
        self.exercise_outer_order(memory_failure=True)


if __name__ == "__main__":
    unittest.main()
