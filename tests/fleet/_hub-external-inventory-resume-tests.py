"""Controlled checkpoint observations; no SQL/provider/restart qualification."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("inventory_resume", Path(__file__).with_name("_hub-external-inventory-resume.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def example():
    generation = {"id": "ociinv-" + "a" * 32, "state": "collecting", "active_slot": 1,
        "registry_id": 1, "placement_id": 2, "collector_lease_expires_at": 100,
        "collector_id": "controlled", "collector_claim_token": "controlled-claim",
        "resource_version": 3, "checkpoint_ordinal": 4, "provider_cursor": None,
        "captured_mutation_epoch": 5, "placement_resource_version": 6,
        "placement_write_spec_version": 7, "placement_observation_version": 8,
        "binding_id": 9, "binding_resource_version": 10, "binding_write_revision": 11}
    current = {key: generation[key] for key in ("placement_resource_version",
        "placement_write_spec_version", "placement_observation_version", "binding_id",
        "binding_resource_version", "binding_write_revision")}
    current.update(registry_stable_id="controlled-registry", placement_prefix="selected/registry", mutation_epoch=5)
    expected = {"registryId": 1, "placementId": 2, "registryStableId": "controlled-registry",
        "placementPrefix": "selected/registry", "objectKey": "oci/blobs/sha256/" + "b" * 64,
        "objectDigest": "sha256:" + "b" * 64, "objectBytes": 16 * 1024 * 1024}
    obj = {"placement_id": 2, "checkpoint_ordinal": 4, "provider_cursor": None,
        "object_key": expected["objectKey"], "object_digest": expected["objectDigest"],
        "expected_size": expected["objectBytes"], "strong_etag": '\"selected\"',
        "next_offset": 8 * 1024 * 1024, "sha_version": 1, "sha_words": [0] * 8,
        "sha_total_bytes": 8 * 1024 * 1024, "sha_tail_hex": ""}
    progress = {"version": 1, "generation_id": generation["id"], "next_provider_cursor": None, "object": obj}
    row = {"generation": generation, "current": current,
        "progressHex": json.dumps(progress, separators=(",", ":")).encode().hex()}
    return row, expected, progress


def encode(row, progress):
    row["progressHex"] = json.dumps(progress, separators=(",", ":")).encode().hex()


class ProgressTests(unittest.TestCase):
    def test_selected_partial_offset_has_only_bounded_public_metadata(self):
        row, expected, _ = example()
        summary = module.require_partial_inventory(row, expected, 99)
        self.assertEqual(summary["nextOffset"], 8 * 1024 * 1024)
        self.assertLess(summary["nextOffset"], summary["expectedSize"])
        for private in ("collector_claim_token", "strong_etag", "provider_cursor", "guarded_source"):
            self.assertNotIn(private, summary)

    def test_expired_claim_and_changed_current_sql_fences_refuse(self):
        for key in ("placement_resource_version", "placement_write_spec_version",
                "placement_observation_version", "binding_id", "binding_resource_version",
                "binding_write_revision", "mutation_epoch"):
            row, expected, _ = example()
            row["current"][key] += 1
            with self.assertRaises(ValueError):
                module.require_partial_inventory(row, expected, 99)
        row, expected, _ = example()
        with self.assertRaises(ValueError):
            module.require_partial_inventory(row, expected, 100)

    def test_other_generation_object_cursor_and_checkpoint_refuse(self):
        for section, key, changed in (("outer", "generation_id", "ociinv-" + "c" * 32),
                ("object", "object_key", "other"), ("object", "provider_cursor", "other"),
                ("object", "checkpoint_ordinal", 5), ("object", "placement_id", 3)):
            row, expected, progress = example()
            (progress if section == "outer" else progress["object"])[key] = changed
            encode(row, progress)
            with self.assertRaises(ValueError):
                module.require_partial_inventory(row, expected, 99)

    def test_terminal_offset_and_corrupt_portable_hash_refuse(self):
        for key, changed in (("next_offset", 0), ("next_offset", 16 * 1024 * 1024),
                ("sha_total_bytes", 1), ("sha_words", [0] * 7), ("sha_tail_hex", "00")):
            row, expected, progress = example()
            progress["object"][key] = changed
            encode(row, progress)
            with self.assertRaises(ValueError):
                module.require_partial_inventory(row, expected, 99)

    def test_duplicate_or_oversized_progress_refuse(self):
        row, expected, _ = example()
        row["progressHex"] = b'{"version":1,"version":1}'.hex()
        with self.assertRaises(ValueError):
            module.require_partial_inventory(row, expected, 99)
        row["progressHex"] = b"x".hex() * (module.MAX_PROGRESS_BYTES + 1)
        with self.assertRaises(ValueError):
            module.require_partial_inventory(row, expected, 99)

    def test_observation_uses_exact_readonly_transaction_and_private_receipt(self):
        row, expected, _ = example()
        calls = []
        def read_sql(query, label):
            calls.append(query)
            return {"value": copy.deepcopy(row), "receipt": {"controlledPrivateReference": label}}
        observed = module.observe_partial_inventory(read_sql, expected, "inventory-partial", 99)
        self.assertEqual(observed["privateSql"]["value"], row)
        self.assertTrue(calls[0].startswith("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;"))
        self.assertTrue(calls[0].endswith("COMMIT;"))
        self.assertIn("g.registry_id=1 AND g.placement_id=2", calls[0])
        self.assertIn("encode(g.object_progress,'hex')", calls[0])
        with self.assertRaises(ValueError):
            module.observe_partial_inventory(lambda *a: {"value": row, "receipt": None}, expected, "inventory-partial", 99)

    def test_lease_time_is_sampled_after_awaited_sql(self):
        row, expected, _ = example()
        calls = []
        def read_sql(*args):
            calls.append("sql")
            return {"value": row, "receipt": {"controlled": True}}
        def after_sql():
            self.assertEqual(calls, ["sql"])
            return 100
        with self.assertRaises(ValueError):
            module.observe_partial_inventory(read_sql, expected, "inventory-expired", after_sql)

    def test_missing_partial_row_remains_retained_unknown_for_bounded_polling(self):
        _, expected, _ = example()
        observed = module.observe_partial_inventory(lambda *a: {
            "value": None, "receipt": {"controlledPrivateReference": "absent"}},
            expected, "inventory-not-yet-partial", 99)
        self.assertIsNone(observed["summary"])
        self.assertIsNone(observed["privateSql"]["value"])


class NativeEpochTests(unittest.TestCase):
    def load(self, name):
        selected = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
        child = importlib.util.module_from_spec(selected)
        selected.loader.exec_module(child)
        return child

    def test_native_restart_input_changes_only_three_observation_paths(self):
        business = self.load("_hub-external-oci-business")
        root = "/var/lib/hybrid-native/external-oci/" + "a" * 32
        original = {"readinessFile": root + "/helper-ready.json", "terminalFile": root + "/helper-terminal.json",
            "shutdownFile": root + "/helper-shutdown.json", "files": {"candidateFile": "/private/current"},
            "placementId": 2, "workerSourceDigest": "b" * 64}
        changed = business.external_inventory_restart_input(original, root)
        differences = {key for key in original if original[key] != changed[key]}
        self.assertEqual(differences, {"readinessFile", "terminalFile", "shutdownFile"})
        self.assertEqual(changed["files"], original["files"])
        with self.assertRaises(ValueError):
            business.external_inventory_restart_input({**original, "shutdownFile": "/another/file"}, root)

    def test_restart_log_is_only_allowed_for_controlled_native_epoch(self):
        window = self.load("_hub-managed-storage-window")
        root = "/var/lib/hybrid-native/external-oci/" + "a" * 32
        worker = "/var/lib/hybrid-worker/external-oci/" + "a" * 32
        processes = {"native": {"logFile": root + "/native-inventory-restart.log"},
            "worker": {"logFile": worker + "/external-oci-final.log"}}
        selected = {"kind": "external_oci", "nativeRole": "controlled_external_oci_native"}
        window.validate_selected_storage_logs(selected, processes, {"native": root, "worker": worker})
        with self.assertRaises(ValueError):
            window.validate_selected_storage_logs({**selected, "nativeRole": "ordinary_native"},
                processes, {"native": root, "worker": worker})
        processes["native"]["logFile"] = root + "/another.log"
        with self.assertRaises(ValueError):
            window.validate_selected_storage_logs(selected, processes, {"native": root, "worker": worker})

    def test_controller_registration_is_not_an_inventory_completion_flag(self):
        process = self.load("_hub-external-oci-process")
        run = "a" * 32
        identity = "external-oci-inventory-" + run
        ready = {"backgroundControllers": {"placementScan": {"intervalSeconds": 2, "maximumPlacements": 5},
            "ociInventory": {"collectorId": identity, "idempotencyPrefix": identity,
                "maximumPlacements": 100, "dispatchBudget": "native"},
            "mirrorSync": {"intervalSeconds": 60, "mode": "full"}}}
        process.require_external_background_controllers(ready, run)
        with self.assertRaises(ValueError):
            process.require_external_background_controllers({}, run)
        with self.assertRaises(ValueError):
            process.require_external_background_controllers(ready, "b" * 32)
        without_mirror = copy.deepcopy(ready)
        del without_mirror["backgroundControllers"]["mirrorSync"]
        with self.assertRaises(ValueError):
            process.require_external_background_controllers(without_mirror, run)
        for field, changed in (("intervalSeconds", 1), ("mode", "pull_through")):
            drifted = copy.deepcopy(ready)
            drifted["backgroundControllers"]["mirrorSync"][field] = changed
            with self.assertRaises(ValueError):
                process.require_external_background_controllers(drifted, run)
        self.assertNotIn("complete", ready["backgroundControllers"])


class ProviderCheckpointTests(unittest.TestCase):
    def fixture(self):
        row, expected, progress = example()
        expected["providerPrefix"] = "/fleet-s3/selected/registry/"
        root = "/private/controlled-inventory"
        files = {}
        def retain(name, value):
            raw = value if isinstance(value, bytes) else json.dumps(value).encode()
            path = root + "/" + name
            files[path] = raw
            return {"path": path, "sha256": hashlib.sha256(raw).hexdigest(), "byteSize": str(len(raw))}
        identity = {"method": "GET", "host": "s3.fleet.test", "signatureVerification": None,
            "targetSha256": hashlib.sha256((expected["providerPrefix"] + expected["objectKey"]).encode()).hexdigest(),
            "ifMatch": progress["object"]["strong_etag"], "range": "bytes=8388608-16777215"}
        receipt = {"version": 1, "scope": "actual_provider_partial_response_offering", "identity": identity,
            "requestReceipt": retain("request", {key: identity[key]
                for key in ("method", "targetSha256", "host", "range", "ifMatch")}),
            "headersReceipt": retain("headers", {"status": 206, "contentLength": "8388608",
                "contentRange": "bytes 8388608-16777215/16777216"}),
            "prefixFile": retain("prefix", b"p" * 65536), "downstreamOfferedBytes": "65536",
            "upstreamComplete": False, "workerConsumedBytes": None, "remoteDrain": None}
        expected["firstRangeSha256"] = hashlib.sha256(b"first-range-controlled").hexdigest()
        first = {"identity": {**identity, "range": "bytes=0-8388607"}, "status": 206,
            "contentLength": "8388608", "contentRange": "bytes 0-8388607/16777216",
            "responseBytes": "8388608", "upstreamComplete": True,
            "responseSha256": expected["firstRangeSha256"]}
        state = {"version": 1, "targetPrefix": expected["providerPrefix"], "selected": True,
            "prefixReceipt": retain("receipt", receipt), "recorderHealthy": True, "terminal": None,
            "pendingLocalHold": True, "providerSettlement": None, "continuationReceipts": [],
            "firstRangeReceipt": retain("first-range", first), "awaitingFirstRange": False,
            "holdUntilUnixMillis": 35000, "fixtureCutoffUnixMillis": 100000}
        observed = {"summary": module.require_partial_inventory(row, expected, 99),
            "privateSql": {"value": row, "receipt": {"controlled": True}}}
        return state, observed, expected, lambda path, maximum: files[path], root, files, retain, receipt

    def test_saved_interval_and_actual_offering_remain_separate(self):
        state, observed, expected, read_private, root, _, _, _ = self.fixture()
        result = module.require_inventory_provider_checkpoint(state, observed, expected, read_private, root)
        self.assertEqual(result["sql"]["summary"]["nextOffset"], 8388608)
        self.assertEqual(result["proxyOfferedBytes"], 65536)
        self.assertIsNone(result["nativeConsumedContinuationBytes"])
        self.assertIsNone(result["remoteDrain"])

    def test_unheld_replayed_or_changed_private_range_refuses_before_restart(self):
        for field, wrong in (("pendingLocalHold", False), ("recorderHealthy", False), ("firstRangeReceipt", None),
                ("providerSettlement", True), ("continuationReceipts", [{"replayed": True}])):
            args = self.fixture()
            args[0][field] = wrong
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.require_inventory_provider_checkpoint(*args[:5])
        args = self.fixture()
        args[5][args[0]["prefixReceipt"]["path"]] += b" "
        with self.assertRaises(ValueError):
            module.require_inventory_provider_checkpoint(*args[:5])
        for field, wrong in (("targetSha256", "f" * 64), ("ifMatch", '"another-tag"'),
                ("range", "bytes=0-8388607"), ("signatureVerification", True)):
            args = self.fixture()
            args[7]["identity"][field] = wrong
            args[0]["prefixReceipt"] = args[6]("receipt", args[7])
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.require_inventory_provider_checkpoint(*args[:5])


class RestartJoinTests(unittest.TestCase):
    def fixture(self):
        row, expected, progress = example()
        obj = progress["object"]
        obj["guarded_source"] = {"version": 1, "scope": "controlled", "closure": {"selected": True}}
        encode(row, progress)
        expected["secondRangeBytes"] = 8388608
        checkpoint = {"sql": {"summary": module.require_partial_inventory(row, expected, 99),
            "privateSql": {"value": row, "receipt": {"controlled": True}}}}
        process = {"pid": 42, "startTicks": "100", "executableSha256": "a" * 64}
        plan = {"plan_id": "controlled-plan", "placement_prefix": expected["placementPrefix"],
            **{name: row["generation"][name] for name in
                ("placement_id", "placement_resource_version", "binding_id", "binding_resource_version")},
            "operation": {"kind": "hash_oci_range", "path": expected["objectKey"], "start": 8388608,
                "end": 16777215, "total": expected["objectBytes"], "strong_etag": obj["strong_etag"],
                "sha256_state": {"version": 1, "words": obj["sha_words"], "total_bytes": 8388608, "tail_hex": ""},
                "guarded_source": obj["guarded_source"]}}
        result = {key: plan[key] for key in ("plan_id", "placement_id", "placement_resource_version", "binding_id", "binding_resource_version")}
        result.update(source_bytes=8388608, outcome={"kind": "oci_range_hashed", "start": 8388608,
            "end": 16777215, "guarded_source": obj["guarded_source"],
            "sha256_state": {"version": 1, "words": [1] * 8, "total_bytes": 16777216, "tail_hex": ""},
            "source": {"key": expected["placementPrefix"] + "/" + expected["objectKey"],
                "size": expected["objectBytes"], "etag": obj["strong_etag"]}})
        files = {}
        def reference(name, value):
            raw = json.dumps(value).encode(); files[name] = raw
            return {"file": name, "sha256": hashlib.sha256(raw).hexdigest(), "byteSize": str(len(raw))}
        request, reply = reference("request", plan), reference("reply", result)
        transport = {"nativeRequestId": "selected", "requestSha256": request["sha256"],
            "replySha256": reply["sha256"], "transportCallIdSha256": hashlib.sha256(b"controlled-call").hexdigest()}
        execute = {"nativeRequestId": "selected", "transportCallId": "controlled-call", "fullReplyConsumed": True,
            "attempt": {"operation": "hash_oci_range", "outcome": "typed_result_checked",
                "offeredRequestSha256": request["sha256"], "exposedReplySha256": reply["sha256"]}}
        window = {"processObservations": {"native": process.copy()},
            "storageBoundary": {"nativeOriginalBodies": {"bodies": [{"requestId": "selected",
                "bodies": {"request": request, "response": reply}}]}},
            "nativeOutboundDecoded": {"complete": True, "observations": [{"requestId": "selected",
                "sourceDigest": "b" * 64, "codecSourceSha256": "c" * 64, "operation": "hash_oci_range",
                "requestSha256": request["sha256"], "replySha256": reply["sha256"]}]},
            "nativeAuthenticatedTransports": {"joined": [transport]},
            "nativeExecuteObservations": {"joined": [execute]}}
        return window, process, checkpoint, expected, files, plan, reference

    def check(self, args):
        return module.require_inventory_restart_exchange(*args[:4], "b" * 64, "c" * 64,
            lambda ref: args[4][ref["file"]])

    def test_new_epoch_exact_checked_hash_is_selected(self):
        self.assertEqual(self.check(self.fixture())["nativeRequestId"], "selected")

    def test_old_epoch_or_missing_authentication_cannot_prove_restart(self):
        for mutation in (lambda w: w["processObservations"]["native"].update(startTicks="old"),
                lambda w: w["nativeAuthenticatedTransports"].update(joined=[]),
                lambda w: w["nativeOutboundDecoded"].update(complete=False),
                lambda w: w["nativeExecuteObservations"]["joined"][0].update(fullReplyConsumed=False)):
            args = self.fixture(); mutation(args[0])
            with self.assertRaises(ValueError): self.check(args)

    def test_substituted_state_key_and_source_profile_refuse(self):
        for key, wrong in (("start", 0), ("path", "other"), ("guarded_source", None), ("strong_etag", "other")):
            args = self.fixture(); args[5]["operation"][key] = wrong
            request = args[6]("request", args[5]); window = args[0]
            window["storageBoundary"]["nativeOriginalBodies"]["bodies"][0]["bodies"]["request"] = request
            window["nativeOutboundDecoded"]["observations"][0]["requestSha256"] = request["sha256"]
            window["nativeAuthenticatedTransports"]["joined"][0]["requestSha256"] = request["sha256"]
            window["nativeExecuteObservations"]["joined"][0]["attempt"]["offeredRequestSha256"] = request["sha256"]
            with self.assertRaises(ValueError): self.check(args)

    def test_renewed_live_fence_can_retain_same_claim_token(self):
        row, expected, _ = example()
        partial = {"summary": module.require_partial_inventory(row, expected, 99), "privateSql": {"value": row}}
        renewed = copy.deepcopy(partial)
        renewed["privateSql"]["value"]["generation"]["collector_lease_expires_at"] += 10
        self.assertIs(module.require_inventory_restart_fence(renewed, partial), renewed)
        renewed["privateSql"]["value"]["generation"]["binding_id"] += 1
        with self.assertRaises(ValueError): module.require_inventory_restart_fence(renewed, partial)


if __name__ == "__main__":
    unittest.main()
