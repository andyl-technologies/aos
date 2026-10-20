"""Exercise controller joins with controlled SQL and private runner transports."""

import importlib.util
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import textwrap
import unittest
import urllib.parse
from unittest.mock import patch


def module(filename, name):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(value)
    return value


sql = module("_hub-managed-gc-sql.py", "managed_window_sql_test")
window = module("_hub-managed-gc-window.py", "managed_window_test")
collector = module("_hub-managed-gc-observer.py", "managed_window_collector_test")


def controlled_transport(run_id, prefix):
    """Build controlled join inputs, not authenticated fleet or codec evidence."""
    source, native = "c" * 64, "d" * 64
    prepared = {"captureSelection": {"run": run_id, "sourceDigest": source},
                "coordinates": {"runId": run_id, "gcPrefix": prefix}}
    provenance = {"workerSourceDigest": source, "nativeExecutableSha256": native,
                  "runtimeCodecRevision": "e" * 40, "codecSourceSha256": "f" * 64}
    selection = {"observerExecutable": {"sha256": "1" * 64},
                 "runtimeProvenance": {"sha256": "2" * 64}}
    boundaries = {"codecSelection": selection, "codecProvenance": provenance}
    plan = {"plan_id": "3" * 32, "deployment_id": "actual-managed-deployment",
            "binding_kind": "deployment_r2", "placement_prefix": prefix,
            "operation": {"kind": "hash_oci_range", "path": "oci/blobs/sha256/exact"}}
    body = {"file": "controlled-plan.private.json", "sha256": "4" * 64, "byteSize": 512}
    reply = {"file": "controlled-reply.private.json", "sha256": "5" * 64, "byteSize": 128}
    capture = {"requestId": "6" * 32, "procedure": "/_internal/storage/v1/execute",
               "bodies": {"request": body, "response": reply},
               "storageWorkSelection": {"sourceDigest": source, "originalPlan": body}}
    completion = {"requestId": capture["requestId"], "nativeRequestId": "7" * 32,
                  "planIdSha256": hashlib.sha256(plan["plan_id"].encode()).hexdigest(),
                  "wireOperation": "hash_oci_range", "operation": "hash_oci_range",
                  "requestSha256": body["sha256"], "replySha256": reply["sha256"],
                  "requestBytes": 512, "replyBytes": 128}
    receipt = {"exitCode": 0, "sourceDigest": source, "codecRevision": "e" * 40,
               "codecSourceSha256": "f" * 64, "executableSha256": "1" * 64,
               "provenanceSha256": "2" * 64, "requestSha256": body["sha256"],
               "replySha256": reply["sha256"], "requestBytes": "512", "replyBytes": "128"}
    decoded = {"version": 1, "nativeBulkBytes": None, "plan": plan, "result": {},
               "handlerCompletion": completion, "validationReceipt": receipt}
    boundary = {"captures": [capture], "authenticatedCompletions": [completion],
                "captureProvenance": {"sourceDigest": source, "nativeExecutableSha256": native,
                                      "run": run_id, "deploymentId": plan["deployment_id"]},
                "actualNativeRequests": 1, "capturedWorkerRequests": 1,
                "unresolvedNativeRequestIds": [], "receivedWithoutOriginal": []}
    report = {"version": 1, "nativeBulkBytes": None, "storageBoundary": boundary,
              "workerLogText": ""}
    return prepared, boundaries, report, decoded


class ManagedGcControllerTests(unittest.TestCase):
    def setUp(self):
        self.run_id = "a" * 32
        self.prefix = "qualification/oci-terminal-cleanup/" + self.run_id
        self.coordinates = {"runId": self.run_id, "gcPrefix": self.prefix}
        self.setup = {"registry": {"stableId": "registry:" + "1" * 32,
                                  "slug": "managed-" + self.run_id + "/containers"},
                      "binding": {"stableId": "binding:" + "2" * 32},
                      "placement": {"name": "managed-gc", "prefix": self.prefix}}

    def test_actual_sql_selection_preserves_colon_ids_and_refuses_another_surface(self):
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.executescript("""
            CREATE TABLE registries(id INTEGER, stable_id TEXT, slug TEXT, resource_version INTEGER);
            CREATE TABLE surface_placements(id INTEGER, registry_id INTEGER, binding_id INTEGER,
                name TEXT, prefix TEXT, kind TEXT, desired_state TEXT,
                resource_version INTEGER, write_spec_version INTEGER);
            CREATE TABLE surface_placement_observations(placement_id INTEGER, state TEXT,
                completeness TEXT, observation_version INTEGER);
            CREATE TABLE bindings(id INTEGER, stable_id TEXT, kind TEXT, resource_version INTEGER);
            CREATE TABLE binding_write_state(binding_id INTEGER, current_write_revision INTEGER);
            CREATE TABLE oci_registry_state(registry_id INTEGER, mutation_epoch INTEGER);
        """)
        connection.execute("INSERT INTO registries VALUES (1,?,?,7)",
                           (self.setup["registry"]["stableId"], self.setup["registry"]["slug"]))
        connection.execute("INSERT INTO surface_placements VALUES (11,1,21,'managed-gc',?,"
                           "'complete','active',8,9)", (self.prefix,))
        connection.execute("INSERT INTO surface_placement_observations VALUES (11,'ready','complete',10)")
        connection.execute("INSERT INTO bindings VALUES (21,?,'deployment_r2',12)",
                           (self.setup["binding"]["stableId"],))
        connection.execute("INSERT INTO binding_write_state VALUES (21,13)")
        connection.execute("INSERT INTO oci_registry_state VALUES (1,14)")
        query = sql.current_pins_sql(self.setup, self.coordinates)

        rows = [dict(row) for row in connection.execute(query)]
        pins = sql.exact_current_projection({"pins": rows}, None)

        self.assertEqual((pins["registry_id"], pins["placement_id"], pins["binding_id"]), (1, 11, 21))
        self.assertEqual(pins["captured_mutation_epoch"], 14)
        connection.execute("UPDATE surface_placements SET registry_id=2")
        with self.assertRaises(ValueError):
            sql.exact_current_projection({"pins": [dict(row) for row in connection.execute(query)]}, None)
        connection.close()

    def test_current_projection_rejects_ambiguous_target_and_absent_capability(self):
        with self.assertRaises(ValueError):
            sql.exact_current_projection({"pins": [{}, {}]}, None)
        with self.assertRaises(ValueError):
            sql.transaction("SELECT 1; DELETE FROM bindings", "fleet_managed_" + self.run_id)
        with self.assertRaises(ValueError):
            sql.current_pins_sql({**self.setup, "placement": {
                "name": "managed-gc", "prefix": "another/prefix"}}, self.coordinates)
        old_prefix = "managed-gc/" + self.run_id
        with self.assertRaises(ValueError):
            sql.current_pins_sql({**self.setup, "placement": {
                "name": "managed-gc", "prefix": old_prefix}},
                {**self.coordinates, "gcPrefix": old_prefix})
        pins = {"registry_id": 1, "placement_id": 2, "registry_resource_version": 3,
                "placement_resource_version": 4, "placement_write_spec_version": 5,
                "placement_observation_version": 6, "binding_id": 7,
                "binding_resource_version": 8, "binding_write_revision": 9,
                "captured_mutation_epoch": 0, "registry_stable_id": "registry:actual",
                "binding_stable_id": "binding:actual", "placement_prefix": self.prefix}
        capability = {"kind": "deployment_r2", "state": "valid", "binding_id": 7,
                      "binding_resource_version": 8, "binding_write_revision": 9,
                      "current_write_revision": 9, "capability_fingerprint": "actual-probe",
                      "resource_version": 1, "delete_credential_purpose": None,
                      "delete_credential_generation": None}
        self.assertEqual(sql.exact_managed_capability({"pins": [pins],
            "capability": [capability]}, None, pins), pins)
        for rows in ([], [{**capability, "binding_resource_version": 99}],
                     [{**capability, "delete_credential_purpose": "put"}],
                     [{**capability, "state": "unknown"}]):
            with self.assertRaises(ValueError):
                sql.exact_managed_capability({"pins": [pins], "capability": rows}, None, pins)

    def test_exact_begin_label_and_current_codec_receipt_survive_window_completion(self):
        prepared, boundaries, report, decoded = controlled_transport(self.run_id, self.prefix)
        tools = {"deploymentId": decoded["plan"]["deployment_id"]}
        token = {"label": "managed-gc-begin-1"}
        calls = []

        def finish(*arguments):
            self.assertIs(arguments[-2], token)
            self.assertEqual(arguments[-1], token["label"])
            return report

        def classify(capture, boundary, label, selection, provenance):
            calls.append((capture, boundary, label, selection, provenance))
            return decoded

        with patch.object(window, "finish_managed_storage_window", finish, create=True), \
                patch.object(window, "classify_managed_storage_capture", classify, create=True):
            observer = window.ManagedGcWindowObserver(None, None, tools, prepared, {}, boundaries, collector)
            completed = observer.finish_transport(token)

        self.assertEqual(calls[0][3:], (boundaries["codecSelection"], boundaries["codecProvenance"]))
        self.assertIs(observer.exchanges[0]["validationReceipt"], decoded["validationReceipt"])
        self.assertEqual(completed["requests"][0]["planId"], decoded["plan"]["plan_id"])
        self.assertNotIn("nativeBulkBytes", completed)

    def test_unknown_duplicate_and_foreign_windows_refuse_before_codec(self):
        prepared, boundaries, report, decoded = controlled_transport(self.run_id, self.prefix)
        tools = {"deploymentId": decoded["plan"]["deployment_id"]}
        mutations = (
            lambda value: value["storageBoundary"].update(unresolvedNativeRequestIds=["7" * 32]),
            lambda value: value["storageBoundary"].update(receivedWithoutOriginal=["8" * 32]),
            lambda value: value["storageBoundary"]["captureProvenance"].update(sourceDigest="9" * 64),
            lambda value: value["storageBoundary"]["authenticatedCompletions"][0].update(replyBytes=129),
            lambda value: value["storageBoundary"].update(captures=[
                value["storageBoundary"]["captures"][0]] * 2),
        )
        for mutate in mutations:
            current = copy.deepcopy(report)
            mutate(current)
            with patch.object(window, "classify_managed_storage_capture", create=True) as classify:
                with self.assertRaises(ValueError):
                    window.validated_managed_storage_exchanges(current, prepared, tools,
                                                               boundaries, "controlled")
                classify.assert_not_called()

    def test_missing_current_tuple_refuses_before_loading_producers(self):
        with patch.object(window, "managed_fixture_module", create=True) as load:
            with self.assertRaises(ValueError):
                window.run_managed_gc_window(None, None, None, None, {}, {}, {}, {},
                                             None, {}, {}, {}, {}, None)
            load.assert_not_called()

    def test_foreign_native_or_source_tuple_refuses_before_loading_producers(self):
        prepared, boundaries, report, decoded = controlled_transport(self.run_id, self.prefix)
        prepared["coordinates"]["deploymentId"] = decoded["plan"]["deployment_id"]
        boundaries["run"] = self.run_id
        boundaries["codecProvenance"].update(version=1, sourceArchiveSha256="8" * 64)
        boundaries["codecSelection"].update(runtimeCodecRevision="e" * 40)
        boundaries["codecSelection"]["observerExecutable"]["path"] = "/controlled/codec"
        boundaries["codecSelection"]["runtimeProvenance"]["path"] = "/controlled/provenance"
        processes = {"native": {"executableSha256": "d" * 64}, "worker": {},
                     "nativeProxy": {}, "workerProxy": {}}
        tools = {"deploymentId": decoded["plan"]["deployment_id"]}
        window.require_managed_gc_current_tuple(prepared, processes, tools, boundaries)
        for changed in ("nativeExecutableSha256", "workerSourceDigest"):
            current = copy.deepcopy(boundaries)
            current["codecProvenance"][changed] = "9" * 64
            with patch.object(window, "managed_fixture_module", create=True) as load:
                with self.assertRaises(ValueError):
                    window.run_managed_gc_window(None, None, None, None, tools, prepared, processes,
                        current, None, {}, {}, {}, {}, None)
                load.assert_not_called()

    def test_wrong_codec_or_placement_refuses_and_nonexecute_control_stays_separate(self):
        prepared, boundaries, report, decoded = controlled_transport(self.run_id, self.prefix)
        tools = {"deploymentId": decoded["plan"]["deployment_id"]}
        for field, changed in (("executableSha256", "9" * 64), ("exitCode", 1)):
            current = copy.deepcopy(decoded)
            current["validationReceipt"][field] = changed
            with patch.object(window, "classify_managed_storage_capture", return_value=current, create=True):
                with self.assertRaises(ValueError):
                    window.validated_managed_storage_exchanges(report, prepared, tools,
                                                               boundaries, "controlled")
        current = copy.deepcopy(decoded)
        current["plan"]["placement_prefix"] = "another/prefix"
        with patch.object(window, "classify_managed_storage_capture", return_value=current, create=True):
            with self.assertRaises(ValueError):
                window.validated_managed_storage_exchanges(report, prepared, tools, boundaries, "controlled")

        control = copy.deepcopy(report)
        capture = control["storageBoundary"]["captures"][0]
        original = capture.pop("storageWorkSelection")["originalPlan"]
        capture["procedure"] = "/_internal/storage/v1/oci/authorize-final"
        capture["controlSelection"] = {"sourceDigest": "c" * 64,
            "deploymentId": tools["deploymentId"], "originalRequest": original}
        control["storageBoundary"]["authenticatedCompletions"][0].update(
            compiledSource="c" * 64, route=capture["procedure"])
        with patch.object(window, "classify_managed_storage_capture", create=True) as classify:
            self.assertEqual(window.validated_managed_storage_exchanges(control, prepared, tools,
                                                                       boundaries, "controlled"), [])
            classify.assert_not_called()

    def test_expected_selectors_use_real_plan_and_claim_ids_without_key_normalization(self):
        exchanges = [{"plan": {"plan_id": "1" * 32, "binding_kind": "deployment_r2",
            "placement_prefix": self.prefix, "operation": {
                "kind": "hash_oci_range", "path": "oci/blobs/sha256/exact"}}},
            {"plan": {"plan_id": "2" * 32, "binding_kind": "deployment_r2",
                "placement_prefix": self.prefix, "operation": {
                    "kind": "delete_if_matches", "path": "oci/blobs/sha256/exact",
                    "claim_id": "actual-sql-action"}}}]

        selected = window.managed_gc_expected_requests(exchanges)

        self.assertIn({"scope": "managed_gc_guard", "key": self.prefix + "/oci/blobs/sha256/exact",
                       "subject_id": "actual-sql-action"}, selected)
        self.assertIn({"scope": "managed_inventory_range", "key": self.prefix + "/oci/blobs/sha256/exact",
                       "subject_id": "1" * 32}, selected)
        exchanges[0]["plan"]["binding_kind"] = "external_s3"
        with self.assertRaises(ValueError):
            window.managed_gc_expected_requests(exchanges)

    def test_missing_terminal_or_empty_console_never_establishes_zero_replay(self):
        selector = {"scope": "managed_gc_guard", "key": self.prefix + "/object",
                    "subject_id": "actual-sql-action"}
        entry = {"version": 1, "capture_id": self.run_id, "request_id": "b" * 32,
                 **selector, "event": {"kind": "request_entry"}}
        records = window.managed_gc_sdk_records("actual console prefix managed_gc_sdk_observer "
                                                + json.dumps(entry))
        with self.assertRaises(ValueError):
            collector.collect(records, self.run_id, "c" * 64, [selector])
        with self.assertRaises(ValueError):
            collector.collect(window.managed_gc_sdk_records("ordinary log only"),
                              self.run_id, "c" * 64, [selector])

    def test_private_snapshot_and_replay_use_the_actual_claim_and_retained_digest(self):
        import hashlib

        requests = []
        retained = []
        receipt = {"claim": {"claim_id": "actual-sql-action", "expected_hash": "sha256:" + "c" * 64},
                   "outcome": {"kind": "deleted", "etag": '"actual"'}}

        def read_command(worker, tools, prepared, processes, request, label):
            requests.append((request, label))
            return {"value": {"backingIdentity": "d" * 64}, "receipt": {"path": "controlled"}}

        window.read_managed_runner_command = read_command
        window.retain_direct_flow = lambda label, value: retained.append((label, value))
        observer = window.ManagedGcWindowObserver(None, None, {},
            {"coordinates": {"runId": self.run_id}}, {}, {}, collector)

        observer.snapshot([self.prefix + "/object"], ["actual-sql-action"])
        observer.replay_positive_guard(self.prefix + "/object", receipt)

        self.assertEqual(requests[0][0]["kind"], "managed-gc-snapshot")
        self.assertEqual(requests[1][0]["kind"], "managed-gc-positive-replay")
        self.assertEqual(requests[1][0]["claimId"], "actual-sql-action")
        self.assertEqual(requests[1][0]["receiptSha256"], hashlib.sha256(
            json.dumps(receipt, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest())
        self.assertEqual(len(retained), 2)
        with self.assertRaises(ValueError):
            observer.replay_positive_guard(self.prefix + "/object", {
                **receipt, "outcome": {"kind": "already_absent"}})
        self.assertEqual(len(requests), 2)


@unittest.skipUnless(os.environ.get("AOS_MANAGED_GC_TEST_PG_BIN"), "explicit source-built PostgreSQL is required")
class ManagedGcPostgresProjectionTests(unittest.TestCase):
    """Execute new query geometry on a private local cluster, never a fleet DB."""

    @classmethod
    def setUpClass(cls):
        cls.bin = Path(os.environ["AOS_MANAGED_GC_TEST_PG_BIN"])
        if not str(cls.bin).startswith("/nix/store/"):
            raise ValueError("PostgreSQL gate requires the declared source-built package")
        cls.private = tempfile.TemporaryDirectory(prefix="aos-managed-gc-projection-")
        cls.root = Path(cls.private.name)
        cls.socket = cls.root / "socket"
        cls.socket.mkdir(mode=0o700)
        cls.data = cls.root / "data"
        cls.database = "fleet_managed_" + "a" * 32
        cls.command("initdb", "-D", str(cls.data), "-U", "managed_gc_projection",
                    "-A", "trust", "--no-locale", "-E", "UTF8")
        cls.command("pg_ctl", "-D", str(cls.data), "-l", str(cls.root / "postgres.log"),
                    "-o", "-k " + str(cls.socket) + " -c listen_addresses=''", "-w", "start")
        try:
            cls.query("CREATE DATABASE " + cls.database, "postgres")
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def command(cls, binary, *arguments):
        result = subprocess.run([str(cls.bin / binary), *arguments], capture_output=True,
                                timeout=30, check=False)
        if result.returncode:
            raise RuntimeError("controlled PostgreSQL command refused: " + result.stderr.decode())
        return result.stdout

    @classmethod
    def query(cls, statement, database=None):
        return cls.command("psql", "-X", "-qAt", "-U", "managed_gc_projection", "-v", "ON_ERROR_STOP=1",
                           "-h", str(cls.socket), "-d", database or cls.database, "-c", statement)

    @classmethod
    def tearDownClass(cls):
        cls.command("pg_ctl", "-D", str(cls.data), "-w", "stop")
        cls.private.cleanup()

    def test_actual_private_sql_capture_binds_query_database_and_create_only_custody(self):
        native_root = self.root / "native-observations"
        materials = native_root / "materials"
        materials.mkdir(mode=0o700, parents=True)
        database = materials / "database.url"
        database.write_text("postgresql://managed_gc_projection@/" + self.database
                            + "?host=" + urllib.parse.quote(str(self.socket), safe="") + "\n")
        database.chmod(0o600)
        prepared = {"coordinates": {"nativeRoot": str(native_root), "database": self.database},
                    "nativeFiles": {"database": str(database)}}
        tools = {"postgres": str(self.bin), "python": str(Path("/proc/self/exe").resolve())}
        retained = []

        def local_guest(machine, python, source, selection, timeout=35):
            script = "import json\nselected=json.loads(" + repr(json.dumps(selection)) + ")\n"
            result = subprocess.run([python, "-c", script + textwrap.dedent(source)],
                                    capture_output=True, timeout=timeout, check=False)
            if result.returncode:
                errors = Path(selection["root"]) / "stderr.private"
                detail = errors.read_text() if errors.is_file() else result.stderr.decode()
                raise ValueError("controlled actual SQL capture refused: " + detail)
            return result.stdout.decode()

        query = sql.transaction("SELECT json_build_object('actual', current_database())", self.database)
        with patch.object(window, "direct_guest_python", local_guest, create=True), \
                patch.object(window, "retain_direct_flow", lambda label, value: retained.append(value),
                             create=True):
            result = window.capture_managed_gc_sql(None, tools, prepared, query, "controlled-read")
            self.assertEqual(result, {"actual": self.database})
            receipt = retained[0]["receipt"]
            body = Path(receipt["path"]).read_bytes()
            self.assertEqual(receipt["sha256"], hashlib.sha256(body).hexdigest())
            self.assertEqual(receipt["byteSize"], len(body))
            self.assertEqual(receipt["querySha256"], hashlib.sha256(query.encode()).hexdigest())
            self.assertEqual(Path(receipt["path"]).stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                window.capture_managed_gc_sql(None, tools, prepared, query, "controlled-read")
            self.assertEqual(Path(receipt["path"]).read_bytes(), body)
            foreign = {**prepared, "coordinates": {**prepared["coordinates"],
                                                  "database": "fleet_managed_" + "b" * 32}}
            # The wrapper reports current_database() from the actual connection;
            # changing an offered coordinate cannot relabel that live database.
            with self.assertRaises(ValueError):
                window.capture_managed_gc_sql(None, tools, foreign, query, "foreign-database")
            database.chmod(0o644)
            with self.assertRaises(ValueError):
                window.capture_managed_gc_sql(None, tools, prepared, query, "insecure-url")

    def test_actual_postgres_projection_casts_and_read_only_transaction(self):
        # These small controlled rows exercise the actual table/column names and
        # query shape; they are not fleet originals or provider qualification.
        self.query("""
            CREATE TABLE registries(id BIGINT, stable_id TEXT, slug TEXT, resource_version BIGINT);
            CREATE TABLE surface_placements(id BIGINT, registry_id BIGINT, binding_id BIGINT,
                name TEXT, prefix TEXT, kind TEXT, desired_state TEXT,
                resource_version BIGINT, write_spec_version BIGINT);
            CREATE TABLE surface_placement_observations(placement_id BIGINT, state TEXT,
                completeness TEXT, observation_version BIGINT);
            CREATE TABLE bindings(id BIGINT, stable_id TEXT, kind TEXT, resource_version BIGINT);
            CREATE TABLE binding_write_state(binding_id BIGINT, current_write_revision BIGINT);
            CREATE TABLE oci_registry_state(registry_id BIGINT, mutation_epoch BIGINT);
            INSERT INTO registries VALUES (1,'registry:actual','managed-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/containers',7);
            INSERT INTO surface_placements VALUES (11,1,21,'managed-gc','qualification/oci-terminal-cleanup/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                'complete','active',8,9);
            INSERT INTO surface_placement_observations VALUES (11,'ready','complete',10);
            INSERT INTO bindings VALUES (21,'binding:actual','deployment_r2',12);
            INSERT INTO binding_write_state VALUES (21,13);
            INSERT INTO oci_registry_state VALUES (1,14);
        """)
        run = "a" * 32
        setup = {"registry": {"stableId": "registry:actual", "slug": "managed-" + run + "/containers"},
                 "binding": {"stableId": "binding:actual"},
                 "placement": {"name": "managed-gc", "prefix": "qualification/oci-terminal-cleanup/" + run}}
        coordinates = {"runId": run, "gcPrefix": "qualification/oci-terminal-cleanup/" + run,
                       "database": self.database}

        observed = json.loads(self.query(sql.current_projection_sql(None, setup, coordinates)))
        action_shape = sql.transaction(sql.one_row_projection(
            "SELECT id, stable_id FROM registries LIMIT 2"), self.database)
        actions = json.loads(self.query(action_shape))

        self.assertEqual(observed["database"], self.database)
        pins = sql.exact_current_projection(observed["value"], None)
        self.assertEqual(pins["binding_write_revision"], 13)
        self.assertEqual(actions["value"], [{"id": 1, "stable_id": "registry:actual"}])
        denied = subprocess.run([str(self.bin / "psql"), "-X", "-qAt", "-U", "managed_gc_projection",
            "-v", "ON_ERROR_STOP=1",
            "-h", str(self.socket), "-d", self.database, "-c",
            "BEGIN TRANSACTION READ ONLY; DELETE FROM bindings; COMMIT;"],
            capture_output=True, timeout=20, check=False)
        self.assertNotEqual(denied.returncode, 0)
        self.assertEqual(self.query("SELECT count(*) FROM bindings").strip(), b"1")


if __name__ == "__main__":
    unittest.main()
