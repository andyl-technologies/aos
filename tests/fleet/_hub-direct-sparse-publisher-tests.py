"""Check sparse journal and original-preserving refusals with controlled inputs.

SQLite rows below are explicitly controlled records. They are never VM,
authenticated issuer, provider or runtime qualification evidence.
"""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch


path = Path(__file__).with_name("_hub-direct-sparse-publisher.py")
specification = importlib.util.spec_from_file_location("sparse_publisher", path)
sparse = importlib.util.module_from_spec(specification)
specification.loader.exec_module(sparse)


def record(value):
    return json.dumps({"version": 1, "value": value}, separators=(",", ":")).encode()


class SparseJournalFences(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        self.addCleanup(self.connection.close)
        self.connection.executescript("""
            CREATE TABLE direct_identity(id INTEGER PRIMARY KEY, namespace TEXT, run_id TEXT, schema_version INTEGER);
            CREATE TABLE direct_records(kind TEXT, owner TEXT, placement TEXT, part INTEGER, body BLOB,
                PRIMARY KEY(kind, owner, placement, part));
        """)
        self.connection.execute("INSERT INTO direct_identity VALUES(1,?,?,1)", ("a" * 64, "b" * 64))
        self.source = {"path": "web/direct-content/qualification-0.bin", "byte_size": 64, "sha256": "c" * 64}
        self.session = {"sessionId": "d" * 64, "logicalFingerprint": "e" * 64}
        self.placement = {"placementId": "31", "placementFingerprint": "f" * 64}
        self.intent = {"version": 1, "clientOperationId": "1" * 64,
            "target": {"kind": "publication_object", "path": self.source["path"],
                "publicationId": "2" * 32, "surfaceObjectId": "77"},
            "byteSize": "64", "partSize": "16", "expectedSha256": self.source["sha256"]}
        self.store("intent", self.intent["clientOperationId"], self.intent)
        self.store("session", "session-" + self.session["sessionId"],
            {"session": self.session, "intent": self.intent, "placements": [self.placement]})
        self.add_part(2)

    def store(self, kind, owner, value, placement="0", part=0):
        self.connection.execute("INSERT OR REPLACE INTO direct_records VALUES(?,?,?,?,?)",
            (kind, owner, placement, part, record(value)))

    def add_part(self, number, observed=False):
        manifest = {"part": {"partNumber": number, "offset": str((number - 1) * 16),
            "byteSize": "16", "sha256": "3" * 64, "checksum": {"algorithm": "md5", "value": "controlled"}},
            "etag": '"controlled-part"'}
        if observed:
            self.store("observed", self.session["sessionId"], manifest, "31", number)
        else:
            self.store("grant", self.session["sessionId"], 1, "31", number)
            self.store("receipt", self.session["sessionId"], {"session": self.session,
                "placement": self.placement, "grant_id": "4" * 64, "grant_revision": "1",
                "observed": manifest}, "31", number)

    def snapshot(self):
        return sparse._read_checkpoint(self.connection, [self.source])

    def test_actual_sql_sparse_gap_keeps_unacknowledged_grant(self):
        self.store("grant", self.session["sessionId"], 1, "31", 1)
        selected = self.snapshot()["sessions"][0]
        self.assertEqual(selected["sparseGaps"], [{"placementId": "31",
            "lowerMissingPart": 1, "higherPositivePart": 2}])
        self.assertEqual(selected["unacknowledgedGrantKeys"], ["31:1"])
        self.assertIsNone(selected["completeSha256"])
        self.add_part(1, observed=True)
        self.assertEqual(self.snapshot()["sessions"][0]["sparseGaps"], [])

    def test_changed_source_geometry_and_missing_original_refuse(self):
        for field, value in (("byte_size", 65), ("sha256", "5" * 64)):
            changed = {**self.source, field: value}
            with self.assertRaises(ValueError, msg=field):
                sparse._read_checkpoint(self.connection, [changed])
        self.connection.execute("DELETE FROM direct_records WHERE kind='intent'")
        with self.assertRaises(ValueError):
            self.snapshot()

    def test_wrong_part_placement_and_missing_grant_refuse(self):
        self.connection.execute("UPDATE direct_records SET part=5 WHERE kind='receipt'")
        with self.assertRaises(ValueError):
            self.snapshot()
        self.connection.execute("UPDATE direct_records SET part=2 WHERE kind='receipt'")
        self.connection.execute("DELETE FROM direct_records WHERE kind='grant'")
        with self.assertRaises(ValueError):
            self.snapshot()

    def test_selected_row_total_is_bounded(self):
        original = sparse.MAX_SELECTED_ROWS
        try:
            sparse.MAX_SELECTED_ROWS = 1
            with self.assertRaises(ValueError):
                self.snapshot()
        finally:
            sparse.MAX_SELECTED_ROWS = original

    def test_publication_metadata_never_exports_retained_lease(self):
        self.store("publication_header", "publication", {"generation": "6" * 64, "manifestDigest": "7" * 64})
        self.store("publication_admission", "publication", {"publicationId": "2" * 32,
            "manifestDigest": "7" * 64, "objectCount": 1, "admittedObjectCount": 1,
            "nextChunkIndex": 1, "state": "staging", "leaseToken": "controlled-private-value"})
        projected = self.snapshot()
        self.assertNotIn("controlled-private-value", json.dumps(projected))
        self.assertEqual(projected["publication"]["admission"]["publicationId"], "2" * 32)


class ContinuityFences(unittest.TestCase):
    def test_actual_child_environment_is_retained_without_echo_or_override(self):
        directory = Path('/proc/self')
        arguments = [value.decode() for value in (directory / 'cmdline').read_bytes().split(b'\x00')[:-1]]
        publisher = sparse._pin(os.getpid(), arguments, os.readlink(directory / 'exe'), os.getuid())
        original = (directory / 'environ').read_bytes()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = sparse._retain_environment(root, publisher, arguments)
            retained = root / 'sparse-child.environment'
            self.assertEqual(retained.read_bytes(), original)
            self.assertEqual(retained.stat().st_mode & 0o777, 0o600)
            self.assertEqual(receipt['sha256'], hashlib.sha256(original).hexdigest())
            self.assertEqual(set(receipt), {'version', 'publisher', 'bytes', 'sha256'})

            # This controlled host directory does not certify trusted VM ancestors.
            # Bypass only that custody walk to exercise actual file/digest correlation.
            with patch.object(sparse, '_private_path', side_effect=lambda path: Path(path).lstat()):
                environment, loaded = sparse._original_environment(root, arguments, os.getuid())
                self.assertEqual(environment, sparse._decode_environment(original))
                self.assertEqual(loaded, receipt)
                with self.assertRaises(ValueError):
                    sparse._original_environment(root, arguments + ['changed'], os.getuid())
                retained.write_bytes(original + b'CHANGED=1\x00')
                with self.assertRaises(ValueError):
                    sparse._original_environment(root, arguments, os.getuid())

    def test_environment_parser_refuses_duplicates_truncation_and_total_bound(self):
        self.assertEqual(sparse._decode_environment(b'ORIGINAL=value=with=equals\x00'),
            {b'ORIGINAL': b'value=with=equals'})
        for body in (b'', b'NO_SEPARATOR\x00', b'=missing-name\x00', b'A=1\x00A=2\x00',
                b'TRUNCATED=1', b'A=' + b'x' * sparse.MAX_ENVIRONMENT_BYTES + b'\x00'):
            with self.assertRaises(ValueError):
                sparse._decode_environment(body)

    def test_actual_readonly_process_pin_checks_live_start_ticks(self):
        directory = Path("/proc/self")
        arguments = [value.decode() for value in (directory / "cmdline").read_bytes().split(b"\x00")[:-1]]
        executable = os.readlink(directory / "exe")
        current = sparse._pin(os.getpid(), arguments, executable, os.getuid())
        with self.assertRaises(ValueError):
            sparse._pin(os.getpid(), arguments, executable, os.getuid(), str(int(current["startTicks"]) + 1))

    def test_process_lifetime_pin_refuses_each_changed_coordinate(self):
        actual = {"pid": 17, "startTicks": "19", "uid": 0,
            "executable": "/controlled/aos", "argvSha256": "a" * 64}
        sparse._same_pin(actual, actual.copy())
        for name in actual:
            changed = {**actual, name: "different"}
            with self.assertRaises(ValueError, msg=name):
                sparse._same_pin(actual, changed)

    def test_resume_needs_original_positive_receipt_and_real_publication(self):
        session = {"path": "web/original.bin", "session": {"sessionId": "a" * 64},
            "originalSha256": "b" * 64, "publicationId": "c" * 32,
            "expectedSha256": "7" * 64, "byteSize": 64,
            "completeSha256": None, "sparseGaps": [{"lowerMissingPart": 1, "higherPositivePart": 2}],
            "receipts": {"31:2": "d" * 64}, "unacknowledgedGrantKeys": ["31:1"]}
        checkpoint = {"namespace": "e" * 64, "runId": "f" * 64, "sessions": [session]}
        admission = {"publication": {"headerSha256": "1" * 64,
            "admission": {"publicationId": "c" * 32}}}
        interrupted = {"checkpoint": checkpoint, "admission": admission}
        completed = copy.deepcopy(checkpoint)
        completed["sessions"][0]["completeSha256"] = "2" * 64
        completed["admission"] = admission
        publication = {"publication_id": "c" * 32, "state": "ready",
            "objects": [{"path": "web/original.bin", "verified": True, "sha256": "7" * 64, "byte_size": "64"}]}
        result = sparse.assert_direct_sparse_resume(interrupted, completed, publication)
        self.assertEqual(result["preservedPositiveParts"], 1)
        for change in ("namespace", "receipt", "original", "header", "incomplete", "publication", "source"):
            altered, visible = copy.deepcopy(completed), copy.deepcopy(publication)
            if change == "namespace":
                altered["namespace"] = "3" * 64
            elif change == "receipt":
                altered["sessions"][0]["receipts"]["31:2"] = "4" * 64
            elif change == "original":
                altered["sessions"][0]["originalSha256"] = "5" * 64
            elif change == "header":
                altered["admission"]["publication"]["headerSha256"] = "6" * 64
            elif change == "incomplete":
                altered["sessions"][0]["completeSha256"] = None
            elif change == "source":
                visible["objects"][0]["sha256"] = "8" * 64
            else:
                visible["state"] = "staging"
            with self.assertRaises(ValueError, msg=change):
                sparse.assert_direct_sparse_resume(interrupted, altered, visible)

    def test_source_refusal_cannot_hide_mutation_timeout_or_changed_custody(self):
        source = {"byte_size": 64, "sha256": "a" * 64}
        outcome = {"exitCode": 1, "timedOut": False, "journalsUnchanged": True,
            "restoredSha256": source["sha256"], "originalBytes": 64, "changedBytes": 63}
        counter = {name: 0 for name in sparse.CLIENT_EFFECT_COUNTERS}
        sparse.assert_direct_changed_source_refusal(outcome, {"error": "controlled refusal"}, [counter], source)
        for name, value in (("exitCode", 0), ("timedOut", True), ("journalsUnchanged", False),
                            ("restoredSha256", "b" * 64)):
            with self.assertRaises(ValueError, msg=name):
                sparse.assert_direct_changed_source_refusal({**outcome, name: value}, {"error": "refused"}, [counter], source)
        for name in counter:
            with self.assertRaises(ValueError, msg=name):
                sparse.assert_direct_changed_source_refusal(outcome, {"error": "refused"}, [{**counter, name: 1}], source)

    def test_guest_libraries_compile_without_inspect_or_loader_source(self):
        namespace = {"__name__": "controlled_generated_fleet"}
        exec(compile(path.read_text(), "<generated-fleet>", "exec"), namespace)
        compile(namespace["_guest_definitions"](), "<guest-library>", "exec")
        self.assertIn("def _read_checkpoint", namespace["_guest_definitions"]())
        guest = {}
        exec(namespace["_guest_definitions"](), guest)
        summary = "Direct upload client: " + " ".join(name + "=0" for name in guest["CLIENT_COUNTERS"])
        guest["_client_writes_zero"](summary)
        with self.assertRaises(ValueError):
            guest["_client_writes_zero"](summary.replace("abort=0", "abort=1"))
        with self.assertRaises(ValueError):
            guest["_client_writes_zero"](summary.replace("status=0", "caps=0"))

    def test_each_actual_guest_program_compiles_before_any_execution(self):
        class CapturedProgram(Exception):
            pass

        def capture(_client, _python, program, _selected, **_options):
            compile(program, "<controlled-guest-program>", "exec")
            raise CapturedProgram()

        sparse.direct_guest_python = capture
        self.addCleanup(lambda: delattr(sparse, "direct_guest_python"))
        process = {"label": "a", "attempt": 1}
        tools, signed = {"python": "controlled-python"}, {}
        corpus = {"large_objects": []}
        calls = (
            lambda: sparse.observe_direct_sparse_publisher(None, tools, process, signed, corpus),
            lambda: sparse.interrupt_direct_sparse_publisher(None, tools, process, signed, corpus,
                {"sparse": True, "state": "live"}),
            lambda: sparse.observe_direct_sparse_completion(None, tools, signed, corpus),
            lambda: sparse.probe_direct_changed_source(None, tools, process, signed, {}, "controlled-token"),
        )
        for call in calls:
            with self.assertRaises(CapturedProgram):
                call()


if __name__ == "__main__":
    unittest.main()
