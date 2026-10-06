"""Local supervision fixtures for the hosted runner, without provider effects.

The subprocess peer is synthetic and source-built Python. Actual production
fleet parsers validate its numeric observations. Tiny source fixtures test the
adapter; they cannot qualify the mandatory hosted corpus or application ledger.
"""

import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


MODULE = Path(__file__).with_name("aos-hub-hosted-workload.py")
spec = importlib.util.spec_from_file_location("hosted_workload", MODULE)
hosted = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hosted)
LIBRARY = Path(__file__).parents[2] / "tests/fleet"
if not LIBRARY.is_dir():
    LIBRARY = Path(__file__).parents[2] / "libraries"


def sample(seconds=0.1):
    return {"curl_cumulative_raw": {"time_starttransfer": str(seconds)}}


class HostedTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.lib = hosted.libraries(LIBRARY)
        self.token = self.root / "session"
        self.token.write_text("fixture-application-token")
        self.token.chmod(0o600)

    def tearDown(self):
        self.temporary.cleanup()

    def selected(self, executable):
        return {"origin": "https://example.test", "pagePath": "/-/instance", "region": "fixture",
                "timeoutSeconds": 60, "tokenFile": str(self.token), "providerPolicyFile": "fixture-policy",
                "tools": {"aos": {"file": str(executable)}}, "captures": {"workerRuntime": None, "nativeBoundary": None},
                "workerSourceDigest": "1" * 64,
                "publishers": {label: {"registry": "fixture-" + label, "surfaceRoot": str(self.root / label),
                    "publisherHome": str(self.root / (label + "-home")), "journal": str(self.root / (label + ".sqlite"))}
                    for label in ("a", "b")}}

    def peer(self, body):
        path = self.root / "peer.py"
        path.write_text("#!" + sys.executable + "\n" + body)
        path.chmod(0o700)
        return path

    def test_private_evidence_is_create_only_and_rejects_symlink_output(self):
        evidence = hosted.Evidence(self.root / "evidence")
        try:
            evidence.save("one.json", {"state": "unknown"})
            with self.assertRaises(FileExistsError):
                evidence.save("one.json", {"state": "positive"})
            self.assertEqual((evidence.path / "one.json").stat().st_mode & 0o777, 0o600)
        finally:
            evidence.close()
        (self.root / "link").symlink_to(self.root / "evidence", target_is_directory=True)
        with self.assertRaises(OSError):
            hosted.Evidence(self.root / "link", fresh=False)

    def test_actual_fleet_latency_parser_and_targets(self):
        row = self.lib["parse_page_observations"](
            "0.100 200 0.020 0.040 0.010 0.050 0.110 1|||\n", 1)[0]
        measured = hosted.latency([row] * 100, [row] * 25)
        self.assertTrue(measured["passed"])
        self.assertFalse(hosted.latency([row] * 100, [sample(0.126)] * 25)["passed"])
        self.assertFalse(hosted.latency([row] * 100, [row] * 24)["passed"])

    def test_production_upload_arguments_preserve_exact_original_inputs(self):
        selected = self.selected("/nix/store/fixture/bin/aos")
        args = hosted.publisher_arguments(selected, selected["publishers"]["a"])
        self.assertEqual(args[:8], ["/nix/store/fixture/bin/aos", "--json", "hub", "registry",
                                   "publish", "upload", "fixture-a", "--root"])
        self.assertEqual(args[-2:], ["--direct-upload-journal", str(self.root / "a.sqlite")])
        self.assertEqual(args[args.index("--hub") + 1], selected["origin"])

    def test_actual_child_stop_pins_process_and_leaves_settlement_unknown(self):
        executable = self.peer("import time\ntime.sleep(30)\n")
        evidence = hosted.Evidence(self.root / "evidence")
        child = hosted.Publisher(self.selected(executable), self.selected(executable)["publishers"]["a"], evidence, "a")
        try:
            self.assertTrue(child.stop())
            self.assertEqual(child.process.returncode, -9)
            saved = json.loads((evidence.path / "a-process.json").read_text())
            self.assertEqual(saved["pid"], child.process.pid)
            self.assertNotIn("fixture-application-token", json.dumps(saved))
        finally:
            child.stop()
            evidence.close()

    def test_parallel_failed_publishers_dispatch_once_without_effect_retry(self):
        count = self.root / "calls"
        executable = self.peer(f"from pathlib import Path\nimport time\n"
                               f"with Path({str(count)!r}).open('a') as output: output.write('dispatch\\n')\n"
                               "time.sleep(0.12)\nraise SystemExit(17)\n")
        selected = self.selected(executable)
        evidence = hosted.Evidence(self.root / "evidence")
        reports = {label: {"large_objects": []} for label in ("a", "b")}
        try:
            with patch.object(hosted, "corpus", return_value=reports), patch.object(
                    hosted, "page_probe", side_effect=lambda *args: (time.sleep(0.01), sample())[1]), patch.object(
                    hosted, "checkpoint", return_value=None):
                with self.assertRaisesRegex(ValueError, "Publisher failed"):
                    hosted.run(selected, "1" * 64, evidence, self.lib)
            self.assertEqual(count.read_text().splitlines(), ["dispatch", "dispatch"])
            exits = json.loads((evidence.path / "publisher-exits.json").read_text())
            self.assertEqual(exits["a"]["exitCode"], 17)
            self.assertEqual(exits["b"]["exitCode"], 17)
            self.assertEqual(exits["a"]["providerDrain"], "unknown")
        finally:
            evidence.close()

    def test_successful_cli_keeps_missing_application_ledger_incomplete(self):
        counters = "Direct upload client: " + " ".join(
            name + "=0" for name in self.lib["DIRECT_CLIENT_COUNTERS"])
        reply = {"data": {"state": "ready", "objects": [], "publication_id": "1" * 32}}
        executable = self.peer("import json,sys,time\ntime.sleep(0.4)\n"
                               + f"print({json.dumps(reply)!r})\nprint({counters!r}, file=sys.stderr)\n")
        selected = self.selected(executable)
        evidence = hosted.Evidence(self.root / "evidence")
        reports = {label: {"large_objects": [], "metadata_objects": 0,
                    "metadata_catalogue_sha256": hosted.hashlib.sha256(b"").hexdigest()}
                   for label in ("a", "b")}
        try:
            with patch.object(hosted, "corpus", return_value=reports), patch.object(
                    hosted, "page_probe", side_effect=lambda *args: (time.sleep(0.01), sample())[1]), patch.object(
                    hosted, "checkpoint", return_value=None):
                outcome = hosted.run(selected, "1" * 64, evidence, self.lib)
            self.assertEqual(outcome["state"], "workload_complete")
            self.assertEqual(outcome["hostedAcceptance"], "incomplete")
            self.assertIsNone(outcome["nativeBulkBytes"])
            measured = json.loads((evidence.path / "measurements.json").read_text())
            self.assertEqual(set(measured["clientCounters"]), {"a", "b"})
            self.assertIn("Native application boundary original-window exporter", measured["missing"])
        finally:
            evidence.close()

    def test_capture_keeps_actual_inode_and_missing_stays_missing(self):
        path = self.root / "export.jsonl"
        path.write_bytes(b"before\n")
        path.chmod(0o600)
        before = hosted.capture_begin({"file": str(path)})
        path.rename(self.root / "old-export")
        path.write_bytes(b"substituted\n")
        with (self.root / "old-export").open("ab") as output:
            output.write(b"actual-original\n")
        evidence = hosted.Evidence(self.root / "evidence")
        try:
            self.assertEqual(hosted.capture_finish(before, evidence, "window"), "actual-original\n")
            self.assertIsNone(hosted.capture_finish(None, evidence, "missing"))
            self.assertFalse((evidence.path / "missing.jsonl").exists())
        finally:
            evidence.close()

    def test_closed_input_and_source_geometry_cannot_be_downgraded(self):
        with self.assertRaises(ValueError):
            hosted.closed_json('{"bytes": 1, "bytes": 0}')
        with self.assertRaises(ValueError):
            hosted.closed_json('{"bytes": NaN}')
        self.assertEqual(hosted.LARGE_BYTES, 2 * 1024 ** 3)
        self.assertEqual(hosted.METADATA_COUNT, 12_535)
        selected = self.selected("fixture")
        for label in ("a", "b"):
            root = Path(selected["publishers"][label]["surfaceRoot"])
            (root / "web/direct-content").mkdir(parents=True)
            (root / "HEAD").write_text("signed-fixture")
        (Path(selected["publishers"]["a"]["surfaceRoot"]) / "web/direct-content/qualification-0.bin").write_bytes(b"tiny")
        with self.assertRaisesRegex(ValueError, "2GiB"):
            hosted.corpus(selected)

    def test_actual_checkpoint_projection_rejects_foreign_owner(self):
        selected = self.selected("fixture")
        for suffix in ("", ".admission"):
            path = Path(selected["publishers"]["a"]["journal"] + suffix)
            connection = sqlite3.connect(path)
            connection.execute("CREATE TABLE direct_identity(id, namespace, run_id, schema_version)")
            connection.execute("INSERT INTO direct_identity VALUES(1, 'foreign', ?, 1)", ("1" * 64,))
            connection.commit()
            connection.close()
            path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "namespace"):
            hosted.checkpoint(selected["publishers"]["a"], [{"path": "original"}], self.lib)

    def test_admission_only_checkpoint_is_not_erased_before_object_begin(self):
        selected = self.selected("fixture")
        publication = selected["publishers"]["b"]
        path = Path(publication["journal"] + ".admission")
        connection = sqlite3.connect(path)
        connection.execute("CREATE TABLE direct_identity(id, namespace, run_id, schema_version)")
        connection.execute("INSERT INTO direct_identity VALUES(1, ?, ?, 1)", ("1" * 64, "2" * 64))
        connection.execute("CREATE TABLE direct_records(kind, owner, placement, part, body)")
        connection.commit()
        connection.close()
        path.chmod(0o600)
        actual = hosted.checkpoint(publication, [{"path": "original"}], self.lib)
        self.assertIsNone(actual["object"])
        self.assertEqual(actual["admission"]["runId"], "2" * 64)
        self.assertFalse(Path(publication["journal"]).exists())

    def test_actual_wrapper_exec_keeps_owned_lifetime_and_records_selected_elf(self):
        bash = Path("/nix/store/071yhimnxva604hfim2d7m51k593jpks-bash-5.3p15/bin/bash").resolve()
        python = Path(sys.executable).resolve()
        gate = self.root / "release"
        program = self.peer("import time\ntime.sleep(30)\n")
        wrapper = self.root / "wrapper"
        wrapper.write_text(f"#!{bash}\nwhile [[ ! -f '{gate}' ]]; do :; done\n"
                           f'exec "{python}" "{program}" "$@"\n')
        wrapper.chmod(0o700)
        selected = self.selected(wrapper)
        evidence = hosted.Evidence(self.root / "evidence")
        child = hosted.Publisher(selected, selected["publishers"]["a"], evidence, "a")
        try:
            before = child.observe()
            self.assertEqual(before["executable"], str(bash))
            gate.touch()
            limit = time.monotonic() + 5
            while time.monotonic() < limit:
                after = child.observe()
                if after["executable"] == str(python):
                    break
                time.sleep(0.005)
            self.assertEqual(after["executable"], str(python))
            self.assertEqual(hosted.process_owner(before), hosted.process_owner(after))
            self.assertNotEqual(before["argumentsSha256"], after["argumentsSha256"])
            receipt = json.loads((evidence.path / "a-exec-transition.json").read_text())
            self.assertEqual(receipt["selectedExecutable"]["file"], str(python))
            self.assertEqual(receipt["previousExecutable"]["file"], str(bash))
            self.assertTrue(child.stop())
            self.assertEqual(child.process.returncode, -9)
        finally:
            child.stop()
            evidence.close()

    def test_cleanup_visits_other_children_and_captures_after_an_actual_failure(self):
        executable = self.peer("import time\ntime.sleep(30)\n")
        selected = self.selected(executable)
        evidence = hosted.Evidence(self.root / "evidence")
        children = {label: hosted.Publisher(selected, selected["publishers"][label], evidence, label)
                    for label in ("a", "b")}
        paths = [self.root / "first-capture", self.root / "second-capture"]
        for path in paths:
            path.write_bytes(b"before\n")
            path.chmod(0o600)
        captures = {name: hosted.capture_begin({"file": str(path)})
                    for name, path in zip(("workerRuntime", "nativeBoundary"), paths)}
        paths[0].write_bytes(b"")
        with paths[1].open("ab") as output:
            output.write(b"retained-current-window\n")
        original_stop = children["a"].stop

        def failed_stop():
            original_stop()
            raise RuntimeError("private-error-canary")

        try:
            with patch.object(children["a"], "stop", side_effect=failed_stop):
                with self.assertRaisesRegex(ValueError, "cleanup or capture failed"):
                    hosted.cleanup(children, captures, evidence)
            self.assertTrue(all(child.process.poll() is not None for child in children.values()))
            for descriptor, _ in captures.values():
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            self.assertEqual((evidence.path / "native-boundary.jsonl").read_bytes(), b"retained-current-window\n")
            errors = (evidence.path / "cleanup-errors.json").read_text()
            self.assertNotIn("private-error-canary", errors)
            self.assertEqual({row["role"] for row in json.loads(errors)}, {"publisher", "capture"})
        finally:
            for child in children.values():
                child.stop()
            evidence.close()

    def test_store_tool_selection_refuses_traversal_and_hash_substitution(self):
        actual = hosted.immutable_executable(str(Path(sys.executable)))
        self.assertEqual(hosted.selected_tool({"file": sys.executable, "sha256": actual["sha256"]}), actual)
        with self.assertRaisesRegex(ValueError, "changed"):
            hosted.selected_tool({"file": sys.executable, "sha256": "0" * 64})
        for path in (sys.executable + "/../python3", "/nix/store/" + "a" * 32 + "-fixture/../../tmp/tool"):
            with self.assertRaisesRegex(ValueError, "canonical"):
                hosted.immutable_executable(path)
        with patch.object(Path, "resolve", return_value=self.root / "foreign-tool"):
            with self.assertRaisesRegex(ValueError, "outside"):
                hosted.immutable_executable(sys.executable)

    def test_same_boot_monotonic_cutoff_prevents_wall_rollback_extension(self):
        with patch.object(hosted.time, "time_ns", return_value=100_000_000_000), patch.object(
                hosted.time, "monotonic_ns", return_value=10_000_000_000):
            cutoff = hosted.original_cutoff(60)
        with patch.object(hosted.time, "time_ns", return_value=20_000_000_000), patch.object(
                hosted.time, "monotonic_ns", return_value=69_000_000_000):
            self.assertEqual(hosted.remaining_cutoff(cutoff), 1)
            self.assertEqual(hosted.original_cutoff(7200, cutoff), cutoff)
        with patch.object(hosted.time, "time_ns", return_value=20_000_000_000), patch.object(
                hosted.time, "monotonic_ns", return_value=70_000_000_000):
            with self.assertRaises(TimeoutError):
                hosted.remaining_cutoff(cutoff)
        changed_boot = {**cutoff, "controllerBootId": "00000000-0000-0000-0000-000000000000"}
        with self.assertRaisesRegex(ValueError, "another boot"):
            hosted.original_cutoff(60, changed_boot)

    def test_retained_first_window_binds_elapsed_logs_and_missing_capture(self):
        evidence = hosted.Evidence(self.root / "first-window")
        try:
            for label in ("a", "b"):
                for stream in ("stdout", "stderr"):
                    evidence.save(label + "-" + stream, b"private-log-canary")
            evidence.save("worker-runtime.jsonl", b"source-bound-private-capture\n")
            cutoff = hosted.original_cutoff(60)
            finished = time.monotonic_ns()
            reference = hosted.retain_window(evidence, cutoff, finished - 123, finished,
                       [sample()] * 100, [sample()] * 3, [], {},
                       {"workerRuntime": "source-bound-private-capture\n", "nativeBoundary": None})
            window = hosted.retained_window(reference, cutoff)
            self.assertEqual(window["version"], 1)
            self.assertNotIn("clockBridge", window)
            self.assertEqual(window["elapsedNs"], "123")
            self.assertEqual(len(window["loaded"]), 3)
            self.assertIsNone(window["captures"]["nativeBoundary"])
            self.assertNotIn("private-log-canary", json.dumps(window))
            (evidence.path / "a-stderr").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "log changed"):
                hosted.retained_window(reference, cutoff)
        finally:
            evidence.close()

    def test_bracketed_clock_window_retains_actual_local_observations(self):
        evidence = hosted.Evidence(self.root / "clock-window")
        try:
            for label in ("a", "b"):
                for stream in ("stdout", "stderr"):
                    evidence.save(label + "-" + stream, b"")
            cutoff = hosted.original_cutoff(60)
            start_clock = hosted.clock_sample()
            finish_clock = hosted.clock_sample()
            started = int(start_clock["monotonicAfterNs"])
            finished = int(finish_clock["monotonicBeforeNs"])
            bridge = {"bootId": cutoff["controllerBootId"], "loadedStart": start_clock,
                      "loadedFinish": finish_clock}

            reference = hosted.retain_window(evidence, cutoff, started, finished,
                        [sample()] * 100, [sample()] * 3, [], {},
                        {"workerRuntime": None, "nativeBoundary": None}, clock_bridge=bridge)
            window = hosted.retained_window(reference, cutoff)

            self.assertEqual(window["version"], 2)
            self.assertEqual(window["clockBridge"], bridge)
            self.assertEqual(window["startedMonotonicNs"], str(started))
            self.assertEqual(window["finishedMonotonicNs"], str(finished))
            self.assertNotIn("remoteClockUncertainty", window["clockBridge"])
        finally:
            evidence.close()

    def test_clock_bridge_refuses_wrong_boot_displaced_boundaries_and_rollback(self):
        cutoff = hosted.original_cutoff(60)
        bridge = {"bootId": cutoff["controllerBootId"],
                  "loadedStart": {"monotonicBeforeNs": "100", "observedUnixNs": "1000",
                                  "monotonicAfterNs": "110"},
                  "loadedFinish": {"monotonicBeforeNs": "200", "observedUnixNs": "1100",
                                   "monotonicAfterNs": "220"}}
        hosted.validate_clock_bridge(bridge, cutoff, 110, 200)
        for field, value, message in (
                ("bootId", "00000000-0000-0000-0000-000000000000", "another boot"),
                ("loadedStart", {**bridge["loadedStart"], "monotonicBeforeNs": "111"}, "boundary"),
                ("loadedFinish", {**bridge["loadedFinish"], "monotonicAfterNs": "199"}, "boundary"),
                ("loadedFinish", {**bridge["loadedFinish"], "observedUnixNs": "999"}, "rollback"),
                ("loadedStart", {**bridge["loadedStart"], "observedUnixNs": "01000"}, "noncanonical"),
                ("loadedStart", {**bridge["loadedStart"], "observedUnixNs": True}, "noncanonical")):
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, message):
                hosted.validate_clock_bridge({**bridge, field: value}, cutoff, 110, 200)

    def test_explicit_resume_uses_original_interval_and_owned_window_references(self):
        counters = "Direct upload client: " + " ".join(
            name + "=0" for name in self.lib["DIRECT_CLIENT_COUNTERS"])
        reply = {"data": {"state": "ready", "objects": [], "publication_id": "1" * 32}}
        executable = self.peer("import sys,time\ntime.sleep(0.4)\n"
                               + f"print({json.dumps(reply)!r})\nprint({counters!r}, file=sys.stderr)\n")
        selected = self.selected(executable)
        reports = {label: {"large_objects": [], "metadata_objects": 0,
                    "metadata_catalogue_sha256": hosted.hashlib.sha256(b"").hexdigest()}
                   for label in ("a", "b")}
        first = hosted.Evidence(self.root / "first-window")
        current = hosted.Evidence(self.root / "resumed-window")
        try:
            for label in ("a", "b"):
                for stream in ("stdout", "stderr"):
                    first.save(label + "-" + stream, b"owned-first-window")
            cutoff = hosted.original_cutoff(60)
            finished = time.monotonic_ns() - 1_000_000_000
            started = finished - 123_000_000
            reference = hosted.retain_window(first, cutoff, started, finished,
                        [sample()] * 100, [sample()] * 5, [], {},
                        {"workerRuntime": None, "nativeBoundary": None})
            # Synthetic checkpoints isolate supervision from provider authority.
            old = {"object": {"sessions": [{"sparseGaps": True, "completeSha256": None}]},
                   "admission": {"publication": {"headerSha256": "1" * 64}}}
            resumed = {"version": 2, "phase": "interrupted_sparse_checkpoint",
                       "bindingSha256": "1" * 64, "corpus": reports,
                       "checkpoints": {"a": old, "b": old}, "completed": {},
                       **cutoff, "firstWindow": reference}
            with patch.object(hosted, "corpus", return_value=reports), patch.object(
                    hosted, "checkpoint", return_value=old), patch.object(
                    hosted, "page_probe", side_effect=lambda *args: (time.sleep(0.01), sample())[1]), patch.dict(
                    self.lib, {"preserve_originals": lambda before, after: None}):
                outcome = hosted.run(selected, "1" * 64, current, self.lib, resumed)
            self.assertEqual(outcome["state"], "workload_complete")
            measured = json.loads((current.path / "measurements.json").read_text())
            window = json.loads((current.path / "workload-window.json").read_text())
            self.assertEqual(window["version"], 2)
            self.assertEqual(window["clockBridge"]["bootId"], cutoff["controllerBootId"])
            self.assertEqual(hosted.retained_window(reference, cutoff)["version"], 1)
            hosted.validate_clock_bridge(window["clockBridge"], cutoff,
                int(window["startedMonotonicNs"]), int(window["finishedMonotonicNs"]))
            self.assertEqual(measured["originalCutoff"], cutoff)
            self.assertEqual(measured["firstWindowElapsedNs"], "123000000")
            self.assertEqual(measured["loadedWindowReferences"][0], reference)
            self.assertEqual(int(measured["workloadElapsedNs"]),
                             int(window["finishedMonotonicNs"]) - started)
            self.assertGreater(int(measured["workloadElapsedNs"]),
                               int(measured["invocationLoadedElapsedNs"]) + 1_000_000_000)
            self.assertEqual(measured["latency"]["loadedSamples"], len(window["loaded"]) + 5)
            self.assertEqual(measured["hostedAcceptance"], "incomplete")
        finally:
            first.close()
            current.close()

    def assessment_fixture(self, body, label="assessment"):
        evidence = hosted.Evidence(self.root / label)
        for publisher in ("a", "b"):
            for stream in ("stdout", "stderr"):
                evidence.save(publisher + "-" + stream, b"owned-original-window")
        cutoff = hosted.original_cutoff(60)
        finished = time.monotonic_ns()
        reference = hosted.retain_window(evidence, cutoff, finished - 10, finished,
                    [sample()] * 100, [sample()] * 25, [], {},
                    {"workerRuntime": None, "nativeBoundary": None})
        evidence.save("measurements.json", {"loadedWindowReferences": [reference], "originalCutoff": cutoff})
        runtime = {"runtimeCodecRevision": "fixture", "workerSourceDigest": "1" * 64,
                   "sourceArchiveSha256": "2" * 64, "nativeExecutableSha256": "3" * 64}
        selection = {name: None for name in ("runtimeProvenance", "bodyManifest", "observerExecutable", "authSidecar",
                     "capturePolicy", "captureExport", "sdkApplicationLog", "clientApplicationLog", "indexSnapshots",
                     "wireMetrics")}
        selection.update(version=1, runtime=runtime, workloadWindows=[])
        selection_path = self.root / (label + "-selection.json")
        selection_path.write_text(json.dumps(selection))
        selection_path.chmod(0o600)
        adapter = self.root / (label + "-adapter.py")
        adapter.write_text(body)
        adapter.chmod(0o600)

        def private_reference(path):
            raw = path.read_bytes()
            return {"file": str(path), "sha256": hosted.hashlib.sha256(raw).hexdigest(), "byteSize": str(len(raw))}

        python = hosted.immutable_executable(sys.executable)
        invocation = {"version": 1, "python": python, "adapter": private_reference(adapter),
                      "selection": private_reference(selection_path)}
        invocation_path = self.root / (label + "-invocation.json")
        invocation_path.write_text(json.dumps(invocation))
        invocation_path.chmod(0o600)
        return evidence, invocation_path, selection_path, reference

    def test_assessment_real_exit2_retains_incomplete_and_exact_window_conversion(self):
        # This peer tests wiring and exit semantics, not body/codec acceptance.
        body = """import json,os,sys
fd=os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW)
with os.fdopen(fd) as source: selected=json.load(source)
report={"version":1,"hostedAcceptance":"incomplete","runtime":selected["runtime"],
        "applicationBodyAssessment":{"state":"incomplete","nativeBulkBytes":None,
                                     "nativeCapturedObjectPayloadBytes":None},
        "applicationProviderLedger":{"state":"incomplete"},"indexParity":None,"wireMetrics":None,
        "loadedWindowReferences":[{"sha256":row["sha256"],"byteSize":row["byteSize"]}
                                  for row in selected["workloadWindows"]]}
print(json.dumps(report))
raise SystemExit(2)
"""
        evidence, invocation, selection, window = self.assessment_fixture(body)
        original = selection.read_bytes()
        try:
            outcome = hosted.assess_workload(str(invocation), evidence)
            self.assertEqual(outcome["state"], "incomplete_observation")
            receipt = json.loads((evidence.path / "assessment-receipt.json").read_text())
            self.assertEqual(receipt["exitCode"], 2)
            self.assertFalse(receipt["timedOut"])
            self.assertEqual(selection.read_bytes(), original)
            derived = json.loads((evidence.path / "assessment-invocation-selection.json").read_text())
            self.assertEqual(derived["workloadWindows"], [{"file": str(evidence.original_path / "workload-window.json"),
                             "sha256": window["reference"]["sha256"], "byteSize": str(window["reference"]["bytes"])}])
            selected = json.loads(original)
            self.assertEqual({key: value for key, value in derived.items() if key != "workloadWindows"},
                             {key: value for key, value in selected.items() if key != "workloadWindows"})
            report = json.loads((evidence.path / "assessment-stdout").read_text())
            self.assertIsNone(report["applicationBodyAssessment"]["nativeBulkBytes"])
            self.assertEqual(receipt["providerSettlement"], "unknown")
        finally:
            evidence.close()

    def test_assessment_optional_cli_wiring_keeps_workload_result_separate(self):
        body = """import json,sys
with open(sys.argv[1]) as source: selected=json.load(source)
print(json.dumps({"version":1,"hostedAcceptance":"incomplete","runtime":selected["runtime"],
      "applicationBodyAssessment":{"state":"incomplete","nativeBulkBytes":None,
      "nativeCapturedObjectPayloadBytes":None,"missing":["synthetic-missing-join"]},
      "applicationProviderLedger":{"state":"incomplete"},"indexParity":None,"wireMetrics":None,
      "loadedWindowReferences":[{"sha256":row["sha256"],"byteSize":row["byteSize"]}
                                for row in selected["workloadWindows"]]}))
raise SystemExit(2)
"""
        prepared, invocation, _, _ = self.assessment_fixture(body)
        output = self.root / "cli-output"

        def completed_workload(selected, binding_hash, evidence, lib, resumed):
            for label in ("a", "b"):
                for stream in ("stdout", "stderr"):
                    evidence.save(label + "-" + stream, b"owned-cli-window")
            cutoff = hosted.original_cutoff(60)
            finished = time.monotonic_ns()
            window = hosted.retain_window(evidence, cutoff, finished - 1, finished,
                     [sample()] * 100, [sample()] * 25, [], {},
                     {"workerRuntime": None, "nativeBoundary": None})
            evidence.save("measurements.json", {"loadedWindowReferences": [window], "originalCutoff": cutoff})
            return {"state": "workload_complete", "hostedAcceptance": "incomplete", "nativeBulkBytes": None}

        try:
            argv = [str(MODULE), "--binding-file", "synthetic-binding", "--library-dir", str(LIBRARY),
                    "--output-dir", str(output), "--assessment-selection-file", str(invocation)]
            with patch.object(sys, "argv", argv), patch.object(hosted, "binding", return_value=({}, "1" * 64)), patch.object(
                    hosted, "libraries", return_value={}), patch.object(hosted, "run", side_effect=completed_workload), patch.object(
                    hosted.signal, "signal"), patch("builtins.print"):
                self.assertEqual(hosted.main(), 2)
            outcome = json.loads((output / "outcome.json").read_text())
            self.assertEqual(outcome["state"], "workload_complete")
            self.assertEqual(outcome["assessment"]["state"], "incomplete_observation")
            self.assertIsNone(outcome["nativeBulkBytes"])
            observed = json.loads((output / "assessment-stdout").read_text())
            self.assertEqual(observed["applicationBodyAssessment"]["missing"], ["synthetic-missing-join"])
        finally:
            prepared.close()

    def test_assessment_actual_exit1_and_invalid_exit2_retain_before_refusal(self):
        peers = {"exit1": "import sys\nprint('private-error-canary',file=sys.stderr)\nraise SystemExit(1)\n",
                 "schema": "print('{\"version\":1,\"version\":1}')\nraise SystemExit(2)\n"}
        for label, body in peers.items():
            with self.subTest(label=label):
                evidence, invocation, _, _ = self.assessment_fixture(body, label)
                try:
                    with self.assertRaisesRegex(ValueError, "private result retained"):
                        hosted.assess_workload(str(invocation), evidence)
                    receipt_text = (evidence.path / "assessment-receipt.json").read_text()
                    receipt = json.loads(receipt_text)
                    self.assertEqual(receipt["exitCode"], 1 if label == "exit1" else 2)
                    self.assertEqual(receipt["state"], "invalid_or_unknown")
                    self.assertNotIn("private-error-canary", receipt_text)
                    self.assertEqual((evidence.path / "assessment-stderr").stat().st_mode & 0o777, 0o600)
                finally:
                    evidence.close()

    def test_assessment_substituted_input_refuses_before_child_dispatch(self):
        marker = self.root / "must-not-dispatch"
        body = f"from pathlib import Path\nPath({str(marker)!r}).touch()\nraise SystemExit(2)\n"
        evidence, invocation, selection, _ = self.assessment_fixture(body)
        selection.write_text("{}")
        try:
            with self.assertRaisesRegex(ValueError, "custody|changed"):
                hosted.assess_workload(str(invocation), evidence)
            self.assertFalse(marker.exists())
        finally:
            evidence.close()

    def test_assessment_collector_bounds_actual_output_and_owned_timeout(self):
        oversized = self.peer("import sys\nsys.stderr.write('x'*70000)\n")
        result = hosted.assessment_process([sys.executable, str(oversized)], [], timeout=5)
        self.assertTrue(result["overflow"])
        self.assertEqual(len(result["stderr"]), 64 * 1024)
        self.assertIsNotNone(result["exitCode"])
        waiting = self.peer("import time\ntime.sleep(30)\n")
        result = hosted.assessment_process([sys.executable, str(waiting)], [], timeout=0.1)
        self.assertTrue(result["timedOut"])
        self.assertIn(result["exitCode"], (-15, -9))

    def test_assessment_reviewed_adapter_actual_refusal_is_retained(self):
        selected_path = os.environ.get("AOS_HOSTED_ASSESSMENT_TEST_ADAPTER")
        if selected_path is None:
            self.skipTest("Separately selected reviewed adapter is required")
        selected = Path(selected_path)
        evidence, invocation, _, _ = self.assessment_fixture(selected.read_text())
        try:
            with self.assertRaisesRegex(ValueError, "private result retained"):
                hosted.assess_workload(str(invocation), evidence)
            receipt = json.loads((evidence.path / "assessment-receipt.json").read_text())
            self.assertEqual(receipt["adapter"]["sha256"], hosted.hashlib.sha256(selected.read_bytes()).hexdigest())
            self.assertEqual(receipt["exitCode"], 1)
            self.assertEqual(receipt["state"], "invalid_or_unknown")
            self.assertIn(b"ValueError", (evidence.path / "assessment-stderr").read_bytes())
        finally:
            evidence.close()

    def assessment_group_peer(self, name, exit_leader=False, overflow=False):
        marker = self.root / (name + "-pids.json")
        body = f"""import json,os,signal,subprocess,sys,time
from pathlib import Path
child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"])
def collect(signum, frame):
    child.wait(timeout=3)
    raise SystemExit(0)
signal.signal(signal.SIGTERM,collect)
record={{"leader":os.getpid(),"child":child.pid}}
Path({str(marker)!r}).write_text(json.dumps(record))
print(json.dumps(record),flush=True)
"""
        if overflow:
            body += "sys.stderr.write('x'*70000); sys.stderr.flush()\n"
        body += "raise SystemExit(2)\n" if exit_leader else "time.sleep(30)\n"
        return self.peer(body), marker

    def assert_no_live_fixture_process(self, pid):
        try:
            state = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()[0]
        except (FileNotFoundError, ProcessLookupError):
            return
        # An exited leader's orphan may await the system reaper. That remains
        # unknown group cleanup, never positive complete ownership evidence.
        self.assertEqual(state, "Z")

    def test_assessment_owned_group_timeout_reaps_peer_helper_without_touching_other_group(self):
        peer, marker = self.assessment_group_peer("owned-timeout")
        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            result = hosted.assessment_process([sys.executable, str(peer)], [], timeout=0.3)
            observed = json.loads(marker.read_text())
            self.assertTrue(result["timedOut"])
            self.assertEqual(result["cleanup"]["state"], "group_absent")
            self.assertEqual(result["cleanup"]["processGroup"], observed["leader"])
            self.assertFalse((Path("/proc") / str(observed["leader"])).exists())
            self.assertFalse((Path("/proc") / str(observed["child"])).exists())
            self.assertIn(str(observed["child"]).encode(), result["stdout"])
            self.assertIsNone(unrelated.poll())
        finally:
            unrelated.kill()
            unrelated.wait(timeout=5)

    def test_assessment_exited_leader_inherited_pipes_still_terminates_helper(self):
        peer, marker = self.assessment_group_peer("exited-leader", exit_leader=True)
        result = hosted.assessment_process([sys.executable, str(peer)], [], timeout=0.3)
        observed = json.loads(marker.read_text())
        self.assertEqual(result["exitCode"], 2)
        self.assertTrue(result["timedOut"])
        self.assertTrue(result["cleanup"]["termSent"])
        self.assertFalse((Path("/proc") / str(observed["leader"])).exists())
        self.assert_no_live_fixture_process(observed["child"])
        self.assertIn(result["cleanup"]["state"], ("group_absent", "unknown"))

    def test_assessment_group_cleanup_covers_cancel_error_and_overflow(self):
        select = hosted.selectors.DefaultSelector.select
        for kind in ("cancel", "error", "overflow"):
            with self.subTest(kind=kind):
                peer, marker = self.assessment_group_peer(kind, overflow=kind == "overflow")

                def interrupted(instance, timeout=None):
                    if marker.exists():
                        raise InterruptedError("private-cancel-canary") if kind == "cancel" else OSError("private-error-canary")
                    return select(instance, timeout)

                if kind == "overflow":
                    result = hosted.assessment_process([sys.executable, str(peer)], [], timeout=3)
                    self.assertTrue(result["overflow"])
                    self.assertEqual(len(result["stderr"]), 64 * 1024)
                else:
                    with patch.object(hosted.selectors.DefaultSelector, "select", interrupted):
                        result = hosted.assessment_process([sys.executable, str(peer)], [], timeout=3)
                    self.assertEqual(result["cancelled"], kind == "cancel")
                    self.assertEqual(result["collectionFailed"], kind == "error")
                observed = json.loads(marker.read_text())
                self.assertEqual(result["cleanup"]["state"], "group_absent")
                self.assertFalse((Path("/proc") / str(observed["leader"])).exists())
                self.assertFalse((Path("/proc") / str(observed["child"])).exists())
                self.assertNotIn("private-error-canary", str(result))
                self.assertNotIn("private-cancel-canary", str(result))


if __name__ == "__main__":
    unittest.main()
