"""Exercise called coordinator custody and terminal ordering without effects.

Embedded CLIENT reads execute against owner-private temporary regular files.
Subprocess/provider/SQL authority is deliberately not asserted by these cases.
"""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


window = load("_hub-direct-queue-fault-window.py")
boundary = load("_hub-direct-boundary.py")
sql = load("_hub-native-sql-projection.py")


class ReceivedOriginalTests(unittest.TestCase):
    def fixture(self, temporary, mutation=None, atime_only=False):
        root = Path(temporary) / "scope"
        root.mkdir(mode=0o700)
        image = root / "original.json"
        image.write_bytes(b'{"original":true}')
        image.chmod(0o600)
        selected_root = "/var/lib/hybrid-client/queue-faults/selected/scope"
        owner = object.__new__(window.ProductionQueueWindow)

        def guest(machine, code, selected, timeout=30):
            mapped = dict(selected)
            mapped["path"] = str(root / Path(selected["path"]).name)
            mapped["root"] = None if selected["root"] is None else str(root)
            mapped["terminalPending"] = (None if selected["terminalPending"] is None
                                          else str(root / "exit.pending"))
            real_fstat = os.fstat
            calls = 0

            def observed_stat(descriptor):
                nonlocal calls
                calls += 1
                if calls == 2 and mutation is not None:
                    mutation(root, image)
                actual = real_fstat(descriptor)
                if not atime_only:
                    return actual
                # Model the kernel's read-induced atime advance while keeping
                # the actual descriptor and every custody/content field intact.
                value = SimpleNamespace(**{name: getattr(actual, name)
                    for name in dir(actual) if name.startswith("st_")})
                value.st_atime_ns += calls
                value.st_atime += calls / 1000000000
                return value

            out = io.StringIO()
            with patch.object(os, "fstat", observed_stat), contextlib.redirect_stdout(out):
                try:
                    exec(compile(textwrap.dedent(code), "selected-client-reader", "exec"),
                         {"selected": mapped, "json": json})
                except SystemExit as terminal:
                    if terminal.code != 0:
                        raise
            value = json.loads(out.getvalue())
            if "custody" in value:
                value["custody"]["file"] = selected["path"]
                value["custody"]["root"] = selected["root"]
            return json.dumps(value)

        owner.guest = guest
        return owner, selected_root, image

    def test_actual_embedded_read_accepts_atime_only_and_commits_exact_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner, root, image = self.fixture(temporary, atime_only=True)
            body = image.read_bytes()
            reference = {"sha256": hashlib.sha256(body).hexdigest(), "byteSize": str(len(body))}
            receipts = []

            observed = owner.received(None, root + "/original.json", 65536, reference,
                                      root=root, retain=receipts.append)

            self.assertEqual(observed, body)
            self.assertEqual(receipts[0]["fileMetadata"]["mode"], "0600")
            self.assertEqual(receipts[0]["fileMetadata"]["nlink"], "1")

    def test_actual_file_content_and_directory_write_during_read_refuse(self):
        mutations = [lambda root, image: image.write_bytes(b'{"original":false}'),
                     lambda root, image: (root / "foreign-write").write_bytes(b"changed")]
        for mutate in mutations:
            with self.subTest(mutation=mutate), tempfile.TemporaryDirectory() as temporary:
                owner, root, _ = self.fixture(temporary, mutation=mutate)
                with self.assertRaises(ValueError):
                    owner.received(None, root + "/original.json", 65536, root=root)

    def test_alias_mode_hash_and_foreign_locator_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner, root, image = self.fixture(temporary)
            (image.parent / "alias.json").symlink_to(image)
            with self.assertRaises(ValueError):
                owner.received(None, root + "/alias.json", 65536, root=root)
            image.chmod(0o644)
            with self.assertRaises(ValueError):
                owner.received(None, root + "/original.json", 65536, root=root)
            image.chmod(0o600)
            with self.assertRaises(ValueError):
                owner.received(None, root + "/original.json", 65536,
                    {"sha256": "0" * 64, "byteSize": str(image.stat().st_size)}, root=root)
            for foreign in (root + "/../original.json", root + "-foreign/original.json"):
                with self.assertRaises(ValueError):
                    owner.received(None, foreign, 65536, root=root)

    def test_existing_whole_journal_bound_stays_distinct_from_client_references(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner, root, image = self.fixture(temporary)
            self.assertEqual(owner.received(None, root + "/original.json", 64 * 1024 * 1024),
                             image.read_bytes())
            with self.assertRaises(ValueError):
                owner.received(None, root + "/original.json", 64 * 1024 * 1024, root=root)

    def test_only_exact_pending_final_two_link_transition_waits_for_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner, root, image = self.fixture(temporary)
            image.rename(image.parent / "exit.pending")
            os.link(image.parent / "exit.pending", image.parent / "exit.json")
            self.assertIsNone(owner.received(None, root + "/exit.json", 65536,
                terminal_pending=root + "/exit.pending"))
            (image.parent / "exit.pending").unlink()
            self.assertEqual(owner.received(None, root + "/exit.json", 65536,
                terminal_pending=root + "/exit.pending"), b'{"original":true}')
            os.link(image.parent / "exit.json", image.parent / "unrelated")
            with self.assertRaises((OSError, ValueError)):
                owner.received(None, root + "/exit.json", 65536,
                    terminal_pending=root + "/exit.pending")

    def test_publisher_unlink_between_final_stat_and_pending_stat_waits_without_accepting_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner, root, image = self.fixture(temporary)
            pending = image.parent / "exit.pending"
            image.rename(pending)
            os.link(pending, image.parent / "exit.json")
            original_lstat = Path.lstat
            def unlink_before_stat(path):
                if path == pending:
                    pending.unlink()
                return original_lstat(path)

            with patch.object(Path, "lstat", unlink_before_stat):
                self.assertIsNone(owner.received(None, root + "/exit.json", 65536,
                    terminal_pending=root + "/exit.pending"))
            self.assertEqual(owner.received(None, root + "/exit.json", 65536,
                terminal_pending=root + "/exit.pending"), b'{"original":true}')


class CollectorTerminalTests(unittest.TestCase):
    def test_zero_byte_prefix_is_not_read_until_actual_terminal_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner = object.__new__(window.ProductionQueueWindow)
            owner.worker = object()
            calls = []
            collector = {"path": "window", "terminalPath": "exit", "arguments": ["selected"],
                         "owner": {"pid": 123, "startTicks": "456"}}
            case = {"collector": collector, "cutoffUnixMs": window.time.time() * 1000 + 5000,
                    "local": Path(temporary)}
            terminal = {"version": 1, "argv": ["selected"], "startedUnixNs": "1",
                        "finishedUnixNs": "2", "exitCode": 0, "timedOut": False}

            def received(machine, path, maximum, missing=False, **kwargs):
                calls.append(path)
                if path == "exit":
                    return None if len(calls) == 1 else window.encoded(terminal)
                self.assertTrue((case["local"] / "collector-exit.json").is_file())
                return b'{"terminal":"completed","samples":[]}'

            owner.received = received
            with patch.object(window.time, "sleep"):
                result, receipt = owner.finish_collector(case)

            self.assertEqual(calls, ["exit", "exit", "window"])
            self.assertEqual(result["terminal"], "completed")
            self.assertIsNotNone(receipt["terminal"])

    def test_actual_nonzero_and_timeout_preserve_terminal_and_partial_without_success(self):
        for exit_code, timed_out in ((1, False), (None, True)):
            with self.subTest(exit=exit_code), tempfile.TemporaryDirectory() as temporary:
                owner = object.__new__(window.ProductionQueueWindow)
                owner.worker = object()
                terminal = {"version": 1, "argv": ["selected"], "startedUnixNs": "1",
                            "finishedUnixNs": "2", "exitCode": exit_code, "timedOut": timed_out}
                owner.received = lambda machine, path, maximum, missing=False, **kwargs: (
                    window.encoded(terminal) if path == "exit" else b'{"terminal":"process_observation_failed"}')
                case = {"collector": {"path": "window", "terminalPath": "exit", "arguments": ["selected"],
                                      "owner": {"pid": 123}},
                        "cutoffUnixMs": window.time.time() * 1000 + 5000, "local": Path(temporary)}

                with self.assertRaises(ValueError):
                    owner.finish_collector(case)

                self.assertEqual(json.loads((case["local"] / "collector-exit.json").read_bytes())["exitCode"], exit_code)
                self.assertTrue((case["local"] / "process-window.json").is_file())


class PhasePublicationTests(unittest.TestCase):
    def test_generated_runner_keeps_terminal_absent_until_actual_exit_and_fsync(self):
        with tempfile.TemporaryDirectory() as temporary:
            local = Path(temporary)
            root = local / "phase"
            root.mkdir(mode=0o700)
            owner = object.__new__(window.ProductionQueueWindow)
            owner.client = object()
            owner.tools = {"python": "/nix/store/selected/bin/python3",
                           "queueFaultStagedSupervisor": "/nix/store/selected/supervisor.py"}
            owner.private_parent = lambda *args: None
            installed = {}
            def install(machine, path, body):
                installed[Path(path).name] = body
                return {"file": path, "sha256": hashlib.sha256(body).hexdigest(), "byteSize": str(len(body))}
            owner.install = install
            owner.owners = {"launch_managed_process": lambda *args: {"pid": 123, "startTicks": "456"}}
            case = {"guestRoot": "/var/lib/hybrid-client/queue-faults/selected", "local": local,
                    "cutoffUnixMs": window.time.time() * 1000 + 5000}
            owner.launch_phase(case, "initial", {"version": 1})
            (root / "invocation.json").write_bytes(installed["invocation.json"])
            (root / "invocation.json").chmod(0o600)
            real_fsync = os.fsync
            observations = []
            def fsync(descriptor):
                self.assertFalse((root / "exit.json").exists())
                self.assertTrue((root / "exit.pending").exists())
                observations.append("fsync_before_publication")
                real_fsync(descriptor)
            def wait(timeout):
                self.assertGreater(timeout, 0)
                self.assertFalse((root / "exit.json").exists())
                observations.append("actual_wait_returned")
                return 2
            child = SimpleNamespace(pid=123, wait=wait)

            with patch.object(sys, "argv", ["runner.py", str(root)]), \
                 patch.object(window.subprocess, "Popen", return_value=child), \
                 patch.object(os, "fsync", fsync):
                exec(compile(installed["runner.py"], "selected-phase-runner", "exec"), {})

            terminal = json.loads((root / "exit.json").read_bytes())
            self.assertEqual(observations, ["actual_wait_returned", "fsync_before_publication"])
            self.assertEqual(terminal["exitCode"], 2)
            self.assertFalse(terminal["timedOut"])
            self.assertFalse((root / "exit.pending").exists())
            self.assertEqual((root / "exit.json").stat().st_nlink, 1)

    def test_malformed_retained_terminal_cannot_trigger_a_second_retention_attempt(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner = object.__new__(window.ProductionQueueWindow)
            owner.client = object()
            reads = []
            def received(*args, **kwargs):
                reads.append(args[1])
                return b"{broken"
            owner.received = received
            case = {"cutoffUnixMs": window.time.time() * 1000 + 5000, "local": Path(temporary)}
            phase = {"root": "/var/lib/hybrid-client/queue-faults/selected/initial"}
            with self.assertRaises(ValueError):
                owner.finish_phase(case, phase)
            with self.assertRaises(ValueError):
                owner.finish_phase(case, phase)
            self.assertEqual(len(reads), 1)
            self.assertEqual((case["local"] / "initial-exit.json").read_bytes(), b"{broken")


class AcceptedOriginalTests(unittest.TestCase):
    def test_unknown_owned_cleanup_retains_outcome_and_refuses_later_caller_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            calls = []
            def run_case(fault, *args):
                calls.append(fault)
                return {"state": "unknown", "cleanupFailures": [
                    {"operation": "wrapperDisposal", "failureClass": "RuntimeError"}]}
            selected = SimpleNamespace(root=Path(temporary), process={"pid": 123}, run_case=run_case)
            owners = {"direct_root_browser_token": lambda *args, **kwargs: "synthetic",
                      "private_guest_command": object()}
            publication = {"queueFaultRegistry": {"registry": {"slug": "selected/registry"}},
                           "storageWorkflowCaptures": {"nativeProcess": {"pid": 456}}}
            tools = {"curl": "selected", "python": "selected"}
            credentials = {"organization": {"ownerScopeKey": "selected-owner"}}

            with patch.object(window, "ProductionQueueWindow", return_value=selected):
                with self.assertRaises(RuntimeError):
                    window.run_production_queue_fault_window(None, None, None, None, None,
                        tools, None, credentials, None, None, None, publication, owners)
                    calls.append("later_lifecycle_mutation")

            self.assertEqual(calls, ["enqueue_ack_lost"])
            outcome = json.loads((Path(temporary) / "outcome.json").read_bytes())
            self.assertEqual(len(outcome["cases"]), 5)
            self.assertEqual(outcome["cases"]["delegation_expired"]["reason"], "prior_owned_cleanup_unknown")
            self.assertIsNone(outcome["qualification"])

    def test_only_actual_exit_two_and_closed_committed_object_summary_can_return(self):
        original_root = "/var/lib/hybrid-client/queue-faults/selected"
        selection = {"file": original_root + "/initial/selection.json", "sha256": "a" * 64, "byteSize": "4"}
        accepted = {"file": original_root + "/initial/output/external_s3/accepted-originals.json",
                    "sha256": "b" * 64, "byteSize": "4"}
        case = {"guestRoot": original_root, "scopeRoot": original_root + "/initial/output/external_s3",
                "initial": {"root": original_root + "/initial", "selectionReference": selection},
                "acceptedReference": accepted}
        summary = {"status": "incomplete", "scopes": ["external_s3"], "mode": "accepted_original_continuation",
                   "publicationCommit": "not_invoked", "raceQualification": None,
                   "cleanupSettlement": None, "windowsAAndC": "not_executed"}
        valid = {"receipt": {"exitCode": 2, "timedOut": False}, "summary": summary,
                 "result": {"mode": summary["mode"], "status": "incomplete", "publicationCommit": "not_invoked",
                            "results": [{"terminalState": "committed", "raceQualification": None}]}}
        for mutation in (None, lambda v: v["receipt"].update(exitCode=1),
                         lambda v: v["receipt"].update(timedOut=True),
                         lambda v: v.update(summary=None),
                         lambda v: v["summary"].update(publicationCommit="committed"),
                         lambda v: v["result"]["results"][0].update(terminalState="unknown")):
            observed = copy.deepcopy(valid)
            if mutation is not None:
                mutation(observed)
            launches, retained = [], []
            def launch(actual_case, phase, **references):
                launches.append(references)
                self.assertIs(references["selection_reference"], selection)
                self.assertIs(references["accepted_reference"], accepted)
                return {"phase": phase}
            def finish(actual_case, phase):
                retained.append(observed)
                return observed
            actual = SimpleNamespace(launch_phase=launch, finish_phase=finish)
            adapter = window.ClientPreparedIO(actual, case)
            adapter.read_reference = lambda *args: b"{}"

            if mutation is None:
                self.assertIs(adapter.continue_acknowledged(selection["file"], accepted["file"],
                    original_root + "/accepted/output"), observed)
            else:
                with self.assertRaises(ValueError):
                    adapter.continue_acknowledged(selection["file"], accepted["file"], original_root + "/accepted/output")
            self.assertEqual(len(launches), 1)
            self.assertEqual(retained, [observed])

    def test_preparation_failure_preserves_owner_and_each_cleanup_despite_retention_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner = object.__new__(window.ProductionQueueWindow)
            owner.process = {"configurationFile": "original"}
            owner.worker, owner.tools = object(), {"python": "selected"}
            calls = []
            def make_case(fault, index, registry, bearer, native, *, case):
                case.update(local=Path(temporary), runDigest="a" * 64, initial={},
                            continuationPhase={"name": "continuation"}, context={},
                            wrapper={}, wrapperProcess={"pid": 123}, collector={})
                raise RuntimeError("controlled harness failure after launch")
            def finish(case, phase):
                calls.append("continuation_terminal" if phase.get("name") else "initial_terminal")
                phase["finishAttempted"] = True
                raise ValueError("controlled missing terminal")
            def collect(case):
                calls.append("collector_terminal")
                return {"terminal": "completed"}
            def stop(*args):
                calls.append("wrapper_stop")
                return {"stopped": True}
            def start(*args):
                calls.append("restore")
                return {"configurationFile": "original", "pid": 456}
            owner.make_case, owner.finish_phase, owner.finish_collector = make_case, finish, collect
            owner.owners = {"stop_direct_worker": stop, "start_direct_worker": start}

            outcome = owner.run_case("enqueue_ack_lost", 0, {}, "synthetic", {})

            self.assertEqual(calls, ["initial_terminal", "continuation_terminal", "collector_terminal", "wrapper_stop", "restore"])
            self.assertEqual(outcome["state"], "unknown")
            self.assertEqual(outcome["failureClass"], "RuntimeError")
            self.assertEqual(outcome["cleanupFailures"], [{"operation": "initialPhase", "failureClass": "ValueError"},
                                                        {"operation": "continuationPhase", "failureClass": "ValueError"}])
            self.assertEqual(json.loads((Path(temporary) / "case-outcome.json").read_bytes()), outcome)


class NamespaceTests(unittest.TestCase):
    def test_actual_body_capture_defaults_and_distinct_namespaces_do_not_collide(self):
        observation = {"request_id": "1" * 32, "procedure": "selected", "phase": "admission",
                       "status": 200, "method": "POST", "response_content_type": "application/json",
                       "response_content_encoding": None, "request_transfer_encoding": None,
                       "request_body_file": "/var/lib/hybrid-native-observations/client-body/request",
                       "response_body_file": "/var/lib/hybrid-native-observations/response-bodies/reply",
                       "request_body_bytes": 2, "response_body_bytes": 2}
        names = []
        def retain(name, body):
            self.assertNotIn("/", name)
            self.assertNotIn(name, names)
            names.append(name)
            return hashlib.sha256(body if isinstance(body, bytes) else window.encoded(body)).hexdigest()
        with patch.object(boundary, "read_direct_guest_file", lambda *args: b"{}", create=True), \
             patch.object(boundary, "retain_direct_flow", retain, create=True), \
             patch.object(boundary, "WORKER_CONTROL_REPLY_LIMIT", 256 * 1024, create=True):
            for namespace in (None, "queue-fault-" + "a" * 64, "queue-fault-" + "b" * 64):
                boundary.capture_direct_native_bodies(None, {"python": "selected"}, [observation],
                                                      artifact_namespace=namespace)
        self.assertEqual(names[0], "native-" + "1" * 32 + ".request.body")
        self.assertEqual(names[2], "actual-native-private-body-receipts.json")
        self.assertTrue(names[3].startswith("qf-" + "a" * 64 + "-native-"))
        for invalid in ("queue-fault-short", "queue-fault-" + "A" * 64, "../foreign"):
            with self.assertRaises(ValueError):
                boundary.capture_direct_native_bodies(None, {}, [], artifact_namespace=invalid)

    def test_sql_default_and_selected_namespace_preserve_query_and_reader_before_dispatch(self):
        class Located(Exception):
            pass
        roots = []
        native, database = SimpleNamespace(name="native"), SimpleNamespace(name="database")
        tools = {"nativeSqlProjectionCollector": str(Path(sql.__file__)), "python": "selected",
                 "nativeDatabaseUrlFile": "selected-private", "deploymentId": "selected",
                 "postgres": "selected-postgres", "workerSourcePath": "selected-runtime"}
        def dispatch(machine, python, script, selection, timeout):
            if "checkpoints" in selection:
                roots.append(selection["selection"])
                raise Located()
            return json.dumps({"process": {}, "bootId": "actual"})
        with patch.object(sql, "direct_guest_python", dispatch, create=True):
            for namespace in (None, "queue-fault-" + "a" * 64, "queue-fault-" + "b" * 64):
                with self.assertRaises(Located):
                    sql.capture_native_sql_projection(native, database, tools, [{"checkpoints": []}],
                        {"role": "reader"}, {}, "database", capture_namespace=namespace)
        self.assertEqual(roots[0]["root"], "/var/lib/hybrid-worker/native-sql-projection-0000")
        self.assertEqual(len({row["root"] for row in roots}), 3)
        for row in roots[1:]:
            self.assertEqual({k: v for k, v in row.items() if k not in {"root", "databaseUrlFile"}},
                             {k: v for k, v in roots[0].items() if k not in {"root", "databaseUrlFile"}})
        with self.assertRaises(ValueError):
            sql.capture_native_sql_projection(None, None, {}, [], {}, {}, "database", capture_namespace="../foreign")


if __name__ == "__main__":
    unittest.main()
