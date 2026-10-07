"""Exercise actual source functions with disposable local inputs.

These tests load the proposed function bodies without claiming an installed
package or provider exchange. Runtime/package installation and actual hosted
custody still require the separate selected window.
"""

import ast
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent
RUNTIME_SOURCE = Path(os.environ.get(
    "AOS_HOSTED_QUALIFICATION_TEST_RUNTIME_SOURCE", str(ROOT.parents[2]))).resolve(strict=True)
RUNTIME = {"runtimeCodecRevision": "disposable-runtime"}


def source_functions(name, skipped, values):
    """Compile actual definitions, excluding only installed-context initialization."""
    path = ROOT / name
    tree = ast.parse(path.read_bytes(), filename=str(path))
    nodes = []
    for node in tree.body:
        if isinstance(node, ast.If):
            continue
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id in skipped
                for target in node.targets):
            continue
        nodes.append(node)
    namespace = {"__file__": str(path), "__name__": "source_function_fixture", **values}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


collector_spec = importlib.util.spec_from_file_location("actual_collector", ROOT / "hosted_collect.py")
collector = importlib.util.module_from_spec(collector_spec)
collector_spec.loader.exec_module(collector)
qualification = source_functions("hosted_qualification.py",
    {"DIRECTORY", "PACKAGE_READER", "PACKAGE"},
    {"DIRECTORY": ROOT, "PACKAGE": {"runtime": RUNTIME}})
assessment = source_functions("hosted_assessment.py",
    {"PACKAGE_READER", "PACKAGE", "SOURCE", "WRAPPER", "READERS"},
    {"SOURCE": RUNTIME_SOURCE, "PACKAGE": {"runtime": RUNTIME,
        "sourceTree": "disposable-tree", "producerSha256": {},
        "captureImplementationSha256": None},
     "PACKAGE_READER": {"installed_bytes": lambda path, maximum: Path(path).read_bytes()}})


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(self.temporary)
        self.policy = {"runtime": RUNTIME, "project": "disposable-project",
            "location": "disposable-region",
            "serviceName": "projects/disposable-project/locations/disposable-region/services/disposable-hub",
            "revisionName": "projects/disposable-project/locations/disposable-region/services/disposable-hub/revisions/disposable-revision",
            "imageDigest": "sha256:" + "0" * 64, "policy": None,
            "instances": ["disposable-instance"], "firstUnixMicros": "100", "lastUnixMicros": "200"}
        self.custody = __import__("runpy").run_path(str(
            RUNTIME_SOURCE / "tests/fleet/observation-tools/hosted_custody.py"))

    def deadline(self):
        return {"bootId": "disposable-boot", "bootTimeNanos": "11000000000",
                "unixNanos": "21000000000"}

    def test_original_boot_cutoff_is_not_renewed_by_clock_rollback(self):
        with mock.patch.object(Path, "read_text", return_value="disposable-boot"), \
                mock.patch.object(collector.time, "clock_gettime_ns", return_value=12000000000), \
                mock.patch.object(collector.time, "time_ns", return_value=1000000000):
            with self.assertRaises(ValueError):
                qualification["original_deadline"](self.deadline())

    def test_host_reboot_and_noncanonical_counts_refuse(self):
        with mock.patch.object(Path, "read_text", return_value="another-boot"):
            with self.assertRaises(ValueError):
                qualification["original_deadline"](self.deadline())
        with mock.patch.object(Path, "read_text", return_value="disposable-boot"):
            for value in ("011000000000", "+11000000000", "1e10", "١١٠٠٠٠٠٠٠٠٠"):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    qualification["original_deadline"]({**self.deadline(), "bootTimeNanos": value})

    def test_expired_boot_clock_blocks_actual_collector_after_suspend(self):
        selected = {"monotonic": 100, "unix": 100,
                    "bootId": "disposable-boot", "bootTimeNanos": "11000000000"}
        with mock.patch.object(Path, "read_text", return_value="disposable-boot"), \
                mock.patch.object(collector.time, "monotonic", return_value=1), \
                mock.patch.object(collector.time, "time", return_value=1), \
                mock.patch.object(collector.time, "clock_gettime_ns", return_value=12000000000):
            with self.assertRaises(ValueError):
                collector.remaining(selected)

    def test_collector_reboot_refuses_before_work(self):
        with mock.patch.object(Path, "read_text", return_value="changed-boot"):
            with self.assertRaises(ValueError):
                collector.remaining({"monotonic": 100, "unix": 100,
                    "bootId": "disposable-boot", "bootTimeNanos": "11000000000"})

    def paginated(self, responses, maximum=None):
        supervisor = mock.Mock()
        supervisor.collect.side_effect = lambda operation, request, scope, fd, bound: (
            request, json.dumps(responses.pop(0)).encode(), b'{"disposableReceipt":true}')
        output = self.root / "pages"
        output.mkdir()
        values = vars(collector).copy()
        with mock.patch.dict(qualification, MAX_PAGES=maximum or qualification["MAX_PAGES"]):
            result = qualification["collect_cloud_run"](
                supervisor, values, self.custody, self.policy, 7, output)
        return result, supervisor

    def test_pagination_retains_exact_images_and_forwards_selected_fd(self):
        result, supervisor = self.paginated([{}, {},
            {"entries": [], "nextPageToken": "disposable-next"}, {"entries": []}])
        self.assertEqual(len(result["pages"]), 2)
        self.assertEqual(supervisor.collect.call_count, 4)
        self.assertTrue(all(call.args[3] == 7 for call in supervisor.collect.call_args_list))
        self.assertNotIn("pageToken", json.loads(supervisor.collect.call_args_list[2].args[1]))
        self.assertEqual(json.loads(supervisor.collect.call_args_list[3].args[1])["pageToken"], "disposable-next")
        reference = result["pages"][0]["response"]
        raw = Path(reference["file"]).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), reference["sha256"])
        self.assertEqual(json.loads(raw)["nextPageToken"], "disposable-next")

    def test_repeated_pagination_token_refuses_with_originals_retained(self):
        with self.assertRaises(ValueError):
            self.paginated([{}, {}, {"entries": [], "nextPageToken": "same"},
                            {"entries": [], "nextPageToken": "same"}])
        self.assertTrue((self.root / "pages/page-1/response.bin").is_file())

    def test_page_bound_refuses_with_raw_response_retained(self):
        with self.assertRaises(ValueError):
            self.paginated([{}, {}, {"entries": [], "nextPageToken": "next"}], maximum=1)
        self.assertTrue((self.root / "pages/page-0/response.bin").is_file())

    def test_live_verifier_cannot_replay_disk_receipt_in_new_owner(self):
        supervisor = collector.Supervisor.__new__(collector.Supervisor)
        supervisor.parent = collector.pin_process(os.getpid())
        supervisor._observations = {}
        request, response, receipt, scope = b'{}', b'{"disposable":true}', b'{}', {"scope": "disposable"}
        self.assertIsNone(supervisor.verify("cloud_run_service", request, response, receipt, scope))
        key = ("cloud_run_service", collector.sha(request), collector.sha(response), collector.sha(receipt))
        supervisor._observations[key] = scope
        self.assertIsNotNone(supervisor.verify("cloud_run_service", request, response, receipt, scope))
        self.assertIsNone(supervisor.verify("cloud_run_service", request, b'changed', receipt, scope))
        other = collector.Supervisor.__new__(collector.Supervisor)
        other.parent = supervisor.parent
        other._observations = {}
        self.assertIsNone(other.verify("cloud_run_service", request, response, receipt, scope))

    def test_inherited_opaque_fd_reaches_actual_child_without_retention(self):
        # Execute the actual child parser in a local subprocess. Only its HTTPS
        # exchange and immutable trust lookup are replaced by disposable seams.
        token_path = self.root / "disposable-input"
        token_path.write_bytes(b"disposable.not-a-credential")
        token_path.chmod(0o600)
        fd = os.open(token_path, os.O_RDONLY | os.O_NOFOLLOW)
        configuration = {"operation": "cloud_run_service",
            "request": json.dumps({"name": self.policy["serviceName"]}),
            "scope": {"serviceName": self.policy["serviceName"]}, "trust": {},
            "deadline": {}, "maximum": 1024}
        read_fd, write_fd = os.pipe()
        os.write(write_fd, json.dumps(configuration).encode())
        os.close(write_fd)
        child_code = """import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location('actual_child', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module.immutable = lambda reference: pathlib.Path('disposable-trust')
def exchange(host, path, method, body, token, trust, deadline, maximum):
    assert token == 'disposable.not-a-credential'
    assert method == 'GET' and body == b''
    return b'{"disposable":true}', {'eof': True}
module.https_read = exchange
module.child_main(int(sys.argv[2]), int(sys.argv[3]))
"""
        try:
            result = subprocess.run([sys.executable, "-B", "-E", "-c", child_code,
                str(ROOT / "hosted_collect.py"), str(read_fd), str(fd)],
                pass_fds=(read_fd, fd), capture_output=True, timeout=10, check=False)
        finally:
            os.close(read_fd)
            os.close(fd)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(token_path.read_bytes(), result.stdout + result.stderr)
        size = int.from_bytes(result.stdout[:4], "big")
        self.assertEqual(result.stdout[4 + size:], b'{"disposable":true}')

    def test_derived_inventory_sidecar_uses_same_live_selection(self):
        references = {"selection": {"runtime": RUNTIME,
            "authSidecar": {"file": "original", "sha256": "0" * 64, "byteSize": "1"},
            "nativeInventory": {"policy": {"file": "policy"},
                "sidecar": {"file": "original", "sha256": "0" * 64, "byteSize": "1"}}},
            "original": {"nativeProcess": None}}
        observed = []
        supervisor = mock.Mock()
        supervisor.failures.return_value = []
        readers = {"fields": collector.closed, "closed_json": collector.closed_json,
            "read_ref": lambda reference, maximum: json.dumps(references[reference["file"]]).encode(),
            "hosted_collector": lambda: vars(collector),
            "start_hosted_supervision": lambda *_: supervisor,
            "hosted_custody": lambda: self.custody}
        adapter = {"READERS": readers, "assess": lambda selection: observed.append(selection) or {"hostedAcceptance": "incomplete"}}
        package = {"runtime": RUNTIME, "hostedCollectorTools": {"python": {}, "collector": {}, "trust": {}}}
        plan = {"version": 1, "runtime": RUNTIME, "originalCutoff": {}, "cloudRun": self.policy,
            "assessmentSelection": {"file": "selection"}, "outputDirectory": str(self.root / "output")}
        with mock.patch.dict(qualification, PACKAGE=package, installed_assessment=lambda: adapter,
                original_deadline=lambda _: {"monotonic": float("inf"), "unix": float("inf")},
                collect_cloud_run=lambda *_: {"pages": [], "scope": "disposable"}):
            result = qualification["assess_live"](plan, 7)
        self.assertEqual(result["hostedAcceptance"], "incomplete")
        self.assertEqual(observed[0]["nativeInventory"]["sidecar"], observed[0]["authSidecar"])
        self.assertEqual(references["selection"]["authSidecar"]["file"], "original")
        self.assertEqual(json.loads(Path(observed[0]["authSidecar"]["file"]).read_bytes())["nativeLog"]["format"], "cloud_run")

    def sender_rows(self, groups):
        reader = {"hosted_messages": lambda _: {"messages": groups}, "closed_json": collector.closed_json}
        with mock.patch.dict(assessment, READERS=reader,
                parsed=lambda _: {"firstUnixMicros": "100", "lastUnixMicros": "200"}):
            return assessment["execute_records"]({"nativeProcess": None,
                "nativeLog": {"format": "cloud_run", "selection": {}}})

    def execute_event(self, call="1" * 32):
        return {"version": 1, "invocationId": "2" * 32, "transportCallId": call,
            "attempt": 1, "planId": "3" * 32, "operation": "head_object",
            "endpointScheme": "https", "offeredRequestSha256": "0" * 64,
            "offeredRequestBytes": "1", "replyStatus": 200,
            "exposedReplySha256": collector.sha(b""), "exposedReplyBytes": "0",
            "replyEof": True, "unreadResponse": False, "outcome": "typed_result_checked",
            "elapsedMicros": "1", "observedAtUnixMicros": "150", "replyMacAuthentication": None}

    def test_hosted_execute_preserves_instance_and_actual_event_without_process(self):
        value = self.execute_event()
        message = "[INFO] message=storage_work_attempt_observed " + json.dumps(value)
        rows = self.sender_rows({"instance-a": [(message, "150")]})
        self.assertEqual(rows["attempts"][0]["hostedInstanceId"], "instance-a")
        self.assertEqual(rows["attempts"][0]["value"], value)
        self.assertIsNone(rows["attempts"][0]["value"]["replyMacAuthentication"])

    def test_duplicate_execute_across_instances_and_expired_event_refuse(self):
        value = self.execute_event()
        message = "[INFO] message=storage_work_attempt_observed " + json.dumps(value)
        with self.assertRaises(ValueError):
            self.sender_rows({"instance-a": [(message, "150")], "instance-b": [(message, "150")]})
        value["observedAtUnixMicros"] = "201"
        with self.assertRaises(ValueError):
            self.sender_rows({"instance-a": [("[INFO] message=storage_work_attempt_observed " + json.dumps(value), "150")]})

    def test_missing_hosted_messages_stays_empty(self):
        rows = self.sender_rows(None)
        self.assertTrue(all(not values for values in rows.values()))

    def test_direct_sender_partial_join_preserves_unknowns_and_rejects_duplicates(self):
        constructor = assessment["direct_constructor_sha256"]()
        event = {"version": 1, "state": "offered",
            "route": "/_internal/storage/direct-upload-authority",
            "transportCallId": "4" * 32, "constructorSourceSha256": constructor,
            "nonceSha256": "0" * 64, "offeredRequestSha256": "1" * 64,
            "offeredRequestBytes": "1", "endpointScheme": "https", "replyStatus": None,
            "exposedReplySha256": collector.sha(b""), "exposedReplyBytes": "0",
            "replyEof": False, "outcome": "offered", "observedAtUnixMicros": "150",
            "replyMacAuthentication": None, "finalSqlAuthority": None}
        message = "[INFO] message=direct_control_sender_observed " + json.dumps(event)
        rows = self.sender_rows({"instance-a": [(message, "150")]})
        self.assertEqual(rows["directOffered"][0]["value"], event)
        self.assertEqual(rows["directOffered"][0]["hostedInstanceId"], "instance-a")
        self.assertEqual(rows["directTerminal"], [])
        with self.assertRaises(ValueError):
            self.sender_rows({"instance-a": [(message, "150")],
                              "instance-b": [(message, "150")]})

    def test_different_inventory_sidecar_refuses_before_output_or_collection(self):
        selection = {"runtime": RUNTIME, "authSidecar": {"file": "original"},
                     "nativeInventory": {"sidecar": {"file": "different"}}}
        readers = {"fields": collector.closed, "closed_json": collector.closed_json,
            "read_ref": lambda reference, maximum: json.dumps(
                selection if reference["file"] == "selection" else {"nativeProcess": None}).encode()}
        plan = {"version": 1, "runtime": RUNTIME, "originalCutoff": {}, "cloudRun": self.policy,
            "assessmentSelection": {"file": "selection"}, "outputDirectory": str(self.root / "output")}
        with mock.patch.dict(qualification, installed_assessment=lambda: {"READERS": readers},
                original_deadline=lambda _: {}):
            with self.assertRaises(ValueError):
                qualification["assess_live"](plan, 7)
        self.assertFalse((self.root / "output").exists())

    def test_actual_installer_pins_canonical_python_and_trust_files(self):
        # Disposable source/codec placeholders exercise the installer, not a
        # compiled codec or a registered helper package.
        installer = source_functions("install.py", set(), {})
        prepared = self.root / "prepared"
        prepared.mkdir()
        (prepared / "selected-build-inputs.json").write_text(json.dumps({
            "runtimeProvenance": {**RUNTIME, "nativeExecutableSha256": "0" * 64,
                "workerSourceDigest": "1" * 64, "sourceArchiveSha256": "2" * 64},
            "runtimeSource": str(RUNTIME_SOURCE),
            "sourceTree": "disposable-tree", "producerSha256": {}, "clientExecutable": None}))
        cargo = prepared / "tests/fleet/storage-body-codec"
        (cargo / "src/native").mkdir(parents=True)
        (cargo / "src/native/extraction.json").write_text("{}")
        for name in ("Cargo.toml", "Cargo.lock"):
            (cargo / name).write_text("disposable installer fixture")

        tool_source = self.root / "helper-source"
        library_source = tool_source / "tests/fleet/observation-tools"
        (library_source / "fixtures").mkdir(parents=True)
        # The real installer chooses its closed asset list. Its copy seam writes
        # only disposable placeholders, avoiding any old package installation.
        def fixture_copy(source, destination):
            Path(destination).write_text("disposable source asset")

        codec = self.root / "codec"
        (codec / "bin").mkdir(parents=True)
        (codec / "bin/aos-storage-body-codec").write_bytes(b"disposable codec")
        trust = self.root / "disposable-trust"
        trust.write_bytes(b"disposable trust input")
        trust_alias = self.root / "trust-alias"
        trust_alias.symlink_to(trust)
        python_alias = Path(sys.executable).parent / "python3"
        output = self.root / "installed-placeholder"
        with mock.patch.object(installer["shutil"], "copyfile", side_effect=fixture_copy):
            installer["install"](prepared, tool_source, codec, output,
                                  str(python_alias), "disposable-shell", str(trust_alias))

        context = json.loads((output / "libexec/aos-observation-tools/package-context.json").read_bytes())
        tools = context["hostedCollectorTools"]
        self.assertEqual(tools["python"]["file"], str(python_alias.resolve(strict=True)))
        self.assertEqual(tools["trust"]["file"], str(trust))
        package = source_functions("package_context.py", set(), {})
        raw = package["installed_bytes"](Path(tools["python"]["file"]))
        self.assertEqual(hashlib.sha256(raw).hexdigest(), tools["python"]["sha256"])


if __name__ == "__main__":
    unittest.main()
