"""Controlled adapter gates; no fleet/cache/provider runtime acceptance."""

import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


sys.dont_write_bytecode = True
specification = importlib.util.spec_from_file_location("read_window", Path(__file__).with_name("_hub-direct-read-window.py"))
window = importlib.util.module_from_spec(specification)
specification.loader.exec_module(window)


class ReadWindowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.body = b"retained actual reference bytes"
        digest = window._sha(self.body)
        self.pin = {"pid": 1, "ownerUid": 0, "startTicks": "100", "executableSha256": "a" * 64}
        self.context = {"version": 1, "registrySlug": "managed-test/containers",
            "sourceCommit": "b" * 64, "packageName": "aos", "privateRegistrySlug": "managed-test/private-docs",
            "origins": {"hybrid": "https://localhost:4643", "native_only": "https://native.example.test:8453",
                "worker_only": "https://worker.example.test:8453"},
            "objects": {kind: {"relativePath": "selected/" + kind, "file": str(self.root / kind),
                "sha256": digest, "byteSize": len(self.body)} for kind in window.OBJECTS},
            "credentials": {"bearerHeaderFile": str(self.root / "bearer"), "cookieHeaderFile": str(self.root / "cookie")},
            "cache": {"socketFile": str(self.root / "runner.socket"), "identity": {"runnerPid": 1,
                "runnerStartTicks": "100", "configurationSha256": "c" * 64, "workerName": "selected-worker",
                "cacheObserverSha256": "d" * 64}}, "curlArgv": ["/nix/store/" + "1" * 32 + "-curl/bin/curl"],
            "evidenceRoot": str(self.root / "captures"),
            "processes": {role: {"machine": machine, "pin": self.pin.copy()}
                for role, machine in window.PROCESS_MACHINES.items()},
            "workerConfigurationFile": str(self.root / "configuration.private.json"),
            "workerConfigurationSha256": "c" * 64,
            "parityModuleFile": "/nix/store/" + "2" * 32 + "-fixtures/read.py", "parityModuleSha256": "e" * 64,
            "indexModuleFile": "/nix/store/" + "2" * 32 + "-fixtures/index.py", "indexModuleSha256": "f" * 64}

    def tearDown(self):
        self.temporary.cleanup()

    def test_fixed_context_refuses_incomplete_relabelled_and_oversized_inputs(self):
        window._context(self.context)
        cases = []
        value = copy.deepcopy(self.context)
        del value["objects"]["container"]
        cases.append(value)
        value = copy.deepcopy(self.context)
        value["sourceCommit"] = "b" * 40
        cases.append(value)
        value = copy.deepcopy(self.context)
        value["objects"]["git"]["byteSize"] = window.MAX_OBJECT_BYTES + 1
        cases.append(value)
        value = copy.deepcopy(self.context)
        value["processes"]["native_only"]["machine"] = "worker"
        cases.append(value)
        value = copy.deepcopy(self.context)
        value["cache"]["identity"]["runnerStartTicks"] = "101"
        cases.append(value)
        value = copy.deepcopy(self.context)
        value["privateRegistrySlug"] = value["registrySlug"]
        cases.append(value)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                window._context(value)

    def test_reference_transfer_checks_bytes_and_cannot_overwrite(self):
        root = self.root / "transfer"
        root.mkdir(mode=0o700)
        (root / "inputs").mkdir(mode=0o700)
        selected = {"action": "copy", "values": {"name": "git", "root": str(root),
            "bodyBase64": base64.b64encode(self.body).decode(), "sha256": window._sha(self.body),
            "byteSize": len(self.body)}}
        result = window._guest_action(selected)
        self.assertEqual(result["sha256"], window._sha(self.body))
        self.assertEqual((root / "inputs/git").read_bytes(), self.body)
        self.assertEqual((root / "inputs/git").stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError):
            window._guest_action(selected)
        selected["values"]["name"] = "package"
        selected["values"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            window._guest_action(selected)
        self.assertFalse((root / "inputs/package").exists())

    def test_reference_source_refuses_wrong_hash_and_links(self):
        file = self.root / "original"
        file.write_bytes(self.body)
        selected = {"action": "source", "values": {"file": str(file), "maximum": window.MAX_OBJECT_BYTES,
            "private": False, "sha256": window._sha(self.body), "byteSize": len(self.body)}}
        self.assertEqual(base64.b64decode(window._guest_action(selected)["bodyBase64"]), self.body)
        file.write_bytes(b"changed but not silently accepted")
        with self.assertRaises(ValueError):
            window._guest_action(selected)
        link = self.root / "link"
        link.symlink_to(file)
        with self.assertRaises(OSError):
            window._file(link, window.MAX_OBJECT_BYTES)

    def test_credentials_need_private_custody_and_exact_header(self):
        file = self.root / "credential"
        file.write_bytes(b"Authorization: Bearer controlled-secret\n")
        selected = {"action": "credential", "values": {"file": str(file), "prefix": "Authorization: Bearer "}}
        file.chmod(0o644)
        with self.assertRaises(ValueError):
            window._guest_action(selected)
        file.chmod(0o600)
        self.assertEqual(window._guest_action(selected)["byteSize"], file.stat().st_size)
        file.write_bytes(b"Authorization: Bearer first\nCookie: second")
        with self.assertRaises(ValueError):
            window._guest_action(selected)

    def test_actual_process_pin_refuses_reused_lifetime_or_executable(self):
        directory = Path("/proc") / str(os.getpid())
        with (directory / "exe").open("rb") as executable:
            digest = hashlib.file_digest(executable, "sha256").hexdigest()
        pin = {"pid": os.getpid(), "ownerUid": os.getuid(), "executableSha256": digest,
            "startTicks": (directory / "stat").read_text().rpartition(") ")[2].split()[19]}
        actual = window._process(pin)
        self.assertEqual(actual["startTicks"], pin["startTicks"])
        for field, changed in (("startTicks", "1"), ("executableSha256", "0" * 64), ("ownerUid", os.getuid() + 1)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                window._process({**pin, field: changed})

    def test_initial_configuration_binds_document_and_observer(self):
        file = Path(self.context["workerConfigurationFile"])
        observer = self.root / "observer.cjs"
        observer.write_bytes(b"controlled observer source")
        observer_store = "/nix/store/" + "3" * 32 + "-fixtures/observer.cjs"
        value = {"name": "selected-worker", "publicDocumentCacheObserverPath": observer_store,
            "publicDocumentCacheCase": {"assetVersion": "1234abcd", "registrySlug": self.context["registrySlug"],
                "documentSha256": self.context["objects"]["document"]["sha256"], "bodyBytes": len(self.body)}}
        original = window._file

        def selected_file(path, *args, **kwargs):
            return original(observer if path == observer_store else path, *args, **kwargs)

        self.context["cache"]["identity"]["cacheObserverSha256"] = window._sha(observer.read_bytes())
        with patch.object(window, "_file", side_effect=selected_file):
            for field, changed in ((None, None), ("assetVersion", "invalid"), ("documentSha256", "0" * 64),
                    ("registrySlug", "managed-test/other"), ("bodyBytes", len(self.body) + 1)):
                selected = copy.deepcopy(value)
                if field:
                    selected["publicDocumentCacheCase"][field] = changed
                file.write_bytes(json.dumps(selected).encode())
                file.chmod(0o600)
                self.context["workerConfigurationSha256"] = window._sha(file.read_bytes())
                if field is None:
                    window._configuration(self.context)
                else:
                    with self.assertRaises(ValueError):
                        window._configuration(self.context)

    def test_capture_inventory_refuses_total_overflow_and_links(self):
        window._private_write(self.root / "one", b"a" * 20)
        window._private_write(self.root / "two", b"b" * 20)
        with patch.object(window, "MAX_CAPTURE_BYTES", 39), self.assertRaises(ValueError):
            window._capture_inventory(self.root)
        with patch.object(window, "MAX_CAPTURE_FILES", 1), self.assertRaises(ValueError):
            window._capture_inventory(self.root)
        (self.root / "link").symlink_to(self.root / "one")
        with self.assertRaises(OSError):
            window._capture_inventory(self.root)

    def test_guest_order_starts_cache_cold_then_fixed_reads(self):
        root = Path(self.context["evidenceRoot"])
        root.mkdir(mode=0o700)
        events = []

        class FixedParity:
            def select_direct_read_corpus(inner, selection):
                events.append("selection")
                self.assertEqual(set(selection["objects"]), window.OBJECTS)

            def DirectReadHttp(inner, argv, destination):
                self.assertEqual(argv, self.context["curlArgv"])
                events.append("transport")
                return object()

            def run_direct_document_cache(inner, *args):
                events.append("cache")
                return {"controlled": "cache"}

            def run_direct_read_parity(inner, *args):
                events.append("objects")
                return {"controlled": "objects"}

            def run_direct_semantic_read_parity(inner, *args):
                events.append("semantic")
                return {"controlled": "semantic"}

        with patch.object(window, "_module", return_value=FixedParity()), \
                patch.object(window, "_process", return_value=self.pin), \
                patch.object(window, "_configuration", return_value={"sha256": "c" * 64}):
            actual = window._run_guest_window(self.context)
        self.assertEqual(events, ["selection", "transport", "cache", "objects", "semantic"])
        self.assertIsNone(actual["result"]["nativeBulkBytes"])
        self.assertTrue((root / "result.private.json").exists())

    def test_failed_http_keeps_unresolved_original_and_no_positive(self):
        root = Path(self.context["evidenceRoot"])
        root.mkdir(mode=0o700)

        class FixedParity:
            def select_direct_read_corpus(inner, _):
                return None

            def DirectReadHttp(inner, *_):
                return object()

            def run_direct_document_cache(inner, *_):
                raise RuntimeError("controlled unknown HTTP outcome")

        with patch.object(window, "_module", return_value=FixedParity()), \
                patch.object(window, "_process", return_value=self.pin), \
                patch.object(window, "_configuration", return_value={}), self.assertRaises(RuntimeError):
            window._run_guest_window(self.context)
        self.assertFalse((root / "result.private.json").exists())
        failure = json.loads((root / "failure.private.json").read_bytes())
        self.assertEqual(failure["outcome"], "unresolved")
        self.assertIsNone(failure["nativeBulkBytes"])

    def test_controller_queries_all_actual_readers_before_guest_dispatch(self):
        events, retained = [], []
        machines = {name: object() for name in ("client", "native", "worker")}

        class Projector:
            def registry_index_observations(inner, query, slug):
                self.assertEqual(slug, self.context["registrySlug"])
                return query("SELECT controlled_actual_projection")

        class Parity:
            def assert_direct_full_index_parity(inner, snapshots, commit):
                self.assertEqual(commit, self.context["sourceCommit"])
                self.assertEqual(set(snapshots), window.MODES)
                events.append("index-compare")
                return {"controlled": "comparison"}

        def query(mode):
            def read(sql):
                self.assertEqual(sql, "SELECT controlled_actual_projection")
                events.append("query-" + mode)
                return [["controlled"]]
            return read

        def guest(machine, python, action, values, **kwargs):
            events.append(action)
            if action == "process":
                return self.pin
            if action in {"source", "credential"}:
                return {"bodyBase64": base64.b64encode(self.body).decode(),
                    "sha256": window._sha(self.body), "byteSize": len(self.body)}
            if action == "run":
                self.assertIs(machine, machines["worker"])
                return {"result": {"nativeBulkBytes": None}, "captures": {"files": []}}
            return {}

        with patch.object(window, "_module", side_effect=[Projector(), Parity()]), \
                patch.object(window, "_guest", side_effect=guest):
            result = window.run_direct_read_window(machines["client"], machines["native"], machines["worker"],
                tools={"python": "selected-python"}, context=self.context,
                index_readers={mode: query(mode) for mode in window.MODES},
                retain=lambda name, value: retained.append(name))
        self.assertLess(events.index("index-compare"), events.index("prepare"))
        self.assertEqual(events.count("source"), 5)
        self.assertEqual(events.count("credential"), 2)
        self.assertEqual(events.count("run"), 1)
        self.assertIsNone(result["nativeBulkBytes"])
        self.assertEqual(retained, ["read-window-indexes.private.json", "actual-called-read-window.json"])

    def test_module_rejects_noninstalled_source_and_duplicate_json(self):
        with self.assertRaises(ValueError):
            window._module(str(self.root / "arbitrary.py"), "0" * 64, "arbitrary")
        for value in (b'{"version":1,"version":1}', b'{"value":NaN}'):
            with self.assertRaises(ValueError):
                window._decode(value)

    def test_actual_guest_program_compiles_and_max_reference_fits_agent_frame(self):
        observed = []

        class Agent:
            def request(inner, command, timeout):
                observed.append(len(command))
                text = command.decode()
                source = text.split("READ_WINDOW_PROGRAM'\n", 1)[1].rsplit("READ_WINDOW_PROGRAM\n", 1)[0]
                compile(source, "controlled-actual-guest-program", "exec")
                return 0, b'{}', b''

        transfer = {"root": str(self.root), "name": "git", "byteSize": window.MAX_OBJECT_BYTES,
            "sha256": "a" * 64, "bodyBase64": base64.b64encode(b"a" * window.MAX_OBJECT_BYTES).decode()}
        result = window._guest(SimpleNamespace(agent=Agent()), "/nix/store/" + "1" * 32 + "-python/bin/python3",
            "copy", transfer)
        self.assertEqual(result, {})
        self.assertLess(observed[0], 8 * 1024 * 1024)

    def companion(self):
        run = "1" * 32
        layout = self.root / "layout"
        (layout / "blobs/sha256").mkdir(parents=True)
        (layout / "index.json").write_bytes(b'{"manifests":[]}')
        (layout / "oci-layout").write_bytes(b'{"imageLayoutVersion":"1.0.0"}')
        index = b'{"schemaVersion":2,"manifests":[],"controlled":true}'
        digest = window._sha(index)
        (layout / "blobs/sha256" / digest).write_bytes(index)
        for name in ("release", "signature_input"):
            (self.root / name).write_bytes(b'{"controlled":"' + name.encode() + b'"}')
        parent = self.root / "companion"
        parent.mkdir(mode=0o700)
        return {"version": 1, "mode": "native_only", "origin": "https://native.example.test:8453",
            "registrySlug": "managed-" + run + "/containers", "coordinates": {"runId": run,
                "workerOrigin": "https://native.example.test:8453", "clientRoot": str(parent)},
            "source": {"sourceCommit": "b" * 64, "surfaceRoot": str(self.root / "surface"),
                "finalized": {"layout": str(layout), "release": str(self.root / "release"),
                    "signature_input": str(self.root / "signature_input"), "index_digest": "sha256:" + digest}}}

    def companion_tools(self):
        root = "/nix/store/" + "4" * 32 + "-selected-tools/bin"
        return {"aos": root + "/aos", "git": root + "/git", "opensshBin": root,
            "nixBin": root, "python": root + "/python3"}

    def test_companion_cli_retains_original_and_explicit_authority_and_unknown(self):
        selection, tools = self.companion(), self.companion_tools()
        home = os.environ.get("HOME")
        calls = []

        def execute(argv, **kwargs):
            calls.append(argv)
            self.assertEqual(kwargs["env"].get("HOME"), home)
            for flag in ("--hub", "--registry-origin"):
                self.assertEqual(argv[argv.index(flag) + 1], selection["origin"])
            self.assertEqual(argv[argv.index("--token") + 1], "controlled-token")
            self.assertEqual(argv[argv.index("--registry-token") + 1], "controlled-token")
            kwargs["stdout"].write(json.dumps({"state": "staged", "tag_updated": False,
                "index_digest": selection["source"]["finalized"]["index_digest"]}).encode())
            return SimpleNamespace(returncode=0)

        with patch.object(window.subprocess, "run", side_effect=execute):
            result = window._companion_step({"selection": selection, "tools": tools,
                "step": "stage", "token": "controlled-token"})
        self.assertEqual(result["result"]["state"], "staged")
        self.assertIn("--stage-only", calls[0])
        retained = Path(result["originalRoot"])
        self.assertEqual(json.loads((retained / "selection.private.json").read_bytes()), selection)
        with self.assertRaises(FileExistsError):
            window._companion_step({"selection": selection, "tools": tools,
                "step": "stage", "token": "controlled-token"})
        (self.root / "release").write_bytes(b"changed")
        with patch.object(window.subprocess, "run") as dispatch, self.assertRaises(ValueError):
            window._companion_step({"selection": selection, "tools": tools,
                "step": "upload", "token": "controlled-token"})
        dispatch.assert_not_called()

    def test_companion_timeout_retains_unknown_without_positive_or_replay(self):
        selection, tools = self.companion(), self.companion_tools()
        with patch.object(window.subprocess, "run", side_effect=window.subprocess.TimeoutExpired("controlled", 1100)), \
                self.assertRaises(window.subprocess.TimeoutExpired):
            window._companion_step({"selection": selection, "tools": tools,
                "step": "stage", "token": "controlled-token"})
        root = Path(selection["coordinates"]["clientRoot"]) / "signed-publication"
        terminal = json.loads((root / "stage.terminal.json").read_bytes())
        self.assertEqual(terminal["outcome"], "unknown")
        self.assertIsNone(terminal["providerSettlement"])
        self.assertFalse((root / "stage.result.private.json").exists())
        with self.assertRaises(FileExistsError):
            window._companion_step({"selection": selection, "tools": tools,
                "step": "stage", "token": "controlled-token"})

    def test_companion_setup_stages_then_same_surface_index_and_final_publish(self):
        selection, tools = self.companion(), self.companion_tools()
        events, retained = [], []

        class Controls:
            def call(inner, service, method, payload):
                self.assertEqual((service, method), ("RegistryService", "GetRegistry"))
                self.assertEqual(payload, {"slug": selection["registrySlug"]})
                events.append("current-index")
                return {"registry": {"indexState": "fresh", "lastIndexedCommit": selection["source"]["sourceCommit"]}}

        def setup(controls, actual):
            self.assertEqual(actual, selection)
            events.append("setup")
            return {"registry": {"slug": selection["registrySlug"]}}

        def route(controls, registry, actual):
            self.assertEqual(actual, selection)
            events.append("route")
            return {"route": {"observation": {"state": "healthy"}, "canonicalRenderedUrl": selection["origin"]}}

        def guest(machine, python, action, values, **kwargs):
            self.assertEqual(action, "companion-step")
            self.assertEqual(values["selection"], selection)
            events.append(values["step"])
            return {"controlled": values["step"]}

        with patch.object(window, "_guest", side_effect=guest):
            result = window.setup_selected_companion(object(), tools=tools, selection=selection,
                controls=Controls(), setup_registry=setup, configure_route=route,
                refresh_token=lambda: "controlled-token", retain=lambda name, value: retained.append(name))
        self.assertEqual(events, ["setup", "route", "stage", "upload", "current-index", "publish"])
        self.assertEqual(set(result["phases"]), {"stage", "upload", "publish"})
        self.assertEqual(result["sourceCommit"], selection["source"]["sourceCommit"])
        self.assertEqual(len(retained), 1)

    def test_companion_wrong_route_refuses_before_any_body_producer(self):
        selection = self.companion()
        with patch.object(window, "_guest") as dispatch, self.assertRaises(ValueError):
            window.setup_selected_companion(object(), tools=self.companion_tools(), selection=selection,
                controls=object(), setup_registry=lambda *args: {"registry": {"slug": selection["registrySlug"]}},
                configure_route=lambda *args: {"route": {"observation": {"state": "healthy"},
                    "canonicalRenderedUrl": "https://different.example.test"}},
                refresh_token=lambda: "controlled-token", retain=lambda *args: None)
        dispatch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
