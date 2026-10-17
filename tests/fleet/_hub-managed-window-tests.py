"""Check Managed controller ordering and refusals without runtime authority."""

import ast
import importlib.util
import json
from pathlib import Path
import textwrap
import unittest
from unittest.mock import patch


HERE = Path(__file__).parent


def load(name, filename):
    specification = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


pair = load("window_pair", "_hub-managed-pair.py")
route = load("window_route", "_hub-managed-route.py")
control = load("window_control", "_hub-managed-control.py")
window = load("managed_window", "_hub-managed-window.py")
held = load("managed_held_index", "_hub-direct-stale-index-setup.py")
for module in (route, control, window):
    module.require_managed_pair = pair.require_managed_pair


class RouteControls:
    """Retain fixed typed model calls; this supplies no runtime observation."""

    def __init__(self, *, generation="1", origin="https://localhost:4643"):
        self.generation = generation
        self.origin = origin
        self.observations = []
        self.calls = []

    def reviewed(self, service, plan, apply, request, label):
        self.calls.append((service, plan, apply, request))
        if apply == "CreateDomain":
            return {"domain": {"stableId": "domain:localhost"}}
        if apply == "CreateEndpoint":
            return {"endpoint": {"stableId": request["stableId"], "desiredGeneration": self.generation,
                "resourceVersion": "1", "desired": request["revision"]}}
        if apply in {"CreateRoute", "EnableRoute"}:
            return {"route": {"resourceVersion": "1"}}
        if apply == "IssueAccessToken":
            return {"secret": "controlled-only"}
        return {}

    def call(self, service, method, request):
        self.calls.append((service, method, request))
        if method == "GetOrganization":
            return {"organization": {"slug": request["slug"], "ownerScopeKey": "org:controlled"}}
        if method == "ReportEndpoint":
            return {"endpoint": {"stableId": request["stableId"], "observed": request["observation"]}}
        if method == "CompleteRouteProbe":
            return {"operation": {"operationId": "controlled-operation"}}
        if method == "GetRoute":
            return {"route": {"observation": {"state": "healthy"}, "canonicalRenderedUrl": self.origin}}
        raise AssertionError("Unexpected model call")

    def wait_operation(self, identifier, terminal):
        self.calls.append(("wait", identifier, terminal))
        return {"state": "succeeded"}


class ManagedWindowTests(unittest.TestCase):
    def setUp(self):
        self.coordinates = pair.managed_pair_coordinates("a" * 32)

    def configure(self, original):
        controller = RouteControls()
        route.private_guest_command = object()
        route.DirectBootstrapControls = lambda *args, **kwargs: controller
        route.managed_controller_token = lambda *args: "model-controller"
        route.observe_managed_route_listener = lambda *args: {"status": 401, "scope": "controlled model"}
        result = route.configure_managed_distribution(object(), object(), {
            "curl": "curl", "python": "python", "issuerCertificate": "/nix/store/tls/value"},
            {"coordinates": self.coordinates, "probePublicKey": "independent-probe"}, {}, original,
            {"registry": {"slug": "managed-" + "a" * 32 + "/containers"},
             "placement": {"name": "managed-gc"}})
        return result, controller

    def test_normal_plans_layer7_generation_and_exact_root_route(self):
        original = RouteControls()
        result, controller = self.configure(original)
        create = next(call for call in original.calls if len(call) == 4 and call[2] == "CreateEndpoint")
        self.assertEqual(create[3]["revision"]["ingressKind"], "ENDPOINT_INGRESS_KIND_LAYER7")
        self.assertEqual(create[3]["effectivePort"], 4643)
        self.assertEqual(create[3]["host"], {"domainId": "domain:localhost"})
        reports = [call for call in controller.calls if call[1] == "ReportEndpoint"]
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0][2]["observation"]["observedGeneration"], "1")
        self.assertEqual(original.calls[-2][0], "wait")
        self.assertIsNone(result["domainVerification"])
        self.assertNotIn("VerifyDomain", str(original.calls))

    def test_uninstalled_endpoint_generation_refuses_before_report_or_route(self):
        original = RouteControls(generation="2")
        with self.assertRaisesRegex(ValueError, "probe generation"):
            self.configure(original)
        self.assertFalse(any(len(call) == 4 and call[2] == "CreateRoute" for call in original.calls))

    def test_different_current_route_origin_refuses(self):
        original = RouteControls(origin="https://localhost:9999")
        with self.assertRaisesRegex(ValueError, "selected root origin"):
            self.configure(original)

    def test_snapshot_bound_and_foreign_control_refuse_before_transport(self):
        valid = {"version": 1, "kind": "managed-gc-snapshot", "keys": ["managed/key"], "claimIds": ["claim"]}
        control.require_managed_runner_request(valid)
        invalid = [dict(valid, keys=["same", "same"]), dict(valid, keys=[str(i) for i in range(33)]),
            dict(valid, extra=True), dict(valid, kind="oci-sdk-anchor")]
        for request in invalid:
            with self.subTest(request=request), self.assertRaises(ValueError):
                control.require_managed_runner_request(request)

    def test_replay_requires_exact_prior_receipt_commitment_shape(self):
        valid = {"version": 1, "kind": "managed-gc-positive-replay", "key": "managed/key",
            "claimId": "claim:actual", "receiptSha256": "b" * 64}
        control.require_managed_runner_request(valid)
        for changed in (dict(valid, receiptSha256=""), dict(valid, claimId="bad\nclaim"), dict(valid, extra=1)):
            with self.assertRaises(ValueError):
                control.require_managed_runner_request(changed)

    def test_main_requires_separate_database_before_any_effect(self):
        with self.assertRaisesRegex(ValueError, "independent PostgreSQL"):
            window.run_managed_pair_window(None, None, None, None, {"separateDatabase": False}, "db", "cfg", {})

    def test_cleanup_listener_refusal_prevents_proxy_or_pair_startup(self):
        selected = {"coordinates": self.coordinates, "cleanupLoss": {
            "arguments": ["/nix/store/python/bin/python3", "/nix/store/listener/value"],
            "executableSha256": "a" * 64}}
        launched = []

        def launch(machine, tools, root, label, arguments, environment, **options):
            launched.append(label)
            return {"executableSha256": "a" * 64}

        with patch.object(pair, "launch_managed_process", side_effect=launch), \
                patch.object(pair, "await_managed_cleanup_loss", create=True,
                    side_effect=ValueError("actual listener failed to bind")):
            with self.assertRaisesRegex(ValueError, "failed to bind"):
                pair.start_managed_pair(None, None, None,
                    {"socat": "/nix/store/socat/bin/socat"}, selected,
                    "10.0.0.2", "10.0.0.3", {})
        self.assertEqual(launched, ["worker-forward", "cleanup-loss"])

    def test_changed_document_refuses_before_asset_selection_or_pair_observation(self):
        digest = "a" * 64
        source = {"document": {"file": "/private/document", "sha256": digest, "byteSize": 4096,
            "relativePath": "-/api/v1/documentation/sha256:" + digest, "identity": {}}}
        with patch.object(window, "read_direct_guest_file", create=True, return_value=b"changed") as read, \
                patch.object(window, "direct_guest_python", create=True) as guest:
            with self.assertRaisesRegex(ValueError, "documentation changed"):
                window.managed_document_cache_selection(None, {"python": "selected-python"},
                    self.coordinates, source)
        read.assert_called_once()
        guest.assert_not_called()

    def test_module_requires_installed_source_path(self):
        with self.assertRaisesRegex(ValueError, "source-bound module"):
            window.managed_fixture_module(str(HERE / "_hub-managed-route.py"), "uninstalled")

    def test_managed_codec_rejects_another_runtime_before_pair_effects(self):
        selected = {"observerExecutable": {"path": "/private/decoder", "sha256": "a" * 64},
            "runtimeCodecRevision": "b" * 40,
            "runtimeProvenance": {"path": "/private/provenance", "sha256": "c" * 64}}
        provenance = {"version": 1, "runtimeCodecRevision": "b" * 40,
            "nativeExecutableSha256": "d" * 64, "workerSourceDigest": "e" * 64,
            "sourceArchiveSha256": "f" * 64, "codecSourceSha256": "0" * 64}
        artifacts = {"files": {"nativeHub": {"sha256": "d" * 64}}}
        with patch.object(window, "await_direct_review", create=True,
                return_value={"selection": selected}), \
                patch.object(window, "retain_direct_flow", create=True, return_value="a" * 64), \
                patch.object(window, "direct_selected_bytes", create=True,
                    side_effect=lambda *args: json.dumps(provenance).encode()), \
                patch.object(window, "_closed_review_json", create=True, side_effect=json.loads):
            actual = window.select_managed_storage_codec(artifacts, "e" * 64)
            self.assertEqual(actual["codecSelection"], selected)
            for field, wrong in (("nativeExecutableSha256", "1" * 64),
                    ("workerSourceDigest", "2" * 64), ("runtimeCodecRevision", "3" * 40)):
                original = provenance[field]
                provenance[field] = wrong
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, "current runtime tuple"):
                    window.select_managed_storage_codec(artifacts, "e" * 64)
                provenance[field] = original

    def test_held_index_sql_refuses_multiple_statements_before_transport(self):
        query = held.DirectStaleIndexSql(object(), {})
        with patch.object(held, "direct_guest_python", create=True) as transport:
            for value in ("DELETE FROM registry_index", "SELECT 1; SELECT 2",
                    "SELECT 1 -- comment", "SELECT /* comment */ 1", "SELECT " + "x" * 32768):
                with self.subTest(query=value[:32]), self.assertRaises(ValueError):
                    query(value)
            transport.assert_not_called()

    def test_embedded_route_and_control_guest_programs_compile(self):
        guests = []
        for filename in ("_hub-managed-route.py", "_hub-managed-control.py", "_hub-direct-stale-index-setup.py",
                "_hub-managed-window.py"):
            tree = ast.parse((HERE / filename).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "direct_guest_python":
                    guests.append(textwrap.dedent(node.args[2].value))
        self.assertEqual(len(guests), 7)
        for body in guests:
            compile(body, "managed-guest", "exec")
            self.assertNotIn("HOME=", body)
            self.assertNotIn("reconcile_endpoint", body)
            self.assertNotIn("reconcile_route", body)


if __name__ == "__main__":
    unittest.main()
