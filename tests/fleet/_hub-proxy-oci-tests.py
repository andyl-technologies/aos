"""Check that OCI fixture setup preserves the actual proxy deployment."""

import ast
import copy
import importlib.util
from pathlib import Path
import textwrap
import unittest
from unittest.mock import patch


HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location("proxy_oci", HERE / "_hub-proxy-oci.py")
proxy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy)


def require(condition, message):
    if not condition:
        raise ValueError(message)


proxy.require_managed_pair = require


class ProxyConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.original = {
            "scriptPath": "/nix/store/selected-dist/shim.mjs",
            "resourcePersistencePath": "/var/lib/hybrid-worker/state",
            "r2Buckets": {"REGISTRY_BUCKET": "old-namespace"},
            "durableObjects": {"HYBRID_OBJECT_GUARD": {"className": "HybridObjectGuard", "useSQLite": True}},
            "bindings": {"HUB_DEPLOYMENT_ID": "fleet-hybrid-v1",
                "HUB_HYBRID_ORIGIN_URL": "https://native.fleet.test:8443",
                "HUB_STORAGE_WORK_KEY": "existing-storage-role",
                "HUB_HYBRID_INGRESS_KEY": "existing-ingress-role"},
        }
        self.tools = {"shim": self.original["scriptPath"], "wasm": "/nix/store/selected-dist/index.wasm",
            "workerSourcePath": "/nix/store/selected-source", "workerd": "/nix/store/workerd/bin/workerd"}
        self.coordinates = {"runId": "a" * 32, "workerRoot": "/var/lib/selected-provider",
            "deploymentId": "fleet-hybrid-v1", "workerOrigin": "https://aos.fleet.test",
            "nativeOrigin": "https://native.fleet.test:8443", "namespaceId": "oci-sdk-qualification-" + "a" * 32}
        self.materials = {"registryKey": "source-derived-slot", "reviewerPublicKey": "b" * 64,
            "roles": {name: str(number) * 64 for number, name in enumerate((
                "HUB_DIRECT_UPLOAD_GUARD_KEY", "HUB_DIRECT_UPLOAD_CONFORMANCE_KEY", "HUB_DIRECT_UPLOAD_JOURNAL_KEY"), 1)},
            "clockPolicy": {"policy": {"uncertaintySeconds": "1"}, "commitment": "c" * 64}}

    def test_proxy_roles_and_persistence_survive_provider_setup(self):
        before = copy.deepcopy(self.original)

        actual = proxy.proxy_oci_configuration(self.original, self.tools, self.coordinates, self.materials)

        self.assertEqual(self.original, before)
        for field in ("HUB_STORAGE_WORK_KEY", "HUB_HYBRID_INGRESS_KEY", "HUB_HYBRID_ORIGIN_URL", "HUB_DEPLOYMENT_ID"):
            self.assertEqual(actual["bindings"][field], before["bindings"][field])
        self.assertEqual(actual["resourcePersistencePath"], before["resourcePersistencePath"])
        self.assertEqual(actual["bindings"]["HUB_DIRECT_UPLOAD_MANAGED_R2"], "false")
        self.assertEqual(actual["r2Buckets"]["REGISTRY_BUCKET"], self.coordinates["namespaceId"])
        self.assertNotIn("queueConsumers", actual)
        self.assertNotIn("HUB_DIRECT_UPLOAD_ACCEPTANCE", actual["kvNamespaces"])

    def test_changed_installed_script_deployment_or_origin_refuses(self):
        for field, value in (("deploymentId", "another-deployment"), ("nativeOrigin", "https://other.test")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                proxy.proxy_oci_configuration(self.original, self.tools,
                    {**self.coordinates, field: value}, self.materials)
        with self.assertRaises(ValueError):
            proxy.proxy_oci_configuration(self.original, {**self.tools, "shim": "/other/shim.mjs"},
                self.coordinates, self.materials)

    def test_embedded_guest_programs_compile(self):
        tree = ast.parse((HERE / "_hub-proxy-oci.py").read_text())
        programs = [node.args[2].value for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "direct_guest_python"]
        self.assertEqual(len(programs), 3)
        for program in programs:
            compile(textwrap.dedent(program), "proxy OCI guest action", "exec")

    def test_native_startup_precedes_process_and_provider_observations(self):
        native, worker = object(), object()
        tools = {"python": "python", "systemctl": "systemctl", "curl": "curl",
            "workerSourcePath": "/nix/store/source", "workerDistribution": "/nix/store/dist", "nixBin": "/nix/store/nix/bin"}
        prepared = {"coordinates": {"nativeOrigin": "https://native.fleet.test:8443", "workerRoot": "/private"}}
        events = []

        def command(*args, **kwargs):
            events.append("restart")

        def ready(*args, **kwargs):
            self.assertEqual(events, ["restart"])
            events.append("TLS")

        def guest(machine, *args, **kwargs):
            if machine is native:
                self.assertEqual(events, ["restart", "TLS"])
                events.append("Native")
                return '{"pid":123,"startTicks":"456","ownerUid":802}'
            return '{"files":{}}'

        def observe(*args, **kwargs):
            self.assertEqual(events, ["restart", "TLS", "Native"])
            events.append("provider")
            return {}

        with patch.object(proxy, "private_guest_command", command, create=True), \
                patch.object(proxy, "wait_fixture_tls_response", ready, create=True), \
                patch.object(proxy, "direct_guest_python", guest, create=True), \
                patch.object(proxy, "observe_managed_pair", observe, create=True), \
                patch.object(proxy, "prepare_managed_oci_candidate", return_value={}, create=True), \
                patch.object(proxy, "install_managed_oci_candidate", return_value={"installed": True}, create=True):
            result = proxy.qualify_proxy_oci(native, worker, tools, prepared, {"pid":789})

        self.assertEqual(result, {"installed": True})
        self.assertEqual(events, ["restart", "TLS", "Native", "provider"])


if __name__ == "__main__":
    unittest.main()
