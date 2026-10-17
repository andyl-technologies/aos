"""Check fresh pair configuration and the real control destination plumbing."""

import ast
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch


HERE = Path(__file__).parent


def load(name, leaf):
    spec = importlib.util.spec_from_file_location(name, HERE / leaf)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pair = load("managed_pair", "_hub-managed-pair.py")
controls = load("managed_controls", "_hub-direct-controls.py")


class PairTests(unittest.TestCase):
    def setUp(self):
        self.selected = {"runId": "a" * 32, "shim": "/nix/store/selected-dist/shim.mjs",
            "wasm": "/nix/store/selected-dist/index.wasm",
            "workerSourcePath": "/nix/store/selected-source",
            "workerd": "/nix/store/selected-workerd/bin/workerd",
            "managedGcObserver": "/nix/store/fixture/_hub-managed-gc-runner-observer.cjs",
            "managedCleanupInstaller": "/nix/store/fixture/_hub-managed-cleanup-install.cjs"}
        self.original = {"scriptPath": self.selected["shim"], "compatibilityDate": "2024-09-23",
            "certificatePath": "/nix/store/selected-tls/value",
            "privateKeyPath": "/nix/store/selected-key/value",
            "name": "old", "resourcePersistencePath": "/old/state",
            "r2Buckets": {"REGISTRY_BUCKET": "hybrid-fleet-r2"},
            "bindings": {"HUB_EXTERNAL_OBJECT_CONSUMER": "original-private-material"},
            "kvNamespaces": {"HUB_DIRECT_UPLOAD_ACCEPTANCE": "original-slot"}}
        self.roles = {name: str(index + 1) * 64
            for index, name in enumerate(pair.PRIVATE_ROLES)}
        self.clock = {"policy": {"version": 1, "mode": "bounded_utc", "uncertaintySeconds": "1"},
            "commitment": "c" * 64}
        self.slot = "oci-sdk-emulator-v1-" + "b" * 64

    def configuration(self, **changes):
        values = {"original": self.original, "selected": self.selected, "roles": self.roles,
            "registry_key": self.slot, "reviewer_key_id": "reviewer", "reviewer_public_key": "d" * 64,
            "clock_policy": self.clock}
        values.update(changes)
        return pair.managed_worker_configuration(**values)

    def test_initial_configuration_isolated_and_never_inherits_external_material(self):
        original = copy.deepcopy(self.original)
        actual = self.configuration()

        self.assertEqual(original, self.original)
        self.assertEqual(actual["r2Buckets"], {"REGISTRY_BUCKET": "oci-sdk-qualification-" + "a" * 32})
        self.assertEqual(set(actual["kvNamespaces"]), {"HUB_OCI_SDK_EMULATOR_ACCEPTANCE"})
        self.assertEqual(actual["ociSdkAcceptanceRegistryKey"], self.slot)
        self.assertEqual(actual["bindings"]["HUB_DIRECT_UPLOAD_MANAGED_R2"], "false")
        self.assertEqual(actual["bindings"]["HUB_HYBRID_ORIGIN_URL"], "https://localhost:4644")
        self.assertNotIn("original-private-material", json.dumps(actual))
        self.assertNotIn("HUB_EXTERNAL_OBJECT_CONSUMER", actual["bindings"])
        self.assertNotIn("queueProducers", actual)

    def test_changed_runtime_clock_slot_or_shared_roles_refuses(self):
        wrong_runtime = {**self.selected, "shim": "/nix/store/other/shim.mjs"}
        wrong_roles = {name: "1" * 64 for name in pair.PRIVATE_ROLES}
        bad_clock = {"policy": {**self.clock["policy"], "uncertaintySeconds": "01"}, "commitment": "c" * 64}
        for change in ({"selected": wrong_runtime}, {"roles": wrong_roles},
                       {"clock_policy": bad_clock}, {"registry_key": "direct-slot"}):
            with self.subTest(change=tuple(change)), self.assertRaises(ValueError):
                self.configuration(**change)

    def test_initial_cache_identity_is_exact_and_never_changes_the_source_selection(self):
        cache = {"registrySlug": "managed-" + "a" * 32 + "/containers",
            "documentSha256": "e" * 64, "bodyBytes": 4096, "assetVersion": "a1b2c3d4"}
        selected = {**self.selected, "publicDocumentCacheCase": cache,
            "publicDocumentCacheObserver": "/nix/store/selected-observer/_hub-worker-cache-observer.cjs"}
        actual = self.configuration(selected=selected)
        cache["documentSha256"] = "f" * 64
        self.assertEqual(actual["publicDocumentCacheCase"]["documentSha256"], "e" * 64)
        self.assertEqual(actual["scriptPath"], self.original["scriptPath"])
        for changed in ({"registrySlug": "other/registry"}, {"bodyBytes": 262145},
                {"assetVersion": "unknown"}, {"extra": True}):
            invalid = {**selected, "publicDocumentCacheCase": {**cache, **changed}}
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.configuration(selected=invalid)

    def test_initial_profile_observation_cannot_select_another_placement_or_graph(self):
        observer = {"version": 1, "capture_id": "a" * 32,
            "placement_prefix": "qualification/oci-terminal-cleanup/" + "a" * 32,
            "document_digest": "sha256:" + "e" * 64}
        selected = {**self.selected, "ociProfileLoadObserverSelection": observer}
        actual = self.configuration(selected=selected)
        self.assertEqual(json.loads(actual["bindings"]["HUB_OCI_PROFILE_LOAD_OBSERVER"]), observer)
        self.assertEqual(actual["ociSdkAcceptanceRegistryKey"], self.slot)
        for changed in ({"version": True}, {"capture_id": "b" * 32},
                {"placement_prefix": "qualification/other"}, {"document_digest": "e" * 64},
                {"accepted": True}):
            invalid = {**selected, "ociProfileLoadObserverSelection": {**observer, **changed}}
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.configuration(selected=invalid)

    def test_native_arguments_have_fresh_db_and_three_separate_activation_files(self):
        coordinates = pair.managed_pair_coordinates("a" * 32)
        files = {name: "/private/" + name for name in (
            "database", "HUB_HYBRID_INGRESS_KEY", "HUB_STORAGE_WORK_KEY", "jwt",
            "certificate", "privateKey", "probeManifest", "acceptance", "reviewers", "HUB_DIRECT_UPLOAD_GUARD_KEY")}
        files.update({name: coordinates["nativeRoot"] + "/materials/" + name for name in (
            "release_seed", "channel_seed", "publication_keys", "qualification_keys", "route_keys")})
        before = pair.managed_native_arguments("/nix/store/hub/bin/aos-hub", coordinates, files)
        after = pair.managed_native_arguments("/nix/store/hub/bin/aos-hub", coordinates, files, acceptance=True)

        self.assertNotIn("--direct-upload-acceptance-file", before + after)
        self.assertEqual(before[before.index("--hybrid-upload-mode") + 1], "worker_proxy")
        self.assertNotIn("--oci-sdk-emulator-acceptance-file", before)
        self.assertEqual(after[:-6], before)
        self.assertEqual(after[-6:], ["--oci-sdk-emulator-acceptance-file", files["acceptance"],
            "--oci-sdk-emulator-review-keys-file", files["reviewers"],
            "--oci-sdk-emulator-guard-key-file", files["HUB_DIRECT_UPLOAD_GUARD_KEY"]])
        self.assertIn(coordinates["nativeRoot"] + "/hub", before)
        for option, expected in (
            ("--deployment-id", coordinates["deploymentId"]),
            ("--release-receipt-key-id", "staging-publication-v1"),
            ("--channel-receipt-key-id", "staging-channel-v1"),
            ("--release-receipt-key-file", files["release_seed"]),
            ("--channel-receipt-key-file", files["channel_seed"]),
            ("--release-publication-keys-file", files["publication_keys"]),
            ("--qualification-keys-file", files["qualification_keys"]),
            ("--route-reservation-keys-file", files["route_keys"]),
        ):
            self.assertEqual(before[before.index(option) + 1], expected)
        for missing in ("release_seed", "channel_seed", "publication_keys", "qualification_keys", "route_keys"):
            incomplete = dict(files)
            del incomplete[missing]
            with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "complete private"):
                pair.managed_native_arguments("/nix/store/hub/bin/aos-hub", coordinates, incomplete)

    def test_observer_uses_selected_worker_origin_and_native_process_owner(self):
        coordinates = pair.managed_pair_coordinates("a" * 32)
        coordinates.update(workerOrigin="https://aos.fleet.test",
            nativeOrigin="https://native.fleet.test:8443")
        prepared = {"coordinates": coordinates, "configurationFile": "/private/configuration.json"}
        tools = {name: "/nix/store/selected/" + name for name in (
            "workerSourcePath", "python", "reviewer", "hub", "qualificationDriver",
            "ociNamespaceObserver", "ociAnchor", "node", "runner", "workerd", "miniflare", "wasm", "shim",
            "setpriv")}
        tools["nativeObserverUser"] = "aos-hub"
        native, worker = object(), object()
        processes = {"native": {"pid": 123}, "worker": {"pid": 456}}
        transferred, commands, selections = [], [], []

        def install(machine, python, path, body):
            transferred.append((machine, path, body))

        def observe(machine, python, body, selected, timeout):
            selections.append(selected)
            return "{}"

        with patch.object(pair, "install_direct_guest_file", install, create=True), \
                patch.object(pair, "read_direct_guest_file", return_value=b"actual observation", create=True), \
                patch.object(pair, "private_guest_command", side_effect=lambda *args, **kwargs: commands.append(args), create=True), \
                patch.object(pair, "direct_guest_python", observe, create=True):
            pair.observe_managed_pair(native, worker, tools, prepared, processes)

        self.assertEqual(json.loads(transferred[0][2])["publicOrigin"], "https://aos.fleet.test")
        self.assertEqual(selections[0]["origin"], "https://aos.fleet.test")
        self.assertIn("setpriv --reuid aos-hub --regid aos-hub --init-groups", commands[0][1])
        self.assertIn("--inh-caps +sys_ptrace --ambient-caps +sys_ptrace --", commands[0][1])
        self.assertIn("oci-sdk-observe-native --pid 123", commands[0][1])
        self.assertEqual(len(transferred), 3)

    def test_forwards_confined_to_real_private_vm_and_fixed_ports(self):
        arguments = pair.managed_forward_arguments("/nix/store/socat/bin/socat", "192.168.10.3", 4643)
        self.assertEqual(arguments[1:], ["TCP4-LISTEN:4643,bind=127.0.0.1,reuseaddr,fork",
            "TCP4:192.168.10.3:4643"])
        for address, port in (("127.0.0.1", 4643), ("0.0.0.0", 4643),
                              ("8.8.8.8", 4643), ("192.168.10.3", 443)):
            with self.subTest(address=address, port=port), self.assertRaises(ValueError):
                pair.managed_forward_arguments("/nix/store/socat/bin/socat", address, port)

    def test_existing_control_defaults_and_new_pair_actual_route_are_distinct(self):
        class Client:
            def __init__(self):
                self.commands = []

            def succeed(self, command):
                self.commands.append(command)

        commands = []
        def transport(client, command, **unused):
            commands.append(command)
            return "200" if "--data-binary" in command else "{}"

        for origin, root in (("https://aos.fleet.test", "/var/lib/hybrid-client/bootstrap-controls"),
                             ("https://localhost:4643", "/var/lib/hybrid-client/managed-a/controls")):
            client = Client()
            kwargs = {} if origin.endswith("andyl.org") else {"origin": origin, "evidence_root": root}
            actual = controls.DirectBootstrapControls(client, "curl --cacert selected", "python", "private",
                transport, **kwargs)
            self.assertEqual(actual.call("BindingService", "GetBinding", {"binding": {"instanceDefault": True}}), {})
            self.assertIn(origin + "/aos.hub.v1.BindingService/GetBinding", commands[-2])
            self.assertIn(root + "/0000.request.json", commands[-2])
        for origin, root in (("http://localhost:4643", "/var/lib/hybrid-client/a"),
                             ("https://localhost:4643/other", "/var/lib/hybrid-client/a"),
                             ("https://other.test", "/var/lib/hybrid-client/a"),
                             ("https://localhost:4643", "/var/lib/hybrid-client/../other")):
            with self.subTest(origin=origin, root=root), self.assertRaises(ValueError):
                controls.validate_control_destination(origin, root)

    def test_all_embedded_guest_programs_compile_with_no_home_reassignment(self):
        tree = ast.parse((HERE / "_hub-managed-pair.py").read_text())
        guests = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "direct_guest_python":
                if len(node.args) >= 3 and isinstance(node.args[2], ast.Constant):
                    import textwrap
                    guests.append(textwrap.dedent(node.args[2].value))
        self.assertEqual(len(guests), 9)
        for guest in guests:
            compile(guest, "selected-guest", "exec")
            self.assertNotIn("HOME=", guest)
            self.assertNotIn("Initialize", guest)
        database = next(guest for guest in guests if "CREATE DATABASE" in guest)
        self.assertIn("database already exists", database)
        self.assertNotIn("DROP DATABASE", database)


if __name__ == "__main__":
    unittest.main()
