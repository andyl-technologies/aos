"""Check the dedicated External pair's initial source and process selections."""

import ast
import copy
import json
import importlib.util
from pathlib import Path
import textwrap
import unittest


spec = importlib.util.spec_from_file_location("external_pair", Path(__file__).with_name(
    "_hub-external-oci-pair.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class ExternalPairTests(unittest.TestCase):
    def test_physical_key_keeps_binding_and_placement_prefixes(self):
        coordinates = fixture.external_oci_pair_coordinates("a" * 32)
        placement = coordinates["placementPrefix"]
        binding = placement.rsplit("/", 1)[0]
        self.assertEqual(fixture.external_oci_provider_prefix("fleet-s3", binding, placement),
            "/fleet-s3/" + binding + "/" + placement + "/")
        for wrong in ("../outside", "/absolute", "bad//prefix"):
            with self.assertRaises(ValueError):
                fixture.external_oci_provider_prefix("fleet-s3", wrong, placement)

    def setUp(self):
        self.coordinates = fixture.external_oci_pair_coordinates("a" * 32)
        self.tools = {"shim": "/nix/store/source/shim.mjs",
            "externalCopyIsolation": "/nix/store/fixture/_hub-external-copy-isolation.cjs"}
        self.original = {"scriptPath": self.tools["shim"], "compatibilityDate": "2024-09-23",
            "certificatePath": "/nix/store/cert/value", "privateKeyPath": "/nix/store/key/value",
            "queueProducers": {"HUB_DIRECT_VERIFY_BULK": "main-bulk", "HUB_DIRECT_VERIFY_METADATA": "main-metadata"},
            "queueConsumers": {"main-bulk": {"maxBatchSize": 2, "maxBatchTimeout": 0},
                "main-metadata": {"maxBatchSize": 3, "maxBatchTimeout": 0}},
            "bindings": {"HUB_DIRECT_VERIFY_MAX_PARALLEL_OBJECTS": "3",
                "HUB_DIRECT_QUALIFY_MAX_OBJECT_BYTES": "2147483648",
                "HUB_EXTERNAL_OBJECT_CONSUMER": "previous authority"}}
        self.roles = {name: f"{index + 1:064x}" for index, name in enumerate(fixture.EXTERNAL_OCI_PAIR_KEYS)}
        self.clock = {"policy": {"version": 1, "mode": "bounded_utc", "uncertaintySeconds": "1"},
            "commitment": "b" * 64}

    def configuration(self, original=None, roles=None):
        return fixture.external_oci_initial_configuration(original or self.original, self.tools,
            self.coordinates, roles or self.roles, self.clock, "c" * 64)

    def test_fresh_pair_preserves_source_and_real_queue_policy(self):
        original = copy.deepcopy(self.original)
        selected = self.configuration()

        self.assertEqual(self.original, original)
        self.assertEqual(selected["scriptPath"], self.original["scriptPath"])
        self.assertEqual(sorted(selected["queueConsumers"].values(), key=lambda row: row["maxBatchSize"]),
            [{"maxBatchSize": 2, "maxBatchTimeout": 0}, {"maxBatchSize": 3, "maxBatchTimeout": 0}])
        self.assertTrue(all(name.startswith("external-" + "a" * 32)
            for name in selected["queueConsumers"]))
        self.assertNotIn("HUB_EXTERNAL_OBJECT_CONSUMER", selected["bindings"])
        self.assertEqual(selected["bindings"]["HUB_DIRECT_UPLOAD_MANAGED_R2"], "false")
        self.assertEqual(selected["durableObjects"]["EXTERNAL_OBJECT_GUARD"],
            {"className": "ExternalObjectGuard", "useSQLite": True})
        self.assertEqual(selected["copyIsolationSelection"],
            {"version": 1, "sourceWorkerName": selected["name"]})

    def test_reused_control_role_or_source_refuses_before_start(self):
        reused = {**self.roles, "HUB_EXTERNAL_STAGE_KEY": self.roles["HUB_STORAGE_WORK_KEY"]}
        with self.assertRaises(ValueError):
            self.configuration(roles=reused)
        changed = {**self.original, "scriptPath": "/nix/store/other/shim.mjs"}
        with self.assertRaises(ValueError):
            self.configuration(original=changed)

    def test_stock_bootstrap_has_exact_later_helper_origins(self):
        fields = ("database", "release_seed", "channel_seed", "publication_keys", "qualification_keys",
            "route_keys", "HUB_HYBRID_INGRESS_KEY", "HUB_STORAGE_WORK_KEY", "jwt", "secrets", "probeManifest",
            "certificate", "privateKey")
        arguments = fixture.external_oci_stock_arguments("/nix/store/hub/bin/aos-hub",
            self.coordinates, {name: "/private/" + name for name in fields})

        for flag, value in (("--listen", "127.0.0.1:4676"),
                ("--external-url", "https://localhost:4673"),
                ("--hybrid-origin-url", "https://localhost:4674")):
            self.assertEqual(arguments[arguments.index(flag) + 1], value)
        self.assertFalse(any("candidate" in argument or "acceptance" in argument for argument in arguments))

    def test_initial_observer_selects_actual_cross_binding_prefix_only_in_source_worker_case(self):
        original = json.loads(self.configuration()["bindings"]["HUB_EXTERNAL_COPY_LIFETIME_OBSERVER"])
        self.tools["copyIsolationCase"] = "source_worker"
        paired = json.loads(self.configuration()["bindings"]["HUB_EXTERNAL_COPY_LIFETIME_OBSERVER"])
        self.assertEqual(paired["source_prefix"], original["source_prefix"])
        self.assertEqual(paired["destination_prefixes"][2:], original["destination_prefixes"][2:])
        self.assertEqual(len(paired["destination_prefixes"]), 4)
        for kind, prefix in zip(("replicate", "repair"), paired["destination_prefixes"]):
            self.assertEqual(prefix, self.coordinates["placementPrefix"].rsplit("/", 1)[0]
                + "/destination/registry-" + kind + "-" + self.coordinates["runId"])

    def test_rendered_guest_blocks_compile(self):
        for node in ast.walk(ast.parse(Path(fixture.__file__).read_text())):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "direct_guest_python" and len(node.args) >= 3
                    and isinstance(node.args[2], ast.Constant)):
                compile(textwrap.dedent(node.args[2].value), "external-pair-guest", "exec")


if __name__ == "__main__":
    unittest.main()
