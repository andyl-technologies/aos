"""Rejects staged K3s artifact substitutions before any guest is started."""

import copy
import unittest

from qualification_k3s_bindings import bind_k3s_fleet, verify_role_configuration_binding


PLATFORM = "x86_64-linux"
STORE_PREFIX = "/nix/store/" + "0" * 32


def fixture():
    """Builds two platform populations with native package contract bindings."""

    payload = {"packages": [], "images": [], "artifacts": []}
    package_contracts = (
        ("k3s", False),
        ("k3s-combined", True),
        ("k3s-control-plane", True),
        ("k3s-worker", True),
    )
    for name, has_native_module in package_contracts:
        cells = []
        for platform in (PLATFORM, "aarch64-linux"):
            output_id = f"package/{name}/{platform}/out"
            output_path = f"{STORE_PREFIX}-{name}-{platform}"
            contract_id = f"package/{name}/{platform}/contract"
            contract_path = f"{STORE_PREFIX}-{name}-{platform}-contract"
            payload["artifacts"].extend([
                {
                    "id": output_id,
                    "kind": "package-nar",
                    "platform": platform,
                    "output": "out",
                    "store_path": output_path,
                },
            ])
            artifact = {"artifact_ids": [output_id]}
            if has_native_module:
                payload["artifacts"].append({
                    "id": contract_id,
                    "kind": "package-nar",
                    "platform": platform,
                    "output": "out",
                    "store_path": contract_path,
                })
                module_path = f"{STORE_PREFIX}-{name}-{platform}-module"
                payload["artifacts"].append({
                    "id": f"source/{name}/{platform}/module",
                    "kind": "source",
                    "store_path": module_path,
                })
                artifact = {
                    "artifact_ids": [contract_id, output_id],
                    "package_contract": {
                        "document_artifact": contract_id,
                        "selectors": [
                            {
                                "package": "self",
                                "output": "module",
                                "store_path": module_path,
                            },
                            {
                                "package": "self",
                                "output": "out",
                                "store_path": output_path,
                            },
                        ],
                    },
                }
            cells.append({
                "platform": platform,
                "decision": {
                    "state": "artifact",
                    "artifact": artifact,
                },
            })
        payload["packages"].append({"name": name, "platforms": cells})

    image_cells = []
    for platform in (PLATFORM, "aarch64-linux"):
        identity = f"image/server/{platform}/logical-disk"
        payload["artifacts"].extend([
            {"id": identity, "kind": "logical-disk", "platform": platform},
            {"id": f"container/manifest/{platform}", "kind": "oci-manifest", "platform": platform},
            {"id": f"container/blob/{platform}/config", "kind": "oci-blob", "platform": platform},
            {"id": f"container/blob/{platform}/layer", "kind": "oci-blob", "platform": platform},
        ])
        image_cells.append({
            "platform": platform,
            "decision": {"state": "artifact", "artifact": {"artifact_ids": [identity]}},
        })
    payload["images"].append({"system_variant": "server", "platforms": image_cells})
    payload["artifacts"].append({"id": "container/index", "kind": "oci-index"})
    return payload


def bind(payload, package="k3s", topology="combined-worker"):
    return bind_k3s_fleet(payload, PLATFORM, package, "server", topology)


class BindingsTest(unittest.TestCase):
    def test_activation_requires_the_exact_native_module_and_candidate(self):
        bindings = bind(fixture())
        path = bindings.package_outputs["k3s-worker"]["module"]
        manifest = {"inputs": {"config_modules": {
            "count": 1,
            "package_names": ["k3s-worker"],
            "store_paths": [path],
            "origins": ["registry"],
            "registry": "andyl-testing",
            "release_tag": "1.0.0",
        }}}
        self.assertEqual(
            verify_role_configuration_binding(
                manifest, bindings, "k3s-worker", "andyl-testing", "1.0.0"
            ),
            path,
        )

        for field, value in (
            ("registry", "unrelated"),
            ("release_tag", "0.9.0"),
            ("origins", ["image"]),
            ("store_paths", [path + "-substitute"]),
            ("package_names", ["k3s-combined"]),
            ("count", 2),
        ):
            changed = copy.deepcopy(manifest)
            changed["inputs"]["config_modules"][field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaisesRegex(ValueError, "configuration"):
                    verify_role_configuration_binding(
                        changed, bindings, "k3s-worker", "andyl-testing", "1.0.0"
                    )

    def test_topologies_select_native_contracts_and_current_platform(self):
        for topology, role in (
            ("combined-worker", "k3s-combined"),
            ("control-plane-worker", "k3s-control-plane"),
        ):
            result = bind(fixture(), topology=topology)
            self.assertEqual(set(result.package_outputs), {"k3s", role, "k3s-worker"})
            self.assertEqual(result.oci_index, "container/index")
            self.assertEqual(result.oci_manifest, f"container/manifest/{PLATFORM}")
            self.assertEqual(len(result.oci_blobs), 2)
            self.assertTrue(result.package_outputs[role]["module"].endswith("-module"))
            self.assertFalse(any("aarch64" in value for value in result.subjects))

    def test_missing_or_substituted_native_module_is_rejected(self):
        for mutation in ("selector", "source", "path"):
            payload = fixture()
            cell = payload["packages"][-1]["platforms"][0]["decision"]["artifact"]
            if mutation == "selector":
                cell["package_contract"]["selectors"] = [
                    entry
                    for entry in cell["package_contract"]["selectors"]
                    if entry["output"] != "module"
                ]
            else:
                selector = next(
                    entry
                    for entry in cell["package_contract"]["selectors"]
                    if entry["output"] == "module"
                )
                if mutation == "source":
                    payload["artifacts"] = [
                        artifact
                        for artifact in payload["artifacts"]
                        if artifact.get("store_path") != selector["store_path"]
                    ]
                else:
                    selector["store_path"] = "/tmp/substitute"
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(ValueError, "module|selector|source"):
                    bind(payload)

    def test_module_requirement_follows_contract_presence(self):
        payload = fixture()
        k3s = payload["packages"][0]["platforms"][0]["decision"]["artifact"]
        bind(payload)

        k3s["package_contract"] = {
            "document_artifact": k3s["artifact_ids"][0],
            "selectors": [],
        }
        with self.assertRaisesRegex(ValueError, "native package module"):
            bind(payload)

    def test_missing_package_or_oci_identity_is_rejected(self):
        payload = fixture()
        payload["packages"] = [
            entry for entry in payload["packages"] if entry["name"] != "k3s-worker"
        ]
        with self.assertRaisesRegex(ValueError, "k3s-worker package entry"):
            bind(payload)

        for kind in ("oci-index", "oci-manifest"):
            payload = fixture()
            entry = next(entry for entry in payload["artifacts"] if entry["kind"] == kind)
            payload["artifacts"] = [
                candidate for candidate in payload["artifacts"] if candidate["id"] != entry["id"]
            ]
            with self.assertRaisesRegex(ValueError, "exactly one published OCI"):
                bind(payload)


if __name__ == "__main__":
    unittest.main()
