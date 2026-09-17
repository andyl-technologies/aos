"""Rejects staged K3s input substitutions before any guest is started."""

import copy
import unittest

from qualification_k3s_bindings import bind_k3s_fleet, verify_role_configuration_binding


PLATFORM = "x86_64-linux"


def fixture():
    """Builds two platform populations so native selection can be observed."""

    payload = {"packages": [], "images": [], "artifacts": []}
    for name in ("k3s", "k3s-combined", "k3s-control-plane", "k3s-worker"):
        cells = []
        for platform in (PLATFORM, "aarch64-linux"):
            identity = f"package/{name}/{platform}/out"
            payload["artifacts"].append({
                "id": identity,
                "kind": "package-nar",
                "platform": platform,
                "output": "out",
                "store_path": "/nix/store/" + "0" * 32 + f"-{name}-{platform}",
            })
            bound = {"artifact_ids": [identity]}
            if name != "k3s":
                module = f"package/{name}/{platform}/config"
                base = f"package/{name}/{platform}/configuration-base"
                for artifact_id, output, suffix in (
                    (module, "config", "config"), (base, "out", "base"),
                ):
                    payload["artifacts"].append({
                        "id": artifact_id, "kind": "package-nar", "platform": platform,
                        "output": output,
                        "store_path": "/nix/store/" + "0" * 32 + f"-{name}-{platform}-{suffix}",
                    })
                bound["artifact_ids"].extend([module, base])
                bound["configuration"] = {
                    "module_artifact": module, "evaluation_base_artifact": base,
                    "dependency_outputs": {},
                }
            cells.append({
                "platform": platform,
                "decision": {"state": "artifact", "artifact": bound},
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
    def test_activation_requires_the_exact_role_source_and_candidate(self):
        bindings = bind(fixture())
        path = bindings.package_outputs["k3s-worker"]["config"]
        manifest = {"inputs": {"config_modules": {
            "count": 1, "package_names": ["k3s-worker"], "store_paths": [path],
            "origins": ["registry"], "registry": "andyl-testing", "release_tag": "1.0.0",
        }}}
        self.assertEqual(verify_role_configuration_binding(
            manifest, bindings, "k3s-worker", "andyl-testing", "1.0.0"
        ), path)

        for field, value in (
            ("registry", "unrelated"), ("release_tag", "0.9.0"),
            ("origins", ["image"]), ("store_paths", [path + "-substitute"]),
            ("package_names", ["k3s-combined"]), ("count", 2),
            ("store_paths", []),
        ):
            changed = copy.deepcopy(manifest)
            changed["inputs"]["config_modules"][field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaisesRegex(ValueError, "configuration"):
                    verify_role_configuration_binding(
                        changed, bindings, "k3s-worker", "andyl-testing", "1.0.0"
                    )

    def test_topologies_select_only_their_native_roles(self):
        for topology, role in (
            ("combined-worker", "k3s-combined"),
            ("control-plane-worker", "k3s-control-plane"),
        ):
            with self.subTest(topology=topology):
                result = bind(fixture(), topology=topology)

                self.assertEqual(set(result.package_outputs), {"k3s", role, "k3s-worker"})
                self.assertEqual(result.oci_index, "container/index")
                self.assertEqual(result.oci_manifest, f"container/manifest/{PLATFORM}")
                self.assertEqual(len(result.oci_blobs), 2)
                self.assertEqual(len(result.subjects), 12)
                self.assertTrue(result.package_outputs[role]["out"].endswith(f"-{role}-{PLATFORM}"))
                self.assertTrue(result.package_outputs[role]["config"].endswith("-config"))
                self.assertTrue(result.package_outputs[role]["configuration-base"].endswith("-base"))
                self.assertFalse(any("aarch64" in value for value in result.subjects))

    def test_missing_or_substituted_configuration_is_rejected(self):
        for mutation in ("binding", "module", "base", "same-artifact", "wrong-output"):
            payload = fixture()
            cell = payload["packages"][-1]["platforms"][0]["decision"]["artifact"]
            configuration = cell["configuration"]
            if mutation == "binding":
                del cell["configuration"]
            elif mutation in {"module", "base"}:
                key = "module_artifact" if mutation == "module" else "evaluation_base_artifact"
                cell["artifact_ids"].remove(configuration[key])
            elif mutation == "same-artifact":
                configuration["evaluation_base_artifact"] = configuration["module_artifact"]
            else:
                module = next(a for a in payload["artifacts"] if a["id"] == configuration["module_artifact"])
                module["output"] = "out"
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(ValueError, "configuration"):
                    bind(payload)

    def test_absent_companion_and_nonartifact_platform_are_rejected(self):
        payload = fixture()
        payload["packages"] = [entry for entry in payload["packages"] if entry["name"] != "k3s-worker"]
        with self.assertRaisesRegex(ValueError, "k3s-worker package entry"):
            bind(payload)

        payload = fixture()
        payload["packages"][-1]["platforms"][0]["decision"] = {"state": "blocked"}
        with self.assertRaisesRegex(ValueError, "not an artifact"):
            bind(payload)

    def test_duplicate_or_missing_container_selection_is_rejected(self):
        for kind in ("oci-index", "oci-manifest"):
            payload = fixture()
            entry = next(entry for entry in payload["artifacts"] if entry["kind"] == kind)
            for duplicate in (False, True):
                changed = copy.deepcopy(payload)
                if duplicate:
                    changed["artifacts"].append({**entry, "id": entry["id"] + "/duplicate"})
                else:
                    changed["artifacts"] = [value for value in changed["artifacts"] if value["id"] != entry["id"]]
                with self.subTest(kind=kind, duplicate=duplicate):
                    with self.assertRaisesRegex(ValueError, "exactly one published OCI"):
                        bind(changed)

    def test_wrong_image_platform_and_missing_variant_are_rejected(self):
        payload = fixture()
        image_id = payload["images"][0]["platforms"][0]["decision"]["artifact"]["artifact_ids"][0]
        next(entry for entry in payload["artifacts"] if entry["id"] == image_id)["platform"] = "aarch64-linux"
        with self.assertRaisesRegex(ValueError, "another platform"):
            bind(payload)

        payload["images"] = []
        with self.assertRaisesRegex(ValueError, "system image variant"):
            bind(payload)

    def test_package_output_substitutions_are_rejected(self):
        for field, value in (
            ("store_path", "/tmp/substitute"),
            ("platform", "aarch64-linux"),
            ("kind", "oci-blob"),
            ("output", "dev"),
        ):
            payload = fixture()
            payload["artifacts"][0][field] = value
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    bind(payload)

    def test_duplicate_artifact_and_output_identities_are_rejected(self):
        payload = fixture()
        payload["artifacts"].append(copy.deepcopy(payload["artifacts"][0]))
        with self.assertRaisesRegex(ValueError, "repeats artifact"):
            bind(payload)

        payload = fixture()
        other = {**payload["artifacts"][0], "id": "duplicate-output"}
        payload["artifacts"].append(other)
        payload["packages"][0]["platforms"][0]["decision"]["artifact"]["artifact_ids"].append(other["id"])
        with self.assertRaisesRegex(ValueError, "unique package output"):
            bind(payload)

    def test_unsupported_execution_is_rejected(self):
        for platform, package, variant, topology in (
            ("x86_64-darwin", "k3s", "server", "combined-worker"),
            (PLATFORM, "k3s-control-plane", "server", "combined-worker"),
            (PLATFORM, "k3s", "../server", "combined-worker"),
            (PLATFORM, "k3s", "server", "unknown"),
        ):
            with self.subTest(platform=platform, package=package, variant=variant, topology=topology):
                with self.assertRaises(ValueError):
                    bind_k3s_fleet(fixture(), platform, package, variant, topology)


if __name__ == "__main__":
    unittest.main()
