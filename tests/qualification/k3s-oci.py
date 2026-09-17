"""Checks staged OCI graph integrity and archive byte preservation for K3s."""

import dataclasses
import hashlib
import json
import pathlib
import tarfile
import tempfile
import unittest

from qualification_k3s_bindings import K3sFleetBindings
from qualification_k3s_oci import assemble_workload


class WorkloadTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.payload = {"artifacts": []}
        self.objects = {}
        self.config = self.add("config", "oci-blob", {"os": "linux", "architecture": "amd64"})
        self.layer = self.add("layer", "oci-blob", b"test layer bytes")
        self.manifest = self.add("manifest", "oci-manifest", {
            "schemaVersion": 2, "config": self.config, "layers": [self.layer],
        })
        self.index_value = {
            "schemaVersion": 2,
            "manifests": [{**self.manifest, "platform": {"os": "linux", "architecture": "amd64"}}],
        }
        self.add("index", "oci-index", self.index_value)
        self.bindings = K3sFleetBindings([], {}, [], "index", "manifest", ["config", "layer"])

    def add(self, identity, kind, value):
        data = value if isinstance(value, bytes) else json.dumps(value).encode()
        digest = hashlib.sha256(data).hexdigest()
        path = self.root / identity
        path.write_bytes(data)
        self.objects[identity] = str(path)
        self.payload["artifacts"] = [entry for entry in self.payload["artifacts"] if entry["id"] != identity]
        self.payload["artifacts"].append({
            "id": identity, "kind": kind, "sha256": "sha256:" + digest,
            "size_bytes": len(data), "path": "oci/blobs/sha256/" + digest,
        })
        return {"digest": "sha256:" + digest, "size": len(data)}

    def assemble(self):
        return assemble_workload(
            self.payload, self.objects, self.bindings, "x86_64-linux", self.root / "archive"
        )

    def test_archive_preserves_published_bytes_and_selects_native_digest(self):
        archive, reference = self.assemble()

        self.assertEqual(reference, "aos.invalid/qualification@" + self.manifest["digest"])
        with tarfile.open(archive) as source:
            for artifact in self.payload["artifacts"]:
                entry = source.extractfile(artifact["path"].removeprefix("oci/"))
                self.assertIsNotNone(entry)
                self.assertEqual(entry.read(), pathlib.Path(self.objects[artifact["id"]]).read_bytes())

    def test_substituted_object_is_rejected(self):
        pathlib.Path(self.objects["layer"]).write_bytes(b"other layer data")
        with self.assertRaisesRegex(ValueError, "bound artifact identity"):
            self.assemble()

    def test_signed_index_cannot_select_an_unbound_manifest(self):
        self.index_value["manifests"][0]["digest"] = "sha256:" + "a" * 64
        self.add("index", "oci-index", self.index_value)
        with self.assertRaisesRegex(ValueError, "bound object"):
            self.assemble()

    def test_ambiguous_native_platform_is_rejected(self):
        self.index_value["manifests"].append(dict(self.index_value["manifests"][0]))
        self.add("index", "oci-index", self.index_value)
        with self.assertRaisesRegex(ValueError, "uniquely select"):
            self.assemble()

    def test_missing_and_unreferenced_blobs_are_rejected(self):
        self.bindings = dataclasses.replace(self.bindings, oci_blobs=["config"])
        with self.assertRaisesRegex(ValueError, "bound object"):
            self.assemble()

        self.add("unreferenced", "oci-blob", b"unreferenced content")
        self.bindings = dataclasses.replace(self.bindings, oci_blobs=["config", "layer", "unreferenced"])
        with self.assertRaisesRegex(ValueError, "unreferenced"):
            self.assemble()

    def test_external_descriptor_is_rejected(self):
        self.index_value["manifests"][0]["urls"] = ["https://example.invalid/substitute"]
        self.add("index", "oci-index", self.index_value)
        with self.assertRaisesRegex(ValueError, "external"):
            self.assemble()

    def test_descriptor_size_mismatch_is_rejected(self):
        self.index_value["manifests"][0]["size"] += 1
        self.add("index", "oci-index", self.index_value)
        with self.assertRaisesRegex(ValueError, "bound object"):
            self.assemble()


if __name__ == "__main__":
    unittest.main()
