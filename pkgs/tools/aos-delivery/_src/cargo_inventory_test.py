"""Checks Cargo evidence selection, source binding, and final-layer semantics."""

import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from cargo_inventory import enrich_cargo_inventory
from transport import DeliveryError


ROOT = "nix/store/" + "0" * 32 + "-aos-hub-0.1.0"
MESSAGES = ROOT + "/nix-support/cargo-build-messages.jsonl"


def record(package_id, kind="lib", name="example", test=False):
    return {
        "reason": "compiler-artifact",
        "package_id": package_id,
        "target": {"kind": [kind], "name": name},
        "profile": {"test": test},
        "filenames": ["target/release/deps/libexample.rlib"],
    }


def messages():
    records = [
        record("path+file://./source/crates/aos-hub#0.1.0", "bin", "aos-hub"),
        record("registry+https://github.com/rust-lang/crates.io-index#tokio@1.45.0"),
        record("registry+https://github.com/rust-lang/crates.io-index#syn@2.0.0", "proc-macro"),
        record("registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0", test=True),
        record("git+https://example.invalid/library#example@1.0.0"),
    ]
    return b"\n".join(json.dumps(value).encode() for value in records) + b"\n"


class CargoInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cargo-inventory-test-")
        self.addCleanup(self.temporary.cleanup)
        self.layout = Path(self.temporary.name) / "layout"
        (self.layout / "blobs" / "sha256").mkdir(parents=True)

    def blob(self, payload, media):
        digest = hashlib.sha256(payload).hexdigest()
        (self.layout / "blobs" / "sha256" / digest).write_bytes(payload)
        return {"digest": "sha256:" + digest, "size": len(payload), "mediaType": media}

    def layer(self, members):
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w") as archive:
            for path, content, kind in members:
                member = tarfile.TarInfo(path)
                if kind == "symlink":
                    member.type = tarfile.SYMTYPE
                    member.linkname = "/external/messages"
                    archive.addfile(member)
                else:
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
        return self.blob(payload.getvalue(), "application/vnd.oci.image.layer.v1.tar")

    def image(self, members=None, extra_layers=()):
        if members is None:
            members = [(MESSAGES, messages(), "file"), (ROOT + "/bin/aos-hub", b"ELF", "file")]
        layers = [self.layer(members), *[self.layer(values) for values in extra_layers]]
        manifest = {"schemaVersion": 2, "layers": layers}
        descriptor = self.blob(
            json.dumps(manifest).encode(), "application/vnd.oci.image.manifest.v1+json"
        )
        (self.layout / "index.json").write_text(
            json.dumps({"schemaVersion": 2, "manifests": [descriptor]}), encoding="utf-8"
        )

    def enrich(self):
        catalog = {"artifacts": []}
        spdx = {"packages": []}
        coverage = enrich_cargo_inventory(self.layout, catalog, spdx)
        return catalog, spdx, coverage

    def test_selects_exact_compiled_registry_library(self):
        self.image()

        catalog, spdx, coverage = self.enrich()

        self.assertEqual([value["purl"] for value in catalog["artifacts"]], ["pkg:cargo/tokio@1.45.0"])
        self.assertEqual(coverage["nativeBuildTargets"], ["aos-hub"])
        self.assertEqual(coverage["cratesIoLibraryCandidates"], 1)
        self.assertEqual(coverage["skippedArtifacts"]["test"], 1)
        self.assertEqual(spdx["packages"][0]["externalRefs"][0]["referenceLocator"], "pkg:cargo/tokio@1.45.0")
        self.assertEqual(coverage["buildMessagesDigest"], "sha256:" + hashlib.sha256(messages()).hexdigest())

    def test_whiteout_removes_lower_layer_evidence(self):
        self.image(extra_layers=[[(ROOT + "/nix-support/.wh.cargo-build-messages.jsonl", b"", "file")]])

        with self.assertRaises(DeliveryError):
            self.enrich()

    def test_root_opaque_whiteout_hides_lower_layer_evidence(self):
        self.image(extra_layers=[[(".wh..wh..opq", b"", "file")]])

        with self.assertRaises(DeliveryError):
            self.enrich()

    def test_same_layer_whiteout_preserves_replacement(self):
        self.image(extra_layers=[[
            (MESSAGES, messages(), "file"),
            (ROOT + "/nix-support/.wh.cargo-build-messages.jsonl", b"", "file"),
        ]])

        self.assertEqual(self.enrich()[2]["cratesIoLibraryCandidates"], 1)

    def test_symlink_evidence_is_rejected(self):
        self.image(extra_layers=[[(MESSAGES, b"", "symlink")]])

        with self.assertRaises(DeliveryError):
            self.enrich()

    def test_ancestor_replacement_hides_old_evidence(self):
        self.image(extra_layers=[[(ROOT + "/nix-support", b"", "symlink")]])

        with self.assertRaises(DeliveryError):
            self.enrich()

    def test_descriptor_tampering_is_rejected(self):
        self.image()
        index = json.loads((self.layout / "index.json").read_text())
        manifest = self.layout / "blobs" / "sha256" / index["manifests"][0]["digest"].split(":")[1]
        manifest.write_bytes(manifest.read_bytes() + b" ")

        with self.assertRaises(DeliveryError):
            self.enrich()

    def test_missing_native_build_record_is_rejected(self):
        self.image(members=[
            (MESSAGES, json.dumps(record("registry+https://github.com/rust-lang/crates.io-index#tokio@1.45.0")).encode(), "file"),
            (ROOT + "/bin/aos-hub", b"ELF", "file"),
        ])

        with self.assertRaises(DeliveryError):
            self.enrich()

    def test_malformed_artifact_filenames_are_rejected(self):
        value = record("registry+https://github.com/rust-lang/crates.io-index#tokio@1.45.0")
        value["filenames"] = None
        self.image(members=[
            (MESSAGES, json.dumps(value).encode(), "file"),
            (ROOT + "/bin/aos-hub", b"ELF", "file"),
        ])

        with self.assertRaises(DeliveryError):
            self.enrich()

    def test_repeat_does_not_duplicate_existing_catalog_entries(self):
        self.image()
        catalog, spdx, _ = self.enrich()
        original = copy.deepcopy(catalog)

        coverage = enrich_cargo_inventory(self.layout, catalog, spdx)

        self.assertEqual(catalog, original)
        self.assertEqual(coverage["addedPackages"], 0)


if __name__ == "__main__":
    unittest.main()
