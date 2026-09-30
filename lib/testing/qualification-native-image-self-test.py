"""Checks image byte custody and native bundle admission without a guest."""

import hashlib
import importlib.util
import json
import sys
import unittest
from pathlib import Path


specification = importlib.util.spec_from_file_location("native_image", Path(sys.argv[1]))
if specification is None or specification.loader is None:
    raise RuntimeError("cannot load native image validation")
NATIVE = importlib.util.module_from_spec(specification)
specification.loader.exec_module(NATIVE)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class NativeImageTests(unittest.TestCase):
    def setUp(self):
        self.payload = "/nix/store/" + "0" * 32 + "-payload"
        self.library = "/nix/store/" + "1" * 32 + "-library"
        self.envelope = "/nix/store/" + "2" * 32 + "-deployment"
        root = lambda path: {
            "storePath": path, "narHash": "sha256:" + "a" * 64,
            "narSize": 100, "references": [],
        }
        packages = {
            "system": "x86_64-linux",
            "artifacts": [{"name": "example", "path": self.payload}],
            "modules": [{"name": "example", "configRoot": self.payload}],
        }
        transaction = {
            "schema": "aos.package.transaction", "system": "x86_64-linux",
            "scope": ["profile", "system"], "artifacts": packages["artifacts"],
            "packages": packages["modules"], "inputs": [self.library, self.payload, self.envelope],
            "graph": {"schema": "aos.activation.graph", "nodes": {}, "order": []},
        }
        evaluation = {
            "schema": "aos.package.evaluation-input", "scope": transaction["scope"],
            "packages": packages, "library": self.library + "/default.nix",
            "libraryNarHash": "sha256:" + "a" * 64,
            "configuration": [], "runtimeConfiguration": [],
        }
        admission = {
            "schema": "aos.package.admission",
            "roots": [root(path) for path in [self.payload, self.library, self.envelope]],
        }
        installed = [{
            "store_path": self.payload,
            "apm": {"deployment": {
                "store_path": self.envelope, "nar_hash": "sha256:" + "a" * 64,
                "nar_size": 100, "references": [],
            }},
        }]
        self.documents = {filename: canonical(value) for filename, value in {
            "transaction.json": transaction, "packages.json": packages,
            "evaluation.json": evaluation, "admission.json": admission,
            "installed.json": installed,
        }.items()}
        self.documents["admission-sha256"] = (
            "sha256:" + hashlib.sha256(self.documents["admission.json"]).hexdigest() + "\n"
        ).encode()
        self.files = self.facts()

    def facts(self):
        purposes = NATIVE.BUNDLE_FILES | {"installed.json": "installed"}
        return {"host-" + purposes[name]: {
            "size_bytes": len(contents),
            "sha256": "sha256:" + hashlib.sha256(contents).hexdigest(),
        } for name, contents in self.documents.items()}

    def validate(self):
        return NATIVE.validate_bundle("host", self.documents, self.files, "x86_64-linux")

    def replace(self, filename, change):
        value = json.loads(self.documents[filename])
        change(value)
        self.documents[filename] = canonical(value)
        self.files = self.facts()

    def test_exact_native_image_bundle_is_accepted(self):
        self.assertEqual(self.validate()["packages"]["artifacts"][0]["path"], self.payload)

    def test_supplemental_source_is_retained_without_becoming_an_import(self):
        self.replace("evaluation.json", lambda value: value.update(supplementalInputs=[self.envelope]))
        result = self.validate()
        self.assertEqual(result["evaluation"]["configuration"], [])
        self.assertEqual(result["evaluation"]["supplementalInputs"], [self.envelope])

    def test_supplemental_source_cannot_be_unretained_or_unadmitted(self):
        self.replace("evaluation.json", lambda value: value.update(supplementalInputs=[self.envelope]))
        self.replace("transaction.json", lambda value: value["inputs"].remove(self.envelope))
        with self.assertRaisesRegex(RuntimeError, "supplemental source root"):
            self.validate()
        self.setUp()
        self.replace("evaluation.json", lambda value: value.update(supplementalInputs=["/nix/store/" + "3" * 32 + "-foreign"]))
        with self.assertRaises(RuntimeError):
            self.validate()

    def test_captured_byte_change_is_rejected(self):
        self.documents["packages.json"] += b"\n"
        with self.assertRaisesRegex(RuntimeError, "captured assembly"):
            self.validate()

    def test_library_nar_identity_must_match_admission(self):
        self.replace("evaluation.json", lambda value: value.update(libraryNarHash="sha256:" + "b" * 64))
        with self.assertRaisesRegex(RuntimeError, "library"):
            self.validate()

    def test_profile_roots_cannot_be_inferred_from_other_outputs(self):
        self.replace("installed.json", lambda value: value[0].update(store_path=self.envelope))
        with self.assertRaisesRegex(RuntimeError, "selected payload"):
            self.validate()

    def test_native_envelope_locator_must_match_exact_nar(self):
        self.replace("installed.json", lambda value: value[0]["apm"]["deployment"].update(nar_size=101))
        with self.assertRaisesRegex(RuntimeError, "NAR metadata"):
            self.validate()

    def test_transaction_cannot_select_another_scope(self):
        self.replace("transaction.json", lambda value: value.update(scope=["other", "system"]))
        with self.assertRaisesRegex(RuntimeError, "evaluation inputs"):
            self.validate()

    def test_admission_digest_must_bind_exact_catalog(self):
        self.documents["admission-sha256"] = ("sha256:" + "b" * 64).encode()
        self.files = self.facts()
        with self.assertRaisesRegex(RuntimeError, "exact catalog"):
            self.validate()

    def test_immutable_locator_cannot_escape_store_root(self):
        with self.assertRaisesRegex(RuntimeError, "escapes"):
            NATIVE.store_root(self.library + "/../foreign")

    def test_fixed_bundle_directory_and_member_aliases_resolve_exact_bytes(self):
        root = "/nix/store/" + "a" * 32 + "-bundle"
        payload = "/nix/store/" + "b" * 32 + "-documents"
        entries = {"lib/aos/initrd/deployment": (0o120777, root.encode()),
                   root.lstrip("/"): (0o040755, b"")}
        for name in NATIVE.BUNDLE_FILES:
            entries[root.lstrip("/") + "/" + name] = (0o120777, (payload + "/" + name).encode())
            entries[payload.lstrip("/") + "/" + name] = (0o100444, name.encode())
        class Archive:
            @staticmethod
            def read_newc_entries(_archive, names):
                return {name: entries[name] for name in names}
        self.assertEqual(NATIVE.archive_documents(Archive, Path("unused"), "initrd"),
                         {name: name.encode() for name in NATIVE.BUNDLE_FILES})

    def test_bundle_directory_cannot_alias_store_member_or_linked_parent(self):
        root = "/nix/store/" + "a" * 32 + "-bundle"
        for target, root_kind in ((root + "/subdirectory", 0o040755), (root, 0o120777)):
            with self.subTest(target=target, kind=root_kind):
                class Archive:
                    @staticmethod
                    def read_newc_entries(_archive, names):
                        return {name: ((0o120777, target.encode()) if name == "lib/aos/initrd/deployment"
                                       else (root_kind, root.encode())) for name in names}
                with self.assertRaises(RuntimeError):
                    NATIVE.archive_documents(Archive, Path("unused"), "initrd")

    def test_initrd_alias_must_point_inside_store(self):
        class Archive:
            @staticmethod
            def read_newc_entries(_archive, names):
                return {name: (0o120777, b"/etc/foreign") for name in names}
        with self.assertRaisesRegex(RuntimeError, "immutable store"):
            NATIVE.archive_documents(Archive, Path("unused"), "initrd")


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
