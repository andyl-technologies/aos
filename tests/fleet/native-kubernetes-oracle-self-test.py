"""Tests live Kubernetes projection and physical file safety invariants."""

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from unittest.mock import patch
from types import SimpleNamespace
import unittest

SPEC = importlib.util.spec_from_file_location("kubernetes_oracle", Path(__file__).with_name("native-kubernetes-oracle.py"))
ORACLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ORACLE)


class KubernetesOracleTests(unittest.TestCase):
    def setUp(self):
        self.document = {
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"namespace": "default", "name": "selected", "uid": "actual-api-uid",
                         "annotations": {ORACLE.OWNER: "sha256:" + "a" * 64}},
            "data": {"message": "baseline"},
        }

    def test_owner_comes_from_live_annotation(self):
        projection = ORACLE.object_projection(self.document, "default", "selected")
        self.assertEqual(projection["owners"], [self.document["metadata"]["annotations"][ORACLE.OWNER]])
        self.assertEqual(projection["uid"], "actual-api-uid")

    def test_absence_has_no_owner(self):
        self.assertEqual(ORACLE.object_projection(None, "default", "selected"), {"exists": False, "owners": []})

    def test_uid_replacement_and_payload_change_are_observable(self):
        baseline = ORACLE.object_projection(self.document, "default", "selected")
        changed = copy.deepcopy(self.document)
        changed["metadata"]["uid"] = "replacement-uid"
        self.assertNotEqual(baseline, ORACLE.object_projection(changed, "default", "selected"))
        changed = copy.deepcopy(self.document)
        changed["data"]["message"] = "candidate"
        self.assertNotEqual(baseline, ORACLE.object_projection(changed, "default", "selected"))

    def test_unowned_foreign_object_is_not_given_synthetic_owner(self):
        self.document["metadata"]["annotations"] = {}
        self.assertEqual(ORACLE.object_projection(self.document, "default", "selected")["owners"], [])

    def test_wrong_identity_and_malformed_owner_fail(self):
        for mutation in (lambda document: document["metadata"].update(name="other"),
                         lambda document: document["metadata"]["annotations"].update({ORACLE.OWNER: "forged"})):
            document = copy.deepcopy(self.document)
            mutation(document)
            with self.assertRaises(ValueError):
                ORACLE.object_projection(document, "default", "selected")

    def test_file_projection_rejects_symlink_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "foreign"
            target.write_bytes(b"independent physical bytes")
            selected = Path(directory) / "selected"
            selected.symlink_to(target)
            with self.assertRaises(OSError):
                ORACLE.file_projection(str(selected))
            self.assertEqual(ORACLE.file_projection(str(target))["digest"], ORACLE.digest(target.read_bytes()))

    def test_dependency_marker_uses_actual_claim_and_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / "selected"
            selected.write_text(json.dumps({"effect": "actual-owner", "revision": "actual-revision"}))
            selected.chmod(0o600)
            metadata = selected.stat()
            protected = SimpleNamespace(st_mode=metadata.st_mode, st_uid=0, st_gid=metadata.st_gid,
                                        st_ino=metadata.st_ino, st_dev=metadata.st_dev)
            with patch.object(ORACLE, "MARKER_ROOT", Path(directory)), patch.object(ORACLE.os, "fstat", return_value=protected):
                projection = ORACLE.dependency_projection(str(selected))
            self.assertEqual(projection["owners"], ["marker:actual-owner"])
            self.assertEqual(projection["inode"], metadata.st_ino)
            self.assertEqual(projection["digest"], ORACLE.digest(selected.read_bytes()))

    def test_dependency_marker_rejects_unprotected_and_symlink_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            selected = Path(directory) / "selected"
            selected.write_text(json.dumps({"effect": "actual-owner", "revision": "actual-revision"}))
            selected.chmod(0o644)
            with patch.object(ORACLE, "MARKER_ROOT", Path(directory)):
                with self.assertRaises(ValueError):
                    ORACLE.dependency_projection(str(selected))
                selected.unlink()
                selected.symlink_to(Path(directory) / "foreign")
                with self.assertRaises(OSError):
                    ORACLE.dependency_projection(str(selected))
                self.assertEqual(ORACLE.dependency_projection(str(Path(directory) / "absent")), {"exists": False, "owners": []})

    def test_configuration_selected_path_is_confined(self):
        with self.assertRaises(ValueError):
            ORACLE.configuration_projection("/tmp/arbitrary.json")


if __name__ == "__main__":
    unittest.main()
