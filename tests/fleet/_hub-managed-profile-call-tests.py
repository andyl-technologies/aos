"""Check confinement and the distinct Clock/namespace input contracts."""

import importlib.util
import json
from pathlib import Path
import unittest


HERE = Path(__file__).parent


def load(name, leaf):
    specification = importlib.util.spec_from_file_location(name, HERE / leaf)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


pair = load("profile_pair", "_hub-managed-pair.py")
callback = load("profile_call", "_hub-managed-profile-call.py")
callback.require_managed_pair = pair.require_managed_pair


class ProfileCallTests(unittest.TestCase):
    def setUp(self):
        self.coordinates = pair.managed_pair_coordinates("a" * 32)
        self.original = {"admission": {"upload_id": "actual-upload-1",
            "placement_prefix": self.coordinates["gcPrefix"]}}

    def test_only_actual_upload_and_reserved_scope_enter_sql(self):
        query = callback.managed_profile_original_sql(self.original, self.coordinates)
        self.assertIn("WHERE id = 'actual-upload-1'", query)
        self.assertIn("placement.registry_id = upload.registry_id", query)
        self.assertIn("writer.current_write_revision AS write_revision", query)
        self.assertNotIn("UPDATE ", query)
        for changed in ({"upload_id": "' OR true --"},
                {"upload_id": "x" * 65}, {"placement_prefix": "ordinary/objects"}):
            original = {"admission": {**self.original["admission"], **changed}}
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                callback.managed_profile_original_sql(original, self.coordinates)

    def test_clock_input_names_actual_origin_and_namespace_consumes_driver_output(self):
        files = {}
        guest = {}
        pair.install_direct_guest_file = lambda machine, python, path, body: files.update({path: body})
        pair.private_guest_command = lambda *args, **kwargs: ""
        pair.read_direct_guest_file = lambda *args: b"{}"
        pair.direct_guest_python = lambda machine, python, code, selected, **kwargs: (
            guest.update({"code": code, "selected": selected}) or "{}")
        tools = {name: "/nix/store/selected/" + name for name in (
            "workerSourcePath", "python", "reviewer", "hub", "qualificationDriver",
            "ociNamespaceObserver", "ociAnchor", "node", "runner", "workerd", "miniflare", "wasm", "shim")}
        prepared = {"coordinates": self.coordinates, "configurationFile": "/private/configuration.json"}
        pair.observe_managed_pair(None, None, tools, prepared,
            {"native": {"pid": 10}, "worker": {"pid": 11}})
        identity = json.loads(files[self.coordinates["workerRoot"] + "/build-selected-identity.json"])
        self.assertEqual(identity["publicOrigin"], "https://localhost:4643")
        self.assertEqual(set(identity), {"sourceDigest", "scriptVersion", "publicOrigin"})
        self.assertIn("str(root/'clock-0/source-identity.json')", guest["code"])
        self.assertNotIn("'--identity-file',selected['identity'],\n", guest["code"])


if __name__ == "__main__":
    unittest.main()
