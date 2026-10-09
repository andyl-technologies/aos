"""Checks native marker observations remain read-only and reject foreign roots."""

from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

specification = importlib.util.spec_from_file_location("marker", sys.argv[1])
marker = importlib.util.module_from_spec(specification)
specification.loader.exec_module(marker)


class MarkerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        marker.ROOT = Path(self.directory.name) / "uncreated"

    def invoke(self, operation, action, name="owned"):
        invocation = {"id": "exact-effect", "revision": "exact-revision",
                      "action": action, "input": {"name": name, "parent": None}}
        input_stream = io.TextIOWrapper(io.BytesIO(json.dumps(invocation).encode()))
        output = io.StringIO()
        with patch.object(sys, "argv", ["fixture", operation]), patch.object(sys, "stdin", input_stream), redirect_stdout(output):
            marker.main()
        return json.loads(output.getvalue())

    def test_absent_apply_observation_is_read_only(self):
        self.assertEqual(self.invoke("observe", "apply"), {"status": "retry-safe"})
        self.assertFalse(marker.ROOT.exists())

    def test_absent_remove_observation_is_read_only(self):
        self.assertEqual(self.invoke("observe", "remove"), {"status": "absent"})
        self.assertFalse(marker.ROOT.exists())

    def test_absent_remove_does_not_create_state(self):
        self.assertEqual(self.invoke("remove", "remove"), {"resource": str(marker.ROOT / "owned")})
        self.assertFalse(marker.ROOT.exists())

    def test_marker_name_cannot_escape_owned_root(self):
        with self.assertRaises(ValueError):
            self.invoke("apply", "apply", "../foreign")
        self.assertFalse(marker.ROOT.exists())

    def test_unprotected_existing_root_is_not_adopted(self):
        marker.ROOT.mkdir(mode=0o777)
        marker.ROOT.chmod(0o777)
        with self.assertRaises(ValueError):
            self.invoke("apply", "apply")
        self.assertFalse((marker.ROOT / "owned").exists())


unittest.main(argv=[sys.argv[0]])
