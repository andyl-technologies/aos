"""Checks native binding publication, observations, and malformed inputs."""

import json
from pathlib import Path
import subprocess
import sys
import unittest


class NativeBindingTests(unittest.TestCase):
    """Checks the process protocol using an empty inherited environment."""

    def invoke(self, action, inputs, desired="apply"):
        script = Path(__file__).with_name("binding-handler.py")
        invocation = {"id": "binding", "input": inputs, "action": desired}
        return subprocess.run(
            [sys.executable, str(script), action],
            input=json.dumps(invocation),
            text=True,
            capture_output=True,
            env={},
            check=False,
        )

    def test_publication_and_service_binding(self):
        inputs = {
            "service": "nginx-nginx-main.service",
            "endpoints": {"app-a": {"address": "127.0.0.1", "port": 19001, "transport": "tcp"}},
        }
        expected = {"resource": "binding", **inputs}

        applied = self.invoke("apply", inputs)
        observed = self.invoke("observe", inputs)

        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertEqual(json.loads(applied.stdout), expected)
        self.assertEqual(json.loads(observed.stdout), {"status": "current", "outputs": expected})

    def test_removal_has_no_persistent_endpoint_state(self):
        inputs = {"endpoints": None}

        removed = self.invoke("remove", inputs, "remove")
        observed = self.invoke("observe", inputs, "remove")

        self.assertEqual(json.loads(removed.stdout), {})
        self.assertEqual(json.loads(observed.stdout), {"status": "absent"})

    def test_nullable_endpoint_publication(self):
        result = self.invoke("apply", {"endpoints": None})

        self.assertEqual(json.loads(result.stdout), {"resource": "binding", "endpoints": None})

    def test_rejects_foreign_or_malformed_binding_values(self):
        endpoint = {"address": "127.0.0.1", "port": 19001, "transport": "tcp"}
        invalid = [
            {"service": "/foreign.service"},
            {"endpoints": {"app-a": {**endpoint, "port": True}}},
            {"endpoints": {"app-a": {**endpoint, "port": 1023}}},
            {"endpoints": {"app-a": {**endpoint, "address": "192.0.2.1"}}},
            {"endpoints": {"bad/slot": endpoint}},
            {"endpoints": {"app-a": {**endpoint, "foreign": True}}},
        ]
        for inputs in invalid:
            with self.subTest(inputs=inputs):
                result = self.invoke("apply", inputs)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")

    def test_rejects_action_mismatch_and_invalid_observation_action(self):
        for action, desired in [("apply", "remove"), ("observe", "foreign")]:
            with self.subTest(action=action, desired=desired):
                result = self.invoke(action, {"service": "nginx.service"}, desired)
                self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
