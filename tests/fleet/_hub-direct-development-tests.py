"""Checks reduced-workload boundaries and queue latency accounting."""

import base64
import json
from pathlib import Path
import re
import statistics
import tempfile
import unittest


class DevelopmentTests(unittest.TestCase):
    def scenario(self, original):
        namespace = {"run_external_direct_fleet": original,
                     "prepare_external_direct_publication_sources": lambda *args: None, "json": json,
                     "re": re, "statistics": statistics, "Path": Path, "base64": base64}
        source = Path(__file__).with_name("_hub-direct-development.py")
        exec(compile(source.read_text(), str(source), "exec"), namespace)
        return namespace

    def test_only_the_explicit_completion_boundary_ends_setup(self):
        namespace = self.scenario(lambda: None)
        namespace["_ordinary_external_direct_fleet"] = lambda: (_ for _ in ()).throw(
            namespace["_DevelopmentPublicationComplete"]())
        self.assertIsNone(namespace["run_external_direct_fleet"]())

        def refused():
            raise ValueError("authority refused")

        namespace["_ordinary_external_direct_fleet"] = refused
        with self.assertRaisesRegex(ValueError, "authority refused"):
            namespace["run_external_direct_fleet"]()

    def test_missing_publication_boundary_is_a_failure(self):
        namespace = self.scenario(lambda: None)
        with self.assertRaisesRegex(RuntimeError, "completion boundary"):
            namespace["run_external_direct_fleet"]()

    def test_small_project_preserves_evaluated_inventory_and_other_runtime_inputs(self):
        namespace = self.scenario(lambda: None)
        with tempfile.TemporaryDirectory(prefix="aos-small-project-", dir="/tmp") as directory:
            inventory = Path(directory) / "inventory.json"
            project = Path(directory) / "default.nix"
            inventory.write_text('{"evaluatedPackage":"real-output"}')
            project.write_text("{crossSystem}: { releasePackageDerivations = "
                               + "builtins.fromJSON (builtins.readFile " + str(inventory) + "); }")
            namespace.update(DEVELOPMENT_PUBLICATION_INVENTORY=str(inventory),
                             DEVELOPMENT_PUBLICATION_PROJECT=str(project))
            writes, calls = [], []
            namespace["direct_guest_python"] = lambda client, python, script, selected: writes.append(selected)
            namespace["_ordinary_publication_sources"] = lambda client, tools: calls.append(tools)
            tools = {"python": "selected-python", "publicationProject": "large-project",
                     "workerUrl": "selected-origin", "providerPolicyFile": "selected-policy"}

            namespace["prepare_external_direct_publication_sources"]("client", tools)

            self.assertEqual(len(writes), 1)
            self.assertEqual(base64.b64decode(writes[0]["inventory.json"]), inventory.read_bytes())
            self.assertIn("builtins.readFile ./inventory.json", base64.b64decode(writes[0]["default.nix"]).decode())
            self.assertEqual(calls, [{**tools, "publicationProject": writes[0]["directory"]}])
            self.assertEqual(tools["publicationProject"], "large-project")

            project.write_text("inventory reference is missing")
            with self.assertRaisesRegex(ValueError, "ambiguous inventory"):
                namespace["prepare_external_direct_publication_sources"]("client", tools)
            self.assertEqual(len(writes), 1)

    def test_queue_retries_keep_original_wait_and_separate_active_attempts(self):
        namespace = self.scenario(lambda: None)
        rows = []
        for kind, outcome, at, attempt in (
                ("queue_enqueue", "positive", 100, "first"),
                ("queue_start", "pending", 150, "first"),
                ("queue_finish", "refused", 170, "first"),
                ("queue_retry", "refused", 170, "first"),
                ("queue_start", "pending", 250, "retry"),
                ("queue_finish", "positive", 280, "retry")):
            rows.append("direct_upload_observation " + json.dumps({
                "object": {"dependencyPhase": "visibility", "session": {"sessionDigest": "original"}},
                "kind": kind, "outcome": outcome, "atMillis": at, "attemptDigest": attempt}))
        rows.append("direct_stage_timing phase=provider_response_headers elapsed_millis=7 success=true")
        rows.append("direct_stage_timing phase=provider_response_headers elapsed_millis=99 success=false")
        rows.append("direct_stage_timing phase=unexpected_label elapsed_millis=123 success=true")

        result = namespace["_development_timing_summary"]("\n".join(rows))

        self.assertEqual(result["timings"]["visibility_enqueue_to_start"]["medianMillis"], 100)
        self.assertEqual(result["timings"]["visibility_active"]["medianMillis"], 25)
        self.assertEqual(result["timings"]["provider_response_headers"]["count"], 1)
        self.assertEqual(result["queueEvents"]["visibility:queue_retry:refused"], 1)
        self.assertNotIn("unexpected_label", result["timings"])


if __name__ == "__main__":
    unittest.main()
