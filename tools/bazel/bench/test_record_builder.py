"""Checks adopted-child reaping and fail-closed builder resource publication."""

import json
import os
from pathlib import Path
import signal
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import record_builder


def resources(cpu, rss):
    return SimpleNamespace(ru_utime=cpu, ru_stime=cpu / 2, ru_maxrss=rss,
                           ru_inblock=3, ru_oublock=4)


class BuilderRecorderTests(unittest.TestCase):
    def run_builder(self, output, children, structured=False):
        process = SimpleNamespace(pid=17, returncode=None)
        environment = dict(os.environ)
        environment.pop("out", None)
        if structured:
            attributes = output.parent / "attributes.json"
            attributes.write_text(json.dumps({"outputs": {"out": str(output)}}))
            environment["NIX_ATTRS_JSON_FILE"] = str(attributes)
        else:
            environment["out"] = str(output)
        with (
            patch.dict(os.environ, environment, clear=True),
            patch.object(record_builder.subprocess, "Popen", return_value=process),
            patch.object(record_builder.os, "wait4", side_effect=[*children, ChildProcessError()]) as wait,
        ):
            status = record_builder.run(["original-builder"])
        self.assertTrue(all(call.args == (-1, 0) for call in wait.call_args_list))
        return status

    def test_adopted_jvm_is_reaped_before_the_original_builder(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            status = self.run_builder(output, [(29, 0, resources(5, 300)), (17, 0, resources(2, 100))])
            report = json.loads((output / "nix-support/benchmark-resources.json").read_text())
        self.assertEqual(status, 0)
        self.assertEqual(report["user_seconds"], 7)
        self.assertEqual(report["peak_rss_kib"], 300)
        self.assertEqual(report["waited_children"], 2)

    def test_structured_nix_attributes_resolve_the_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            status = self.run_builder(output, [(17, 0, resources(2, 100))], structured=True)
            self.assertTrue((output / "nix-support/benchmark-resources.json").is_file())
        self.assertEqual(status, 0)

    def test_failed_original_builder_cannot_publish_successful_resources(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            status = self.run_builder(output, [(29, 0, resources(5, 300)), (17, 7 << 8, resources(2, 100))])
            self.assertFalse(output.exists())
        self.assertEqual(status, 7)

    def test_terminated_original_builder_preserves_its_signal(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            status = self.run_builder(output, [(17, signal.SIGTERM, resources(2, 100))])
            self.assertFalse(output.exists())
        self.assertEqual(status, -signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
