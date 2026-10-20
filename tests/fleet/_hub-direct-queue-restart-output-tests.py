"""Exercise bounded retention with real private local files, not a guest replay."""

import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import textwrap
import types
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().with_name("_hub-direct-queue-restart.py")
RUN = "a" * 64


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.previous = Path.cwd()
        os.chdir(self.base)
        self.operator = self.base / "operator"
        self.operator.mkdir(mode=0o700)
        self.root = self.operator / ("restart-" + RUN)
        self.root.mkdir(mode=0o700)
        for name, body in (("stdout.log", b"fixed fixture output\n"), ("stderr.log", b"fixed fixture failure\n")):
            path = self.root / name
            path.write_bytes(body)
            path.chmod(0o600)
        self.driver = {"runId": RUN, "root": "/var/lib/hybrid-worker/operator/restart-" + RUN,
                       "pid": 123, "ownerUid": os.getuid(), "startTicks": "456"}
        self.observation = {k: self.driver[k] for k in ("runId", "pid", "ownerUid", "startTicks")}
        self.observation.update({"category": "driver_status_unknown_after_original", "ready": True,
                                 "custody": False, "exitCode": None, "outputs": self.metadata()})
        self.module = types.ModuleType("candidate")
        exec(compile(SOURCE.read_text(), str(SOURCE), "exec"), self.module.__dict__)
        self.calls = []
        self.module.direct_guest_python = self.guest
        self.transforms = {}

    def tearDown(self):
        os.chdir(self.previous)
        self.temp.cleanup()

    def metadata(self):
        return {name: {"present": True, "custody": True, "byteSize": str((self.root / name).stat().st_size)}
                for name in ("stdout.log", "stderr.log")}

    def guest(self, worker, python, snippet, selected, timeout):
        self.calls.append(selected["name"])
        self.assertEqual(timeout, 10)
        original_open = os.open

        def mapped_open(path, flags, *args, **kwargs):
            if path == "/var/lib/hybrid-worker/operator":
                path = self.operator
            return original_open(path, flags, *args, **kwargs)

        output = io.StringIO()
        with patch("os.open", mapped_open), contextlib.redirect_stdout(output):
            exec(textwrap.dedent(snippet), {"selected": selected, "json": json})
        raw = output.getvalue()
        transform = self.transforms.get(selected["name"])
        return json.dumps(transform(json.loads(raw))) if transform else raw

    def retain(self):
        return self.module.retain_direct_restart_outputs(None, {"python": "source-built fixture"},
                                                         self.driver, self.observation)

    def test_positive_actual_files_private_and_unknown_process_preserved(self):
        result = self.retain()
        self.assertFalse(result["processCustody"])
        self.assertIsNone(result["exitCode"])
        self.assertEqual(self.calls, ["stdout.log", "stderr.log"])
        for record in result["files"]:
            self.assertEqual(record["state"], "retained")
            path = Path(record["file"])
            self.assertEqual(path.read_bytes(), (self.root / record["name"]).read_bytes())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertTrue(record["eof"])
            self.assertFalse(record["truncated"])

    def test_path_traversal_and_different_run_refused_before_dispatch(self):
        original = self.driver["root"]
        for root in (original + "/../other", original.replace(RUN, "b" * 64)):
            self.driver["root"] = root
            with self.assertRaises(ValueError):
                self.retain()
        self.assertEqual(self.calls, [])

    def test_symlink_file_or_directory_never_followed(self):
        path = self.root / "stderr.log"
        path.unlink()
        path.symlink_to(self.root / "stdout.log")
        result = self.retain()
        self.assertEqual(result["files"][0]["state"], "retained")
        self.assertEqual(result["files"][1]["state"], "refused_or_unknown")

    def test_symlink_directory_and_hardlinked_file_are_unknown(self):
        alternate = self.operator / "actual-private-directory"
        self.root.rename(alternate)
        self.root.symlink_to(alternate, target_is_directory=True)
        result = self.retain()
        self.assertEqual([r["state"] for r in result["files"]], ["refused_or_unknown"] * 2)

    def test_hardlinked_stream_refused_independently(self):
        os.link(self.root / "stderr.log", self.root / "second-link")
        result = self.retain()
        self.assertEqual([r["state"] for r in result["files"]], ["retained", "refused_or_unknown"])

    def test_foreign_owner_refused_without_process_claim(self):
        self.driver["ownerUid"] += 1
        self.observation["ownerUid"] = self.driver["ownerUid"]
        result = self.retain()
        self.assertEqual([r["state"] for r in result["files"]], ["refused_or_unknown"] * 2)
        self.assertIsNone(result["exitCode"])

    def test_missing_stream_does_not_erase_other_stream(self):
        (self.root / "stdout.log").unlink()
        result = self.retain()
        self.assertEqual([r["state"] for r in result["files"]], ["refused_or_unknown", "retained"])

    def test_oversize_retains_only_prefix_with_explicit_non_eof(self):
        (self.root / "stderr.log").write_bytes(b"x" * 65537)
        self.observation["outputs"] = self.metadata()
        result = self.retain()["files"][1]
        self.assertEqual(result["state"], "retained_prefix")
        self.assertEqual(result["byteSize"], 65536)
        self.assertEqual(Path(result["file"]).stat().st_size, 65536)
        self.assertFalse(result["eof"])
        self.assertTrue(result["truncated"])

    def test_partial_transport_or_changed_observed_size_is_unknown(self):
        self.transforms["stdout.log"] = lambda value: value | {"body": ""}
        self.observation["outputs"]["stderr.log"]["byteSize"] = "999"
        result = self.retain()
        self.assertEqual([r["state"] for r in result["files"]], ["refused_or_unknown"] * 2)

    def test_retention_precedes_original_readiness_refusal(self):
        self.module.observe_direct_restart_readiness = lambda *args: self.observation
        records = []
        self.module.retain_direct_flow = lambda name, body: records.append((name, body))
        with self.assertRaisesRegex(AssertionError, "readiness observation refused"):
            self.module.direct_restart_readiness(None, {"python": "fixture"}, self.driver)
        self.assertEqual(records[0][0], "queue-restart-readiness-failure.json")
        self.assertEqual(records[0][1]["category"], self.observation["category"])
        self.assertFalse(records[0][1]["custody"])
        for record in records[0][1]["childOutputs"]["files"]:
            self.assertTrue(Path(record["file"]).exists())
        self.assertEqual(self.calls, ["stdout.log", "stderr.log"])

    def test_exclusive_destination_preserves_existing_outputs(self):
        original = self.retain()
        with self.assertRaises(FileExistsError):
            self.retain()
        self.assertEqual(self.calls, ["stdout.log", "stderr.log"])
        self.assertTrue(Path(original["files"][0]["file"]).exists())


if __name__ == "__main__":
    unittest.main()
