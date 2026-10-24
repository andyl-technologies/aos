"""Binds reconstructed compiler arguments and environment to actual input digests."""

import copy
import hashlib
import unittest

from reconstruct_compiler_inputs import reconstruct
from retain_compiler_inputs import command_digest


class CompilerInputReconstructionTests(unittest.TestCase):
    def setUp(self):
        self.command = ["wrapper", "--arg-file", "args", "--env-file", "env", "--", "rustc", "source.rs"]
        self.references = [{"flag": "--arg-file", "path": "args"}, {"flag": "--env-file", "path": "env"}]
        files = {"args": "--cfg=generated\n-Copt-level=s\n", "env": "EVIDENCE_VALUE=generated\n"}
        self.event = {
            "mnemonic": "Rustc", "exitCode": 0, "targetLabel": "//crates/example:lib", "commandArgs": self.command,
            "environmentVariables": [{"name": "EVIDENCE_VALUE", "value": "ambient"}],
            "inputs": [{"path": name, "digest": {"hash": hashlib.sha256(text.encode()).hexdigest()}}
                       for name, text in files.items()],
        }
        self.graph = {"targets": [{"id": "1", "label": self.event["targetLabel"]}],
                      "actions": [{"targetId": "1", "mnemonic": "Rustc", "arguments": self.command}]}
        self.retained = {
            "schema_version": 1,
            "actions": [{"target_label": self.event["targetLabel"], "command_sha256": command_digest(self.command),
                         "files": self.references}],
            "files": {name: {"text": text, "size": len(text.encode()), "sha256": hashlib.sha256(text.encode()).hexdigest()}
                      for name, text in files.items()},
        }

    def reconstruct(self):
        return reconstruct(self.graph, [self.event], self.retained)

    def test_generated_options_and_environment_retain_their_actual_values(self):
        result = self.reconstruct()["actions"][0]

        self.assertEqual(result["arguments"], ["rustc", "source.rs", "--cfg=generated", "-Copt-level=s"])
        self.assertEqual(result["environment"], {"EVIDENCE_VALUE": "generated"})

    def test_changed_bytes_size_and_self_reported_digest_are_independently_rejected(self):
        for field, value in [("text", "changed"), ("size", 0), ("sha256", "stale")]:
            with self.subTest(field=field):
                original = copy.deepcopy(self.retained)
                self.retained["files"]["args"][field] = value
                with self.assertRaisesRegex(ValueError, "differs from execution digest"):
                    self.reconstruct()
                self.retained = original
        self.event["inputs"][0]["digest"]["hash"] = "stale"
        with self.assertRaisesRegex(ValueError, "differs from execution digest"):
            self.reconstruct()

    def test_missing_extra_and_duplicate_action_records_reject_the_inventory(self):
        original = copy.deepcopy(self.retained)
        variants = [[], [*original["actions"], *original["actions"]],
                    [{**original["actions"][0], "command_sha256": "unexecuted"}],
                    [{**original["actions"][0], "files": []}]]
        for actions in variants:
            with self.subTest(actions=actions), self.assertRaisesRegex(ValueError, "action inventory differs"):
                self.retained["actions"] = actions
                self.reconstruct()

    def test_unconsumed_and_undeclared_file_records_are_rejected(self):
        self.retained["files"]["extra"] = copy.deepcopy(self.retained["files"]["args"])
        with self.assertRaisesRegex(ValueError, "unconsumed inputs"):
            self.reconstruct()
        del self.retained["files"]["extra"]
        self.event["inputs"] = []
        with self.assertRaisesRegex(ValueError, "missing executed or retained"):
            self.reconstruct()

    def test_failed_execution_and_ambiguous_environment_fail_closed(self):
        self.event["exitCode"] = 1
        with self.assertRaisesRegex(ValueError, "failed Rust"):
            self.reconstruct()
        self.event["exitCode"] = 0
        self.event["environmentVariables"] *= 2
        with self.assertRaisesRegex(ValueError, "ambiguous executed"):
            self.reconstruct()


if __name__ == "__main__":
    unittest.main()
