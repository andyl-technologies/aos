"""Checks that indirect compiler inputs are retained with actual execution digests."""

import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from retain_compiler_inputs import action_candidates, command_digest, executed_command, retain, wrapper_files


class CompilerInputRetentionTests(unittest.TestCase):
    def graph(self, event):
        return {"targets": [{"id": "1", "label": event["targetLabel"]}], "actions": [
            {"targetId": "1", "mnemonic": "Rustc", "arguments": event["commandArgs"]},
        ]}

    def event(self, contents):
        command = ["process_wrapper", "--arg-file", "build/flags", "--env-file", "build/environment",
                   "--", "rustc", "source.rs"]
        return {"mnemonic": "Rustc", "targetLabel": "//crates/example:lib", "exitCode": 0,
                "commandArgs": command, "inputs": [
                    {"path": name, "digest": {"hash": hashlib.sha256(value).hexdigest()}}
                    for name, value in contents.items()
                ]}

    def test_every_wrapper_file_preserves_literal_bytes_and_repeated_use(self):
        contents = {"build/flags": b'-Clink-arg=literal$(value)\n--cfg=generated\n',
                    "build/environment": b'EXAMPLE=line\\ncontinued\n'}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "build").mkdir()
            for name, value in contents.items():
                (root / name).write_bytes(value)
            event = self.event(contents)
            result = retain(self.graph(event), [event, copy.deepcopy(event)], root)

            self.assertEqual(len(result["actions"]), 2)
            self.assertEqual(len(result["files"]), 2)
            self.assertEqual(result["files"]["build/flags"]["text"].encode(), contents["build/flags"])
            self.assertEqual(result["files"]["build/environment"]["text"].encode(), contents["build/environment"])
            self.assertEqual(result["actions"][0]["command_sha256"], command_digest(event["commandArgs"]))

    def test_changed_missing_and_undeclared_files_reject_retention(self):
        contents = {"build/flags": b'--cfg=original\n', "build/environment": b'VALUE=original\n'}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "build").mkdir()
            for name, value in contents.items():
                (root / name).write_bytes(value)
            event = self.event(contents)

            (root / "build/flags").write_bytes(b'--cfg=changed\n')
            with self.assertRaisesRegex(ValueError, "differs from execution digest"):
                retain(self.graph(event), [event], root)

            (root / "build/flags").unlink()
            with self.assertRaises(FileNotFoundError):
                retain(self.graph(event), [event], root)

            event["inputs"] = []
            with self.assertRaisesRegex(ValueError, "omitted from executed"):
                retain(self.graph(event), [event], root)

    def test_wrapper_outputs_and_compiler_arguments_are_not_mistaken_for_inputs(self):
        command = ["wrapper", "--stdout-file", "output/log", "--touch-file", "output/touch",
                   "--stable-status-file", "input/stable", "--volatile-status-file", "input/volatile",
                   "--", "rustc", "--arg-file", "compiler-argument"]
        self.assertEqual(wrapper_files(command), [
            {"flag": "--stable-status-file", "path": "input/stable"},
            {"flag": "--volatile-status-file", "path": "input/volatile"},
        ])

    def test_ambiguous_boundaries_and_noncanonical_paths_fail_closed(self):
        invalid = [["wrapper", "rustc"], ["wrapper", "--", "rustc", "--"],
                   ["wrapper", "--arg-file", "--", "rustc"],
                   ["wrapper", "--env-file=", "--", "rustc"]]
        invalid += [["wrapper", "--arg-file", path, "--", "rustc"]
                    for path in ["../escape", "/absolute", "input//file", "input/./file", "--env-file"]]
        for command in invalid:
            with self.subTest(command=command), self.assertRaises(ValueError):
                wrapper_files(command)

    def test_failed_rust_actions_reject_and_native_only_graphs_are_explicitly_empty(self):
        event = self.event({})
        event["exitCode"] = 1
        with self.assertRaisesRegex(ValueError, "failed Rust"):
            retain(self.graph(event), [event], Path("unused"))
        event["mnemonic"] = "CppCompile"
        self.assertEqual(retain({"targets": [], "actions": []}, [event], Path("unused")), {"schema_version": 1, "actions": [], "files": {}})

    def test_execution_and_target_configurations_match_the_actual_response_digest(self):
        prefix = ["wrapper", "--", "rustc"]
        arguments = ["source.rs", "--target=x86_64-unknown-linux-gnu"]
        event = {"mnemonic": "Rustc", "targetLabel": "//crates/example:lib", "commandArgs": [*prefix, "@compile.params"],
                 "inputs": [{"path": "compile.params", "digest": {
                     "hash": hashlib.sha256(("\n".join(arguments) + "\n").encode()).hexdigest(),
                 }}]}
        graph = {"targets": [{"id": "1", "label": event["targetLabel"]}], "actions": [
            {"targetId": "1", "mnemonic": "Rustc", "arguments": [*prefix, "source.rs", "--target=other"]},
            {"targetId": "1", "mnemonic": "Rustc", "arguments": [*prefix, *arguments]},
        ]}

        self.assertEqual(executed_command(action_candidates(graph), event), [*prefix, *arguments])
        event["inputs"][0]["digest"]["hash"] = "stale"
        with self.assertRaisesRegex(ValueError, "no unambiguous retained command"):
            executed_command(action_candidates(graph), event)

    def test_command_identity_preserves_argument_boundaries(self):
        self.assertNotEqual(command_digest(["one two", "three"]), command_digest(["one", "two three"]))

    def test_every_file_in_a_repeated_flag_group_is_retained(self):
        command = ["wrapper", "--arg-file", "build/one", "build/two", "--env-file", "build/env-one", "build/env-two",
                   "--arg-file", "build/three", "--", "rustc"]
        self.assertEqual(wrapper_files(command), [
            {"flag": "--arg-file", "path": path} for path in ["build/one", "build/two", "build/three"]
        ] + [{"flag": "--env-file", "path": path} for path in ["build/env-one", "build/env-two"]])

    def test_virtual_filewrite_inputs_require_exact_execution_digests(self):
        contents = {"build/flags": b'--cfg=virtual\n', "build/environment": b''}
        event = self.event(contents)
        graph = self.graph(event)
        graph["pathFragments"] = [{"id": "root", "label": "build"},
                                  {"id": "flags", "parentId": "root", "label": "flags"},
                                  {"id": "environment", "parentId": "root", "label": "environment"}]
        graph["artifacts"] = [{"id": name, "pathFragmentId": name} for name in ["flags", "environment"]]
        graph["actions"] += [
            {"targetId": "1", "mnemonic": "FileWrite", "outputIds": ["flags"], "fileContents": contents["build/flags"].decode()},
            {"targetId": "1", "mnemonic": "FileWrite", "outputIds": ["environment"]},
        ]
        with tempfile.TemporaryDirectory() as temporary:
            result = retain(graph, [event], Path(temporary))
            self.assertEqual(result["files"]["build/flags"]["text"], '--cfg=virtual\n')
            self.assertEqual(result["files"]["build/environment"]["size"], 0)

            graph["actions"][1]["fileContents"] = "stale"
            with self.assertRaisesRegex(ValueError, "differs from execution digest"):
                retain(graph, [event], Path(temporary))


if __name__ == "__main__":
    unittest.main()
