"""Rejects dynamic artifacts, missing static inputs, and execution-flag leaks."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import verify_static_runtime


class StaticRuntimeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.build = self.root / "build"
        self.libraries = self.root / "libraries"
        (self.build / "evidence").mkdir(parents=True)
        self.inputs = []
        for name, archive in [("sqlite", "libsqlite3.a"), ("zstd", "libzstd.a"),
                              ("static", "libc.a"), ("static", "libm.a"), ("static", "libgcc_eh.a")]:
            path = self.libraries / name / "lib" / archive
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((name + archive).encode())
            identity = {} if name == "static" else {"package": str(self.libraries / name), "libraryFile": f"lib/{archive}"}
            (self.libraries / name / "closure.json").write_text(json.dumps(identity))
            self.inputs.append({"path": f"external/aos_native/{name}/lib/{archive}",
                                "digest": {"hash": hashlib.sha256(path.read_bytes()).hexdigest()}})
        self.inputs.extend({"path": f"external/aos_native/{name}/closure.json"}
                           for name in ["sqlite", "zstd", "static"])
        prefix = "//tools/bazel/tests/static-runtime:"
        self.events = [{"targetLabel": prefix + name, "mnemonic": mnemonic, "runner": "linux-sandbox",
                        "inputs": list(self.inputs), "commandArgs": ["rustc", "-Ctarget-feature=+crt-static", "-Crelocation-model=static"]}
                       for name, mnemonic in [("rust_app", "Rustc"), ("c_app", "CppLink")]]
        self.events.append({"targetLabel": prefix + "execution_macro", "mnemonic": "Rustc",
                            "runner": "linux-sandbox", "inputs": [], "commandArgs": ["rustc", "--crate-type=proc-macro"]})

    def verify(self):
        (self.build / "evidence/execution.json").write_text("\n".join(json.dumps(event) for event in self.events))
        graph = {"targets": [{"id": str(index), "label": event["targetLabel"]} for index, event in enumerate(self.events)],
                 "actions": [{"targetId": str(index), "mnemonic": event["mnemonic"], "arguments": event["commandArgs"]}
                             for index, event in enumerate(self.events)]}
        (self.build / "evidence/actions.json").write_text(json.dumps(graph))
        with patch.object(verify_static_runtime, "inspect_elf", return_value={}):
            return verify_static_runtime.verify(self.build, self.root / "package", self.libraries, Path("readelf"))

    def test_selected_archive_bytes_are_required_for_each_link(self):
        self.verify()
        self.events[0]["inputs"][0] = {**self.inputs[0], "digest": {"hash": "wrong"}}
        with self.assertRaisesRegex(ValueError, "exact archive/script bytes"):
            self.verify()

    def test_runtime_closure_is_an_independent_link_input(self):
        self.events[1]["inputs"] = [entry for entry in self.inputs
                                    if not entry["path"].endswith("/static/closure.json")]
        with self.assertRaisesRegex(ValueError, "realized library closure"):
            self.verify()

    def test_static_flags_cannot_reach_execution_macro(self):
        self.events[2]["commandArgs"].append("-Ctarget-feature=+crt-static")
        with self.assertRaisesRegex(ValueError, "guest flags reached execution"):
            self.verify()

    def test_static_target_requires_the_qualified_relocation_model(self):
        self.events[0]["commandArgs"].remove("-Crelocation-model=static")
        with self.assertRaisesRegex(ValueError, "did not receive relocation-model=static"):
            self.verify()

    def test_an_action_cache_hit_does_not_prove_sandboxed_link_execution(self):
        self.events[0]["runner"] = "disk cache hit"
        with self.assertRaisesRegex(ValueError, "actual sandboxed static link"):
            self.verify()

    def test_dynamic_imports_interpreters_and_static_pie_are_rejected(self):
        for header, program, dynamic in [("Type: DYN", "", ""), ("Type: EXEC", "INTERP", ""),
                                          ("Type: EXEC", "", "(NEEDED) libc.so.6")]:
            with self.subTest(header=header, program=program, dynamic=dynamic):
                with patch.object(subprocess, "check_output", side_effect=[header, program, dynamic]):
                    with self.assertRaisesRegex(ValueError, "classic static executable"):
                        verify_static_runtime.inspect_elf(Path("binary"), Path("readelf"))

    def test_retained_parameter_contents_must_match_executed_bytes(self):
        arguments = ["--crate-type=proc-macro", "--edition=2024"]
        event = {"targetLabel": "//fixture:macro", "mnemonic": "Rustc", "commandArgs": ["rustc", "@macro.params"],
                 "inputs": [{"path": "macro.params", "digest": {"hash": hashlib.sha256(("\n".join(arguments) + "\n").encode()).hexdigest()}}]}
        graph = {"targets": [{"id": "1", "label": event["targetLabel"]}], "actions": [{
            "targetId": "1", "mnemonic": "Rustc", "arguments": ["rustc", *arguments],
        }]}

        self.assertEqual(verify_static_runtime.expanded_command(graph, event), ["rustc", *arguments])

        graph["actions"][0]["arguments"].append("-Ctarget-feature=+crt-static")
        with self.assertRaisesRegex(ValueError, "parameter contents differ"):
            verify_static_runtime.expanded_command(graph, event)


if __name__ == "__main__":
    unittest.main()
