"""Checks compiler-option evidence without collapsing distinct build units."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from verify_compiler_options import audit, cargo_compilation_source, compiler_options, pair_invocations
from retain_compiler_inputs import command_digest


class CompilerOptionsTests(unittest.TestCase):
    def invocation(self, arguments=(), source="crates/shared/example/src/lib.rs"):
        return {"source": source, "arguments": ["rustc", source, "--edition=2024", *arguments]}

    def test_cargo_source_mapping_survives_workspace_layout_changes(self):
        for domain in ["bindings", "core", "packages", "registry", "shared"]:
            with self.subTest(domain=domain):
                source = domain + "/example/src/lib.rs"
                self.assertEqual(cargo_compilation_source({
                    "directory": "/build/source/crates", "arguments": ["rustc", source],
                }), "crates/" + source)

        self.assertEqual(cargo_compilation_source({
            "directory": "/build/source/crates/bindings/example",
            "arguments": ["rustc", "src/../lib.rs"],
        }), "crates/bindings/example/lib.rs")

    def test_cargo_source_mapping_excludes_registry_and_escaped_paths(self):
        for source in ["/build/cargo/registry/example/src/lib.rs", "../registry/src/lib.rs"]:
            with self.subTest(source=source):
                self.assertIsNone(cargo_compilation_source({
                    "directory": "/build/source/crates", "arguments": ["rustc", source],
                }))

        with self.assertRaisesRegex(ValueError, "ambiguous first-party compilation source"):
            cargo_compilation_source({
                "directory": "/build/source/crates",
                "arguments": ["rustc", "core/a/lib.rs", "core/b/lib.rs"],
            })

    def test_scalar_profile_overrides_use_the_last_explicit_value(self):
        options = compiler_options([
            "--codegen=opt-level=0", "-C", "opt-level=s", "--codegen", "debuginfo=2", "-Cdebuginfo=0",
        ])
        self.assertEqual(options["effective_scalar_codegen"], {"opt-level": "s", "debuginfo": "0"})
        self.assertEqual(options["codegen"], ["opt-level=0", "opt-level=s", "debuginfo=2", "debuginfo=0"])

    def test_repeated_link_and_unknown_options_retain_every_value_in_order(self):
        options = compiler_options(["-Clink-arg=-lfirst", "-Clink-arg=-lsecond", "-Cfuture-option=one", "-Cfuture-option=two"])
        self.assertEqual(options["codegen"], ["link-arg=-lfirst", "link-arg=-lsecond", "future-option=one", "future-option=two"])
        self.assertEqual(options["effective_scalar_codegen"], {})

    def test_missing_and_empty_option_values_fail_closed(self):
        for arguments in [["-C"], ["--cfg"], ["-C" , ""], ["-C=invalid"], ["--edition="], ["-Copt-level="]]:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                compiler_options(arguments)

    def test_profile_and_target_differences_remain_visible_after_feature_pairing(self):
        bazel = self.invocation(["--cfg=feature=\"fixture\"", "--target=x86_64-unknown-linux-gnu", "-Cdebug-assertions=yes"])
        cargo = self.invocation(["--cfg", "feature=\"fixture\"", "-C", "debug-assertions=on", "-Cincremental=/target"])
        report = pair_invocations([bazel], [cargo])[0]
        self.assertEqual(report["differences"]["target"], {"bazel": "x86_64-unknown-linux-gnu", "cargo": None})
        self.assertEqual(report["differences"]["effective_scalar_codegen"]["cargo"], {"debug-assertions": "on", "incremental": "/target"})

    def test_feature_and_edition_drift_rejects_the_audit(self):
        for argument in ["--cfg=feature=\"extra\"", "--edition=2021"]:
            with self.subTest(argument=argument), self.assertRaisesRegex(ValueError, "compiler .* differs"):
                pair_invocations([self.invocation([argument])], [self.invocation()])

    def test_library_and_libtest_views_are_distinct_units(self):
        invocations = [self.invocation(), self.invocation(["--test"])]
        report = pair_invocations(invocations, list(reversed(invocations)))
        self.assertEqual([pair["test"] for pair in report], [False, True])

    def test_missing_duplicate_and_empty_unit_inventories_fail_closed(self):
        unit = self.invocation()
        for bazel, cargo in [([], []), ([unit], []), ([unit, unit], [unit]), ([unit], [unit, unit])]:
            with self.subTest(bazel=bazel, cargo=cargo), self.assertRaises(ValueError):
                pair_invocations(bazel, cargo)

    def test_audit_rejects_stale_retained_response_file_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir()
            source = "crates/shared/example/src/lib.rs"
            arguments = [source, "--edition=2024", "-Clink-arg=literal$(value)"]
            prefix = ["process_wrapper", "--", "rustc"]
            graph = {"targets": [{"id": "1", "label": "//crates/shared/example:lib"}], "actions": [
                {"targetId": "1", "mnemonic": "Rustc", "arguments": [*prefix, *arguments]},
            ]}
            event = {
                "targetLabel": "//crates/shared/example:lib", "mnemonic": "Rustc",
                "commandArgs": [*prefix, "@unit.params"], "exitCode": 0, "cacheHit": False,
                "runner": "linux-sandbox", "inputs": [{"path": "unit.params", "digest": {
                    "hash": hashlib.sha256(("\n".join(arguments) + "\n").encode()).hexdigest(),
                }}],
            }
            (evidence / "execution.json").write_text(json.dumps(event))
            graph_path = evidence / "actions.json"
            graph_path.write_text(json.dumps(graph))
            (root / "compiler-arguments.jsonl").write_text(json.dumps({
                "schema_version": 1, "directory": "/build/source/crates", "environment": {},
                "arguments": ["rustc", source.removeprefix("crates/"), "--edition=2024"],
            }) + "\n")

            report = audit(root, root)
            self.assertEqual(report["units"], 1)
            self.assertIn("link-arg=literal$(value)", report["pairs"][0]["bazel"]["options"]["codegen"])

            graph["actions"][0]["arguments"].append("-Cpanic=abort")
            graph_path.write_text(json.dumps(graph))
            with self.assertRaisesRegex(ValueError, "no unambiguous retained command"):
                audit(root, root)

    def test_audit_compares_generated_cfg_and_checks_its_executed_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir()
            source = "crates/shared/example/src/lib.rs"
            label = "//crates/shared/example:lib"
            command = ["wrapper", "--arg-file", "generated", "--", "rustc", source, "--edition=2024"]
            text = "--cfg=generated\n"
            digest = hashlib.sha256(text.encode()).hexdigest()
            graph = {"targets": [{"id": "1", "label": label}], "actions": [
                {"targetId": "1", "mnemonic": "Rustc", "arguments": command},
            ]}
            event = {"targetLabel": label, "mnemonic": "Rustc", "commandArgs": command, "exitCode": 0,
                     "cacheHit": False, "runner": "linux-sandbox", "environmentVariables": [],
                     "inputs": [{"path": "generated", "digest": {"hash": digest}}]}
            retained = {"schema_version": 1, "actions": [
                {"target_label": label, "command_sha256": command_digest(command),
                 "files": [{"flag": "--arg-file", "path": "generated"}]},
            ], "files": {"generated": {"text": text, "size": len(text), "sha256": digest}}}
            (evidence / "actions.json").write_text(json.dumps(graph))
            (evidence / "execution.json").write_text(json.dumps(event))
            retained_path = evidence / "compiler-inputs.json"
            retained_path.write_text(json.dumps(retained))
            (root / "compiler-arguments.jsonl").write_text(json.dumps({
                "schema_version": 1, "directory": "/build/source/crates", "environment": {},
                "arguments": ["rustc", source.removeprefix("crates/"), "--edition=2024", "--cfg=generated"],
            }) + "\n")

            report = audit(root, root)

            self.assertIn("wrapper-expanded", report["status"])
            self.assertEqual(report["pairs"][0]["bazel"]["options"]["cfg"], ["generated"])
            self.assertIn("indirect_inputs", report["inputs_sha256"])

            retained["files"]["generated"]["text"] = "--cfg=changed\n"
            retained_path.write_text(json.dumps(retained))
            with self.assertRaisesRegex(ValueError, "differs from execution digest"):
                audit(root, root)


if __name__ == "__main__":
    unittest.main()
