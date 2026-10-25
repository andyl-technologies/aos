"""Checks artifact-derived native roles without profile-based inference."""

from copy import deepcopy
import importlib.util
from pathlib import Path
import unittest


path = Path(__file__).resolve().parents[1] / "qualification/native_compiler_units.py"
spec = importlib.util.spec_from_file_location("native_compiler_units", path)
units = importlib.util.module_from_spec(spec)
spec.loader.exec_module(units)
classify = units.classify
linux_outputs = units.linux_outputs


def invocation(name, source, suffix, dependencies=(), kind="lib"):
    arguments = ["--crate-name", name, source, "--crate-type", kind,
                 "--out-dir", "/build/target/debug/deps", "-Cextra-filename=-" + suffix]
    for alias, filename in dependencies:
        arguments.extend(["--extern", alias + "=" + filename])
    return {"schema_version": 1, "directory": "/build/source", "arguments": arguments}


def artifact(source, kind="lib"):
    return {"reason": "compiler-artifact", "target": {"src_path": source, "kind": [kind]}}


class NativeCompilerUnitsTests(unittest.TestCase):
    def fixture(self):
        invocations = [
            invocation("app", "/source/app.rs", "app", [
                ("target_dependency", "/build/target/debug/deps/libdependency-target.rlib"),
                ("macro", "/build/target/debug/deps/libmacro-macro.so"),
            ]),
            invocation("dependency", "/vendor/dependency.rs", "target"),
            invocation("macro", "/vendor/macro.rs", "macro", [
                ("execution_dependency", "/build/target/debug/deps/libdependency-exec.rlib"),
            ], kind="proc-macro"),
            invocation("dependency", "/vendor/dependency.rs", "exec"),
        ]
        messages = [artifact("/source/app.rs"), artifact("/vendor/dependency.rs"), artifact("/vendor/macro.rs", "proc-macro")]
        return invocations, messages, {"/source/app.rs"}

    def test_same_source_in_one_directory_has_distinct_target_and_execution_units(self):
        invocations, messages, targets = self.fixture()
        for row in invocations:
            row["arguments"].append("-Copt-level=3")

        report = classify(invocations, messages, targets)

        self.assertEqual([unit["role"] for unit in report["units"]], ["target", "target", "execution", "execution"])
        self.assertEqual(report["units"][0]["dependencies"], [1, 2])
        self.assertEqual(report["units"][2]["dependencies"], [3])
        self.assertEqual(report["excluded_invocations"], [])

    def test_custom_build_root_selects_execution_dependencies_without_a_target_consumer(self):
        invocations, messages, targets = self.fixture()
        invocations.extend([
            invocation("build_script_build", "/source/build.rs", "script", [
                ("execution_dependency", "/build/target/debug/deps/libdependency-exec.rlib"),
            ], kind="bin"),
        ])
        messages.append(artifact("/source/build.rs", "custom-build"))

        report = classify(invocations, messages, targets)

        self.assertEqual(report["units"][-1]["role"], "execution")
        self.assertEqual(report["units"][-1]["dependencies"], [3])

    def test_queries_and_unreported_build_probes_stay_explicitly_excluded(self):
        invocations, messages, targets = self.fixture()
        invocations.extend([
            {"schema_version": 1, "directory": "/build", "arguments": ["--print=cfg"]},
            invocation("probe", "/build/probe.rs", "probe"),
        ])

        report = classify(invocations, messages, targets)

        self.assertEqual(len(report["units"]), 4)
        self.assertEqual([row["reason"] for row in report["excluded_invocations"]],
                         ["compiler query", "source has no Cargo compiler artifact"])

    def test_missing_extern_owner_and_unreachable_unit_fail_closed(self):
        invocations, messages, targets = self.fixture()
        invocations[0]["arguments"][-1] = "missing=/build/target/debug/deps/libmissing-x.rlib"
        with self.assertRaisesRegex(ValueError, "no compiler artifact owner"):
            classify(invocations, messages, targets)

        invocations, messages, targets = self.fixture()
        invocations.append(invocation("orphan", "/vendor/orphan.rs", "orphan"))
        messages.append(artifact("/vendor/orphan.rs"))
        with self.assertRaisesRegex(ValueError, "unreachable"):
            classify(invocations, messages, targets)

    def test_duplicate_output_and_cross_role_artifact_reuse_fail_closed(self):
        invocations, messages, targets = self.fixture()
        invocations.append(deepcopy(invocations[1]))
        with self.assertRaisesRegex(ValueError, "ambiguous native compiler artifact owner"):
            classify(invocations, messages, targets)

        invocations, messages, targets = self.fixture()
        invocations[0]["arguments"].extend(["--extern", "shared=/build/target/debug/deps/libdependency-exec.rlib"])
        with self.assertRaisesRegex(ValueError, "shared by target and execution"):
            classify(invocations, messages, targets)

    def test_missing_or_conflicting_root_sources_fail_closed(self):
        invocations, messages, targets = self.fixture()
        with self.assertRaisesRegex(ValueError, "omitted a declared compiler source"):
            classify(invocations, messages, targets | {"/source/missing.rs"})
        with self.assertRaisesRegex(ValueError, "execution root was also declared as a target root"):
            classify(invocations, messages, targets | {"/vendor/macro.rs"})

    def test_sysroot_macro_extern_is_retained_and_unsupported_bare_extern_is_rejected(self):
        invocations, messages, targets = self.fixture()
        invocations[2]["arguments"].extend(["--extern", "proc_macro"])

        report = classify(invocations, messages, targets)

        self.assertEqual(report["sysroot_externs"], [{"unit": 2, "name": "proc_macro"}])
        invocations[2]["arguments"][-1] = "unknown"
        with self.assertRaisesRegex(ValueError, "omitted its artifact path"):
            classify(invocations, messages, targets)

    def test_linkable_library_artifact_kinds_and_implicit_test_binary_are_preserved(self):
        row = invocation("ffi", "/source/ffi.rs", "ffi", kind="rlib,staticlib,cdylib")

        outputs, kinds = linux_outputs(row["arguments"])

        self.assertEqual(kinds, {"rlib", "staticlib", "cdylib"})
        self.assertEqual(outputs, ["/build/target/debug/deps/libffi-ffi.a", "/build/target/debug/deps/libffi-ffi.rlib",
                                   "/build/target/debug/deps/libffi-ffi.rmeta", "/build/target/debug/deps/libffi-ffi.so"])
        arguments = row["arguments"]
        index = arguments.index("--crate-type")
        del arguments[index:index + 2]
        arguments.append("--test")
        self.assertEqual(linux_outputs(arguments), (["/build/target/debug/deps/ffi-ffi"], {"bin"}))
        arguments.extend(["-o", "/build/custom-output"])
        with self.assertRaisesRegex(ValueError, "explicit native output paths"):
            linux_outputs(arguments)


if __name__ == "__main__":
    unittest.main()
