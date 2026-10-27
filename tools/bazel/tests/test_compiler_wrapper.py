"""Checks indirect compiler options without shell parsing or inferred defaults."""

import unittest

from compiler_wrapper import expand_wrapper, logical_lines, wrapper_options


class CompilerWrapperTests(unittest.TestCase):
    def test_repeated_flags_accept_multiple_values_and_preserve_order(self):
        options, child = wrapper_options([
            "wrapper", "--arg-file", "first", "second", "--env-file", "environment",
            "--arg-file", "third", "--", "rustc", "source.rs",
        ])

        self.assertEqual(options["--arg-file"], ["first", "second", "third"])
        self.assertEqual(child, ["rustc", "source.rs"])

    def test_unknown_flags_missing_values_and_duplicate_scalars_fail(self):
        prefixes = [["--future-file", "input"], ["--arg-file"], ["unflagged"],
                    ["--out-dir", "one", "two"], ["--out-dir", "one", "--out-dir", "two"],
                    ["--env-file=unsupported"]]
        for prefix in prefixes:
            with self.subTest(prefix=prefix), self.assertRaises(ValueError):
                wrapper_options(["wrapper", *prefix, "--", "rustc"])
        with self.assertRaisesRegex(ValueError, "missing Rust wrapper child"):
            wrapper_options(["wrapper", "--"])

    def test_line_endings_and_continuations_match_the_pinned_wrapper(self):
        text = "literal $(value)\r\n\ncontinued\\\n\nnext\npaired\\\\\nfinal\r"

        self.assertEqual(logical_lines(text), ["literal $(value)", "continued\nnext", "paired\\", "final\r"])
        self.assertEqual(logical_lines("unterminated\\"), [])
        self.assertEqual(logical_lines("one\u2028two\n"), ["one\u2028two"])

    def test_environment_precedence_status_and_substitution_order_are_explicit(self):
        command = [
            "wrapper", "--env-file", "first", "second", "--stable-status-file", "stable",
            "--volatile-status-file", "volatile", "--subst", "one=replaced", "two=${one}",
            "--", "rustc", "${one}", "${two}",
        ]
        files = {
            "first": "VALUE=first\nKEEP=literal $(value)\n",
            "second": "VALUE=${one}:{BUILD}:{NEXT}\n",
            "stable": "BUILD {NEXT}\n", "volatile": "NEXT final\n",
        }

        result = expand_wrapper(command, {"VALUE": "ambient", "INHERITED": "kept"}, files, {})

        self.assertEqual(result["arguments"], ["rustc", "replaced", "${one}"])
        self.assertEqual(result["environment"], {
            "VALUE": "replaced:final:final", "KEEP": "literal $(value)", "INHERITED": "kept",
        })

    def test_out_dir_and_indirect_arguments_override_in_the_original_order(self):
        command = [
            "wrapper", "--subst", "pwd=${pwd}", "--out-dir", "build/generated",
            "--env-file", "env", "--arg-file", "args", "--", "rustc", "-Copt-level=0",
        ]
        result = expand_wrapper(command, {}, {
            "env": "OUT_DIR=stale\nGENERATED=${pwd}/${out_dir}/file\n",
            "args": "-Copt-level=s\n--cfg=generated\n",
        }, {"pwd": "/explicit/action/root"})

        self.assertEqual(result["arguments"], ["rustc", "-Copt-level=0", "-Copt-level=s", "--cfg=generated"])
        self.assertEqual(result["environment"]["OUT_DIR"], "/explicit/action/root/build/generated")
        self.assertEqual(result["environment"]["GENERATED"], "/explicit/action/root/build/generated/file")

    def test_unstable_allowlist_is_added_only_when_the_wrapper_requires_it(self):
        prefix = ["wrapper", "--require-explicit-unstable-features", "true", "--", "rustc"]
        self.assertEqual(expand_wrapper(prefix, {}, {}, {})["arguments"], ["rustc", "-Zallow-features="])
        for flag in ["-Zallow-features=chosen", "allow-features=chosen"]:
            self.assertEqual(expand_wrapper([*prefix, flag], {}, {}, {})["arguments"], ["rustc", flag])

    def test_missing_or_unretained_inputs_and_invalid_records_fail_closed(self):
        cases = [
            (["--arg-file", "missing"], {}, "missing retained"),
            (["--env-file", "env"], {"env": "not-an-assignment\n"}, "invalid Rust wrapper environment"),
            (["--stable-status-file", "status"], {"status": "invalid\n"}, "invalid Rust wrapper status"),
            (["--subst", "pwd=${pwd}"], {}, "missing explicit"),
            (["--subst", "invalid"], {}, "invalid Rust wrapper substitution"),
            (["--arg-file", "args"], {"args": "@unretained.params\n"}, "nested response file"),
        ]
        for prefix, files, error in cases:
            with self.subTest(prefix=prefix), self.assertRaisesRegex(ValueError, error):
                expand_wrapper(["wrapper", *prefix, "--", "rustc"], {}, files, {})


if __name__ == "__main__":
    unittest.main()
