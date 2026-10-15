"""Checks refusal of incomplete registrations and substituted symbol providers."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "common_unit", Path(__file__).with_name("qemu-common-unit.py")
)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class RegistrationTests(unittest.TestCase):
    """Rejects apparently passing subsets and changed native commands."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.source = Path(self.directory.name)
        self.build = self.source / "build"
        (self.build / "meson-info").mkdir(parents=True)
        self.tests = []
        self.targets = []
        for name in RUNNER.NAMES:
            binary = str(self.build / "tests/unit" / name)
            self.tests.append({
                "name": name, "cmd": [binary, "--tap", "-k"],
                "timeout": 30, "protocol": "tap", "is_parallel": True,
                "env": {
                    "G_TEST_SRCDIR": str(self.source / "tests/unit"),
                    "G_TEST_BUILDDIR": str(self.build / "tests/unit"),
                },
                "suite": ["qemu:unit"],
            })
            self.targets.append({
                "name": name, "type": "executable", "filename": [binary],
                "installed": False,
            })

    def check(self):
        (self.build / "meson-info/intro-tests.json").write_text(json.dumps(self.tests))
        (self.build / "meson-info/intro-targets.json").write_text(json.dumps(self.targets))
        return RUNNER.registered_tests(self.source, self.build)

    def test_original_commands_selected(self):
        self.assertEqual(self.check(), self.tests)

    def test_missing_registration(self):
        self.tests.pop()
        with self.assertRaises(ValueError):
            self.check()

    def test_duplicate_registration(self):
        self.tests.append(dict(self.tests[0]))
        with self.assertRaises(ValueError):
            self.check()

    def test_substituted_command(self):
        self.tests[0]["cmd"] = ["true"]
        with self.assertRaises(ValueError):
            self.check()

    def test_changed_disposition(self):
        for field, value in (
            ("should_fail", True), ("protocol", "exitcode"), ("timeout", 60),
            ("env", {}), ("workdir", "/tmp"),
        ):
            with self.subTest(field=field):
                original = self.tests[0].copy()
                self.tests[0][field] = value
                with self.assertRaises(ValueError):
                    self.check()
                self.tests[0] = original

    def test_installed_or_substituted_target(self):
        self.targets[0]["installed"] = True
        with self.assertRaises(ValueError):
            self.check()


class SymbolTests(unittest.TestCase):
    """Rejects missing, weak, duplicate and unrelated archive definitions."""

    def setUp(self):
        self.lines = [
            f"libqemuutil.a:stubs_crucible-qmp-allocation.c.o:0000 T {symbol}"
            for symbol in RUNNER.SYMBOLS
        ]

    def test_strong_provider(self):
        self.assertEqual(len(RUNNER.defined_symbols("\n".join(self.lines), True)), 5)

    def test_missing_or_substituted_provider(self):
        variants = [
            self.lines[:-1], self.lines + [self.lines[0]],
            [line.replace(" T ", " W ") for line in self.lines],
            [line.replace("stubs_crucible-qmp-allocation.c.o", "unrelated.o") for line in self.lines],
        ]
        for lines in variants:
            with self.subTest(lines=lines), self.assertRaises(ValueError):
                RUNNER.defined_symbols("\n".join(lines), True)

    def test_binary_need_not_retain_unreferenced_functions(self):
        self.assertEqual(len(RUNNER.defined_symbols(self.lines[0])), 1)


if __name__ == "__main__":
    unittest.main()
