# SPDX-License-Identifier: MIT
"""Checks the defining restored-temp rebinder without importing native m5."""

import ast
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest


class TemporaryRootRebinding(unittest.TestCase):
    def test_actual_private_root_rebinds_python_native_and_cached_views(self):
        source = Path(__file__).with_name("native-controller.py").read_text()
        module = ast.parse(source)
        function = next(node for node in module.body if isinstance(node, ast.FunctionDef)
                        and node.name == "rebind_operational_temporary_root")
        isolated = ast.Module(body=[function], type_ignores=[])
        namespace = {"os": os, "Path": Path, "sys": sys}
        exec(compile(isolated, str(Path(__file__).with_name("native-controller.py")), "exec"), namespace)
        rebind = namespace["rebind_operational_temporary_root"]
        original_cwd = Path.cwd()
        original_environment = {key: os.environ.get(key) for key in ("TMPDIR", "DMTCP_TMPDIR")}
        original_cache = tempfile.tempdir
        native = {}

        def setenv(key, value, overwrite):
            self.assertEqual(overwrite, 1)
            native[key] = value
            return 0

        try:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                tempfile.tempdir = "/old/source/temporary"
                rebind(os.fsencode(root), setenv, native.get)

                self.assertEqual(Path.cwd(), root)
                self.assertIsNone(tempfile.tempdir)
                self.assertEqual(os.environ["TMPDIR"], str(root))
                self.assertEqual(os.environ["DMTCP_TMPDIR"], str(root))
                self.assertEqual(native[b"TMPDIR"], os.fsencode(root))
                self.assertEqual(native[b"DMTCP_TMPDIR"], os.fsencode(root))
                self.assertEqual(Path(tempfile.gettempdir()), root)
                root.chmod(0o755)
                before = dict(native)
                with self.assertRaises(ValueError):
                    rebind(os.fsencode(root), setenv, native.get)
                self.assertEqual(native, before)
                root.chmod(0o700)
                os.chdir(original_cwd)
        finally:
            os.chdir(original_cwd)
            for key, value in original_environment.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            tempfile.tempdir = original_cache

    def test_failed_native_rebind_refuses_before_callback_route(self):
        source = Path(__file__).with_name("native-controller.py").read_text()
        node = next(node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)
                    and node.name == "rebind_operational_temporary_root")
        namespace = {"os": os, "Path": Path, "sys": sys}
        exec(compile(ast.Module(body=[node], type_ignores=[]), "temporary-rebind", "exec"), namespace)
        before = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                namespace["rebind_operational_temporary_root"](
                    os.fsencode(Path(directory).resolve()), lambda *args: -1, lambda key: None,
                )
        self.assertEqual(Path.cwd(), before)


if __name__ == "__main__":
    unittest.main()
