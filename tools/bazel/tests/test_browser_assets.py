"""Checks immutable browser naming and the glue's actual relative module URL."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


specification = importlib.util.spec_from_file_location(
    "package_browser_assets", Path(__file__).parents[1] / "metadata/package_browser_assets.py",
)
packager = importlib.util.module_from_spec(specification)
specification.loader.exec_module(packager)


class BrowserAssetsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.javascript = self.root / "app.js"
        self.wasm = self.root / "app_bg.wasm"
        self.stylesheet = self.root / "style.css"
        self.javascript.write_text("const module = new URL('app_bg.wasm', import.meta.url);\n")
        self.wasm.write_bytes(b"\0asm\x01\0\0\0")
        self.stylesheet.write_text("body { color: blue; }\n")

    def package(self, name, **kwargs):
        output = self.root / name
        packager.package_assets(self.javascript, self.wasm, self.stylesheet, output, **kwargs)
        return output

    def test_distribution_preserves_bytes_and_loads_its_named_wasm(self):
        output = self.package("dist")
        wasm = next(output.glob("*_bg.wasm"))
        script = next(output.glob("*.js"))

        self.assertEqual(len(list(output.iterdir())), 3)
        self.assertEqual(wasm.read_bytes(), self.wasm.read_bytes())
        self.assertEqual(next(output.glob("*.css")).read_bytes(), self.stylesheet.read_bytes())
        self.assertIn("new URL('" + wasm.name + "', import.meta.url)", script.read_text())
        self.assertEqual(script.stem, wasm.name.removesuffix("_bg.wasm"))

    def test_js_only_changes_invalidate_the_pair_and_css_changes_stay_independent(self):
        original = {path.name for path in self.package("original").iterdir()}
        self.javascript.write_text(self.javascript.read_text() + "export const version = 2;\n")
        changed_script = {path.name for path in self.package("script").iterdir()}

        self.assertEqual(original & changed_script, {next(name for name in original if name.endswith(".css"))})

        self.stylesheet.write_text("body { color: red; }\n")
        changed_css = {path.name for path in self.package("css").iterdir()}
        self.assertEqual(changed_script & changed_css, {name for name in changed_script if not name.endswith(".css")})

    def test_missing_or_ambiguous_wasm_urls_fail_before_packaging(self):
        for script in ["const module = 'app_bg.wasm';", self.javascript.read_text() * 2]:
            with self.subTest(script=script):
                self.javascript.write_text(script)
                with self.assertRaisesRegex(ValueError, "exactly one relative Wasm"):
                    self.package("invalid")
                self.assertFalse((self.root / "invalid").exists())

    def test_type_declarations_follow_the_pair_and_partial_inputs_fail(self):
        typescript = self.root / "app.d.ts"
        wasm_typescript = self.root / "app_bg.wasm.d.ts"
        typescript.write_text("export type Module = typeof import('./app_bg.wasm');\n")
        wasm_typescript.write_text("export const memory: WebAssembly.Memory;\n")

        with self.assertRaisesRegex(ValueError, "both files"):
            self.package("partial", typescript=typescript)

        output = self.package("typed", typescript=typescript, wasm_typescript=wasm_typescript)
        wasm = next(output.glob("*_bg.wasm"))
        self.assertEqual(len(list(output.iterdir())), 5)
        self.assertIn(wasm.name, next(path for path in output.glob("*.d.ts") if not path.name.endswith(".wasm.d.ts")).read_text())
        self.assertEqual((output / (wasm.name + ".d.ts")).read_bytes(), wasm_typescript.read_bytes())


if __name__ == "__main__":
    unittest.main()
