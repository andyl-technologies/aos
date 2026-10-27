"""Compares registry browser package contracts without claiming DOM execution."""

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from verify_worker import artifact, public_exports, wasm_exports


def binding_export_contract(exports):
    """Retains closure signatures while normalizing their Rust crate identities."""
    result = {}
    for name, kind in public_exports(exports).items():
        normalized = name
        if re.match(r"wasm_bindgen_[0-9a-f]{16}___convert__closures_____invoke___", name):
            # These generated closure names embed rustc's crate disambiguators.
            # Cargo and Bazel assign different identities to the same dependency.
            # Keep the full signature and collision suffix; normalize only the
            # embedded identities of these two pinned binding crates.
            normalized = re.sub(r"(wasm_bindgen|js_sys)_[0-9a-f]{16}(?=___)", r"\1_CRATE", name)
        if normalized in result:
            raise ValueError("registry binding export normalization merged distinct symbols")
        result[normalized] = kind
    return result


def one_file(directory, pattern):
    paths = list(directory.glob(pattern))
    if len(paths) != 1:
        raise ValueError(f"expected one {pattern} in {directory}")
    return paths[0]


def javascript_exports(node, path):
    # Importing the glue checks its syntax and API without calling the browser
    # entry point. The .mjs extension makes the module mode explicit to Node.
    with tempfile.TemporaryDirectory(prefix="aos-registry-glue-") as directory:
        module = Path(directory) / "bindings.mjs"
        shutil.copyfile(path, module)
        script = """
const {pathToFileURL} = require('node:url');
import(pathToFileURL(process.argv[1]).href).then(module => {
    process.stdout.write(JSON.stringify(Object.fromEntries(
        Object.entries(module).map(([name, value]) => [name, typeof value]))));
}).catch(error => { console.error(error); process.exit(1); });
"""
        return json.loads(subprocess.check_output([str(node), "-e", script, str(module)], text=True))


def verify(bazel, cargo, stylesheet, node):
    distributions = {}
    for role, root in [("bazel", bazel), ("cargo", cargo)]:
        directory = root / "dist"
        javascript = one_file(directory, "*.js")
        wasm = one_file(directory, "*_bg.wasm")
        css = one_file(directory, "*.css")
        typescript = directory / (javascript.stem + ".d.ts")
        wasm_typescript = directory / (wasm.name + ".d.ts")
        expected = {javascript, wasm, css, typescript, wasm_typescript}
        if set(directory.iterdir()) != expected or not all(path.is_file() for path in expected):
            raise ValueError(f"incomplete {role} registry distribution")
        if css.read_bytes() != stylesheet.read_bytes():
            raise ValueError(f"{role} registry stylesheet differs from source")
        url = "new URL('" + wasm.name + "', import.meta.url)"
        if javascript.read_text().count(url) != 1:
            raise ValueError(f"{role} glue lost its deployed relative Wasm URL")
        if role == "bazel":
            if not re.fullmatch(r"app-[0-9a-f]{64}", javascript.stem):
                raise ValueError("registry bindings require immutable hash names")
            if wasm.name != javascript.stem + "_bg.wasm":
                raise ValueError("registry glue and Wasm filenames disagree")
            if css.name != "style-" + artifact(css)["sha256"] + ".css":
                raise ValueError("registry stylesheet name does not identify its bytes")

        exports = binding_export_contract(wasm_exports(node, wasm))
        if exports.get("__wbindgen_start") != "function":
            raise ValueError(f"{role} registry module lost its SPA start function")
        script_exports = javascript_exports(node, javascript)
        if any(script_exports.get(name) != "function" for name in ["default", "initSync"]):
            raise ValueError(f"{role} glue lost its initialization API")
        distributions[role] = {
            "wasm_exports": exports, "javascript_exports": script_exports,
            "artifacts": {path.relative_to(root).as_posix(): artifact(path) for path in sorted(expected)},
            "raw_wasm_exports": public_exports(wasm_exports(node, root / "registry-spa.wasm")),
        }

    for key in ["wasm_exports", "javascript_exports", "raw_wasm_exports"]:
        if distributions["bazel"][key] != distributions["cargo"][key]:
            raise ValueError(f"Bazel/Cargo registry {key} differ")
    return {
        "status": "PASS", "distributions": distributions,
        "runtime_scope": "Wasm module validation and JavaScript module import; browser DOM mounting and generated-page loading require separate checks.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["bazel", "cargo", "stylesheet", "node", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    result = verify(options.bazel, options.cargo, options.stylesheet, options.node)
    options.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
