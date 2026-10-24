"""Packages wasm-bindgen browser assets with immutable, mutually consistent names."""

import argparse
import hashlib
from pathlib import Path
import re


def package_assets(javascript, wasm, stylesheet, output, typescript=None, wasm_typescript=None):
    """Names the complete binding pair together and retains its relative Wasm URL."""
    if (typescript is None) != (wasm_typescript is None):
        raise ValueError("browser type declarations must include both files")
    javascript_bytes = javascript.read_bytes()
    script = javascript_bytes.decode("utf-8")
    wasm_bytes = wasm.read_bytes()
    css = stylesheet.read_bytes()
    wasm_name = wasm.name
    pattern = r"new URL\((['\"])" + re.escape(wasm_name) + r"\1,\s*import\.meta\.url\)"
    if len(re.findall(pattern, script)) != 1:
        raise ValueError("browser glue must contain exactly one relative Wasm module URL")

    declarations = [path.read_bytes() for path in [typescript, wasm_typescript]] if typescript else []
    # The pair includes the glue: a JS-only change must invalidate the JS name
    # even when the compiled Wasm bytes remain identical.
    digest = hashlib.sha256()
    for data in [javascript_bytes, wasm_bytes, *declarations]:
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    stem = "app-" + digest.hexdigest()
    hashed_wasm = stem + "_bg.wasm"
    script = re.sub(pattern, lambda _: "new URL('" + hashed_wasm + "', import.meta.url)", script)

    files = {
        stem + ".js": script.encode("utf-8"),
        hashed_wasm: wasm_bytes,
        "style-" + hashlib.sha256(css).hexdigest() + ".css": css,
    }
    if declarations:
        files[stem + ".d.ts"] = declarations[0].replace(wasm_name.encode(), hashed_wasm.encode())
        files[hashed_wasm + ".d.ts"] = declarations[1]

    if output.exists() and any(output.iterdir()):
        raise ValueError("browser distribution output must be empty")
    output.mkdir(parents=True, exist_ok=True)
    for name, data in sorted(files.items()):
        (output / name).write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--javascript", type=Path, required=True)
    parser.add_argument("--wasm", type=Path, required=True)
    parser.add_argument("--stylesheet", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--typescript", type=Path)
    parser.add_argument("--wasm-typescript", type=Path)
    options = parser.parse_args()
    package_assets(**vars(options))


if __name__ == "__main__":
    main()
