"""Builds the complete Worker deployment from declared Wasm and asset inputs."""

import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile


STATIC_ASSETS = {
    "style.css": "style.css",
    "app.js": "app.js",
    "theme.js": "theme.js",
    "Geist-Variable.woff2": "geist-sans-variable.woff2",
    "GeistMono-Variable.woff2": "geist-mono-variable.woff2",
    "OFL.txt": "OFL.txt",
}
CONSOLE_ASSETS = ["hub-console.js", "hub-console_bg.wasm", "hub-console.css"]


def install_assets(static, console, output):
    """Preserves the production asset names, content key and cache policy."""
    assets = output / "_assets"
    assets.mkdir(parents=True)
    for source, destination in STATIC_ASSETS.items():
        shutil.copyfile(static / source, assets / destination)

    version_input = b"".join((static / name).read_bytes() for name in ["style.css", "app.js", "theme.js"])
    version_input += b"".join((console / name).read_bytes() for name in CONSOLE_ASSETS)
    version_input += b"bootstrap-api=object-v1\n"
    version = hashlib.sha256(version_input).hexdigest()[:8]
    for source, destination in zip(CONSOLE_ASSETS, [
        f"hub-console-{version}.js", f"hub-console-{version}_bg.wasm", f"hub-console-{version}.css",
    ], strict=True):
        shutil.copyfile(console / source, assets / destination)

    (assets / f"hub-console-bootstrap-{version}.js").write_text(
        f"import init, {{ mount }} from './hub-console-{version}.js';\n\n"
        f"await init({{ module_or_path: new URL('./hub-console-{version}_bg.wasm', import.meta.url) }});\n"
        "mount();\n"
    )
    (output / "_headers").write_text(
        "/_assets/*\n  Cache-Control: public, max-age=86400\n\n"
        "/_assets/hub-console*\n  Cache-Control: public, max-age=31536000, immutable\n"
    )


def bundle(options):
    """Runs pinned source-built generators without tool discovery or downloads."""
    with tempfile.TemporaryDirectory(prefix="aos-worker-bundle-") as temporary:
        build = Path(temporary) / "build"
        build.mkdir()
        subprocess.run([
            str(options.bindgen), "--target", "bundler", "--no-typescript",
            "--out-dir", str(build), "--out-name", "index", str(options.wasm),
        ], check=True)

        worker = build / "worker"
        worker.mkdir()
        (build / "index_bg.js").rename(worker / "index_bg.js")
        (build / "index_bg.wasm").rename(worker / "index.wasm")
        if (build / "snippets").is_dir():
            shutil.copytree(build / "snippets", worker / "snippets")
        for name in ["glue.js", "shim.js"]:
            shutil.copyfile(options.templates / name, worker / name)
        subprocess.run([
            str(options.node), str(options.templates / "rewrite.mjs"), str(worker / "index_bg.js"),
        ], check=True)
        subprocess.run([
            str(options.esbuild), "--external:./index.wasm", "--external:cloudflare:sockets",
            "--external:cloudflare:workers", "--format=esm", "--bundle", "./shim.js", "--outfile=shim.mjs",
        ], cwd=worker, check=True)

        if not options.test_hooks:
            for name in ["shim.mjs", "index.wasm"]:
                content = (worker / name).read_bytes()
                if any(marker in content for marker in [b"/_e2e/", b"aos_e2e_surface_", b"workerd-e2e"]):
                    raise ValueError("Worker test hooks leaked into the production deployment")
        for source, destination in [(worker / "shim.mjs", options.shim), (worker / "index.wasm", options.output_wasm)]:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)

    install_assets(options.static, options.console, options.assets)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["bindgen", "node", "esbuild", "templates", "wasm", "static", "console", "shim", "output-wasm", "assets"]:
        parser.add_argument("--" + name, required=True, type=lambda value: Path(value).resolve())
    parser.add_argument("--test-hooks", action="store_true")
    bundle(parser.parse_args())


if __name__ == "__main__":
    main()
