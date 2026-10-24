"""Exercises the static registry generator with the actual Bazel browser package."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


PACKAGE = '''[package]
name = "fixture"
description = "Registry packaging fixture"
license = "MIT"
maintainer = "fixture"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/fixturehash00001-fixture-1.0.0"
nar_hash = "sha256:abc"
nar_size = 1
closure_size = 1
source_drv = ""
source_nar_hash = ""
references = []
'''


def verify(apr, package):
    """Checks real asset staging and content-bearing pages without a web service."""
    with tempfile.TemporaryDirectory(prefix="aos-registry-staging-") as directory:
        root = Path(directory)
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(root / "home"),
            "XDG_CONFIG_HOME": str(root / "config"),
            "XDG_CACHE_HOME": str(root / "cache"),
            "XDG_DATA_HOME": str(root / "data"),
            "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
        }
        registry = root / "data/apm/registries/bazel-fixture"
        (registry / "packages/f").mkdir(parents=True)
        (registry / "registry.toml").write_text('[registry]\nname = "fixture"\ndescription = "Fixture registry"\n')
        (registry / "packages/f/fixture.toml").write_text(PACKAGE)

        for name, extra in [("plain", []), ("enhanced", ["--spa-dist", str(package / "dist")])]:
            subprocess.run(
                [str(apr), "web", "generate", "--registry", "bazel-fixture",
                 "--output", str(root / name), *extra],
                env=environment, check=True, capture_output=True, text=True,
            )

        assets = {}
        for source in sorted((package / "dist").iterdir()):
            if source.suffix not in [".js", ".wasm", ".css"]:
                continue
            staged = root / "enhanced/web" / source.name
            if staged.read_bytes() != source.read_bytes():
                raise ValueError(f"registry generator changed browser asset: {source.name}")
            assets[source.name] = hashlib.sha256(source.read_bytes()).hexdigest()
        if len(assets) != 3:
            raise ValueError("registry generator must stage all three browser assets")

        for relative in ["index.html", "browse/fixture.html"]:
            plain = (root / "plain" / relative).read_text()
            enhanced = (root / "enhanced" / relative).read_text()
            for page in [plain, enhanced]:
                if "Registry packaging fixture" not in page or "fixture" not in page:
                    raise ValueError(f"registry page lost its no-JS package content: {relative}")
                if "http://" in page or "https://" in page:
                    raise ValueError(f"registry fixture page acquired an off-origin asset: {relative}")
            if '<script type="module">' in plain:
                raise ValueError("plain registry page unexpectedly loads the SPA")
            if '<script type="module">' not in enhanced:
                raise ValueError("enhanced registry page lost its SPA loader")
            if any("/web/" + name not in enhanced for name in assets):
                raise ValueError(f"registry page does not load every staged asset: {relative}")

        relative = "web/packages/fixture.json"
        plain_snapshot = json.loads((root / "plain" / relative).read_text())
        if json.loads((root / "enhanced" / relative).read_text()) != plain_snapshot:
            raise ValueError("SPA staging changed the package JSON snapshot")
        return {
            "status": "PASS", "apr": str(apr), "browser_package": str(package),
            "staged_asset_sha256": assets, "pages": ["index.html", "browse/fixture.html"],
            "package_snapshot_unchanged": True,
            "runtime_scope": "Static generation and loader references; no browser DOM execution or HTTP service.",
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["apr", "package", "output"]:
        parser.add_argument("--" + name, type=Path, required=True)
    options = parser.parse_args()
    options.output.write_text(json.dumps(verify(options.apr, options.package), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
