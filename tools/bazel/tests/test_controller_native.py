"""Exercises fail-closed binding of retained ring products to compiler inputs."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_controller_native as native


class ControllerNativeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.build = Path(self.temporary.name)
        products = self.build / "native-inputs"
        products.mkdir()
        files = {}
        for number in range(32):
            path = products / f"{number}.o"
            path.write_bytes(f"native-product-{number}".encode())
            files[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        (self.build / "native-inputs.json").write_text(json.dumps(files))
        self.compiler = {
            "targetLabel": native.RING_LABEL, "mnemonic": "Rustc",
            "cacheHit": False, "exitCode": 0, "runner": "linux-sandbox",
            "inputs": [
                {"path": f"{native.NATIVE_DIRECTORY}/{name}", "digest": {"hash": digest}}
                for name, digest in files.items()
            ],
            "actualOutputs": [{
                "path": "libring.rlib",
                "digest": {"hashFunctionName": "SHA-256", "hash": "a" * 64, "sizeBytes": "100"},
            }],
        }
        self.script = {
            "targetLabel": f"@@{native.RING_REPOSITORY}//:_bs", "mnemonic": "CargoBuildScriptRun",
            "cacheHit": False, "exitCode": 0, "runner": "linux-sandbox",
        }
        mock = patch.object(native, "execution_events", return_value=[self.compiler, self.script])
        mock.start()
        self.addCleanup(mock.stop)

    def inspect(self):
        return native.inspect(self.build, Path("unused-readelf"), mapped=True)

    def test_changed_retained_product_is_rejected(self):
        (self.build / "native-inputs/0.o").write_bytes(b"changed")

        with self.assertRaisesRegex(ValueError, "retained native product changed"):
            self.inspect()

    def test_compiler_input_digest_must_match_retained_bytes(self):
        self.compiler["inputs"][0]["digest"]["hash"] = "b" * 64

        with self.assertRaisesRegex(ValueError, "differs from actual Rustc input"):
            self.inspect()

    def test_cached_compiler_action_does_not_qualify(self):
        self.compiler["cacheHit"] = True

        with self.assertRaisesRegex(ValueError, "unexpected cache result"):
            self.inspect()

    def test_unsandboxed_build_script_does_not_qualify(self):
        self.script["runner"] = "local"

        with self.assertRaisesRegex(ValueError, "build script did not use linux-sandbox"):
            self.inspect()

    def test_native_inventory_path_escape_is_rejected(self):
        inventory = self.build / "native-inputs.json"
        files = json.loads(inventory.read_text())
        files["../outside"] = files.pop("0.o")
        inventory.write_text(json.dumps(files))

        with self.assertRaisesRegex(ValueError, "escapes the retained directory"):
            self.inspect()

    def test_single_output_cannot_supply_all_four_controls(self):
        names = [
            "ordinary_strict", "ordinary_conservative",
            "mapped_strict", "mapped_conservative",
        ]

        with self.assertRaisesRegex(ValueError, "four distinct Nix outputs"):
            native.compare({name: self.build for name in names}, Path("unused"))


if __name__ == "__main__":
    unittest.main()
