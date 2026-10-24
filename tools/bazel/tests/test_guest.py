"""Rejects guest metadata drift, missing runtime inputs, and CLI regressions."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "metadata"))
import verify_guest

SOURCE = """pub const WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION: u16 = 4;
pub const WHITEBOX_DOORBELL_ABIS: &[WhiteboxDoorbellAbi] =
    &[WHITEBOX_DOORBELL_X86_64_ABI, WHITEBOX_DOORBELL_AARCH64_ABI];
"""


class GuestTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.build = self.root / "build"
        self.package = self.root / "package"
        self.libraries = self.root / "libraries"
        (self.build / "evidence").mkdir(parents=True)
        (self.package / "bin").mkdir(parents=True)
        (self.package / "nix-support").mkdir()
        (self.package / "bin/crucible-guest").write_bytes(b"guest")
        self.source = self.root / "doorbell_abi.rs"
        self.source.write_text(SOURCE)
        self.metadata = self.package / "nix-support/crucible-guest-build-info"
        self.metadata.write_text(verify_guest.build_info(self.source.read_text(), "x86_64-linux"))
        inputs = []
        for name in ["lib/libc.a", "lib/libm.a", "lib/libgcc_eh.a", "closure.json"]:
            path = self.libraries / "static" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}" if name == "closure.json" else name)
            inputs.append({"path": "external/aos_native/static/" + name,
                           "digest": {"hash": hashlib.sha256(path.read_bytes()).hexdigest()}})
        self.event = {"targetLabel": "//crates/crucible/crucible-guest:crucible-guest",
                      "mnemonic": "Rustc", "runner": "linux-sandbox", "inputs": inputs}
        (self.build / "evidence/actions.json").write_text("{}")
        self.command = ["rustc", "-Ctarget-feature=+crt-static", "-Crelocation-model=static"]
        self.results = [subprocess.CompletedProcess([], 0, "help", "")] * 12

    def verify(self):
        with patch.object(verify_guest, "execution_events", return_value=[self.event]), \
                patch.object(verify_guest, "expanded_command", return_value=self.command), \
                patch.object(subprocess, "check_output", side_effect=["Type: EXEC", "", ""]), \
                patch.object(subprocess, "run", side_effect=self.results):
            return verify_guest.verify(self.build, self.package, self.libraries, self.root / "cargo",
                                       self.source, "x86_64-linux", Path("readelf"))

    def test_installed_metadata_must_match_the_canonical_abi(self):
        self.verify()
        self.metadata.write_text(self.metadata.read_text().replace("x86_64-linux", "aarch64-linux"))
        with self.assertRaisesRegex(ValueError, "metadata differs"):
            self.verify()

    def test_cached_links_cannot_prove_execution_or_static_inputs(self):
        self.event["cacheHit"] = True
        with self.assertRaisesRegex(ValueError, "actual sandboxed guest link"):
            self.verify()

    def test_runtime_bytes_are_required(self):
        self.event["inputs"][0]["digest"]["hash"] = "wrong"
        with self.assertRaisesRegex(ValueError, "exact static runtime input"):
            self.verify()

    def test_static_relocation_flags_are_required(self):
        self.command.remove("-Crelocation-model=static")
        with self.assertRaisesRegex(ValueError, "omitted relocation-model=static"):
            self.verify()

    def test_cli_status_and_both_output_streams_must_match(self):
        self.results[1] = subprocess.CompletedProcess([], 1, "help", "regression")
        with self.assertRaisesRegex(ValueError, "CLI differs"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
