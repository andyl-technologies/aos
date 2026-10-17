"""Controlled Mirror source renderer/custody tests; no APR, guest or provider proof."""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import textwrap
import unittest


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


source = load("_hub-external-mirror-source")
window = load("_hub-external-mirror-window")
lifecycle = load("_hub-direct-worker-lifecycle")
source.require_mirror_source_inventory = window.require_mirror_source_inventory


class SourceTests(unittest.TestCase):
    def tools(self):
        store = "/nix/store/" + "a" * 32
        return {"issuerCertificate": store + "-certificate/value", "issuerPrivateKey": store + "-key/value",
            "nginx": store + "-nginx/bin/nginx", "python": "controlled-python", "apr": "controlled-apr",
            "git": "controlled-git", "opensshBin": "controlled-ssh", "nixBin": "controlled-nix",
            "helperStorePath": store + "-hub-helper", "publicationProject": store + "-publication-project"}

    def test_upstream_is_selected_tls_run_surface_with_no_auth_header_log(self):
        run = "b" * 32
        root = "/var/lib/hybrid-worker/mirror-upstream/" + run
        configuration = source.mirror_upstream_configuration(run, root, self.tools())
        self.assertIn("listen 4778 ssl;", configuration)
        self.assertIn("location /fleet-mirror/" + run + "/", configuration)
        self.assertIn("alias " + root + "/surface/;", configuration)
        self.assertIn("location / { return 404; }", configuration)
        self.assertNotIn("$http_authorization", configuration)
        self.assertNotIn("$args", configuration)
        self.assertNotIn("proxy_pass", configuration)
        for field in ("nginx", "issuerCertificate", "issuerPrivateKey"):
            tools = self.tools()
            tools[field] = "/usr/bin/host-tool"
            with self.assertRaises(ValueError):
                source.mirror_upstream_configuration(run, root, tools)
        with self.assertRaises(ValueError):
            source.mirror_upstream_configuration(run, root + "/other", self.tools())

    def source_fixture(self, directory):
        helper = self.tools()["helperStorePath"]
        narinfo = Path(directory) / ("a" * 32 + ".narinfo")
        nar = Path(directory) / "nar" / ("a" * 32 + "-hub-helper.nar.zst")
        nar.parent.mkdir()
        nar.write_bytes(b"controlled encoded NAR bytes")
        narinfo.write_text("StorePath: " + helper + "\nURL: nar/" + nar.name + "\n")
        (Path(directory) / "HEAD").write_text("controlled HEAD")
        (Path(directory) / "info").mkdir()
        (Path(directory) / "info/refs").write_text("controlled refs")
        signed = {"surfaceRoot": directory, "sourceCommit": "c" * 64}
        return signed, nar

    def run_inventory(self, signed):
        calls = []
        def private_command(machine, command, timeout):
            # Execute the exact private guest action against controlled local
            # files. No APR/HTTP/process success is inferred from this test.
            code = command.split("\n", 1)[1].rsplit("DIRECT_PRIVATE_ACTION", 1)[0]
            compile(code, "retained-mirror-source-action", "exec")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exec(code, {})
            calls.append(code)
            return output.getvalue()
        lifecycle.private_guest_command = private_command
        source.direct_guest_python = lifecycle.direct_guest_python
        source.prepare_direct_signed_surface = lambda *args, **kwargs: signed
        return source.prepare_external_mirror_signed_source(None, self.tools(), "b" * 32), calls

    def test_actual_rendered_inventory_joins_helper_pair_and_all_source_hashes(self):
        with tempfile.TemporaryDirectory(prefix="mirror-source-controlled-") as directory:
            signed, nar = self.source_fixture(directory)
            result, calls = self.run_inventory(signed)
            self.assertEqual(len(result["inventory"]["objects"]), 4)
            pair = result["inventory"]["pullObjects"]
            self.assertEqual(pair[1]["sha256"], hashlib.sha256(nar.read_bytes()).hexdigest())
            self.assertEqual(result["inventory"]["sourceCommit"], signed["sourceCommit"])
            self.assertEqual(len(calls), 1)

    def test_rendered_inventory_refuses_link_and_unselected_helper_url(self):
        with tempfile.TemporaryDirectory(prefix="mirror-source-controlled-") as directory:
            signed, nar = self.source_fixture(directory)
            (Path(directory) / "linked-private").symlink_to(nar)
            with self.assertRaises(OSError):
                self.run_inventory(signed)
            (Path(directory) / "linked-private").unlink()
            (Path(directory) / ("a" * 32 + ".narinfo")).write_text(
                "StorePath: " + self.tools()["helperStorePath"] + "\nURL: nar/not-selected.nar.zst\n")
            with self.assertRaises(ValueError):
                self.run_inventory(signed)

    def test_changed_transfer_refuses_before_worker_install_or_launch(self):
        calls = []
        row = {"path": "HEAD", "sha256": hashlib.sha256(b"actual").hexdigest(), "byteSize": 6}
        selected = {"runId": "a" * 32, "signed": {"surfaceRoot": "/controlled/source"},
            "inventory": {"objects": [row, {**row, "path": "info/refs"}]}}
        source.read_direct_guest_file = lambda *args: b"changed"
        source.install_direct_guest_file = lambda *args: calls.append("install")
        source.launch_managed_process = lambda *args, **kwargs: calls.append("launch")
        with self.assertRaises(ValueError):
            source.install_external_mirror_upstream(None, None, self.tools(), selected, {})
        self.assertEqual(calls, [])

    def test_cleanup_selects_only_the_recorded_upstream_owner(self):
        calls = []
        owner = {"mirrorUpstream": {"root": "/var/lib/hybrid-worker/mirror-upstream/" + "a" * 32,
            "process": {"controlledLifetime": "only-this-owner"}}}
        source.stop_external_oci_process = lambda *args: calls.append(args) or {"exited": True}
        result = source.stop_external_mirror_upstream("controlled-worker", self.tools(), owner)
        self.assertEqual(calls[0][-2], {"controlledLifetime": "only-this-owner"})
        self.assertEqual(calls[0][-1], "upstream")
        self.assertIsNone(owner["mirrorUpstream"])
        self.assertIsNone(result["providerSettlement"])
        self.assertIsNone(source.stop_external_mirror_upstream("controlled-worker", self.tools(), owner))


if __name__ == "__main__":
    unittest.main()
