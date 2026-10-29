"""Check called read lifetime, source selection and refusal boundaries.

Temporary files are controlled source fixtures. These checks execute the guest
source selector and lifecycle callback, without claiming any live Hub, provider
permission, cache result or runtime qualification.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import textwrap
import unittest
from unittest.mock import patch


HERE = Path(__file__).parent


def load(name, file):
    specification = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


pair = load("read_pair", "_hub-managed-pair.py")
read = load("managed_read", "_hub-managed-read.py")
runtime = load("managed_runtime", "_hub-runtime-parity.py")
read.require_managed_pair = pair.require_managed_pair


def execute_guest(machine, python, program, selected, **options):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        exec(compile(textwrap.dedent(program), "controlled-guest", "exec"), {
            "selected": selected, "json": json,
        })
    return output.getvalue()


class ManagedReadTests(unittest.TestCase):
    def test_live_read_occurs_after_full_index_and_before_both_stops(self):
        events = []
        pins = {"native_only": {"pid": 1}, "worker_only": {"pid": 2}}

        def snapshot(readers, slug, **options):
            events.append("indexes")
            self.assertEqual(set(readers), {"hybrid", "native_only", "worker_only"})
            return {"controlled": "index-result"}

        def reads(**live):
            events.append("reads")
            self.assertIs(live["processes"], pins)
            self.assertEqual(live["roots"]["worker_only"], "/fresh/worker")
            return {"controlled": "read-result"}

        result = self.observe(snapshot, reads, pins, lambda machine, pin: events.append("stop-" + str(pin["pid"])))
        self.assertEqual(events, ["indexes", "reads", "stop-1", "stop-2"])
        self.assertEqual(result, ({"controlled": "index-result"}, {"controlled": "read-result"}))

    def test_refused_read_still_stops_only_recorded_companions(self):
        stopped = []
        pins = {"native_only": {"pid": 7}, "worker_only": {"pid": 8}}

        def refusal(**live):
            raise ValueError("actual read refused")

        with self.assertRaisesRegex(ValueError, "actual read refused"):
            self.observe(lambda *args, **kwargs: {}, refusal, pins,
                lambda machine, pin: stopped.append(pin))
        self.assertEqual(stopped, [pins["native_only"], pins["worker_only"]])

    def observe(self, snapshot, reads, pins, stop):
        return runtime.observe_runtime_parity_before_stop(
            readers={mode: object() for mode in ("hybrid", "native_only", "worker_only")},
            registry_slug="selected/containers", snapshot_assert=snapshot,
            container_index_digest="sha256:" + "a" * 64, read_window=reads,
            origins={"native_only": "https://native.test:8453", "worker_only": "https://worker.test:8453"},
            process_receipts=pins, worker_configuration={"selected": "configuration"},
            native=object(), worker=object(), native_root="/fresh/native", worker_root="/fresh/worker", process_stop=stop)

    def fixture(self, root):
        surface = root / "surface"
        layout = root / "layout/blobs/sha256"
        surface.mkdir()
        layout.mkdir(parents=True)
        commit = "a" * 64
        git = surface / "objects/aa" / commit[2:]
        git.parent.mkdir(parents=True)
        git.write_bytes(b"controlled loose commit bytes" * 2)
        nar = surface / "nar/helper.nar"
        nar.parent.mkdir()
        nar.write_bytes(b"controlled genuine-file selector NAR bytes" * 2)
        (surface / ("b" * 32 + ".narinfo")).write_text("StorePath: /nix/store/" + "b" * 32
            + "-helper\nURL: nar/helper.nar\n")
        config = b'{"architecture":"amd64","os":"linux","config":{}}'
        config_sha = hashlib.sha256(config).hexdigest()
        (layout / config_sha).write_bytes(config)
        manifest = json.dumps({"schemaVersion": 2, "config": {
            "digest": "sha256:" + config_sha, "size": len(config)}, "layers": []}).encode()
        manifest_sha = hashlib.sha256(manifest).hexdigest()
        (layout / manifest_sha).write_bytes(manifest)
        index = json.dumps({"schemaVersion": 2, "manifests": [{
            "digest": "sha256:" + manifest_sha, "size": len(manifest)}]}).encode()
        index_sha = hashlib.sha256(index).hexdigest()
        (layout / index_sha).write_bytes(index)
        document = root / "document"
        body = b'{"schema":"aos.module.documentation","options":[{"name":"actual-option"}]}'
        document.write_bytes(body)
        document_sha = hashlib.sha256(body).hexdigest()
        return {"surfaceRoot": str(surface), "document": {"file": str(document), "sha256": document_sha,
            "byteSize": len(body), "relativePath": "-/api/v1/documentation/sha256:" + document_sha},
            "finalized": {"layout": str(layout.parent.parent), "index_digest": "sha256:" + index_sha}}

    def selected(self, root, source):
        return read.select_managed_read_objects(None, {
            "python": "controlled-source-executor", "helperStorePath": "/nix/store/" + "b" * 32 + "-helper"},
            {"coordinates": {"clientRoot": str(root)}}, source,
            {"signedSource": {"sourceCommit": "a" * 64}})

    def test_actual_retained_files_bind_all_five_reference_hashes_and_paths(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(read, "direct_guest_python",
                create=True, side_effect=execute_guest):
            root = Path(directory)
            source = self.fixture(root)
            selected = self.selected(root, source)
            self.assertEqual(set(selected), {"git", "package", "metadata", "document", "container"})
            for kind, row in selected.items():
                body = Path(row["file"]).read_bytes()
                self.assertEqual(row["sha256"], hashlib.sha256(body).hexdigest())
                self.assertEqual(row["byteSize"], len(body))
                self.assertEqual(Path(row["file"]).stat().st_mode & 0o777, 0o600)
            self.assertEqual(selected["container"]["relativePath"], "v2/aos/blobs/sha256:" + selected["container"]["sha256"])

    def test_narinfo_traversal_refuses_before_copying_any_reference(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(read, "direct_guest_python",
                create=True, side_effect=execute_guest):
            root = Path(directory)
            source = self.fixture(root)
            (root / "surface" / ("b" * 32 + ".narinfo")).write_text("URL: ../../outside.nar\n")
            with self.assertRaisesRegex(ValueError, "narinfo URL differs"):
                self.selected(root, source)
            self.assertEqual(list((root / "read-originals").iterdir()), [])

    def test_changed_signed_oci_child_refuses_as_actual_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(read, "direct_guest_python",
                create=True, side_effect=execute_guest):
            root = Path(directory)
            source = self.fixture(root)
            layout = Path(source["finalized"]["layout"]) / "blobs/sha256"
            index = json.loads((layout / source["finalized"]["index_digest"][7:]).read_bytes())
            child = layout / index["manifests"][0]["digest"][7:]
            child.write_bytes(b"changed child manifest" * 2)
            with self.assertRaisesRegex(ValueError, "signed child manifest changed"):
                self.selected(root, source)

    def test_sql_mutation_or_multi_statement_refuses_before_guest_transport(self):
        query = read.ManagedIndexReader(None, {}, {})
        with patch.object(read, "direct_guest_python", create=True) as transport:
            for sql in ("DELETE FROM packages", "SELECT 1; SELECT 2", "SELECT /* hidden */ 1", "SELECT 1 -- comment"):
                with self.subTest(sql=sql), self.assertRaises(ValueError):
                    query(sql)
        transport.assert_not_called()



if __name__ == "__main__":
    unittest.main()
