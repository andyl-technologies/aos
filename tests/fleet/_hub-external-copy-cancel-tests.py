"""Exercise actual local file custody used by the pending Copy callback."""

import base64
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import textwrap
import unittest


specification = importlib.util.spec_from_file_location("copy_cancel",
    Path(__file__).with_name("_hub-external-copy-cancel.py"))
fixture = importlib.util.module_from_spec(specification)
specification.loader.exec_module(fixture)


def run_guest(_machine, _python, source, selected):
    output = io.StringIO()
    namespace = {"selected": selected, "json": json, "base64": base64}
    with contextlib.redirect_stdout(output):
        exec(compile(textwrap.dedent(source), "copy-pending-guest", "exec"), namespace)
    return output.getvalue()


class PendingCopyCustodyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        fixture.direct_guest_python = run_guest
        self.pin = {"pid": os.getpid(), "ownerUid": os.getuid(), "startTicks":
            Path("/proc/self/stat").read_text().rpartition(") ")[2].split()[19]}
        self.operation = "retained-operation"
        self.body = json.dumps({"control": "advance", "original": {
            "topology": {"operation_id": self.operation}}}, separators=(",", ":")).encode()

    def test_existing_files_are_excluded_and_selected_bytes_keep_actual_commitments(self):
        old = self.root / "old-request"
        old.write_bytes(self.body)
        before = fixture.external_copy_pending_files(None, {"python": "selected"}, str(self.root), self.pin)
        new = self.root / "new-request"
        new.write_bytes(self.body)
        (self.root / "other-operation").write_bytes(self.body.replace(b"retained-operation", b"other-operation"))

        after = fixture.external_copy_pending_files(None, {"python": "selected"}, str(self.root), self.pin,
            operation_id=self.operation, before=before["paths"])

        self.assertEqual([row["path"] for row in after["candidates"]], [str(new)])
        row = after["candidates"][0]
        self.assertEqual(base64.b64decode(row["body"]), self.body)
        self.assertEqual(row["sha256"], hashlib.sha256(self.body).hexdigest())
        self.assertEqual(row["inode"], str(new.stat().st_ino))

    def test_symlink_and_changed_process_refuse(self):
        (self.root / "request").write_bytes(self.body)
        (self.root / "alias").symlink_to(self.root / "request")
        with self.assertRaises(ValueError):
            fixture.external_copy_pending_files(None, {"python": "selected"}, str(self.root), self.pin)
        (self.root / "alias").unlink()
        with self.assertRaises(ValueError):
            fixture.external_copy_pending_files(None, {"python": "selected"}, str(self.root),
                {**self.pin, "startTicks": str(int(self.pin["startTicks"]) + 1)})

    def test_fixed_log_suffix_retains_bytes_and_refuses_rotation(self):
        path = self.root / "worker.log"
        path.write_bytes(b"before\n")
        metadata = path.stat()
        position = {"path": str(path), "device": str(metadata.st_dev), "inode": str(metadata.st_ino),
            "byteSize": metadata.st_size}
        with path.open("ab") as output:
            output.write(b"actual selected log suffix\n")

        text, receipt = fixture.external_copy_pending_log(None, {"python": "selected"}, position, self.pin)

        self.assertEqual(text, "actual selected log suffix\n")
        self.assertEqual(receipt["sha256"], hashlib.sha256(text.encode()).hexdigest())
        path.rename(self.root / "previous.log")
        path.write_bytes(b"substituted\n")
        with self.assertRaises(ValueError):
            fixture.external_copy_pending_log(None, {"python": "selected"}, position, self.pin)


if __name__ == "__main__":
    unittest.main()
