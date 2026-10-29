"""Bounded replacement semantics and actual curl SigV4 invocation construction.

Controlled replies exercise local adapter decisions, not Garage qualification.
The optional selected-curl loopback gate belongs in the reviewed gate plan.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch


source = Path(__file__).with_name("_hub-direct-queue-fault-garage.py")
spec = importlib.util.spec_from_file_location("garage_fault", source)
garage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(garage)


def admission():
    cohort = {"alias": {"spec": {"bucket": "fixture-bucket"}}}
    return {"sessionId": "actual-session", "intent": {"byteSize": "4",
            "expectedSha256": hashlib.sha256(b"body").hexdigest()},
            "placements": [{"placementId": "1", "stagingPrefix": "managed/binding/.aos-direct-upload",
                            "physical": {"kind": "external", "writeCohort": cohort, "readCohort": cohort}}]}


class ControlledTransport:
    def __init__(self, old_read=412, put=200):
        self.calls = []
        self.old_read, self.put = old_read, put

    def exchange(self, method, bucket, key, **kwargs):
        self.calls.append((method, bucket, key, kwargs))
        if method == "PUT":
            return {"status": self.put, "headers": {}, "body": b""}
        if len(self.calls) == 1:
            headers = {"etag": '"original"'}
            if kwargs.get("version") is not None:
                headers["x-amz-version-id"] = kwargs["version"]
            return {"status": 200, "headers": headers, "body": b"body"}
        if "if_match" not in kwargs:
            return {"status": 200, "headers": {"etag": '"changed"'}, "body": bytes([ord("b") ^ 255]) + b"ody"}
        return {"status": self.old_read, "headers": {"etag": '"original"'}, "body": b"body"}


class GarageAdapterTests(unittest.TestCase):
    def adapter(self, transport, version=None):
        return garage.GarageReplacement(transport, admission(), "1",
                                       {"etag": '"original"', "providerVersion": version}, "a" * 64)

    def test_actual_key_comes_from_admission_not_qualification_prefix(self):
        adapter = self.adapter(ControlledTransport())
        self.assertEqual(adapter.key, "managed/binding/.aos-direct-upload/"
                         + hashlib.sha256(b"actual-session").hexdigest() + "/1/payload")
        with tempfile.TemporaryDirectory() as directory:
            result = adapter.replace_once(Path(directory) / "original.marker")
            self.assertEqual(result["state"], "replacement_observed")
            self.assertIsNone(result["productionConditionalRead"])
            self.assertIsNone(result["qualification"])

    def test_still_readable_pinned_version_is_unavailable_never_fake_412(self):
        transport = ControlledTransport(old_read=200)
        adapter = self.adapter(transport, "provider-old-version")
        with tempfile.TemporaryDirectory() as directory:
            result = adapter.replace_once(Path(directory) / "original.marker")
            self.assertEqual(result["state"], "unavailable")
            self.assertEqual(result["reason"], "old_pinned_incarnation_remains_readable")
        self.assertEqual(transport.calls[-1][3]["version"], "provider-old-version")

    def test_conditional_put_unavailable_and_unknown_read_are_not_success(self):
        for transport, expected in [(ControlledTransport(put=412), "unavailable"),
                                    (ControlledTransport(old_read=502), "unknown")]:
            with tempfile.TemporaryDirectory() as directory:
                adapter = self.adapter(transport)
                self.assertEqual(adapter.replace_once(Path(directory) / "original.marker")["state"], expected)
                with self.assertRaises(ValueError):
                    adapter.replace_once(Path(directory) / "retry.marker")

    def test_wrong_source_refuses_before_mutation_and_existing_marker_refuses(self):
        transport = ControlledTransport()
        adapter = self.adapter(transport)
        adapter.source_sha = "b" * 64
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                adapter.replace_once(Path(directory) / "original.marker")
        self.assertFalse(any(call[0] == "PUT" for call in transport.calls))
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "original.marker"
            marker.write_bytes(b"prior pending original")
            adapter = self.adapter(ControlledTransport())
            with self.assertRaises(FileExistsError):
                adapter.replace_once(marker)

    def test_managed_context_literal_null_or_foreign_bucket_refuses(self):
        for mutate in [lambda value: value["placements"][0]["physical"].update(kind="deployment_r2"),
                       lambda value: value["intent"].update(byteSize=str(garage.MAX_OBJECT + 1))]:
            value = admission()
            mutate(value)
            with self.assertRaises(ValueError):
                garage.GarageReplacement(ControlledTransport(), value, "1",
                                        {"etag": '"original"', "providerVersion": None}, "a" * 64)
        with self.assertRaises(ValueError):
            self.adapter(ControlledTransport(), "null")

    def test_sigv4_credential_is_private_stdin_not_arguments_and_output_is_instrumentation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            credential = root / "selected.json"
            credential.write_text(json.dumps({"accessKeyId": "synthetic-access", "secretAccessKey": "synthetic-secret"}))
            credential.chmod(0o600)
            transport = garage.GarageSigV4("/nix/store/synthetic-curl/bin/curl", "http://127.0.0.1:3900",
                "garage", str(credential), root / "outputs", int(time.time() * 1000) + 10000)
            def process(arguments, **options):
                self.assertNotIn("synthetic-secret", " ".join(arguments))
                self.assertIn(b'aws-sigv4 = "aws:amz:garage:s3"', options["input"])
                Path(arguments[arguments.index("--output") + 1]).write_bytes(b"body")
                Path(arguments[arguments.index("--dump-header") + 1]).write_bytes(
                    b'HTTP/1.1 200 OK\r\nETag: "original"\r\nContent-Length: 4\r\n\r\n')
                return subprocess.CompletedProcess(arguments, 0, b"200", b"")
            with patch.object(garage.subprocess, "run", process):
                reply = transport.exchange("GET", "fixture-bucket", "managed/payload", if_match='"original"')
            self.assertEqual(reply["body"], b"body")
            self.assertEqual(transport.records[0]["scope"], "fixture_instrumentation")
            self.assertNotIn("synthetic-secret", json.dumps(transport.records))


if __name__ == "__main__":
    unittest.main()
