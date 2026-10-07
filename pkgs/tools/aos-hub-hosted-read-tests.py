"""Exercise closed read contracts and actual local TLS with synthetic content.

Source-built curl/OpenSSL are explicit test inputs. These small local responses
exercise the transport and assertions; they do not qualify a hosted deployment,
signed publication, Cache API, provider, actor, or SQL reader.
"""

import argparse
import base64
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch


MODULE = Path(__file__).with_name("aos-hub-hosted-read.py")
spec = importlib.util.spec_from_file_location("hosted_read", MODULE)
read = importlib.util.module_from_spec(spec)
spec.loader.exec_module(read)
PARITY_PATH = Path(__file__).resolve().parents[2] / "tests/fleet/_hub-direct-read-parity.py"
CURL = None
OPENSSL = None


class Contracts(unittest.TestCase):
    def test_closed_selection_rejects_extra_authority_and_runtime_shape(self):
        with self.assertRaises(ValueError):
            read.closed({"version": 1, "signingKey": "not-an-input"}, {"version"})
        with self.assertRaises(ValueError):
            read.runtime({"runtimeCodecRevision": "old", "workerSourceDigest": "a" * 64,
                          "sourceArchiveSha256": "b" * 64, "nativeExecutableSha256": "c" * 64})

    def test_readback_refuses_fresh_foreign_process_and_future_clock(self):
        selected = {"corpus": {"origins": {"hybrid": "https://example.invalid"}},
                    "runtime": {"source": "synthetic"}, "sourceTree": "a" * 40,
                    "deployments": {"hybrid": {"deploymentId": "selected", "moduleSha256": "b" * 64,
                        "configurationSha256": "c" * 64, "processEpoch": "original"}}}
        value = {"version": 1, "mode": "hybrid", "origin": "https://example.invalid",
                 "runtime": selected["runtime"], "sourceTree": selected["sourceTree"],
                 **selected["deployments"]["hybrid"], "observedAtUnixNs": "100"}
        self.assertEqual(read.readback(value, selected, "hybrid", earliest=90, latest=110), value)
        foreign = {**value, "processEpoch": "replacement"}
        with self.assertRaises(ValueError):
            read.readback(foreign, selected, "hybrid", earliest=90, latest=110)
        with self.assertRaises(ValueError):
            read.readback(value, selected, "hybrid", earliest=90, latest=99)

    def test_missing_fanout_and_edge_evidence_remain_unknown(self):
        self.assertEqual(read.fanout(None, {}, None)["state"], "unknown")
        self.assertIsNone(read.fanout(None, {}, None)["providerState"])
        self.assertIsNone(read.location(b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\n"))
        with self.assertRaises(ValueError):
            read.location(b"cf-ray: aaaaaaaaaaaaaaaa-TST\r\ncf-ray: bbbbbbbbbbbbbbbb-TST\r\n")

    def test_arbitrary_private_adapter_is_not_a_fanout_input(self):
        invocation = {"version": 1, "python": {}, "adapter": {}, "selection": {}}
        with patch.object(read, "parsed", return_value=invocation):
            with self.assertRaises(ValueError):
                read.fanout({}, {}, None)

    def test_fanout_keeps_unconsumed_attempt_and_refuses_receiver_substitution(self):
        attempt = {"transportCallId": "selected-call", "planId": "actual-plan", "replyEof": True,
                   "exposedReplyBytes": "128", "outcome": "typed_result_checked"}
        join = {"transportCallId": "selected-call", "requestImage": "matched_selected_receiver_byte_image",
                "typedPayload": {"planIdSha256": read.digest(b"actual-plan")},
                "fullReplyConsumed": True, "nativeReplyConsumedBytes": "128"}
        records = {"attempts": [{"value": attempt}]}
        self.assertEqual(read.fanout_summary(records, [join])["state"], "observed_selected_attempts")
        partial = copy.deepcopy(records)
        partial["attempts"][0]["value"].update(replyEof=False, exposedReplyBytes="64")
        unknown = read.fanout_summary(partial, [join])
        self.assertEqual(unknown["unresolvedCallIds"], ["selected-call"])
        self.assertIsNone(unknown["wholeFanoutCompleteness"])
        foreign = copy.deepcopy(join)
        foreign["typedPayload"]["planIdSha256"] = read.digest(b"foreign-plan")
        self.assertEqual(read.fanout_summary(records, [foreign])["state"], "unknown")
        with self.assertRaises(ValueError):
            read.fanout_summary(records, [join, join])


class ActualTlsReads(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if CURL is None or OPENSSL is None:
            raise RuntimeError("Select explicit AOS curl and OpenSSL for the actual TLS cases")
        read.HOSTED["immutable_executable"](CURL)
        read.HOSTED["immutable_executable"](OPENSSL)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        certificate, key = self.root / "certificate.pem", self.root / "key.pem"
        subprocess.run([OPENSSL, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                        "-out", str(certificate), "-keyout", str(key)],
                       stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=30)
        certificate.chmod(0o600)
        key.chmod(0o600)
        self.document = json.dumps({"schema": "aos.package-documentation/v1", "options": ["synthetic"]}).encode()
        self.bodies = {"git": b"synthetic-git-object-bytes", "package": b"synthetic-nar-object-bytes",
                       "metadata": b"synthetic-narinfo-bytes", "document": self.document,
                       "container": b"synthetic-oci-object-bytes"}
        relative = {"git": "objects/aa/" + "b" * 62, "package": "nar/synthetic.nar",
                    "metadata": "a" * 32 + ".narinfo", "document": "-/api/v1/documentation/sha256:" + read.digest(self.document),
                    "container": "v2/synthetic/blobs/sha256:" + read.digest(self.bodies["container"])}
        objects = {}
        for kind, body in self.bodies.items():
            path = self.root / kind
            path.write_bytes(body)
            objects[kind] = {"relativePath": relative[kind], "file": str(path),
                             "sha256": read.digest(body), "byteSize": len(body)}
        self.paths = {("/" if kind == "container" else "/synthetic/public/") + relative[kind]: body
                      for kind, body in self.bodies.items()}
        self.warm = False
        self.bad_range = False
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_HEAD(self):
                self.do_GET()

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                query = json.loads(body)
                if (self.path != "/aos.hub.v1.DocumentationService/GetDocumentationArtifact"
                        or query["registry"] != "synthetic/private" or self.headers.get("Authorization") is None):
                    self.reply(403, b"refused")
                    return
                self.reply(200, json.dumps({"identity": "synthetic", "canonicalJson": base64.b64encode(fixture.document).decode(),
                                           "etag": "sha256:" + read.digest(fixture.document)}).encode(), "application/json")

            def do_GET(self):
                if self.path.startswith("/synthetic/private/"):
                    self.reply(404, b"hidden-private-content")
                    return
                if self.path in fixture.paths:
                    body = fixture.paths[self.path]
                    if self.headers.get("Range"):
                        status = 200 if fixture.bad_range else 206
                        self.reply(status, body[6:14], extra={"Content-Range": "bytes 6-13/" + str(len(body))})
                    elif "/documentation/" in self.path:
                        authenticated = self.headers.get("Authorization") is not None or self.headers.get("Cookie") is not None
                        extra = {"X-Aos-Front-Cache": "hit"} if fixture.warm and not authenticated else {}
                        fixture.warm = True
                        self.reply(200, body, "application/json", extra)
                    else:
                        self.reply(200, body)
                    return
                values = {"packages": [{"name": "synthetic"}], "packages/synthetic": {"name": "synthetic", "versions": ["1"]},
                          "channels": [{"name": "stable"}], "releases": [{"version": "1"}]}
                self.reply(200, json.dumps(values[self.path.split("/-/api/", 1)[1]]).encode(), "application/json")

            def reply(self, status, body, content_type="application/octet-stream", extra=None):
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Type", content_type)
                self.send_header("Cf-Ray", "aaaaaaaaaaaaaaaa-TST")
                for name, value in (extra or {}).items():
                    self.send_header(name, value)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

        origins = {}
        for mode in read.MODES:
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certificate, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            self.addCleanup(lambda s=server, t=thread: (s.shutdown(), s.server_close(), t.join(timeout=5)))
            origins[mode] = "https://127.0.0.1:" + str(server.server_port)
        for name, value in (("bearer", b"Authorization: Bearer synthetic-test\n"), ("cookie", b"Cookie: synthetic=test\n")):
            (self.root / name).write_bytes(value)
            (self.root / name).chmod(0o600)
        self.selected = {"expiresAt": int(time.time()) + 180, "curl": read.HOSTED["immutable_executable"](CURL),
                         "trustFile": {"file": str(certificate), "sha256": read.digest(certificate.read_bytes()),
                                       "byteSize": str(certificate.stat().st_size)},
                         "bearerHeaderFile": str(self.root / "bearer"), "cookieHeaderFile": str(self.root / "cookie"),
                         "privateRegistrySlug": "synthetic/private", "corpus": {"version": 1, "sourceCommit": "a" * 64,
                             "registrySlug": "synthetic/public", "packageName": "synthetic", "origins": origins, "objects": objects}}
        self.parity = read.load_parity(PARITY_PATH.parent, read.digest(PARITY_PATH.read_bytes()))
        self.evidence = read.HOSTED["Evidence"](self.root / "evidence")
        self.addCleanup(self.evidence.close)
        self.transport = read.HostedReadHttp(self.selected, self.parity, self.evidence)

    def test_actual_tls_full_head_range_and_complete_semantic_queries(self):
        result = self.parity["run_direct_read_parity"](self.selected["corpus"], self.transport)
        queries = self.parity["run_direct_semantic_read_parity"](self.selected["corpus"], self.transport)
        self.assertEqual(len(result["observations"]), 39)
        self.assertEqual(len(queries["observations"]), 12)
        self.assertTrue(all(row["responseEof"] for row in self.transport.observations))
        self.assertIsNone(result["nativeBulkBytes"])

    def test_actual_tls_cache_bypass_private_positive_and_anonymous_refusal(self):
        result = read.cache_reads(self.selected, self.parity, self.transport)
        self.assertEqual(result["state"], "observed")
        self.assertFalse(result["firstRequestWasHit"])
        self.assertEqual([row["status"] for row in result["observations"]], [200, 200, 200, 200, 200, 404])
        self.assertIsNone(result["cacheApiContents"])
        self.assertIsNone(result["coldCacheState"])

    def test_preexisting_cache_hit_refuses_fill_without_eviction_or_retry(self):
        self.warm = True
        with self.assertRaises(ValueError):
            read.cache_reads(self.selected, self.parity, self.transport)
        self.assertEqual(len(self.transport.observations), 1)
        self.assertTrue(self.transport.observations[0]["responseEof"])

    def test_real_tls_untrusted_peer_retains_unknown_not_an_empty_positive(self):
        self.selected["trustFile"] = None
        with self.assertRaises(RuntimeError):
            self.transport.request("untrusted", self.parity["_read_url"](self.selected["corpus"], "hybrid", "git"))
        row = self.transport.observations[0]
        self.assertFalse(row["responseEof"])
        self.assertIsNone(row["bodyBytes"])
        self.assertIsNone(row["bodySha256"])
        self.assertNotEqual(row["transport"]["exitCode"], 0)

    def test_wrong_range_retains_actual_response_and_expiry_never_dispatches(self):
        self.bad_range = True
        with self.assertRaises(ValueError):
            self.parity["run_direct_read_parity"](self.selected["corpus"], self.transport)
        self.assertEqual(self.transport.observations[-1]["status"], 200)
        self.assertTrue(self.transport.observations[-1]["responseEof"])
        count = len(self.transport.observations)
        self.transport.cutoff["originalCutoffUnixNs"] = "1"
        with self.assertRaises(TimeoutError):
            self.transport.request("expired", self.parity["_read_url"](self.selected["corpus"], "hybrid", "git"))
        self.assertEqual(len(self.transport.observations), count)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--curl", required=True)
    parser.add_argument("--openssl", required=True)
    options, remainder = parser.parse_known_args()
    CURL, OPENSSL = options.curl, options.openssl
    unittest.main(argv=[__file__, *remainder])
