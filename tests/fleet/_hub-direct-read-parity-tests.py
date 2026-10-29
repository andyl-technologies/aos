"""Controlled source tests; no actual fleet, cache admission or provider facts."""

import base64
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


specification = importlib.util.spec_from_file_location("read_parity", Path(__file__).with_name("_hub-direct-read-parity.py"))
parity = importlib.util.module_from_spec(specification)
specification.loader.exec_module(parity)


class ReadParityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="aos-read-parity-controlled-")
        self.root = Path(self.directory.name)
        self.selection = {"version": 1, "sourceCommit": "a" * 64, "registrySlug": "fleet/read-parity",
            "packageName": "aos-hub", "origins": {mode: "https://" + mode.replace("_", "-") + ".test"
                for mode in parity.READ_MODES}, "objects": {}}
        self.bodies = {kind: (kind.encode() + b"-controlled-source-") * 4 for kind in parity.READ_CLASSES}
        self.bodies["document"] = json.dumps({"schema": "aos.module.documentation",
            "options": [{"controlled": True}]}).encode()
        paths = {"git": "objects/aa/" + "a" * 62, "package": "nar/controlled.nar",
            "metadata": "0" * 32 + ".narinfo"}
        for kind, body in self.bodies.items():
            digest = hashlib.sha256(body).hexdigest()
            paths.setdefault(kind, "-/api/v1/documentation/sha256:" + digest if kind == "document"
                else "v2/fleet/read-parity/blobs/sha256:" + digest)
            source = self.root / kind; source.write_bytes(body); source.chmod(0o600)
            self.selection["objects"][kind] = {"file": str(source), "relativePath": paths[kind],
                "sha256": digest, "byteSize": len(body)}

    def tearDown(self):
        self.directory.cleanup()

    def transport(self, changed=None):
        selection, bodies = self.selection, self.bodies

        class ControlledTransport:
            def request(self, label, url, method="GET", request_headers=(), expected_size=parity.READ_BODY_LIMIT,
                        request_body=None):
                if label == "cache-private-known-positive":
                    self.asserted = request_body
                    body = json.dumps({"identity": {}, "canonicalJson": base64.b64encode(bodies["document"]).decode(),
                        "etag": "sha256:" + hashlib.sha256(bodies["document"]).hexdigest()}).encode()
                    return {"label": label, "status": 200}, body, {}
                kind = next((kind for kind in parity.READ_CLASSES
                    if url.endswith(selection["objects"][kind]["relativePath"])), "document")
                expected, headers, status = bodies[kind], {}, 200
                if method == "HEAD":
                    body = b""; headers["content-length"] = str(len(expected))
                elif request_headers == ("Range: bytes=6-13",):
                    body, status = expected[6:14], 206
                    headers = {"content-range": "bytes 6-13/" + str(len(expected)), "content-length": "8"}
                else:
                    body = expected
                if label == "cache-private-bypass":
                    body, status = b"not found", 404
                if label in {"cache-hit", "cache-rebuilt-hit"}:
                    headers["x-aos-front-cache"] = "hit"
                if changed:
                    body, headers, status = changed(label, body, headers, status)
                return {"label": label, "status": status}, body, headers

        return ControlledTransport()

    def test_fixed_corpus_exercises_three_modes_four_actual_range_classes_and_docs(self):
        result = parity.run_direct_read_parity(self.selection, self.transport())
        self.assertEqual(len(result["observations"]), 39)
        self.assertIsNone(result["nativeBulkBytes"])
        self.assertEqual(sum(row["label"].endswith("range") for row in result["observations"]), 12)

    def test_semantic_reads_compare_complete_nonempty_indexed_responses(self):
        values = {"packages": [{"name": "aos-hub", "latestVersion": "1.0.0"}],
            "package": {"name": "aos-hub", "versions": [{"version": "1.0.0"}]},
            "channels": [{"name": "stable", "frontier": "1.0.0"}],
            "releases": [{"semver": "1.0.0", "commitOid": "a" * 64}]}

        class SemanticTransport:
            def request(inner, label, url):
                name = label.split("-indexed-", 1)[1]
                return {"label": label, "status": 200}, json.dumps(values[name]).encode(), {
                    "content-type": "application/json"}

        transport = SemanticTransport()
        result = parity.run_direct_semantic_read_parity(self.selection, transport)
        self.assertEqual(len(result["observations"]), 12)
        self.assertIsNone(result["nativeBulkBytes"])
        for change in ("empty", "different", "duplicates", "nonfinite"):
            original = transport.request

            def changed(label, url):
                row, body, headers = original(label, url)
                if label == "worker-only-indexed-package":
                    if change == "empty":
                        body = b'{}'
                    elif change == "different":
                        body = json.dumps({**values["package"], "license": "different"}).encode()
                    elif change == "duplicates":
                        body = b'{"name":"aos-hub","name":"aos-hub","versions":[{}]}'
                    else:
                        body = b'{"name":"aos-hub","versions":[{}],"extra":NaN}'
                return row, body, headers

            transport.request = changed
            with self.assertRaises(ValueError, msg=change):
                parity.run_direct_semantic_read_parity(self.selection, transport)
            transport.request = original

    def test_unsupported_missing_wrong_source_or_invented_document_address_refuses(self):
        for change in ("missing", "tampered", "wrong_digest", "old_document_route", "same_origin"):
            selected = copy.deepcopy(self.selection)
            if change == "missing":
                del selected["objects"]["container"]
            elif change == "tampered":
                selected["objects"]["package"]["byteSize"] += 1
            elif change == "wrong_digest":
                selected["objects"]["metadata"]["sha256"] = "b" * 64
            elif change == "old_document_route":
                selected["objects"]["document"]["relativePath"] = selected["objects"]["document"]["relativePath"].replace("sha256:", "")
            else:
                selected["origins"]["hybrid"] = selected["origins"]["native_only"]
            with self.assertRaises(ValueError, msg=change):
                parity.select_direct_read_corpus(selected)

    def test_range_fallback_wrong_head_and_content_range_refuse(self):
        for fault in ("fallback", "head", "range"):
            def changed(label, body, headers, status):
                if fault == "fallback" and label.endswith("range"):
                    status = 200
                if fault == "head" and label.endswith("head"):
                    headers["content-length"] = "1"
                if fault == "range" and label.endswith("range"):
                    headers["content-range"] = "bytes 0-7/10"
                return body, headers, status
            with self.assertRaises(ValueError, msg=fault):
                parity.run_direct_read_parity(self.selection, self.transport(changed))

    def test_source_fifo_symlink_and_changed_size_refuse_before_dispatch(self):
        source = Path(self.selection["objects"]["git"]["file"])
        alias = self.root / "alias"; alias.symlink_to(source)
        with self.assertRaises(OSError):
            parity._read_source(alias)
        with self.assertRaises(ValueError):
            parity._read_source(source, maximum=1)

    def test_response_duplicate_headers_redirect_encoding_and_interim_refuse(self):
        valid = b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 6-13/64\r\nContent-Length: 8\r\n\r\n"
        self.assertEqual(parity.parse_direct_read_headers(valid)["content-length"], "8")
        for body in (valid + valid, valid.replace(b"\r\n\r\n", b"\r\nContent-Length: 8\r\n\r\n"),
                valid.replace(b"\r\n\r\n", b"\r\nContent-Encoding: gzip\r\n\r\n")):
            with self.assertRaises(ValueError):
                parity.parse_direct_read_headers(body)

    def test_full_index_refuses_missing_docs_oci_stale_or_different_semantics(self):
        index = {"index": [["fresh", None, "a" * 64, "description"]]}
        for name in ("packages", "versions", "platforms", "keys", "releases", "release_records", "channels",
                "channel_floors", "channel_partitions", "catalog_artifacts", "artifact_snapshots", "release_artifacts",
                "documentation", "container_roots", "container_closure_members", "container_evidence",
                "container_provenance", "container_layers", "browse_catalogs", "browse_nodes"):
            index[name] = [["controlled-nonempty"]]
        snapshots = {mode: copy.deepcopy(index) for mode in parity.READ_MODES}
        self.assertTrue(parity.assert_direct_full_index_parity(snapshots, "a" * 64)["rowsByTable"]["documentation"])
        for fault in ("documentation", "container_layers", "stale", "difference"):
            changed = copy.deepcopy(snapshots)
            if fault in {"documentation", "container_layers"}:
                changed["hybrid"][fault] = []
            elif fault == "stale":
                changed["hybrid"]["index"][0][2] = "b" * 64
            else:
                changed["worker_only"]["packages"] = [["different"]]
            with self.assertRaises(ValueError, msg=fault):
                parity.assert_direct_full_index_parity(changed, "a" * 64)

    def test_cache_cases_require_private_known_positive_real_expiry_and_exact_eviction(self):
        bearer = self.root / "bearer"; bearer.write_text("Authorization: Bearer controlled"); bearer.chmod(0o600)
        cookie = self.root / "cookie"; cookie.write_text("Cookie: controlled=value"); cookie.chmod(0o600)
        calls = []
        identity = {"runnerPid": 123, "runnerStartTicks": "1", "workerName": "controlled-worker",
            "miniflareVersion": "5.20260801.0-alpha"}
        for field in ("configurationSha256", "cacheObserverSha256", "miniflareModuleSha256",
                "cacheWorkerSha256", "cacheEntrySha256", "shimSha256", "cacheKeySha256"):
            identity[field] = "a" * 64
        identity["documentUrlSha256"] = parity._digest(parity._read_url(self.selection, "hybrid", "document").encode())

        def control(kind, label):
            calls.append((kind, label))
            value = None if label == "cache-cold" else {"expiresAtUnixSeconds": "101",
                "bodySha256": parity._digest(self.bodies["document"]), "byteSize": str(len(self.bodies["document"]))}
            return {**identity, "version": 1, "kind": kind,
                "observationScope": "selected_public_document_cache_api", "observedAtUnixMillis": "100000",
                "before": value, "after": None if label == "cache-evicted" else value,
                "deleted": True if label == "cache-evicted" else None}
        with patch.object(parity.time, "time", side_effect=[100.0, 102.0]):
            result = parity.run_direct_document_cache(self.selection, self.transport(), control,
                str(bearer), str(cookie), "fleet/private-parity", identity)
        self.assertIn("cache-private-known-positive", [row["label"] for row in result["observations"]])
        self.assertEqual(sum(kind.endswith("evict") for kind, _ in calls), 1)
        self.assertIsNone(result["nativeBulkBytes"])
        for field in ("runnerPid", "runnerStartTicks", "configurationSha256", "cacheKeySha256", "shimSha256"):
            changed = copy.deepcopy(control("public-document-cache-readback", "cache-filled"))
            changed[field] = 124 if field == "runnerPid" else "2" if field == "runnerStartTicks" else "b" * 64
            with self.assertRaises(ValueError, msg=field):
                parity._cache_observation(changed, identity, "public-document-cache-readback", self.bodies["document"])
        changed = copy.deepcopy(control("public-document-cache-readback", "cache-filled"))
        changed["before"]["byteSize"] = "1"
        with self.assertRaises(ValueError):
            parity._cache_observation(changed, identity, "public-document-cache-readback", self.bodies["document"])

    def test_refusal_requires_actual_private_window_and_unchanged_sql(self):
        rows = {}
        for name in ('provider_timeout', 'stale_placement', 'worker_revision'):
            events = []
            if name == 'provider_timeout':
                for number, kind in enumerate(('read_started', 'peer_closed')):
                    events.append({'version': 1, 'kind': kind, 'sequence': number,
                        'runDigest': 'a' * 64, 'keyDigest': 'b' * 64, 'versionDigest': 'c' * 64,
                        'etagDigest': 'd' * 64, 'atUnixMillis': str(1000 + number),
                        'elapsedNanoseconds': str(number + 1), 'method': 'GET',
                        'status': None, 'responseOfferedBytes': '0'})
            raw = b''.join(json.dumps(row).encode() + b'\n' for row in events)
            path = self.root / (name + '.provider'); path.write_bytes(raw); path.chmod(0o600)
            position = {'path': '/private/actual-log', 'device': '1', 'inode': '2', 'byteSize': 0}
            rows[name] = {'originalRequestSha256': 'a' * 64, 'receivedRequestSha256': 'a' * 64,
                'replySha256': 'b' * 64, 'replyBytes': 64, 'status': 409,
                'startedAtUnixNs': '1000000000', 'completedAtUnixNs': '2000000000',
                'providerWindow': {'file': str(path), 'sha256': hashlib.sha256(raw).hexdigest(),
                    'capturedBytes': len(raw), 'before': position,
                    'after': {**position, 'byteSize': len(raw)}},
                'sqlBeforeSha256': 'c' * 64, 'sqlAfterSha256': 'c' * 64,
                'actualSourceDigest': 'd' * 64,
                'selectedSourceDigest': ('e' if name == 'worker_revision' else 'd') * 64}
            if name == 'stale_placement':
                rows[name]['placementBefore'] = {'placementId': '1', 'resourceVersion': '1'}
                rows[name]['placementAfter'] = {'placementId': '1', 'resourceVersion': '2'}
        self.assertEqual(parity.assert_direct_read_refusals(rows)['provider_timeout']['providerRequests'], 1)
        self.assertIsNone(parity.assert_direct_read_refusals(rows)['stale_placement']['providerRequests'])
        eligible_read = json.dumps({'method': 'GET', 'controlledObservedSourceBytes': 64}).encode() + b'\n'
        window = rows['stale_placement']['providerWindow']
        Path(window['file']).write_bytes(eligible_read)
        window.update(sha256=hashlib.sha256(eligible_read).hexdigest(), capturedBytes=len(eligible_read))
        window['after']['byteSize'] = len(eligible_read)
        self.assertIsNone(parity.assert_direct_read_refusals(rows)['stale_placement']['providerRequests'])
        for fault in ('sql', 'rotation', 'missing', 'success', 'revision', 'placement'):
            changed = copy.deepcopy(rows)
            if fault == 'sql':
                changed['stale_placement']['sqlAfterSha256'] = 'f' * 64
            elif fault == 'rotation':
                changed['provider_timeout']['providerWindow']['after']['inode'] = 'other'
            elif fault == 'missing':
                changed['provider_timeout']['providerWindow']['sha256'] = 'f' * 64
            elif fault == 'success':
                changed['provider_timeout']['status'] = 200
            elif fault == 'revision':
                changed['worker_revision']['selectedSourceDigest'] = 'd' * 64
            else:
                changed['stale_placement']['placementAfter']['resourceVersion'] = '1'
            with self.assertRaises(ValueError, msg=fault):
                parity.assert_direct_read_refusals(changed)

    def test_actual_http_command_has_one_dispatch_strict_tls_and_empty_head_capture(self):
        executable = "/nix/store/" + "0" * 32 + "-curl/bin/curl"
        transport = parity.DirectReadHttp([executable], self.root / "captures")
        calls = []
        def run(arguments, **kwargs):
            calls.append(arguments)
            headers = Path(arguments[arguments.index("--dump-header") + 1])
            headers.write_bytes(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n")
            return subprocess_result
        class Result:
            returncode = 0; stdout = b"200"; stderr = b""
        subprocess_result = Result()
        with patch.object(parity.subprocess, "run", run):
            _, body, headers = transport.request("controlled-head", "https://worker.test/object", method="HEAD", expected_size=0)
        self.assertEqual(body, b"")
        self.assertEqual(calls[0][-1], "https://worker.test/object")
        self.assertIn("Accept-Encoding: identity", calls[0])
        self.assertIn("--head", calls[0]); self.assertIn("/dev/null", calls[0])
        self.assertEqual(headers["content-length"], "64")
        for options in (["-k"], ["-ksS"], ["--config", "extra"], ["--url", "https://extra.test"]):
            with self.assertRaises(ValueError):
                parity.DirectReadHttp([executable] + options, self.root / "rejected")

    def test_guest_document_producer_program_compiles_and_keeps_actual_apr_commands(self):
        import textwrap

        source = Path(parity.__file__).read_text()
        tree = ast.parse(source)
        scripts = [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)
            and isinstance(node.value, str) and "import hashlib, json, os, re, stat" in node.value]
        self.assertEqual(len(scripts), 1)
        guest = textwrap.dedent(scripts[0])
        compile(guest, "actual-document-producer-guest", "exec")
        self.assertNotIn("'--documentation-base-lib'", guest)
        self.assertIn("module_documentation", guest)
        self.assertIn("options.json", guest)
        self.assertIn("'--upload-url', 'file://' + selected['surface']", guest)
        self.assertNotIn("shell=True", guest)
        self.assertFalse(any(isinstance(node, ast.keyword) and node.arg == "HOME"
            for node in ast.walk(ast.parse(guest))))

    def test_guest_document_paths_preserve_home_and_select_the_prepared_apr_registry(self):
        import os
        import textwrap

        tree = ast.parse(Path(parity.__file__).read_text())
        guest = next(node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)
            and isinstance(node.value, str) and "import hashlib, json, os, re, stat" in node.value)
        prefix = textwrap.dedent(guest).split("for number, arguments in enumerate(commands):", 1)[0]
        selected = {"publisherRoot": str(self.root / "publisher"), "apr": "controlled-unused-apr",
            "git": "controlled-git", "toolDirectories": [], "hubPackage": "controlled-unused-package",
            "hubVersion": "1.0.0", "cacheUrl": "https://cache.test",
            "surface": str(self.root / "surface")}
        Path(selected["publisherRoot"]).mkdir(mode=0o700)
        calls = []

        class Result:
            returncode = 0
            stderr = b""
            stdout = b"controlled-existing-identity\n"

        def inspect_identity(arguments, **options):
            calls.append(arguments)
            return Result()

        original_home = os.environ.get("HOME")
        namespace = {"selected": selected}
        with patch.object(parity.subprocess, "run", inspect_identity):
            exec(compile(prefix, "document-producer-environment-controlled", "exec"), namespace)
        environment = namespace["environment"]
        self.assertEqual(environment.get("HOME"), original_home)
        self.assertEqual(environment["XDG_DATA_HOME"], selected["publisherRoot"] + "/.local/share")
        self.assertEqual(environment["XDG_CONFIG_HOME"], selected["publisherRoot"] + "/.config")
        self.assertEqual([call[-1] for call in calls], ["user.name", "user.email"])
        self.assertTrue(all(call[2].endswith("/apm/registries/external-direct-docs") for call in calls))


if __name__ == "__main__":
    unittest.main()
