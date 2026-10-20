"""Controlled source tests; these never qualify an issuer or a scale workload."""

import asyncio
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


def load(name, filename):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


setup = load("scale_setup", "_hub-direct-issuer-scale-setup.py")
workload = load("scale_workload", "_hub-direct-issuer-scale-workload.py")


def selected_workers():
    return [{"host": "127.0.0.1", "port": 11000 + index,
        "isolateLabel": f"{index + 1:032x}", "configurationDigest": f"{index + 1:064x}",
        "transport": {"kind": "loopback_http"}}
        for index in range(4)]


def calls():
    return workload.plan_scale_wave("1" * 32, "2" * 64, selected_workers(),
        [f"{index + 1:064x}" for index in range(32)], 100, "controlled-wave", 8)


def reply_for(call, digest):
    original = call["original"]
    return {"version": 1, "runId": original["run_id"], "isolateLabel": call["worker"]["isolateLabel"],
        "nonce": original["nonce"], "requestSha256": digest,
        "sourceDigest": original["source_digest"], "configurationDigest": original["configuration_digest"],
        "cohortDigest": original["cohort_digest"], "leaseDigest": "3" * 64,
        "leaseSequence": 1, "issuedAt": 100, "notAfter": 108, "attestationValidUntil": 200,
        "maximumLifetime": 8, "clockUncertainty": 2, "observedAt": 100}


def write_exports(root, lifetime):
    """Build explicitly synthetic files for projection/custody tests only."""
    authority = {"guard_namespace_id": "controlled-namespace"}
    installation = {"authority": authority, "executor_identity": "controlled-executor"}
    publication = {"authority": authority, "aliases": [], "syntheticProjectionTest": True}
    directories = []
    for index in range(16):
        directory = root / f"association-{index:02d}"
        directory.mkdir(mode=0o700)
        cohort = {"association": {"association_id": f"controlled-{index}"}}
        bootstrap = {"version": 1, "publication": publication,
            "issuer_installation": installation, "issuer_key_id": "controlled-key",
            "issuer_public_key": "4" * 64, "timing_profile": {"maximum_lifetime": str(lifetime)},
            "clock_uncertainty": 2, "deployment_id": "controlled-deployment",
            "read_cohort": {**cohort, "testEffect": "read"},
            "write_cohort": {**cohort, "testEffect": "write"}}
        for name, value in [("bootstrap.json", bootstrap), ("publication.json", publication)]:
            descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(setup._encode(value))
        directories.append(str(directory))
    return directories


class ProjectionTests(unittest.TestCase):
    def test_full_publication_projection_keeps_all_32_and_four_contexts(self):
        for lifetime in (8, 120):
            with tempfile.TemporaryDirectory() as directory:
                paths = write_exports(Path(directory), lifetime)

                result = setup.project_scale_exports(paths, "1" * 32,
                    [f"{index + 1:032x}" for index in range(4)])

                self.assertEqual(len(set(result["cohortDigests"])), 32)
                self.assertEqual(len(result["configurations"]), 4)
                self.assertEqual(len(result["exports"]), 32)
                self.assertIsNone(result["qualification"])
                for configuration in result["configurations"]:
                    self.assertEqual(configuration["configurationDigest"], hashlib.sha256(
                        setup._encode([configuration["objectConsumer"], configuration["fixture"]])).hexdigest())

    def test_a_different_full_publication_cannot_be_dropped_or_truncated(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = write_exports(Path(directory), 8)
            publication_path = Path(paths[-1]) / "publication.json"
            bootstrap_path = Path(paths[-1]) / "bootstrap.json"
            publication = json.loads(publication_path.read_bytes())
            publication["otherCurrentHead"] = "another-original"
            bootstrap = json.loads(bootstrap_path.read_bytes())
            bootstrap["publication"] = publication
            publication_path.write_bytes(setup._encode(publication))
            bootstrap_path.write_bytes(setup._encode(bootstrap))

            with self.assertRaises(ValueError):
                setup.project_scale_exports(paths, "1" * 32, [f"{index + 1:032x}" for index in range(4)])

    def test_wrong_file_custody_or_used_output_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = write_exports(Path(directory), 8)
            (Path(paths[0]) / "bootstrap.json").chmod(0o644)

            with self.assertRaises(ValueError):
                setup.project_scale_exports(paths, "1" * 32, [f"{index + 1:032x}" for index in range(4)])
            with self.assertRaises(FileExistsError):
                write_exports(Path(directory), 8)

    def test_bad_geometry_refuses_before_any_api_control(self):
        class NoControl:
            def reviewed(self, *arguments):
                raise AssertionError("invalid geometry dispatched a control")

        with self.assertRaises(ValueError):
            setup.bootstrap_scale_bindings(NoControl(), "1" * 32, {}, [], None, None)


class WorkloadTests(unittest.TestCase):
    def test_wave_offers_every_cohort_follower_without_relabeling_rpcs(self):
        values = calls()

        self.assertEqual(len(values), 4224)
        self.assertEqual(len({row["original"]["nonce"] for row in values}), 4224)
        for worker in selected_workers():
            rows = [row for row in values if row["worker"] == worker]
            self.assertEqual(len(rows), 1056)
            for cohort in {row["original"]["cohort_digest"] for row in rows}:
                group = [row for row in rows if row["original"]["cohort_digest"] == cohort]
                self.assertEqual({row["offeredIndex"] for row in group}, set(range(33)))
        self.assertTrue(all(row["original"]["expires_at"] - row["original"]["issued_at"] == 30 for row in values))

    def test_mac_context_and_exclusive_expiry_refuse(self):
        key, call = b"controlled-key" * 4, calls()[0]
        digest = hashlib.sha256(workload._json(call["original"])).hexdigest()
        reply = reply_for(call, digest)

        def correlate(value, selected=call):
            body = workload._json(value)
            signature = hmac.new(key, workload.REPLY_DOMAIN + body, hashlib.sha256).hexdigest()
            return workload._correlate_reply(body, signature, key, selected, digest)

        self.assertEqual(correlate(reply), reply)
        for field, value in (("nonce", "f" * 64), ("isolateLabel", "f" * 32),
                ("cohortDigest", "f" * 64), ("observedAt", 106), ("version", True)):
            with self.assertRaises(ValueError):
                correlate({**reply, field: value})

    def test_actual_inventory_refuses_omissions_and_unknown_is_not_outage_refusal(self):
        originals = calls()
        results = [{"isolateLabel": row["worker"]["isolateLabel"], "original": row["original"],
            "outcome": "unknown", "httpStatus": None} for row in originals]

        facts = workload.observed_wave(results, selected_workers(),
            [f"{index + 1:064x}" for index in range(32)])

        self.assertFalse(facts["completePositiveCoverage"])
        self.assertFalse(facts["httpRefusalsOnly"])
        self.assertIsNone(facts["issuerRpcCount"])
        with self.assertRaises(ValueError):
            workload.observed_wave(results[:-1], selected_workers(),
                [f"{index + 1:064x}" for index in range(32)])

    def test_actual_cap_requires_returned_expiry_at_the_selected_bound(self):
        replies = [{"maximumLifetime": 120, "issuedAt": 100, "notAfter": 120, "attestationValidUntil": 120}]
        facts = {"completePositiveCoverage": True, "groups": {"controlled": replies}}

        self.assertEqual(workload.observed_attestation_cap(facts)["maximumExpiry"], 120)
        replies[0]["notAfter"] = 119
        with self.assertRaises(ValueError):
            workload.observed_attestation_cap(facts)


class WorkflowTests(unittest.IsolatedAsyncioTestCase):
    async def test_reused_store_selection_refuses_before_genuine_setup_is_called(self):
        selections = [{"case": name, "maximumLifetime": lifetime, "attestationCapped": capped,
            "authorityId": name, "guardNamespaceId": name, "issuerStore": name, "physicalStore": "reused"}
            for name, lifetime, capped in [("ttl-8", 8, False), ("ttl-120", 120, False), ("cap-120", 120, True)]]

        async def setup_must_not_run(selected):
            raise AssertionError("invalid selection dispatched setup")

        with self.assertRaises(ValueError):
            await workload.run_selected_scale_cases(selections, setup_must_not_run)


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_local_http_stub_consumption_and_mac_are_separate_from_issuer(self):
        key, offered = b"controlled-key" * 4, calls()[0]
        received = []

        async def serve(reader, writer):
            header = await reader.readuntil(b"\r\n\r\n")
            size = int(next(line.split(b":", 1)[1] for line in header.split(b"\r\n")
                if line.lower().startswith(b"content-length:")))
            body = await reader.readexactly(size)
            received.append(body)
            reply = workload._json(reply_for(offered, hashlib.sha256(body).hexdigest()))
            signature = hmac.new(key, workload.REPLY_DOMAIN + reply, hashlib.sha256).hexdigest()
            writer.write((f"HTTP/1.1 200 OK\r\nContent-Length: {len(reply)}\r\n"
                f"{workload.SIGNATURE_HEADER}: {signature}\r\nConnection: close\r\n\r\n").encode() + reply)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        offered["worker"]["port"] = server.sockets[0].getsockname()[1]
        try:
            result = await workload.exchange_scale_original(offered, key)
        finally:
            server.close()
            await server.wait_closed()

        self.assertEqual(received, [workload._json(offered["original"])])
        self.assertEqual(result["outcome"], "authenticated_probe_metadata")
        self.assertGreater(result["replyBodyBytesConsumed"], 0)
        self.assertIsNone(result["issuerRpcCount"])
        self.assertIsNone(result["nativeBulkBytes"])
        self.assertIsNone(result["qualification"])

    async def test_real_short_response_retains_unknown_without_retry(self):
        received = []

        async def serve(reader, writer):
            received.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nshort")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        offered = calls()[0]
        offered["worker"]["port"] = server.sockets[0].getsockname()[1]
        try:
            result = await workload.exchange_scale_original(offered, b"controlled-key" * 4)
        finally:
            server.close()
            await server.wait_closed()

        self.assertEqual(len(received), 1)
        self.assertEqual(result["outcome"], "unknown")
        self.assertIsNone(result["replyBodyBytesConsumed"])
        self.assertIsNone(result["issuerRpcCount"])


if __name__ == "__main__":
    unittest.main()
