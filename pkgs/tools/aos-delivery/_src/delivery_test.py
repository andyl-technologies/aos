"""Exercises actual producer bytes and API protocol fences without providers.

Fixture scanners are explicit mocks. A passing unit or consumer test does not
claim an actual artifact scan, independent qualification or live admission.
"""

import argparse
import base64
import datetime
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import artifact
import delivery
from transport import ARTIFACT_MEDIA_TYPE, Client, DeliveryError, encoded


def fixture_layout(root):
    """Creates a tiny real descriptor closure for cross-repository parsing."""
    root = Path(root)
    blobs = root / "blobs" / "sha256"
    blobs.mkdir(parents=True)

    def blob(content, media):
        value = artifact.digest(content)
        (blobs / value.removeprefix("sha256:")).write_bytes(content)
        return {"digest": value, "size": len(content), "mediaType": media}

    config = blob(encoded({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}}), "application/vnd.oci.image.config.v1+json")
    manifest = blob(encoded({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": config, "layers": []}), "application/vnd.oci.image.manifest.v1+json")
    manifest["annotations"] = {"org.opencontainers.image.ref.name": "aos-hub"}
    index = encoded({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [manifest]})
    (root / "index.json").write_bytes(index)
    (root / "oci-layout").write_bytes(encoded({"imageLayoutVersion": "1.0.0"}))
    return artifact.digest(index)


class Response(io.BytesIO):
    """Acts as an ordinary bounded HTTP success response."""

    status = 200


class Opener:
    """Records actual urllib request bodies and security-relevant headers."""

    def __init__(self, *values):
        self.values = list(values)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        return Response(encoded(self.values.pop(0)))


class ProtocolTests(unittest.TestCase):
    def test_upload_finalize_and_anchored_release_actual_wire_shapes(self):
        source = {"repository": artifact.REPOSITORY, "repositoryOwnerId": "159484437", "repositoryId": "1156711779",
                  "commitSha": "a" * 40, "ref": artifact.REF, "workflowRef": artifact.WORKFLOW,
                  "workflowRunId": "101", "declarationDigest": "sha256:" + "b" * 64,
                  "declaration": base64.b64encode(b"{}").decode()}
        target = delivery.target_for("release-graph")
        calls = []

        class Intake:
            def rpc(self, method, body):
                calls.append({"method": method, "body": body})
                if method == "BeginArtifactUpload":
                    self.begin = body
                    return {"upload": {"name": "artifacts/artifact-test"}}
                if method == "FinalizeArtifactUpload":
                    return {"artifact": {"name": "artifacts/artifact-test", "objectGeneration": "1",
                            "digest": self.begin["digest"], "sizeBytes": self.begin["sizeBytes"],
                            "mediaType": ARTIFACT_MEDIA_TYPE, "sourceCommit": source["commitSha"],
                            "declarationDigest": source["declarationDigest"]}}
                request = body["reconciliation"]
                return {"operation": {"name": "operations/" + "c" * 32, "state": "OPERATION_STATE_PENDING",
                        "target": request["target"], "source": {key: value for key, value in request["source"].items() if key != "declaration"},
                        "generationAnchor": request["generationAnchor"], "artifact": request["artifact"]}}

            def upload(self, reservation, content, size, digest):
                self.uploaded = content.read()

        client = Intake()
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(os.environ, {"GITHUB_RUN_ID": "101", "GITHUB_RUN_ATTEMPT": "1"}):
            path = Path(temporary) / "artifact.tar"
            path.write_bytes(b"actual fixture bundle bytes")
            coordinate = delivery.upload(argparse.Namespace(artifact=str(path)), client, target, source)
            self.assertEqual(client.uploaded, path.read_bytes())
            coordinate_path = Path(temporary) / "coordinate.json"
            coordinate_path.write_bytes(encoded(coordinate))
            args = argparse.Namespace(command="reconcile-artifact", artifact_coordinate=str(coordinate_path),
                                      generation_anchor="operations/" + "d" * 32, github_output=None, wait=False)
            with mock.patch("sys.stdout", io.StringIO()):
                delivery.reconcile(args, client, target, source)
        self.assertEqual([call["method"] for call in calls], ["BeginArtifactUpload", "FinalizeArtifactUpload", "ReconcileAnchoredApplication"])
        output = os.environ.get("AOS_DELIVERY_WIRE_OUTPUT")
        if output:
            Path(output).write_bytes(encoded(calls))

    def test_exact_push_caller_rejects_other_sources_and_dirty_checkouts(self):
        environment = {"GITHUB_REPOSITORY": artifact.REPOSITORY, "GITHUB_REPOSITORY_ID": "1156711779",
                       "GITHUB_REPOSITORY_OWNER_ID": "159484437", "GITHUB_REF": artifact.REF,
                       "GITHUB_WORKFLOW_REF": artifact.WORKFLOW, "GITHUB_SHA": "a" * 40,
                       "GITHUB_EVENT_NAME": "push", "GITHUB_RUN_ID": "101", "GITHUB_RUN_ATTEMPT": "1"}
        with mock.patch.dict(os.environ, environment):
            with mock.patch.object(artifact.subprocess, "check_output", side_effect=["a" * 40, b""]):
                artifact.prove_source("a" * 40)
            for field, value in (("GITHUB_EVENT_NAME", "workflow_dispatch"), ("GITHUB_REF", "refs/heads/master"), ("GITHUB_REPOSITORY_ID", "999")):
                with self.subTest(field=field), mock.patch.dict(os.environ, {field: value}), mock.patch.object(artifact.subprocess, "check_output", side_effect=["a" * 40, b""]):
                    with self.assertRaises(DeliveryError):
                        artifact.prove_source("a" * 40)
            with mock.patch.object(artifact.subprocess, "check_output", side_effect=["a" * 40, b" M modified"]):
                with self.assertRaises(DeliveryError):
                    artifact.prove_source("a" * 40)

    def test_rpc_protobuf_json_and_separate_upload_credentials(self):
        opener = Opener({"upload": {}}, {})
        with mock.patch.dict(os.environ, {"DELIVERY_ID_TOKEN": "api-proof"}):
            client = Client("https://delivery.example", opener, lambda endpoint, unused: "github-proof")
        body = {"requestId": "stable", "sizeBytes": "17", "source": {"declaration": base64.b64encode(b"{}").decode()}}
        client.rpc("BeginArtifactUpload", body)
        request = opener.requests[0]
        self.assertEqual(request.full_url, "https://delivery.example/andyl.infrastructure.delivery.v1.DeliveryService/BeginArtifactUpload")
        self.assertEqual(json.loads(request.data), body)
        self.assertEqual(request.get_header("Authorization"), "Bearer api-proof")
        self.assertEqual(request.get_header("X-andyl-github-oidc"), "github-proof")
        self.assertEqual(request.get_header("Connect-protocol-version"), "1")

        reservation = {"expectedSizeBytes": "17", "expectedDigest": "sha256:" + "c" * 64,
                       "mediaType": ARTIFACT_MEDIA_TYPE, "uploadUrl": "https://storage.example/object?signature=private"}
        client.upload(reservation, io.BytesIO(b"actual file bytes"), 17, reservation["expectedDigest"])
        upload = opener.requests[1]
        self.assertIsNone(upload.get_header("Authorization"))
        self.assertIsNone(upload.get_header("X-andyl-github-oidc"))
        self.assertEqual(upload.get_header("X-goog-if-generation-match"), "0")
        self.assertEqual(upload.get_header("Content-length"), "17")

    def test_finalize_and_cross_job_coordinate_fences(self):
        target = delivery.target_for("release-graph")
        source = {"repository": artifact.REPOSITORY, "repositoryOwnerId": "159484437", "repositoryId": "1156711779",
                  "commitSha": "a" * 40, "ref": artifact.REF, "workflowRef": artifact.WORKFLOW,
                  "workflowRunId": "101", "declarationDigest": "sha256:" + "b" * 64}
        coordinate = {**delivery.coordinate_for(target, source), "name": "artifacts/artifact-test", "digest": "sha256:" + "c" * 64}
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "coordinate.json"
            path.write_bytes(encoded(coordinate))
            self.assertEqual(delivery.checked_coordinate(path, target, source), coordinate)
            for field, value in (("workflowRunId", "102"), ("sourceRef", "refs/heads/master"), ("surface", "other"), ("declarationDigest", "sha256:" + "d" * 64)):
                path.write_bytes(encoded({**coordinate, field: value}))
                with self.subTest(field=field), self.assertRaises(DeliveryError):
                    delivery.checked_coordinate(path, target, source)

    def test_database_integrity_schema_and_freshness(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        status = {"valid": True, "schemaVersion": "v6.1.9", "built": now.isoformat()}
        delivery.validate_database(status)
        for changed in ({"valid": False}, {"error": "bad"}, {"schemaVersion": "v5.1.0"},
                        {"built": (now - datetime.timedelta(hours=121)).isoformat()},
                        {"built": (now + datetime.timedelta(hours=1)).isoformat()}):
            with self.subTest(changed=changed), self.assertRaises(DeliveryError):
                delivery.validate_database({**status, **changed})

    def test_operation_replacement_cannot_pass_target_source_or_anchor_fences(self):
        target = delivery.target_for("release-graph")
        source = {"commitSha": "a" * 40, "artifactDigest": "sha256:" + "b" * 64}
        anchor = "operations/" + "c" * 32
        operation = {"name": "operations/" + "d" * 32, "target": target, "source": source,
                     "generationAnchor": anchor, "artifact": "artifacts/artifact-test"}
        delivery.checked_operation(operation, target, source, anchor, operation["artifact"])
        for changed in ({"target": delivery.target_for("application")}, {"source": {**source, "commitSha": "f" * 40}},
                        {"generationAnchor": "operations/" + "e" * 32}, {"artifact": "artifacts/artifact-other"}):
            with self.subTest(changed=changed), self.assertRaises(DeliveryError):
                delivery.checked_operation({**operation, **changed}, target, source, anchor, operation["artifact"])

    def test_watch_fences_same_commit_foreign_source_target_artifact_and_anchor(self):
        source = {
            "repository": artifact.REPOSITORY,
            "repositoryOwnerId": "159484437",
            "repositoryId": "1156711779",
            "commitSha": "a" * 40,
            "ref": artifact.REF,
            "workflowRef": artifact.WORKFLOW,
            "workflowRunId": "101",
            "declarationDigest": "sha256:" + "b" * 64,
        }
        target = delivery.target_for("release-graph")
        anchor = "operations/" + "c" * 32
        name = "artifacts/artifact-test"
        digest = "sha256:" + "d" * 64
        coordinate = {**delivery.coordinate_for(target, source), "name": name, "digest": digest}
        operation = {
            "name": "operations/" + "e" * 32,
            "target": target,
            "source": {**source, "artifactDigest": digest},
            "generationAnchor": anchor,
            "artifact": name,
        }
        client = mock.Mock()
        client.wait.side_effect = lambda current, timeout: current
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "coordinate.json"
            path.write_bytes(encoded(coordinate))
            args = argparse.Namespace(
                operation=operation["name"], phase="release-graph", timeout=1,
                artifact_coordinate=str(path), generation_anchor=anchor,
            )
            client.rpc.return_value = {"operation": operation}
            with mock.patch("sys.stdout", io.StringIO()):
                delivery.watch(args, client, source)
            client.wait.assert_called_once()
            mutations = [
                {"name": "operations/" + "f" * 32},
                {"target": delivery.target_for("application")},
                {"generationAnchor": "operations/" + "f" * 32},
                {"artifact": "artifacts/artifact-other"},
            ]
            mutations.extend(
                {"source": {**operation["source"], field: "different"}}
                for field in source if field != "commitSha"
            )
            mutations.append({"source": {**operation["source"], "artifactDigest": "sha256:" + "f" * 64}})
            for changed in mutations:
                client.wait.reset_mock()
                client.rpc.return_value = {"operation": {**operation, **changed}}
                with self.subTest(changed=changed), self.assertRaises(DeliveryError):
                    delivery.watch(args, client, source)
                client.wait.assert_not_called()
            args.phase = "application"
            with self.assertRaises(DeliveryError):
                delivery.watch(args, client, source)
            args.artifact_coordinate = None
            args.generation_anchor = None
            client.rpc.return_value = {"operation": {
                "name": args.operation,
                "source": source,
                "target": delivery.target_for("application"),
            }}
            with mock.patch("sys.stdout", io.StringIO()):
                delivery.watch(args, client, source)
            client.wait.assert_called_once()

    def test_presentation_whitespace_never_changes_canonical_declaration_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "project.json"
            path.write_text('{ "b": 2, "a": 1 }\n')
            self.assertEqual(artifact.declaration_content(path), b'{"a":1,"b":2}')


class ProducerTests(unittest.TestCase):
    def test_layout_tampering_and_unassigned_files_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "original"
            fixture_layout(source)
            artifact.normalize_layout(source, root / "normalized")
            blob = next((source / "blobs" / "sha256").iterdir())
            original = blob.read_bytes()
            blob.write_bytes(b"tampered")
            with self.assertRaises(DeliveryError):
                artifact.normalize_layout(source, root / "bad")
            blob.write_bytes(original)
            (source / "unassigned").write_text("extra")
            with self.assertRaises(DeliveryError):
                artifact.normalize_layout(source, root / "extra")

    def test_empty_coverage_and_critical_findings_fail_closed(self):
        with self.assertRaises(DeliveryError):
            artifact.validate_catalog({"artifacts": []})
        with self.assertRaises(DeliveryError):
            artifact.validate_catalog({"artifacts": [{"name": "generic", "version": "1"}]})
        artifact.validate_catalog({"artifacts": [{"name": "fixture", "version": "1", "purl": "pkg:generic/fixture@1"}]})
        with self.assertRaises(DeliveryError):
            artifact.validate_scan({"descriptor": {}, "matches": [{"vulnerability": {"severity": "Critical"}}]})
        with self.assertRaises(DeliveryError):
            artifact.validate_scan({"descriptor": {}, "matches": [], "ignoredMatches": [{"vulnerability": {"severity": "Critical"}}]})

    def test_actual_producer_is_deterministic_and_consumer_ready(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "image"
            original_digest = fixture_layout(image / "layout")
            evidence = root / "evidence" / "evidence"
            evidence.mkdir(parents=True)
            (evidence / "sbom.payload.json").write_bytes(encoded({"spdxVersion": "SPDX-2.3", "packages": [{"name": "fixture", "versionInfo": "1"}]}))
            (evidence / "provenance.payload.json").write_bytes(encoded({"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://aos.dev/attestations/container-build/v1",
                "subject": [{"name": "container-image-index", "digest": {"sha256": original_digest.removeprefix("sha256:")}}]}))
            declaration = root / "project.json"
            declaration.write_bytes(encoded({"name": artifact.APPLICATION, "releaseGroups": {"native": {"components": [artifact.COMPONENT]}}}))
            database = root / "db-status.json"
            database.write_bytes(encoded({"valid": True, "schemaVersion": "v6.1.9", "built": datetime.datetime.now(datetime.timezone.utc).isoformat()}))
            args = argparse.Namespace(source_sha="a" * 40, declaration=str(declaration), image=str(image), evidence=str(root / "evidence"), cataloger="fixture-syft", scanner="fixture-grype", database_status=str(database), output=str(root / "first.tar"))
            calls = []

            def scanner(argv, check):
                calls.append(argv)
                if argv[0] == "fixture-syft":
                    catalog = argv[argv.index("--output") + 1].removeprefix("syft-json=")
                    Path(catalog).write_bytes(encoded({"artifacts": [{"name": "fixture", "version": "1", "type": "generic", "purl": "pkg:generic/fixture@1"}]}))
                    spdx = argv[-1].removeprefix("spdx-json=")
                    Path(spdx).write_bytes(encoded({"spdxVersion": "SPDX-2.3", "packages": [{"name": "fixture"}]}))
                else:
                    self.assertEqual(argv[-2:], ["--fail-on", "critical"])
                    Path(argv[argv.index("--file") + 1]).write_bytes(encoded({"descriptor": {"name": "fixture-grype"}, "matches": []}))

            with mock.patch.object(artifact, "prove_source"), mock.patch.object(artifact, "archive_digest", return_value="sha256:" + "d" * 64), mock.patch.object(artifact, "enrich_cargo_inventory", return_value={"fixture": True}), mock.patch.object(artifact.subprocess, "run", side_effect=scanner), mock.patch.dict(os.environ, {"GITHUB_RUN_ID": "101"}):
                artifact.build_bundle(args)
                args.output = str(root / "second.tar")
                artifact.build_bundle(args)
            self.assertEqual((root / "first.tar").read_bytes(), (root / "second.tar").read_bytes())
            self.assertEqual(len(calls), 6)
            output = os.environ.get("AOS_DELIVERY_FIXTURE_OUTPUT")
            if output:
                Path(output).write_bytes((root / "first.tar").read_bytes())


if __name__ == "__main__":
    unittest.main()
