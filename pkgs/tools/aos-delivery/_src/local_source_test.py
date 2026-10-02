"""Tests local Git refusal and bundle mode separation with real Git fixtures.

Scanner fixtures exercise packaging gates only; they do not qualify a backend
or claim that Syft/Grype scanned a production image.
"""

import argparse
import contextlib
import datetime
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

import artifact
import delivery
import local_source
from delivery_test import fixture_layout
from transport import DeliveryError, encoded


class LocalSourceTests(unittest.TestCase):
    def setUp(self):
        self.git_path = os.environ["PATH"]
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.enter = contextlib.chdir(self.repo)
        self.enter.__enter__()
        self.addCleanup(self.enter.__exit__, None, None, None)
        self.git("init", "-q", "-b", artifact.REF.removeprefix("refs/heads/"))
        self.git("config", "user.name", "Source fixture")
        self.git("config", "user.email", "fixture@example.test")
        self.git("remote", "add", "origin", "https://github.com/" + artifact.REPOSITORY)
        source = self.repo / "crates/aos-proto/src/proto/aos/hub/source.proto"
        source.parent.mkdir(parents=True)
        source.write_text("fixture source\n")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "Initial source fixture")
        self.revision = self.git("rev-parse", "HEAD").strip()

    def git(self, *arguments):
        return subprocess.check_output(["git", *arguments], text=True, stderr=subprocess.PIPE)

    def proof(self):
        return local_source.prove(self.revision, artifact.REPOSITORY, artifact.REF)

    def test_actual_tree_archive_and_explicit_cli_proof(self):
        proof = self.proof()
        self.assertEqual(proof["tree"], self.git("rev-parse", "HEAD^{tree}").strip())
        self.assertEqual(proof["archiveDigest"], artifact.archive_digest(self.revision))
        with mock.patch("sys.stdout", io.StringIO()) as output:
            delivery.main(["prove-source", "--source-proof", "local", "--source-sha", self.revision])
        self.assertEqual(json.loads(output.getvalue()), proof)
        self.assertNotIn("workflowRef", proof)
        self.assertNotIn("runId", proof)

    def test_sha_dirty_index_untracked_and_hidden_changes_refuse(self):
        args = argparse.Namespace(source_proof="local", source_sha="short", output=str(self.root / "bad.tar"))
        with self.assertRaises(DeliveryError):
            artifact.build_bundle(args)
        self.assertFalse(Path(args.output).exists())
        with self.assertRaises(DeliveryError):
            local_source.prove("a" * 40, artifact.REPOSITORY, artifact.REF)

        source = Path("crates/aos-proto/src/proto/aos/hub/source.proto")
        source.write_text("changed\n")
        with self.assertRaises(DeliveryError):
            self.proof()
        self.git("add", ".")
        with self.assertRaises(DeliveryError):
            self.proof()
        self.git("reset", "--hard", "-q")
        Path("extra").write_text("untracked")
        args.source_sha = self.revision
        with self.assertRaises(DeliveryError):
            artifact.build_bundle(args)
        self.assertFalse(Path(args.output).exists())
        Path("extra").unlink()
        self.git("update-index", "--assume-unchanged", str(source))
        source.write_text("hidden change\n")
        with self.assertRaises(DeliveryError):
            self.proof()

    def test_ref_repository_ignored_and_proof_drift_refuse(self):
        proof = self.proof()
        for field in ("tree", "archiveDigest"):
            with self.subTest(field=field), self.assertRaises(DeliveryError):
                local_source.recheck({**proof, field: "different"})
        self.git("remote", "set-url", "origin", "https://example.test/aos")
        with self.assertRaises(DeliveryError):
            self.proof()
        self.git("remote", "set-url", "origin", proof["origin"])
        self.git("switch", "-q", "-c", "dplecki/other-source")
        with self.assertRaises(DeliveryError):
            self.proof()
        self.git("switch", "-q", artifact.REF.removeprefix("refs/heads/"))
        Path(".git/info/exclude").write_text("ignored\n")
        Path("ignored").write_text("build output")
        with self.assertRaises(DeliveryError):
            self.proof()

    def test_local_mode_cannot_authorize_legacy_transport(self):
        with mock.patch.dict(os.environ, {"PATH": self.git_path}, clear=True):
            with self.assertRaises(DeliveryError):
                artifact.prove_source(self.revision)
        for command in ("upload-artifact", "reconcile", "reconcile-artifact", "watch"):
            argv = [command, "--endpoint", "https://example.test", "--source-sha", self.revision, "--declaration", "project.json"]
            if command == "upload-artifact":
                argv.extend(["--artifact", "bundle.tar"])
            elif command == "reconcile-artifact":
                argv.extend(["--artifact-coordinate", "coordinate.json", "--generation-anchor", "operations/fixture"])
            elif command == "watch":
                argv.extend(["--operation", "operations/fixture", "--phase", "application"])
            with self.subTest(command=command), mock.patch("sys.stderr", io.StringIO()) as errors, self.assertRaises(SystemExit):
                delivery.main([*argv, "--source-proof", "local"])
            self.assertIn("unrecognized arguments: --source-proof local", errors.getvalue())

    def test_clean_new_commit_and_detached_ref_cannot_reuse_proof(self):
        proof = self.proof()
        Path("new-source").write_text("new tracked source")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "Changed source fixture")
        with self.assertRaises(DeliveryError):
            local_source.recheck(proof)
        self.git("switch", "-q", "--detach", self.revision)
        with self.assertRaises(DeliveryError):
            self.proof()

    def test_subdirectory_proof_checks_hidden_flags_across_repository(self):
        proof = self.proof()
        source = "crates/aos-proto/src/proto/aos/hub/source.proto"
        subtree = self.repo / "empty-subtree"
        subtree.mkdir()
        with contextlib.chdir(subtree):
            self.assertEqual(self.proof(), proof)
            self.git("update-index", "--assume-unchanged", "../" + source)
            with self.assertRaises(DeliveryError):
                self.proof()

    def bundle_inputs(self):
        image = self.root / "image"
        original = fixture_layout(image / "layout")
        evidence = self.root / "evidence/evidence"
        evidence.mkdir(parents=True)
        (evidence / "sbom.payload.json").write_bytes(encoded({"spdxVersion": "SPDX-2.3", "packages": [{"name": "fixture"}]}))
        (evidence / "provenance.payload.json").write_bytes(encoded({
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://aos.dev/attestations/container-build/v1",
            "subject": [{"name": "container-image-index", "digest": {"sha256": original.removeprefix("sha256:")}}],
        }))
        declaration = self.root / "project.json"
        declaration.write_bytes(encoded({"name": artifact.APPLICATION, "releaseGroups": {"native": {"components": [artifact.COMPONENT]}}}))
        database = self.root / "db.json"
        database.write_bytes(encoded({"valid": True, "schemaVersion": "v6.1.9", "built": datetime.datetime.now(datetime.timezone.utc).isoformat()}))
        return argparse.Namespace(
            source_proof="local", source_sha=self.revision, declaration=str(declaration),
            image=str(image), evidence=str(evidence.parent), cataloger="fixture-syft",
            scanner="fixture-grype", database_status=str(database), output=str(self.root / "bundle.tar"),
        )

    def test_local_bundle_provenance_and_after_scan_source_refusal(self):
        args = self.bundle_inputs()
        run = subprocess.run
        drift = False

        def scanner(argv, **kwargs):
            if argv[0] == "fixture-syft":
                Path(argv[3].removeprefix("syft-json=")).write_bytes(encoded({"artifacts": [{"name": "fixture", "version": "1", "purl": "pkg:generic/fixture@1"}]}))
                Path(argv[5].removeprefix("spdx-json=")).write_bytes(encoded({"spdxVersion": "SPDX-2.3", "packages": [{"name": "fixture"}]}))
            elif argv[0] == "fixture-grype":
                Path(argv[5]).write_bytes(encoded({"descriptor": {}, "matches": []}))
                if drift:
                    Path("changed-during-scan").write_text("source contamination")
            else:
                return run(argv, **kwargs)

        with mock.patch.object(artifact.subprocess, "run", side_effect=scanner), mock.patch.object(artifact, "enrich_cargo_inventory", return_value={"fixture": True}), mock.patch.dict(os.environ, {}, clear=True):
            # Retain PATH for source-built Git; no workflow variables exist.
            os.environ["PATH"] = self.git_path
            artifact.build_bundle(args)
            with tarfile.open(args.output) as bundle:
                manifest = json.load(bundle.extractfile("manifest.json"))
                provenance = json.load(bundle.extractfile("attestations/" + artifact.COMPONENT + "/slsa-provenance.json"))
            self.assertEqual(manifest["sourceProof"], self.proof())
            self.assertEqual(provenance["sourceProof"], manifest["sourceProof"])
            self.assertEqual(manifest["repositoryId"], 1156711779)
            self.assertEqual(manifest["ownerId"], 159484437)
            self.assertNotIn("repositoryId", manifest["sourceProof"])
            self.assertNotIn("workflowRef", provenance)
            self.assertNotIn("runId", provenance)
            with self.assertRaises(FileExistsError):
                artifact.build_bundle(args)
            drift = True
            args.output = str(self.root / "invalid.tar")
            with self.assertRaises(DeliveryError):
                artifact.build_bundle(args)
            self.assertFalse(Path(args.output).exists())
