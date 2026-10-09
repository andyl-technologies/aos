"""Check Managed producer ordering, command contracts and refusal boundaries.

Command and HTTP boundaries are controlled here. These tests do not publish a
container, contact a provider or establish a runtime qualification result.
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "managed_container", Path(__file__).with_name("_hub-managed-container.py"))
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)

RUN = "a" * 32
ORIGIN = "https://localhost:4643"
SLUG = "managed-" + RUN + "/containers"
TOOLS = {"aos": "/nix/store/fixture-aos/bin/aos",
    "apr": "/nix/store/fixture-aos/bin/apr", "git": "/nix/store/fixture-git/bin/git",
    "opensshBin": "/nix/store/fixture-openssh/bin", "nixBin": "/nix/store/fixture-nix/bin",
    "helperStorePath": "/nix/store/fixture-helper", "aosStorePath": "/nix/store/fixture-aos",
    "containerPublicationInputs": "/nix/store/fixture-publication-inputs",
    "python": "/nix/store/fixture-python/bin/python3"}


class ProducerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.coordinates = {"runId": RUN, "clientRoot": str(self.root), "workerOrigin": ORIGIN}
        self.source = {"helperSha256": "b" * 64, "sourceCommit": "1" * 64,
            "surfaceRoot": str(self.root / "surface"), "registryRoot": str(self.root / "registry"),
            "finalized": {"index_digest": "sha256:" + "c" * 64, "release_identity": "1.0.0",
                "release": str(self.root / "release.json"), "layout": str(self.root / "layout"),
                "signature_input": str(self.root / "signature-input.json")}}
        (self.root / "source.private.json").write_text(json.dumps(self.source))

    def selection(self, action):
        return {"tools": TOOLS, "coordinates": self.coordinates, "source": self.source,
            "helperSha256": "b" * 64, "action": action, "registry": SLUG, "token": "private"}

    def retain(self, name, value):
        (self.root / name).write_text(json.dumps(value))

    def test_actual_pipeline_waits_for_exact_index_before_final_publish(self):
        calls = []
        signed_commit = "2" * 64

        class Controls:
            def call(self, service, method, request):
                calls.append((service, method, request))
                return {"registry": {"indexState": "fresh", "lastIndexedCommit": signed_commit}}

        def guest(client, tools, coordinates, action, **values):
            calls.append(action)
            if action == "release":
                return {"sourceCommit": signed_commit}
            return {"state": "ready"}

        with patch.object(producer, "_guest", side_effect=guest):
            result = producer.publish_managed_container(None, TOOLS, Controls(), self.coordinates,
                {"slug": SLUG}, self.source, lambda: "private")
        self.assertEqual(calls, ["stage", "release", "registry-upload",
            ("RegistryService", "GetRegistry", {"slug": SLUG}), "retain-index", "publish"])
        self.assertEqual(result["signedSource"]["sourceCommit"], signed_commit)

    def test_stale_index_never_invokes_final_publish(self):
        actions = []

        class Controls:
            def call(self, *arguments):
                return {"registry": {"indexState": "fresh", "lastIndexedCommit": "9" * 64}}

        def guest(client, tools, coordinates, action, **values):
            actions.append(action)
            return {"sourceCommit": "2" * 64}

        with patch.object(producer, "_guest", side_effect=guest), \
                patch.object(producer.time, "monotonic", side_effect=[0, 241]):
            with self.assertRaisesRegex(ValueError, "exact current index"):
                producer.publish_managed_container(None, TOOLS, Controls(), self.coordinates,
                    {"slug": SLUG}, self.source, lambda: "private")
        self.assertNotIn("publish", actions)
        self.assertEqual(actions[-1], "retain-index")

    def test_failed_stage_is_not_retried_or_promoted(self):
        with patch.object(producer, "_guest", side_effect=RuntimeError("unknown stage")) as guest:
            with self.assertRaises(RuntimeError):
                producer.publish_managed_container(None, TOOLS, None, self.coordinates,
                    {"slug": SLUG}, self.source, lambda: "private")
        self.assertEqual(guest.call_count, 1)

    def test_other_registry_is_refused_before_command(self):
        with patch.object(producer, "_guest") as guest:
            with self.assertRaises(ValueError):
                producer.publish_managed_container(None, TOOLS, None, self.coordinates,
                    {"slug": "managed-" + "d" * 32 + "/containers"}, self.source, lambda: "private")
        guest.assert_not_called()

    def test_stage_arguments_never_require_direct_and_final_is_not_stage_only(self):
        captured = []

        def run(root, environment, label, arguments, **options):
            captured.append(arguments)
            return {"index_digest": self.source["finalized"]["index_digest"],
                "state": "staged", "tag_updated": False}

        with patch.object(producer, "_run", side_effect=run):
            producer._publish_action(self.root, self.selection("stage"), {})
        arguments = captured[0]
        self.assertIn("--stage-only", arguments)
        self.assertNotIn("--direct-required", arguments)
        self.assertEqual(arguments[arguments.index("--registry") + 1], SLUG)
        self.assertIn("localhost:4643/aos:managed-" + RUN, arguments)

    def test_signed_release_requires_staged_result_and_uses_exact_sidecar(self):
        selected = self.selection("release")
        with patch.object(producer, "_run") as run:
            with self.assertRaises(FileNotFoundError):
                producer._publish_action(self.root, selected, {})
        run.assert_not_called()
        self.retain("stage-result.private.json", {"state": "staged", "tag_updated": False})
        commands = []

        def execute(root, environment, label, arguments, **options):
            commands.append(arguments)
            if label == "signed-commit":
                output = root / "test-signed-commit"
                output.mkdir()
                (output / "stdout.private").write_text("2" * 64 + "\n")
                return output

        with patch.object(producer, "_run", side_effect=execute):
            result = producer._publish_action(self.root, selected, {})
        self.assertEqual(commands[0][2], TOOLS["aosStorePath"])
        release = commands[1]
        self.assertIn("--container-release", release)
        self.assertEqual(release[release.index("--channel") + 1], "stable")
        self.assertIn("--init-channel", release)
        self.assertIn(self.source["finalized"]["signature_input"], release)
        self.assertEqual(result["sourceCommit"], "2" * 64)

    def test_final_publication_requires_actual_ready_and_exact_index(self):
        selected = self.selection("publish")
        with patch.object(producer, "_run") as run:
            with self.assertRaises(FileNotFoundError):
                producer._publish_action(self.root, selected, {})
        run.assert_not_called()
        self.retain("registry-upload-result.private.json", {"state": "ready"})
        self.retain("signed-source.json", {"sourceCommit": "2" * 64})
        self.retain("index-observations.json", [{"indexState": "fresh", "lastIndexedCommit": "2" * 64}])
        with patch.object(producer, "_run", return_value={"index_digest": "sha256:" + "c" * 64,
                "verified_release_root": "sha256:" + "c" * 64, "verification": "pending"}):
            with self.assertRaisesRegex(ValueError, "verified ready"):
                producer._publish_action(self.root, selected, {})

    def test_registry_upload_uses_actual_flat_data_result(self):
        self.retain("signed-source.json", {"sourceCommit": "2" * 64})
        with patch.object(producer, "_run", return_value={"data": {"state": "ready", "publication_id": "actual"}}):
            result = producer._publish_action(self.root, self.selection("registry-upload"), {})
        self.assertEqual(result["publication_id"], "actual")

    def test_environment_preserves_home_and_uses_supported_xdg(self):
        with patch.dict(os.environ, {"HOME": "/existing-guest-home"}, clear=False):
            environment = producer._environment(self.root, TOOLS)
        self.assertEqual(environment["HOME"], "/existing-guest-home")
        self.assertEqual(environment["XDG_CONFIG_HOME"], str(self.root / "publisher/.config"))
        self.assertIn(TOOLS["opensshBin"], environment["PATH"])

    def test_prepare_executes_real_command_shapes_with_private_xdg_and_local_identity(self):
        root = self.root / "fresh"
        root.mkdir(mode=0o700)
        commands = []

        def execute(directory, environment, label, arguments, **options):
            commands.append((label, arguments, dict(environment)))
            output = directory / ("controlled-" + label)
            output.mkdir()
            (output / "stdout.private").write_text("")
            (output / "stderr.private").write_text("")
            if label == "key":
                key = Path(environment["XDG_CONFIG_HOME"]) / "apm/keys/containers-initial.key"
                key.parent.mkdir(parents=True)
                key.write_text("controlled signing command output")
                (output / "stderr.private").write_text("Public key: containers:Ed25519:controlled\n")
            if label == "finalize-signature":
                finalized = directory / "finalized"
                finalized.mkdir()
                (finalized / "layout").mkdir()
                for name in ("release.json", "signature-input.json"):
                    (finalized / name).write_text("{}")
                return {"verification": "verified-external-sshsig", "release_identity": "1.0.0",
                    "index_digest": "sha256:" + "c" * 64, "layout": str(finalized / "layout"),
                    "release": str(finalized / "release.json"),
                    "signature_input": str(finalized / "signature-input.json")}
            if label == "initial-commit":
                (output / "stdout.private").write_text("1" * 64 + "\n")
            return output

        with patch.object(producer, "_run", side_effect=execute), \
                patch.dict(os.environ, {"HOME": "/existing-guest-home"}, clear=False):
            result = producer._prepare(root, self.selection("prepare"))
        self.assertEqual([row[0] for row in commands], ["key", "create", "git-user.name",
            "git-user.email", "prepare-signature", "sign", "finalize-signature", "initial-commit"])
        self.assertTrue(all(row[2]["HOME"] == "/existing-guest-home" for row in commands))
        self.assertIn("--local", commands[2][1])
        self.assertNotIn("--global", commands[2][1])
        self.assertIn("aos-container-signature-dsse-v1", commands[5][1])
        self.assertEqual(result["sourceCommit"], "1" * 64)
        self.assertEqual(result["trustKey"], "containers:Ed25519:controlled")

    def documentation(self, *, options=None, identity_digest=None):
        package = {"storePath": "/nix/store/selected-hub", "version": "0.1.0"}
        body = json.dumps({"schema": "aos.module.documentation",
            "options": [{"path": "aos.hub.enable"}] if options is None else options}).encode()
        source = self.root / "canonical-document"
        source.mkdir()
        (source / "options.json").write_bytes(body)
        digest = hashlib.sha256(body).hexdigest()
        registry = self.root / "documentation-registry"
        (registry / "packages/a").mkdir(parents=True)
        identity = {"store_path": str(source), "document_sha256": "sha256:" + (identity_digest or digest),
            "document_size": len(body)}
        (registry / "packages/a/aos-hub.toml").write_text(
            '[[versions]]\nversion = "0.1.0"\n[versions.platforms.x86_64-linux.module_documentation]\n'
            + ''.join(name + ' = ' + json.dumps(value) + '\n' for name, value in identity.items()))
        return package, body, registry

    def test_documentation_is_real_publish_command_then_independent_canonical_read(self):
        package, body, registry = self.documentation()
        with patch.object(producer, "_run") as run:
            result = producer._prepare_documentation(self.root, {},
                {**TOOLS, "documentedPackage": package}, registry)
        command = run.call_args.args[3]
        self.assertEqual(command[:3], [TOOLS["apr"], "publish", package["storePath"]])
        self.assertNotIn("--documentation-base-lib", command)
        self.assertEqual(Path(result["file"]).read_bytes(), body)
        self.assertEqual(Path(result["file"]).stat().st_mode & 0o777, 0o600)
        self.assertEqual(result["sha256"], hashlib.sha256(body).hexdigest())

    def test_documentation_refuses_noncanonical_identity_or_empty_option_content(self):
        for options, identity_digest in (([], None), (None, "a" * 64)):
            with self.subTest(options=options, digest=identity_digest):
                with tempfile.TemporaryDirectory() as temporary:
                    previous = self.root
                    self.root = Path(temporary)
                    package, _, registry = self.documentation(options=options, identity_digest=identity_digest)
                    with patch.object(producer, "_run"), self.assertRaisesRegex(ValueError, "canonical option"):
                        producer._prepare_documentation(self.root, {}, {**TOOLS, "documentedPackage": package}, registry)
                    self.assertFalse((self.root / "document.private.json").exists())
                    self.root = previous

    def test_documentation_rejects_unselected_source_before_command(self):
        for selected in ({"storePath": "/host/hub", "version": "0.1.0"},
                {"storePath": "/nix/store/hub", "version": "0.1.0", "extra": True}):
            with patch.object(producer, "_run") as run, self.assertRaises(ValueError):
                producer._prepare_documentation(self.root, {}, {**TOOLS, "documentedPackage": selected}, self.root)
            run.assert_not_called()

    def test_source_drift_refuses_before_external_command(self):
        selected = self.selection("stage")
        selected["source"] = {**self.source, "sourceCommit": "4" * 64}
        with patch.object(producer, "_run") as run:
            with self.assertRaisesRegex(ValueError, "selection changed"):
                producer._publish_action(self.root, selected, {})
        run.assert_not_called()

    def test_location_is_exact_origin_with_no_credentials_or_redirect(self):
        self.assertEqual(producer._same_origin_location(ORIGIN, ORIGIN + "/v2/aos/blobs/uploads/",
            "/v2/aos/blobs/uploads/actual?state=1"), ORIGIN + "/v2/aos/blobs/uploads/actual?state=1")
        for location in ("https://other.example.test/upload", "http://localhost:4643/upload",
                "https://user@localhost:4643/upload", "/upload#fragment", ""):
            with self.subTest(location=location), self.assertRaises(ValueError):
                producer._same_origin_location(ORIGIN, ORIGIN, location)

    def test_headers_are_case_insensitive_and_ambiguous_refuses(self):
        self.assertEqual(producer._header({"location": "/upload"}, "Location"), "/upload")
        with self.assertRaises(ValueError):
            producer._header({"location": "a", "Location": "b"}, "Location")

    def test_unrooted_uses_actual_random_body_and_distribution_sequence(self):
        self.retain("publish-result.private.json", {"verification": "verified"})
        calls = []

        def request(root, label, method, url, token, body, status, headers=None):
            calls.append((method, url, body, headers, status))
            if method in {"POST", "PATCH"}:
                return {"headers": {"location": "/v2/aos/blobs/uploads/actual?state=2"}}
            return {"headers": {"Docker-Content-Digest": "sha256:" + hashlib.sha256(calls[1][2]).hexdigest()}}

        with patch.object(producer, "_request", side_effect=request):
            result = producer._distribution(self.root, self.selection("unrooted"))
        self.assertEqual([call[0] for call in calls], ["POST", "PATCH", "PUT"])
        self.assertEqual(len(calls[1][2]), 256)
        self.assertEqual(calls[1][3]["Content-Range"], "0-255")
        self.assertIn("digest=sha256%3A", calls[2][1])
        self.assertEqual(result["digest"], "sha256:" + hashlib.sha256(calls[1][2]).hexdigest())

    def test_root_mutation_hashes_retained_signed_document_and_refuses_drift(self):
        self.retain("publish-result.private.json", {"verification": "verified"})
        document = json.dumps({"mediaType": "application/vnd.oci.image.index.v1+json",
            "schemaVersion": 2, "manifests": []}).encode()
        digest = "sha256:" + hashlib.sha256(document).hexdigest()
        self.source["finalized"]["index_digest"] = digest
        self.retain("source.private.json", self.source)
        blob = Path(self.source["finalized"]["layout"]) / "blobs/sha256" / digest.split(":")[1]
        blob.parent.mkdir(parents=True)
        blob.write_bytes(document)
        with patch.object(producer, "_request", return_value={"headers": {"Docker-Content-Digest": digest}}) as request:
            result = producer._distribution(self.root, self.selection("root-mutation"))
        self.assertEqual(result["digest"], digest)
        self.assertEqual(request.call_args.args[5], document)
        blob.write_bytes(document + b"\n")
        with patch.object(producer, "_request") as request:
            with self.assertRaisesRegex(ValueError, "document changed"):
                producer._distribution(self.root, self.selection("root-mutation"))
        request.assert_not_called()

    def test_generated_guest_program_is_valid_and_uses_private_transport(self):
        commands = []

        class Agent:
            def request(self, command, timeout):
                commands.append(command.decode())
                return 0, b'{"retained":true}', b""

        class Client:
            agent = Agent()

        producer._guest(Client(), TOOLS, self.coordinates, "prepare")
        program = commands[0].split("\n", 1)[1].rsplit("\nMANAGED_CONTAINER_PROGRAM", 1)[0]
        compile(program, "managed-guest", "exec")
        self.assertNotIn("--direct-required", program)
        self.assertNotIn("config\", \"--global", program)

    def candidate_source(self):
        document = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:" + "e" * 64, "size": 321,
                "platform": {"architecture": "amd64", "os": "linux"}}],
            "annotations": {"org.opencontainers.image.version": "1.0.0"}}
        body = json.dumps(document).encode()
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        self.source["finalized"]["index_digest"] = digest
        self.retain("source.private.json", self.source)
        blob = Path(self.source["finalized"]["layout"]) / "blobs/sha256" / digest.split(":")[1]
        blob.parent.mkdir(parents=True)
        blob.write_bytes(body)
        self.retain("publish-result.private.json", {"verification": "verified"})
        return document, blob

    def candidate_transport(self, mismatch=False):
        calls = []

        def request(root, label, method, url, token, body, status, headers=None):
            calls.append((method, url, body, headers))
            digest = url.rsplit("/", 1)[1]
            if method == "GET":
                directory = root / label
                directory.mkdir()
                (directory / "response-body.private").write_bytes(
                    b"changed" if mismatch else calls[0][2])
            return {"status": status, "headers": {"Docker-Content-Digest": digest,
                "Content-Type": "application/vnd.oci.image.index.v1+json"}}

        return calls, request

    def test_candidate_is_distinct_digest_only_admission_with_exact_children_and_readback(self):
        original, _ = self.candidate_source()
        calls, request = self.candidate_transport()
        with patch.object(producer, "_request", side_effect=request):
            candidate = producer._distribution(self.root, self.selection("prepare-root-candidate"))
        self.assertEqual([row[0] for row in calls], ["PUT", "GET"])
        self.assertNotEqual(candidate["digest"], self.source["finalized"]["index_digest"])
        self.assertTrue(all(row[1].endswith("/manifests/" + candidate["digest"]) for row in calls))
        document = json.loads(calls[0][2])
        self.assertEqual(document["manifests"], original["manifests"])
        self.assertEqual(document["annotations"]["org.aos.fixture.gc-candidate"], RUN)
        self.assertEqual(document["annotations"]["org.opencontainers.image.version"], "1.0.0")
        self.assertEqual(Path(candidate["bodyPath"]).read_bytes(), calls[0][2])

    def test_candidate_changed_signed_source_refuses_before_admission(self):
        _, blob = self.candidate_source()
        blob.write_bytes(blob.read_bytes() + b"\n")
        with patch.object(producer, "_request") as request:
            with self.assertRaisesRegex(ValueError, "source index changed"):
                producer._distribution(self.root, self.selection("prepare-root-candidate"))
        request.assert_not_called()

    def test_candidate_readback_mismatch_never_becomes_a_rootable_record(self):
        self.candidate_source()
        _, request = self.candidate_transport(mismatch=True)
        with patch.object(producer, "_request", side_effect=request):
            with self.assertRaisesRegex(ValueError, "readback differs"):
                producer._distribution(self.root, self.selection("prepare-root-candidate"))
        self.assertFalse((self.root / "root-candidate.private.json").exists())

    def test_candidate_empty_index_refuses_before_admission(self):
        self.candidate_source()
        body = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": []}).encode()
        digest = "sha256:" + hashlib.sha256(body).hexdigest()
        self.source["finalized"]["index_digest"] = digest
        self.retain("source.private.json", self.source)
        (Path(self.source["finalized"]["layout"]) / "blobs/sha256" / digest.split(":")[1]).write_bytes(body)
        with patch.object(producer, "_request") as request:
            with self.assertRaisesRegex(ValueError, "nonempty OCI index"):
                producer._distribution(self.root, self.selection("prepare-root-candidate"))
        request.assert_not_called()

    def test_candidate_tag_uses_exact_admitted_body_and_digest(self):
        self.candidate_source()
        _, request = self.candidate_transport()
        with patch.object(producer, "_request", side_effect=request):
            candidate = producer._distribution(self.root, self.selection("prepare-root-candidate"))
        selected = {**self.selection("root-candidate"), "candidate": candidate}
        with patch.object(producer, "_request", return_value={
                "headers": {"Docker-Content-Digest": candidate["digest"]}}) as request:
            result = producer._distribution(self.root, selected)
        self.assertEqual(request.call_args.args[5], Path(candidate["bodyPath"]).read_bytes())
        self.assertTrue(request.call_args.args[3].endswith("/manifests/gc-candidate-" + RUN))
        self.assertEqual(result["digest"], candidate["digest"])

    def test_candidate_body_or_selected_record_drift_never_tags(self):
        self.candidate_source()
        _, request = self.candidate_transport()
        with patch.object(producer, "_request", side_effect=request):
            candidate = producer._distribution(self.root, self.selection("prepare-root-candidate"))
        selected = {**self.selection("root-candidate"), "candidate": {**candidate, "bytes": 1}}
        with patch.object(producer, "_request") as request:
            with self.assertRaisesRegex(ValueError, "selection changed"):
                producer._distribution(self.root, selected)
        request.assert_not_called()
        Path(candidate["bodyPath"]).write_bytes(b"changed")
        selected["candidate"] = candidate
        with patch.object(producer, "_request") as request:
            with self.assertRaisesRegex(ValueError, "body changed"):
                producer._distribution(self.root, selected)
        request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
