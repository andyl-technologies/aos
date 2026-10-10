"""Controlled setup plumbing tests, never provider or authority qualification."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


setup = load("external_oci_setup", "_hub-external-oci-setup.py")
operator = load("external_oci_operator", "_hub-direct-operator.py")
authority_controls = load("external_authority_controls", "_hub-direct-controls.py")


def coordinates():
    run = "a" * 32
    return {"version": 1, "runId": run, "publicOrigin": "https://localhost:4673",
        "controlOrigin": "https://localhost:4674", "listen": "127.0.0.1:4676",
        "nativeRoot": "/var/lib/hybrid-native/external-oci/" + run,
        "workerRoot": "/var/lib/hybrid-worker/external-oci/" + run,
        "clientRoot": "/var/lib/hybrid-client/external-oci/" + run,
        "databaseName": "fleet_external_" + run, "operatorRole": "external_reader",
        "placementPrefix": ".aos-direct-qualification/external-oci/" + run + "/registry"}


def projection():
    # Only the Python transport/projection predicates are under test here.
    # These synthetic records have not passed the Rust shared validators.
    installation = {"executor_identity": "synthetic-fresh-executor"}
    publication = {"authority": {"guard_namespace_id": "synthetic-fresh-namespace"}, "aliases": []}
    read = {"credential": {"purpose": "read"}, "allowed_effects": ["head", "read"]}
    write = {"credential": {"purpose": "write"}, "allowed_effects": ["put"]}
    listing = {"credential": {"purpose": "list"}, "allowed_effects": ["list"]}
    bootstrap = {"publication": publication, "issuer_installation": installation,
        "read_cohort": read, "write_cohort": write, "issuer_key_id": "synthetic-key",
        "issuer_public_key": "1" * 64, "timing_profile": {}, "clock_uncertainty": 2}
    exports = {"bootstrap": bootstrap, "listExport": {"publication": publication,
        "issuer_installation": installation, "list_cohort": listing}}
    profile = {"issuer_installation": installation, "read_cohort": read,
        "write_cohort": write, "versionless_conditional_reads": True}
    receipt = {"providerReviewSha256": "2" * 64, "profileDigest": "3" * 64}
    selection = {"providerReportSha256": "2" * 64, "providerConcurrency": 3,
        "maximumListPageObjects": 256, "maximumListPages": 256,
        "providerContract": {"contract_id": "synthetic-controlled-provider", "evidence_digest": "2" * 64,
            "versioned_conditional_range_read": False, "versioned_multipart_complete": False,
            "private_incomplete_upload": True, "completed_upload_rejects_late_parts": True,
            "abort_closes_upload_id": True, "upload_part_checksum_enforced": True,
            "versioned_empty_put": False, "protected_versionless": {
                "strong_conditional_range_read": True, "positive_multipart_complete": True}}}
    return exports, profile, receipt, selection


class SetupTests(unittest.TestCase):
    def test_private_transport_failure_reports_only_closed_category_and_time(self):
        private_input = "fixture-private-command-and-error"
        cases = [
            (TimeoutError, "TimeoutError"),
            (type("ClientAgentTimeout", (Exception,), {}), "ClientAgentTimeout"),
            (RuntimeError, "OtherTransportError"),
            (type(private_input, (Exception,), {}), "OtherTransportError"),
        ]
        for error_type, category in cases:
            with self.subTest(category=category):
                def request(body, *, timeout):
                    raise error_type(private_input)

                machine = types.SimpleNamespace(agent=types.SimpleNamespace(request=request))
                with patch.object(operator.time, "monotonic", side_effect=[1.0, 1.25]), \
                        self.assertRaises(RuntimeError) as raised:
                    operator.private_guest_command(machine, private_input)

                self.assertEqual(str(raised.exception),
                    "private operator fixture command failed in transport "
                    f"(category={category}, elapsed_ms=250)")
                self.assertNotIn(private_input, str(raised.exception))
                self.assertTrue(raised.exception.__suppress_context__)

    def test_origins_database_and_roots_cannot_alias_main_or_another_run(self):
        value = coordinates()
        self.assertEqual(setup.setup_coordinates(value), value)
        for field, changed in (("publicOrigin", "https://aos.fleet.test"),
                ("controlOrigin", "https://localhost:4673"), ("listen", "127.0.0.1:4660"),
                ("databaseName", "postgres"), ("workerRoot", "/var/lib/hybrid-worker"),
                ("placementPrefix", "normal/registry"), ("operatorRole", "reader;GRANT")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                setup.setup_coordinates({**value, field: changed})

    def test_projection_keeps_actual_list_and_does_not_share_caller_mutations(self):
        exports, profile, receipt, selected = projection()
        result = setup.project_external_oci_consumers(exports, profile, receipt, selected)
        self.assertEqual(result["HUB_EXTERNAL_OBJECT_CONSUMER"]["cohorts"][1],
            exports["listExport"]["list_cohort"])
        self.assertEqual(result["HUB_EXTERNAL_COPY_CONSUMER"]["domains"][0]["producer_profile_digest"], "3" * 64)
        selected["providerContract"]["private_incomplete_upload"] = False
        self.assertTrue(result["HUB_EXTERNAL_COPY_CONSUMER"]["domains"][0]["provider_contract"]["private_incomplete_upload"])
        self.assertNotIn("acceptance", result)

    def test_observed_range_is_preserved_without_writer_geometry_inference(self):
        values = projection()
        legacy = setup.project_external_oci_consumers(*values)
        self.assertNotIn("maximum_copy_read_range_bytes",
            legacy["HUB_EXTERNAL_COPY_CONSUMER"]["domains"][0]["provider_contract"])
        values[3]["providerContract"]["maximum_copy_read_range_bytes"] = "8388608"
        result = setup.project_external_oci_consumers(*values)
        self.assertEqual(result["HUB_EXTERNAL_COPY_CONSUMER"]["domains"][0]
            ["provider_contract"]["maximum_copy_read_range_bytes"], "8388608")
        for wrong in (8388608, "08388608", "0", "67108865", "unknown"):
            values[3]["providerContract"]["maximum_copy_read_range_bytes"] = wrong
            with self.assertRaises(ValueError):
                setup.project_external_oci_consumers(*values)

    def test_unknown_or_rewritten_provider_facts_refuse_before_scan(self):
        for mutation in (
                lambda a: a[0]["listExport"]["publication"].update(aliases=["foreign"]),
                lambda a: a[2].update(providerReviewSha256="4" * 64),
                lambda a: a[3]["providerContract"].update(abort_closes_upload_id=None),
                lambda a: a[3]["providerContract"]["protected_versionless"].update(strong_conditional_range_read=False),
                lambda a: a[3].update(maximumListPageObjects=257),
                lambda a: a[3].update(providerConcurrency=33)):
            values = copy.deepcopy(projection())
            # Separate the synthetic publications so substitution is real.
            values[0]["listExport"] = copy.deepcopy(values[0]["listExport"])
            mutation(values)
            with self.assertRaises(ValueError):
                setup.project_external_oci_consumers(*values)

    def test_paired_initial_consumers_preserve_independent_exports_and_refuse_aliases(self):
        def consumer(identity):
            values = copy.deepcopy(projection())
            association = {"binding_id": identity, "binding_stable_id": "binding-" + identity}
            for row in (values[0]["bootstrap"]["read_cohort"], values[0]["bootstrap"]["write_cohort"],
                    values[0]["listExport"]["list_cohort"]):
                row["association"] = association
            result = setup.project_external_oci_consumers(*values)
            result["HUB_EXTERNAL_STAGING_CONSUMER"] = {"version": 1, "domains": [{
                "publication": values[0]["bootstrap"]["publication"], **{name: values[1][name]
                    for name in ("issuer_installation", "read_cohort", "write_cohort")}}]}
            return result
        source, destination = consumer("7"), consumer("8")
        combined = setup.combine_external_oci_consumers(source, destination)
        self.assertEqual(len(combined["HUB_EXTERNAL_OBJECT_CONSUMER"]["cohorts"]), 6)
        for key, member in (("HUB_EXTERNAL_COPY_CONSUMER", "domains"),
                ("HUB_EXTERNAL_OCI_CONSUMER", "profiles"), ("HUB_EXTERNAL_STAGING_CONSUMER", "domains")):
            self.assertEqual(combined[key][member], source[key][member] + destination[key][member])
        with self.assertRaises(ValueError):
            setup.combine_external_oci_consumers(source, source)
        changed = copy.deepcopy(destination)
        changed["HUB_EXTERNAL_STAGING_CONSUMER"]["domains"][0]["read_cohort"]["association"]["binding_id"] = "9"
        with self.assertRaises(ValueError):
            setup.combine_external_oci_consumers(source, changed)

    def test_scan_uses_normal_writer_original_and_refuses_missing_list(self):
        calls = []
        coord = coordinates()
        controls = types.SimpleNamespace(origin=setup.PUBLIC_ORIGIN,
            evidence_root=coord["clientRoot"] + "/controls",
            create_external_registry=lambda *args: calls.append(args) or {"controlledCall": True})
        consumers = setup.project_external_oci_consumers(*projection())
        report = {"organization": {"slug": "synthetic"}, "binding": {"stableId": "synthetic"},
            "currentSqlPins": {"currentWriteRevision": "7"}}
        setup.scan_external_oci_registry(controls, coord, report, ["actual-selected-publisher"], consumers)
        self.assertEqual(calls[0][5:], (coord["placementPrefix"], "7", True))
        consumers["HUB_EXTERNAL_OBJECT_CONSUMER"]["cohorts"] = []
        with self.assertRaises(ValueError):
            setup.scan_external_oci_registry(controls, coord, report, ["actual-selected-publisher"], consumers)
        self.assertEqual(len(calls), 1)

    def test_operator_stage_defaults_and_dedicated_roots_keep_exact_queued_original(self):
        calls = []
        original = operator.private_guest_command
        operator.private_guest_command = lambda machine, command, timeout=60: (
            calls.append(command) or ("{}" if "STAGED_CREDENTIAL_RECEIPT" in command else ""))
        try:
            arguments = (object(), sys.executable, "/nix/store/synthetic/bin/aos-hub-authority-bootstrap",
                "actual-operation-id", "read", "actual-deployment", setup.PUBLIC_ORIGIN,
                "/private/work.key", "/private/versions.json")
            operator.stage_queued_provider_credential(*arguments)
            self.assertIn("/var/lib/hybrid-worker/operator/sql.url", calls[0])
            calls.clear()
            root = coordinates()["workerRoot"] + "/operator"
            operator.stage_queued_provider_credential(*arguments, operator_root=root)
            self.assertIn(root + "/sql.url", calls[0])
            self.assertIn("--operation-id actual-operation-id", calls[0])
            self.assertNotIn("/var/lib/hybrid-worker/operator/sql.url", calls[0])
            with self.assertRaises(ValueError):
                operator.stage_queued_provider_credential(*arguments, operator_root=root + "/../main")
        finally:
            operator.private_guest_command = original

    def test_sql_pin_reader_selects_dedicated_database_without_mutating_sql(self):
        calls = []
        binding = {"stableId": "actual-stable", "resourceVersion": "2", "spec": {"s3": {"prefix": "actual-prefix"}}}
        reply = {"bindingStableId": "actual-stable", "bindingResourceVersion": "2",
            "bindingPrefix": "actual-prefix", "bindingId": "8", "currentWriteRevision": "9",
            "credentials": [{"purpose": purpose, "validationState": "valid", "validatedAt": "1"}
                for purpose in ("read", "write", "presign", "list")]}
        original = operator.private_guest_command
        operator.private_guest_command = lambda machine, command, timeout=60: calls.append(command) or json.dumps(reply)
        try:
            coord = coordinates()
            operator.read_operator_binding_pins(object(), "/nix/store/synthetic/bin", "database", binding,
                operator_root=coord["workerRoot"] + "/operator", database_name=coord["databaseName"],
                operator_role=coord["operatorRole"])
            self.assertIn("-U external_reader -d " + coord["databaseName"], calls[0])
            self.assertIn("SELECT json_build_object", calls[0])
            for forbidden in ("GRANT ", "UPDATE ", "INSERT ", "CREATE ROLE"):
                self.assertNotIn(forbidden, calls[0])
            reply["currentWriteRevision"] = "0"
            with self.assertRaises(ValueError):
                operator.read_operator_binding_pins(object(), "/nix/store/synthetic/bin", "database", binding)
        finally:
            operator.private_guest_command = original

    def test_actual_private_metadata_custody_bounds_symlinks_and_duplicates(self):
        def local_private(machine, command, timeout=60):
            program = command.split("\n", 1)[1].rsplit("\nEXTERNAL_OCI_SETUP_METADATA", 1)[0]
            result = subprocess.run([sys.executable, "-c", program], capture_output=True)
            if result.returncode:
                raise RuntimeError("controlled private metadata refusal")
            return result.stdout.decode()

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "record.json"
            path.write_text('{"version":1}')
            path.chmod(0o600)
            value, reference = setup._read_json(None, local_private, sys.executable, str(path), maximum=16)
            self.assertEqual(value, {"version": 1})
            self.assertEqual(reference["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            with self.assertRaises(RuntimeError):
                setup._read_json(None, local_private, sys.executable, str(path), maximum=4)
            path.chmod(0o644)
            with self.assertRaises(RuntimeError):
                setup._read_json(None, local_private, sys.executable, str(path))
            path.chmod(0o600)
            link = Path(temporary) / "link.json"
            link.symlink_to(path)
            with self.assertRaises(RuntimeError):
                setup._read_json(None, local_private, sys.executable, str(link))
            path.write_text('{"version":1,"version":2}')
            with self.assertRaises(ValueError):
                setup._read_json(None, local_private, sys.executable, str(path))

    def test_preparation_correlates_actual_input_before_returning_profile(self):
        coord = coordinates()
        input_file = coord["nativeRoot"] + "/profile-input.json"
        offered = {"runId": coord["runId"], "phase": "profile", "bindingId": 8,
            "placementId": None, "placementPrefix": coord["placementPrefix"],
            "outputDirectory": coord["nativeRoot"] + "/profile"}
        files = {input_file: offered,
            coord["nativeRoot"] + "/profile/profile.json": {"synthetic": "profile"}}
        def reference(path):
            raw = json.dumps(files[path], separators=(",", ":")).encode()
            return {"path": path, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        receipt_path = coord["nativeRoot"] + "/profile/setup-receipt.json"
        files[receipt_path] = {"inputSha256": reference(input_file)["sha256"],
            "bindingId": 8, "placementId": None,
            "profileSha256": reference(coord["nativeRoot"] + "/profile/profile.json")["sha256"],
            "qualification": None, "providerCalls": None, "sqlMutation": False, "candidateSha256": None}
        original_read, original_invoke = setup._read_json, setup._invoke
        calls = []
        setup._read_json = lambda machine, private, python, path, maximum=0: (files[path], reference(path))
        setup._invoke = lambda *args, **kwargs: calls.append(args[2])
        tools = {"python": sys.executable, "env": "/nix/store/synthetic/bin/env",
            "managedCleanupNativeHelper": "/nix/store/synthetic/bin/native-lib-test"}
        try:
            result = setup.invoke_external_oci_preparation(None, tools, coord, input_file, "profile", None)
            self.assertEqual(result["inputFile"]["sha256"], files[receipt_path]["inputSha256"])
            self.assertIn(setup.SETUP_SELECTOR, calls[0])
            files[receipt_path]["inputSha256"] = "0" * 64
            with self.assertRaises(ValueError):
                setup.invoke_external_oci_preparation(None, tools, coord, input_file, "profile", None)
            before = len(calls)
            offered["runId"] = "b" * 32
            with self.assertRaises(ValueError):
                setup.invoke_external_oci_preparation(None, tools, coord, input_file, "profile", None)
            self.assertEqual(len(calls), before)
        finally:
            setup._read_json, setup._invoke = original_read, original_invoke

    def test_second_binding_has_separate_versions_stage_roots_and_idempotency_labels(self):
        coord = coordinates()
        run = coord["runId"]
        source = {"organization": {"slug": "external-" + run, "ownerScopeKey": "controlled-owner"},
            "binding": {"stableId": "source-binding", "ownerScopeKey": "controlled-owner",
                "spec": {"name": "objects", "s3": {"bucket": "selected", "prefix": "selected/source",
                    "endpoint": {"scheme": "https", "dnsName": "selected.test", "port": 443},
                    "signingRegion": "selected", "accessMode": "private"}}},
            "currentSqlPins": {"bindingId": "7"}}
        calls, private = [], []
        def reviewed(service, plan, apply, request, label):
            calls.append((service, request, label))
            return {"binding": {"stableId": request["stableId"], "ownerScopeKey": request["ownerScopeKey"],
                "resourceVersion": "1", "spec": request["spec"]}}
        def validated(org, name, references, digest, stage, **options):
            calls.append(("credentials", name, references, options))
            return {purpose: stage("controlled-operation-" + purpose, purpose) for purpose in references}
        controls = types.SimpleNamespace(origin=setup.PUBLIC_ORIGIN,
            evidence_root=coord["clientRoot"] + "/controls", reviewed=reviewed,
            validate_external_credentials=validated,
            get_external_binding=lambda *a: {"stableId": calls[0][1]["stableId"],
                "ownerScopeKey": calls[0][1]["ownerScopeKey"], "spec": calls[0][1]["spec"]})
        op = types.SimpleNamespace(
            install_operator_provider_versions=lambda *a, **k: {
                "manifestFile": k["operator_root"] + "/provider-versions/manifest.json", "materialSha256": "b" * 64},
            stage_queued_provider_credential=lambda *a, **k: {"root": k["operator_root"], "operation": a[3]},
            read_operator_binding_pins=lambda *a, **k: {"bindingId": "8"})
        def private_command(machine, command):
            import shlex
            program = shlex.split(command)[2]
            compile(program, "private-reader-custody", "exec")
            private.append(program)
        tools = {"python": sys.executable, "authorityBootstrap": "/nix/store/selected/bin/bootstrap",
            "deploymentId": "controlled-deployment", "storageWorkKeyFile": "/private/work.key", "postgres": "/nix/store/selected/bin"}
        result = setup.bootstrap_external_oci_destination(controls, None, tools, coord,
            source, b"controlled-source-material", op, "database", private_command)
        self.assertEqual(calls[0][0], "BindingService")
        self.assertEqual(calls[0][1]["spec"]["s3"]["prefix"], coord["placementPrefix"].rsplit("/", 1)[0] + "/destination")
        self.assertEqual(calls[1][3]["label_prefix"], "external-destination-" + run)
        self.assertTrue(all("/destination/" in reference for reference in calls[1][2].values()))
        self.assertTrue(all(value["root"].endswith("/operator/destination") for value in result["credentialOperations"].values()))
        self.assertIn("os.O_NOFOLLOW", private[0])
        self.assertIn("metadata.st_nlink!=1", private[0])
        self.assertNotIn("print(", private[0])
        self.assertIsNone(result["qualification"])

    def test_binding_requires_fresh_credential_references_before_any_api_effect(self):
        coord = coordinates()
        calls = []
        controls = types.SimpleNamespace(origin=setup.PUBLIC_ORIGIN,
            evidence_root=coord["clientRoot"] + "/controls",
            create_external_binding=lambda *args: calls.append(args))
        selected = {"organizationSlug": "external-" + coord["runId"],
            "organizationName": "Synthetic shape only", "bindingStableId": "synthetic", "bindingName": "synthetic",
            "providerCoordinates": {"bucket": "synthetic", "prefix": coord["placementPrefix"].rsplit("/", 1)[0],
                "endpoint": {}, "signingRegion": "synthetic", "accessMode": "private"},
            "versionReferences": {purpose: "secret://fleet/direct/" + purpose + "/v1"
                for purpose in ("presign", "read", "list", "write")}, "providerMaterial": b"synthetic"}
        with self.assertRaises(ValueError):
            setup.bootstrap_external_oci_binding(controls, None, {}, coord, selected, None, "database")
        self.assertEqual(calls, [])

    def test_paired_authority_attests_both_actual_bindings_before_admission(self):
        decisions = []
        def selected_binding(name, identity):
            prefix = ".aos-direct-qualification/selected" + ("/destination" if name == "destination" else "")
            binding = {"stableId": name, "resourceVersion": "2", "spec": {"name": name,
                "s3": {"bucket": "selected", "prefix": prefix, "endpoint": {"dnsName": "selected.test", "port": 443}}}}
            pins = {"bindingId": str(identity), "bindingStableId": name, "bindingResourceVersion": "2",
                "bindingPrefix": prefix, "currentWriteRevision": "3", "credentials": [{"purpose": purpose,
                    "generation": "4", "secretVersionRef": "secret://selected/" + name + "/" + purpose,
                    "credentialFingerprint": "a" * 64, "validationState": "valid"}
                    for purpose in ("read", "write", "list", "presign")]}
            return binding, pins
        source, source_sql = selected_binding("objects", 7)
        destination, destination_sql = selected_binding("destination", 8)
        selected = {key: "controlled-" + key for key in ("authorityId", "aliasId", "associationId",
            "attestationId", "guardNamespaceId", "physicalResourceEvidenceDigest", "qualificationDigest",
            "equivalenceEvidenceDigest", "providerPolicyEvidenceDigest", "executorIdentity")}
        selected.update(qualifiedManagedPrefix=".aos-direct-qualification/selected", attestationLifetimeSeconds=300)
        def call(service, method, request):
            if method == "GetAuthority":
                return {"resourceVersion": "1"}
            pins = source_sql if request["binding"]["organization"]["name"] == "objects" else destination_sql
            write = next(item for item in pins["credentials"] if item["purpose"] == "write")
            return {"revision": {"bindingId": pins["bindingStableId"], "revision": "3",
                "writeCredentialGeneration": "4", "writeCredentialVersionRef": write["secretVersionRef"],
                "validationState": "valid", "writesSupported": True}}
        controls = types.SimpleNamespace(call=call, authority_decision=lambda decision, version, label:
            decisions.append((decision, version, label)))
        extra = [{"binding": destination, "sqlPins": destination_sql, "associationId": "selected-destination"}]
        authority_controls.admit_external_fixture_authority(controls, "selected-org", source, source_sql,
            selected, 100, additional_associations=extra)
        kinds = [next(iter(item[0])) for item in decisions]
        self.assertEqual(kinds, ["create", "approveAlias", "associateBinding", "associateBinding", "attest", "setAdmission"])
        members = decisions[-2][0]["attest"]["credentials"]
        self.assertEqual(len(members), 8)
        self.assertEqual({item["associationId"] for item in members},
            {selected["associationId"], "selected-destination"})
        self.assertEqual(decisions[-1][0]["setAdmission"]["associationIds"],
            [selected["associationId"], "selected-destination"])
        for name, value in (("bindingId", "7"), ("bindingResourceVersion", "99"),
                ("bindingPrefix", "outside/destination")):
            changed = copy.deepcopy(extra)
            changed[0]["sqlPins"][name] = value
            before = len(decisions)
            with self.subTest(name=name), self.assertRaises(ValueError):
                authority_controls._associate_external_fixture_destinations(controls,
                    "selected-org", source, source_sql, selected, changed)
            self.assertEqual(len(decisions), before)


if __name__ == "__main__":
    unittest.main()
