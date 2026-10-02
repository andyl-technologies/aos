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


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


setup = load("external_oci_setup", "_hub-external-oci-setup.py")
operator = load("external_oci_operator", "_hub-direct-operator.py")


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
    def test_origins_database_and_roots_cannot_alias_main_or_another_run(self):
        value = coordinates()
        self.assertEqual(setup.setup_coordinates(value), value)
        for field, changed in (("publicOrigin", "https://aos.andyl.org"),
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


if __name__ == "__main__":
    unittest.main()
