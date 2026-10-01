"""Reject incomplete controlled observations and unobserved production claims.

All documents here are synthetic validator inputs. They are never runtime
evidence, provider qualifications, reviewer measurements or signed purposes.
"""

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


specification = importlib.util.spec_from_file_location(
    "mirror_pack_gc", Path(__file__).with_name("_hub-mirror-pack-gc.py")
)
driver = importlib.util.module_from_spec(specification)
specification.loader.exec_module(driver)


def report():
    prefix = ".aos-mirror-qualification/" + "a" * 32 + "/final"
    key = prefix + "/.aos-internal/conditional-delete-probes/1001"
    original = {"key": key, "etag": '"one"', "size": 0, "provider_version": "version-one"}
    replacement = {**original, "etag": '"two"', "provider_version": "version-two"}

    def snapshot(deletes, version, pending=None, receipt=None):
        return {
            "guard": {"pendingMutation": None, "pendingDelete": pending,
                      "deleteReceipt": receipt, "mirrorOwnerJobId": None},
            "provider": {"operations": [{"action": "delete", "requests": deletes}],
                         "objects": [] if version is None else [{"object_key": key, "version": version}]},
        }

    receipt = {
        "claim": {"claim_id": "exact-delete", "expected_etag": original["etag"],
                  "expected_size": 0, "expected_provider_version": "version-one"},
        "outcome": {"kind": "deleted", "etag": original["etag"]},
    }
    pending = {"claim_id": "unknown-delete", "expected_provider_version": "version-two"}
    stable = snapshot(2, None, pending=pending)
    cases = [
        {"case": "version_mismatch", "before": snapshot(0, "version-one"),
         "after": snapshot(0, "version-one")},
        {"case": "exact_delete_absence", "before": snapshot(0, "version-one"),
         "after": snapshot(1, None, receipt=receipt)},
        {"case": "replay_preserves_new_writer", "before": snapshot(1, "version-two", receipt=receipt),
         "after": snapshot(1, "version-two", receipt=receipt), "replacement": replacement},
        {"case": "unknown_delete_effect", "before": snapshot(1, "version-two"), "after": stable},
        {"case": "unknown_restart_refusal", "before": stable, "after": copy.deepcopy(stable)},
    ]
    plan = {"plan_id": "original", "deployment_id": "controlled", "placement_id": 1,
            "placement_resource_version": 2, "binding_id": 3, "binding_resource_version": 4,
            "placement_prefix": prefix}
    operations = [
        {"kind": "delete_if_matches", "path": ".aos-internal/conditional-delete-probes/1001", "expected_provider_version": "version-two"},
        {"kind": "delete_if_matches", "path": ".aos-internal/conditional-delete-probes/1001", "expected_provider_version": "version-two"},
        {"kind": "head", "path": ".aos-internal/conditional-delete-probes/1001"},
        {"kind": "put_probe", "path": ".aos-internal/conditional-delete-probes/1001"},
    ]
    controls = [{"plan": {**plan, "plan_id": str(number), "operation": operation},
                 "result": None, "outcome": "refused_or_unknown"}
                for number, operation in enumerate(operations)]
    return {
        "version": 1, "execution": "controlled", "deploymentId": "controlled", "physicalKey": key,
        "placement": {"id": 1, "resourceVersion": 2, "bindingId": 3,
                      "writeSpecVersion": 1, "prefix": prefix},
        "binding": {"id": 3, "resourceVersion": 4, "kind": "deployment_r2"},
        "writer": {"reconciliationState": "ready", "desiredPlacementId": 1, "observedPlacementId": 1,
                   "desiredWriteSpecVersion": 1, "observedWriteSpecVersion": 1,
                   "desiredBindingWriteRevision": 7, "observedBindingWriteRevision": 7,
                   "desiredGeneration": 2, "observedGeneration": 2},
        "currentWriteRevision": 7, "original": original, "cases": cases, "controls": controls,
    }


class EvidenceRefusals(unittest.TestCase):
    def test_complete_controlled_scope_preserves_hosted_and_unknown_boundaries(self):
        accepted = driver.assess_gc(report())
        self.assertEqual(accepted["managedPhysicalGuard"], "passed")
        self.assertEqual(accepted["unknownDelete"], "blocked")
        self.assertEqual(accepted["hostedConditionalDelete"], "unknown")
        self.assertEqual(accepted["sqlGcAccounting"], "unknown")

    def test_absence_requires_actual_delete_and_original_positive_receipt(self):
        for change in ("no_effect", "no_receipt", "new_version", "pending"):
            changed = report()
            after = changed["cases"][1]["after"]
            if change == "no_effect":
                after["provider"]["operations"][0]["requests"] = 0
            elif change == "no_receipt":
                after["guard"]["deleteReceipt"]["outcome"]["kind"] = "not_found"
            elif change == "new_version":
                after["guard"]["deleteReceipt"]["claim"]["expected_provider_version"] = "version-two"
            else:
                after["guard"]["pendingDelete"] = {"claim_id": "still-pending"}
            with self.assertRaises(ValueError, msg=change):
                driver.assess_gc(changed)

    def test_independent_absence_cannot_clear_or_replay_unknown_after_restart(self):
        for change in ("clear_pending", "replay_delete", "invent_receipt", "omit_refusal"):
            changed = report()
            after = changed["cases"][4]["after"]
            if change == "clear_pending":
                after["guard"]["pendingDelete"] = None
            elif change == "replay_delete":
                after["provider"]["operations"][0]["requests"] += 1
            elif change == "invent_receipt":
                after["guard"]["deleteReceipt"] = changed["cases"][1]["after"]["guard"]["deleteReceipt"]
            else:
                changed["controls"].pop()
            with self.assertRaises(ValueError, msg=change):
                driver.assess_gc(changed)

    def test_known_writer_and_frozen_physical_scope_are_required(self):
        for change in ("writer_revision", "writer_generation", "external", "physical_prefix", "control_version", "missing_case"):
            changed = report()
            if change == "writer_revision":
                changed["writer"]["observedBindingWriteRevision"] = 8
            elif change == "writer_generation":
                changed["writer"]["observedGeneration"] = 3
            elif change == "external":
                changed["binding"]["kind"] = "s3"
            elif change == "physical_prefix":
                changed["physicalKey"] = "foreign/key"
            elif change == "control_version":
                changed["controls"][0]["plan"]["binding_resource_version"] = 5
            else:
                changed["cases"].pop()
            with self.assertRaises(ValueError, msg=change):
                driver.assess_gc(changed)

    def test_source_manifest_does_not_accept_a_generic_runner_command(self):
        with self.assertRaises(ValueError):
            driver.checked_configuration({"version": 1, "command": ["host-cargo", "test"]})

    def test_failed_mirror_keeps_independent_gc_report_and_failure_exit(self):
        # These mocked invocations only test reporting. They never start a
        # provider or qualify the synthetic observations as runtime evidence.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "synthetic"
            configuration = {name: "synthetic" for name in (
                "workerSourceSha256", "workerDist", "workerd", "node", "nix", "devShell",
                "targetDir", "sourceRoot", "sourceRevision", "sourceAssemblyManifestSha256",
                "workerArtifactReceiptSha256", "workerWasmSha256", "workerShimSha256",
            )}
            configuration.update({"evidenceDir": str(root), "sourceFiles": {}})

            def invocation(arguments, **options):
                evidence = Path(options["env"]["AOS_MIRROR_RUNTIME_EVIDENCE"])
                if driver.PURPOSE_TEST in arguments:
                    (evidence / "purpose-observations.json").write_text(json.dumps({
                        "productionAdmission": "unknown", "purposeChain": "unknown",
                    }))
                    return mock.Mock(returncode=0)
                if driver.GC_TEST in arguments:
                    (evidence / "GC-PASS").write_text("synthetic validator input")
                    (evidence / "gc-observations.json").write_text(json.dumps(report()))
                    return mock.Mock(returncode=0)
                self.assertIn(driver.RUNTIME_TEST, arguments)
                return mock.Mock(returncode=1)

            with mock.patch.object(driver, "checked_configuration", return_value=configuration), \
                    mock.patch.object(driver.subprocess, "run", side_effect=invocation):
                with self.assertRaisesRegex(ValueError, "runtime qualification failed"):
                    driver.run(configuration)

            retained = json.loads((root / "qualification.json").read_text())
            self.assertEqual(retained["managedGc"]["managedPhysicalGuard"], "passed")
            self.assertEqual(retained["controlledMirrorPack"], "failed")
            self.assertEqual(retained["productionAdmission"], "unknown")
            self.assertEqual([row["exitCode"] for row in json.loads((root / "invocations.json").read_text())], [0, 0, 1])


if __name__ == "__main__":
    unittest.main()
