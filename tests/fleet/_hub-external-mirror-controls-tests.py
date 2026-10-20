"""Controlled Mirror placement calls retain normal scans, promotion and fencing."""

import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location("mirror_controls", Path(__file__).with_name("_hub-direct-controls.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Controls(module.DirectBootstrapControls):
    def __init__(self, prefix):
        self.prefix = prefix
        self.requests = []

    def reviewed(self, service, plan, apply, request, label):
        self.requests.append((service, plan, apply, request, label))
        if apply == "CreateRegistry":
            return {"registry": {"slug": "controlled/mirror-full"}}
        if apply == "ScanPlacement":
            return {"operation": {"operationId": "controlled-scan"}}
        return {}

    def wait_operation(self, identifier, states):
        self.requests.append(("wait", identifier, states))
        return {"operationId": identifier, "state": "succeeded"}

    def call(self, service, method, request):
        self.requests.append((service, method, request))
        if method == "GetPlacement":
            return {"placement": {"prefix": self.prefix, "resourceVersion": "2",
                "spec": {"kind": "complete", "desiredState": "active"},
                "observation": {"state": "ready", "completeness": "complete"},
                "status": {"observedWriter": True, "effectiveWriteEnabled": True}}}
        return {"authority": {"reconciliationState": "ready", "desiredPlacementName": "mirror-full",
            "observedPlacementName": "mirror-full", "desiredBindingWriteRevision": "3",
            "observedBindingWriteRevision": "3", "observedGeneration": "4", "desiredGeneration": "4"}}


class MirrorControlsTests(unittest.TestCase):
    def run_case(self, prefix, *, mirror_run_id=None, label_prefix="fleet-direct"):
        controls = Controls(prefix)
        organization = {"ownerScopeKey": "org:controlled", "slug": "controlled"}
        binding = {"ownerScopeKey": "org:controlled", "stableId": "controlled-binding",
            "spec": {"s3": {"prefix": "controlled-binding-prefix"}}}
        result = controls.create_external_registry(organization, binding, "mirror-full", ["actual-trust"],
            "mirror-full", prefix, 3, True, mirror_run_id=mirror_run_id, label_prefix=label_prefix)
        return controls, result

    def test_exact_mirror_logical_prefix_keeps_scan_promotion_and_current_writer(self):
        run = "a" * 32
        prefix = ".aos-mirror-qualification/" + run + "/final/full"
        controls, result = self.run_case(prefix, mirror_run_id=run, label_prefix="mirror-full-" + run)
        mutations = [call for call in controls.requests if len(call) == 5]
        self.assertEqual([call[2] for call in mutations],
            ["CreateRegistry", "CreatePlacement", "ScanPlacement", "PromotePlacement"])
        self.assertEqual(mutations[1][3]["prefix"], prefix)
        self.assertEqual(mutations[1][3]["bindingId"], "controlled-binding")
        self.assertTrue(mutations[1][3]["requiresConditionalWrites"])
        self.assertTrue(any(call[0] == "wait" and call[2] == {"succeeded"} for call in controls.requests))
        self.assertEqual(result["authority"]["observedBindingWriteRevision"], "3")
        self.assertEqual(len({call[4] for call in mutations}), 4)

    def test_existing_default_prefix_and_control_labels_remain_literal(self):
        controls, _ = self.run_case("controlled-binding-prefix/registry")
        mutations = [call for call in controls.requests if len(call) == 5]
        self.assertEqual([call[4] for call in mutations], ["fleet-direct-registry", "fleet-direct-placement",
            "fleet-direct-placement-scan", "fleet-direct-placement-promote"])

    def test_wrong_run_child_and_unscoped_mirror_prefix_refuse_before_api(self):
        run = "a" * 32
        for prefix, selected in ((".aos-mirror-qualification/" + "b" * 32 + "/final/full", run),
                (".aos-mirror-qualification/" + run + "/final/other", run),
                (".aos-mirror-qualification/" + run + "/final/full", None)):
            controls = Controls(prefix)
            with self.assertRaises(ValueError):
                controls.create_external_registry({"ownerScopeKey": "org:controlled", "slug": "controlled"},
                    {"ownerScopeKey": "org:controlled", "stableId": "controlled-binding",
                        "spec": {"s3": {"prefix": "controlled-binding-prefix"}}},
                    "mirror-full", ["actual-trust"], "mirror-full", prefix, 3, True, mirror_run_id=selected)
            self.assertEqual(controls.requests, [])


if __name__ == "__main__":
    unittest.main()
