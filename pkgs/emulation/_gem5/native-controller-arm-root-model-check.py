# SPDX-License-Identifier: MIT
"""Checks explicit root-model selection and stopped native lineage construction."""

import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


sys.modules["m5"] = types.ModuleType("m5")
spec = importlib.util.spec_from_file_location(
    "root_model", Path(__file__).with_name("native-controller-arm-root-model.py")
)
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)


class RootConstructionTests(unittest.TestCase):
    def test_previous_model_selection_refuses(self):
        for selection in (None, {}, {"schema": "crucible.gem5.arm-linux-model.v1"},
                          {"schema": "operator-model"}):
            with self.subTest(selection=selection):
                with patch.object(model.mechanism.ArmLinuxModel, "__init__") as delegated:
                    with self.assertRaises(ValueError):
                        model.ArmRootLinuxModel({"model": selection}, Path("/private"))
                    delegated.assert_not_called()

    def test_original_selection_remains_immutable(self):
        selection = {"schema": model.ArmRootLinuxModel.selection_schema,
                     "assets": {"kernel": "immutable-role"}, "configs": {"files": "168"}}
        bootstrap = {"model": selection, "owner": "root-owner"}
        with patch.object(model.mechanism.ArmLinuxModel, "__init__", return_value=None) as delegated:
            instance = model.ArmRootLinuxModel(bootstrap, Path("/private"))
        forwarded = delegated.call_args.args[0]
        self.assertEqual(bootstrap["model"]["schema"], instance.selection_schema)
        self.assertEqual(forwarded["model"]["schema"], "crucible.gem5.arm-linux-model.v1")
        self.assertIsNot(forwarded, bootstrap)
        self.assertIsNot(forwarded["model"], selection)
        self.assertEqual(forwarded["model"]["assets"], selection["assets"])

    def test_native_root_lineage_selected_at_realization(self):
        instance = model.ArmRootLinuxModel.__new__(model.ArmRootLinuxModel)
        calls = []
        instance.terminal = types.SimpleNamespace(
            crucibleSetOutputParent=lambda parent: calls.append(("parent", parent)) or True
        )
        def stopped_base(_):
            calls.append(("stopped-instantiation", None))
            return "actual-root"
        with patch.object(model.mechanism.ArmLinuxModel, "realize", stopped_base):
            self.assertEqual(instance.realize(), "actual-root")
        self.assertEqual(calls, [("stopped-instantiation", None), ("parent", 0)])

    def test_failed_native_lineage_binding_refuses(self):
        instance = model.ArmRootLinuxModel.__new__(model.ArmRootLinuxModel)
        instance.terminal = types.SimpleNamespace(crucibleSetOutputParent=lambda _: False)
        with patch.object(model.mechanism.ArmLinuxModel, "realize", return_value="root"):
            with self.assertRaises(ValueError):
                instance.realize()

    def test_distinct_scope_never_promotes_admission(self):
        instance = model.ArmRootLinuxModel.__new__(model.ArmRootLinuxModel)
        original = {"model_id": "old-model", "complete_process_closure_qualified": False,
                    "cpu_timing_qualified": False, "guest_readiness_qualified": False}
        with patch.object(model.mechanism.ArmLinuxModel, "describe_scope",
                          side_effect=lambda: dict(original)):
            scope = instance.describe_scope()
        self.assertEqual(scope["model_id"], instance.model_id)
        for field in ("complete_process_closure_qualified", "cpu_timing_qualified",
                      "guest_readiness_qualified"):
            self.assertIs(scope[field], False)
        self.assertEqual(original["model_id"], "old-model")


class ArmRootCoexistenceTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).with_name("native-controller-arm-root-image-check.py")
        if not path.is_file():
            # The fixed proof recipe installs this same ARM helper under the
            # original generic witness basename. No live owner is imported.
            path = Path(__file__).with_name("native-controller-image-check.py")
        specification = importlib.util.spec_from_file_location("arm_root_image_data_controls", path)
        self.image = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(self.image)

    def process(self, pid, start):
        return types.SimpleNamespace(pid=pid, returncode=None, _crucible_group_custody={
            "identity": (pid, pid, start), "signal_attempted": False,
            "reaped": False, "reclaimed": False, "wait_error": False})

    def test_two_original_live_groups_are_censused_without_reenrollment(self):
        processes = (self.process(11, "101"), self.process(12, "102"))
        identities = {process.pid: process._crucible_group_custody["identity"] for process in processes}
        with patch.object(self.image, "kernel_identity", side_effect=identities.__getitem__):
            with patch.object(self.image.os, "getpgid", side_effect=lambda pid: pid):
                with patch.object(self.image, "observe_exit", return_value=None) as observed:
                    anchors = self.image.require_coexisting_groups(processes)
        self.assertEqual(anchors, [{"pid": "11", "group": "11", "start_ticks": "101"},
                                   {"pid": "12", "group": "12", "start_ticks": "102"}])
        self.assertEqual(observed.call_count, 2)

    def test_duplicate_changed_or_exited_original_groups_cannot_claim_coexistence(self):
        first, second = self.process(11, "101"), self.process(12, "102")
        with self.assertRaises(ValueError):
            self.image.require_coexisting_groups((first, first))
        with patch.object(self.image, "kernel_identity", return_value=(11, 11, "changed")):
            with self.assertRaises(ValueError):
                self.image.require_coexisting_groups((first, second))
        for field in ("signal_attempted", "reclaimed"):
            with self.subTest(field=field):
                first._crucible_group_custody[field] = True
                with self.assertRaises(ValueError):
                    self.image.require_coexisting_groups((first, second))
                first._crucible_group_custody[field] = False
        identities = {11: (11, 11, "101"), 12: (12, 12, "102")}
        with patch.object(self.image, "kernel_identity", side_effect=identities.__getitem__):
            with patch.object(self.image.os, "getpgid", side_effect=lambda pid: pid):
                with patch.object(self.image, "observe_exit", return_value=object()):
                    with self.assertRaises(ValueError):
                        self.image.require_coexisting_groups((first, second))


if __name__ == "__main__":
    unittest.main()
