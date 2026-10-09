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


if __name__ == "__main__":
    unittest.main()
