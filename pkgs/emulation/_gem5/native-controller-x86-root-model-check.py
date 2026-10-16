# SPDX-License-Identifier: MIT
"""Checks root construction sequencing without running a simulator.

The modeled base below supplies no native owner or successful qualification.
These controls exercise the actual root subclass and its pre-callback refusal.
"""

import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


native = types.ModuleType("m5")
native.crucibleEventPosition = lambda: {
    "active": False, "tick": "0", "ordinal": "0", "tick_ordinal": "0"}
sys.modules["m5"] = native
specification = importlib.util.spec_from_file_location(
    "crucible_x86_root_control", Path(__file__).with_name("native-controller-x86-root-model.py"))
model = importlib.util.module_from_spec(specification)
specification.loader.exec_module(model)


class X86RootConstructionTests(unittest.TestCase):
    def test_previous_or_unknown_selection_refuses_before_base_construction(self):
        for selection in (None, {}, {"schema": "crucible.gem5.x86-linux-model.v1"},
                          {"schema": "crucible.gem5.arm-linux-root-model.v1"}):
            with self.subTest(selection=selection):
                with patch.object(model.board.X86LinuxModel, "__init__") as delegated:
                    with self.assertRaises(ValueError):
                        model.X86RootLinuxModel({"model": selection}, Path("/private"))
                    delegated.assert_not_called()

    def test_original_root_selection_and_asset_objects_are_not_rewritten(self):
        selection = {"schema": model.X86RootLinuxModel.selection_schema,
                     "assets": {"kernel": "original-data"}, "configs": {"files": "168"}}
        bootstrap = {"model": selection, "owner": "original-owner"}
        with patch.object(model.board.X86LinuxModel, "__init__", return_value=None) as delegated:
            instance = model.X86RootLinuxModel(bootstrap, Path("/private"))
        forwarded = delegated.call_args.args[0]
        self.assertEqual(bootstrap["model"]["schema"], instance.selection_schema)
        self.assertEqual(forwarded["model"]["schema"], "crucible.gem5.x86-linux-model.v1")
        self.assertIsNot(forwarded, bootstrap)
        self.assertIsNot(forwarded["model"], selection)
        self.assertIs(forwarded["model"]["assets"], selection["assets"])
        self.assertIs(forwarded["model"]["configs"], selection["configs"])

    def test_zero_parent_is_selected_only_after_stopped_base_realization(self):
        instance = model.X86RootLinuxModel.__new__(model.X86RootLinuxModel)
        calls = []
        instance.terminal = types.SimpleNamespace(
            crucibleSetOutputParent=lambda parent: calls.append(("parent", parent)) or True)
        def stopped(_):
            calls.append(("base-stopped", None))
            return "root-data"
        with patch.object(model.board.X86LinuxModel, "realize", stopped):
            self.assertEqual(instance.realize(), "root-data")
        self.assertEqual(calls, [("base-stopped", None), ("parent", 0)])

    def test_progress_or_active_callback_refuses_before_parent_mutation(self):
        instance = model.X86RootLinuxModel.__new__(model.X86RootLinuxModel)
        changes = []
        instance.terminal = types.SimpleNamespace(
            crucibleSetOutputParent=lambda parent: changes.append(parent) or True)
        original = native.crucibleEventPosition()
        for key, value in (("active", True), ("tick", "1"),
                           ("ordinal", "1"), ("tick_ordinal", "1")):
            with self.subTest(key=key):
                with patch.object(native, "crucibleEventPosition", return_value=dict(original, **{key: value})):
                    with patch.object(model.board.X86LinuxModel, "realize", return_value="root-data"):
                        with self.assertRaises(ValueError):
                            instance.realize()
        self.assertEqual(changes, [])

    def test_native_parent_refusal_does_not_claim_success(self):
        instance = model.X86RootLinuxModel.__new__(model.X86RootLinuxModel)
        instance.terminal = types.SimpleNamespace(crucibleSetOutputParent=lambda _: False)
        with patch.object(model.board.X86LinuxModel, "realize", return_value="root-data"):
            with self.assertRaises(ValueError):
                instance.realize()

    def test_distinct_scope_keeps_all_original_unqualified_flags_and_loader(self):
        instance = model.X86RootLinuxModel.__new__(model.X86RootLinuxModel)
        original = {"model_id": "x86-linux-pc-atomic-functional-v1", "loader": {"original": "data"},
                    "complete_process_closure_qualified": False, "cpu_timing_qualified": False,
                    "guest_readiness_qualified": False, "device_parity_qualified": False}
        with patch.object(model.board.X86LinuxModel, "describe_scope", side_effect=lambda: dict(original)):
            scope = instance.describe_scope()
        self.assertEqual(scope["model_id"], instance.model_id)
        self.assertEqual(original["model_id"], "x86-linux-pc-atomic-functional-v1")
        self.assertIs(scope["loader"], original["loader"])
        for name in ("complete_process_closure_qualified", "cpu_timing_qualified",
                     "guest_readiness_qualified", "device_parity_qualified"):
            self.assertIs(scope[name], False)


class X86RootCoexistenceTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).with_name("native-controller-x86-root-image-check.py")
        if not path.is_file():
            # The fixed proof recipe installs this same x86 helper under the
            # original generic witness basename. No live owner is imported.
            path = Path(__file__).with_name("native-controller-image-check.py")
        specification = importlib.util.spec_from_file_location("x86_root_image_data_controls", path)
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
        identities = {11: (11, 11, "101"), 12: (12, 12, "102")}
        with patch.object(self.image, "kernel_identity", side_effect=identities.__getitem__):
            with patch.object(self.image.os, "getpgid", side_effect=lambda pid: pid):
                with patch.object(self.image, "observe_exit", return_value=object()):
                    with self.assertRaises(ValueError):
                        self.image.require_coexisting_groups((first, second))


if __name__ == "__main__":
    unittest.main()
