# SPDX-License-Identifier: MIT
"""Selects a distinct closed ARM root-computation model before native callbacks.

This source-owned draft grants no production execution or timing admission.
Its root lineage is a construction choice, never a rewritten publication receipt.
"""

import importlib.util
from pathlib import Path


spec = importlib.util.spec_from_file_location(
    "crucible_arm_mechanism_model", Path(__file__).with_name("native-controller-arm-model.py")
)
mechanism = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mechanism)


class ArmRootLinuxModel(mechanism.ArmLinuxModel):
    """Selects native root lineage for the unchanged closed ARM board model."""

    selection_schema = "crucible.gem5.arm-linux-root-model.v1"
    model_id = "arm-linux-vexpress-atomic-root-functional-v1"

    def __init__(self, bootstrap, resource_root):
        selection = bootstrap.get("model")
        if not isinstance(selection, dict) or selection.get("schema") != self.selection_schema:
            raise ValueError("ARM root computation requires its source-owned model selection")
        # Reuse only the finite asset validator, retaining the original root
        # selection in the controller's own immutable bootstrap record.
        delegated = dict(bootstrap)
        delegated["model"] = dict(selection, schema="crucible.gem5.arm-linux-model.v1")
        super().__init__(delegated, resource_root)

    def realize(self):
        root = super().realize()
        # Instantiation schedules callbacks but does not service them. Both
        # setters run at that same stopped pre-execution cut with an empty FIFO.
        if not self.terminal.crucibleSetOutputParent(0):
            raise ValueError("native ARM root lineage was not selected before callbacks")
        return root

    def describe_scope(self):
        scope = super().describe_scope()
        scope["model_id"] = self.model_id
        return scope
