# SPDX-License-Identifier: MIT
"""Selects the source-owned ARM root-computation model without public admission."""

import importlib.util
from pathlib import Path


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


engine = load("crucible_native_controller", "native-controller.py")
model = load("crucible_native_arm_root_model", "native-controller-arm-root-model.py")
engine.serve(model.ArmRootLinuxModel)
