# SPDX-License-Identifier: MIT
"""Selects the source-owned x86 Linux root model, never an operator module."""

import importlib.util
from pathlib import Path


def load(name, filename):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


engine = load("crucible_x86_root_controller", "native-controller.py")
model = load("crucible_x86_root_model", "native-controller-x86-root-model.py")
engine.serve(model.X86RootLinuxModel)
