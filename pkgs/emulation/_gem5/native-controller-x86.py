# SPDX-License-Identifier: MIT
"""Selects the fixed unqualified x86 Linux native controller implementation."""

import importlib.util
from pathlib import Path


def load(name, filename):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


engine = load("crucible_fixed_x86_controller", "native-controller.py")
model = load("crucible_fixed_x86_model", "native-controller-x86-model.py")
engine.serve(model.X86LinuxModel)
