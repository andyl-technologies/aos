# SPDX-License-Identifier: MIT
"""Selects only the installed closed native-owned ARM network lifecycle model."""

import importlib.util
from pathlib import Path


def load(name, filename):
    specification = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


engine = load('crucible_closed_network_controller', 'native-controller-device.py')
model = load('crucible_closed_network_model', 'native-controller-arm-network-model.py')
engine.serve(model.ArmLinuxNetworkModel)
