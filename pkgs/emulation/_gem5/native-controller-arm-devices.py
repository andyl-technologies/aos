# SPDX-License-Identifier: MIT
"""Selects only the fixed source-owned ARM Linux Net/block mechanism model."""

import importlib.util
from pathlib import Path


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


engine = load('crucible_native_device_control', 'native-controller-device.py')
model = load('crucible_native_arm_devices', 'native-controller-arm-devices-model.py')
engine.serve(model.ArmLinuxDeviceModel)
