"""Exercises provider-contract-derived native matrix applicability."""

from __future__ import annotations

import copy
import importlib.util
import os
import pathlib
import sys


def load(path: pathlib.Path):
    """Loads the packaged runner without executing its command entry point."""

    os.environ.setdefault("AOS_QUALIFICATION_NATIVE_ADAPTER_MATRIX_SPEC", str(path))
    os.environ.setdefault("AOS_QUALIFICATION_NATIVE_ADAPTER_MATRIX_CHECK", "fixture")
    spec = importlib.util.spec_from_file_location("native_matrix_runner", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load native matrix runner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def rejected(module, specification):
    """Requires a stale applicability partition to fail closed."""

    try:
        module.applicable_cells(specification)
    except RuntimeError:
        return
    raise AssertionError("stale provider-contract applicability was accepted")


def classify(module, specification):
    """Builds the partition expected from the fixture provider contract."""

    contract = specification["surface"]["adapters"][0]["provider_contract"]
    cell = specification["cells"][0]
    reason = None
    if contract["resource_lifetime"] != "persistent":
        reason = "non-persistent-lifetime"
    elif contract["state_format"] is None:
        reason = "missing-authenticated-state-format"
    excluded = [] if reason is None else [{"cell_id": cell["id"], "reason": reason}]
    specification["applicability"] = {
        "schema": module.APPLICABILITY_SCHEMA,
        "required_production_vm_cells": 1 - len(excluded),
        "inapplicable_cells": excluded,
    }
    return specification


def main() -> None:
    """Proves lifetime and state-format changes alter the exact partition."""

    module = load(pathlib.Path(sys.argv[1]))
    cell = {
        "id": "fixture/aos.fixture/abi-1/apply/adopt-compatible-state",
        "adapter": "fixture",
    }
    specification = classify(
        module,
        {
            "surface": {
                "adapters": [
                    {
                        "adapter": "fixture",
                        "provider_contract": {
                            "resource_lifetime": "instance",
                            "state_format": None,
                        },
                    }
                ]
            },
            "cells": [cell],
        },
    )
    assert module.applicable_cells(specification) == []

    persistent = copy.deepcopy(specification)
    persistent["surface"]["adapters"][0]["provider_contract"][
        "resource_lifetime"
    ] = "persistent"
    rejected(module, persistent)
    classify(module, persistent)
    assert persistent["applicability"]["inapplicable_cells"] == [
        {"cell_id": cell["id"], "reason": "missing-authenticated-state-format"}
    ]

    stateful = copy.deepcopy(persistent)
    stateful["surface"]["adapters"][0]["provider_contract"]["state_format"] = (
        "sha256:" + "11" * 32
    )
    rejected(module, stateful)
    classify(module, stateful)
    assert module.applicable_cells(stateful) == [cell]


if __name__ == "__main__":
    main()
