"""Exercises the authoritative native matrix applicability partition."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import sys
import tempfile


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
    """Requires a malformed applicability partition to fail closed."""

    try:
        module.applicable_cells(specification)
    except RuntimeError:
        return
    raise AssertionError("malformed matrix applicability was accepted")


def main() -> None:
    """Proves the exact partition is consumed without semantic re-expansion."""

    module = load(pathlib.Path(sys.argv[1]))
    cell = {
        "id": "fixture/aos.fixture/abi-1/apply/adopt-compatible-state",
        "adapter": "fixture",
        "applicability": {
            "required_resource_lifetimes": ["persistent"],
            "requires_state_format": True,
        },
    }
    specification = {
        "cells": [cell],
        "applicability": {
            "schema": module.APPLICABILITY_SCHEMA,
            "applicable_cell_ids": [],
            "inapplicable_cells": [
                {
                    "cell_id": cell["id"],
                    "reason": "missing-authenticated-state-format",
                }
            ],
        },
    }
    assert module.applicable_cells(specification) == []

    specification["applicability"] = {
        "schema": module.APPLICABILITY_SCHEMA,
        "applicable_cell_ids": [cell["id"]],
        "inapplicable_cells": [],
    }
    assert module.applicable_cells(specification) == [cell]

    specification["applicability"]["applicable_cell_ids"] = []
    rejected(module, specification)

    with tempfile.TemporaryDirectory() as temporary_directory:
        artifact = pathlib.Path(temporary_directory) / "matrix.json"
        artifact.write_bytes(module.canonical(specification))
        assert module.read_canonical_json(artifact) == specification

        artifact.write_text(json.dumps(specification, indent=2), encoding="utf-8")
        try:
            module.read_canonical_json(artifact)
        except RuntimeError:
            pass
        else:
            raise AssertionError("equivalent non-canonical matrix bytes were accepted")


if __name__ == "__main__":
    main()
