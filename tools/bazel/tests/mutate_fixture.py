"""Constructs immutable fixture variants for semantic cache invalidation."""

import argparse
from pathlib import Path


def replace(root, filename, original, replacement):
    path = root / filename
    text = path.read_text()
    if text.count(original) != 1:
        raise ValueError(f"fixture mutation no longer applies: {filename}: {original}")
    path.write_text(text.replace(original, replacement))


def mutate(root, variant):
    """Changes exactly the selected semantic input in a fixture snapshot."""
    if variant == "header":
        replace(root, "library.h", "HEADER_OFFSET 0", "HEADER_OFFSET 1")
    elif variant == "cpp-source":
        replace(root, "library.cc", "return AOS_FIXTURE_VALUE", "return 1 + AOS_FIXTURE_VALUE")
    elif variant == "rust-source":
        replace(root, "lib.rs", "fixture_generated::answer()", "1 + fixture_generated::answer()")
    elif variant == "generated-input":
        replace(root, "value.txt", "42", "43")
    elif variant == "generator-environment":
        replace(root, "BUILD.bazel", '"AOS_FIXTURE_OFFSET": "0"', '"AOS_FIXTURE_OFFSET": "1"')
    elif variant in {"feature", "rust-flags"}:
        setting = 'crate_features = ["extra"],' if variant == "feature" else 'rustc_flags = ["-Copt-level=1"],'
        replace(root, "BUILD.bazel", 'crate_name = "fixture_library",', 'crate_name = "fixture_library",\n    ' + setting)
    elif variant != "tool-closure":
        raise ValueError(f"unsupported cache fixture variant: {variant}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--variant", required=True)
    options = parser.parse_args()
    mutate(options.root / "tools/bazel/tests/fixture", options.variant)
