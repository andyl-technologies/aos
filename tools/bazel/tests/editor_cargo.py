"""Scopes editor Cargo feature selection to the application workspace.

Rust-analyzer also invokes Cargo for the source-built standard library. Its
packages do not declare application features, so those queries must retain
their original arguments.
"""

import argparse
import json
import os
from pathlib import Path


def forwarded_arguments(arguments, workspace, flags, directory):
    """Adds selected features only to application metadata and check commands."""
    if not arguments or arguments[0] not in {"metadata", "check"}:
        return list(arguments)

    manifests = []
    for index, argument in enumerate(arguments):
        if argument.startswith("--manifest-path="):
            manifests.append(argument.partition("=")[2])
        elif argument == "--manifest-path" and index + 1 < len(arguments):
            manifests.append(arguments[index + 1])
    if len(manifests) > 1:
        raise ValueError("ambiguous Cargo editor manifest selection")

    directory = directory.resolve()
    if manifests:
        manifest = (directory / manifests[0]).resolve()
    else:
        manifest = next(
            (parent / "Cargo.toml" for parent in [directory, *directory.parents]
             if (parent / "Cargo.toml").is_file()),
            None,
        )
    if manifest is not None and manifest.is_relative_to(workspace.resolve()):
        return [*arguments, *flags]
    return list(arguments)


def main():
    """Delegates Cargo queries with the selected workspace's feature flags."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--flags", required=True)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    arguments = options.arguments
    if arguments[:1] == ["--"]:
        arguments = arguments[1:]
    flags = json.loads(options.flags)
    if not isinstance(flags, list) or not all(isinstance(flag, str) for flag in flags):
        raise ValueError("Cargo editor feature flags must be a list of strings")
    forwarded = forwarded_arguments(arguments, options.workspace, flags, Path.cwd())
    os.execv(options.cargo, [options.cargo, *forwarded])


if __name__ == "__main__":
    main()
