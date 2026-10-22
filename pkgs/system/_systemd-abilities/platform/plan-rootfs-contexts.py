"""Plans root-image labels using the selected image's separate /etc aliases.

The canonical /etc metadata image owns its own inodes. Its immutable symlinks
also identify store inodes in the root image, whose labels must reflect their
conventional policy paths. This adapter composes those actual inventories for
the existing label planner, then emits only the root image's physical paths.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from dataclasses import replace
from pathlib import Path


def load_planner(source: Path):
    """Loads the image-selected planner and its existing dump parser."""

    sys.path.insert(0, str(source.parent))
    spec = importlib.util.spec_from_file_location("aos_rootfs_context_planner", source)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load the selected context planner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def compose_etc_inventory(planner, root_entries, etc_entries):
    """Combines physical root entries with the actual /etc metadata namespace.

    Metadata entries carry no root-image inode identity. Only existing physical
    directories may overlap; metadata must not hide a physical file or alias.
    """

    combined = list(root_entries)
    physical = {entry.path: entry for entry in root_entries}
    seen = set()

    for entry in etc_entries:
        path = entry.path
        if path != "/" and (
            not path.startswith("/")
            or any(part in {"", ".", ".."} for part in path.split("/")[1:])
        ):
            raise planner.PlanError("noncanonical /etc metadata path")
        if any(character in path for character in "\x00\r\n"):
            raise planner.PlanError("control character in /etc metadata path")
        if path in seen:
            raise planner.PlanError("duplicate /etc metadata path")
        seen.add(path)

        runtime_path = "/etc" if path == "/" else "/etc" + path
        existing = physical.get(runtime_path)
        if existing is not None:
            if (
                existing.kind is not planner.InodeKind.directory
                or entry.kind is not planner.InodeKind.directory
            ):
                raise planner.PlanError(
                    f"/etc metadata hides a root-image inode: {runtime_path}"
                )
            continue

        combined.append(replace(entry, path=runtime_path, source=None, inode_key=None))

    return combined


def plan_root_labels(planner, root_entries, etc_entries, resolver, dynamic_loaders=()):
    """Returns root-inode labels while retaining the metadata aliases as inputs."""

    combined = compose_etc_inventory(planner, root_entries, etc_entries)
    labels = planner.plan_labels(combined, resolver, dynamic_loaders)
    physical_paths = {entry.path for entry in root_entries}
    return [label for label in labels if label.path in physical_paths]


def main() -> int:
    """Runs the existing planner with the image's canonical /etc dump."""

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--planner", type=Path, required=True)
    parser.add_argument("--etc-dump", type=Path, required=True)
    adapter, remaining = parser.parse_known_args()
    planner = load_planner(adapter.planner)
    options = planner.parse_args(remaining)
    if options.root is None or options.lookup_prefix != "/":
        parser.error("/etc aliases require a root-tree inventory at the root namespace")

    root_entries = planner.inventory_tree(options.root.resolve(strict=True))
    etc_entries = planner.inventory_composefs_dump(adapter.etc_dump)
    with planner.FileContextResolver(options.libselinux, options.file_contexts) as resolver:
        labels = plan_root_labels(
            planner, root_entries, etc_entries, resolver, options.dynamic_loader
        )
    planner.write_outputs(
        options.file_contexts,
        labels,
        options.output_file_contexts,
        options.output_map,
        "/",
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"rootfs-context-plan: {error}", file=sys.stderr)
        raise SystemExit(1) from error
