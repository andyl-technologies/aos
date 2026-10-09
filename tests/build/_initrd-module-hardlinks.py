"""Verifies shared module payloads and independent overlays in extracted archives."""

from pathlib import Path
import stat
import sys


def check_modules(tree, module_tree):
    """Checks physical module identities without resolving against the host store."""
    root = tree.resolve()
    relative_tree = Path(module_tree).relative_to("/")
    retained = root / relative_tree
    view = root / "lib/modules" / relative_tree.name
    if not retained.is_dir():
        raise ValueError("admitted kernel module tree is missing from archive")

    retained_inodes = {
        (module.stat().st_dev, module.stat().st_ino)
        for module in retained.rglob("*.ko")
        if module.is_file() and not module.is_symlink()
    }
    shared = 0
    independent = 0
    for module in view.rglob("*.ko"):
        if module.is_symlink() or not module.is_file():
            continue
        counterpart = retained / module.relative_to(view)
        if counterpart.is_symlink() or not counterpart.is_file():
            if (module.stat().st_dev, module.stat().st_ino) in retained_inodes:
                raise ValueError(f"unmatched module shares an admitted inode: {module}")
            independent += 1
            continue
        if not module.resolve().is_relative_to(root) or not counterpart.resolve().is_relative_to(root):
            raise ValueError("module path escapes extracted archive")

        module_stat = module.stat()
        counterpart_stat = counterpart.stat()
        identical = (
            stat.S_IMODE(module_stat.st_mode) == stat.S_IMODE(counterpart_stat.st_mode)
            and module.read_bytes() == counterpart.read_bytes()
        )
        same_inode = (module_stat.st_dev, module_stat.st_ino) == (
            counterpart_stat.st_dev, counterpart_stat.st_ino
        )
        if same_inode != identical:
            raise ValueError(f"module sharing disagrees with retained payload: {module}")
        if not identical and (module_stat.st_dev, module_stat.st_ino) in retained_inodes:
            raise ValueError(f"changed module shares an admitted inode: {module}")
        shared += identical
        independent += not identical

    for metadata in view.glob("modules.*"):
        counterpart = retained / metadata.name
        if metadata.is_file() and counterpart.is_file() and metadata.samefile(counterpart):
            raise ValueError(f"generated module metadata shares its admitted inode: {metadata}")
    if shared == 0:
        raise ValueError("archive has no verified shared kernel module payloads")
    print(f"PASS: {shared} shared module payloads; {independent} independent overlays")


if __name__ == "__main__":
    check_modules(Path(sys.argv[1]), sys.argv[2])
