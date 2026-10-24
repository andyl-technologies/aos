"""Normalize staged image timestamps and derive content-scoped identifiers.

Only the supplied staging tree is changed. Symlinks are never followed; modes,
owners, hardlinks, and extended attributes retain their guest semantics. Image
builders normalize ownership to root separately, so host build IDs are excluded
from the identity. Files are streamed rather than accumulated in memory.
"""

import argparse
import hashlib
import json
import os
import stat
import uuid
from pathlib import Path

EPOCH = 1


def _record(digest, value):
    encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)


def _file(digest, path):
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)


def identifier(namespace, digest):
    value = hashlib.sha256((namespace + ":" + digest).encode()).hexdigest()
    return str(uuid.UUID(hex=value[:32], version=5))


def tree_identity(root, namespace):
    digest = hashlib.sha256()
    inodes = {}

    def visit(path):
        info = path.lstat()
        _record(digest, [str(path.relative_to(root)), info.st_mode])
        for name in sorted(os.listxattr(path, follow_symlinks=False)):
            _record(digest, [name, os.getxattr(path, name, follow_symlinks=False).hex()])

        if stat.S_ISLNK(info.st_mode):
            _record(digest, os.readlink(path))
        elif stat.S_ISREG(info.st_mode):
            inode = (info.st_dev, info.st_ino)
            if inode in inodes:
                _record(digest, ["hardlink", inodes[inode]])
            else:
                inodes[inode] = str(path.relative_to(root))
                _record(digest, info.st_size)
                _file(digest, path)
        elif stat.S_ISDIR(info.st_mode):
            for child in sorted(path.iterdir()):
                visit(child)
        else:
            _record(digest, info.st_rdev)

        # Do this after reading files and traversing directories, which can
        # update atime. mke2fs clamps ctime to the same SOURCE_DATE_EPOCH.
        os.utime(path, (EPOCH, EPOCH), follow_symlinks=False)

    visit(root)
    return identifier(namespace, digest.hexdigest())


def tree_size(root):
    """Count logical payload once per inode, excluding host directory sizes."""
    seen = set()
    total = 0
    for directory, directories, files in os.walk(root, followlinks=False):
        for name in directories + files:
            info = (Path(directory) / name).lstat()
            inode = (info.st_dev, info.st_ino)
            if not stat.S_ISDIR(info.st_mode) and (not stat.S_ISREG(info.st_mode) or inode not in seen):
                total += info.st_size
                seen.add(inode)
    return total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("tree", "size", "files", "uuid"))
    parser.add_argument("namespace")
    parser.add_argument("paths", nargs="*")
    args = parser.parse_args()

    if args.kind == "size":
        result = tree_size(Path(args.namespace))
    elif args.kind == "tree":
        if len(args.paths) != 1:
            parser.error("tree requires one staging directory")
        result = tree_identity(Path(args.paths[0]), args.namespace)
    else:
        digest = hashlib.sha256()
        for value in args.paths:
            path = Path(value)
            _record(digest, path.stat().st_size)
            _file(digest, path)
        result = identifier(args.namespace, digest.hexdigest())
    print(result)


if __name__ == "__main__":
    main()
