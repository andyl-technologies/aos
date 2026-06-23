"""Filesystem helpers for the test driver.

Each VM boots from a private, writable copy of its base disk image. Fleet
tests boot many machines from one *deduplicated* base image (Nix collapses
machines with identical inputs to a single store path — see mkTestDisk in
lib/testing/vm.nix), so the per-VM copy is the same large file cloned N
times into the build's scratch directory.

On a copy-on-write filesystem (btrfs, XFS with reflink, or OpenZFS >= 2.2
with block cloning) that copy can be a reflink clone instead of a full byte
copy: the clone is near-instant and consumes no extra space until the guest
writes to it, with divergence handled lazily by the filesystem.
`clone_or_copy` prefers the clone and falls back to a plain copy when the
filesystem can't honor it.
"""

import fcntl
import shutil

# FICLONE = _IOW(0x94, 9, int): the generic VFS ioctl that reflinks one
# whole file onto another — the same call `cp --reflink` issues. It is NOT
# btrfs-specific: the kernel routes it (fs/ioctl.c FICLONE -> ioctl_file_
# clone -> vfs_clone_file_range) to the filesystem's ->remap_file_range, so
# every copy-on-write filesystem that implements that op honors it — btrfs,
# XFS (reflink=1), bcachefs, OCFS2, and OpenZFS >= 2.2 whose pool has the
# block_cloning feature enabled (zpl_remap_file_range, on by default since
# zfs_bclone_enabled = 1). FICLONE is just FICLONERANGE over the whole file
# and shares its code path. The _IOC encoding for a 4-byte int argument is
# identical across the architectures this driver runs on (x86-64, aarch64),
# so the literal is portable here.
#
# The clone is all-or-nothing: the kernel passes no REMAP_FILE_CAN_SHORTEN
# flag for FICLONE, so it fails with EOPNOTSUPP/EINVAL (no reflink support,
# or block_cloning off), EXDEV (cross-filesystem source), or — on ZFS —
# EINVAL when the source still holds unsynced dirty data it would have to
# shorten the clone around. Our source is an immutable, long-synced Nix
# store path, so that last case doesn't arise; the caller's copy fallback
# covers the rest.
_FICLONE = 0x40049409


def clone_or_copy(src: str, dst: str) -> bool:
    """Create *dst* as a copy of *src*, preferring a reflink clone.

    Attempts a copy-on-write clone so *dst* shares extents with *src*
    until one side is written; on any filesystem that can't honor the
    clone, falls back to ``shutil.copyfile`` (a full byte copy). *dst* is
    created — or truncated if it already exists — in both paths. File
    mode is not preserved; callers set it explicitly afterwards.

    Returns ``True`` if the reflink clone succeeded, ``False`` if it fell
    back to a full copy — letting callers report which path ran.
    """
    with open(src, "rb") as fsrc, open(dst, "wb") as fdst:
        try:
            fcntl.ioctl(fdst.fileno(), _FICLONE, fsrc.fileno())
            return True
        except OSError:
            # Cross-filesystem, or no reflink support. The `wb` open above
            # left dst as a 0-byte file; the plain copy below overwrites
            # it from the same source.
            pass
    shutil.copyfile(src, dst)
    return False
