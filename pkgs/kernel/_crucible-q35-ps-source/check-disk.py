"""Refuses RAM filesystems before source/build scratch is created."""

from pathlib import Path
import os
import sys


def unescape_mount_path(text):
    for escape, value in (('\\040', ' '), ('\\011', '\t'), ('\\012', '\n'), ('\\134', '\\')):
        text = text.replace(escape, value)
    return text


def main():
    root = Path(sys.argv[1]).resolve()
    body = Path('/proc/self/mountinfo').read_text()
    if len(body) > 1024 ** 2:
        raise ValueError('Mount census exceeds finite reservation')
    matches = []
    for line in body.splitlines():
        before, after = line.split(' - ', 1)
        fields = before.split()
        mount = Path(unescape_mount_path(fields[4]))
        if root == mount or mount in root.parents:
            matches.append((len(mount.parts), after.split()[0], str(mount)))
    if not matches:
        raise ValueError('No actual workspace filesystem census')
    _, filesystem, mount = max(matches)
    if filesystem in ('tmpfs', 'ramfs'):
        raise ValueError('RAM filesystem scratch refuses: ' + mount)
    floor = os.statvfs(root)
    if floor.f_bavail * floor.f_frsize < 2 * 1024 ** 3:
        raise ValueError('Insufficient task disk floor; stop without relocating work')
    print('Actual disk workspace accepted: ' + filesystem)


if __name__ == '__main__':
    main()
