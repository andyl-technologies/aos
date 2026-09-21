"""Pins installed Python entry points to the interpreter in their own output."""

import os
import re
import stat
import sys


def pin_python_scripts(root):
    """Rewrites Python shebangs without changing script bodies or file metadata."""
    interpreter = os.fsencode(os.path.join(root, "bin", "python3"))
    for directory, _, names in os.walk(root):
        for name in names:
            path = os.path.join(directory, name)
            metadata = os.lstat(path)
            if not stat.S_ISREG(metadata.st_mode):
                continue

            with open(path, "rb") as source:
                if source.read(2) != b"#!":
                    continue
                command = source.readline().split()
                if command and os.path.basename(command[0]) == b"env":
                    command.pop(0)
                    if command and command[0] == b"-S":
                        command.pop(0)
                if not command or not re.fullmatch(
                    rb"python(?:[0-9]+(?:\.[0-9]+)*)?", os.path.basename(command[0])
                ):
                    continue
                body = source.read()

            header = b"#!" + b" ".join([interpreter] + command[1:]) + b"\n"
            os.chmod(path, stat.S_IMODE(metadata.st_mode) | stat.S_IWUSR)
            try:
                # Preserve hard links by rewriting the existing inode.
                with open(path, "wb") as destination:
                    destination.write(header)
                    destination.write(body)
            finally:
                os.chmod(path, stat.S_IMODE(metadata.st_mode))
                os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))


if __name__ == "__main__":
    pin_python_scripts(sys.argv[1])
