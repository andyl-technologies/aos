"""Run Go's linker with an anonymous output before copying it to the build tree.

Some filesystems accept fallocate on an already mapped file but discard its
earlier writes. The Go linker grows its output this way without noticing the
lost data, so an apparently successful build can produce an empty executable.
"""

import os
import shutil
import subprocess
import sys


def main() -> int:
    arguments = sys.argv[1:]
    real_linker = f"{__file__}.real"

    if "-o" not in arguments:
        return subprocess.run([__file__, *arguments], executable=real_linker).returncode

    output_index = arguments.index("-o") + 1
    output_path = arguments[output_index]
    output_fd = os.memfd_create("go-link-output", flags=0)
    arguments[output_index] = f"/proc/self/fd/{output_fd}"

    try:
        result = subprocess.run(
            [__file__, *arguments],
            executable=real_linker,
            pass_fds=(output_fd,),
        )
        if result.returncode != 0:
            return result.returncode

        os.lseek(output_fd, 0, os.SEEK_SET)
        with os.fdopen(output_fd, "rb", closefd=False) as source:
            with open(output_path, "wb") as target:
                shutil.copyfileobj(source, target)

        os.chmod(output_path, 0o755)
        return 0
    finally:
        os.close(output_fd)


if __name__ == "__main__":
    sys.exit(main())
