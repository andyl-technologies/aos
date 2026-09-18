"""Checks resource-limit and POSIX regressions under a full-system ARM kernel."""

import pathlib
import selectors
import subprocess
import sys
import time


def main():
    qemu, kernel, initrd, log_path = sys.argv[1:]
    command = [
        qemu,
        "-machine", "virt,accel=tcg",
        "-cpu", "max",
        "-smp", "2",
        "-m", "2048",
        "-nographic",
        "-monitor", "none",
        "-nic", "none",
        "-no-reboot",
        "-kernel", kernel,
        "-initrd", initrd,
        "-append", "console=ttyAMA0 rdinit=/init panic=1",
    ]
    required = {
        "AOS_GUILE_RESOURCE_LIMIT_PASS:test-out-of-memory",
        "AOS_GUILE_RESOURCE_LIMIT_PASS:test-stack-overflow",
        "AOS_GUILE_RESOURCE_LIMIT_PASS:posix.test",
        "AOS_GUILE_RESOURCE_LIMITS_COMPLETE",
    }
    transcript = ""
    deadline = time.monotonic() + 1200

    with pathlib.Path(log_path).open("w") as log:
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as process:
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            try:
                while time.monotonic() < deadline:
                    for key, _ in selector.select(timeout=1):
                        chunk = key.fileobj.read1(65536)
                        if not chunk:
                            raise RuntimeError("ARM kernel VM exited before the tests completed")
                        text = chunk.decode(errors="replace")
                        log.write(text)
                        log.flush()
                        sys.stdout.write(text)
                        sys.stdout.flush()
                        transcript += text

                    if "AOS_GUILE_RESOURCE_LIMIT_FAIL:" in transcript:
                        raise RuntimeError("Guile resource-limit regression failed")
                    if all(marker in transcript for marker in required):
                        return
                raise TimeoutError("ARM kernel Guile tests exceeded 1200 seconds")
            finally:
                selector.close()
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    main()
