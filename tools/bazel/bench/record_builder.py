"""Records a benchmark builder's waited resources without replacing its phases.

The outer Nix client cannot observe daemon-owned compiler processes. This
wrapper runs inside the derivation and records the original builder and its
adopted descendants. Bazel JVM counters are additional, overlapping evidence.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run(command):
    started = time.monotonic()
    process = subprocess.Popen(command)
    resources = []
    # A Nix builder can be PID 1 in its namespace. Reap adopted children while
    # the shell is running, so an exited JVM cannot remain a zombie and make
    # Bazel's shutdown client wait for a process that has already terminated.
    while True:
        try:
            pid, status, usage = os.wait4(-1, 0)
        except ChildProcessError:
            break
        resources.append(usage)
        if pid == process.pid:
            process.returncode = os.waitstatus_to_exitcode(status)
    if process.returncode is None:
        raise RuntimeError("original Nix builder was not reaped")
    if process.returncode:
        return process.returncode

    if "out" in os.environ:
        output = Path(os.environ["out"])
    else:
        attributes = json.loads(Path(os.environ["NIX_ATTRS_JSON_FILE"]).read_text())
        output = Path(attributes["outputs"]["out"])
    destination = output / "nix-support/benchmark-resources.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps({
        "scope": "original Nix builder and adopted descendants; CPU totals and maximum per-process RSS",
        "wall_seconds": time.monotonic() - started,
        "user_seconds": sum(usage.ru_utime for usage in resources),
        "system_seconds": sum(usage.ru_stime for usage in resources),
        "peak_rss_kib": max(usage.ru_maxrss for usage in resources),
        "block_inputs": sum(usage.ru_inblock for usage in resources),
        "block_outputs": sum(usage.ru_oublock for usage in resources),
        "waited_children": len(resources),
    }, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    command = json.loads(Path(sys.argv[1]).read_text())
    status = run(command)
    if status < 0:
        os.kill(os.getpid(), -status)
    raise SystemExit(status)
