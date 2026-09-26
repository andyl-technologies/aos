"""Exercise the AOS CMake compiler launcher inside a Nix check."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


accache, gcc, gxx, cmake, ninja = sys.argv[1:]


def run_suite(root):
    root = Path(root)
    source = root / "source"
    build = root / "build"
    source.mkdir()

    (source / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.20)\n"
        "project(accache_cmake_probe C CXX)\n"
        "add_library(accache_cmake_probe STATIC source.c source.cc)\n"
    )
    (source / "source.c").write_text(
        '#include "value.h"\nint c_value(void) { return VALUE; }\n'
    )
    (source / "source.cc").write_text(
        '#include "value.h"\nint cpp_value() { return VALUE + 1; }\n'
    )
    header = source / "value.h"
    header.write_text("#define VALUE 42\n")

    env = os.environ | {
        "ACCACHE_DIR": str(root / "cache"),
        "ACCACHE_STATE_DIR": str(root / "state"),
        "LC_ALL": "C",
    }
    assert env["CMAKE_C_COMPILER_LAUNCHER"] == accache
    assert env["CMAKE_CXX_COMPILER_LAUNCHER"] == accache

    subprocess.run(
        [cmake, "-S", str(source), "-B", str(build), "-G", "Ninja",
         f"-DCMAKE_MAKE_PROGRAM={ninja}", f"-DCMAKE_C_COMPILER={gcc}",
         f"-DCMAKE_CXX_COMPILER={gxx}"],
        env=env, check=True, capture_output=True, timeout=120,
    )

    def stats():
        return json.loads(subprocess.check_output([accache, "stats"], env=env))

    def object_bytes():
        objects = sorted(build.glob("CMakeFiles/accache_cmake_probe.dir/source.*.o"))
        assert len(objects) == 2, objects
        return {path.name: path.read_bytes() for path in objects}

    before = stats()
    subprocess.run([cmake, "--build", str(build)], env=env, check=True,
                   capture_output=True, timeout=120)
    cold = stats()
    original = object_bytes()
    assert cold.get("miss", 0) - before.get("miss", 0) >= 2, (before, cold)

    subprocess.run([ninja, "-C", str(build), "-t", "clean"], env=env,
                   check=True, capture_output=True, timeout=30)
    subprocess.run([cmake, "--build", str(build)], env=env, check=True,
                   capture_output=True, timeout=120)
    warm = stats()
    if warm.get("hit", 0) - cold.get("hit", 0) < 2:
        # A miss here is safe but defeats the launcher's purpose. Include
        # provenance so a rare miss can be diagnosed from the Nix build log.
        application_events = []
        for path in sorted((root / "state/events").glob("*.json")):
            event = json.loads(path.read_text())
            if any(arg.endswith(("/source.c", "/source.cc"))
                   for arg in event["command"]):
                application_events.append({key: event[key] for key in
                                           ("timestamp_ms", "outcome", "reason", "action",
                                            "changes", "command")})
        application_events.sort(key=lambda event: event["timestamp_ms"])
        raise AssertionError((cold, warm, application_events))
    assert object_bytes() == original

    header.write_text("#define VALUE 73\n")
    subprocess.run([cmake, "--build", str(build)], env=env, check=True,
                   capture_output=True, timeout=120)
    changed = stats()
    assert changed.get("miss", 0) - warm.get("miss", 0) >= 2, (warm, changed)
    assert object_bytes() != original
    print("PASS CMake GCC/G++ launcher miss, hit, and header invalidation", flush=True)


with tempfile.TemporaryDirectory(prefix="accache-cmake-") as directory:
    run_suite(directory)
