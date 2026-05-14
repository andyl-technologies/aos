"""Entry point — ``python3 -m aos_test_driver``.

Usage:
    aos-test-driver --manifest <path> --test <path> [-v]

The manifest is written by the test derivation's builder script; the
schema is documented in the v1 spec ("Manifest schema"). The test path
is the user's Python testScript. Machines are exposed as module globals
named after each machine's ``name`` (e.g. ``vm``, ``controlplane``,
``worker``).
"""

import argparse
import json
import logging
import os
import re
import runpy
import sys
import time
from pathlib import Path

from .errors import AosDriverError
from .firecracker import FirecrackerMachine
from .logger import setup as setup_logging
from .qemu import QemuMachine


log = logging.getLogger(__name__)

NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _load_manifest(path):
    with open(path) as f:
        manifest = json.load(f)

    required_top = {"name", "timeout", "machines"}
    missing = required_top - manifest.keys()
    if missing:
        raise SystemExit(f"manifest missing top-level fields: {sorted(missing)}")
    if not isinstance(manifest["machines"], list) or not manifest["machines"]:
        raise SystemExit("manifest.machines must be a non-empty list")

    seen_transports = set()
    for m in manifest["machines"]:
        if not isinstance(m, dict):
            raise SystemExit(f"machine entry is not an object: {m!r}")
        name = m.get("name", "")
        if not NAME_PATTERN.match(name):
            raise SystemExit(
                f"machine name {name!r} is not a valid Python identifier"
            )
        transport = m.get("transport")
        if transport not in ("qemu", "firecracker"):
            raise SystemExit(
                f"machine {name!r}: transport must be 'qemu' or"
                f" 'firecracker' (got {transport!r})"
            )
        for required in ("kernel", "initrd", "disk", "memory_mib", "vcpu_count"):
            if required not in m:
                raise SystemExit(
                    f"machine {name!r}: missing required field {required!r}"
                )
        if "metadata" not in m:
            raise SystemExit(
                f"machine {name!r}: missing 'metadata' (use null to omit)"
            )
        if transport == "qemu":
            if m["metadata"] is None:
                raise SystemExit(
                    f"machine {name!r}: qemu transport requires non-null metadata"
                )
            for required in ("mac", "ip"):
                if required not in m:
                    raise SystemExit(
                        f"machine {name!r}: qemu requires field {required!r}"
                    )
        seen_transports.add(transport)

    if len(seen_transports) > 1:
        raise SystemExit(
            "mixing qemu and firecracker transports in one manifest is not supported"
        )
    return manifest


def _build_machine(entry, tmpdir):
    transport = entry["transport"]
    common = dict(
        name=entry["name"],
        kernel=entry["kernel"],
        initrd=entry["initrd"],
        disk=entry["disk"],
        metadata=entry.get("metadata"),
        memory_mib=entry["memory_mib"],
        vcpu_count=entry["vcpu_count"],
        tmpdir=str(tmpdir),
    )
    if transport == "firecracker":
        return FirecrackerMachine(**common)
    return QemuMachine(**common, mac=entry["mac"], ip=entry["ip"])


def _dump_serial_logs(machines):
    for m in machines:
        path = Path(m.serial_log_path)
        if not path.exists():
            continue
        sys.stderr.write(f"\n--- {m.name} serial log ---\n")
        try:
            sys.stderr.buffer.write(path.read_bytes())
            sys.stderr.flush()
        except OSError as e:
            sys.stderr.write(f"(could not read {path}: {e})\n")
        sys.stderr.write(f"--- end {m.name} serial log ---\n\n")


def _wait_agents(machines, deadline):
    for m in machines:
        log.info("Waiting for %s agent...", m.name)
        while True:
            try:
                if m.agent.ping(timeout=2):
                    log.info("%s agent ready.", m.name)
                    break
            except Exception:
                pass
            if time.monotonic() > deadline:
                raise RuntimeError(
                    f"[{m.name}] agent did not become ready before manifest timeout"
                )
            time.sleep(0.5)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="aos-test-driver")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--test", required=True, type=Path)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    setup_logging(verbose=args.verbose)

    manifest = _load_manifest(args.manifest)

    tmpdir = Path(os.environ.get("TMPDIR", "/tmp"))
    machines = [_build_machine(entry, tmpdir) for entry in manifest["machines"]]

    log.info(
        "==> aos-test-driver: %s (%d machine(s))",
        manifest["name"],
        len(machines),
    )

    started = []
    exit_code = 0
    try:
        for m in machines:
            m.start()
            started.append(m)

        deadline = time.monotonic() + manifest["timeout"]
        _wait_agents(started, deadline)

        # Expose machines as test-module globals; chdir to TMPDIR so
        # tracebacks render as ./test.py:NN regardless of where the
        # synthesised file lives.
        os.chdir(str(tmpdir))
        init_globals = {"machines": started}
        for m in started:
            init_globals[m.name] = m

        log.info("==> Running test: %s", manifest["name"])
        runpy.run_path(
            str(args.test), init_globals=init_globals, run_name="__main__"
        )
        log.info("==> All tests passed for: %s", manifest["name"])
    except SystemExit:
        raise
    except AosDriverError as e:
        exit_code = 1
        log.error("test failed: %s", e)
        _dump_serial_logs(started)
    except BaseException:
        exit_code = 1
        log.exception("test raised")
        _dump_serial_logs(started)
    finally:
        if exit_code == 0:
            # Graceful shutdown on the happy path; on failure the agent
            # may be wedged so we skip SHUTDOWN and kill the VM proc
            # directly (matches the bash cleanup trap's behaviour).
            for m in started:
                try:
                    m.shutdown()
                except Exception:
                    pass
            time.sleep(2)
        for m in started:
            try:
                m.stop()
            except Exception:
                log.exception("cleanup error for %s", m.name)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
