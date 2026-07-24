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
import io
import json
import logging
import os
import re
import runpy
import sys
import time
from pathlib import Path
from typing import Any

from .errors import AosDriverError
from .firecracker import FirecrackerMachine
from .logger import setup as setup_logging
from .machine import Machine
from .qemu import QemuMachine


log: logging.Logger = logging.getLogger(__name__)

NAME_PATTERN: re.Pattern[str] = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _configure_stdio() -> None:
    """Keep driver/test output visible while Nix is still running the check."""
    for stream in (sys.stdout, sys.stderr):
        # reconfigure() lives on TextIOWrapper; sys.stdout/stderr are typed
        # as the broader TextIO, so narrow before calling. The isinstance
        # check also covers the runtime case where stdio was replaced with
        # a non-wrapper stream. ValueError guards an already-detached stream.
        if not isinstance(stream, io.TextIOWrapper):
            continue
        try:
            stream.reconfigure(line_buffering=True, write_through=True)
        except ValueError:
            pass


def _load_manifest(path: Path) -> dict[str, Any]:
    with open(path) as f:
        manifest: Any = json.load(f)
    if not isinstance(manifest, dict):
        raise SystemExit(f"manifest at {path} is not a JSON object")

    required_top = {"name", "timeout", "machines"}
    missing = required_top - manifest.keys()
    if missing:
        raise SystemExit(f"manifest missing top-level fields: {sorted(missing)}")
    if not isinstance(manifest["machines"], list) or not manifest["machines"]:
        raise SystemExit("manifest.machines must be a non-empty list")

    seen_transports: set[str] = set()
    for m in manifest["machines"]:
        if not isinstance(m, dict):
            raise SystemExit(f"machine entry is not an object: {m!r}")
        name = m.get("name", "")
        if not isinstance(name, str) or not NAME_PATTERN.match(name):
            raise SystemExit(
                f"machine name {name!r} is not a valid Python identifier"
            )
        transport = m.get("transport")
        if transport not in ("qemu", "firecracker"):
            raise SystemExit(
                f"machine {name!r}: transport must be 'qemu' or"
                f" 'firecracker' (got {transport!r})"
            )
        boot = m.get("boot", "kernel")
        if boot not in ("kernel", "image"):
            raise SystemExit(
                f"machine {name!r}: boot must be 'kernel' or 'image'"
                f" (got {boot!r})"
            )
        if boot == "image" and transport != "qemu":
            raise SystemExit(
                f"machine {name!r}: image boot requires the qemu transport"
            )
        for required in ("disk", "memory_mib", "vcpu_count"):
            if required not in m:
                raise SystemExit(
                    f"machine {name!r}: missing required field {required!r}"
                )
        if boot == "kernel":
            for required in ("kernel", "initrd"):
                if required not in m:
                    raise SystemExit(
                        f"machine {name!r}: missing required field {required!r}"
                    )
            if "metadata" not in m:
                raise SystemExit(
                    f"machine {name!r}: missing 'metadata' (use null to omit)"
                )
        else:
            # Image boot requires UEFI firmware. A metadata ISO is optional
            # and, when present, drives native initrd provisioning.
            for required in ("firmware_code", "firmware_vars"):
                if required not in m:
                    raise SystemExit(
                        f"machine {name!r}: image boot requires {required!r}"
                    )
        if transport == "qemu":
            # A null metadata ISO is valid when identity is baked into /etc
            # and no provisioning input is attached. The driver omits the
            # SCSI CD-ROM when it is None.
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


def _build_machine(entry: dict[str, Any], tmpdir: Path) -> Machine:
    transport: str = entry["transport"]
    if transport == "firecracker":
        return FirecrackerMachine(
            name=entry["name"],
            kernel=entry["kernel"],
            initrd=entry["initrd"],
            disk=entry["disk"],
            metadata=entry.get("metadata"),
            memory_mib=entry["memory_mib"],
            vcpu_count=entry["vcpu_count"],
            tmpdir=str(tmpdir),
        )
    return QemuMachine(
        name=entry["name"],
        boot=entry.get("boot", "kernel"),
        kernel=entry.get("kernel"),
        initrd=entry.get("initrd"),
        disk=entry["disk"],
        metadata=entry.get("metadata"),
        firmware_code=entry.get("firmware_code"),
        firmware_vars=entry.get("firmware_vars"),
        fw_cfg=entry.get("fw_cfg"),
        disk_size_mib=entry.get("disk_size_mib"),
        var_size_mib=entry.get("var_size_mib"),
        tpm=entry.get("tpm", False),
        swtpm_bin=entry.get("swtpm_bin"),
        memory_mib=entry["memory_mib"],
        vcpu_count=entry["vcpu_count"],
        mac=entry["mac"],
        ip=entry["ip"],
        tmpdir=str(tmpdir),
    )


def _dump_serial_logs(machines: list[Machine]) -> None:
    for m in machines:
        path = Path(m.serial_log_path)
        if not path.exists():
            continue
        _write_stderr_bytes(f"\n--- {m.name} serial log ---\n".encode())
        try:
            _write_stderr_bytes(path.read_bytes())
        except OSError as e:
            _write_stderr_bytes(f"(could not read {path}: {e})\n".encode())
        _write_stderr_bytes(f"--- end {m.name} serial log ---\n\n".encode())


def _write_stderr_bytes(data: bytes) -> None:
    """Write raw diagnostic bytes to stderr without text-buffer reordering."""
    sys.stderr.flush()
    sys.stderr.buffer.write(data)
    sys.stderr.buffer.flush()


# Default budget for the agent-readiness handshake — strictly the time
# from VM start until the guest agent answers PING. Independent of
# manifest["timeout"], which is the test-body budget; a slow boot must
# not silently eat the checks' time (see the 2026-05-19 microvm-races
# briefing). Surfaceable per-test via manifest["boot_timeout"].
DEFAULT_BOOT_TIMEOUT: float = 180.0

# Default budget for waiting on `systemctl is-system-running` to settle.
# Once the agent is up, multi-user.target is conceptually reached, but
# some Wants= units (sshd, auditd, …) may still be activating. The
# briefing's Shape 2 was a check racing a still-finishing oneshot;
# gating at the harness avoids needing every individual check to know
# which unit it depends on. Independent of test_body / boot_timeout.
DEFAULT_SYSTEM_READY_TIMEOUT: float = 60.0


def _wait_agents(machines: list[Machine], deadline: float) -> None:
    for m in machines:
        log.info("Waiting for %s agent...", m.name)
        # wait_ready blocks until the agent answers a PING (raising
        # RuntimeError on the deadline). For the qemu transport it also
        # establishes the persistent connection reused for the run.
        m.agent.wait_ready(deadline)
        log.info("%s agent ready.", m.name)


def _wait_system_ready(machines: list[Machine], timeout: float) -> None:
    """Block until each machine's systemd reports the boot complete.

    ``systemctl is-system-running --wait`` returns once systemd is in
    one of: running, degraded, maintenance, stopping. ``degraded`` is
    fine for our purposes — it means startup finished but a unit failed,
    which is a useful diagnostic to surface to the test rather than
    masking by hanging forever. A non-zero exit is logged but not fatal;
    individual tests can still assert on specific units.

    The timeout is per-machine. Falls back to a warning if the agent
    cannot run the command at all (very early boot, agent crashed) —
    the test body will then surface a more specific failure.
    """
    cmd = (
        # `|| true` so a `degraded` exit (= 1) doesn't propagate to the
        # agent's exit_code path; we want to capture and log the actual
        # final state regardless.
        "timeout {t:.0f}s systemctl is-system-running --wait; "
        "systemctl is-system-running"
    ).format(t=timeout)
    for m in machines:
        log.info("Waiting for %s system to finish booting...", m.name)
        try:
            exit_code, stdout, _ = m.execute(cmd, timeout=timeout + 10)
        except Exception as e:
            log.warning(
                "[%s] system-ready probe raised %s; continuing",
                m.name,
                e,
            )
            continue
        state = stdout.decode("utf-8", errors="replace").strip().splitlines()
        final = state[-1] if state else "(no output)"
        if exit_code == 0:
            log.info("[%s] system %s.", m.name, final)
        else:
            log.warning(
                "[%s] system %s (probe exit %d); proceeding",
                m.name,
                final,
                exit_code,
            )


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()

    parser = argparse.ArgumentParser(prog="aos-test-driver")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--test", required=True, type=Path)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    setup_logging(verbose=args.verbose)

    manifest = _load_manifest(args.manifest)

    tmpdir = Path(os.environ.get("TMPDIR", "/tmp"))
    machines: list[Machine] = [
        _build_machine(entry, tmpdir) for entry in manifest["machines"]
    ]

    log.info(
        "==> aos-test-driver: %s (%d machine(s))",
        manifest["name"],
        len(machines),
    )

    # Two-axis budget. `boot_timeout` covers VM boot → agent PING reply;
    # `manifest["timeout"]` is left intact for the test body (per-RPC
    # timeouts already enforce it indirectly). The briefing's Shape 1
    # (agent never connects) was conflated with test-body slowness when
    # a single deadline covered both.
    boot_timeout: float = float(
        manifest.get("boot_timeout", DEFAULT_BOOT_TIMEOUT)
    )
    system_ready_timeout: float = float(
        manifest.get("system_ready_timeout", DEFAULT_SYSTEM_READY_TIMEOUT)
    )

    started: list[Machine] = []
    exit_code: int = 0
    try:
        for m in machines:
            m.start()
            started.append(m)

        boot_deadline = time.monotonic() + boot_timeout
        _wait_agents(started, boot_deadline)
        _wait_system_ready(started, system_ready_timeout)

        # Expose machines as test-module globals; chdir to TMPDIR so
        # tracebacks render as ./test.py:NN regardless of where the
        # synthesised file lives. The dict is typed `dict[str, object]`
        # so pyrefly doesn't infer a TypedDict and reject the per-name
        # machine assignments below.
        os.chdir(str(tmpdir))
        init_globals: dict[str, object] = {"machines": started}
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
    except BaseException:
        exit_code = 1
        log.exception("test raised")
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
        # stop() before _dump_serial_logs: terminating the VM proc forces
        # the serial chardev / Firecracker stdout buffer to flush, so the
        # dumped log actually contains the boot output we want for
        # diagnosis. Reading the file mid-run regularly produced an empty
        # dump because the VM hadn't been flushed yet.
        for m in started:
            try:
                m.stop()
            except Exception:
                log.exception("cleanup error for %s", m.name)
        if exit_code != 0:
            _dump_serial_logs(started)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
