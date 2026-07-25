"""Machine base class — the API tests interact with.

Modelled on NixOS's test driver Machine but stripped to what the AOS
agent supports (no copy_from_*, no QMP, no OCR, no monitor commands).
The agent RPC speaks one verb (run a bash blob) plus PING / SHUTDOWN.
"""

import logging
import os
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import ClassVar

from .agent import DEFAULT_TIMEOUT, AgentClient, Driver
from .errors import MachineFailure


log: logging.Logger = logging.getLogger(__name__)


class Machine:
    """Base; QemuMachine / FirecrackerMachine implement start() / stop()."""

    # Set by each subclass.
    transport: ClassVar[Driver]

    name: str
    agent: AgentClient
    serial_log_path: str
    expect_agent: bool

    def __init__(
        self, name: str, agent_socket_path: str, serial_log_path: str
    ) -> None:
        self.name = name
        self.agent = AgentClient(name, agent_socket_path, self.transport)
        self.serial_log_path = serial_log_path
        self.expect_agent = True

    # ------------------------------------------------------------------
    # Subclass hooks
    # ------------------------------------------------------------------
    def start(self) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError

    # ------------------------------------------------------------------
    # API surface used by tests
    # ------------------------------------------------------------------
    def execute(
        self, cmd: str, timeout: float = DEFAULT_TIMEOUT
    ) -> tuple[int, bytes, bytes]:
        """Run cmd on the guest; return (exit_code, stdout, stderr) (bytes)."""
        log.debug("[%s] execute: %s", self.name, _summary(cmd))
        with self._mirror_serial_until_complete():
            return self.agent.request(cmd.encode("utf-8"), timeout=timeout)

    @contextmanager
    def _mirror_serial_until_complete(self) -> Iterator[None]:
        """Mirror serial bytes produced while one guest command is running."""
        try:
            offset = os.path.getsize(self.serial_log_path)
        except OSError:
            yield
            return

        stop = threading.Event()

        def pump() -> None:
            try:
                with open(self.serial_log_path, "rb") as serial:
                    serial.seek(offset)
                    while not stop.is_set():
                        chunk = serial.read(8192)
                        if chunk:
                            sys.stderr.buffer.write(chunk)
                            sys.stderr.buffer.flush()
                        else:
                            stop.wait(0.1)
                    while True:
                        chunk = serial.read(8192)
                        if not chunk:
                            break
                        sys.stderr.buffer.write(chunk)
                        sys.stderr.buffer.flush()
            except OSError:
                return

        thread = threading.Thread(
            target=pump,
            name=f"{self.name}-serial-mirror",
            daemon=True,
        )
        thread.start()
        try:
            yield
        finally:
            stop.set()
            thread.join(timeout=2)

    def succeed(self, *cmds: str, timeout: float = DEFAULT_TIMEOUT) -> str:
        """Each cmd must exit 0; returns the last cmd's decoded stdout."""
        last_out = ""
        for cmd in cmds:
            exit_code, stdout, stderr = self.execute(cmd, timeout=timeout)
            if exit_code != 0:
                raise MachineFailure(self.name, cmd, exit_code, stdout, stderr)
            last_out = stdout.decode("utf-8", errors="replace")
        return last_out

    def fail(self, *cmds: str, timeout: float = DEFAULT_TIMEOUT) -> str:
        """Each cmd must exit nonzero; returns the last cmd's decoded stdout."""
        last_out = ""
        for cmd in cmds:
            exit_code, stdout, stderr = self.execute(cmd, timeout=timeout)
            if exit_code == 0:
                raise MachineFailure(self.name, cmd, exit_code, stdout, stderr)
            last_out = stdout.decode("utf-8", errors="replace")
        return last_out

    def wait_until_succeeds(
        self, cmd: str, timeout: float = 60, poll: float = 0.5
    ) -> str:
        """Poll cmd at ``poll`` s; raise MachineFailure on deadline."""
        deadline = time.monotonic() + timeout
        last_exit: int = 1
        last_stdout: bytes = b""
        last_stderr: bytes = b""
        while time.monotonic() < deadline:
            try:
                exit_code, stdout, stderr = self.execute(cmd)
            except Exception as e:
                last_exit, last_stdout, last_stderr = 1, b"", str(e).encode("utf-8")
                time.sleep(poll)
                continue
            last_exit, last_stdout, last_stderr = exit_code, stdout, stderr
            if exit_code == 0:
                return stdout.decode("utf-8", errors="replace")
            time.sleep(poll)
        raise MachineFailure(
            self.name, cmd, last_exit, last_stdout, last_stderr, timeout=timeout
        )

    def wait_until_fails(
        self, cmd: str, timeout: float = 60, poll: float = 0.5
    ) -> str:
        """Poll cmd at ``poll`` s; raise MachineFailure on deadline."""
        deadline = time.monotonic() + timeout
        last_exit: int = 0
        last_stdout: bytes = b""
        last_stderr: bytes = b""
        while time.monotonic() < deadline:
            try:
                exit_code, stdout, stderr = self.execute(cmd)
            except Exception as e:
                last_exit, last_stdout, last_stderr = 0, b"", str(e).encode("utf-8")
                time.sleep(poll)
                continue
            last_exit, last_stdout, last_stderr = exit_code, stdout, stderr
            if exit_code != 0:
                return stdout.decode("utf-8", errors="replace")
            time.sleep(poll)
        raise MachineFailure(
            self.name, cmd, last_exit, last_stdout, last_stderr, timeout=timeout
        )

    def wait_for_unit(
        self, unit: str, state: str = "active", timeout: float = 60
    ) -> None:
        """Convenience: poll ``systemctl is-active <unit>``."""
        self.wait_until_succeeds(
            f"systemctl is-active --quiet {unit}", timeout=timeout
        )

    def wait_for_file(self, path: str, timeout: float = 60) -> None:
        """Poll ``test -e <path>``."""
        self.wait_until_succeeds(f"test -e {path}", timeout=timeout)

    def shutdown(self) -> None:
        """Ask the agent to power off. Caller still waits for the VM proc."""
        try:
            self.agent.shutdown()
        except Exception:
            pass


def _summary(s: str | bytes) -> str:
    if isinstance(s, bytes):
        s = s.decode("utf-8", errors="replace")
    s = s.strip()
    if "\n" in s:
        first, _ = s.split("\n", 1)
        return first[:120] + " ..."
    return s[:120]
