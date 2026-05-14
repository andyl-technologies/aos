"""Machine base class — the API tests interact with.

Modelled on NixOS's test driver Machine but stripped to what the AOS
agent supports (no copy_from_*, no QMP, no OCR, no monitor commands).
The agent RPC speaks one verb (run a bash blob) plus PING / SHUTDOWN.
"""

import logging
import time

from .agent import DEFAULT_TIMEOUT, AgentClient
from .errors import MachineFailure


log = logging.getLogger(__name__)


class Machine:
    """Base; QemuMachine / FirecrackerMachine implement start() / stop()."""

    transport: str  # "qemu" or "firecracker"; set by subclass

    def __init__(self, name, agent_socket_path, serial_log_path):
        self.name = name
        self.agent = AgentClient(name, agent_socket_path, self.transport)
        self.serial_log_path = serial_log_path

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
    def execute(self, cmd, timeout=DEFAULT_TIMEOUT):
        """Run cmd on the guest; return (exit_code, stdout, stderr) (bytes)."""
        log.debug("[%s] execute: %s", self.name, _summary(cmd))
        return self.agent.request(cmd.encode("utf-8"), timeout=timeout)

    def succeed(self, *cmds, timeout=DEFAULT_TIMEOUT):
        """Each cmd must exit 0; returns the last cmd's decoded stdout."""
        last_out = ""
        for cmd in cmds:
            exit_code, stdout, stderr = self.execute(cmd, timeout=timeout)
            if exit_code != 0:
                raise MachineFailure(self.name, cmd, exit_code, stdout, stderr)
            last_out = stdout.decode("utf-8", errors="replace")
        return last_out

    def fail(self, *cmds, timeout=DEFAULT_TIMEOUT):
        """Each cmd must exit nonzero; returns the last cmd's decoded stdout."""
        last_out = ""
        for cmd in cmds:
            exit_code, stdout, stderr = self.execute(cmd, timeout=timeout)
            if exit_code == 0:
                raise MachineFailure(self.name, cmd, exit_code, stdout, stderr)
            last_out = stdout.decode("utf-8", errors="replace")
        return last_out

    def wait_until_succeeds(self, cmd, timeout=60, poll=0.5):
        """Poll cmd at ``poll`` s; raise MachineFailure on deadline."""
        deadline = time.monotonic() + timeout
        last_exit, last_stdout, last_stderr = 1, b"", b""
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

    def wait_until_fails(self, cmd, timeout=60, poll=0.5):
        """Poll cmd at ``poll`` s; raise MachineFailure on deadline."""
        deadline = time.monotonic() + timeout
        last_exit, last_stdout, last_stderr = 0, b"", b""
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

    def wait_for_unit(self, unit, state="active", timeout=60):
        """Convenience: poll ``systemctl is-active <unit>``."""
        self.wait_until_succeeds(
            f"systemctl is-active --quiet {unit}", timeout=timeout
        )

    def wait_for_file(self, path, timeout=60):
        """Poll ``test -e <path>``."""
        self.wait_until_succeeds(f"test -e {path}", timeout=timeout)

    def shutdown(self) -> None:
        """Ask the agent to power off. Caller still waits for the VM proc."""
        try:
            self.agent.shutdown()
        except Exception:
            pass


def _summary(s):
    if isinstance(s, bytes):
        s = s.decode("utf-8", errors="replace")
    s = s.strip()
    if "\n" in s:
        first, _ = s.split("\n", 1)
        return first[:120] + " ..."
    return s[:120]
