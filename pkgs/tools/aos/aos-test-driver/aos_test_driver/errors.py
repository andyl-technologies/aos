"""Exception classes for the AOS test driver.

Three distinct exceptions, all subclassing AosDriverError, mirroring
the three failure modes a test author may encounter:

  - MachineFailure: a test-issued command did not meet its assertion
    (succeed got nonzero, fail got zero, wait_until_* deadline fired).
  - AgentTimeout: the agent did not respond within the per-RPC deadline.
  - AgentProtocolError: the agent returned a malformed wire response;
    indicates a bug in the agent or transport — don't retry.

The driver's top-level except clause prints the exception, dumps every
machine's serial log to stderr, and exits 1.
"""


class AosDriverError(Exception):
    """Base class for all driver-internal errors."""


class MachineFailure(AosDriverError):
    """A test-issued command did not meet its assertion."""

    def __init__(self, machine, cmd, exit_code, stdout, stderr, timeout=None):
        self.machine = machine
        self.cmd = cmd
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.timeout = timeout
        super().__init__(self._format())

    def _format(self):
        head = f"[{self.machine}] command failed (exit {self.exit_code})"
        if self.timeout is not None:
            head += f" — deadline {self.timeout}s fired"
        cmd_line = self.cmd if "\n" not in self.cmd else self.cmd.splitlines()[0] + " ..."
        out = self.stdout.decode("utf-8", errors="replace").rstrip()
        err = self.stderr.decode("utf-8", errors="replace").rstrip()
        lines = [head, f"  cmd: {cmd_line}"]
        if out:
            lines.append(f"  stdout:\n{_indent(out)}")
        if err:
            lines.append(f"  stderr:\n{_indent(err)}")
        return "\n".join(lines)


class AgentTimeout(AosDriverError):
    """The agent did not respond within the per-RPC deadline."""

    def __init__(self, machine, cmd, timeout):
        self.machine = machine
        self.cmd = cmd
        self.timeout = timeout
        super().__init__(
            f"[{machine}] agent timeout after {timeout}s on {cmd!r}"
        )


class AgentProtocolError(AosDriverError):
    """The agent returned a malformed wire response or the socket died."""

    def __init__(self, machine, detail):
        self.machine = machine
        self.detail = detail
        super().__init__(f"[{machine}] agent protocol error: {detail}")


def _indent(text, prefix="    "):
    return "\n".join(prefix + line for line in text.splitlines())
