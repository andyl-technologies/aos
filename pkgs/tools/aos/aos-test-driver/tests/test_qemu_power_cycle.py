"""Checks unclean QEMU/vTPM process retirement and retained backing state."""

import signal
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from aos_test_driver.qemu import QemuMachine


def machine_fixture(directory: str, *, tpm: bool = True) -> QemuMachine:
    """Creates an unstarted machine with mocked process and agent boundaries."""
    machine = QemuMachine(
        name="vm",
        disk="/disk",
        memory_mib=512,
        vcpu_count=2,
        mac="52:54:00:12:00:01",
        ip="192.168.50.10",
        tmpdir=directory,
        tpm=tpm,
        swtpm_bin="/swtpm" if tpm else None,
    )
    machine.agent = MagicMock()
    machine.qemu_proc = MagicMock(pid=101, returncode=-9)
    machine.qemu_proc.poll.return_value = None
    if tpm:
        machine.swtpm_proc = MagicMock(pid=102, returncode=-9)
        machine.swtpm_proc.poll.return_value = None
    machine._stop_serial_bridge = MagicMock()
    machine._launch = MagicMock()
    return machine


class PowerCycleTests(unittest.TestCase):
    """Requires both original processes to die before persistent-state reuse."""

    def test_tpm_is_stopped_before_disconnect_and_reaped_before_relaunch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            machine = machine_fixture(directory)
            qemu = machine.qemu_proc
            tpm = machine.swtpm_proc
            assert qemu is not None and tpm is not None
            assert machine.tpm_state_dir is not None
            state = Path(machine.tpm_state_dir)
            state.mkdir()
            nv = state / "tpm2-00.permall"
            nv.write_bytes(b"retained NV state")
            disk = Path(machine.disk_copy)
            disk.write_bytes(b"retained guest disk")
            events = []
            tpm.send_signal.side_effect = lambda received: events.append(("signal", received))
            qemu.kill.side_effect = lambda: events.append("kill QEMU")
            qemu.wait.side_effect = lambda **kwargs: events.append("reap QEMU")
            tpm.kill.side_effect = lambda: events.append("kill swtpm")
            tpm.wait.side_effect = lambda **kwargs: events.append("reap swtpm")

            def relaunch() -> None:
                self.assertIsNone(machine.swtpm_proc)
                self.assertEqual(nv.read_bytes(), b"retained NV state")
                self.assertEqual(disk.read_bytes(), b"retained guest disk")
                events.append("relaunch")

            machine._launch.side_effect = relaunch
            machine.power_cycle(timeout=3)

            self.assertEqual(
                events,
                [
                    ("signal", signal.SIGSTOP),
                    "kill QEMU",
                    "reap QEMU",
                    "kill swtpm",
                    "reap swtpm",
                    "relaunch",
                ],
            )
            machine.agent.wait_ready.assert_called_once()

    def test_qemu_reap_failure_still_retires_stopped_tpm_and_refuses_relaunch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            machine = machine_fixture(directory)
            qemu = machine.qemu_proc
            tpm = machine.swtpm_proc
            assert qemu is not None and tpm is not None
            qemu.wait.side_effect = subprocess.TimeoutExpired("qemu", 3)

            with self.assertRaisesRegex(RuntimeError, "could not kill and reap QEMU"):
                machine.power_cycle(timeout=3)

            tpm.send_signal.assert_called_once_with(signal.SIGSTOP)
            tpm.kill.assert_called_once()
            tpm.wait.assert_called_once()
            machine._launch.assert_not_called()
            machine.agent.wait_ready.assert_not_called()

    def test_missing_tpm_refuses_before_touching_running_qemu(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            machine = machine_fixture(directory)
            qemu = machine.qemu_proc
            assert qemu is not None
            machine.swtpm_proc = None

            with self.assertRaisesRegex(RuntimeError, "requires running swtpm"):
                machine.power_cycle(timeout=3)

            qemu.kill.assert_not_called()
            machine.agent.close.assert_not_called()
            machine._launch.assert_not_called()

    def test_non_tpm_machine_still_reaps_qemu_and_relaunches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            machine = machine_fixture(directory, tpm=False)
            qemu = machine.qemu_proc
            assert qemu is not None

            machine.power_cycle(timeout=3)

            qemu.kill.assert_called_once()
            qemu.wait.assert_called_once()
            machine._launch.assert_called_once()
            machine.agent.wait_ready.assert_called_once()


if __name__ == "__main__":
    unittest.main()
