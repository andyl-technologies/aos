"""Regression tests for versioned QEMU manifest platform profiles."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from aos_test_driver.__main__ import _build_machine, _cleanup_machines, _load_manifest
from aos_test_driver.qemu import QemuMachine


def machine_entry(**overrides: object) -> dict[str, object]:
    """Builds one minimal direct-kernel QEMU manifest entry."""
    entry: dict[str, object] = {
        "name": "vm",
        "transport": "qemu",
        "kernel": "/kernel",
        "initrd": "/initrd",
        "disk": "/disk",
        "metadata": None,
        "memory_mib": 512,
        "vcpu_count": 2,
        "mac": "52:54:00:12:00:01",
        "ip": "192.168.50.10",
    }
    entry.update(overrides)
    return entry


def load_entry(entry: dict[str, object]) -> dict[str, object]:
    """Validates one entry through the real JSON manifest loader."""
    manifest = {"name": "profile-test", "timeout": 60, "machines": [entry]}
    with tempfile.TemporaryDirectory() as temp_dir:
        path = Path(temp_dir) / "manifest.json"
        path.write_text(json.dumps(manifest))
        return _load_manifest(path)["machines"][0]


def qemu_machine(temp_dir: str, *, export_firmware_vars: bool) -> QemuMachine:
    """Builds an unstarted x86 QEMU machine for cleanup-path tests."""
    return QemuMachine(
        name="vm",
        disk="/disk",
        memory_mib=512,
        vcpu_count=2,
        mac="52:54:00:12:00:01",
        ip="192.168.50.10",
        tmpdir=temp_dir,
        export_firmware_vars=export_firmware_vars,
    )


class QemuProfileTests(unittest.TestCase):
    """Checks compatibility defaults and architecture-profile coherence."""

    def test_legacy_manifest_retains_x86_64_defaults(self) -> None:
        entry = load_entry(machine_entry())
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = _build_machine(entry, Path(temp_dir))

        self.assertIsInstance(machine, QemuMachine)
        assert isinstance(machine, QemuMachine)
        self.assertEqual(machine.architecture, "x86_64")
        self.assertEqual(
            machine._base_qemu_argv()[:5],
            ["qemu-system-x86_64", "-machine", "q35,accel=kvm", "-cpu", "host"],
        )

    def test_explicit_aarch64_profile_selects_virt_tcg(self) -> None:
        entry = load_entry(
            machine_entry(
                architecture="aarch64",
                qemu_binary="qemu-system-aarch64",
                machine_type="virt",
                acceleration="tcg",
                cpu_model="cortex-a57",
                console="ttyAMA0",
            )
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = _build_machine(entry, Path(temp_dir))

        self.assertIsInstance(machine, QemuMachine)
        assert isinstance(machine, QemuMachine)
        self.assertEqual(
            machine._base_qemu_argv()[:5],
            [
                "qemu-system-aarch64",
                "-machine",
                "virt,accel=tcg",
                "-cpu",
                "cortex-a57",
            ],
        )
        self.assertEqual(machine.console, "ttyAMA0")

    def test_architecture_only_aarch64_manifest_is_normalized(self) -> None:
        entry = load_entry(machine_entry(architecture="aarch64"))
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = _build_machine(entry, Path(temp_dir))

        self.assertIsInstance(machine, QemuMachine)
        assert isinstance(machine, QemuMachine)
        self.assertEqual(
            machine._base_qemu_argv()[:5],
            [
                "qemu-system-aarch64",
                "-machine",
                "virt,accel=tcg",
                "-cpu",
                "cortex-a57",
            ],
        )
        self.assertEqual(machine.console, "ttyAMA0")

    def test_direct_construction_rejects_incoherent_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(RuntimeError, "machine_type='virt'"):
                QemuMachine(
                    name="vm",
                    architecture="aarch64",
                    machine_type="q35",
                    kernel="/kernel",
                    initrd="/initrd",
                    disk="/disk",
                    memory_mib=512,
                    vcpu_count=2,
                    mac="52:54:00:12:00:01",
                    ip="192.168.50.10",
                    tmpdir=temp_dir,
                )

    def test_direct_construction_rejects_aarch64_image_boot(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(RuntimeError, "image boot is not implemented"):
                QemuMachine(
                    name="vm",
                    boot="image",
                    architecture="aarch64",
                    disk="/disk",
                    memory_mib=512,
                    vcpu_count=2,
                    mac="52:54:00:12:00:01",
                    ip="192.168.50.10",
                    tmpdir=temp_dir,
                )

    def test_direct_construction_rejects_aarch64_tpm(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(RuntimeError, "TPM attachment is not implemented"):
                QemuMachine(
                    name="vm",
                    architecture="aarch64",
                    kernel="/kernel",
                    initrd="/initrd",
                    disk="/disk",
                    tpm=True,
                    memory_mib=512,
                    vcpu_count=2,
                    mac="52:54:00:12:00:01",
                    ip="192.168.50.10",
                    tmpdir=temp_dir,
                )

    def test_aarch64_label_cannot_select_x86_binary(self) -> None:
        with self.assertRaisesRegex(SystemExit, "qemu_binary='qemu-system-aarch64'"):
            load_entry(
                machine_entry(
                    architecture="aarch64",
                    qemu_binary="qemu-system-x86_64",
                    machine_type="virt",
                    acceleration="tcg",
                    cpu_model="cortex-a57",
                    console="ttyAMA0",
                )
            )

    def test_aarch64_label_cannot_select_kvm(self) -> None:
        with self.assertRaisesRegex(SystemExit, "acceleration='tcg'"):
            load_entry(
                machine_entry(
                    architecture="aarch64",
                    qemu_binary="qemu-system-aarch64",
                    machine_type="virt",
                    acceleration="kvm",
                    cpu_model="cortex-a57",
                    console="ttyAMA0",
                )
            )

    def test_aarch64_image_boot_is_rejected_before_launch(self) -> None:
        with self.assertRaisesRegex(SystemExit, "aarch64 image boot is not supported"):
            load_entry(
                machine_entry(
                    boot="image",
                    architecture="aarch64",
                    qemu_binary="qemu-system-aarch64",
                    machine_type="virt",
                    acceleration="tcg",
                    cpu_model="cortex-a57",
                    console="ttyAMA0",
                    firmware_code="/firmware-code",
                    firmware_vars="/firmware-vars",
                )
            )

    def test_aarch64_tpm_is_rejected_before_launch(self) -> None:
        with self.assertRaisesRegex(SystemExit, "aarch64 TPM attachment is not supported"):
            load_entry(
                machine_entry(
                    architecture="aarch64",
                    qemu_binary="qemu-system-aarch64",
                    machine_type="virt",
                    acceleration="tcg",
                    cpu_model="cortex-a57",
                    console="ttyAMA0",
                    tpm=True,
                )
            )

    def test_firmware_export_requires_image_boot(self) -> None:
        with self.assertRaisesRegex(SystemExit, "firmware-vars export requires image boot"):
            load_entry(machine_entry(export_firmware_vars=True))

    def test_image_manifest_passes_firmware_export_flag(self) -> None:
        entry = load_entry(
            machine_entry(
                boot="image",
                firmware_code="/firmware-code",
                firmware_vars="/firmware-vars",
                export_firmware_vars=True,
            )
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = _build_machine(entry, Path(temp_dir))

        self.assertIsInstance(machine, QemuMachine)
        assert isinstance(machine, QemuMachine)
        self.assertTrue(machine.export_firmware_vars)


class FirmwareExportShutdownTests(unittest.TestCase):
    """Checks the opt-in natural-exit proof and cleanup propagation."""

    def test_natural_qemu_exit_allows_export(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = qemu_machine(temp_dir, export_firmware_vars=True)
            process = MagicMock()
            process.wait.return_value = 0
            machine.qemu_proc = process
            machine.agent = MagicMock()
            machine.agent.shutdown.return_value = (0, b"", b"")

            machine.shutdown_for_firmware_export(timeout=17)

        machine.agent.shutdown.assert_called_once_with()
        machine.agent.close.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=17)

    def test_missing_qemu_process_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = qemu_machine(temp_dir, export_firmware_vars=True)
            machine.agent = MagicMock()

            with self.assertRaisesRegex(RuntimeError, "without a QEMU process"):
                machine.shutdown_for_firmware_export()

        machine.agent.shutdown.assert_not_called()

    def test_shutdown_request_failure_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = qemu_machine(temp_dir, export_firmware_vars=True)
            machine.qemu_proc = MagicMock()
            machine.agent = MagicMock()
            machine.agent.shutdown.side_effect = RuntimeError("agent unavailable")

            with self.assertRaisesRegex(RuntimeError, "shutdown request failed"):
                machine.shutdown_for_firmware_export()

        machine.agent.close.assert_called_once_with()

    def test_shutdown_rejection_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = qemu_machine(temp_dir, export_firmware_vars=True)
            machine.qemu_proc = MagicMock()
            machine.agent = MagicMock()
            machine.agent.shutdown.return_value = (1, b"", b"rejected")

            with self.assertRaisesRegex(RuntimeError, "shutdown returned 1"):
                machine.shutdown_for_firmware_export()

    def test_natural_exit_timeout_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = qemu_machine(temp_dir, export_firmware_vars=True)
            process = MagicMock()
            process.wait.side_effect = subprocess.TimeoutExpired("qemu", 3)
            machine.qemu_proc = process
            machine.agent = MagicMock()
            machine.agent.shutdown.return_value = (0, b"", b"")

            with self.assertRaisesRegex(RuntimeError, "did not exit naturally"):
                machine.shutdown_for_firmware_export(timeout=3)

    def test_nonzero_qemu_exit_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = qemu_machine(temp_dir, export_firmware_vars=True)
            process = MagicMock()
            process.wait.return_value = 2
            machine.qemu_proc = process
            machine.agent = MagicMock()
            machine.agent.shutdown.return_value = (0, b"", b"")

            with self.assertRaisesRegex(RuntimeError, "QEMU exited with 2"):
                machine.shutdown_for_firmware_export()

    def test_forced_kill_exit_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = qemu_machine(temp_dir, export_firmware_vars=True)
            process = MagicMock()
            process.wait.return_value = -9
            machine.qemu_proc = process
            machine.agent = MagicMock()
            machine.agent.shutdown.return_value = (0, b"", b"")

            with self.assertRaisesRegex(RuntimeError, "QEMU exited with -9"):
                machine.shutdown_for_firmware_export()

    @patch("aos_test_driver.__main__.time.sleep")
    def test_export_shutdown_failure_changes_cleanup_result(self, _: MagicMock) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = qemu_machine(temp_dir, export_firmware_vars=True)
            machine.shutdown_for_firmware_export = MagicMock(
                side_effect=RuntimeError("natural exit failed")
            )
            machine.stop = MagicMock()

            result = _cleanup_machines([machine], 0)

        self.assertEqual(result, 1)
        machine.stop.assert_called_once_with()

    @patch("aos_test_driver.__main__.time.sleep")
    def test_export_cleanup_exception_preserves_failure(self, _: MagicMock) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = qemu_machine(temp_dir, export_firmware_vars=True)
            machine.shutdown_for_firmware_export = MagicMock()
            machine.stop = MagicMock(side_effect=RuntimeError("cleanup failed"))

            result = _cleanup_machines([machine], 0)

        self.assertEqual(result, 1)

    @patch("aos_test_driver.__main__.time.sleep")
    def test_non_export_cleanup_behavior_is_unchanged(self, _: MagicMock) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = qemu_machine(temp_dir, export_firmware_vars=False)
            machine.shutdown = MagicMock(side_effect=RuntimeError("ignored shutdown"))
            machine.stop = MagicMock(side_effect=RuntimeError("ignored cleanup"))

            result = _cleanup_machines([machine], 0)

        self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
