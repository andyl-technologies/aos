"""Regression tests for versioned QEMU manifest platform profiles."""

import json
import tempfile
import unittest
from pathlib import Path

from aos_test_driver.__main__ import _build_machine, _load_manifest
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


if __name__ == "__main__":
    unittest.main()
