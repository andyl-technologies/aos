"""Tests that VM reboot evidence survives SSH transport failures."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


BOOT_BEFORE = "11111111-1111-4111-8111-111111111111"
BOOT_AFTER = "22222222-2222-4222-8222-222222222222"


class RebootEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Importing the transport declares tool paths but launches no tools.
        # Each test supplies SSH results at the subprocess boundary instead.
        settings = (
            "PLATFORM", "ASSESSMENTS", "STAGING_HUB_URL", "QEMU", "QEMU_IMG",
            "FIRMWARE_CODE", "FIRMWARE_VARS", "SWTPM", "SGDISK", "MKE2FS",
            "ZSTD", "SSH", "SCP", "SSH_KEYGEN", "OPENSSL", "OBJCOPY", "NIX_STORE",
        )
        environment = {f"AOS_QUALIFICATION_{name}": "" for name in settings}
        environment["AOS_QUALIFICATION_PLATFORM"] = "x86_64-linux"
        source = Path(__file__).with_name("qualification-image.py")
        spec = importlib.util.spec_from_file_location("_qualification_image_tests", source)
        if spec is None or spec.loader is None:
            raise RuntimeError("could not load the image qualification transport")

        cls.transport = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.transport
        cls.addClassCleanup(sys.modules.pop, spec.name, None)
        with patch.dict(os.environ, environment):
            spec.loader.exec_module(cls.transport)

    def setUp(self):
        # Reboot observation needs no disk, TPM, or QEMU process construction.
        self.machine = self.transport.VirtualMachine.__new__(self.transport.VirtualMachine)
        self.machine.name = "image-guest"
        self.machine.port = 2222
        self.machine.ssh_key = Path("test-key")
        self.machine.counts = self.transport.Counts()
        self.ready = self.enterContext(patch.object(self.machine, "wait_for_ssh"))
        self.enterContext(patch.object(self.transport.time, "sleep"))

    @staticmethod
    def reply(output, status=0):
        return subprocess.CompletedProcess(["ssh"], status, stdout=output)

    def test_connection_error_does_not_count_as_a_new_boot(self):
        replies = [
            self.reply(BOOT_BEFORE),
            self.reply("Connection closed by remote host", 255),
            self.reply("ssh: connect to host 127.0.0.1: Connection refused", 255),
            self.reply(BOOT_AFTER),
        ]
        with patch.object(self.transport.subprocess, "run", side_effect=replies) as ssh:
            self.machine.reboot()

        self.assertEqual(ssh.call_count, 4)
        self.ready.assert_called_once_with(420)
        self.assertEqual(self.machine.counts.reboot_cycles, 1)

    def test_connection_failures_cannot_produce_reboot_evidence(self):
        replies = [
            self.reply(BOOT_BEFORE),
            self.reply(""),
            self.reply("ssh: connect to host 127.0.0.1: Connection refused", 255),
        ]
        with (
            patch.object(self.transport.subprocess, "run", side_effect=replies),
            patch.object(self.transport.time, "monotonic", side_effect=[0, 1, 721]),
        ):
            with self.assertRaisesRegex(RuntimeError, "timed out rebooting image-guest"):
                self.machine.reboot()

        self.ready.assert_not_called()
        self.assertEqual(self.machine.counts.reboot_cycles, 0)


if __name__ == "__main__":
    unittest.main()
