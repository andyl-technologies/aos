"""Tests matrix completeness, byte binding and capability enforcement."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import image_matrix_boot as boot
import image_matrix as matrix
from image_matrix_boot import guest, pe_command_line


SOURCE = "/nix/store/" + "a" * 32 + "-source"
LOGICAL = hashlib.sha256(b"logical disk").hexdigest()


def fixture_manifest(names=("server",), *, measured=False, lockdown=False):
    """Declares independent subjects with the same supported format inventory."""

    security = {
        "rootFilesystem": "erofs",
        "readOnlyRoot": True,
        "verity": True,
        "secureBoot": measured or lockdown,
        "measuredBoot": measured,
        "lockdown": "confidentiality" if lockdown else "none",
    }
    return {
        "schema": "aos.image-matrix-input/v1",
        "sourceIdentity": SOURCE,
        "platform": "aarch64-linux",
        "buildPlatform": "x86_64-linux",
        "formats": list(matrix.FORMATS),
        "tools": {"qemuImg": "qemu-img", "zstd": "zstd"},
        "firmwareCode": "/nix/store/firmware/FV/AAVMF_CODE.fd",
        "firmwareVars": "",
        "systems": [{
            "name": name,
            "images": {image_format: f"/nix/store/{name}-{image_format}" for image_format in matrix.FORMATS},
            "expected": {
                "toplevel": f"/nix/store/{name}-system",
                "version": "1",
                "kernel": "6.12",
                "moduleAbi": 1,
                "role": "server",
                "security": copy.deepcopy(security),
            },
        } for name in names],
    }


def fixture_report(manifest):
    """Represents completed observations, independently of report generation."""

    systems = []
    for system in manifest["systems"]:
        expected = system["expected"]
        security = expected["security"]
        configured = {
            "generation": 2,
            "runtimeModulesDigest": "b" * 64,
            "hostNixDigest": "c" * 64,
        }
        observations = []
        for number, phase in enumerate(("initial", "warm", "cold"), start=2):
            observations.append({
                "phase": phase,
                "machine": "aarch64",
                "kernel": expected["kernel"],
                "version": expected["version"],
                "moduleAbi": expected["moduleAbi"],
                "toplevel": expected["toplevel"],
                "security": security | {
                    "encryptedState": security["measuredBoot"],
                    "tpm": True,
                    "measurementIndexActive": security["measuredBoot"],
                    "lockdownRejection": security["lockdown"] != "none",
                },
                "configuration": configured | {"generation": number},
            })
        systems.append({
            "name": system["name"],
            "binding": matrix.subject_binding(manifest, system),
            "formats": [{
                "format": image_format,
                "artifact": system["images"][image_format] + "/disk",
                "artifactSha256": "d" * 64,
                "metadataSha256": "e" * 64,
                "byteSize": 100,
                "virtualSizeBytes": 1000,
                "logicalDiskSha256": LOGICAL,
                "equivalent": True,
            } for image_format in matrix.FORMATS],
            "boot": {
                "logicalDiskSha256": LOGICAL,
                "formatBinding": "decoded-logical-disk",
                "warmBoots": 1,
                "coldBoots": 1,
                "checks": {name: True for name in matrix.REQUIRED_BOOT_CHECKS},
                "observations": observations,
                "configuration": configured,
                "imageUpdateClaims": False,
            },
        })
    return {
        "schema": matrix.REPORT_SCHEMA,
        "sourceIdentity": manifest["sourceIdentity"],
        "platform": manifest["platform"],
        "systems": systems,
    }


class ReportTests(unittest.TestCase):
    """Rejects gaps that could otherwise turn partial observations into PASS."""

    def test_all_nine_subjects_bind_thirty_six_formats(self):
        names = tuple(f"system-{number}" for number in range(9))
        manifest = fixture_manifest(names)
        reports = [fixture_report(manifest | {"systems": [system]}) for system in manifest["systems"]]

        result = matrix.merge_reports(manifest, reports)

        self.assertEqual(result["formatCells"], 36)
        self.assertEqual(result["bootSubjects"], 9)
        self.assertEqual(result["evidenceScope"], "format-equivalence-and-boot-runtime")

    def test_missing_or_duplicate_system_is_rejected(self):
        manifest = fixture_manifest(("server", "edge"))
        report = fixture_report(manifest)
        for systems in (report["systems"][:1], report["systems"] + report["systems"][:1]):
            with self.subTest(systems=len(systems)), self.assertRaisesRegex(matrix.MatrixError, "systems"):
                matrix.merge_reports(manifest, [report | {"systems": systems}])

    def test_missing_duplicate_or_foreign_format_is_rejected(self):
        manifest = fixture_manifest()
        for operation in ("missing", "duplicate", "foreign"):
            report = fixture_report(manifest)
            cells = report["systems"][0]["formats"]
            if operation == "missing":
                cells.pop()
            elif operation == "duplicate":
                cells[-1] = copy.deepcopy(cells[0])
            else:
                cells[-1]["format"] = "vdi"
            with self.subTest(operation=operation), self.assertRaisesRegex(matrix.MatrixError, "format cells"):
                matrix.merge_reports(manifest, [report])

    def test_changed_source_or_subject_is_rejected(self):
        manifest = fixture_manifest()
        report = fixture_report(manifest)
        report["sourceIdentity"] = SOURCE + "-different"
        with self.assertRaisesRegex(matrix.MatrixError, "source"):
            matrix.merge_reports(manifest, [report])

        report = fixture_report(manifest)
        manifest["systems"][0]["expected"]["version"] = "2"
        with self.assertRaisesRegex(matrix.MatrixError, "binding"):
            matrix.merge_reports(manifest, [report])

    def test_mismatched_logical_format_or_boot_is_rejected(self):
        manifest = fixture_manifest()
        for target in ("format", "boot"):
            report = fixture_report(manifest)
            subject = report["systems"][0]
            if target == "format":
                subject["formats"][0]["logicalDiskSha256"] = "f" * 64
            else:
                subject["boot"]["logicalDiskSha256"] = "f" * 64
            with self.subTest(target=target), self.assertRaisesRegex(matrix.MatrixError, "logical disk"):
                matrix.merge_reports(manifest, [report])

    def test_missing_cold_boot_or_negative_check_is_rejected(self):
        manifest = fixture_manifest()
        for target in ("coldBoots", "configurationRejection"):
            report = fixture_report(manifest)
            boot = report["systems"][0]["boot"]
            if target == "coldBoots":
                boot["coldBoots"] = 0
            else:
                boot["checks"].pop(target)
            with self.subTest(target=target), self.assertRaises(matrix.MatrixError):
                matrix.merge_reports(manifest, [report])

    def test_boot_reevaluation_may_advance_generation_but_not_inputs(self):
        manifest = fixture_manifest()
        report = fixture_report(manifest)
        matrix.merge_reports(manifest, [report])

        cold = report["systems"][0]["boot"]["observations"][-1]
        cold["configuration"]["runtimeModulesDigest"] = "f" * 64
        with self.assertRaisesRegex(matrix.MatrixError, "configuration input"):
            matrix.merge_reports(manifest, [report])

    def test_image_update_claim_is_not_accepted_from_boot_evidence(self):
        manifest = fixture_manifest()
        report = fixture_report(manifest)
        report["systems"][0]["boot"]["imageUpdateClaims"] = True
        with self.assertRaisesRegex(matrix.MatrixError, "image transitions"):
            matrix.merge_reports(manifest, [report])

    def test_mutable_source_is_rejected(self):
        manifest = fixture_manifest()
        manifest["sourceIdentity"] = "/home/user/checkout"
        with self.assertRaisesRegex(matrix.MatrixError, "immutable"):
            matrix.validate_manifest(manifest)


class SecurityTests(unittest.TestCase):
    """Requires enforcement on every measured warm/cold boot observation."""

    def test_measured_and_lockdown_positive_observations_pass(self):
        for measured, lockdown in ((True, False), (False, True)):
            manifest = fixture_manifest(measured=measured, lockdown=lockdown)
            matrix.merge_reports(manifest, [fixture_report(manifest)])

    def test_each_measured_capability_fails_closed(self):
        manifest = fixture_manifest(measured=True)
        for field in ("verity", "secureBoot", "measuredBoot", "encryptedState", "tpm", "measurementIndexActive"):
            report = fixture_report(manifest)
            report["systems"][0]["boot"]["observations"][-1]["security"][field] = False
            with self.subTest(field=field), self.assertRaises(matrix.MatrixError):
                matrix.merge_reports(manifest, [report])

    def test_missing_or_integer_security_boolean_is_rejected(self):
        manifest = fixture_manifest()
        for value in (None, 1):
            report = fixture_report(manifest)
            security = report["systems"][0]["boot"]["observations"][0]["security"]
            if value is None:
                security.pop("verity")
            else:
                security["verity"] = value
            with self.subTest(value=value), self.assertRaises(matrix.MatrixError):
                matrix.merge_reports(manifest, [report])

    def test_lockdown_requires_a_rejected_operation(self):
        manifest = fixture_manifest(lockdown=True)
        report = fixture_report(manifest)
        report["systems"][0]["boot"]["observations"][1]["security"]["lockdownRejection"] = False
        with self.assertRaisesRegex(matrix.MatrixError, "rejected"):
            matrix.merge_reports(manifest, [report])

    def test_guest_checks_stop_at_first_failure(self):
        class Machine:
            def ssh(self, command, **options):
                return command

        self.assertEqual(guest(Machine(), "false; true"), "set -eu; false; true")


class FormatTests(unittest.TestCase):
    """Checks real artifact hashes and decoder comparison failures."""

    def prepare(self, root):
        manifest = fixture_manifest()
        system = manifest["systems"][0]
        logical = b"logical disk"
        for image_format in matrix.FORMATS:
            directory = root / image_format
            directory.mkdir()
            system["images"][image_format] = str(directory)
            encoded = (image_format + " encoding").encode()
            (directory / "disk").write_bytes(encoded)
            metadata = {
                "schemaVersion": 2,
                "format": image_format,
                "platform": "aarch64-linux",
                "version": "1",
                "name": "AOS",
                "moduleAbi": 1,
                "filename": "disk",
                "compression": "zstd" if image_format == "raw" else "none",
                "byteSize": len(encoded),
                "sha256": hashlib.sha256(encoded).hexdigest(),
                "logicalDiskSha256": hashlib.sha256(logical).hexdigest(),
                "virtualSizeBytes": len(logical),
                "artifactBudgetsMiB": {"download": 1},
                "rootfsSha256": "a" * 64,
                "uki": {"signed": False, "measured": False},
            }
            (directory / "image-info.json").write_text(json.dumps(metadata))
        return manifest, system, logical

    def test_changed_artifact_bytes_are_rejected_before_decoding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, system, _ = self.prepare(root)
            artifact = root / "vhd" / "disk"
            artifact.write_bytes(b"X" * artifact.stat().st_size)

            with self.assertRaisesRegex(matrix.MatrixError, "artifact hash differs"):
                matrix.verify_formats(manifest, system, root)

    def test_decoder_byte_difference_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, system, logical = self.prepare(root)

            def command(arguments):
                if arguments[0] == "zstd":
                    Path(arguments[-1]).write_bytes(logical)
                elif arguments[1] == "info":
                    return subprocess.CompletedProcess(arguments, 0, json.dumps({"virtual-size": len(logical)}))
                elif arguments[1] == "compare" and "vpc" in arguments:
                    raise matrix.MatrixError("qemu-img found different disk bytes")
                return subprocess.CompletedProcess(arguments, 0, "")

            with patch.object(matrix, "run", side_effect=command):
                with self.assertRaisesRegex(matrix.MatrixError, "different disk bytes"):
                    matrix.verify_formats(manifest, system, root)

    def test_wrong_raw_decode_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, system, logical = self.prepare(root)

            def command(arguments):
                Path(arguments[-1]).write_bytes(b"X" * len(logical))
                return subprocess.CompletedProcess(arguments, 0, "")

            with patch.object(matrix, "run", side_effect=command):
                with self.assertRaisesRegex(matrix.MatrixError, "decoded raw hash"):
                    matrix.verify_formats(manifest, system, root)


class ConfigurationTests(unittest.TestCase):
    """Distinguishes initial configuration from committed runtime modules."""

    def test_initial_generation_may_omit_runtime_modules(self):
        manifest = {"inputs": {"host_nix": "host input"}}
        with (
            patch.object(boot, "read_guest_generation", return_value=1),
            patch.object(boot, "guest", return_value=json.dumps(manifest)),
        ):
            identity = boot.configuration_identity(object(), require_runtime=False)

        self.assertEqual(identity["runtimeModulesDigest"], matrix.digest(None))
        self.assertEqual(identity["hostNixDigest"], matrix.digest("host input"))

    def test_configured_generation_requires_runtime_modules(self):
        manifest = {"inputs": {"host_nix": "host input"}}
        with (
            patch.object(boot, "read_guest_generation", return_value=1),
            patch.object(boot, "guest", return_value=json.dumps(manifest)),
        ):
            with self.assertRaisesRegex(matrix.MatrixError, "runtime-module binding"):
                boot.configuration_identity(object())

    def test_enrollment_uses_production_helper(self):
        machine = unittest.mock.Mock()
        system = {"guestTools": {
            "enroll": "/nix/store/enroll/bin/aos-sb-enroll",
            "enrollAuthDir": "/nix/store/auth",
        }}
        with (
            patch.object(boot, "efivar", side_effect=[1, 0, 0, 1]),
            patch.object(boot, "guest") as guest_command,
        ):
            boot.enroll(machine, system)

        guest_command.assert_any_call(machine, system["guestTools"]["enroll"], timeout=300)
        machine.reboot.assert_called_once()


class PeTests(unittest.TestCase):
    """Exercises cross-architecture section parsing and offset bounds."""

    def image(self, command):
        data = bytearray(1024)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 60, 64)
        data[64:68] = b"PE\0\0"
        struct.pack_into("<HH", data, 68, 0xAA64, 1)
        struct.pack_into("<H", data, 84, 0)
        data[88:96] = b".cmdline"
        payload = command.encode() + b"\0"
        struct.pack_into("<IIII", data, 96, len(payload), 0x1000, 512, 512)
        data[512:512 + len(payload)] = payload
        return data

    def test_reads_arm_pe_command_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "uki.efi"
            command = "root=/dev/mapper/root roothash=" + "a" * 64
            path.write_bytes(self.image(command))
            self.assertEqual(pe_command_line(path), command)

    def test_out_of_bounds_section_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "uki.efi"
            image = self.image("root=/dev/mapper/root")
            struct.pack_into("<I", image, 108, 1000)
            path.write_bytes(image)
            with self.assertRaisesRegex(matrix.MatrixError, "exceeds file"):
                pe_command_line(path)


if __name__ == "__main__":
    unittest.main()
