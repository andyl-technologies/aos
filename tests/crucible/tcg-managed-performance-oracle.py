# SPDX-License-Identifier: Apache-2.0
"""Validate newly admitted native samples without relabeling historical rows.

Canonical BLAKE roots bind the execution scope. They are not the historical
flat physical-memory SHA256 witness. Timing stops at the authenticated native
boundary and does not claim an immediate serial socket receipt interval.
"""

import copy
import re
import runpy
import struct
from pathlib import Path

SCHEMA = "crucible.managed-tcg-performance.v1"
WITNESS_KEYS = (
    "raw_icount", "logical_tick", "request", "canonical_execution_fingerprint",
    "canonical_ram_blake3", "canonical_register_blake3", "canonical_device_blake3",
    "ram_bytes", "serial_hex", "timer_witness", "workload", "ram_mib",
    "registers", "ram_prefix_hex", "record_hex", "sim_saved_registers_hex",
)


def require_witness(sample, workload, ram_mib):
    """Require actual owner, exact native stop, canonical roots and cleanup."""
    if sample["schema"] != SCHEMA or sample["workload"] != workload:
        raise AssertionError("sample belongs to another measurement contract")
    if not all(sample[key] is True for key in (
        "managed_owner", "accepted_assignment", "native_cleanup",
        "fingerprint_requests_after_measurement",
    )):
        raise AssertionError("sample lacks accepted native ownership or physical cleanup")
    if sample["mode"] != "sim" or sample["ram_mib"] != ram_mib:
        raise AssertionError("sample differs from its authored workload shape")
    if sample["component_failures"] != 0 or sample["ram_bytes"] < ram_mib * 1024 * 1024:
        raise AssertionError("sample has incomplete canonical RAM/component coverage")
    for key in ("canonical_execution_fingerprint", "canonical_ram_blake3",
                "canonical_register_blake3", "canonical_device_blake3"):
        if not re.fullmatch(r"[0-9a-f]{64}", sample[key]) or sample[key] == "0" * 64:
            raise AssertionError("missing canonical component identity")
    if not 0 <= sample["startup_seconds"] <= sample["seconds"]:
        raise AssertionError("native timing endpoint precedes process startup")
    if sample["serial_receipt_roi_seconds"] is not None:
        raise AssertionError("native stop timing cannot claim serial receipt ROI")
    request = sample["request"]
    if workload == "bios":
        if request is not None or sample["logical_tick"] != sample["raw_icount"] * 50:
            raise AssertionError("BIOS lacks its exact instruction horizon")
    else:
        expected = {"sequence": 2, "selectable_id": "flight.ready", "instance_key": "boot"}
        if any(request[key] != value for key, value in expected.items()):
            raise AssertionError("unexpected authenticated readiness request")
        if (sample["raw_icount"] != request["raw_icount"] + 1
                or sample["logical_tick"] != request["logical_tick"] + 50):
            raise AssertionError("request-to-stop boundary changed")
        serial = bytes.fromhex(sample["serial_hex"])
        if workload == "linux":
            if serial.count(b"\nCRUCIBLE_TCG_BOOT_READY_V1\n") != 1:
                raise AssertionError("missing unique complete Linux boot token")
            timer = sample["timer_witness"]
            if (not timer or timer["completed"] != 1 or timer["reserved"] != 0
                    or timer["generation"] < 1
                    or timer["armed_raw_icount"] != timer["fired_raw_icount"]
                    or timer["fired_raw_icount"] > sample["raw_icount"]
                    or timer["deadline_ps"] != timer["fired_expire_ps"]
                    or timer["fired_expire_ps"] > timer["fired_virtual_ps"]):
                raise AssertionError("Linux timer callback witness is incomplete")
        elif workload == "rom":
            manifest = sample["manifest"]
            start, end = (manifest[key].encode() for key in ("start_token", "end_token"))
            if not start or not end or serial.count(start) != 1 or serial.count(end) != 1:
                raise AssertionError("finite checksum tokens are incomplete or ambiguous")
            if serial.index(start) >= serial.index(end):
                raise AssertionError("finite END preceded START")
            if sample["record_hex"] != manifest["record_hex"]:
                raise AssertionError("finite RAM checksum/counter/iteration/tag differs")
            if sample["sim_saved_registers_hex"] != struct.pack("<II", 0, manifest["checksum"]).hex():
                raise AssertionError("finite saved EAX/ECX differs from independent checksum")
            registers = {name: int(value, 16) for name, value in re.findall(
                r"\b(EAX|ECX|ESP)=([0-9a-fA-F]+)", sample["registers"])}
            operands = {"EAX": manifest["request_address"], "ECX": 128, "ESP": 0x5ff8}
            if any(registers.get(name) != value for name, value in operands.items()):
                raise AssertionError("finite native request operands or saved stack differ")
            if sample["raw_icount"] <= manifest["loop_retired_instructions"]:
                raise AssertionError("finite arithmetic work did not precede the stop")
    return {key: sample[key] for key in WITNESS_KEYS}


def negative_controls(sample, workload, ram_mib):
    """Require original ownership and boundary mutations to be rejected."""
    mutations = {
        "unadmitted_owner": lambda value: value.update(managed_owner=False),
        "unaccepted_assignment": lambda value: value.update(accepted_assignment=False),
        "unreaped_process": lambda value: value.update(native_cleanup=False),
        "incomplete_components": lambda value: value.update(component_failures=1),
        "incomplete_ram": lambda value: value.update(ram_bytes=ram_mib * 1024 * 1024 - 1),
        "invented_serial_roi": lambda value: value.update(serial_receipt_roi_seconds=1),
        "raw_overshoot": lambda value: value.update(raw_icount=value["raw_icount"] + 1),
    }
    for name, mutate in mutations.items():
        invalid = copy.deepcopy(sample)
        mutate(invalid)
        try:
            require_witness(invalid, workload, ram_mib)
        except AssertionError:
            continue
        raise AssertionError(f"managed sample negative control accepted: {name}")
    return list(mutations)


def require_bios_reference(sample, horizon, loop_instructions=7):
    """Compare actual post-stop registers/RAM with the independent BIOS arithmetic."""
    require_witness(sample, "bios", 64)
    oracle = runpy.run_path(str(Path(__file__).with_name("tcg-performance.py")))
    witness = {key: sample[key] for key in (
        "raw_icount", "logical_tick", "registers", "ram_prefix_hex",
    )}
    oracle["require_reference"]({"witness": witness}, horizon, loop_instructions)
    return {key: sample[key] for key in WITNESS_KEYS}
