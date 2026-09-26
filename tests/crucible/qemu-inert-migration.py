"""Authenticate the sole picosecond PIT delta in sim-off QEMU migration.

QEMU 11.1.1 writes a version-three migration body followed by a framed JSON
VMState description. The pinned patched build adds one i8254 subsection for
fractional clock phase; every legacy byte must still match pinned QEMU.
"""

import argparse
import hashlib
import json
import struct
from pathlib import Path


MAGIC = b"QEVM\x00\x00\x00\x03"
PIT_NAME = b"i8254"
SUBSECTION_NAME = b"i8254/crucible-clock"
# QEMU 11.1.1's pinned i8254 VMState writes 108 legacy bytes after its
# 19-byte SECTION_FULL header; changing either layout must fail this gate.
PIT_BASE_SIZE = 108
PIT_HEADER_SIZE = 19
SUBSECTION_PAYLOAD_SIZE = 32
SUBSECTION_FIELDS = [
    ("channels[0].count_load_phase_ps", "uint16", 2),
    ("channels[1].count_load_phase_ps", "uint16", 2),
    ("channels[2].count_load_phase_ps", "uint16", 2),
    ("channels[0].next_transition_phase_ps", "uint16", 2),
    ("channels[0].crucible_guest_deadline_ps", "uint64", 8),
    ("channels[0].crucible_transform_generation", "uint64", 8),
    ("channels[0].crucible_timer_arm_sequence", "uint64", 8),
]
EXPECTED_SUBSECTION_SCHEMA = {
    "vmsd_name": SUBSECTION_NAME.decode("ascii"),
    "version": 3,
    "fields": [
        {"name": name, "type": kind, "size": size}
        for name, kind, size in SUBSECTION_FIELDS
    ],
}
EXPECTED_JSON_INSERTION = (
    ', "subsections": ' + json.dumps([EXPECTED_SUBSECTION_SCHEMA])
).encode("ascii")


class MigrationMismatch(ValueError):
    """The stream contains a non-allowlisted or malformed difference."""


def require(condition, reason):
    if not condition:
        raise MigrationMismatch(reason)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def split_stream(data):
    """Split QEMU's EOF-terminated body from its final VMDESCRIPTION frame."""
    require(data.startswith(MAGIC), "migration magic or version differs")

    candidates = []
    for offset in range(len(MAGIC), len(data) - 5):
        if data[offset] != 0x06 or data[offset - 1] != 0x00:
            continue
        length = int.from_bytes(data[offset + 1 : offset + 5], "big")
        if offset + 5 + length == len(data):
            candidates.append(offset)
    require(len(candidates) == 1, "missing or ambiguous final VMDESCRIPTION frame")

    offset = candidates[0]
    descriptor_bytes = data[offset + 5 :]
    try:
        descriptor = json.loads(descriptor_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MigrationMismatch("malformed VMDESCRIPTION JSON") from error
    require(isinstance(descriptor, dict), "VMDESCRIPTION is not an object")
    return data[:offset], descriptor_bytes, descriptor


def pit_descriptor(descriptor):
    devices = descriptor.get("devices")
    require(isinstance(devices, list), "VMDESCRIPTION has no devices")
    matches = [
        device
        for device in devices
        if isinstance(device, dict) and device.get("name") == "i8254"
    ]
    require(len(matches) == 1, "VMDESCRIPTION has no unique i8254 device")
    return matches[0]


def verify_descriptor(reference_bytes, reference, patched_bytes, patched):
    reference_pit = pit_descriptor(reference)
    patched_pit = pit_descriptor(patched)
    require("subsections" not in reference_pit, "reference PIT has subsections")
    require(
        patched_pit.get("subsections") == [EXPECTED_SUBSECTION_SCHEMA],
        "patched PIT subsection schema differs",
    )

    original_pit = patched_pit
    patched_pit = patched_pit.copy()
    del patched_pit["subsections"]
    patched = patched.copy()
    patched["devices"] = [
        patched_pit if device is original_pit else device
        for device in patched["devices"]
    ]
    require(patched == reference, "non-PIT VMDESCRIPTION schema differs")

    # The pinned QEMU JSON writer inserts this one member. Preserve the rest
    # of the VMDESCRIPTION bytes, including ordering and whitespace.
    start = next(
        (index for index, (left, right) in enumerate(zip(reference_bytes, patched_bytes))
         if left != right),
        None,
    )
    require(start is not None, "patched VMDESCRIPTION lacks PIT subsection")
    require(
        patched_bytes[start : start + len(EXPECTED_JSON_INSERTION)]
        == EXPECTED_JSON_INSERTION,
        "unexpected PIT VMDESCRIPTION insertion",
    )
    require(
        patched_bytes[:start] + patched_bytes[start + len(EXPECTED_JSON_INSERTION) :]
        == reference_bytes,
        "VMDESCRIPTION changed outside PIT subsection",
    )


def verify_subsection(data):
    frame_size = 1 + 1 + len(SUBSECTION_NAME) + 4 + SUBSECTION_PAYLOAD_SIZE
    require(len(data) >= frame_size, "truncated PIT subsection")
    frame = data[:frame_size]
    require(frame[0] == 0x05, "PIT subsection marker differs")
    require(frame[1] == len(SUBSECTION_NAME), "PIT subsection name length differs")
    require(frame[2 : 2 + len(SUBSECTION_NAME)] == SUBSECTION_NAME, "PIT subsection name differs")
    version_offset = 2 + len(SUBSECTION_NAME)
    require(frame[version_offset : version_offset + 4] == b"\x00\x00\x00\x03", "PIT subsection version differs")
    phase_offset = version_offset + 4
    phases = struct.unpack_from(">4H", frame, phase_offset)
    require(all(phase < 1000 for phase in phases), "PIT fractional phase is outside one nanosecond")
    require(phases[3] != 0, "paused PIT fixture did not exercise fractional timer phase")
    owners = struct.unpack_from(">3Q", frame, phase_offset + 8)
    require(owners == (0, 0, 0), "sim-off PIT unexpectedly owns a Crucible timer")
    return frame, phases, owners


def compare(reference_data, patched_data):
    reference_body, reference_json, reference_desc = split_stream(reference_data)
    patched_body, patched_json, patched_desc = split_stream(patched_data)
    verify_descriptor(reference_json, reference_desc, patched_json, patched_desc)

    difference = next(
        (index for index, (left, right) in enumerate(zip(reference_body, patched_body))
         if left != right),
        None,
    )
    require(difference is not None, "patched migration has no PIT subsection")
    frame, phases, owners = verify_subsection(patched_body[difference:])

    # Derive the only eligible insertion point from the first differing byte.
    # The exact PIT SECTION_FULL header, fixed legacy payload, and matching
    # footer bind it to VMState framing rather than a matching string in RAM.
    header_start = difference - PIT_BASE_SIZE - PIT_HEADER_SIZE
    require(header_start >= len(MAGIC), "PIT section begins before migration body")
    header = reference_body[header_start : header_start + PIT_HEADER_SIZE]
    require(len(header) == PIT_HEADER_SIZE, "truncated PIT section header")
    section_id = header[1:5]
    require(
        header == b"\x04" + section_id + b"\x05" + PIT_NAME + b"\x00" * 4 + b"\x00\x00\x00\x03",
        "first difference is not after the framed i8254 legacy payload",
    )
    require(reference_body.count(header) == 1, "ambiguous i8254 section header")
    require(reference_body[difference : difference + 5] == b"\x7e" + section_id, "reference i8254 footer differs")
    require(patched_body[difference + len(frame) : difference + len(frame) + 5] == b"\x7e" + section_id, "patched i8254 footer differs")
    require(
        patched_body[:difference] + patched_body[difference + len(frame) :] == reference_body,
        "migration differs outside authenticated PIT subsection",
    )
    return {
        "reference_sha256": sha256(reference_data),
        "patched_sha256": sha256(patched_data),
        "legacy_body_sha256": sha256(reference_body),
        "pit_subsection_sha256": sha256(frame),
        "pit_subsection_offset": difference,
        "pit_phase_ps": phases,
        "pit_owner_fields": owners,
    }


def verify_pair(reference_a, reference_b, patched_a, patched_b):
    require(reference_a == reference_b, "reference A/B migration streams differ")
    require(patched_a == patched_b, "patched A/B migration streams differ")
    return compare(reference_a, patched_a)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference_a", type=Path)
    parser.add_argument("reference_b", type=Path)
    parser.add_argument("patched_a", type=Path)
    parser.add_argument("patched_b", type=Path)
    args = parser.parse_args()

    try:
        result = verify_pair(*(path.read_bytes() for path in vars(args).values()))
    except MigrationMismatch as error:
        parser.exit(1, f"FAIL: {error}\n")

    for key, value in result.items():
        if isinstance(value, tuple):
            value = ",".join(map(str, value))
        print(f"migration_{key}={value}")
    print("migration_legacy_projection_identical=true")
    print("migration_exact_ps_subsection_authenticated=true")
    print("migration_same_binary_repeats_identical=true")


if __name__ == "__main__":
    main()
