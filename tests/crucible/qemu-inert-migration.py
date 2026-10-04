"""Authenticate the ten wide-timer VMState additions in paused sim-off QEMU.

Only framed wide-timer subsections, the section-ID shift caused by one added
registration, and PIT's documented nanosecond shadows may differ. Everything
else is compared byte for byte with the independently built reference QEMU.
"""

import argparse
import copy
import hashlib
import json
import struct
from pathlib import Path

MAGIC = b"QEVM\x00\x00\x00\x03"
# Owner, name, version, payload size, SHA-256 of QEMU's canonical JSON schema.
# The hash fixes every field name, signedness, array length, nesting and order;
# decode_fields below independently checks the physical byte layout and values.
WIDE = (
    ("apic", "apic/timer-wide", 1, 74, "3de205937ecad518c2b464fbe8d342fe15d41c36db33a60a2184415fa8e6eb6a"),
    ("mc146818rtc", "mc146818rtc/timer-wide", 1, 211, "215b80d194e5b119e42aa723a960f070acb27c5ceb9215303afcef01c3fd1d3c"),
    ("0000:00:1f.0/ICH9LPC", "ich9_pm/timer-wide", 2, 34, "39f1234fa73c95ba9cc07ce158d94f678c6e9fcc17bd5f2c536ded3ca189384e"),
    ("0000:00:1f.0/ICH9LPC", "ich9_pm/tco-timer-wide", 1, 18, "89263c95cb755c5eb629ffa9c152864d1250a655879a76b320674160127a4e15"),
    ("0000:00:1f.0/ICH9LPC", "ich9_pm/swsmi-timer-wide", 1, 18, "ba3b500f4a8c958601d04d0afbd4aa9fdfa2aa0bfdc8c5426e92091201f11123"),
    ("0000:00:1f.0/ICH9LPC", "ich9_pm/periodic-timer-wide", 1, 18, "81dc438c0e814cd9f295c6807f7405cc86cd2746698090172b2b3ae9382d2d11"),
    ("hpet", "hpet/clock-wide", 2, 167, "f2485644ced16847ce5de838b6971c3625d079e9b29f201352ec5a887ed71fe4"),
    ("i8254", "i8254/timer-wide", 1, 172, "6205d367dca5de31d8ced8de5114f5c2464678e8c0e688c41a00a592b0296dec"),
    ("serial", "serial/timing-wide", 1, 43, "9cc9d76bac6fb61d8b415fd96de7d14fb61fc3427383dcc4a0a8d932ee8358d7"),
    ("pckbd", "pckbd/timer-wide", 1, 19, "941fdb0dc629efc47e747ba5b25303cfce300cdc95427d03517571836fd57159"),
)
VERSIONS = {"apic": 3, "mc146818rtc": 3, "0000:00:1f.0/ICH9LPC": 1,
            "hpet": 2, "i8254": 3, "serial": 3, "pckbd": 3}

# Exact QEMU 11.1.1 section header/footer pairs in this paused q35 profile.
# Offsets address the final byte of each big-endian section ID in the stock
# body. Pinning actual section frames prevents a payload that resembles a
# marker followed by an ID from gaining projection authority.
# (header ID offset, footer ID offset, header marker, stock ID, name,
#  instance ID, version). START/PART/END are the three RAM frames.
SECTION_FRAMES = (
    (28, 193, 1, 1, "ram", 0, 4),
    (198, 791944, 2, 1, None, None, None),
    (791954, 791967, 3, 1, None, None, None),
    (791972, 792171, 4, 6, "apic", 0, 3),
    (792176, 792219, 4, 0, "timer", 0, 2),
    (792224, 792256, 4, 3, "cpu_common", 0, 1),
    (792261, 794129, 4, 4, "cpu", 0, 12),
    (794134, 794303, 4, 5, "kvm-tpr-opt", 0, 1),
    (794308, 794402, 4, 7, "fw_cfg", 0, 2),
    (794407, 794714, 4, 8, "0000:00:00.0/mch", 0, 1),
    (794719, 794744, 4, 9, "PCIHost", 0, 1),
    (794749, 794805, 4, 10, "PCIBUS", 0, 1),
    (794810, 794902, 4, 11, "dma", 0, 1),
    (794907, 794999, 4, 12, "dma", 1, 1),
    (795004, 795274, 4, 13, "mc146818rtc", 0, 3),
    (795279, 814225, 4, 14, "0000:00:1f.0/ICH9LPC", 0, 1),
    (814230, 814265, 4, 15, "i8259", 0, 1),
    (814270, 814305, 4, 16, "i8259", 1, 1),
    (814310, 814536, 4, 17, "ioapic", 0, 3),
    (814541, 814710, 4, 18, "hpet", 0, 2),
    (814715, 814842, 4, 19, "i8254", 0, 3),
    (814847, 814868, 4, 20, "pcspk", 0, 1),
    (814873, 814904, 4, 21, "serial", 0, 3),
    (814909, 815213, 4, 22, "ps2kbd", 0, 3),
    (815218, 815531, 4, 23, "ps2mouse", 0, 2),
    (815536, 815595, 4, 24, "pckbd", 0, 3),
    (815600, 819726, 4, 25, "vmmouse", 0, 0),
    (819731, 819752, 4, 26, "port92", 0, 1),
    (819757, 823961, 4, 27, "0000:00:1f.2/ich9_ahci", 0, 1),
    (823966, 823988, 4, 28, "i2c_bus", 0, 1),
    (823993, 824353, 4, 29, "0000:00:1f.3/ich9_smb", 0, 1),
    (824358, 824383, 4, 38, "acpi_build", 0, 1),
    (824388, 824517, 4, 39, "globalstate", 0, 1),
)

# Each frame must project to its VMState save position within its real owner.
INSERTION_POINTS = (792167, 795270, 797833, 797833, 797833, 797833,
                    814706, 814838, 814900, 815591)


class MigrationMismatch(ValueError):
    """A migration stream differs outside the pinned timer projection."""


def require(condition, reason):
    if not condition:
        raise MigrationMismatch(reason)


def split_stream(data):
    require(data.startswith(MAGIC), "migration magic or version differs")
    candidates = []
    for offset in range(len(MAGIC), len(data) - 5):
        if data[offset] == 6 and data[offset - 1] == 0:
            length = int.from_bytes(data[offset + 1:offset + 5], "big")
            if offset + 5 + length == len(data):
                candidates.append(offset)
    require(len(candidates) == 1, "missing or ambiguous VMDESCRIPTION frame")
    offset = candidates[0]
    raw = data[offset + 5:]
    try:
        descriptor = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MigrationMismatch("malformed VMDESCRIPTION JSON") from error
    require(isinstance(descriptor, dict) and json.dumps(descriptor).encode() == raw,
            "VMDESCRIPTION encoding or member order differs")
    return data[:offset], raw, descriptor


def device(descriptor, name):
    devices = descriptor.get("devices")
    require(isinstance(devices, list), "VMDESCRIPTION lacks devices")
    matches = [entry for entry in devices if isinstance(entry, dict)
               and entry.get("name") == name]
    require(len(matches) == 1, f"non-unique {name} descriptor")
    return matches[0]


def at(root, path):
    for key in path:
        root = root[key]
    return root


def change_field(root, path, new, old, old_type=None):
    entry = at(root, path)
    require(entry["name"] == new and (old_type is None or entry["type"] == "int64"),
            f"unexpected {new} VMState field")
    entry["name"] = old
    if old_type:
        entry["type"] = old_type


def remove_wide(root, specs, legacy_count=0):
    sections = root.get("subsections")
    require(isinstance(sections, list) and len(sections) == legacy_count + len(specs),
            "timer subsection inventory differs")
    for actual, (_, name, version, _, digest) in zip(sections[legacy_count:], specs):
        require(actual["vmsd_name"] == name and actual["version"] == version and
                hashlib.sha256(json.dumps(actual).encode()).hexdigest() == digest,
                f"{name} schema differs")
    if legacy_count:
        root["subsections"] = sections[:legacy_count]
    else:
        del root["subsections"]


def verify_descriptor(reference_raw, reference, patched_raw, patched):
    require(len(reference["devices"]) == len(patched["devices"]) == 30,
            "paused machine VMState roster differs")
    projected = copy.deepcopy(patched)
    for name, indexes in (("apic", (0,)), ("mc146818rtc", (1,)),
                          ("hpet", (6,)), ("i8254", (7,))):
        remove_wide(device(projected, name), [WIDE[index] for index in indexes])
    rtc = device(projected, "mc146818rtc")
    change_field(rtc, ("fields", 3), "periodic_ns_shadow", "periodic_timer", "timer")
    change_field(rtc, ("fields", 11), "update_ns_shadow", "update_timer", "timer")

    pm = device(projected, "0000:00:1f.0/ICH9LPC")["fields"][2]
    require(pm["size"] == 2449, "ICH9 PM wide size differs")
    pm["size"] = 2246
    remove_wide(pm["struct"], WIDE[2:6], 4)
    change_field(pm, ("struct", "fields", 3), "acpi_regs.tmr.legacy_timer_ns",
                 "acpi_regs.tmr.timer", "timer")
    change_field(pm, ("struct", "fields", 4), "acpi_regs.tmr.legacy_overflow_time",
                 "acpi_regs.tmr.overflow_time")
    tco = ("struct", "subsections", 1, "fields", 0, "struct", "fields")
    change_field(pm, tco + (12,), "legacy_timer_ns", "tco_timer", "timer")
    change_field(pm, tco + (13,), "legacy_expire_time", "expire_time")

    hpet = device(projected, "hpet")
    change_field(hpet, ("fields", 4, "struct", "fields", 6),
                 "legacy_deadline_ns", "qemu_timer", "timer")
    serial = device(projected, "serial")["fields"][0]
    require(serial["size"] == 78, "serial wide size differs")
    serial["size"] = 11
    remove_wide(serial["struct"], WIDE[8:9])
    keyboard = device(projected, "pckbd")["fields"][0]
    require(keyboard["size"] == 81, "keyboard wide size differs")
    keyboard["size"] = 40
    remove_wide(keyboard["struct"], WIDE[9:10], 1)

    require(projected == reference and json.dumps(projected).encode() == reference_raw,
            "VMDESCRIPTION differs outside seven timer schemas")
    require(json.dumps(patched).encode() == patched_raw,
            "patched VMDESCRIPTION bytes differ from parsed schema")
    return patched


def decode_fields(fields, payload):
    """Decode QEMU VMState primitives with checked nested sizes and arrays."""
    result = {}
    offset = 0
    for entry in fields:
        values = []
        for _ in range(entry.get("array_len", 1)):
            size = entry["size"]
            chunk = payload[offset:offset + size]
            require(len(chunk) == size, "truncated wide timer field")
            if entry["type"] == "struct":
                value = decode_fields(entry["struct"]["fields"], chunk)
            else:
                require(entry["type"] in ("uint8", "uint64", "int64", "bool") and
                        size == (1 if entry["type"] in ("uint8", "bool") else 8),
                        "unexpected wide timer primitive")
                value = int.from_bytes(chunk, "big", signed=entry["type"] == "int64")
                if entry["type"] == "bool":
                    require(value in (0, 1), "non-boolean wide timer value")
            values.append(value)
            offset += size
        result[entry["name"]] = values if "array_len" in entry else values[0]
    require(offset == len(payload), "wide timer field length differs")
    return result


def section_bounds(body, name, version):
    matches = [item for item in SECTION_FRAMES if item[4] == name and
               item[6] == version]
    require(len(matches) == 1, f"missing pinned {name} section")
    header_site, footer_site, _, identifier, _, _, _ = matches[0]
    require(body[header_site - 4:header_site + 1] ==
            b"\x04" + identifier.to_bytes(4, "big") and
            body[footer_site - 4:footer_site + 1] ==
            b"\x7e" + identifier.to_bytes(4, "big"),
            f"{name} section header/footer differs")
    return header_site - 4, footer_site - 4, identifier


def verify_section_frames(reference, projected):
    """Authenticate actual registered frame sites before changing any ID."""
    require(len(reference) == len(projected), "legacy migration body size differs")
    require(len(SECTION_FRAMES) * 2 == 66, "pinned section roster differs")
    for head, foot, marker, identifier, name, instance, version in SECTION_FRAMES:
        require(head + 1 <= foot - 4, "invalid pinned section span")
        for body, delta in ((reference, 0), (projected, 1)):
            actual_id = (identifier + delta).to_bytes(4, "big")
            require(body[head - 4:head + 1] == bytes([marker]) + actual_id and
                    body[foot - 4:foot + 1] == b"\x7e" + actual_id,
                    "registered section header/footer identity differs")
            if name is not None:
                encoded = name.encode()
                header = (bytes([len(encoded)]) + encoded +
                          instance.to_bytes(4, "big") + version.to_bytes(4, "big"))
                require(body[head + 1:head + 1 + len(header)] == header,
                        f"{name} registered section header differs")

    # The final EOF byte and all bytes outside the sites below are compared
    # later, so an extra apparent section cannot be silently discarded.
    require(reference[-1:] == projected[-1:] == b"\x00",
            "migration EOF marker differs")


def subsection_schemas(descriptor):
    pm = device(descriptor, "0000:00:1f.0/ICH9LPC")["fields"][2]["struct"]
    serial = device(descriptor, "serial")["fields"][0]["struct"]
    keyboard = device(descriptor, "pckbd")["fields"][0]["struct"]
    result = {}
    for name in VERSIONS:
        if name == "0000:00:1f.0/ICH9LPC":
            sections = pm["subsections"][-4:]
        elif name == "serial":
            sections = serial["subsections"]
        elif name == "pckbd":
            sections = keyboard["subsections"][-1:]
        else:
            sections = device(descriptor, name)["subsections"]
        result.update((entry["vmsd_name"], entry) for entry in sections)
    return result


def verify_frames(reference, patched, descriptor):
    schemas = subsection_schemas(descriptor)
    require(set(schemas) >= {item[1] for item in WIDE},
            "wide timer schemas missing")
    frames = []
    values = {}
    for owner, name, version, size, _ in WIDE:
        prefix = b"\x05" + bytes([len(name)]) + name.encode()
        require(reference.count(prefix) == 0 and patched.count(prefix) == 1,
                f"missing, duplicate, or pre-existing {name} frame")
        offset = patched.index(prefix)
        header_size = len(prefix) + 4
        require(patched[offset + len(prefix):offset + header_size] ==
                version.to_bytes(4, "big"), f"{name} frame version differs")
        payload = patched[offset + header_size:offset + header_size + size]
        require(len(payload) == size, f"truncated {name} frame")
        values[name] = decode_fields(schemas[name]["fields"], payload)
        frames.append((offset, patched[offset:offset + header_size + size]))
    require(frames == sorted(frames), "wide timer frame order differs")
    require(sum(len(frame) for _, frame in frames) == 1027 and
            all(left + len(frame) <= right for (left, frame), (right, _) in
                zip(frames, frames[1:])), "wide timer frame inventory differs")
    removed = 0
    for (offset, frame), insertion, (owner, _, _, _, _) in zip(
            frames, INSERTION_POINTS, WIDE):
        projected_offset = offset - removed
        owner_start, owner_end, _ = section_bounds(reference, owner, VERSIONS[owner])
        require(projected_offset == insertion and
                owner_start < insertion <= owner_end,
                "wide timer frame is outside its pinned owner position")
        removed += len(frame)
    projected = patched
    for offset, frame in reversed(frames):
        projected = projected[:offset] + projected[offset + len(frame):]
    verify_section_frames(reference, projected)
    return projected, values, frames


def verify_values(values):
    for name, fields in values.items():
        for key, value in fields.items():
            if key in ("wide_clock_mode", "wide_mode", "clock_mode_save",
                       "timing_wide_mode", "throttle_timer_wide_mode"):
                require(value == 1, f"{name} is not in precise clock mode")
            if key.endswith(("_active", "_present", "_pending")) and isinstance(value, int):
                require(value in (0, 1), f"{name} has invalid timer flag")
        for prefix, bound in (("wide_", 3), ("timing_wide_", 2)):
            present = fields.get(prefix + "present_mask")
            pending = fields.get(prefix + "pending_mask")
            if present is not None:
                require(present < 1 << bound, f"{name} presence mask differs")
            if pending is not None:
                require(pending < 1 << bound and pending & ~present == 0,
                        f"{name} pending mask differs")
    pit = values["i8254/timer-wide"]
    require(pit["wide_transition_mask"] < 8 and
            pit["wide_pending_mask"] & ~pit["wide_transition_mask"] == 0,
            "PIT transition mask differs")
    require(all(pit[key] == 0 for key in pit if key.startswith("channels[0].crucible")),
            "sim-off PIT unexpectedly owns a Crucible timer")

    # These are the physical coordinates of the pinned paused machine, not
    # disposable padding. Reject a malformed 128-bit value even if deleting
    # its frame would otherwise leave the stock stream unchanged.
    for name in ("apic/timer-wide", "ich9_pm/tco-timer-wide",
                 "ich9_pm/swsmi-timer-wide", "ich9_pm/periodic-timer-wide",
                 "pckbd/timer-wide"):
        fields = values[name]
        require(all(value in (0, 1) for value in fields.values()) and
                sum(value == 1 for value in fields.values()) == 1,
                f"{name} has unexpected inactive timer coordinate")
    pm = values["ich9_pm/timer-wide"]["acpi_regs.tmr"]
    require(pm["wide_clock_mode"] == 1 and
            all(value == 0 for key, value in pm.items() if key != "wide_clock_mode"),
            "ICH9 PM inactive wide timer coordinate differs")
    hpet = values["hpet/clock-wide"]
    require(hpet["offset_hi_save"] == hpet["offset_lo_save"] == 0 and
            all(all(value == 0 for value in timer.values()) for timer in hpet["timer"]),
            "HPET inactive signed wide coordinates differ")

    rtc = values["mc146818rtc/timer-wide"]
    require(rtc["wide_present_mask"] == 3 and rtc["wide_pending_mask"] == 2 and
            rtc["wide_hi"] == [0] * 6 and
            rtc["wide_lo"] == [0, 0, 86400000000000000, 0, 1000000000000, 0] and
            rtc["crucible_epoch_ns"] == 1767225600000000000 and
            all(value == 0 for key, value in rtc.items()
                if key.startswith("crucible_") and key != "crucible_epoch_ns"),
            "RTC signed 128-bit coordinates or inert owner fields differ")
    serial = values["serial/timing-wide"]
    require(serial["timing_wide_present_mask"] == 3 and
            serial["timing_wide_pending_mask"] == 0 and
            serial["char_transmit_time_vmstate"] == 1041660 and
            serial["timing_wide_hi"] == serial["timing_wide_lo"] == [0, 0],
            "serial signed wide coordinates differ")
    require(pit["wide_time_hi"] == [0] * 9 and
            all(pit["wide_time_lo"][index] == 0 for index in (0, 1, 2, 4, 5, 7, 8)),
            "PIT signed 128-bit inactive coordinates differ")


def verify_projection(reference, projected, wide):
    normalized = bytearray(projected)
    for head, foot, _, _, _, _, _ in SECTION_FRAMES:
        normalized[head - 3:head + 1] = reference[head - 3:head + 1]
        normalized[foot - 3:foot + 1] = reference[foot - 3:foot + 1]

    pit_start, _, _ = section_bounds(reference, "i8254", 3)
    pit_payload = pit_start + 19
    next_ps = wide["wide_time_hi"][3] * (1 << 64) + wide["wide_time_lo"][3]
    floor_ns, phase_ps = divmod(next_ps, 1000)
    require(phase_ps != 0 and
            wide["wide_present_mask"] == wide["wide_pending_mask"] ==
            wide["wide_transition_mask"] == 1 and
            wide["wide_time_hi"][6] == wide["wide_time_hi"][3] and
            wide["wide_time_lo"][6] == wide["wide_time_lo"][3],
            "paused PIT fractional coordinate or masks differ")
    # pre_save rounds the live transition up and writes -1 for inactive ones.
    for displacement, old, new in ((28, floor_ns, floor_ns + 1),
                                   (60, 0, -1), (92, 0, -1),
                                   (100, floor_ns, floor_ns + 1)):
        offset = pit_payload + displacement
        require(struct.unpack_from(">q", reference, offset)[0] == old and
                struct.unpack_from(">q", normalized, offset)[0] == new,
                "PIT nanosecond shadow differs from signed wide coordinate")
        normalized[offset:offset + 8] = reference[offset:offset + 8]
    require(bytes(normalized) == reference,
            "migration differs outside authenticated timer projection")
    return phase_ps, len(SECTION_FRAMES) * 2


def compare(reference_data, patched_data):
    reference_body, reference_json, reference_desc = split_stream(reference_data)
    patched_body, patched_json, patched_desc = split_stream(patched_data)
    verify_descriptor(reference_json, reference_desc, patched_json, patched_desc)
    projected, values, frames = verify_frames(reference_body, patched_body, patched_desc)
    verify_values(values)
    phase, shifted = verify_projection(reference_body, projected, values["i8254/timer-wide"])
    return {
        "reference_sha256": hashlib.sha256(reference_data).hexdigest(),
        "patched_sha256": hashlib.sha256(patched_data).hexdigest(),
        "legacy_body_sha256": hashlib.sha256(reference_body).hexdigest(),
        "timer_subsection_count": len(frames),
        "timer_frame_bytes": sum(len(frame) for _, frame in frames),
        "pit_fractional_phase_ps": phase,
        "section_id_changes": shifted,
    }


def verify_pair(reference_a, reference_b, patched_a, patched_b):
    require(reference_a == reference_b, "reference A/B migration streams differ")
    require(patched_a == patched_b, "patched A/B migration streams differ")
    return compare(reference_a, patched_a)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("reference_a", "reference_b", "patched_a", "patched_b"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    try:
        result = verify_pair(*(getattr(args, name).read_bytes() for name in
                               ("reference_a", "reference_b", "patched_a", "patched_b")))
    except MigrationMismatch as error:
        parser.exit(1, f"FAIL: {error}\n")
    for key, value in result.items():
        print(f"migration_{key}={value}")
    print("migration_legacy_projection_identical=true")
    print("migration_wide_timer_subsections_authenticated=true")
    print("migration_same_binary_repeats_identical=true")


if __name__ == "__main__":
    main()
