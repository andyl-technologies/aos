# SPDX-License-Identifier: MIT
"""Audits a parked native process and its uncompressed DMTCP image.

This helper returns evidence, not an admission capability. Its caller must bind
the kernel peer, native stop, installed helper, immutable launch configuration,
and capture request before constructing a private qualification certificate.
Native addresses remain private capture-format coordinates.
"""

import hashlib
import json
import os
import platform
import re
import stat
import struct
import sys


PAGE = 4096
MAX_AREAS = 65536
MAX_REQUEST = 4 * 1024 * 1024
MAX_IMAGE = 64 * 1024 * 1024 * 1024
SIGNATURE = b"DMTCP_CHECKPOINT_IMAGE_v4.0\n"
DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
MAP_LINE = re.compile(
    r"([0-9a-f]+)-([0-9a-f]+) ([r-][w-][x-][ps]) ([0-9a-f]+) "
    r"([0-9a-f]+):([0-9a-f]+) ([0-9]+)\s*(.*)\Z"
)


def integer(value, ceiling=1 << 64):
    """Decodes an unambiguous bounded protocol integer."""
    if not isinstance(value, str) or DECIMAL.fullmatch(value) is None:
        raise ValueError("integer is not canonical decimal text")
    number = int(value)
    if number >= ceiling:
        raise ValueError("integer exceeds its ceiling")
    return number


def digest_file(path):
    """Hashes a stable regular file without following a final symlink."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("capture asset is not a regular file")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
        ):
            raise ValueError("capture asset changed during inspection")
        return digest.hexdigest(), before.st_size
    finally:
        os.close(descriptor)


def _cstring(raw):
    if b"\0" not in raw:
        raise ValueError("native checkpoint name is not terminated")
    return raw.split(b"\0", 1)[0].decode("utf-8", "strict")


def parse_image(path):
    """Validates the pinned native64 little-endian DMTCP 4.2 area stream."""
    if platform.machine() != "x86_64" or sys.byteorder != "little":
        raise ValueError("unqualified DMTCP image ABI")
    image_size = os.stat(path, follow_symlinks=False).st_size
    if image_size > MAX_IMAGE:
        raise ValueError("checkpoint image exceeds its ceiling")

    mappings = []
    spans = []
    with open(path, "rb") as image:
        first, second = image.read(PAGE), image.read(PAGE)
        if len(first) != PAGE or first != second or not first.startswith(SIGNATURE):
            raise ValueError("checkpoint duplicate headers differ or are unsupported")
        if struct.unpack_from("<I", first, 132)[0] != 1:
            raise ValueError("checkpoint is not an ELF64 process image")

        # These offsets are part of the pinned DmtcpCkptHeader native ABI.
        exclusions = {
            key: struct.unpack_from("<QQ", first, offset)
            for key, offset in (("restore_buffer", 168), ("vdso", 184),
                                ("vvar", 200), ("vvar_vclock", 216))
        }
        parent = None
        cursor = None
        for ordinal in range(MAX_AREAS):
            raw = image.read(PAGE)
            if len(raw) != PAGE:
                raise ValueError("checkpoint area header is truncated")
            values = struct.unpack_from("<9QqQ", raw)
            start, end, extent, offset, protection, flags, major, minor, inode, file_bytes, properties = values
            protection &= 0xffffffff
            flags &= 0xffffffff
            if extent == (1 << 64) - 1:
                if start != 0 or image.tell() != image_size:
                    raise ValueError("checkpoint sentinel or final extent is invalid")
                if parent is not None and cursor != parent["end"]:
                    raise ValueError("anonymous child runs do not cover their parent")
                break
            if extent == 0 or end - start != extent or end >= 1 << 64:
                raise ValueError("checkpoint mapped extent is invalid")
            if start % PAGE or extent % PAGE or protection > 7 or properties & ~7:
                raise ValueError("checkpoint area flags or alignment are unsupported")
            name = _cstring(raw[88:1112])
            area = {"ordinal": ordinal, "start": start, "end": end,
                    "size": extent, "offset": offset, "protection": protection,
                    "flags": flags, "name": name, "device": [major, minor],
                    "inode": inode, "properties": properties}
            if properties & 4:
                if parent is None or start != cursor or end > parent["end"]:
                    raise ValueError("anonymous child runs are missing, reordered, or overlapping")
                if protection != parent["protection"] or flags != parent["flags"]:
                    raise ValueError("anonymous child protections differ from their parent")
                cursor = end
            else:
                if parent is not None and cursor != parent["end"]:
                    raise ValueError("anonymous parent is incompletely captured")
                if mappings and start < mappings[-1]["end"]:
                    raise ValueError("checkpoint mappings overlap or are reordered")
                mappings.append(area)
                parent = area if properties & 2 else None
                cursor = start if parent else None

            data_bytes = 0 if properties & 3 else (file_bytes if file_bytes > 0 else extent)
            if data_bytes > extent or image.tell() + data_bytes > image_size:
                raise ValueError("checkpoint payload is truncated or exceeds its mapping")
            if not properties & 2:
                spans.append({"start": start, "end": end,
                              "image_offset": image.tell(), "data_bytes": data_bytes,
                              "zero": bool(properties & 1)})
            image.seek(data_bytes, os.SEEK_CUR)
        else:
            raise ValueError("checkpoint contains too many area records")

    return {"mappings": mappings, "spans": spans, "exclusions": exclusions,
            "image_bytes": image_size, "source_executable": _cstring(first[1280:2304])}


def captured_bytes(path, spans, start, extent):
    """Reads a bounded virtual interval from captured payloads or zero runs."""
    if extent > 65536:
        raise ValueError("native context interval exceeds its ceiling")
    end, cursor, pieces = start + extent, start, []
    with open(path, "rb") as image:
        for span in spans:
            if span["end"] <= cursor:
                continue
            if span["start"] > cursor:
                break
            stop = min(end, span["end"])
            size = stop - cursor
            if span["zero"]:
                pieces.append(bytes(size))
            else:
                displacement = cursor - span["start"]
                if displacement + size > span["data_bytes"]:
                    raise ValueError("native context crosses uncaptured file padding")
                image.seek(span["image_offset"] + displacement)
                pieces.append(image.read(size))
            cursor = stop
            if cursor == end:
                return b"".join(pieces)
    raise ValueError("native context is absent from captured mapped bytes")


def process_start(pid):
    """Reads the kernel identity despite spaces or parentheses in comm."""
    text = open(f"/proc/{pid}/stat", encoding="ascii").read()
    return text[text.rfind(")") + 2:].split()[19]


def kernel_maps(pid):
    """Reads every mapped region from the authenticated parked kernel peer."""
    result = []
    with open(f"/proc/{pid}/maps", encoding="utf-8") as source:
        for line in source:
            match = MAP_LINE.fullmatch(line.rstrip("\n"))
            if match is None or len(result) >= MAX_AREAS:
                raise ValueError("unsupported or unbounded kernel map inventory")
            start, end, permissions, offset, major, minor, inode, name = match.groups()
            result.append({"start": int(start, 16), "end": int(end, 16),
                           "permissions": permissions, "offset": int(offset, 16),
                           "device": [int(major, 16), int(minor, 16)],
                           "inode": int(inode), "name": name})
    return result


def _inside(path, root):
    return path == root or path.startswith(root + os.sep)


def saved_kernel_maps(image_path, spans, records):
    """Decodes the actual writer's captured original kernel-map snapshot."""
    if not records or len(records) > 8192:
        raise ValueError("captured kernel-map ledger is missing or unbounded")
    result = []
    for record in records:
        payload = bytes.fromhex(record["bytes_hex"])
        if len(payload) != 1112:
            raise ValueError("captured kernel-map prefix ABI differs")
        actual = captured_bytes(image_path, spans, integer(record["address"]), len(payload))
        if actual != payload:
            raise ValueError("native kernel-map record body differs from image")
        mapping = decode_kernel_map(payload)
        if result and mapping["start"] < result[-1]["end"]:
            raise ValueError("captured kernel maps overlap or are reordered")
        result.append(mapping)
    return result



def decode_kernel_map(payload):
    """Decodes meaningful Area fields without reading native union padding."""
    if len(payload) != 1112:
        raise ValueError("native map record ABI differs")
    start, end, extent, offset, protection, flags, major, minor, inode, file_bytes, properties = struct.unpack_from("<9QqQ", payload)
    protection &= 0xffffffff
    flags &= 0xffffffff
    if end <= start or end - start != extent or start % PAGE or extent % PAGE:
        raise ValueError("captured kernel-map extent is invalid")
    if protection > 7 or (flags & 3) not in (1, 2) or properties != 0:
        raise ValueError("captured kernel-map flags are unsupported")
    permissions = "".join(char if protection & bit else "-"
                          for char, bit in (("r", 1), ("w", 2), ("x", 4)))
    permissions += "s" if flags & 1 else "p"
    return {"start": start, "end": end, "permissions": permissions,
            "offset": offset, "device": [major, minor], "inode": inode,
            "name": _cstring(payload[88:1112]),
            "record_sha256": hashlib.sha256(payload).hexdigest()}


def verify_file_map_receipts(image_path, spans, records, original_maps,
                             supplementary_root, guest_executable, assets, root):
    """Authenticates DMTCP's exact shared-file to placeholder transformation.

    The actual native FileConnection binds its original map and saved copy in
    captured bytes. Only the measured private read-only guest ELF is admitted;
    the ordinary anonymous allocator classification never permits this change.
    """
    if len(records) > 1024:
        raise ValueError("native file mapping ledger exceeds its ceiling")
    result, seen = [], set()
    original_by_interval = {(item["start"], item["end"]): item for item in original_maps}
    for record in records:
        payload = bytes.fromhex(record["bytes_hex"])
        if len(payload) != 5224:
            raise ValueError("native file mapping receipt ABI differs")
        if captured_bytes(image_path, spans, integer(record["address"]), len(payload)) != payload:
            raise ValueError("native file mapping receipt differs from captured bytes")
        mapping = decode_kernel_map(payload[:1112])
        saved_path = _cstring(payload[1112:5208])
        checkpointed, transient_fd = struct.unpack_from("<QQ", payload, 5208)
        if transient_fd >= 1 << 20:
            raise ValueError("native transient mapping descriptor is unbounded")
        interval = mapping["start"], mapping["end"]
        if interval in seen:
            raise ValueError("duplicate native file mapping transformation")
        seen.add(interval)
        placeholder = original_by_interval.get(interval)
        if (placeholder is None or placeholder["permissions"] != "---p"
                or placeholder["name"] or placeholder["offset"]
                or placeholder["inode"] or placeholder["device"] != [0, 0]):
            raise ValueError("native transformed file placeholder differs")
        name = mapping["name"]
        if (mapping["permissions"] != "r--s" or name != guest_executable
                or name not in assets or not _inside(name, root)
                or checkpointed != 1):
            raise ValueError("native transformed file mapping is not the owned guest ELF")
        if not os.path.isabs(saved_path) or os.path.realpath(saved_path) != saved_path:
            raise ValueError("native saved file path is not canonical")
        if not _inside(saved_path, supplementary_root):
            raise ValueError("native saved file escapes supplementary custody")
        metadata = os.stat(name, follow_symlinks=False)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or mapping["device"] != [os.major(metadata.st_dev), os.minor(metadata.st_dev)]
                or mapping["inode"] != metadata.st_ino):
            raise ValueError("native original guest map inode custody differs")
        saved_metadata = os.stat(saved_path, follow_symlinks=False)
        if not stat.S_ISREG(saved_metadata.st_mode) or saved_metadata.st_nlink != 1:
            raise ValueError("native saved guest copy lacks private file custody")
        saved_digest, saved_size = digest_file(saved_path)
        if {"sha256": saved_digest, "bytes": str(saved_size)} != assets[name]:
            raise ValueError("native saved guest ELF copy differs from measured asset")
        if mapping["offset"] >= saved_size or interval[1] - interval[0] > 65536:
            raise ValueError("native mapped guest ELF extent is unsupported")
        result.append({"original_map": mapping, "saved_relative_path": os.path.relpath(saved_path, supplementary_root),
                       "saved_sha256": saved_digest, "saved_bytes": str(saved_size),
                       "transient_fd": str(transient_fd),
                       "receipt_sha256": hashlib.sha256(payload).hexdigest()})
    return result

def verify_retained_maps(original, current):
    """Audits original external custody separately from later allocator changes.

    The image and authenticated original ledger own the captured private bytes.
    A parked controller can free its Python serialization arenas after capture;
    those later allocator changes are never used as evidence of original bytes.
    """
    extras = []
    for old in original:
        allocator_region = (old["name"] in ("", "[heap]")
                            and old["permissions"] in ("rw-p", "---p"))
        if allocator_region:
            intersections = [item for item in current
                             if item["start"] < old["end"] and old["start"] < item["end"]]
            cursor = old["start"]
            for live in intersections:
                if live["name"] not in ("", "[heap]") or live["permissions"] != old["permissions"]:
                    raise ValueError("original private allocator custody became external")
                if cursor < live["start"]:
                    extras.append({**old, "start": cursor, "end": live["start"],
                                   "coverage": "operational-owner-release-after-capture"})
                cursor = max(cursor, min(old["end"], live["end"]))
            if cursor < old["end"]:
                extras.append({**old, "start": cursor,
                               "coverage": "operational-owner-release-after-capture"})
            continue
        candidates = [item for item in current
                      if item["start"] <= old["start"] and old["end"] <= item["end"]]
        if len(candidates) != 1:
            raise ValueError("original capture mapping is not retained by parked owner")
        live = candidates[0]
        if (old["permissions"], old["name"], old["device"], old["inode"]) != (
            live["permissions"], live["name"], live["device"], live["inode"]
        ):
            raise ValueError("original capture mapping custody or permissions changed")
        if old["name"].startswith("/") and old["offset"] != live["offset"] + old["start"] - live["start"]:
            raise ValueError("original immutable mapped file offset changed")

    for live in current:
        cursor = live["start"]
        intersections = [item for item in original
                         if item["start"] < live["end"] and live["start"] < item["end"]]
        for old in intersections:
            if cursor < old["start"]:
                extras.append({**live, "start": cursor, "end": old["start"]})
            cursor = max(cursor, old["end"])
        if cursor < live["end"]:
            extras.append({**live, "start": cursor})
    for extra in extras:
        if extra.get("coverage") == "operational-owner-release-after-capture":
            continue
        if extra["permissions"] != "rw-p" or extra["name"] not in ("", "[heap]"):
            raise ValueError("postcapture owner created an unsupported resource mapping")
        extra["coverage"] = "operational-owner-allocation-after-capture"
    return extras


def owned_tree(root):
    """Accounts for every supplementary file without shared inode custody."""
    entries = []
    if not os.path.isdir(root) or os.path.islink(root):
        raise ValueError("supplementary checkpoint file directory is missing")
    for directory, subdirectories, filenames in os.walk(root, followlinks=False):
        if len(entries) > MAX_AREAS:
            raise ValueError("supplementary checkpoint tree exceeds its ceiling")
        for name in sorted(subdirectories + filenames):
            path = os.path.join(directory, name)
            metadata = os.lstat(path)
            relative = os.path.relpath(path, root)
            if stat.S_ISDIR(metadata.st_mode):
                entries.append({"path": relative, "type": "directory"})
            elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                digest, size = digest_file(path)
                entries.append({"path": relative, "type": "regular",
                                "sha256": digest, "bytes": str(size)})
            else:
                raise ValueError("supplementary file has shared, symbolic, or device custody")
    return sorted(entries, key=lambda entry: entry["path"])


def audit(request):
    """Collects closure evidence and rejects every unaccounted resource."""
    if request.get("schema") != "crucible.gem5.process-closure-request.v1":
        raise ValueError("unsupported process closure request")
    pid = integer(request["pid"], 1 << 31)
    expected_start = request["start_ticks"]
    if process_start(pid) != expected_start:
        raise ValueError("native process identity changed")
    root = os.path.realpath(request["owned_root"])
    image_path = os.path.realpath(request["image"])
    if not _inside(image_path, root):
        raise ValueError("checkpoint image escapes the owned capture root")
    image_digest, image_size = digest_file(image_path)
    image = parse_image(image_path)
    if image_size != image["image_bytes"]:
        raise ValueError("checkpoint image changed during parse")
    supplementary_root = image_path.removesuffix(".dmtcp") + "_files"
    supplementary = owned_tree(supplementary_root)
    assets = {}
    for asset in request["assets"]:
        path, expected = asset["path"], asset["sha256"]
        if DIGEST.fullmatch(expected) is None:
            raise ValueError("asset digest is not canonical")
        observed, size = digest_file(path)
        if observed != expected:
            raise ValueError("immutable launch asset digest differs")
        assets[os.path.realpath(path)] = {"sha256": observed, "bytes": str(size)}
    guest_executable = os.path.realpath(request.get("guest_executable", ""))

    omissions, current_maps, mutable = [], kernel_maps(pid), []
    captured_maps = request.get("captured_maps", [])
    if captured_maps:
        maps = saved_kernel_maps(image_path, image["spans"], captured_maps)
        file_map_receipts = verify_file_map_receipts(
            image_path, image["spans"], request.get("captured_file_maps", []), maps,
            supplementary_root, guest_executable, assets, root)
        transformed = {(item["original_map"]["start"], item["original_map"]["end"]): item
                       for item in file_map_receipts}
        retained = [transformed.get((item["start"], item["end"]), {}).get("original_map", item)
                    for item in maps]
        postcapture_maps = verify_retained_maps(retained, current_maps)
    else:
        omissions.append("native-captured-kernel-map-ledger")
        maps, postcapture_maps, file_map_receipts, transformed = current_maps, [], [], {}
    coverage = {(item["start"], item["end"]): item for item in image["mappings"]}
    operational_shared = request.get("operational_shared_maps", [])
    shared_regions = {(integer(item["start"]), integer(item["end"])) for item in operational_shared}
    for mapping in maps:
        interval = mapping["start"], mapping["end"]
        name = mapping["name"]
        excluded = next((key for key, region in image["exclusions"].items()
                         if interval == region and region[0] != region[1]), None)
        if name == "[vsyscall]" and interval == (0xffffffffff600000, 0xffffffffff601000):
            excluded = "kernel_vsyscall"
        if interval in shared_regions:
            excluded = "dmtcp_operational_shared_data"
        mapping["coverage"] = excluded or "captured"
        if excluded:
            continue
        saved = coverage.get(interval)
        if saved is None:
            raise ValueError(f"mapped interval is absent from image: {name}")
        expected_protection = sum(bit for char, bit in zip(mapping["permissions"][:3], (1, 2, 4)) if char != "-")
        if saved["protection"] != expected_protection:
            raise ValueError("saved mapping protections differ")
        if mapping["permissions"][3] != "p":
            # gem5 maps its measured ELF read-only/shared. This is a closed
            # immutable input only when its private file and all mapped bytes
            # are independently bound; mutable shared model RAM stays refused.
            if (mapping["permissions"] != "r--s" or name != guest_executable
                    or name not in assets or not _inside(name, root)):
                raise ValueError(f"external shared memory is not admitted: {name} "
                                 f"[{mapping['start']:x},{mapping['end']:x})")
            metadata = os.stat(name, follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("read-only shared guest image has non-private custody")
            data_size = min(metadata.st_size - mapping["offset"], interval[1] - interval[0])
            if data_size <= 0 or data_size > 65536:
                raise ValueError("read-only shared guest image extent is unsupported")
            with open(name, "rb") as executable:
                executable.seek(mapping["offset"])
                original = executable.read(data_size)
            if captured_bytes(image_path, image["spans"], interval[0], data_size) != original:
                raise ValueError("read-only shared guest image differs from captured bytes")
            mapping["coverage"] = "captured-owned-readonly-guest-image"
        if name.startswith("/"):
            if " (deleted)" in name:
                raise ValueError("deleted external mapped file is not admitted")
            if not _inside(name, root) and not name.startswith("/nix/store/"):
                raise ValueError("mapped file is neither privately owned nor immutable")
            if name not in assets:
                observed, size = digest_file(name)
                assets[name] = {"sha256": observed, "bytes": str(size)}
        if interval in transformed:
            mapping["coverage"] = "captured-native-file-connection-and-owned-guest-copy"
            mapping["file_mapping_receipt"] = transformed[interval]
        if "w" in mapping["permissions"]:
            mutable.append(interval)

    native = request["native_inventory"]
    if native.get("schema") != "crucible.gem5.native-process-inventory.v1":
        raise ValueError("native resource ledger schema differs")
    native_fds = {integer(item["fd"], 1 << 20): item for item in native["descriptors"]}
    descriptor_dir = f"/proc/{pid}/fd"
    observed_fds = sorted(int(name) for name in os.listdir(descriptor_dir))
    if observed_fds != sorted(native_fds):
        raise ValueError("native and kernel descriptor rosters differ")
    descriptors = []
    control_fd = integer(native["control_fd"], 1 << 20)
    for fd in observed_fds:
        target = os.readlink(f"{descriptor_dir}/{fd}")
        item = native_fds[fd]
        if target != item["target"]:
            raise ValueError("native and kernel descriptor identities differ")
        info = open(f"/proc/{pid}/fdinfo/{fd}", encoding="ascii").read()
        record = {"fd": str(fd), "target": target, "fdinfo": info}
        if fd == control_fd:
            if not target.startswith("socket:["):
                raise ValueError("fresh operational control is not a socket")
            record["custody"] = "fresh-postcapture-controller"
        elif item.get("dmtcp_protected") is True:
            record["custody"] = "dmtcp-operational-protected"
        elif target == "/dev/null":
            record["custody"] = "immutable-null-device"
        elif _inside(target, root):
            metadata = os.stat(f"{descriptor_dir}/{fd}")
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("owned descriptor is not a private singly linked regular file")
            record["custody"] = "owned-regular-file"
            record["sha256"], record["bytes"] = digest_file(target)
        else:
            raise ValueError("descriptor has no private or operational custody")
        descriptors.append(record)

    # A postcapture /proc census alone cannot prove which descriptors existed
    # in the image or their original offsets. The stopped native ledger must
    # bind those original identities, including closure of the controller.
    captured_descriptors = request.get("captured_descriptors", [])
    captured_fd_records = []
    captured_nonoperational = set()
    if not captured_descriptors:
        omissions.append("native-captured-descriptor-ledger")
    if len(captured_descriptors) > 1024:
        raise ValueError("native captured descriptor ledger exceeds its ceiling")
    seen_captured_fds = set()
    transient_file_fds = {integer(item["transient_fd"], 1 << 20): item for item in file_map_receipts}
    if len(transient_file_fds) != len(file_map_receipts):
        raise ValueError("native file mappings share an unsupported transient descriptor")
    retired_file_fds = set()
    for captured in captured_descriptors:
        payload = bytes.fromhex(captured["bytes_hex"])
        if len(payload) != 4160:
            raise ValueError("native captured descriptor ABI differs")
        actual = captured_bytes(image_path, image["spans"], integer(captured["address"]), len(payload))
        if actual != payload:
            raise ValueError("native captured descriptor body is absent or altered in image")
        fd, descriptor_flags, status_flags, mode, position, device, inode, size, links, protected, reserved = struct.unpack_from("<iIIIqQQQQII", payload)
        target = _cstring(payload[64:])
        if fd < 0 or fd in seen_captured_fds or reserved or protected not in (0, 1):
            raise ValueError("native captured descriptor identity is invalid")
        seen_captured_fds.add(fd)
        record = {"fd": str(fd), "target": target, "descriptor_flags": str(descriptor_flags),
                  "status_flags": str(status_flags), "mode": str(mode),
                  "position": str(position), "device": str(device), "inode": str(inode),
                  "bytes": str(size), "links": str(links), "protected": bool(protected),
                  "body_sha256": hashlib.sha256(payload).hexdigest()}
        if not protected and fd in transient_file_fds:
            receipt = transient_file_fds[fd]
            original = receipt["original_map"]
            if (target != original["name"] or not stat.S_ISREG(mode) or links != 1
                    or inode != original["inode"]
                    or [os.major(device), os.minor(device)] != original["device"]):
                raise ValueError("native transient mapping descriptor differs from FileConnection")
            current = native_fds.get(fd)
            if current is not None and fd != control_fd:
                raise ValueError("native temporary file mapping descriptor was not retired")
            retired_file_fds.add(fd)
            record["custody"] = "captured-file-connection-then-retired-before-control-rebind"
        elif not protected:
            captured_nonoperational.add(fd)
            current = native_fds.get(fd)
            if current is None or current["target"] != target or current["dmtcp_protected"]:
                raise ValueError("captured application descriptor custody changed")
            metadata = os.stat(f"{descriptor_dir}/{fd}")
            if (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink) != (device, inode, mode, links):
                raise ValueError("captured application descriptor kernel identity differs")
            if target != "/dev/null" and not _inside(target, root):
                raise ValueError("captured application descriptor is external")
            if target.startswith("socket:[") or not (stat.S_ISREG(mode) or target == "/dev/null"):
                raise ValueError("controller or external device was captured")
        captured_fd_records.append(record)
    if retired_file_fds != set(transient_file_fds):
        raise ValueError("native FileConnection descriptor is absent from captured roster")
    expected_captured_fds = {fd for fd, item in native_fds.items()
                             if fd != control_fd and item["dmtcp_protected"] is False}
    if captured_descriptors and captured_nonoperational != expected_captured_fds:
        raise ValueError("captured and live application descriptor rosters differ")

    tasks = sorted(int(name) for name in os.listdir(f"/proc/{pid}/task"))
    contexts = request.get("thread_contexts", [])
    if not contexts:
        omissions.append("native-suspended-register-context-ledger")
    else:
        captured_tasks = sorted(integer(item["real_tid"], 1 << 31) for item in contexts)
        if captured_tasks != tasks:
            raise ValueError("saved native and kernel task rosters differ")
        application_count = 0
        for context in contexts:
            if context["role"] == "application":
                if context["state"] != "suspended":
                    raise ValueError("application thread was not stopped for capture")
                application_count += 1
            elif context["role"] != "checkpoint-worker":
                raise ValueError("unknown native thread role")
            payload = bytes.fromhex(context["bytes_hex"])
            actual = captured_bytes(image_path, image["spans"], integer(context["address"]), len(payload))
            if actual != payload:
                raise ValueError("saved native register/TLS context bytes differ")
        if application_count != 1:
            raise ValueError("closed O3 profile requires exactly one application thread")
    if not operational_shared:
        omissions.append("authenticated-dmtcp-operational-shared-map-ledger")
    if request.get("profile") != "freestanding-o3-classic-ddr3-v1":
        raise ValueError("opaque capture profile is not qualified")
    if request.get("guest_isa") not in ("x86_64", "aarch64"):
        raise ValueError("guest ISA is not admitted")
    if process_start(pid) != expected_start or current_maps != kernel_maps(pid):
        raise ValueError("native maps changed during closure inspection")
    if digest_file(image_path)[0] != image_digest:
        raise ValueError("checkpoint image changed during closure inspection")
    if owned_tree(supplementary_root) != supplementary:
        raise ValueError("supplementary checkpoint files changed during inspection")

    return {"schema": "crucible.gem5.process-closure.v1", "complete": not omissions,
            "modeled_diagnostics_complete": False, "omissions": omissions,
            "pid": str(pid), "start_ticks": expected_start,
            "profile": request["profile"], "guest_isa": request["guest_isa"],
            "boundary_sha256": request["boundary_sha256"],
            "image_sha256": image_digest, "image_bytes": str(image_size),
            "mapped_regions": maps, "captured_region_count": str(len(image["mappings"])),
            "postcapture_operational_mappings": postcapture_maps,
            "mutable_region_count": str(len(mutable)), "tasks": [str(tid) for tid in tasks],
            "descriptors": descriptors, "assets": assets,
            "captured_descriptors": captured_fd_records,
            "captured_file_mappings": file_map_receipts,
            "supplementary_files": supplementary,
            "host_abi": {"machine": platform.machine(), "kernel_release": platform.release(),
                         "page_bytes": str(os.sysconf("SC_PAGE_SIZE")), "byte_order": sys.byteorder}}


def main():
    raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
    if len(raw) > MAX_REQUEST:
        raise ValueError("process closure request exceeds its ceiling")
    result = audit(json.loads(raw))
    sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        sys.stderr.write(f"process closure refused: {error}\n")
        sys.exit(1)
