# SPDX-License-Identifier: Apache-2.0
"""Compares complete stopped-capture bytes independently of RAM fingerprints.

The RAM input is the existing initial CRURCP01 checkpoint spool. Every byte in
its exact-scope inventory is read, including immutable and continuation regions.
Root digests and page versions are transport metadata, not the comparison key.
Non-RAM VMState and both complete Apache continuations compare byte-for-byte;
no representation change is normalized without a separate source proof.

Pinned files prove retained artifact identity, not original process ownership or
physical inventory completeness. The actual stopped producer must establish
those facts. This consumer never issues launch or performance qualification.
"""

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
import stat
import struct


PAGE_BYTES = 4096
MAX_ROOT_BYTES = 3 * 1024 * 1024
MAX_REGIONS = 4096
# The fixed admitted backing ceiling bounds streamed files, not an IO grant.
# Complete inventory may include device/immutable backing beyond main 512 MiB.
MAX_RAM_BYTES = 4 * 1024 * 1024 * 1024
MAX_STATE_BYTES = 512 * 1024 * 1024
STATE_ROLES = ("device", "host_io", "node")
NODE_MAGIC = b"crucible.qemu-node-continuation.v7\0"
HOST_MAGIC = b"crucible.qemu-host-io-checkpoint.v6\0"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, message, minimum=0):
    require(type(value) is int and minimum <= value <= 2**64 - 1, message)
    return value


def exact(stream, count):
    data = stream.read(count)
    require(len(data) == count, "truncated complete capture")
    return data


def bounded_digest(stream, maximum):
    """Hashes at most the admitted extent and one byte needed to detect growth."""
    hasher = hashlib.sha256()
    total = 0
    while True:
        chunk = stream.read(min(65536, maximum - total + 1))
        if not chunk:
            return hasher.hexdigest()
        total += len(chunk)
        require(total <= maximum, "capture grew beyond bounded hash extent")
        hasher.update(chunk)


@contextmanager
def pinned_file(artifact, maximum):
    require(set(artifact) == {"path", "sha256"}, "capture artifact fields")
    require(isinstance(artifact["sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"]), "capture artifact digest")
    path = Path(artifact["path"])
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,
                "capture must be a bounded nonempty regular file")
        yield stream, before.st_size
        stream.seek(0)
        observed_digest = bounded_digest(stream, before.st_size)
        after = os.fstat(stream.fileno())
        named = path.stat(follow_symlinks=False)
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns)
        require(identity(before) == identity(after) == identity(named),
                "capture changed or was replaced during comparison")
        require(observed_digest == artifact["sha256"], "capture artifact differs from pin")


class RootReader:
    """Reads only the existing bounded root-record format."""

    def __init__(self, data):
        self.data = data
        self.position = 0

    def take(self, count):
        require(count <= len(self.data) - self.position, "truncated root record")
        value = self.data[self.position:self.position + count]
        self.position += count
        return value

    def u32(self):
        return int.from_bytes(self.take(4), "big")

    def string(self, maximum):
        count = self.u32()
        require(0 < count <= maximum, "root identifier length")
        value = self.take(count)
        decoded = value.decode("utf-8")
        require(all(ord(char) > 31 and ord(char) != 127 for char in decoded),
                "root identifier control character")
        return value

    def region(self):
        name = self.string(255)
        region_class, mask = self.take(2)
        length = int.from_bytes(self.take(8), "big")
        require(region_class in (1, 2, 3, 4) and mask == (7 if region_class < 3 else 6)
                and 0 < length <= MAX_RAM_BYTES, "root region descriptor")
        return name, region_class, mask, length


def inventory(data):
    reader = RootReader(data)
    require(reader.take(8) == b"CRUCRR01" and reader.u32() == 1
            and reader.u32() == PAGE_BYTES and reader.string(9) == b"exact",
            "complete RAM requires exact-scope root edition1")
    count = reader.u32()
    require(0 < count <= MAX_REGIONS, "complete RAM region count")
    regions = [reader.region() for _ in range(count)]
    require(all(left[0] < right[0] for left, right in zip(regions, regions[1:])),
            "RAM inventory must be strictly ordered and unique")
    require(sum(region[3] for region in regions) <= MAX_RAM_BYTES, "complete RAM byte ceiling")
    require(reader.u32() == count, "exact root must select every region")
    for region in regions:
        require(reader.region() == region, "selected root inventory differs")
        reader.take(32)  # Production region digest is never the independent witness.
    require(reader.position == len(data), "trailing root-record bytes")
    return regions


def complete_ram(artifact, generation):
    # Fixed record overhead and root bounds are separate from logical RAM bytes.
    maximum = (
        MAX_RAM_BYTES
        + (MAX_RAM_BYTES // PAGE_BYTES + MAX_REGIONS) * 24
        + MAX_ROOT_BYTES
        + 72
    )
    with pinned_file(artifact, maximum) as (stream, _):
        header = exact(stream, 72)
        magic, edition, initial, observed, records, root_length, reserved = struct.unpack(
            ">8sIIQQII", header[:40])
        require(magic == b"CRURCP01" and edition == 1 and initial == 1
                and observed == generation and generation > 0 and reserved == 0
                and 0 < root_length <= MAX_ROOT_BYTES, "initial complete capture header")
        regions = inventory(exact(stream, root_length))
        expected_records = sum((length + PAGE_BYTES - 1) // PAGE_BYTES
                               for _, _, _, length in regions)
        require(records == expected_records, "capture omits complete RAM records")
        hasher = hashlib.sha256(b"crucible.independent-complete-ram-bytes.v1\0")
        total = 0
        for ordinal, (name, region_class, mask, length) in enumerate(regions):
            hasher.update(struct.pack(">I", len(name)) + name + bytes((region_class, mask))
                          + struct.pack(">Q", length))
            for page in range((length + PAGE_BYTES - 1) // PAGE_BYTES):
                region, valid, index, version = struct.unpack(">IIQQ", exact(stream, 24))
                expected = min(PAGE_BYTES, length - page * PAGE_BYTES)
                require((region, index, valid) == (ordinal, page, expected) and version > 0,
                        "complete page coverage/order/length/version")
                hasher.update(struct.pack(">QI", page, valid))
                hasher.update(exact(stream, valid))
                total += valid
        require(stream.read(1) == b"", "trailing complete RAM bytes")
    return {"sha256": hasher.hexdigest(), "logical_bytes": total,
            "regions": len(regions), "pages": records}


def complete_state_bytes(artifact, role):
    with pinned_file(artifact, MAX_STATE_BYTES) as (stream, length):
        prefix = exact(stream, min(length, len(HOST_MAGIC)))
        if role == "host_io":
            require(prefix.startswith(HOST_MAGIC), "host continuation edition")
        elif role == "node":
            require(prefix.startswith(NODE_MAGIC), "node continuation edition")
        else:
            require(prefix.startswith(b"QEVM\x00\x00\x00\x03"), "QEMU VMState edition")
        stream.seek(0)
        observed_digest = bounded_digest(stream, length)
    return {"sha256": observed_digest, "bytes": length}


def capture_witness(capture):
    require(set(capture) == {"boundary", "ram", *STATE_ROLES}, "complete capture roles")
    boundary = capture["boundary"]
    require(set(boundary) == {"seed", "node", "logical_icount", "capture_generation"},
            "stopped capture boundary fields")
    integer(boundary["seed"], "capture seed")
    integer(boundary["logical_icount"], "capture coordinate")
    integer(boundary["capture_generation"], "capture generation", 1)
    require(isinstance(boundary["node"], str) and 0 < len(boundary["node"].encode()) <= 255,
            "capture node")
    return {"coordinate": {key: boundary[key] for key in ("seed", "node", "logical_icount")},
            "ram": complete_ram(capture["ram"], boundary["capture_generation"]),
            **{role: complete_state_bytes(capture[role], role) for role in STATE_ROLES}}


def compare_pair(baseline, candidate):
    reference = capture_witness(baseline)
    observed = capture_witness(candidate)
    require(reference == observed, "complete captured RAM/state bytes or coordinate differ")
    return {"common_witness": reference, "complete_capture_bytes_equal": True,
            "normalization": "none: only operational RAM roots/page versions/generation excluded",
            "physical_origin_verified": False, "performance_qualified": False}


def legacy_direct_ram(artifact):
    """Reads master19d's real migratable RAM spool without calling it whole RAM."""
    maximum = MAX_RAM_BYTES + MAX_REGIONS * 300 + (MAX_RAM_BYTES // PAGE_BYTES) * 16 + 232
    with pinned_file(artifact, maximum) as (stream, _):
        header = exact(stream, 232)
        magic, edition, kind, page_size, count, records, declared_bytes = struct.unpack(
            "<8sIIIIQQ", header[:40])
        require(magic == b"CRUCRAM2" and edition == 2 and kind == 1
                and page_size == PAGE_BYTES and 0 < count <= 1024
                and header[136:] == bytes(96), "master direct RAM header")
        regions = []
        for _ in range(count):
            length, maximum_length, backing_page_size, name_length = struct.unpack(
                "<QQQI", exact(stream, 28))
            require(0 < name_length <= 255 and 0 < length <= MAX_RAM_BYTES
                    and length % PAGE_BYTES == 0 and maximum_length >= length
                    and backing_page_size > 0 and backing_page_size % PAGE_BYTES == 0,
                    "master RAMBlock geometry")
            name = exact(stream, name_length)
            decoded = name.decode("utf-8")
            require(all(ord(char) > 31 and ord(char) != 127 for char in decoded),
                    "master RAMBlock identifier")
            regions.append((name, length))
        require(all(left[0] < right[0] for left, right in zip(regions, regions[1:])),
                "master RAMBlock order")
        total = sum(length for _, length in regions)
        require(total == declared_bytes and total <= MAX_RAM_BYTES, "master complete mutable extent")
        hasher = hashlib.sha256(b"crucible.independent-migratable-ram-bytes.v1\0")
        observed_records = 0
        for ordinal, (name, length) in enumerate(regions):
            hasher.update(struct.pack(">I", len(name)) + name + struct.pack(">Q", length))
            offset = 0
            while offset < length:
                region, valid, observed_offset = struct.unpack("<IIQ", exact(stream, 16))
                require(region == ordinal and observed_offset == offset
                        and valid == min(length - offset, 4 * 1024 * 1024),
                        "master direct RAM record coverage")
                # The producer uses up to 4 MiB records; the reader retains 4 KiB.
                remaining = valid
                while remaining:
                    size = min(remaining, PAGE_BYTES)
                    hasher.update(exact(stream, size))
                    remaining -= size
                offset += valid
                observed_records += 1
        require(observed_records == records and stream.read(1) == b"", "master RAM count/EOF")
    return {"sha256": hasher.hexdigest(), "logical_bytes": total, "regions": count,
            "coverage": "migratable RAMBlocks only; not a complete guest RAM witness",
            "complete_guest_ram": False}
