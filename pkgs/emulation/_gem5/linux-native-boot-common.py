# SPDX-License-Identifier: MIT
"""Validates bounded Linux UART observations without granting node authority.

The original FIFO, birth, ACK-before-progress and transcript predicates are
retained from the accepted x86 diagnostic. The caller binds its terminal owner.
"""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys



MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_TRANSCRIPT_BYTES = 256 * 1024
MAX_EVENTS = 500_000_000
EVENT_BATCH = 128
TICKS_PER_SECOND = 1_000_000_000_000
REQUIRED_LINES = (b"GEM5_LINUX_INIT_READY", b"GEM5_LINUX_PROBE_COMPLETE")
FAILURE_TEXT = (b"GEM5_DEVICE_FAILURE", b"GEM5_LINUX_PROBE_FAILED", b"Kernel panic")


def horizon_tick(seconds, permitted_cases):
    """Selects one finite diagnostic case at the fixed native 1 THz clock."""
    if type(seconds) is not str or seconds not in permitted_cases:
        raise ValueError("native boot horizon must select a declared finite case")
    return int(seconds) * TICKS_PER_SECOND


def load(name, source):
    """Loads one fixed installed helper without replacing a prior module."""
    if name in sys.modules:
        raise ValueError("native boot helper name was already loaded")
    specification = importlib.util.spec_from_file_location(name, source)
    if specification is None or specification.loader is None:
        raise ValueError("installed native boot helper is not loadable")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


def read_document(path):
    """Bounds the source-installed or prepared data document before parsing."""
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_DOCUMENT_BYTES + 1)
    if len(data) > MAX_DOCUMENT_BYTES:
        raise ValueError("native boot document exceeds its finite extent")
    document = json.loads(data)
    if type(document) is not dict:
        raise ValueError("native boot document is not an object")
    return document


class Console:
    """Retains the bounded raw UART transcript and its original birth digest."""

    def __init__(self, path, current_tick, terminal_owner, maximum_tick):
        self.current_tick = current_tick
        self.terminal_owner = terminal_owner
        if type(maximum_tick) is not int or not 0 < maximum_tick < 1 << 64:
            raise ValueError("native boot horizon is not a positive bounded tick")
        self.maximum_tick = maximum_tick
        self.stream = Path(path).open("xb")
        self.byte_hash = hashlib.sha256()
        self.birth_hash = hashlib.sha256()
        self.bytes = 0
        self.last_identifier = 0
        self.first_birth = None
        self.last_birth = None
        self.line = bytearray()
        self.required = set()

    def consume(self, publication):
        """Checks and retains a publication before its native FIFO ACK."""
        if (type(publication) is not dict or set(publication) != {
                "output_id", "tick", "event_ordinal", "tick_ordinal",
                "causal_parent", "facet", "terminal", "payload"}):
            raise ValueError("native boot UART publication fields differ")
        if (publication["facet"] != "serial"
                or publication["terminal"] != self.terminal_owner
                or publication["causal_parent"] != "17"):
            raise ValueError("native boot UART owner or causal parent differs")
        numeric = []
        for name in ("output_id", "tick", "event_ordinal", "tick_ordinal"):
            value = publication[name]
            if (type(value) is not str or not value.isascii() or not value.isdecimal()
                    or len(value) > 20 or str(int(value)) != value
                    or int(value) >= 1 << 64):
                raise ValueError("native boot UART birth is not a canonical u64")
            numeric.append(int(value))
        identifier, tick, ordinal, tie = numeric
        if (identifier != self.last_identifier + 1 or not ordinal or not tie
                or tick > self.current_tick() or tick >= self.maximum_tick):
            raise ValueError("native boot UART birth or FIFO order differs")
        payload = publication["payload"]
        if (type(payload) is not list or len(payload) != 1
                or type(payload[0]) is not int or not 0 <= payload[0] <= 255):
            raise ValueError("native boot UART publication is not one byte")
        if self.bytes == MAX_TRANSCRIPT_BYTES:
            raise ValueError("native boot UART transcript exhausted its finite credit")

        data = bytes(payload)
        self.stream.write(data)
        self.byte_hash.update(data)
        encoded_birth = json.dumps(publication, sort_keys=True, separators=(",", ":")).encode()
        self.birth_hash.update(len(encoded_birth).to_bytes(8, "big"))
        self.birth_hash.update(encoded_birth)
        self.bytes += 1
        self.last_identifier = identifier
        self.first_birth = self.first_birth or publication
        self.last_birth = publication

        if data == b"\n":
            line = bytes(self.line).removesuffix(b"\r")
            if line in REQUIRED_LINES:
                self.required.add(line)
            self.line.clear()
        else:
            self.line.extend(data)
            if len(self.line) > 4096:
                raise ValueError("native boot console line exceeds its finite extent")
        if any(marker in self.line for marker in FAILURE_TEXT):
            raise ValueError("actual guest console reported a boot or PID1 failure")
        return identifier

    def summary(self):
        return {
            "bytes": self.bytes,
            "sha256": self.byte_hash.hexdigest(),
            "birth_sha256": self.birth_hash.hexdigest(),
            "first_birth": self.first_birth,
            "last_birth": self.last_birth,
        }

