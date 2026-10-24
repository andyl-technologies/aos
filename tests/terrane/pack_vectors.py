"""Reproduces pack witnesses from primitive fields, independently of codecs."""

import argparse
from pathlib import Path
import re
import subprocess
import textwrap


HEADING = "## Two-entry pack and detached index"
PACK_ID = bytes(range(16))
PLAINTEXTS = [b"hello\n", b"world\n"]


def crc32c(data):
    """Computes the reflected Castagnoli CRC with initial/final inversion."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def digest(binary, domain, data):
    """Hashes the domain, zero separator and bytes with the raw primitive."""
    result = subprocess.run(
        [str(binary)], input=domain.encode("ascii") + b"\0" + data,
        stdout=subprocess.PIPE, check=True,
    ).stdout.decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", result):
        raise ValueError("raw BLAKE3 helper must return one lowercase digest")
    return bytes.fromhex(result)


def witnesses(binary):
    """Constructs every binary field from the format's fixed-width table."""
    header = b"TRPK" + (1).to_bytes(2, "little") + bytes(2) + PACK_ID
    bodies = b"".join(b"\0" + plaintext for plaintext in PLAINTEXTS)
    rows = []
    offset = len(header)
    for plaintext in PLAINTEXTS:
        identity = digest(binary, "terrane-chunk-v1", plaintext)
        row = identity + offset.to_bytes(8, "little")
        row += (len(plaintext) + 1).to_bytes(4, "little")
        row += len(plaintext).to_bytes(4, "little") + bytes(8)
        rows.append((identity, offset, row))
        offset += len(plaintext) + 1
    rows.sort(key=lambda row: row[0])
    index = b"TRIX" + len(rows).to_bytes(8, "little")
    index += b"".join(row[2] for row in rows)

    def seal(index_bytes, checksum):
        footer = offset.to_bytes(8, "little")
        footer += checksum.to_bytes(4, "little") + b"TRPE"
        return header + bodies + index_bytes + footer

    checksum = crc32c(index)
    pack = seal(index, checksum)
    detached = header + index
    reserved_index = bytearray(index)
    reserved_index[12 + 52] = 1
    variants = {
        "pack-two-entry": pack,
        "pack-detached-index": detached,
        "pack-bad-crc": seal(index, checksum ^ 1),
        "pack-reserved-index": seal(reserved_index, crc32c(reserved_index)),
    }
    return rows, offset, checksum, variants


def render(binary):
    """Renders complete positive models and independently constructed negatives."""
    rows, offset, checksum, variants = witnesses(binary)
    parts = [HEADING, "", textwrap.fill(
        "These TEST-1/TEST-2 witnesses use the field tables in "
        "12-pack-format.md. The fixed pack ID is a byte-format fixture and "
        "claims no writer entropy. Bodies retain physical write order; index "
        "records are sorted by content digest. All integers in the pack and "
        "index are little-endian.", 78), "", "```text",
        f"pack-id = {PACK_ID.hex()}", "version = 1; flags = 0",
        "physical bodies = [00 || h'68656c6c6f0a', 00 || h'776f726c640a']",
        "plaintext bodies = [h'68656c6c6f0a', h'776f726c640a']",
        f"index count = 2; index offset = {offset}; index CRC32C = {checksum:08x}",
        "index records (digest, offset, body length, plaintext length, codec, kind):"]
    for identity, body_offset, _ in rows:
        parts.append(f"({identity.hex()}, {body_offset}, 7, 6, 0, 0)")
    parts += ["dictionary fields = 0; reserved fields = 0", "```", ""]
    for name, data in variants.items():
        parts += [f"### {name}", ""]
        if name == "pack-two-entry":
            identity = digest(binary, "terrane-pack-v1", data).hex()
            parts += [f"Positive pack: {len(data)} bytes. Identity:", "", "```text",
                      f"blake3:terrane-pack-v1:{identity}", "```", ""]
        elif name == "pack-detached-index":
            identity = digest(binary, "terrane-index-v1", data).hex()
            parts += [f"Positive header-prefixed index: {len(data)} bytes. Identity:",
                      "", "```text", f"blake3:terrane-index-v1:{identity}", "```", ""]
        elif name == "pack-bad-crc":
            parts += ["Negative pack: only the footer CRC's low bit is flipped.",
                      "The decoder rejects it with an index CRC error.", ""]
        else:
            parts += ["Negative pack: byte 52 of the first sorted index record is 1.",
                      "The footer CRC is recomputed over that index. The decoder",
                      "rejects the reserved field despite its valid CRC.", ""]
        parts += ["```hex", *textwrap.wrap(data.hex(), 72), "```", ""]
    parts += [textwrap.fill(
        "Positive container identities hash the complete corresponding bytes "
        "with their registered domain and zero separator. They do not enter "
        "tree or commit identities. Negative wires have no conforming "
        "container identity. Structural decoding does not verify plaintext "
        "chunk identities or authorize serving; the positive tests check "
        "those identities separately.", 78), ""]
    return "\n".join(parts)


def main():
    """Checks or inserts only this generator's bounded reference section."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blake3-bin", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--emit", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--insert", action="store_true")
    parser.add_argument("reference", type=Path, nargs="?")
    arguments = parser.parse_args()
    section = render(arguments.blake3_bin)
    if arguments.emit:
        print(section, end="")
        return
    if arguments.reference is None:
        parser.error("--check and --insert require a reference path")
    original = arguments.reference.read_text(encoding="utf-8")
    if arguments.insert:
        if HEADING in original:
            raise SystemExit("pack section already exists; refusing to replace it")
        marker = "## Reproduction\n"
        if original.count(marker) != 1:
            raise SystemExit("expected one reproduction section")
        arguments.reference.write_text(
            original.replace(marker, section + "\n" + marker), encoding="utf-8",
        )
        return
    if original.count(HEADING + "\n") != 1:
        raise SystemExit("expected one pack reference section")
    existing = original.split(HEADING + "\n", 1)[1].split("\n## ", 1)[0]
    if (HEADING + "\n" + existing).rstrip() != section.rstrip():
        raise SystemExit("pack reference bytes or models differ")
    print("PASS: independent pack reference section matches byte-for-byte")


if __name__ == "__main__":
    main()
