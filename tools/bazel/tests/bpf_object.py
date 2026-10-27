"""Reads BPF ELF and BTF contracts without loading programs into the kernel.

Only source-file locations in BTF line records are made relative. Instructions,
maps, symbols, relocations, types, function records, and CO-RE records remain
exact comparisons. Unsupported encodings fail instead of being approximated.
"""

from pathlib import PurePosixPath
import struct


def elf_sections(data):
    """Reads a little-endian ELF64 BPF relocatable object's section table."""
    if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<HH", data, 16) != (1, 247):
        raise ValueError("expected a little-endian ELF64 BPF relocatable object")
    offset = struct.unpack_from("<Q", data, 40)[0]
    size, count, names_index = struct.unpack_from("<HHH", data, 58)
    if size != 64 or not count or not 0 < names_index < count:
        raise ValueError("unsupported BPF ELF section table")
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, offset + index * size)
               for index in range(count)]
    names_header = headers[names_index]
    names = data[names_header[4]:names_header[4] + names_header[5]]
    sections = []
    for header in headers:
        name, kind, flags, _, position, length, link, info, _, stride = header
        contents = data[position:position + length] if kind != 8 else b""
        if kind != 8 and len(contents) != length:
            raise ValueError("truncated BPF ELF section")
        sections.append({"name": cstring(names, name), "kind": kind, "flags": flags,
                         "data": contents, "size": length, "link": link,
                         "info": info, "stride": stride})
    if len({section["name"] for section in sections}) != count:
        raise ValueError("duplicate BPF ELF section name")
    return sections


def cstring(data, offset):
    """Reads a terminated UTF-8 name at a checked table offset."""
    if not 0 <= offset < len(data):
        raise ValueError("BPF string offset is outside its table")
    end = data.find(b"\0", offset)
    if end < 0:
        raise ValueError("unterminated BPF string")
    return data[offset:end].decode("utf-8")


def btf_types(data):
    """Resolves BTF names while preserving every type ID and layout field."""
    magic, version, flags, header, types_offset, types_size, strings_offset, strings_size = (
        struct.unpack_from("<HBBIIIII", data))
    if (magic, version, flags, header) != (0xEB9F, 1, 0, 24):
        raise ValueError("unsupported BTF header")
    if types_offset != 0 or strings_offset != types_size or header + strings_offset + strings_size != len(data):
        raise ValueError("unsupported BTF section layout")
    types = data[header + types_offset:header + types_offset + types_size]
    strings = data[header + strings_offset:header + strings_offset + strings_size]
    if len(types) != types_size or len(strings) != strings_size:
        raise ValueError("truncated BTF data")
    result = []
    position = 0
    while position < len(types):
        name, info, size_or_type = struct.unpack_from("<III", types, position)
        position += 12
        kind, count = (info >> 24) & 31, info & 65535
        if kind in {2, 7, 8, 9, 10, 11, 12, 16, 18}:
            words = 0
        elif kind in {1, 14, 17}:
            words = 1
        elif kind == 3:
            words = 3
        elif kind in {4, 5, 15, 19}:
            words = count * 3
        elif kind in {6, 13}:
            words = count * 2
        else:
            raise ValueError("unsupported BTF type kind: " + str(kind))
        payload = list(struct.unpack_from("<" + "I" * words, types, position))
        position += words * 4
        if kind in {4, 5, 6, 13, 19}:
            stride = 3 if kind in {4, 5, 19} else 2
            for index in range(0, len(payload), stride):
                payload[index] = cstring(strings, payload[index])
        result.append({"name": cstring(strings, name), "info": info,
                       "size_or_type": size_or_type, "payload": payload})
    return result, strings


def btf_extensions(data, strings, source_name):
    """Reads function, line, and CO-RE records, allowing only known file paths."""
    magic, version, flags, header, *ranges = struct.unpack_from("<HBBIIIIIII", data)
    if (magic, version, flags, header) != (0xEB9F, 1, 0, 32):
        raise ValueError("unsupported BTF extension header")
    result = {}
    paths = set()
    end = 0
    for index, (name, expected_stride) in enumerate([("functions", 8), ("lines", 16), ("core", 16)]):
        offset, length = ranges[index * 2:index * 2 + 2]
        if offset != end:
            raise ValueError("unsupported BTF extension layout")
        end = offset + length
        records = data[header + offset:header + offset + length]
        if len(records) != length:
            raise ValueError("truncated BTF extension records")
        groups = []
        if records:
            stride = struct.unpack_from("<I", records)[0]
            if stride != expected_stride:
                raise ValueError("unsupported BTF extension record size")
            position = 4
            while position < len(records):
                section, count = struct.unpack_from("<II", records, position)
                position += 8
                entries = []
                for _ in range(count):
                    values = list(struct.unpack_from("<" + "I" * (stride // 4), records, position))
                    position += stride
                    if name == "lines":
                        source = cstring(strings, values[1])
                        if source not in {"/build/" + source_name, "./pkgs/security/" + source_name}:
                            raise ValueError("unexpected BTF source-file location: " + source)
                        paths.add(source)
                        values[1] = PurePosixPath(source).name
                        values[2] = cstring(strings, values[2])
                    elif name == "core":
                        values[2] = cstring(strings, values[2])
                    entries.append(values)
                groups.append({"section": cstring(strings, section), "records": entries})
        result[name] = groups
    if header + end != len(data) or not result["functions"] or not result["lines"] or len(paths) != 1:
        raise ValueError("BPF object omits its BTF function or source-line records")
    return result, sorted(paths)


def relocations(sections):
    """Resolves ELF relocation symbols without depending on symbol-table order."""
    result = {}
    for section in sections:
        if section["kind"] not in {4, 9}:
            continue
        symbols = sections[section["link"]]
        strings = sections[symbols["link"]]["data"]
        if symbols["stride"] != 24 or section["stride"] != (24 if section["kind"] == 4 else 16):
            raise ValueError("unsupported BPF relocation encoding")
        entries = []
        for position in range(0, len(section["data"]), section["stride"]):
            offset, info = struct.unpack_from("<QQ", section["data"], position)
            name, symbol_info, visibility, owner, value, size = struct.unpack_from(
                "<IBBHQQ", symbols["data"], (info >> 32) * 24)
            owner = sections[owner]["name"] if owner < len(sections) else owner
            entry = [offset, info & 0xFFFFFFFF,
                     {"name": cstring(strings, name), "info": symbol_info,
                      "visibility": visibility, "section": owner, "value": value, "size": size}]
            if section["kind"] == 4:
                entry.append(struct.unpack_from("<q", section["data"], position + 16)[0])
            entries.append(entry)
        result[section["name"]] = entries
    return result


def object_contract(path, source_name):
    """Checks retained BTF and returns the object's executable and ABI contract."""
    sections = elf_sections(path.read_bytes())
    by_name = {section["name"]: section for section in sections}
    if any(name.startswith(".debug") for name in by_name):
        raise ValueError("installed BPF object retains DWARF")
    if by_name["license"]["data"] != b"Dual BSD/GPL\0":
        raise ValueError("BPF object changed its kernel license declaration")
    types, strings = btf_types(by_name[".BTF"]["data"])
    extensions, paths = btf_extensions(by_name[".BTF.ext"]["data"], strings, source_name)
    allocated = {section["name"]: {"kind": section["kind"], "flags": section["flags"],
                                  "size": section["size"], "hex": section["data"].hex()}
                 for section in sections if section["flags"] & 2}
    return {"allocated_sections": allocated, "relocations": relocations(sections),
            "btf_types": types, "btf_extensions": extensions}, paths
