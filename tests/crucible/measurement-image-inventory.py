"""Describes final private fixture ELF images without executing their loaders.

All dependency search roots are explicit AOS derivation inputs. The resulting
inventory records facts; it does not authorize a runtime resource reservation.
"""

import argparse
import hashlib
import json
import pathlib
import struct


PAGE_BYTES = 4096
U64_MAX = (1 << 64) - 1


def checked_end(start, length):
    """Rejects offsets that cannot describe an unsigned 64-bit extent."""
    end = start + length
    if start < 0 or length < 0 or end > U64_MAX:
        raise ValueError("extent arithmetic overflow")
    return end


def read_exact(stream, offset, count, size):
    if checked_end(offset, count) > size:
        raise ValueError("truncated image extent")
    stream.seek(offset)
    data = stream.read(count)
    if len(data) != count:
        raise ValueError("image changed while reading")
    return data


def file_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(65536):
            digest.update(block)
    return digest.hexdigest()


def page_union(segments):
    intervals = []
    for segment in segments:
        if segment["kind"] != 1 or segment["memory_bytes"] == 0:
            continue
        start = segment["address"] // PAGE_BYTES * PAGE_BYTES
        last = checked_end(segment["address"], segment["memory_bytes"])
        end = checked_end(last, PAGE_BYTES - 1) // PAGE_BYTES * PAGE_BYTES
        intervals.append((start, end))

    merged = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(end, merged[-1][1])
        else:
            merged.append([start, end])
    return merged


def inspect_image(path):
    path = path.resolve(strict=True)
    initial = path.stat()
    if not path.is_file():
        raise ValueError("image is not a regular file")
    size = initial.st_size

    with path.open("rb") as stream:
        header = struct.unpack("<16sHHIQQQIHHHHHH", read_exact(stream, 0, 64, size))
        if header[0][:7] != b"\x7fELF\x02\x01\x01" or header[2] != 62:
            raise ValueError("requires ELF64 little-endian x86_64 version 1")
        if header[1] not in (2, 3) or header[3] != 1 or header[8] != 64 or header[9] != 56:
            raise ValueError("unsupported ELF executable header")
        program_offset, count = header[5], header[10]
        if count in (0, 65535):
            raise ValueError("missing or unsupported extended program headers")
        checked_end(program_offset, count * 56)

        segments = []
        for index in range(count):
            fields = struct.unpack("<IIQQQQQQ", read_exact(stream, program_offset + index * 56, 56, size))
            kind, flags, offset, address, _, file_bytes, memory_bytes, alignment = fields
            if checked_end(offset, file_bytes) > size:
                raise ValueError("program segment exceeds image")
            checked_end(address, memory_bytes)
            if kind in (1, 7) and file_bytes > memory_bytes:
                raise ValueError("load or TLS file extent exceeds memory extent")
            if alignment > 1 and alignment & (alignment - 1):
                raise ValueError("non-power-of-two segment alignment")
            if kind == 1 and alignment > 1 and address % alignment != offset % alignment:
                raise ValueError("inconsistent load alignment")
            segments.append(dict(kind=kind, flags=flags, offset=offset, address=address,
                                 file_bytes=file_bytes, memory_bytes=memory_bytes,
                                 alignment=alignment))

        def file_offset(address, length):
            end = checked_end(address, length)
            for segment in segments:
                if segment["kind"] == 1 and segment["address"] <= address and end <= segment["address"] + segment["file_bytes"]:
                    return segment["offset"] + address - segment["address"]
            raise ValueError("dynamic extent is not completely file-backed")

        dynamic = []
        for segment in segments:
            if segment["kind"] != 2:
                continue
            if segment["file_bytes"] % 16:
                raise ValueError("invalid dynamic table size")
            terminated = False
            for offset in range(segment["offset"], segment["offset"] + segment["file_bytes"], 16):
                tag, value = struct.unpack("<QQ", read_exact(stream, offset, 16, size))
                if tag == 0:
                    terminated = True
                    break
                dynamic.append((tag, value))
            if not terminated:
                raise ValueError("unterminated dynamic table")
        if any(tag in (0x6FFFFEFB, 0x6FFFFEFC, 0x7FFFFFFD, 0x7FFFFFFF) for tag, _ in dynamic):
            raise ValueError("audit, filter, or auxiliary loading is outside the private image contract")

        string_addresses = [value for tag, value in dynamic if tag == 5]
        string_lengths = [value for tag, value in dynamic if tag == 10]
        if dynamic and (len(string_addresses) != 1 or len(string_lengths) != 1):
            raise ValueError("ambiguous dynamic string table")

        def dynamic_string(offset):
            length = string_lengths[0]
            if offset >= length:
                raise ValueError("dynamic string offset exceeds table")
            start = file_offset(string_addresses[0], length) + offset
            value = bytearray()
            for displacement in range(length - offset):
                byte = read_exact(stream, start + displacement, 1, size)
                if byte == b"\0":
                    return value.decode("ascii")
                value.extend(byte)
                if len(value) > 4096:
                    raise ValueError("dynamic path exceeds fixed path contract")
            raise ValueError("unterminated dynamic string")

        interpreters = []
        for segment in segments:
            if segment["kind"] == 3:
                if not 1 < segment["file_bytes"] <= 4097:
                    raise ValueError("invalid interpreter path extent")
                raw = read_exact(stream, segment["offset"], segment["file_bytes"], size)
                if not raw.endswith(b"\0") or b"\0" in raw[:-1]:
                    raise ValueError("invalid interpreter path")
                interpreters.append(raw[:-1].decode("ascii"))
        if len(interpreters) > 1:
            raise ValueError("multiple interpreters")
        needed = [dynamic_string(value) for tag, value in dynamic if tag == 1]
        sonames = [dynamic_string(value) for tag, value in dynamic if tag == 14]
        if len(sonames) > 1 or any(not name or "/" in name for name in sonames):
            raise ValueError("invalid or ambiguous library SONAME")
        rpath = [dynamic_string(value) for tag, value in dynamic if tag == 15]
        runpath = [dynamic_string(value) for tag, value in dynamic if tag == 29]
        if rpath and runpath:
            raise ValueError("dual RPATH and RUNPATH is outside the private image contract")

    digest = file_digest(path)
    final = path.stat()
    if (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns) != (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns):
        raise ValueError("image changed during inspection")
    intervals = page_union(segments)
    return dict(path=str(path), sha256=digest, file_bytes=size,
                loads=[segment for segment in segments if segment["kind"] == 1],
                load_intervals=intervals, load_bytes=sum(end - start for start, end in intervals),
                tls=[segment for segment in segments if segment["kind"] == 7],
                interpreter=interpreters[0] if interpreters else None,
                needed=needed, soname=sonames[0] if sonames else None,
                rpath=rpath, runpath=runpath)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", action="append", required=True)
    parser.add_argument("--dependency-root", action="append", required=True)
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args()
    roots = [pathlib.Path(value).resolve(strict=True) for value in arguments.dependency_root]
    initial_images = [str(pathlib.Path(value).resolve(strict=True)) for value in arguments.image]
    if len(initial_images) != len(set(initial_images)):
        raise ValueError("duplicate initial image")
    rows = {}

    def describe(path):
        observed = inspect_image(path)
        if str(path) in rows and rows[str(path)] != observed:
            raise ValueError("shared input changed between process inventories")
        return rows.setdefault(str(path), observed)

    processes = []
    for initial_image in initial_images:
        pending = [(pathlib.Path(initial_image), [])]
        reached = set()
        edges = []
        loaded_names = {}

        def load_dependency(loader, dependency, inherited, requested_name):
            resolved = dependency.resolve(strict=True)
            if not any(resolved.is_relative_to(root) for root in roots):
                raise ValueError("dependency escapes declared roots")
            dependency_row = describe(resolved)
            for name in (requested_name, dependency_row["soname"]):
                if name:
                    loaded_names.setdefault(name, resolved)
            edges.append(dict(loader=str(loader), dependency=str(resolved)))
            pending.append((resolved, inherited))

        while pending:
            path, inherited_rpath = pending.pop(0)
            if str(path) in reached:
                continue
            reached.add(str(path))
            row = describe(path)
            own_rpath = [pathlib.Path(value) for entry in row["rpath"] for value in entry.split(":")]
            own_runpath = [pathlib.Path(value) for entry in row["runpath"] for value in entry.split(":")]
            # Each executable has its own loader ancestry. File deduplication
            # across processes must not discount their separate mappings/TLS.
            inherited = own_rpath + inherited_rpath
            searches = own_runpath if own_runpath else inherited
            for search in searches:
                if not search.is_absolute() or not any(search.is_relative_to(root) for root in roots):
                    raise ValueError("undeclared or relative dynamic search root")
            if row["interpreter"]:
                interpreter = pathlib.Path(row["interpreter"])
                load_dependency(path, interpreter, [], interpreter.name)
            for name in row["needed"]:
                if not name or "/" in name:
                    raise ValueError("dependency is not a simple library name")
                # The pinned loader checks already loaded names and SONAMEs
                # before searching. Main dependencies are loaded breadth first.
                if name in loaded_names:
                    load_dependency(path, loaded_names[name], inherited, name)
                    continue
                candidates = [directory / name for directory in searches if (directory / name).is_file()]
                if not candidates:
                    raise ValueError("dependency cannot be resolved from declared image search roots")
                load_dependency(path, candidates[0], inherited, name)

        processes.append(dict(
            executable=initial_image,
            images=sorted(reached),
            dependencies=edges,
            load_bytes_without_sharing=sum(rows[path]["load_bytes"] for path in reached),
            tls=[dict(image=path, segments=rows[path]["tls"]) for path in sorted(reached) if rows[path]["tls"]],
        ))

    output = dict(schema="crucible.private-image-inventory.v1", architecture="x86_64-linux",
                  page_bytes=PAGE_BYTES, initial_images=initial_images,
                  rows=[rows[key] for key in sorted(rows)],
                  processes=processes,
                  unique_file_bytes=sum(row["file_bytes"] for row in rows.values()),
                  admission=False, complete_loader_or_stack_bound=False)
    pathlib.Path(arguments.output).write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
