# SPDX-License-Identifier: Apache-2.0
r"""Reproduce diagnostic TCG CPU profiles with explicitly supplied AOS tools.

This host-only analyzer reads gperftools' legacy little-endian, 64-bit profile
format; it does not link QEMU or load into its process. The companion
tcg-profile-threads.c interposer is GPL-2.0-or-later because it loads into QEMU.
It changes diagnostic thread signal masks: only SIGPROF is unblocked, then
ProfilerRegisterThread enables per-thread sampling. Normal QEMU threads inherit
SIGPROF blocked, which otherwise biases sampling toward the waiting main thread.

Use source-built AOS tools and disable remote builders. For example, with
AOS_PYTHON and AOS_BASH supplied from the AOS packages and all paths quoted:

    PROFILER=$(aos-dev --release build package gperftools --no-out-link \
        --option builders '')
    nix --option builders '' develop -c gcc -shared -fPIC -O2 -Wall -Wextra -Werror \
        tests/crucible/tcg-profile-threads.c -o "$SHIM" \
        -L"$PROFILER/lib" -Wl,-rpath,"$PROFILER/lib" -lprofiler -ldl -pthread
    nix --option builders '' develop -c gcc -O2 -Wall -Wextra -Werror \
        tests/crucible/tcg-profile-mask-fixture.c -o "$MASK_FIXTURE" -pthread

Check sampling bias before using the interposer. The fixture runs a CPU worker
with the inherited mask and a waiting main thread. Plain profiling samples the
waiting thread; the corrected profile must reach busy_worker instead:

    CPUPROFILE="$CONTROL_PROFILE" LD_PRELOAD="$PROFILER/lib/libprofiler.so" \
        "$MASK_FIXTURE"
    CPUPROFILE="$MASK_PROFILE" CPUPROFILE_PER_THREAD_TIMERS=1 \
        CPUPROFILE_FREQUENCY=100 LD_PRELOAD="$SHIM" "$MASK_FIXTURE"

Instrument only QEMU, leaving the driver uninstrumented. Supply the exact
matched QEMU/plugin, stock kernel/initrd, driver and previously qualified
uninstrumented reference. Acquire these with the existing AOS checks and
release package recipes; retain executable, guest and interposer SHA256 hashes.

    "$AOS_PYTHON" tests/crucible/tcg-profile.py wrapper --bash "$AOS_BASH" \
        --qemu "$QEMU" --shim "$SHIM" --profile "$PROFILE" --output "$WRAPPER"
    "$DRIVER" --linux "$WRAPPER" "$PLUGIN" "$KERNEL" "$INITRD" \
        "$CAPTURE_DIRECTORY" "$CPU" 256 off > "$PROFILE_RESULT"
    "$AOS_PYTHON" tests/crucible/tcg-profile.py decode "$PROFILE" --nm "$AOS_NM"
    "$AOS_PYTHON" tests/crucible/tcg-profile.py compare "$REFERENCE" \
        "$PROFILE_RESULT" --output "$COMPARISON"

For a campaign results.json, select its full reference sample explicitly with
--reference-sample INDEX; the aggregate witness omits configuration fields.
Decode uses only exact ELF symbols and that ELF's installed function map. An
explicit map is accepted as --symbol-map ELF=TSV; never reuse a different ELF's
addresses. Preserve raw profiles, decoded stacks, maps and failed attempts.
Unknown/JIT addresses remain anonymous. Leaf costs are exclusive; cumulative
costs overlap. A graceful QEMU exit is needed to flush its profile.

All instrumented timings, including failed runs, are excluded from performance
means. Compare full readiness witnesses against two equivalent uninstrumented
references before attributing a successful diagnostic profile. A mismatching or
missing witness makes it behavior-perturbed diagnostic evidence only. This
method does not replace balanced, uninstrumented head-to-head timing trials.
"""

import argparse
import bisect
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess


WITNESS_FIELDS = (
    "raw_icount", "logical_tick", "idle_wake_tick", "registers",
    "timer_witness", "device_projection_manifest", "ram_sha256", "ram_bytes",
    "serial_sha256", "markers", "advances", "status", "kernel", "initrd",
    "ram_mib", "coverage", "fingerprint", "whitebox",
)
TIMING_FIELDS = (
    "seconds", "boot_seconds", "startup_seconds", "user_seconds",
    "system_seconds", "boot_user_seconds", "boot_system_seconds",
)


def sha256(path):
    """Hash an artifact without changing it."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_profile(path):
    """Decode the documented gperftools 64-bit legacy records and trailing maps."""
    data = path.read_bytes()
    if len(data) < 40:
        raise ValueError("profile is empty or its header is truncated")
    header = struct.unpack_from("<5Q", data)
    if header[:3] != (0, 3, 0) or header[3] == 0 or header[4] != 0:
        raise ValueError(f"unsupported profile header: {header}")

    cursor = 40
    records = []
    while True:
        if cursor + 16 > len(data):
            raise ValueError("profile record or trailer is truncated")
        count, depth = struct.unpack_from("<2Q", data, cursor)
        cursor += 16
        if not 1 <= depth <= 1024 or cursor + depth * 8 > len(data):
            raise ValueError("profile stack depth is invalid or truncated")
        pcs = struct.unpack_from(f"<{depth}Q", data, cursor)
        cursor += depth * 8
        if count == 0 and pcs == (0,):
            break
        if count == 0:
            raise ValueError("profile contains an invalid zero-count record")
        records.append((count, pcs))

    maps_text = data[cursor:].decode(errors="replace")
    mappings = []
    for line in maps_text.splitlines():
        match = re.match(
            r"([0-9a-f]+)-([0-9a-f]+) ([rwxps-]+) ([0-9a-f]+) \S+ \S+\s*(.*)",
            line,
        )
        if match:
            start, end, permissions, offset, name = match.groups()
            name = name or f"[anonymous-{permissions}]"
            mappings.append((int(start, 16), int(end, 16), int(offset, 16), name))
    return header[3], records, mappings, maps_text


def read_symbols(path, nm, symbol_maps):
    """Read bounded functions from this ELF's map or its regular/dynamic symbols."""
    binary = Path(path)
    if path not in symbol_maps and binary.is_file():
        candidate = binary.parent.parent / "share/qemu/symbols" / (binary.name + ".tsv")
        if candidate.is_file():
            symbol_maps[path] = candidate

    if path in symbol_maps:
        symbols = []
        for line in symbol_maps[path].read_text().splitlines():
            fields = line.split(maxsplit=3)
            if len(fields) != 4 or fields[2] not in ("T", "t", "W", "w"):
                raise ValueError("function map must contain start size type symbol")
            start, size, _, name = fields
            if int(size, 16) > 0:
                symbols.append((int(start, 16), int(size, 16), name))
        return sorted(symbols)

    if not binary.is_file():
        return []
    for flags in ([], ["-D"]):
        result = subprocess.run(
            [str(nm), *flags, "-C", "-n", "-S", "--defined-only", path],
            text=True, capture_output=True, check=False,
        )
        symbols = []
        for line in result.stdout.splitlines():
            match = re.match(r"([0-9a-f]+) ([0-9a-f]+) [tTwW] (.+)", line)
            if match:
                start, size, name = match.groups()
                if int(size, 16) > 0:
                    symbols.append((int(start, 16), int(size, 16), name))
        if symbols:
            return sorted(symbols)
    return []


def decode_profile(path, nm, symbol_maps):
    """Retain all annotated stacks and aggregate leaf/cumulative sample costs."""
    period, records, mappings, maps_text = read_profile(path)
    symbol_tables = {}
    annotations = {}

    def annotate(pc):
        if pc in annotations:
            return annotations[pc]
        for start, end, file_offset, name in mappings:
            if start <= pc < end:
                offset = pc - start + file_offset
                if name not in symbol_tables:
                    symbols = read_symbols(name, nm, symbol_maps)
                    symbol_tables[name] = (symbols, [item[0] for item in symbols])
                symbols, starts = symbol_tables[name]
                index = bisect.bisect_right(starts, offset) - 1
                label = f"{name}+0x{offset:x}"
                function = None
                if index >= 0:
                    symbol_start, size, function_name = symbols[index]
                    if offset < symbol_start + size:
                        function = function_name
                        label = f"{name}:{function_name}+0x{offset-symbol_start:x}"
                result = dict(pc=hex(pc), object=name, offset=hex(offset),
                              symbol=function, label=label)
                annotations[pc] = result
                return result
        result = dict(pc=hex(pc), object="unmapped", offset=None,
                      symbol=None, label=f"unmapped:{pc:#x}")
        annotations[pc] = result
        return result

    flat = collections.Counter()
    cumulative = collections.Counter()
    flat_functions = collections.Counter()
    cumulative_functions = collections.Counter()
    depths = collections.Counter()
    objects = collections.Counter()
    stacks = []
    for count, pcs in records:
        frames = [annotate(pc) for pc in pcs]
        flat[frames[0]["label"]] += count
        objects[frames[0]["object"]] += count
        depths[len(frames)] += count
        functions = [f"{frame['object']}:{frame['symbol']}" if frame["symbol"]
                     else frame["label"] for frame in frames]
        flat_functions[functions[0]] += count
        for function in set(functions):
            cumulative_functions[function] += count
        for label in set(frame["label"] for frame in frames):
            cumulative[label] += count
        stacks.append(dict(count=count, frames=frames))

    total = sum(count for count, _ in records)
    summary = dict(
        profile=str(path), profile_sha256=sha256(path), nm=str(nm),
        sampling_period_us=period, total_samples=total,
        symbol_maps={key: str(value) for key, value in symbol_maps.items()},
        symbol_map_sha256={key: sha256(value) for key, value in symbol_maps.items()},
        mapped_elf_sha256={name: sha256(Path(name)) for _, _, _, name in mappings
                           if Path(name).is_file()},
        profile_records=len(records), sampled_cpu_seconds=total * period / 1_000_000,
        stack_depth_samples=sorted(depths.items()), flat_objects=objects.most_common(),
        flat_pcs=flat.most_common(), flat_functions=flat_functions.most_common(),
        cumulative_functions=cumulative_functions.most_common(),
        cumulative_pcs=cumulative.most_common(),
        stacks=sorted(stacks, key=lambda record: record["count"], reverse=True),
        timings_excluded_from_performance_means=True,
    )
    path.with_suffix(path.suffix + ".maps").write_text(maps_text)
    path.with_suffix(path.suffix + ".json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def write_wrapper(arguments):
    """Create a separate QEMU-only loader with caller-supplied executable paths."""
    if arguments.profile.exists():
        raise ValueError("profile output already exists; preserve previous attempts")
    lines = [f"#!{arguments.bash}",
             f"export LD_PRELOAD={shlex.quote(str(arguments.shim))}",
             f"export CPUPROFILE={shlex.quote(str(arguments.profile))}",
             "export CPUPROFILE_FREQUENCY=100",
             "export CPUPROFILE_PER_THREAD_TIMERS=1",
             f'exec {shlex.quote(str(arguments.qemu))} "$@"']
    with arguments.output.open("x") as output:
        output.write("\n".join(lines) + "\n")
    os.chmod(arguments.output, 0o755)
    return dict(wrapper=str(arguments.output), wrapper_sha256=sha256(arguments.output),
                qemu_sha256=sha256(arguments.qemu), shim_sha256=sha256(arguments.shim),
                profile=str(arguments.profile), timings_excluded_from_performance_means=True)


def compare_witness(arguments):
    """Fail when any captured semantic/configuration field is absent or differs."""
    reference = json.loads(arguments.reference.read_text())
    if arguments.reference_sample is not None:
        reference = reference["samples"][arguments.reference_sample]
    profile = json.loads(arguments.result.read_text())
    missing = [field for field in WITNESS_FIELDS if field not in reference or field not in profile]
    differing = [field for field in WITNESS_FIELDS if field in reference and field in profile
                 and reference[field] != profile[field]]
    comparison = dict(
        reference=str(arguments.reference), profile_result=str(arguments.result),
        reference_sha256=sha256(arguments.reference),
        profile_result_sha256=sha256(arguments.result),
        reference_sample=arguments.reference_sample, compared_fields=list(WITNESS_FIELDS),
        missing_fields=missing, differing_fields=differing,
        profile_witness_matches_reference=not missing and not differing,
        profile_timings_excluded_from_means=True,
        profile_only_timings={field: profile.get(field) for field in TIMING_FIELDS},
    )
    arguments.output.write_text(json.dumps(comparison, indent=2) + "\n")
    return comparison


def existing_path(value):
    """Resolve explicit input artifacts and tools before acting on them."""
    return Path(value).resolve(strict=True)


def output_path(value):
    """Resolve an output path without requiring the output to exist."""
    return Path(value).resolve()


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    decode = commands.add_parser("decode", help="decode legacy CPU records using exact ELF maps")
    decode.add_argument("profile", type=existing_path)
    decode.add_argument("--nm", type=existing_path, required=True, help="source-built AOS nm")
    decode.add_argument("--symbol-map", action="append", default=[], metavar="ELF=TSV")

    wrapper = commands.add_parser("wrapper", help="create a QEMU-only profiler wrapper")
    for option in ("bash", "qemu", "shim"):
        wrapper.add_argument(f"--{option}", type=existing_path, required=True)
    for option in ("profile", "output"):
        wrapper.add_argument(f"--{option}", type=output_path, required=True)

    compare = commands.add_parser("compare", help="compare full stopped readiness witnesses")
    compare.add_argument("reference", type=existing_path)
    compare.add_argument("result", type=existing_path)
    compare.add_argument("--reference-sample", type=int)
    compare.add_argument("--output", type=output_path, required=True)
    arguments = parser.parse_args()

    if arguments.command == "decode":
        symbol_maps = {}
        for item in arguments.symbol_map:
            elf, map_path = item.split("=", 1)
            symbol_maps[str(existing_path(elf))] = existing_path(map_path)
        summary = decode_profile(arguments.profile, arguments.nm, symbol_maps)
        print(json.dumps({key: summary[key] for key in
                          ("profile", "total_samples", "sampled_cpu_seconds", "flat_objects")},
                         indent=2))
        return 0
    if arguments.command == "wrapper":
        print(json.dumps(write_wrapper(arguments), indent=2))
        return 0
    comparison = compare_witness(arguments)
    print(json.dumps(comparison, indent=2))
    return 0 if comparison["profile_witness_matches_reference"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
