"""Report pointers into thread stacks found elsewhere in an x86-64 ELF core.

A hot-fork child inherits the memory of parent threads that no longer exist,
and the C library hands their stacks to the child's new threads.  Any
inherited heap or global value that still points into one of those stacks
aliases the frames of whichever new thread reused it.  This scan lists such
values so a stale reference can be named from the retained core alone.

Only data the kernel wrote is read; sparse holes are skipped.  Output is
bounded and raw: addresses, offsets and neighbouring words, never a verdict.
"""

import bisect
import os
import struct
import sys

PT_LOAD = 1
PT_NOTE = 4
NT_PRSTATUS = 1
NT_FILE = 0x46494C45
PF_W = 2

# struct elf_prstatus on x86-64: pr_pid at 32, pr_reg (user_regs_struct) at 112.
PRSTATUS_PID = 32
PRSTATUS_REGS = 112
REG_INDEX = {"rbp": 4, "rip": 16, "rsp": 19, "fs_base": 21}

MAX_GUARD_BYTES = 1 << 20
MAX_DETAIL_ROWS = 160
MAX_NEAR_ROWS = 48
MAX_ROWS_PER_TARGET = 24
# Thread descriptors and static TLS sit in roughly the top page of a stack;
# references deeper than this point into frames.
DESCRIPTOR_BYTES = 0x1000
NEAR_FAULT_SLOT_BYTES = 0x800
CHUNK_BYTES = 8 << 20


def read_at(core, offset, size):
    # Positional reads leave the descriptor offset to the extent probes.
    data = os.pread(core.fileno(), size, offset)
    if len(data) != size:
        raise ValueError("short read at %#x" % offset)
    return data


def parse_core(core):
    header = read_at(core, 0, 64)
    if header[:4] != b"\x7fELF" or header[4] != 2 or header[5] != 1:
        raise ValueError("not a little-endian ELF64 core")
    phoff, = struct.unpack_from("<Q", header, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", header, 0x36)

    loads = []
    notes = []
    for index in range(phnum):
        entry = read_at(core, phoff + index * phentsize, 56)
        p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = \
            struct.unpack("<IIQQQQQQ", entry)
        if p_type == PT_LOAD:
            loads.append((p_vaddr, p_memsz, p_flags, p_offset, p_filesz))
        elif p_type == PT_NOTE:
            notes.append(read_at(core, p_offset, p_filesz))
    loads.sort()

    threads = []
    files = []
    for blob in notes:
        position = 0
        while position + 12 <= len(blob):
            namesz, descsz, note_type = struct.unpack_from("<III", blob, position)
            position += 12 + ((namesz + 3) & ~3)
            desc = blob[position:position + descsz]
            position += (descsz + 3) & ~3
            if note_type == NT_PRSTATUS and len(desc) >= PRSTATUS_REGS + 27 * 8:
                tid, = struct.unpack_from("<I", desc, PRSTATUS_PID)
                regs = {name: struct.unpack_from("<Q", desc, PRSTATUS_REGS + 8 * slot)[0]
                        for name, slot in REG_INDEX.items()}
                threads.append((tid, regs))
            elif note_type == NT_FILE and len(desc) >= 16:
                count, _ = struct.unpack_from("<QQ", desc, 0)
                names = desc[16 + 24 * count:].split(b"\0")
                for entry in range(count):
                    start, end, _ = struct.unpack_from("<QQQ", desc, 16 + 24 * entry)
                    name = names[entry].decode("utf-8", "replace") if entry < len(names) else "?"
                    files.append((start, end, name))
    files.sort()
    return loads, threads, files


def stack_regions(loads, threads):
    """Writable mappings directly above a PROT_NONE guard, or holding an RSP."""
    regions = []
    for index, (vaddr, memsz, flags, _, _) in enumerate(loads):
        if not flags & PF_W:
            continue
        guarded = False
        if index > 0:
            g_vaddr, g_memsz, g_flags, _, _ = loads[index - 1]
            guarded = g_flags == 0 and g_vaddr + g_memsz == vaddr and g_memsz <= MAX_GUARD_BYTES
        holders = [tid for tid, regs in threads if vaddr <= regs["rsp"] < vaddr + memsz]
        if guarded or holders:
            regions.append((vaddr, vaddr + memsz, holders, guarded))
    return regions


def describe_location(address, files, regions):
    for index, (start, end, _, _) in enumerate(regions):
        if start <= address < end:
            return "stack#%d+%#x" % (index, address - start)
    position = bisect.bisect_right(files, (address, 1 << 64, "")) - 1
    if position >= 0:
        start, end, name = files[position]
        if start <= address < end:
            return "%s+%#x(map %#x)" % (os.path.basename(name), address - start, start)
    return "anon"


def data_extents(descriptor, start, end):
    """Yield populated byte ranges of the core file within [start, end)."""
    position = start
    while position < end:
        try:
            data = os.lseek(descriptor, position, os.SEEK_DATA)
        except OSError:
            return
        if data >= end:
            return
        try:
            hole = os.lseek(descriptor, data, os.SEEK_HOLE)
        except OSError:
            hole = end
        yield data, min(hole, end)
        position = hole


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: native-core-stack-references CORE FAULT-TID")
    path = sys.argv[1]
    fault_tid = int(sys.argv[2])

    with open(path, "rb") as core:
        loads, threads, files = parse_core(core)
        regions = stack_regions(loads, threads)
        thread_by_tid = dict(threads)
        if fault_tid not in thread_by_tid:
            print("native_core_stack_refs=inconclusive reason=fault-thread-absent")
            return
        fault_rsp = thread_by_tid[fault_tid]["rsp"]
        # g_main_dispatch's callee saves the caller's source register here.
        fault_slot = fault_rsp - 0x20

        for tid, regs in threads:
            print("native_core_thread tid=%d rsp=%#x rbp=%#x rip=%#x fs_base=%#x" %
                  (tid, regs["rsp"], regs["rbp"], regs["rip"], regs["fs_base"]))
        for index, (start, end, holders, guarded) in enumerate(regions):
            pads = [tid for tid, regs in threads if start <= regs["fs_base"] < end]
            print("native_core_stack_region index=%d start=%#x end=%#x bytes=%#x guarded=%s rsp_holders=%s fs_base_holders=%s" %
                  (index, start, end, end - start, guarded, holders, pads))
        print("native_core_fault_slot tid=%d slot=%#x" % (fault_tid, fault_slot))

        starts = [start for start, _, _, _ in regions]
        lowest = min(starts) if starts else 0
        highest = max(end for _, end, _, _ in regions) if regions else 0
        rows = []
        per_target = {}
        totals = {}
        descriptor = core.fileno()
        # A core truncated by its size limit ends before its headers say.
        file_bytes = os.fstat(descriptor).st_size
        for vaddr, memsz, flags, p_offset, p_filesz in loads:
            if p_filesz == 0:
                continue
            available = min(p_offset + p_filesz, file_bytes)
            for begin, finish in data_extents(descriptor, p_offset, available):
                begin -= (begin - p_offset) % 8
                position = begin
                while position < finish:
                    size = min(CHUNK_BYTES, finish - position)
                    size -= size % 8
                    if size == 0:
                        break
                    words = memoryview(read_at(core, position, size)).cast("Q")
                    base = vaddr + (position - p_offset)
                    for index, value in enumerate(words):
                        if not lowest <= value < highest:
                            continue
                        target = bisect.bisect_right(starts, value) - 1
                        if target < 0 or value >= regions[target][1]:
                            continue
                        location = base + 8 * index
                        t_start, t_end, holders, _ = regions[target]
                        if t_start <= location < t_end:
                            continue
                        key = (target, bool(holders))
                        totals[key] = totals.get(key, 0) + 1
                        near = abs(value - fault_slot) <= NEAR_FAULT_SLOT_BYTES
                        frame = t_end - value > DESCRIPTOR_BYTES
                        bucket = (target, near, frame)
                        limit = MAX_NEAR_ROWS if near else MAX_ROWS_PER_TARGET
                        if per_target.get(bucket, 0) >= limit:
                            continue
                        per_target[bucket] = per_target.get(bucket, 0) + 1
                        # Near-slot rows first, then frame references into
                        # guarded thread stacks, then descriptor references.
                        rank = (not near, not regions[target][3], not frame)
                        rows.append((rank, location, value, target))
                    position += size

        for (target, live), count in sorted(totals.items()):
            print("native_core_stack_ref_total target=stack#%d live=%s references=%d" %
                  (target, live, count))
        rows.sort()
        for rank, location, value, target in rows[:MAX_DETAIL_ROWS]:
            t_start, t_end, holders, _ = regions[target]
            words = []
            for neighbour in range(location - 0x18, location + 0x20, 8):
                found = None
                for vaddr, memsz, _, p_offset, p_filesz in loads:
                    if vaddr <= neighbour < vaddr + min(memsz, p_filesz):
                        found = struct.unpack("<Q", read_at(core, p_offset + neighbour - vaddr, 8))[0]
                        break
                words.append("%#x" % found if found is not None else "-")
            print("native_core_stack_ref near_fault_slot=%s location=%#x where=%s value=%#x target=stack#%d top_offset=-%#x slot_delta=%#x holders=%s words=[%s]" %
                  (not rank[0], location, describe_location(location, files, regions), value, target,
                   t_end - value, value - fault_slot, holders, " ".join(words)))
        print("native_core_stack_refs=complete detail_rows=%d" % min(len(rows), MAX_DETAIL_ROWS))


if __name__ == "__main__":
    main()
