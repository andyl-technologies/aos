"""Checks production dormant/active RAM dirty planes and paging activation.

The fixture compiles extracted production functions against scalar bitmap and
ownership instrumentation. It verifies dirty-client behavior and activation
ordering; it does not qualify a live borrower barrier or kernel fault service.
"""

import argparse
from pathlib import Path
import subprocess
import tempfile


def function(source: str, result: str, name: str) -> str:
    start = source.index(f"{result} {name}(")
    opening = source.index("{", start)
    depth = 1
    cursor = opening + 1
    while depth:
        if source[cursor] == "{":
            depth += 1
        elif source[cursor] == "}":
            depth -= 1
        cursor += 1
    return source[start:cursor]


parser = argparse.ArgumentParser()
parser.add_argument("--source", required=True, type=Path)
parser.add_argument("--cc", required=True)
arguments = parser.parse_args()
physmem = (arguments.source / "system/physmem.c").read_text()
pager = (arguments.source / "plugins/crucible-paged-ram.c").read_text()
memory = (arguments.source / "system/memory.c").read_text()
cpu = (arguments.source / "cpu-common.c").read_text()
cpu_header = (arguments.source / "include/hw/core/cpu.h").read_text()
union_start = cpu_header.index("typedef union", cpu_header.index("/* work queue */"))
union_end = cpu_header.index("} run_on_cpu_data;", union_start) + len("} run_on_cpu_data;")
item_start = cpu.index("struct qemu_work_item {")
item_end = cpu.index("};", item_start) + 2
measured_source = (
    "#include <assert.h>\n#include <stdbool.h>\n#include <stdint.h>\n"
    "#include <stdio.h>\n#include <stdlib.h>\n#include <malloc.h>\n"
    '#include "qemu/queue.h"\n'
    "typedef uint64_t vaddr;\ntypedef struct CPUState CPUState;\n"
    + cpu_header[union_start:union_end]
    + "\ntypedef void (*run_on_cpu_func)(CPUState *, run_on_cpu_data);\n"
    + cpu[item_start:item_end]
    + "\n"
    + function(cpu, "size_t", "qemu_cpu_async_work_size")
    + r"""
int main(void)
{
    size_t bytes = qemu_cpu_async_work_size();
    void *item = calloc(1, bytes);
    assert(item != NULL);
    assert(malloc_usable_size(item) <= bytes + 128);
    free(item);
    printf("%zu\n", bytes);
    return 0;
}
"""
)
production = "\n\n".join(
    [
        function(memory, "uint64_t", "memory_listener_commit_count"),
        function(physmem, "bool", "physical_memory_is_clean"),
        function(physmem, "void", "physical_memory_set_dirty_range"),
        function(physmem, "int", "qemu_crucible_ram_dirty_rearm_metadata_bytes"),
        function(pager, "int", "qemu_plugin_crucible_ram_pin_topology_v1"),
    ]
)
fixture = r"""
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint64_t ram_addr_t;
typedef struct Error { int unused; } Error;
enum { DIRTY_MEMORY_VGA, DIRTY_MEMORY_CODE, DIRTY_MEMORY_MIGRATION,
       DIRTY_MEMORY_CRUCIBLE_CHECKPOINT, DIRTY_MEMORY_CRUCIBLE_RAM,
       DIRTY_MEMORY_NUM };
#define GLOBAL_DIRTY_CRUCIBLE_RAM 16
#define GLOBAL_DIRTY_CRUCIBLE_CHECKPOINT 8
#define TARGET_PAGE_BITS 12
#define TARGET_PAGE_ALIGN(value) (((value) + 4095) & ~UINT64_C(4095))
#define DIRTY_MEMORY_BLOCK_SIZE 8
#define MIN(left, right) ((left) < (right) ? (left) : (right))
#define likely(value) (value)
#define unlikely(value) (value)
#define RCU_READ_LOCK_GUARD() ++rcu_scopes
#define WITH_RCU_READ_LOCK_GUARD() for (bool entered = (++rcu_scopes, true); entered; entered = false)
#define qatomic_read(pointer) (*(pointer))
#define qatomic_store_release(pointer, value) (*(pointer) = (value))

typedef struct DirtyMemoryBlocks { unsigned long *blocks[2]; } DirtyMemoryBlocks;
static struct { DirtyMemoryBlocks *dirty_memory[DIRTY_MEMORY_NUM]; } ram_list;
static DirtyMemoryBlocks storage[DIRTY_MEMORY_NUM];
static unsigned long bits[DIRTY_MEMORY_NUM][2];
static unsigned reads[DIRTY_MEMORY_NUM];
static unsigned rcu_scopes;
static unsigned global_dirty_tracking;
static unsigned root_epochs;
static unsigned checkpoint_epochs;
static bool paging_topology_pinned;
static DirtyMemoryBlocks *paging_dirty_planes[DIRTY_MEMORY_NUM];
static uint64_t physical_device_generation = 2;
static unsigned validations;
static int validation_status;
static int second_validation_status;
static bool start_succeeds = true;
static unsigned starts;
static unsigned seals;
static int seal_status;
static bool bql_owned = true;
static size_t work_size = WORK_BYTES_MEASURED;
static uint64_t admitted_rearm_metadata = WORK_BYTES_MEASURED + 128;

typedef struct MemoryListener MemoryListener;
struct MemoryListener {
    void (*commit)(MemoryListener *);
    MemoryListener *next;
};
static MemoryListener listeners[4096];
static MemoryListener *memory_listeners;
#define QTAILQ_FOREACH(item, head, link) for ((item) = *(head); (item); (item) = (item)->next)

static bool bql_locked(void) { return bql_owned; }
static void tcg_commit(MemoryListener *listener) { (void)listener; }
static void other_commit(MemoryListener *listener) { (void)listener; }
static void set_listeners(unsigned count)
{
    assert(count <= 4096);
    memory_listeners = count ? &listeners[0] : NULL;
    for (unsigned index = 0; index < count; index++) {
        listeners[index].commit = tcg_commit;
        listeners[index].next = index + 1 < count ? &listeners[index + 1] : NULL;
    }
}
static size_t qemu_cpu_async_work_size(void) { return work_size; }

static DirtyMemoryBlocks *read_header(DirtyMemoryBlocks **pointer)
{
    for (unsigned client = 0; client < DIRTY_MEMORY_NUM; client++) {
        if (pointer == &ram_list.dirty_memory[client]) {
            reads[client]++;
            return *pointer;
        }
    }
    assert(false);
    return NULL;
}
#define qatomic_rcu_read(pointer) read_header(pointer)

static bool test_bit(unsigned long bit, const unsigned long *bitmap)
{
    return (*bitmap >> bit) & 1;
}

static void bitmap_set_atomic(unsigned long *bitmap, unsigned long first,
                              unsigned long count)
{
    assert(first + count <= DIRTY_MEMORY_BLOCK_SIZE);
    for (unsigned long bit = first; bit < first + count; bit++) {
        *bitmap |= 1UL << bit;
    }
}

static void qemu_crucible_ram_dirty_generation_advance(void) { root_epochs++; }
static void qemu_crucible_checkpoint_dirty_generation_advance(void) { checkpoint_epochs++; }
static bool xen_enabled(void) { return false; }
static void xen_hvm_modified_memory(ram_addr_t start, ram_addr_t length)
{
    (void)start;
    (void)length;
    assert(false);
}

static int qemu_plugin_crucible_ram_physical_validate_v1(uint64_t token,
                                                        uint64_t generation)
{
    assert(token == 11 && generation == 7);
    validations++;
    return validations == 1 ? validation_status : second_validation_status;
}

static bool memory_global_dirty_log_start(unsigned flags, Error **error)
{
    (void)error;
    assert(flags == GLOBAL_DIRTY_CRUCIBLE_RAM && validations == 1);
    assert(!paging_topology_pinned);
    starts++;
    if (start_succeeds) {
        global_dirty_tracking |= flags;
    }
    return start_succeeds;
}

static void error_free(Error *error) { (void)error; }
static int qemu_crucible_ram_physical_graph_seal(uint64_t generation)
{
    assert(generation == 2 && validations == 2 && starts == 1);
    assert(global_dirty_tracking & GLOBAL_DIRTY_CRUCIBLE_RAM);
    seals++;
    return seal_status;
}

static void reset(void)
{
    memset(bits, 0, sizeof(bits));
    memset(reads, 0, sizeof(reads));
    for (unsigned client = 0; client < DIRTY_MEMORY_NUM; client++) {
        storage[client].blocks[0] = &bits[client][0];
        storage[client].blocks[1] = &bits[client][1];
        ram_list.dirty_memory[client] = &storage[client];
        paging_dirty_planes[client] = NULL;
    }
    global_dirty_tracking = root_epochs = checkpoint_epochs = rcu_scopes = 0;
    validations = starts = seals = 0;
    validation_status = second_validation_status = seal_status = 0;
    paging_topology_pinned = false;
    start_succeeds = true;
    bql_owned = true;
    set_listeners(1);
    work_size = WORK_BYTES_MEASURED;
    admitted_rearm_metadata = WORK_BYTES_MEASURED + 128;
}
"""
checks = r"""
int main(void)
{
    /* Enumerate every client bit combination at both block boundaries. */
    for (unsigned active = 0; active < 2; active++) {
        for (unsigned dirty = 0; dirty < 32; dirty++) {
            for (unsigned page = 0; page < 16; page++) {
                reset();
                global_dirty_tracking = active ? GLOBAL_DIRTY_CRUCIBLE_RAM : 0;
                for (unsigned client = 0; client < DIRTY_MEMORY_NUM; client++) {
                    bits[client][page / 8] = ((dirty >> client) & 1) << (page % 8);
                }
                unsigned relevant = active ? 31 : 15;
                assert(physical_memory_is_clean((uint64_t)page * 4096 + 4095) ==
                       ((dirty & relevant) != relevant));
                assert(rcu_scopes == 1);
                if (!active) {
                    assert(reads[DIRTY_MEMORY_CRUCIBLE_RAM] == 0);
                }
            }
        }
    }

    /* All masks, unaligned starts, and block-spanning ranges preserve clients. */
    for (unsigned active = 0; active < 2; active++) {
        for (unsigned mask = 0; mask < 32; mask++) {
            reset();
            global_dirty_tracking = GLOBAL_DIRTY_CRUCIBLE_CHECKPOINT |
                (active ? GLOBAL_DIRTY_CRUCIBLE_RAM : 0);
            physical_memory_set_dirty_range(7 * 4096 + 3, 4096, mask);
            for (unsigned client = 0; client < DIRTY_MEMORY_NUM; client++) {
                bool expected = (mask & (1 << client)) &&
                    (client != DIRTY_MEMORY_CRUCIBLE_RAM || active);
                assert(bits[client][0] == (expected ? 128 : 0));
                assert(bits[client][1] == (expected ? 1 : 0));
                assert(reads[client] == (unsigned)expected);
            }
            assert(root_epochs == (unsigned)(active && (mask & 16)));
            assert(checkpoint_epochs == (unsigned)!!(mask & 8));
        }
    }

    /* Activation before first capture arms native tracking and revalidates. */
    reset();
    assert(qemu_plugin_crucible_ram_pin_topology_v1(11, 7) == 0);
    assert(paging_topology_pinned && validations == 2 && starts == 1 && seals == 1);
    for (unsigned client = 0; client < DIRTY_MEMORY_NUM; client++) {
        assert(paging_dirty_planes[client] == ram_list.dirty_memory[client]);
    }
    physical_memory_set_dirty_range(0, 1, 31);
    assert(root_epochs == 1 && bits[DIRTY_MEMORY_CRUCIBLE_RAM][0] == 1);
    physical_memory_set_dirty_range(4096, 1, 16);
    assert(root_epochs == 2 && bits[DIRTY_MEMORY_CRUCIBLE_RAM][0] == 3);

    reset();
    validation_status = -ESTALE;
    assert(qemu_plugin_crucible_ram_pin_topology_v1(11, 7) == -ESTALE);
    assert(!paging_topology_pinned && starts == 0);
    reset();
    start_succeeds = false;
    assert(qemu_plugin_crucible_ram_pin_topology_v1(11, 7) == -EIO);
    assert(!paging_topology_pinned && seals == 0);
    reset();
    second_validation_status = -ESTALE;
    assert(qemu_plugin_crucible_ram_pin_topology_v1(11, 7) == -ESTALE);
    assert(!paging_topology_pinned && seals == 0);
    reset();
    seal_status = -EBUSY;
    assert(qemu_plugin_crucible_ram_pin_topology_v1(11, 7) == -EBUSY);
    assert(!paging_topology_pinned);
    reset();
    set_listeners(2);
    assert(qemu_plugin_crucible_ram_pin_topology_v1(11, 7) == -ENOSPC);
    assert(!paging_topology_pinned && starts == 0);

    uint64_t allowance = UINT64_MAX;
    assert(qemu_crucible_ram_dirty_rearm_metadata_bytes(NULL) == -EINVAL);
    bql_owned = false;
    assert(qemu_crucible_ram_dirty_rearm_metadata_bytes(&allowance) == -EINVAL);
    bql_owned = true;
    work_size = SIZE_MAX;
    assert(qemu_crucible_ram_dirty_rearm_metadata_bytes(&allowance) == -EOVERFLOW);
    work_size = 40;
    work_size = SIZE_MAX - 128;
    set_listeners(2);
    assert(qemu_crucible_ram_dirty_rearm_metadata_bytes(&allowance) == -EOVERFLOW);
    work_size = 40;
    set_listeners(4096);
    assert(qemu_crucible_ram_dirty_rearm_metadata_bytes(&allowance) == 0);
    assert(allowance == 4096 * 168);
    listeners[0].commit = other_commit;
    listeners[1].commit = NULL;
    assert(memory_listener_commit_count(tcg_commit) == 4094);
    assert(memory_listener_commit_count(other_commit) == 1);
    set_listeners(0);
    assert(qemu_crucible_ram_dirty_rearm_metadata_bytes(&allowance) == 0);
    assert(allowance == 0);
    puts("ram_dirty_plane_activation_component=passed");
    return 0;
}
"""
with tempfile.TemporaryDirectory(prefix="ram-dirty-plane-") as temporary:
    temporary = Path(temporary)
    test = temporary / "dirty-plane.c"
    binary = temporary / "dirty-plane"
    measured = temporary / "work-size.c"
    measured_binary = temporary / "work-size"
    measured.write_text(measured_source)
    subprocess.run(
        [arguments.cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-I",
         str(arguments.source / "include"), str(measured), "-o", str(measured_binary)],
        check=True,
    )
    measured_bytes = int(subprocess.check_output([str(measured_binary)], text=True).strip())
    test.write_text(
        f"#define WORK_BYTES_MEASURED {measured_bytes}\n" + fixture + "\n" + production + "\n" + checks
    )
    subprocess.run(
        [arguments.cc, "-std=c11", "-Wall", "-Wextra", "-Werror", str(test), "-o", str(binary)],
        check=True,
    )
    subprocess.run([str(binary)], check=True)
    print(f"ram_rearm_actual_work_object_bytes={measured_bytes}")
