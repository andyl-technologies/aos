/* SPDX-License-Identifier: GPL-2.0-or-later */
/* This fixture runs only inside QEMU. Actual source symbols are resolved from
 * that same process's unstripped ELF; no pointer crosses a process protocol.
 * Names and negative source calls are mechanism tests, never qualification. */
#include "qemu/osdep.h"
#include "qemu/aio.h"
#include "qemu/coroutine_int.h"
#include "hw/core/cpu.h"
#include "plugins/qemu-plugin.h"
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <stdatomic.h>
#include <sys/mman.h>

typedef int (*WriterQuery)(
    const uint8_t *, uint64_t, QemuPluginCrucibleNodeWriterCut *,
    QemuPluginCrucibleNodeWriterCpu *, uint32_t,
    QemuPluginCrucibleNodeWriterWork *, uint32_t,
    QemuPluginCrucibleNodeWriterAio *, uint32_t,
    QemuPluginCrucibleNodeWriterBh *, uint32_t,
    QemuPluginCrucibleNodeWriterHandler *, uint32_t);
typedef void *(*SymbolLookup)(void *, const char *);
static _Atomic(WriterQuery) original_writer;
static atomic_bool completed;

static G_NORETURN void source_probe_failed(const char *reason)
{
    dprintf(STDERR_FILENO, "source-fixture FAIL: %s\n", reason);
    _exit(92);
}

static int main_load_address(struct dl_phdr_info *info, size_t size, void *data)
{
    if (!info->dlpi_name || !*info->dlpi_name) {
        *(uintptr_t *)data = info->dlpi_addr;
        return 1;
    }
    return 0;
}

static bool file_span(uint64_t offset, uint64_t length, size_t size)
{
    return offset <= size && length <= size - offset;
}

static void *source_symbol(const char *name, uintptr_t target, char *label, size_t capacity)
{
    struct stat status;
    uintptr_t base = 0;
    const Elf64_Ehdr *header;
    const Elf64_Shdr *sections;
    void *result = NULL;
    uint8_t *mapped;
    size_t length;
    int fd;

    fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &status) || status.st_size < (off_t)sizeof(Elf64_Ehdr) ||
        status.st_size > 512 * 1024 * 1024) {
        source_probe_failed("actual source ELF unavailable or oversized");
    }
    length = status.st_size;
    mapped = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED) {
        source_probe_failed("actual source ELF cannot be mapped read-only");
    }
    header = (const Elf64_Ehdr *)mapped;
    if (memcmp(header->e_ident, ELFMAG, SELFMAG) ||
        header->e_ident[EI_CLASS] != ELFCLASS64 ||
        header->e_ident[EI_DATA] != ELFDATA2LSB ||
        header->e_machine != EM_X86_64 || header->e_shnum == 0 ||
        header->e_shentsize != sizeof(Elf64_Shdr) ||
        !file_span(header->e_shoff,
                   (uint64_t)header->e_shnum * sizeof(Elf64_Shdr), length)) {
        source_probe_failed("unsupported exact native source ELF geometry");
    }
    dl_iterate_phdr(main_load_address, &base);
    sections = (const Elf64_Shdr *)(mapped + header->e_shoff);
    for (unsigned section = 0; section < header->e_shnum; section++) {
        const Elf64_Shdr *symbols = &sections[section];
        const Elf64_Shdr *strings;
        const Elf64_Sym *entries;
        size_t count;

        if (symbols->sh_type != SHT_SYMTAB) {
            continue;
        }
        if (symbols->sh_entsize != sizeof(Elf64_Sym) ||
            symbols->sh_size % sizeof(Elf64_Sym) ||
            symbols->sh_link >= header->e_shnum ||
            !file_span(symbols->sh_offset, symbols->sh_size, length)) {
            source_probe_failed("invalid native symbol table");
        }
        strings = &sections[symbols->sh_link];
        if (strings->sh_type != SHT_STRTAB ||
            !file_span(strings->sh_offset, strings->sh_size, length)) {
            source_probe_failed("invalid native symbol names");
        }
        entries = (const Elf64_Sym *)(mapped + symbols->sh_offset);
        count = symbols->sh_size / sizeof(*entries);
        for (size_t index = 0; index < count; index++) {
            const Elf64_Sym *symbol = &entries[index];
            const char *symbol_name;

            if (ELF64_ST_TYPE(symbol->st_info) != STT_FUNC ||
                symbol->st_shndx == SHN_UNDEF ||
                symbol->st_name >= strings->sh_size) {
                continue;
            }
            symbol_name = (const char *)(mapped + strings->sh_offset +
                                          symbol->st_name);
            if (!memchr(symbol_name, '\0', strings->sh_size - symbol->st_name)) {
                source_probe_failed("unterminated native symbol name");
            }
            if ((name && !strcmp(symbol_name, name)) ||
                (!name && symbol->st_value <= UINTPTR_MAX - base &&
                 base + symbol->st_value == target)) {
                if (!symbol->st_value || symbol->st_value > UINTPTR_MAX - base) {
                    source_probe_failed("invalid native symbol address");
                }
                result = (void *)(base + symbol->st_value);
                if (label) {
                    size_t name_length = strlen(symbol_name);
                    if (name_length >= capacity) {
                        source_probe_failed("native entry label exceeds fixture bound");
                    }
                    memcpy(label, symbol_name, name_length + 1);
                }
                break;
            }
        }
        if (result) {
            break;
        }
    }
    munmap(mapped, length);
    if (!result && name) {
        source_probe_failed("required exact native source symbol absent");
    }
    return result;
}

static void *source_function(const char *name)
{
    return source_symbol(name, 0, NULL, 0);
}

static void print_actual_coroutine_sources(void)
{
    const char *getters[] = { "qemu_get_aio_context", "iohandler_get_aio_context" };

    for (unsigned context_index = 0; context_index < 2; context_index++) {
        AioContext *(*get_context)(void) = source_function(getters[context_index]);
        AioContext *context = get_context();
        Coroutine *co;
        uint32_t count = 0;

        QSLIST_FOREACH(co, &context->scheduled_coroutines, co_scheduled_next) {
            char label[256] = "<external-or-unresolved>";

            if (++count > 4096) {
                source_probe_failed("actual native coroutine diagnostic exceeds cap");
            }
            source_symbol(NULL, (uintptr_t)co->entry, label, sizeof(label));
            dprintf(STDERR_FILENO,
                    "source-fixture CO ctx=%llu ordinal=%u entry=%s scheduled=%s locks=%zu\n",
                    (unsigned long long)context->crucible_hot_fork_id, count,
                    label, co->scheduled ? co->scheduled : "<none>", co->locks_held);
        }
    }
}

static void print_actual_bh_names(void)
{
    void (*query)(QemuBhHotForkInventory *) =
        source_function("qemu_bh_hot_fork_inventory");
    void (*destroy)(QemuBhHotForkInventory *) =
        source_function("qemu_bh_hot_fork_inventory_destroy");
    QemuBhHotForkInventory inventory;

    query(&inventory);
    if (!inventory.stable || inventory.overflowed ||
        inventory.entry_count > QEMU_BH_HOT_FORK_INVENTORY_MAX) {
        source_probe_failed("original BH inventory is not a stable finite cut");
    }
    for (size_t index = 0; index < inventory.entry_count; index++) {
        QemuBhHotForkInventoryEntry *row = &inventory.entries[index];

        if (row->pending || row->scheduled) {
            dprintf(STDERR_FILENO,
                    "source-fixture BH id=%llu ctx=%llu pending=%u scheduled=%u "
                    "deleted=%u oneshot=%u idle=%u name_valid=%u name=%s\n",
                    (unsigned long long)row->bh_id,
                    (unsigned long long)row->context_id,
                    row->pending, row->scheduled, row->deleted, row->oneshot,
                    row->idle, row->name_valid, row->name);
        }
    }
    destroy(&inventory);
}

typedef int (*FaultQuery)(const uint8_t *, QemuPluginCrucibleNodeSourceFault *);
static atomic_uint callback_calls;

static void never_dispatch_callback(CPUState *cpu, run_on_cpu_data data)
{
    atomic_fetch_add_explicit(&callback_calls, 1, memory_order_relaxed);
}

typedef struct FaultThreadProbe {
    FaultQuery query;
    const uint8_t *scope;
    QemuPluginCrucibleNodeSourceFault original;
    int status;
} FaultThreadProbe;

static void *fault_without_bql(void *opaque)
{
    FaultThreadProbe *probe = opaque;

    probe->status = probe->query(probe->scope, &probe->original);
    return NULL;
}

static void inject_actual_unknown_source(const char *mode, const uint8_t scope[32],
                                         uint32_t cpu_index)
{
    CPUState *(*get_cpu)(int) = source_function("qemu_get_cpu");
    FaultQuery query = source_function("qemu_plugin_crucible_node_query_source_fault");
    int (*park_query)(const uint8_t *, QemuPluginCrucibleNodeCpuParkFacts *) =
        source_function("qemu_plugin_crucible_node_query_cpu_park");
    CPUState *cpu = get_cpu(cpu_index);
    QemuPluginCrucibleNodeSourceFault original, repeated, negative;
    QemuPluginCrucibleNodeCpuParkFacts park, zero_park = { 0 };
    QemuPluginCrucibleNodeSourceFault zero_fault = { 0 };
    uint8_t wrong_scope[32], zero_digest[32] = { 0 };
    FaultThreadProbe thread_probe = { .query = query, .scope = scope };
    pthread_t thread;
    uint32_t kind;

    if (!cpu || query(scope, &original) != -EAGAIN ||
        memcmp(&original, &zero_fault, sizeof(original))) {
        source_probe_failed("source already invalid before actual fixture ingress");
    }
    if (!strcmp(mode, "irq")) {
        void (*set_interrupt)(CPUState *, int) = source_function("cpu_set_interrupt");

        kind = 2;
        set_interrupt(cpu, 2); /* Actual source CPU_INTERRUPT_HARD. */
        if (!(cpu->interrupt_request & 2)) {
            source_probe_failed("original IRQ producer behavior was suppressed");
        }
    } else if (!strcmp(mode, "work")) {
        void (*enqueue)(CPUState *, run_on_cpu_func, run_on_cpu_data) =
            source_function("async_run_on_cpu");
        void (*process)(CPUState *) = source_function("process_queued_cpu_work");
        struct qemu_work_item *original_item;

        kind = 1;
        enqueue(cpu, never_dispatch_callback, RUN_ON_CPU_HOST_PTR(&callback_calls));
        original_item = QSIMPLEQ_FIRST(&cpu->work_list);
        if (!original_item) {
            source_probe_failed("actual original CPU work was not queued");
        }
        process(cpu);
        if (QSIMPLEQ_FIRST(&cpu->work_list) != original_item ||
            atomic_load_explicit(&callback_calls, memory_order_relaxed) != 0) {
            source_probe_failed("unclassified original callback was consumed");
        }
    } else {
        source_probe_failed("unsupported source fixture mode");
    }
    if (query(scope, &original) || original.version != 1 ||
        original.size != sizeof(original) || original.code != 3 ||
        original.flags != 7 || original.fault_id != 1 ||
        original.command_sequence != 0 || original.cpu_index != cpu_index ||
        original.ingress_kind != kind ||
        memcmp(original.prepared_scope_hash, scope, 32) ||
        memcmp(original.original_command_digest, zero_digest, 32)) {
        source_probe_failed("actual first unmediated source diagnostic mismatch");
    }
    if (query(scope, &repeated) || memcmp(&original, &repeated, sizeof(original))) {
        source_probe_failed("original source diagnostic changed on retry");
    }
    memcpy(wrong_scope, scope, 32);
    wrong_scope[0] ^= 1;
    memset(&negative, 0xa5, sizeof(negative));
    if (query(wrong_scope, &negative) != -ESTALE ||
        memcmp(&negative, &zero_fault, sizeof(negative))) {
        source_probe_failed("foreign scope acquired source fault authority");
    }
    memset(&park, 0xa5, sizeof(park));
    if (park_query(scope, &park) != -ENOTRECOVERABLE ||
        memcmp(&park, &zero_park, sizeof(park))) {
        source_probe_failed("invalidated source promoted CPU park evidence");
    }
    /* The native getter still holds BQL. This independent diagnostic reader
     * must finish without acquiring it or any producer-held work mutex. */
    if (pthread_create(&thread, NULL, fault_without_bql, &thread_probe) ||
        pthread_join(thread, NULL) || thread_probe.status ||
        memcmp(&thread_probe.original, &original, sizeof(original))) {
        source_probe_failed("independent source query required producer BQL");
    }
    dprintf(STDERR_FILENO,
            "source-fixture PASS mode=%s first-fault=3 unknown-effects=7 "
            "retry=identical foreign-scope=ESTALE invalid-park=refused "
            "reader=no-BQL callback-count=0\n", mode);
}

static int source_writer_query(
    const uint8_t *scope, uint64_t generation,
    QemuPluginCrucibleNodeWriterCut *cut,
    QemuPluginCrucibleNodeWriterCpu *cpus, uint32_t cpu_capacity,
    QemuPluginCrucibleNodeWriterWork *work, uint32_t work_capacity,
    QemuPluginCrucibleNodeWriterAio *aio, uint32_t aio_capacity,
    QemuPluginCrucibleNodeWriterBh *bhs, uint32_t bh_capacity,
    QemuPluginCrucibleNodeWriterHandler *handlers, uint32_t handler_capacity)
{
    WriterQuery query = atomic_load_explicit(&original_writer, memory_order_acquire);
    int status;

    if (!query) {
        source_probe_failed("actual source query not retained");
    }
    status = query(scope, generation, cut, cpus, cpu_capacity, work, work_capacity,
                   aio, aio_capacity, bhs, bh_capacity, handlers, handler_capacity);
    if (status || atomic_exchange_explicit(&completed, true, memory_order_acq_rel)) {
        return status;
    }
    print_actual_bh_names();
    print_actual_coroutine_sources();
    for (uint32_t index = 0; index < cut->aio_count; index++) {
        dprintf(STDERR_FILENO,
                "source-fixture AIO id=%llu pending_bhs=%u queued_coroutines=%u active_bhs=%u\n",
                (unsigned long long)aio[index].context_id, aio[index].pending_bhs,
                aio[index].queued_coroutines, aio[index].active_bhs);
    }
    const char *mode = getenv("CRUCIBLE_NATIVE_SOURCE_FIXTURE_MODE");
    if (mode && strcmp(mode, "names")) {
        if (!cut->cpu_count || cut->raw_icount || cut->current_ps) {
            source_probe_failed("negative fixture requires actual initial no-retirement cut");
        }
        inject_actual_unknown_source(mode, scope, cpus[0].cpu_index);
    }
    dprintf(STDERR_FILENO, "source-fixture PASS actual-BH-names-only held=%llu\n",
            (unsigned long long)cut->gate_generation);
    return status;
}

void *dlsym(void *handle, const char *name)
{
    SymbolLookup lookup = (SymbolLookup)dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.2.5");
    void *symbol;

    if (!lookup) {
        source_probe_failed("actual source-built libc lookup unavailable");
    }
    symbol = lookup(handle, name);
    if (symbol && !strcmp(name, "qemu_plugin_crucible_node_query_writer_cut")) {
        atomic_store_explicit(&original_writer, (WriterQuery)symbol, memory_order_release);
        return (void *)source_writer_query;
    }
    return symbol;
}
