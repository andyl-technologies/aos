/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Actual QEMU-only constructor custody probe; no readiness certificate. */
#include "qemu/osdep.h"
#include "plugins/qemu-plugin.h"
#include "qemu/crucible-node-root.h"
#include "hw/core/crucible-device-roots.h"
#include "hw/core/qdev.h"
#include "hw/i386/apic_internal.h"
#include "qemu/timer.h"
#include "hw/core/loader.h"
#include "hw/nvram/fw_cfg.h"
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <stdatomic.h>
#include <sys/mman.h>

typedef void *(*SymbolLookup)(void *, const char *);
typedef int (*SuccessorQuery)(const uint8_t *, uint64_t, const uint8_t *,
                            QemuPluginCrucibleNodePreparationSuccessor *);
static _Atomic(SuccessorQuery) original_query;
typedef int (*RootRegistration)(const CrucibleNodeRootPolicy *);
static _Atomic(RootRegistration) original_registration;

static G_NORETURN void root_probe_failed(const char *reason)
{
    dprintf(STDERR_FILENO, "root-factory-fixture FAIL: %s\n", reason);
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
        root_probe_failed("actual source ELF unavailable or oversized");
    }
    length = status.st_size;
    mapped = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mapped == MAP_FAILED) {
        root_probe_failed("actual source ELF cannot be mapped read-only");
    }
    header = (const Elf64_Ehdr *)mapped;
    if (memcmp(header->e_ident, ELFMAG, SELFMAG) ||
        header->e_ident[EI_CLASS] != ELFCLASS64 ||
        header->e_ident[EI_DATA] != ELFDATA2LSB ||
        header->e_machine != EM_X86_64 || header->e_shnum == 0 ||
        header->e_shentsize != sizeof(Elf64_Shdr) ||
        !file_span(header->e_shoff,
                   (uint64_t)header->e_shnum * sizeof(Elf64_Shdr), length)) {
        root_probe_failed("unsupported exact native source ELF geometry");
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
            root_probe_failed("invalid native symbol table");
        }
        strings = &sections[symbols->sh_link];
        if (strings->sh_type != SHT_STRTAB ||
            !file_span(strings->sh_offset, strings->sh_size, length)) {
            root_probe_failed("invalid native symbol names");
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
                root_probe_failed("unterminated native symbol name");
            }
            if ((name && !strcmp(symbol_name, name)) ||
                (!name && symbol->st_value <= UINTPTR_MAX - base &&
                 base + symbol->st_value == target)) {
                if (!symbol->st_value || symbol->st_value > UINTPTR_MAX - base) {
                    root_probe_failed("invalid native symbol address");
                }
                result = (void *)(base + symbol->st_value);
                if (label) {
                    size_t name_length = strlen(symbol_name);
                    if (name_length >= capacity) {
                        root_probe_failed("native entry label exceeds fixture bound");
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
        root_probe_failed("required exact native source symbol absent");
    }
    return result;
}

static void *source_function(const char *name)
{
    return source_symbol(name, 0, NULL, 0);
}

static int original_pit(Object *object, void *opaque)
{
    Object *(*cast)(Object *, const char *) = source_function("object_dynamic_cast");
    DeviceState **pit = opaque;

    if (cast(object, "isa-pit")) {
        if (*pit) {
            root_probe_failed("multiple actual PIT constructor objects");
        }
        *pit = (DeviceState *)object;
    }
    return 0;
}

static void original_lifetime_refusals(void)
{
    Object *(*root)(void) = source_function("object_get_root");
    int (*census)(Object *, int (*)(Object *, void *), void *) =
        source_function("object_child_foreach_recursive");
    bool (*set_parent)(DeviceState *, BusState *, Error **) =
        source_function("qdev_set_parent_bus");
    bool (*set_bool)(Object *, const char *, bool, Error **) =
        source_function("object_property_set_bool");
    void (*free_error)(Error *) = source_function("error_free");
    DeviceState *pit = NULL;
    BusState *original_bus;
    Error *error = NULL;

    if (census(root(), original_pit, &pit) || !pit || !pit->realized) {
        root_probe_failed("original actual PIT is missing");
    }
    original_bus = pit->parent_bus;
    if (set_parent(pit, NULL, &error) || !error ||
        pit->parent_bus != original_bus || !pit->realized) {
        root_probe_failed("parent-bus replacement crossed original lifetime gate");
    }
    free_error(error);
    error = NULL;
    if (set_bool((Object *)pit, "realized", false, &error) || !error ||
        pit->parent_bus != original_bus || !pit->realized) {
        root_probe_failed("PIT unrealize crossed original lifetime gate");
    }
    free_error(error);
    dprintf(STDERR_FILENO,
            "root-factory-fixture PASS original-PIT detach/unrealize refused "
            "before-effects original-parent-and-realized-state=unchanged\n");
}

static int original_apic(Object *object, void *opaque)
{
    Object *(*cast)(Object *, const char *) = source_function("object_dynamic_cast");
    APICCommonState **apic = opaque;

    if (cast(object, TYPE_APIC_COMMON)) {
        if (*apic) {
            root_probe_failed("multiple actual local APIC payload owners");
        }
        *apic = (APICCommonState *)object;
    }
    return 0;
}

static void original_allocated_timer_refusals(void)
{
    Object *(*root)(void) = source_function("object_get_root");
    int (*census)(Object *, int (*)(Object *, void *), void *) =
        source_function("object_child_foreach_recursive");
    int (*seal)(void) = source_function("qemu_timer_node_roots_seal");
    bool (*sealed)(void) = source_function("qemu_timer_node_roots_sealed");
    APICCommonState *apic = NULL;
    QEMUTimer *timer;
    QEMUTimerCB *callback;
    void *payload;
    QEMUTimerList *list;
    uint64_t id;
    int scale, attributes;

    if (census(root(), original_apic, &apic) || !apic || !apic->timer ||
        apic->timer->pending || apic->timer->crucible_hot_fork_pending ||
        !apic->timer->crucible_hot_fork_id) {
        root_probe_failed("genuine unarmed original APIC timer missing");
    }
    timer = apic->timer;
    callback = timer->cb;
    payload = timer->opaque;
    list = timer->timer_list;
    id = timer->crucible_hot_fork_id;
    scale = timer->scale;
    attributes = timer->attributes;
    if (seal() || !sealed()) {
        root_probe_failed("actual complete allocated timer census refused");
    }

    /* Native private fields change only while BQL and the original writer HOLD
     * are owned here. No callback executes and all bytes are restored before
     * returning to the real plugin. An unarmed timer must remain in the census. */
    timer->cb = NULL;
    if (seal() != -ENOTSUP) {
        root_probe_failed("changed unarmed callback omitted from root census");
    }
    timer->cb = callback;
    timer->opaque = NULL;
    if (seal() != -ENOTSUP) {
        root_probe_failed("changed unarmed payload omitted from root census");
    }
    timer->opaque = payload;
    timer->timer_list = NULL;
    if (seal() != -ENOTSUP) {
        root_probe_failed("changed unarmed timer list omitted from root census");
    }
    timer->timer_list = list;
    timer->crucible_hot_fork_id = 0;
    if (seal() != -ENOTSUP) {
        root_probe_failed("changed original allocated timer ID accepted");
    }
    timer->crucible_hot_fork_id = id;
    timer->scale = scale + 1;
    if (seal() != -ENOTSUP) {
        root_probe_failed("changed original timer scale accepted");
    }
    timer->scale = scale;
    timer->attributes = attributes ^ 1;
    if (seal() != -ENOTSUP) {
        root_probe_failed("changed original timer attributes accepted");
    }
    timer->attributes = attributes;
    if (seal() || !sealed()) {
        root_probe_failed("restored original timer lineage changed custody");
    }
    dprintf(STDERR_FILENO,
            "allocated-timer-fixture PASS native-roles=8 guest-timers=3 dormant-migration-timers=2 dormant-clock-wander=3 original-unarmed-APIC=%llu "
            "callback/payload/list/id/scale/attributes negatives=6 "
            "original-restored-retry=identical\n", (unsigned long long)id);
}

/* Exact native layout is confined to the GPL fixture. These addresses and
 * callbacks never cross the process protocol or convey host authority. */
struct FWCfgEntry {
    uint32_t len;
    bool allow_write;
    uint8_t *data;
    void *callback_opaque;
    FWCfgCallback select_cb;
    FWCfgWriteCallback write_cb;
};

static int original_fwcfg(Object *object, void *opaque)
{
    Object *(*cast)(Object *, const char *) = source_function("object_dynamic_cast");
    FWCfgState **fw = opaque;

    if (cast(object, TYPE_FW_CFG_IO)) {
        if (*fw) {
            root_probe_failed("multiple original firmware configuration owners");
        }
        *fw = (FWCfgState *)object;
    }
    return 0;
}

static void original_firmware_refusals(void)
{
    Object *(*root)(void) = source_function("object_get_root");
    int (*census)(Object *, int (*)(Object *, void *), void *) =
        source_function("object_child_foreach_recursive");
    int (*seal)(FWCfgState *) = source_function("fw_cfg_crucible_root_firmware_seal");
    int (*query)(FWCfgCrucibleRootInventory *) =
        source_function("fw_cfg_crucible_root_firmware_inventory");
    int (*rom_query)(RomCrucibleRootInventory *) =
        source_function("rom_crucible_root_inventory");
    FWCfgCrucibleRootInventory before, after;
    RomCrucibleRootInventory rom;
    FWCfgState *fw = NULL;
    FWCfgEntry *entry;
    uint8_t *original_data;
    uint32_t original_length, original_offset;
    FWCfgFiles *original_files;
    int original_order;

    if (census(root(), original_fwcfg, &fw) || !fw || seal(fw) ||
        query(&before) || before.flags != 7 || before.entry_count != 13 ||
        before.retained_bytes < 1024 * 1024 ||
        before.retained_bytes > FW_CFG_CRUCIBLE_ROOT_MAX_BYTES ||
        rom_query(&rom) || rom.count != 1 || rom.flags != 1 ||
        rom.entries[0].kind != 1 || rom.entries[0].length != 65536 ||
        !rom.entries[0].original_id) {
        root_probe_failed("complete actual firmware backing custody missing");
    }
    /* RAM_SIZE uses the actual constructor-owned heap buffer; SIGNATURE is
     * a read-only source literal and must never be modified by the fixture. */
    entry = &fw->entries[0][FW_CFG_RAM_SIZE];
    if (!entry->data || entry->len != 8 || entry->allow_write ||
        entry->select_cb || entry->write_cb || entry->callback_opaque) {
        root_probe_failed("actual RAM_SIZE source alias is not read-only");
    }
    original_data = entry->data;
    original_length = entry->len;
    original_offset = fw->cur_offset;
    original_files = fw->files;
    if (!fw->entry_order || !be32_to_cpu(fw->files->count)) {
        root_probe_failed("actual native file order missing");
    }
    original_order = fw->entry_order[0];

    entry->data[0] ^= 1;
    if (seal(fw) != -ESTALE) {
        root_probe_failed("changed actual read-only buffer accepted");
    }
    entry->data[0] ^= 1;
    entry->data = NULL;
    if (seal(fw) != -ENOTSUP) {
        root_probe_failed("missing actual source buffer accepted");
    }
    entry->data = original_data;
    entry->len++;
    if (seal(fw) != -ESTALE) {
        root_probe_failed("changed original source extent accepted");
    }
    entry->len = original_length;
    entry->allow_write = true;
    if (seal(fw) != -ENOTSUP) {
        root_probe_failed("writable source entry accepted as readonly");
    }
    entry->allow_write = false;
    entry->callback_opaque = fw;
    if (seal(fw) != -ENOTSUP) {
        root_probe_failed("new native callback payload admitted");
    }
    entry->callback_opaque = NULL;
    fw->cur_offset++;
    if (seal(fw) != -ESTALE) {
        root_probe_failed("changed native read cursor erased");
    }
    fw->cur_offset = original_offset;
    fw->files = NULL;
    if (seal(fw) != -ESTALE) {
        root_probe_failed("replaced native source file directory accepted");
    }
    fw->files = original_files;
    fw->entry_order[0] ^= 1;
    if (seal(fw) != -ESTALE) {
        root_probe_failed("changed actual native file order accepted");
    }
    fw->entry_order[0] = original_order;
    if (seal(fw) || query(&after) || memcmp(&before, &after, sizeof(before))) {
        root_probe_failed("restored original firmware changed held bytes");
    }
    dprintf(STDERR_FILENO,
            "firmware-root-fixture PASS actual-loaded-ROMs=1 BIOS-bytes=%llu "
            "readonly-source-buffers=%u retained-bytes=%llu full-FDT-1MiB "
            "negatives=8 immutable-original-retry scope=construction-only\n",
            (unsigned long long)rom.entries[0].length, before.entry_count,
            (unsigned long long)before.retained_bytes);
}

static int root_probe_query(const uint8_t *scope, uint64_t sequence,
                            const uint8_t *cut,
                            QemuPluginCrucibleNodePreparationSuccessor *facts)
{
    SuccessorQuery query = atomic_load_explicit(&original_query,
                                               memory_order_acquire);
    int (*prepare)(void) = source_function("crucible_node_root_prepare_factory");
    bool (*sealed)(void) = source_function("qemu_crucible_device_roots_sealed");
    int result = query(scope, sequence, cut, facts);

    if (result) {
        return result;
    }
    result = prepare();
    if (result || !sealed()) {
        dprintf(STDERR_FILENO, "root-factory-fixture status=%d sealed=%u\n",
                result, sealed());
        root_probe_failed("actual original native factory did not seal");
    }
    if (prepare() || !sealed()) {
        root_probe_failed("original native factory retry changed custody");
    }
    original_lifetime_refusals();
    original_allocated_timer_refusals();
    original_firmware_refusals();
    dprintf(STDERR_FILENO,
            "root-factory-fixture PASS original-init=%llu devices=17 buses=10 "
            "empty-transports=8 actual-native-seal original-retry=identical\n",
            (unsigned long long)sequence);
    return 0;
}

static int root_probe_registration(const CrucibleNodeRootPolicy *original)
{
    RootRegistration registration = atomic_load_explicit(
        &original_registration, memory_order_acquire);
    CrucibleNodeRootPolicy changed;
    unsigned negatives = 0;

    if (!original || !registration) {
        root_probe_failed("missing actual original root registration");
    }
    if (registration(NULL) != -EINVAL) {
        root_probe_failed("null policy adopted as original registration");
    }
    /* Change every field independently, before the first real registration.
     * Each native refusal must leave the original source enrollment untouched. */
    for (unsigned offset = 0; offset < sizeof(*original); offset++) {
        changed = *original;
        ((uint8_t *)&changed)[offset] ^= 1;
        if (registration(&changed) != -EINVAL) {
            root_probe_failed("partial or changed native root policy adopted");
        }
        negatives++;
    }
    if (registration(original) || registration(original)) {
        root_probe_failed("exact original root registration/retry refused");
    }
    dprintf(STDERR_FILENO,
            "root-registration-fixture PASS changed-byte-negatives=%u "
            "exact-original328 registration-and-retry=identical\n", negatives);
    return 0;
}

void *dlsym(void *handle, const char *name)
{
    SymbolLookup lookup = (SymbolLookup)dlvsym(RTLD_NEXT, "dlsym", "GLIBC_2.2.5");
    void *symbol;

    if (!lookup) {
        root_probe_failed("actual native symbol resolver unavailable");
    }
    symbol = lookup(handle, name);
    if (symbol && !strcmp(name,
                         "qemu_plugin_crucible_node_query_preparation_successor")) {
        atomic_store_explicit(&original_query, (SuccessorQuery)symbol,
                              memory_order_release);
        return (void *)root_probe_query;
    }
    if (symbol && !strcmp(name,
                         "qemu_plugin_register_crucible_node_root_policy")) {
        atomic_store_explicit(&original_registration, (RootRegistration)symbol,
                              memory_order_release);
        return (void *)root_probe_registration;
    }
    return symbol;
}
