"""Compile actual QEMU/kernel response-byte source with explicit native plumbing.

The source-owned ABI, kernel byte journal and x86/ARM consumers, QEMU canonical
capture/private handler/STEP/retry paths and original receipt validator are
compiled unchanged. CPU scheduling, VM clock, FPU/registers, buses, QMP allocation
and syscall dispatch are modeled. This is not hardware or whole-node evidence.
"""
from pathlib import Path
import importlib.util
import re
import subprocess
import sys


def record(text, name):
    match = re.search(r'(?:typedef )?(?:struct|enum) ' + name + r'\s*\{', text)
    if not match:
        raise ValueError('Missing actual native record: ' + name)
    end = text.index(';', text.index('\n}', match.start())) + 1
    return text[match.start():end] + '\n'


def function(text, name):
    match = re.search(r'^(?:static )?[^;{}\n]+\b' + name + r'\s*\([^;{}]*\)\s*\{', text, re.M)
    if not match:
        raise ValueError('Missing actual native function: ' + name)
    cursor = text.index('{', match.start()) + 1
    depth = 1
    while depth:
        depth += (text[cursor] == '{') - (text[cursor] == '}')
        cursor += 1
    return text[match.start():cursor] + '\n'


QEMU_CONTEXT = r'''
typedef struct CPUState CPUState;
typedef int QemuMutex;
typedef int MemTxAttrs;
@RECORDS@
typedef struct KVMState { @FIELDS@ } KVMState;
struct CPUState {
    int cpu_index;
    uint64_t native_id;
    bool stopped;
    struct kvm_run *kvm_run;
};
typedef struct Error { bool set; } Error;
static KVMState native, *kvm_state = &native;
static CPUState original_cpu;
static struct fixture kernel_fixture;
static bool model_bql = true, paused = true, enabled = true, autostart;
static bool allocation_fails, extension_missing, malformed_reply;
static bool stopped_owner = true;
static unsigned native_queries, native_steps, vm_queries, kernel_enables;
static unsigned handler_calls;
static unsigned char bus_reply;
static bool bus_fails;
static int address_space_memory;
#define MEMTX_OK 0
#define QEMU_CRUCIBLE_BUILD_ID "1111111111111111111111111111111111111111111111111111111111111111"
#define QEMU_CRUCIBLE_ATOMIC_PATCH_HASH "2222222222222222222222222222222222222222222222222222222222222222"
#define QEMU_CRUCIBLE_RESPONSE_BYTES_MAX_VCPUS 128
#define QEMU_CRUCIBLE_RESPONSE_BYTES_COMPONENTS 7
#define QEMU_CRUCIBLE_CLOCK_ARM_COMPONENTS 228
#define QEMU_CRUCIBLE_CLOCK_V3_COMPONENTS 159
#define KVM_CAP_CRUCIBLE_CLOCK_V2 0xa026
#define KVM_CAP_CRUCIBLE_CLOCK_V3 0xa027
#define KVM_CRUCIBLE_CLOCK_QUERY 4
#define KVM_ENABLE_CAP 1
#define KVM_CAP_CRUCIBLE_RESPONSE_BYTES_V1 0xa02a
#define KVM_CRUCIBLE_RESPONSE_BYTES 0xd8
#define G_STATIC_ASSERT(condition) _Static_assert(condition, "actual source ABI")
#define qatomic_load_acquire(pointer) (*(pointer))
#define g_try_new0(type, count) (allocation_fails ? NULL : calloc(count, sizeof(type)))
#define g_try_malloc0(size) (allocation_fails ? NULL : calloc(1, size))
#define g_free(pointer) free(pointer)
#define error_report(...) ((void)0)
#define error_setg(errp, ...) ((*(errp))->set = true)
#define CPU_FOREACH(cpu) for ((cpu) = &original_cpu; (cpu); (cpu) = NULL)
#define RUN_STATE_PAUSED 1
#define RUN_STATE_PRELAUNCH 2
static bool bql_locked(void) { return model_bql; }
static bool kvm_enabled(void) { return enabled; }
static bool runstate_check(int value) { return paused && value == RUN_STATE_PAUSED; }
static bool qemu_cpu_is_self(CPUState *cpu) { return cpu == &original_cpu; }
static bool qemu_cpu_native_window_stopped(CPUState *cpu)
{ return cpu == &original_cpu && cpu->stopped && stopped_owner; }
static uint64_t kvm_arch_vcpu_id(CPUState *cpu) { return cpu->native_id; }
static void qemu_mutex_lock(QemuMutex *lock) { assert(!*lock); *lock = 1; }
static void qemu_mutex_unlock(QemuMutex *lock) { assert(*lock); *lock = 0; }
static int kvm_vm_check_extension(KVMState *state, unsigned cap)
{ assert(state == &native && cap == KVM_CAP_CRUCIBLE_RESPONSE_BYTES_V1); return !extension_missing; }
static int kvm_vm_ioctl(KVMState *state, unsigned command, struct kvm_enable_cap *cap)
{
    assert(state == &native && command == KVM_ENABLE_CAP);
    if (cap->cap == KVM_CAP_CRUCIBLE_RESPONSE_BYTES_V1) {
        kernel_enables++;
        return kernel_bytes_configure(&kernel_fixture.vm, cap);
    }
    assert(cap->cap == KVM_CAP_CRUCIBLE_CLOCK_V3 || cap->cap == KVM_CAP_CRUCIBLE_CLOCK_V2);
    struct kvm_crucible_clock *clock = (void *)(uintptr_t)cap->args[0];
    assert(clock->operation == KVM_CRUCIBLE_CLOCK_QUERY);
    vm_queries++;
    clock->window_generation = kernel_fixture.vm.generation;
    clock->coverage = clock->version == 2 ? 228 : 159;
    clock->active = kernel_fixture.vm.crucible_active;
    clock->close_acknowledged = !clock->active;
    return 0;
}
static int kvm_vcpu_ioctl(CPUState *cpu, unsigned command,
                         struct kvm_crucible_response_bytes *packet)
{
    assert(cpu == &original_cpu && command == KVM_CRUCIBLE_RESPONSE_BYTES);
    if (packet->operation == KVM_CRUCIBLE_RESPONSE_BYTES_QUERY)
        native_queries++;
    else
        native_steps++;
    int result = kernel_bytes_ioctl(&kernel_fixture.cpu, packet);
    if (result >= 0 && malformed_reply)
        packet->native_vcpu_id++;
    return result;
}
static void qapi_free_CrucibleKvmResponseBytesInfo(CrucibleKvmResponseBytesInfo *info)
{
    if (info) { free(info->qemu_build_id); free(info->qemu_source_hash);
        free(info->data_base64); free(info); }
}
/* Encoding is serialization plumbing; real GLib is compiled in the native TU. */
static size_t g_base64_encode_step(const unsigned char *data, size_t size,
    bool breaks, char *output, int *state, int *save)
{ (void)breaks; (void)state; (void)save; memcpy(output, data, size); return size; }
static size_t g_base64_encode_close(bool breaks, char *output, int *state, int *save)
{ (void)breaks; (void)output; (void)state; (void)save; return 0; }
static int address_space_rw(int *space, uint64_t address, MemTxAttrs attrs,
    void *buffer, unsigned length, bool write)
{
    assert(space == &address_space_memory && attrs == 17);
    assert(address == 0x1000 || address == 0x2000);
    assert(length == 4);
    handler_calls++;
    if (write)
        assert(((unsigned char *)buffer)[0] == bus_reply);
    else
        memset(buffer, bus_reply, length);
    return bus_fails ? -1 : MEMTX_OK;
}
static void kvm_handle_io(uint64_t address, MemTxAttrs attrs, void *buffer,
    unsigned direction, unsigned size, unsigned count)
{
    assert(address == 0x1234 && attrs == 17 && size == 4 && count == 1024);
    handler_calls++;
    if (direction)
        assert(((unsigned char *)buffer)[0] == bus_reply &&
            ((unsigned char *)buffer)[4095] == bus_reply);
    else
        memset(buffer, bus_reply, size * count);
}
'''

CASES = r'''
static Error diagnostic;
static Error *error_pointer = &diagnostic;

static void prepare(void)
{
    memset(&native, 0, sizeof(native));
    memset(&kernel_fixture, 0, sizeof(kernel_fixture));
    kernel_fixture.vm = (struct kvm) {
        .crucible_controlled = true, .crucible_response_enabled = true,
        .crucible_run_return_enabled = true, .generation = 9,
    };
    native.crucible_clock_configured = native.crucible_userspace_configured = true;
    native.crucible_completion_configured = native.crucible_response_service_configured = true;
    native.crucible_window_configured = native.crucible_response_bytes_experiment = true;
    native.crucible_clock_kernel_edition = 3;
    native.crucible_userspace_capacity = 1;
    native.crucible_userspace_exits = calloc(1, sizeof(*native.crucible_userspace_exits));
    native.crucible_response_services = calloc(1, sizeof(*native.crucible_response_services));
    native.crucible_window_vcpus = calloc(1, sizeof(*native.crucible_window_vcpus));
    native.crucible_window_returns = calloc(1, sizeof(*native.crucible_window_returns));
    assert(kvm_crucible_response_bytes_configure(&native) == 0);
    kernel_fixture.cpu.kvm = &kernel_fixture.vm;
    kernel_fixture.cpu.run = &kernel_fixture.run;
    kernel_fixture.cpu.vcpu_id = 13;
    kernel_fixture.cpu.crucible_run_return.original.invocation = 21;
    kernel_fixture.cpu.crucible_run_return.original.generation_end = 9;
    assert(kernel_bytes_vcpu_init(&kernel_fixture.cpu) == 0);
    original_cpu = (CPUState) { .cpu_index = 0, .native_id = 13,
        .stopped = true, .kvm_run = &kernel_fixture.run };
    native.crucible_userspace_exits[0] = (CrucibleKvmUserspaceExit) {
        .assigned = true, .kernel_vcpu_id = 13,
    };
    native.crucible_window_vcpus[0] = (CrucibleKvmWindowVcpu) {
        .assigned = true, .original_cpu = &original_cpu,
    };
    native.crucible_window_return_count = 1;
    native.crucible_window_generation = 9;
    native.crucible_window_phase = CRUCIBLE_KVM_WINDOW_CLOSED;
    model_bql = paused = enabled = stopped_owner = true;
    malformed_reply = fail_result_copy = fail_source_copy = false;
    memset(&diagnostic, 0, sizeof(diagnostic));
}

static void release(void)
{
    kernel_bytes_vcpu_destroy(&kernel_fixture.cpu);
    kvm_crucible_response_bytes_destroy(&native);
    free(native.crucible_userspace_exits); free(native.crucible_response_services);
    free(native.crucible_window_vcpus); free(native.crucible_window_returns);
}

static void original_birth(bool write, bool more)
{
    mmio_birth(&kernel_fixture, write, more);
    struct kvm_crucible_response_bytes packet = query(&kernel_fixture);
    struct kvm_crucible_run_return receipt = {
        .version = 1, .operation = KVM_CRUCIBLE_RUN_RETURN_QUERY,
        .expected_invocation = 21, .invocation = 21,
        .generation_begin = 9, .generation_end = 9, .run_result = 0,
        .native_vcpu_id = 13, .response_sequence = packet.pending_sequence,
        .response_consumed = packet.consumed_sequence,
        .response_revision = packet.revision, .response_phase = packet.phase,
        .flags = KVM_CRUCIBLE_RUN_RETURN_RETURNED |
            KVM_CRUCIBLE_RUN_RETURN_CLOCK_ENTERED | KVM_CRUCIBLE_RUN_RETURN_BEGIN_ACTIVE,
    };
    native.crucible_window_returns[0] = (CrucibleKvmOriginalReturn) {
        .receipt = receipt, .generation = 9, .expected_invocation = 21,
        .issued = true, .receipt_known = true,
    };
    assert(kvm_crucible_response_bytes_capture_return(&native, &original_cpu, &receipt));
    assert(!response_bytes_query_valid(&packet, 21, 14));
    CrucibleKvmUserspaceExit *entry = &native.crucible_userspace_exits[0];
    entry->exit_sequence = packet.pending_sequence;
    entry->exit_reason = packet.reason;
    entry->phase = CRUCIBLE_KVM_USERSPACE_HANDLING;
}

static void actual_handler(unsigned char reply)
{
    CrucibleKvmUserspaceExit *entry = &native.crucible_userspace_exits[0];
    native.crucible_response_services[0] = (CrucibleKvmResponseService) {
        .issued = true, .executing = true, .exit_sequence = entry->exit_sequence,
    };
    native.crucible_response_service_active = true;
    model_bql = false;
    CrucibleKvmResponseGeometry *geometry =
        kvm_crucible_response_bytes_dispatch_geometry(&native, &original_cpu);
    assert(geometry);
    assert(geometry->reason == KVM_EXIT_IO ? geometry->address == 0x1234 :
        geometry->address == (entry->exit_sequence == 1 ? 0x1000 : 0x2000));
    bus_reply = reply;
    assert(kvm_crucible_dispatch_original_response(&original_cpu, 17) == 0);
    assert(native.crucible_response_bytes[0].handler_completed);
    entry->phase = CRUCIBLE_KVM_USERSPACE_PENDING;
    assert(kvm_crucible_response_bytes_geometry(&native, &original_cpu, entry, true));
    native.crucible_response_services[0].executing = false;
    native.crucible_response_services[0].completed = true;
    native.crucible_response_services[0].collected = true;
    native.crucible_response_service_active = false;
    model_bql = true;
    /* Actual service collection consumes the retained More revision credit. */
    native.crucible_userspace_reserved_revisions -= entry->reserved_revisions;
    entry->reserved_revisions = 0;
}

static CrucibleKvmResponseBytesInfo *complete(uint64_t id, uint64_t sequence)
{
    diagnostic.set = false;
    return qmp_x_crucible_kvm_response_bytes(
        CRUCIBLE_KVM_RESPONSE_BYTES_OPERATION_COMPLETE, 0, 9, 21, id, sequence,
        &error_pointer);
}

static void read_more_retry(void)
{
    prepare(); original_birth(false, true);
    /* Shared mapping substitution must never change private handler geometry. */
    kernel_fixture.run.exit_reason = KVM_EXIT_IO;
    kernel_fixture.run.mmio.phys_addr = 0xdead;
    memset(kernel_fixture.run.mmio.data, 0xff, 8);
    actual_handler(0x31);
    unsigned before = callbacks;
    fail_result_copy = true;
    CrucibleKvmResponseBytesInfo *info = complete(1, 1);
    assert(info && !info->result_known && info->uncertain_effects);
    assert(info->payload_kind == CRUCIBLE_KVM_RESPONSE_BYTES_PAYLOAD_KIND_ORIGINAL_REQUEST);
    assert(info->native_phase == KVM_CRUCIBLE_COMPLETION_UNKNOWN);
    assert(info->expected_revision == 1 && info->data_length == 4);
    assert(callbacks == before + 1 && kernel_fixture.first[0] == 0x31);
    qapi_free_CrucibleKvmResponseBytesInfo(info);
    fail_result_copy = false;
    info = complete(1, 1);
    assert(info && info->result_known && info->native_phase == KVM_CRUCIBLE_COMPLETION_MORE);
    assert(info->payload_kind == CRUCIBLE_KVM_RESPONSE_BYTES_PAYLOAD_KIND_NATIVE_RESULT);
    assert(callbacks == before + 1 && info->uncertain_effects);
    /* Historical uncertainty refuses any new callback/native grant. */
    assert(native.crucible_userspace_exits[0].phase == CRUCIBLE_KVM_USERSPACE_UNKNOWN);
    qapi_free_CrucibleKvmResponseBytesInfo(info);
    assert(complete(2, 2) == NULL && diagnostic.set);
    release();

    prepare(); original_birth(false, true); actual_handler(0x41);
    info = complete(1, 1);
    assert(info && info->result_known && info->native_phase == KVM_CRUCIBLE_COMPLETION_MORE);
    assert(kernel_fixture.first[0] == 0x41 && native.crucible_userspace_exits[0].phase == CRUCIBLE_KVM_USERSPACE_HANDLING);
    CrucibleKvmResponseBytesInfo original = *info;
    qapi_free_CrucibleKvmResponseBytesInfo(info);
    actual_handler(0x52);
    native.crucible_response_service_active = true;
    kernel_fixture.vm.generation = 99;
    before = callbacks;
    unsigned before_queries = vm_queries;
    info = complete(1, 1);
    assert(info && info->result_known && info->pending_sequence == original.pending_sequence);
    assert(callbacks == before && vm_queries == before_queries && native.crucible_response_service_active);
    qapi_free_CrucibleKvmResponseBytesInfo(info);
    native.crucible_response_service_active = false;
    kernel_fixture.vm.generation = 9;
    info = complete(2, 2);
    assert(info && info->result_known && info->native_phase == KVM_CRUCIBLE_COMPLETION_DONE);
    assert(kernel_fixture.second[0] == 0x52 && native.crucible_userspace_exits[0].phase == CRUCIBLE_KVM_USERSPACE_READY);
    qapi_free_CrucibleKvmResponseBytesInfo(info);
    diagnostic.set = false;
    info = qmp_x_crucible_kvm_response_bytes(CRUCIBLE_KVM_RESPONSE_BYTES_OPERATION_QUERY,
        0, 9, 21, 0, 0, &error_pointer);
    assert(info && info->result_known && !diagnostic.set);
    assert(info->payload_kind == CRUCIBLE_KVM_RESPONSE_BYTES_PAYLOAD_KIND_NATIVE_QUERY);
    assert(!info->kernel_source_qualified && !info->profile_qualified && !info->device_closure);
    qapi_free_CrucibleKvmResponseBytesInfo(info);
    release();
}

static void write_and_refusal(void)
{
    prepare(); kernel_fixture.first[0] = 0x63; original_birth(true, false);
    memset(kernel_fixture.run.mmio.data, 0xa4, 8);
    kernel_fixture.run.mmio.len = 8;
    actual_handler(0x63);
    unsigned before = callbacks;
    native.crucible_window_returns[0].issued = false;
    assert(!complete(1, 1) && callbacks == before);
    native.crucible_window_returns[0].issued = true;
    stopped_owner = false;
    assert(!complete(1, 1) && callbacks == before);
    stopped_owner = true;
    kernel_fixture.vm.crucible_active = true;
    assert(!complete(1, 1) && callbacks == before);
    kernel_fixture.vm.crucible_active = false;
    kernel_fixture.vm.generation++;
    assert(!complete(1, 1) && callbacks == before);
    kernel_fixture.vm.generation--;
    allocation_fails = true;
    assert(!complete(1, 1) && callbacks == before);
    allocation_fails = false;
    CrucibleKvmResponseBytesInfo *info = complete(1, 1);
    assert(info && info->result_known && info->native_phase == KVM_CRUCIBLE_COMPLETION_DONE);
    assert(callbacks == before + 1 && kernel_fixture.first[0] == 0x63);
    qapi_free_CrucibleKvmResponseBytesInfo(info);
    release();
}

static void pio_native_producer(void)
{
    prepare();
    u8 original[4096];
    memset(original, 0x67, sizeof(original));
    assert(emulator_pio_in_out(&kernel_fixture.cpu, 4, 0x1234,
        original, 1024, false) == 0);
    assert(kvm_crucible_response_birth(&kernel_fixture.cpu.crucible_response));
    struct kvm_crucible_response_bytes packet = query(&kernel_fixture);
    struct kvm_crucible_run_return receipt = {
        .version = 1, .operation = KVM_CRUCIBLE_RUN_RETURN_QUERY,
        .expected_invocation = 21, .invocation = 21,
        .generation_begin = 9, .generation_end = 9, .run_result = 0,
        .native_vcpu_id = 13, .response_sequence = packet.pending_sequence,
        .response_consumed = packet.consumed_sequence,
        .response_revision = packet.revision, .response_phase = packet.phase,
        .flags = KVM_CRUCIBLE_RUN_RETURN_RETURNED |
            KVM_CRUCIBLE_RUN_RETURN_CLOCK_ENTERED | KVM_CRUCIBLE_RUN_RETURN_BEGIN_ACTIVE,
    };
    native.crucible_window_returns[0] = (CrucibleKvmOriginalReturn) {
        .receipt = receipt, .generation = 9, .expected_invocation = 21,
        .issued = true, .receipt_known = true,
    };
    assert(kvm_crucible_response_bytes_capture_return(&native, &original_cpu, &receipt));
    native.crucible_userspace_exits[0].exit_sequence = 1;
    native.crucible_userspace_exits[0].phase = CRUCIBLE_KVM_USERSPACE_HANDLING;
    native.crucible_userspace_exits[0].response.response[0]++;
    assert(!kvm_crucible_response_bytes_geometry(&native, &original_cpu,
        &native.crucible_userspace_exits[0], false));
    native.crucible_userspace_exits[0].response.response[0]--;
    memset(original, 0x91, sizeof(original));
    memset(kernel_fixture.cpu.arch.pio_data, 0x92, 4096);
    kernel_fixture.run.io.count = 1;
    actual_handler(0x67);
    CrucibleKvmResponseBytesInfo *info = complete(1, 1);
    assert(info && info->result_known && info->native_phase == KVM_CRUCIBLE_COMPLETION_DONE);
    qapi_free_CrucibleKvmResponseBytesInfo(info);
    release();
}

static void unknown_and_metadata_refusal(void)
{
    prepare(); original_birth(false, false);
    CrucibleKvmUserspaceExit *entry = &native.crucible_userspace_exits[0];
    native.crucible_response_services[0] = (CrucibleKvmResponseService) {
        .issued = true, .executing = true, .exit_sequence = 1,
    };
    native.crucible_response_service_active = true;
    model_bql = false;
    entry->response.address++;
    unsigned before = handler_calls;
    assert(kvm_crucible_dispatch_original_response(&original_cpu, 17) == -ESTALE);
    assert(handler_calls == before && !native.crucible_response_bytes[0].handler_completed);
    entry->response.address--;
    bus_reply = 0x75;
    bus_fails = true;
    assert(kvm_crucible_dispatch_original_response(&original_cpu, 17) == -EIO);
    assert(handler_calls == before + 1 && native.crucible_userspace_faulted);
    assert(entry->uncertain_effects && !native.crucible_response_bytes[0].handler_completed);
    model_bql = true;
    native.crucible_response_service_active = false;
    bus_fails = false;
    assert(!complete(1, 1));
    release();

    prepare(); original_birth(false, false); actual_handler(0x76);
    malformed_reply = true;
    unsigned before_callbacks = callbacks;
    CrucibleKvmResponseBytesInfo *info = complete(1, 1);
    assert(info && !info->result_known && info->uncertain_effects);
    qapi_free_CrucibleKvmResponseBytesInfo(info);
    malformed_reply = false;
    info = complete(1, 1);
    assert(info && info->result_known && info->uncertain_effects);
    assert(callbacks == before_callbacks + 1);
    qapi_free_CrucibleKvmResponseBytesInfo(info);
    assert(native.crucible_userspace_exits[0].phase == CRUCIBLE_KVM_USERSPACE_UNKNOWN);
    release();
}

static void canonical_geometry_and_credit_guards(void)
{
    prepare(); original_birth(false, false);
    struct kvm_crucible_response_bytes packet = native.crucible_response_bytes[0].canonical;
    packet.reserved[0] = 1;
    assert(!response_bytes_packet_valid(&packet));
    packet = native.crucible_response_bytes[0].canonical;
    packet.data[4095] = 1;
    assert(!response_bytes_packet_valid(&packet));
    packet = native.crucible_response_bytes[0].canonical;
    packet.length = 9;
    assert(!response_bytes_packet_valid(&packet));
    packet = native.crucible_response_bytes[0].canonical;
    packet.data_length = 4;
    assert(!response_bytes_packet_valid(&packet));
    original_cpu.native_id++;
    assert(!response_bytes_journal(&native, &original_cpu));
    original_cpu.native_id--;
    CrucibleKvmUserspaceExit *entry = &native.crucible_userspace_exits[0];
    native.crucible_response_services[0] = (CrucibleKvmResponseService) {
        .issued = true, .executing = false, .exit_sequence = 1,
    };
    native.crucible_response_service_active = true;
    model_bql = false;
    assert(!kvm_crucible_response_bytes_dispatch_geometry(&native, &original_cpu));
    native.crucible_response_services[0].executing = true;
    native.crucible_response_service_active = false;
    assert(!kvm_crucible_response_bytes_dispatch_geometry(&native, &original_cpu));
    native.crucible_response_service_active = true;
    native.crucible_response_services[0].exit_sequence = 2;
    assert(!kvm_crucible_response_bytes_dispatch_geometry(&native, &original_cpu));
    native.crucible_response_service_active = false;
    model_bql = true;
    actual_handler(0x77);
    unsigned before = native_steps;
    native.crucible_userspace_revision = UINT64_MAX - 2;
    assert(!complete(1, 1) && native_steps == before);
    native.crucible_userspace_revision = 0;
    entry->response.length++;
    assert(!complete(1, 1) && native_steps == before);
    entry->response.length--;
    CrucibleKvmResponseBytesInfo *info = complete(1, 1);
    assert(info && info->result_known);
    qapi_free_CrucibleKvmResponseBytesInfo(info);
    assert(!complete(1, 2) && native_steps == before + 1);
    release();
}

static void original_configuration_guards(void)
{
    memset(&native, 0, sizeof(native));
    unsigned before = kernel_enables;
    assert(kvm_crucible_response_bytes_configure(&native) == 0);
    assert(kernel_enables == before && !native.crucible_response_bytes);
    native.crucible_response_bytes_experiment = true;
    native.crucible_clock_configured = native.crucible_userspace_configured = true;
    native.crucible_completion_configured = native.crucible_response_service_configured = true;
    native.crucible_window_configured = true;
    native.crucible_clock_kernel_edition = 3;
    native.crucible_userspace_capacity = 1;
    extension_missing = true;
    assert(kvm_crucible_response_bytes_configure(&native) == -ENOTSUP);
    extension_missing = false;
    autostart = true;
    assert(kvm_crucible_response_bytes_configure(&native) == -ENOTSUP);
    autostart = false;
    native.crucible_userspace_capacity = 129;
    assert(kvm_crucible_response_bytes_configure(&native) == -ENOTSUP);
    native.crucible_userspace_capacity = 1;
    native.crucible_completion_configured = false;
    assert(kvm_crucible_response_bytes_configure(&native) == -ENOTSUP);
    native.crucible_completion_configured = true;
    native.crucible_clock_kernel_edition = 1;
    assert(kvm_crucible_response_bytes_configure(&native) == -ENOTSUP);
    native.crucible_clock_kernel_edition = 3;
    allocation_fails = true;
    assert(kvm_crucible_response_bytes_configure(&native) == -ENOMEM);
    allocation_fails = false;
    assert(kernel_enables == before && !native.crucible_response_bytes);
    assert(!response_bytes_source_id(NULL));
    assert(!response_bytes_source_id("1111"));
    assert(!response_bytes_source_id("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
}

static void arm_private_consumer(void)
{
    prepare(); original_birth(false, false);
    use_arm = true;
    kernel_fixture.cpu.arm_length = 4;
    kernel_fixture.cpu.arm_rd = 2;
    actual_handler(0x78);
    memset(kernel_fixture.run.mmio.data, 0x93, 8);
    CrucibleKvmResponseBytesInfo *info = complete(1, 1);
    assert(info && info->result_known && info->native_phase == KVM_CRUCIBLE_COMPLETION_DONE);
    assert(kernel_fixture.cpu.regs[2] == 0x78787878 && kernel_fixture.cpu.pc == 4);
    qapi_free_CrucibleKvmResponseBytesInfo(info);
    use_arm = false;
    release();
}

static void original_native_opacity(void)
{
    prepare(); original_birth(false, false); actual_handler(0x79);
    model_native_opaque = true;
    unsigned before = callbacks;
    CrucibleKvmResponseBytesInfo *info = complete(1, 1);
    assert(info && info->result_known && info->callback_result < 0);
    assert(info->native_phase == KVM_CRUCIBLE_COMPLETION_UNKNOWN);
    assert(info->uncertain_effects && info->opaque_effects);
    assert(native.crucible_userspace_exits[0].opaque_effects);
    assert(kernel_fixture.first[0] == 0x79 && callbacks == before + 1);
    qapi_free_CrucibleKvmResponseBytesInfo(info);
    model_native_opaque = false;
    info = complete(1, 1);
    assert(info && info->result_known && info->opaque_effects);
    assert(callbacks == before + 1);
    qapi_free_CrucibleKvmResponseBytesInfo(info);
    assert(!complete(2, 2));
    release();
}

int main(void)
{
    read_more_retry(); write_and_refusal(); pio_native_producer();
    unknown_and_metadata_refusal();
    canonical_geometry_and_credit_guards();
    original_configuration_guards(); arm_private_consumer();
    original_native_opacity();
    printf("Actual QEMU/private kernel response byte bridge PASS; %u handlers, %u kernel callbacks (native plumbing modeled)\n", handler_calls, callbacks);
    return 0;
}
'''


def main():
    source, kernel, compiler, output = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4])
    output.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).parent
    helper = root / 'fixtures/kernel-bytes-proof.py'
    spec = importlib.util.spec_from_file_location('kernel_byte_proof', helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    uapi = (kernel / 'include/uapi/linux/kvm.h').read_text()
    abi = uapi[uapi.index('#define KVM_CAP_CRUCIBLE_RESPONSE_BYTES_V1'):uapi.index('#define KVM_CAP_CRUCIBLE_CLOCK_V1')]
    abi = '\n'.join(line for line in abi.splitlines() if '_IOWR(' not in line)
    policy = re.sub(r'^#include[^\n]*\n', '', (kernel / 'include/linux/kvm_crucible_completion.h').read_text(), flags=re.M)
    body = re.sub(r'^#include[^\n]*\n', '', (kernel / 'virt/kvm/crucible-response-bytes.c').read_text(), flags=re.M)
    names = sorted(set(re.findall(r'\b(kvm_crucible_response_bytes_\w+)\s*\(', body)))
    renamed = {name: name.replace('kvm_crucible_response_bytes_', 'kernel_bytes_') for name in names}
    macros = '\n'.join('#define ' + name + ' ' + new for name, new in renamed.items())
    undo = '\n'.join('#undef ' + name for name in renamed)
    x86 = (kernel / 'arch/x86/kvm/x86.c').read_text()
    x86_header = (kernel / 'arch/x86/kvm/x86.h').read_text()
    arm = (kernel / 'arch/arm64/kvm/mmio.c').read_text()
    consumers = '\n'.join(module.function(x86_header, name) for name in ('__kvm_prepare_emulated_mmio_exit', 'kvm_prepare_emulated_mmio_exit'))
    consumers += '\n'.join(module.function(x86, name) for name in ('emulator_pio_in_out', 'complete_emulator_pio_in', 'complete_emulated_mmio'))
    consumers += module.function(arm, 'kvm_handle_mmio_return')
    fixture = module.CASES[:module.CASES.index('static void geometry_and_retry')]
    # Only helper setup/birth/query/step plumbing is reused, not its old main.
    fixture = fixture[:fixture.index('static void setup')] + function(module.CASES, 'mmio_birth') + function(module.CASES, 'query')
    prefix = module.PREFIX.replace('struct kvm_enable_cap { u32 flags;', 'struct kvm_enable_cap { u32 cap, flags;')
    prefix += '#include <sys/ioctl.h>\n'
    # The architecture plumbing can expose an actual invalid More producer
    # after its real consumer effect. Native producer/error bookkeeping remains
    # the exact source; this switch models the surrounding architecture fault.
    dispatcher = module.DISPATCH.replace('    return result;\n}', '''    if (model_native_opaque) {
        kvm_crucible_response_bytes_produce(cpu, KVM_EXIT_UNKNOWN,
            0, 0, 0, 0, 0, 0, NULL);
        return -EIO;
    }
    return result;
}''')
    generated = prefix + abi + '\n' + policy + module.CONTEXT + 'static bool model_native_opaque;\n' + macros + '\n' + body + consumers + dispatcher + fixture + '\n' + undo + '\n'
    clock = (source / 'include/system/crucible-kvm-clock.h').read_text()
    window = (source / 'include/system/crucible-kvm-window.h').read_text()
    bytes_header = (source / 'include/system/crucible-kvm-response-bytes.h').read_text()
    state = (source / 'include/system/kvm_int.h').read_text()
    if (source / 'scripts/qapi-gen.py').is_file():
        qapi_dir = output / 'qapi'
        qapi_dir.mkdir(exist_ok=True)
        subprocess.run([sys.executable, str(source / 'scripts/qapi-gen.py'),
                        '-o', str(qapi_dir), '-b', str(source / 'qapi/qapi-schema.json')],
                       check=True, timeout=30)
    else:
        # Thin private mutation copies reuse the independently generated exact
        # schema. Production fixtures always generate from their full source.
        qapi_dir = root / 'generated/qapi'
    qapi = (qapi_dir / 'qapi-types-run-state.h').read_text()
    # Compare every native byte field, not only total length, with the actual
    # kernel UAPI before this model shares its compatible boundary structure.
    qemu_abi = record(bytes_header, 'kvm_crucible_response_bytes')
    qemu_abi = qemu_abi.replace('struct kvm_crucible_response_bytes', 'struct QemuResponseBytesABI')
    generated += qemu_abi
    fields = re.findall(r'^\s+uint\d+_t\s+(\w+)', qemu_abi, re.M)
    fields += ['callback_result']
    assert len(fields) == 25, fields
    for field in fields:
        generated += '_Static_assert(offsetof(struct QemuResponseBytesABI, ' + field + ') == offsetof(struct kvm_crucible_response_bytes, ' + field + '), "' + field + ' native ABI");\n'
    generated += '_Static_assert(sizeof(struct QemuResponseBytesABI) == sizeof(struct kvm_crucible_response_bytes), "complete native ABI");\n'
    records = record(clock, 'kvm_crucible_clock')
    records += '\n'.join(record(clock, name) for name in ('CrucibleKvmUserspacePhase', 'CrucibleKvmResponseGeometry', 'CrucibleKvmCompletionJournal', 'CrucibleKvmUserspaceExit', 'CrucibleKvmResponseService'))
    records += '\n'.join(record(window, name) for name in ('CrucibleKvmWindowPhase', 'CrucibleKvmInitialResponseJournal', 'CrucibleKvmOriginalReturn', 'CrucibleKvmWindowVcpu'))
    records += record(bytes_header, 'CrucibleKvmResponseBytesJournal')
    records += record(qapi, 'CrucibleKvmResponseBytesOperation')
    records += record(qapi, 'CrucibleKvmResponseBytesPayloadKind')
    records += 'typedef struct CrucibleKvmResponseBytesInfo CrucibleKvmResponseBytesInfo;\n' + record(qapi, 'CrucibleKvmResponseBytesInfo')
    fields = state[state.index('    bool crucible_clock_experiment;'):state.index('    int coalesced_mmio;')]
    generated += QEMU_CONTEXT.replace('original_cpu', 'fixture_cpu').replace('@RECORDS@', records).replace('@FIELDS@', fields)
    window_source = (source / 'accel/kvm/crucible-window.c').read_text()
    generated += '\n'.join(function(window_source, name) for name in ('window_vcpu_locked', 'run_receipt_shape', 'kvm_crucible_window_initial_record_locked'))
    native = re.sub(r'^#include[^\n]*\n', '', (source / 'accel/kvm/crucible-response-bytes.c').read_text(), flags=re.M)
    actual_dispatch = function((source / 'accel/kvm/kvm-all.c').read_text(), 'kvm_crucible_dispatch_original_response')
    generated += native + actual_dispatch + CASES.replace('original_cpu', 'fixture_cpu').replace('.fixture_cpu =', '.original_cpu =')
    (output / 'bridge.c').write_text(generated)
    subprocess.run([compiler, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-pthread', str(output / 'bridge.c'), '-o', str(output / 'bridge')], check=True)
    subprocess.run([str(output / 'bridge')], check=True, timeout=30)


if __name__ == '__main__':
    main()
