"""Exercise original response caller and device handler source in a closed model.

Kernel continuation, QAPI definitions, device handler and KVM journal functions
are extracted from their actual sources. CPU-slot scheduling is model plumbing;
the separate slot fixture exercises its actual source with pthreads and death.
Neither proof qualifies KVM execution or complete device/input/output closure.
"""

from pathlib import Path
import re
import subprocess
import sys


def record(body, name):
    match = re.search(r'(?:typedef )?struct ' + name + r' \{', body)
    if match is None:
        raise ValueError('missing actual source record ' + name)
    start = match.start()
    end = body.index(';', body.index('\n}', start)) + 1
    return body[start:end]


def function(body, name, result):
    declaration = re.search(r'^(?:static )?' + result + ' ' + name + r'\(', body, re.M)
    if declaration is None:
        raise ValueError('missing actual source function ' + name)
    end = body.index('\n}\n', declaration.start()) + 3
    return body[declaration.start():end]


PLUMBING = r'''
/* This legacy More fixture never enables canonical-byte mode. */
static CrucibleKvmResponseGeometry *kvm_crucible_response_bytes_dispatch_geometry(
    KVMState *state, CPUState *cpu)
{ (void)state; (void)cpu; assert(false); return NULL; }
static void kvm_crucible_response_bytes_dispatch_done(KVMState *state,
    CPUState *cpu, int result)
{ (void)state; (void)cpu; (void)result; assert(false); }
#include <unistd.h>
#define qatomic_load_acquire(pointer) __atomic_load_n((pointer), __ATOMIC_ACQUIRE)
#define qatomic_store_release(pointer, value) __atomic_store_n((pointer), (value), __ATOMIC_RELEASE)
@CLOCK_CONSTANTS@
@ATTRIBUTES@
@SERVICE@
@OPERATION@
typedef struct CrucibleKvmResponseServiceInfo CrucibleKvmResponseServiceInfo;
@INFO@
typedef int (*QemuCpuPausedServiceFunc)(CPUState *, uint64_t, uint64_t);
static CrucibleKvmResponseService original_service;
static struct {
    uint64_t native_id, operation_id, sequence;
    QemuCpuPausedServiceFunc callback;
    int result;
    bool enrolled, active, completed;
} model_slot;
static bool model_bql = true, model_cpu_thread;
static bool slot_busy, fail_transaction;
static unsigned slot_submissions, device_transactions;
static MemTxAttrs observed_attributes;
typedef int AddressSpace;
static AddressSpace address_space_memory = 1, address_space_io = 2;
#define MEMTX_OK 0

static bool qemu_cpu_is_self(CPUState *cpu)
{
    assert(cpu == &fixture_cpu);
    return model_cpu_thread;
}

static uint32_t address_space_rw(AddressSpace *space, uint64_t address,
                                 MemTxAttrs attributes, void *bytes,
                                 uint32_t length, bool is_write)
{
    assert(!model_bql && model_cpu_thread);
    assert(space == &address_space_memory || space == &address_space_io);
    observed_attributes = attributes;
    device_transactions++;
    if (!is_write) {
        memset(bytes, 0x5a, length);
    }
    return fail_transaction ? 1 : 0;
}

static int qemu_cpu_paused_service_enroll(CPUState *cpu, uint64_t native_id,
                                         QemuCpuPausedServiceFunc callback)
{
    assert(model_bql && cpu == &fixture_cpu);
    if (cpu->created || model_slot.enrolled) {
        return -EBUSY;
    }
    model_slot.enrolled = true;
    model_slot.native_id = native_id;
    model_slot.callback = callback;
    return 0;
}

static int qemu_cpu_paused_service_submit(CPUState *cpu, uint64_t native_id,
                                         uint64_t operation_id, uint64_t sequence)
{
    assert(model_bql && cpu == &fixture_cpu);
    if (!model_slot.enrolled || native_id != model_slot.native_id || slot_busy ||
        model_slot.active || operation_id != model_slot.operation_id + 1) {
        return -EBUSY;
    }
    model_slot.operation_id = operation_id;
    model_slot.sequence = sequence;
    model_slot.active = true;
    model_slot.completed = false;
    slot_submissions++;
    return 0;
}

static int qemu_cpu_paused_service_collect(CPUState *cpu, uint64_t native_id,
                                          uint64_t operation_id, uint64_t sequence,
                                          int *result)
{
    assert(model_bql && cpu == &fixture_cpu);
    if (!model_slot.enrolled || native_id != model_slot.native_id ||
        operation_id != model_slot.operation_id || sequence != model_slot.sequence) {
        return -ESTALE;
    }
    if (!model_slot.completed) {
        return -EAGAIN;
    }
    *result = model_slot.result;
    if (*result >= 0) {
        model_slot.active = false;
    }
    return 0;
}
'''


TESTS = r'''
static void reset_service(bool io_more)
{
    reset();
    memset(&original_service, 0, sizeof(original_service));
    memset(&model_slot, 0, sizeof(model_slot));
    native.crucible_response_service_configured = true;
    native.crucible_response_services = &original_service;
    fixture_cpu.created = false;
    assert(kvm_crucible_response_service_bind_vcpu(&native, &fixture_cpu) == 0);
    fixture_cpu.created = true;
    original_entry.phase = CRUCIBLE_KVM_USERSPACE_HANDLING;
    assert(kvm_crucible_response_service_retain_attrs(&native, &fixture_cpu,
        (MemTxAttrs){ .secure = 1, .user = 1, .requester_id = 123 }));
    original_entry.phase = CRUCIBLE_KVM_USERSPACE_PENDING;
    slot_busy = fail_transaction = false;
    slot_submissions = device_transactions = 0;
    native_more = true;
    model_more_io = io_more;
    g_free(command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 1, 1, false));
    assert(original_entry.phase == CRUCIBLE_KVM_USERSPACE_HANDLING);
    assert(original_entry.exit_sequence == 2 && original_entry.reserved_revisions == 1);
}

static CrucibleKvmResponseServiceInfo *service_command(
    CrucibleKvmResponseServiceOperation operation, uint64_t completion_id,
    uint64_t sequence, bool refused)
{
    Error error = { 0 }, *pointer = &error;
    CrucibleKvmResponseServiceInfo *info = qmp_x_crucible_kvm_response_service(
        operation, 0, completion_id, sequence, &pointer);

    assert(error.set == refused && (info == NULL) == refused);
    if (info) {
        assert(!info->device_closure && !info->input_custody &&
               !info->output_custody && !info->profile_qualified);
    }
    return info;
}

static void execute_callback(void)
{
    assert(model_slot.active && !model_slot.completed && model_bql);
    model_bql = false;
    model_cpu_thread = true;
    model_slot.result = model_slot.callback(&fixture_cpu, model_slot.operation_id,
                                            model_slot.sequence);
    model_slot.completed = true;
    model_cpu_thread = false;
    model_bql = true;
}

static void caller_tests(void)
{
    CrucibleKvmResponseServiceInfo *info;
    unsigned initial_steps;

    reset_service(false);
    initial_steps = kernel_steps;
    assert(!service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_POLL, 1, 2, true));
    info = service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT, 1, 2, false);
    assert(info->submitted && !info->completed && !info->result_known);
    g_free(info); /* Lost host reply cannot duplicate the original callback. */
    g_free(service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT, 1, 2, false));
    assert(slot_submissions == 1 && device_transactions == 0);
    assert(!service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT, 1, 3, true));
    info = service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_POLL, 1, 2, false);
    assert(!info->completed && !info->result_known && native.crucible_response_service_active);
    g_free(info);
    assert(!command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 2, 2, true));
    execute_callback();
    assert(device_transactions == 1 && kernel_steps == initial_steps);
    assert(observed_attributes.secure && observed_attributes.user &&
           observed_attributes.requester_id == 123);
    assert(original_entry.phase == CRUCIBLE_KVM_USERSPACE_PENDING &&
           !original_entry.reserved_revisions);
    assert(native.crucible_response_service_active);
    info = service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_POLL, 1, 2, false);
    assert(info->completed && info->result_known && info->callback_result == 0);
    assert(!native.crucible_response_service_active && !model_slot.active);
    g_free(info);
    g_free(service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_POLL, 1, 2, false));
    assert(device_transactions == 1 && slot_submissions == 1);
    /* Cached older scope cannot release another original handler's custody. */
    native.crucible_response_service_active = true;
    g_free(service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_POLL, 1, 2, false));
    assert(native.crucible_response_service_active);
    native.crucible_response_service_active = false;
    native_more = false;
    g_free(command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 2, 2, false));
    assert(original_entry.phase == CRUCIBLE_KVM_USERSPACE_READY && kernel_steps == 2);

    reset_service(true);
    initial_steps = kernel_steps;
    g_free(service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT, 1, 2, false));
    execute_callback();
    assert(device_transactions == 3 && kernel_steps == initial_steps);
    for (unsigned index = 0; index < 6; index++) {
        assert(run_bytes[4096 + index] == 0x5a);
    }
    info = service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_POLL, 1, 2, false);
    assert(info->result_known && info->callback_result == 0);
    g_free(info);

    reset_service(false);
    fail_transaction = true;
    g_free(service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT, 1, 2, false));
    execute_callback();
    info = service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_POLL, 1, 2, false);
    assert(info->result_known && info->callback_result == -EIO && info->uncertain_effects);
    assert(native.crucible_response_service_active && model_slot.active);
    assert(original_entry.phase == CRUCIBLE_KVM_USERSPACE_UNKNOWN);
    assert(original_entry.reserved_revisions == 1 &&
           native.crucible_userspace_reserved_revisions == 1);
    assert(!kvm_crucible_userspace_allow_state_put(&native, &fixture_cpu));
    g_free(info);

    reset_service(false);
    g_free(service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT, 1, 2, false));
    fixture_cpu.kvm_run->mmio.phys_addr++;
    execute_callback();
    assert(device_transactions == 0 && original_entry.uncertain_effects);

    reset_service(false);
    original_service.attributes_known = false;
    assert(!service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT, 1, 2, true));
    assert(slot_submissions == 0);
    reset_service(false);
    clock_active = true;
    assert(!service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT, 1, 2, true));
    assert(slot_submissions == 0);
    reset_service(false);
    slot_busy = true;
    assert(!service_command(CRUCIBLE_KVM_RESPONSE_SERVICE_OPERATION_SUBMIT, 1, 2, true));
    assert(!original_service.issued && slot_submissions == 0);

    reset();
    native.crucible_response_service_experiment = true;
    native.crucible_completion_configured = false;
    assert(kvm_crucible_response_service_configure(&native) == -ENOTSUP);
    native.crucible_completion_configured = true;
    allocation_fails = true;
    assert(kvm_crucible_response_service_configure(&native) == -ENOMEM);
    allocation_fails = false;
    assert(kvm_crucible_response_service_configure(&native) == 0);
    kvm_crucible_response_service_destroy(&native);
    assert(!native.crucible_response_service_configured);
    puts("Actual response/QAPI/handler source model PASS; native qualification absent");
}

int main(void)
{
    assert(original_completion_tests() == 0);
    caller_tests();
    return 0;
}
'''


def main():
    if len(sys.argv) != 6:
        raise SystemExit("usage: model.py SOURCE AOS_CC OUTPUT KERNEL_PATCH COMPLETION_MODEL")
    source, compiler, output, kernel, baseline = (
        Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4]), Path(sys.argv[5])
    )
    output.mkdir(parents=True, exist_ok=True)
    # Only an incomplete declaration is needed for the optional-disabled
    # original model's new private pointer. Keep all old assertions intact.
    adapted = baseline.read_text().replace(
        'typedef struct KVMState { @FIELDS@ } KVMState;',
        'typedef struct CrucibleKvmResponseService CrucibleKvmResponseService;\n'
        'typedef struct KVMState { @FIELDS@ } KVMState;',
    )
    script = output / 'completion-model-disabled.py'
    script.write_text(adapted)
    old_output = output / 'completion-disabled'
    subprocess.run([sys.executable, str(script), str(source), compiler,
                    str(old_output), str(kernel)], check=True)
    generated = (old_output / 'completion.c').read_text()
    generated = generated.replace('int main(void)', 'int original_completion_tests(void)')
    generated = generated.replace('static bool bql_locked(void) { return true; }',
                                  'static bool bql_locked(void) { return model_bql; }')
    # Define the operational flag before the original source functions use it.
    generated = generated.replace('static bool native_enabled =',
                                  'static bool model_bql = true, model_more_io;\n'
                                  'static bool native_enabled =')
    # Extend only the model's architecture callback plumbing to issue a genuine
    # original IO-shaped More result. All kernel policy and source callers stay
    # unmodified; this is not a claim of executing a hardware IO instruction.
    old_more = '''    if (native_more) {
        cpu->kvm_run->mmio.phys_addr += 8;
        cpu->kvm_run->mmio.len = 4;
    }'''
    assert generated.count(old_more) == 1
    generated = generated.replace(old_more, '''    if (native_more && model_more_io) {
        cpu->kvm_run->exit_reason = KVM_EXIT_IO;
        cpu->kvm_run->io.direction = KVM_EXIT_IO_IN;
        cpu->kvm_run->io.size = 2;
        cpu->kvm_run->io.count = 3;
        cpu->kvm_run->io.port = 0x72;
        cpu->kvm_run->io.data_offset = 4096;
    } else if (native_more) {
        cpu->kvm_run->mmio.phys_addr += 8;
        cpu->kvm_run->mmio.len = 4;
    }''')
    header = (source / 'include/system/crucible-kvm-clock.h').read_text()
    attributes = (source / 'include/exec/memattrs.h').read_text()
    qapi = (old_output / 'qapi/qapi-types-run-state.h').read_text()
    operation_start = qapi.index('typedef enum CrucibleKvmResponseServiceOperation {')
    operation_end = qapi.index(';', qapi.index('\n}', operation_start)) + 1
    plumbing = PLUMBING.replace('static bool model_bql = true, model_cpu_thread;',
                               'static bool model_cpu_thread;')
    for tag, body in {
        'CLOCK_CONSTANTS': '\n'.join(re.findall(
            r'^#define (?:KVM_CAP_CRUCIBLE_CLOCK_|KVM_CRUCIBLE_CLOCK_|QEMU_CRUCIBLE_CLOCK_)[A-Z0-9_]+ (?:0x[0-9a-f]+|[0-9]+)$',
            header, re.M,
        )),
        'ATTRIBUTES': record(attributes, 'MemTxAttrs'),
        'SERVICE': record(header, 'CrucibleKvmResponseService'),
        'OPERATION': qapi[operation_start:operation_end],
        'INFO': record(qapi, 'CrucibleKvmResponseServiceInfo'),
    }.items():
        plumbing = plumbing.replace('@' + tag + '@', body)
    kvm = (source / 'accel/kvm/kvm-all.c').read_text()
    clock = (source / 'accel/kvm/crucible-clock.c').read_text()
    functions = '\n\n'.join([
        # Existing upstream int/uint32 loop is bounded by original geometry.
        # Preserve its exact body; scope its pre-existing warning locally.
        '#pragma GCC diagnostic push\n#pragma GCC diagnostic ignored \"-Wsign-compare\"\n'
        + function(kvm, 'kvm_handle_io', 'void')
        + '\n#pragma GCC diagnostic pop',
        function(kvm, 'kvm_crucible_dispatch_original_response', 'int'),
        function(clock, 'userspace_dispatch_return', 'bool'),
        function(clock, 'kvm_crucible_userspace_after_dispatch', 'bool'),
        clock[clock.index('/* This optional original-response service'):
              clock.index('CrucibleKvmInitialResponseInfo *qmp_x_crucible_kvm_initial_response(')],
    ])
    body = output / 'response.c'
    # This original More fixture keeps the first-response/window profile off.
    # The distinct initial model exercises its genuine original-owner validator.
    initial_disabled = r'''
static CPUState *kvm_crucible_window_initial_response_owner_locked(
    KVMState *state, uint32_t row, uint64_t generation, uint64_t invocation)
{
    assert(!state->crucible_window_configured && !original_service.initial_return);
    assert(false && "initial-response callback reached the disabled More fixture");
    return NULL;
}
'''
    body.write_text(generated + '\n' + plumbing + '\n' + initial_disabled + '\n' + functions + TESTS)
    includes = old_output / 'include'
    executable = output / 'response'
    subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-Wno-unused-parameter', '-I' + str(source / 'linux-headers'),
                    '-I' + str(includes), str(body), '-o', str(executable)], check=True)
    subprocess.run([str(executable)], check=True, timeout=20)


if __name__ == '__main__':
    main()
