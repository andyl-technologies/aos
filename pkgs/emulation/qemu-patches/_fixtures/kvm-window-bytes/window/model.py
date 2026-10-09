"""Exercise actual QEMU window/return callers against original kernel receipts.

The ABI, full QEMU controller functions and kernel QUERY/ACK functions are source
extractions. Native clock, CPU stop, BQL, device and syscall plumbing are modeled;
no guest, real KVM ioctl or complete-profile qualification is represented.
"""
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True

def function(body, name):
    matches = list(re.finditer(r'^(?:static )?(?:[A-Za-z_][A-Za-z_0-9]*\s+)+\*?' + re.escape(name) + r'\(', body, re.M))
    if len(matches) != 1:
        raise ValueError(name + ': expected one actual function')
    opened = body.index('{', matches[0].start())
    depth, cursor = 1, opened + 1
    while depth:
        depth += (body[cursor] == '{') - (body[cursor] == '}')
        cursor += 1
    return body[matches[0].start():cursor] + '\n'

def record(body, name):
    match = re.search(r'(?:typedef )?(?:struct|enum) ' + name + r' \{', body)
    if match is None:
        raise ValueError('missing actual native type ' + name)
    end = body.index(';', body.index('\n}', match.start())) + 1
    return body[match.start():end]

PLUMBING = r'''
#include <stdlib.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#define qatomic_load_acquire(p) __atomic_load_n((p), __ATOMIC_ACQUIRE)
#define qatomic_store_release(p, v) __atomic_store_n((p), (v), __ATOMIC_RELEASE)
#define g_try_new0(type, count) ((type *)calloc((count), sizeof(type)))
#define g_new0 g_try_new0
#define g_free free
#define MIN(left, right) ((left) < (right) ? (left) : (right))
#define G_STATIC_ASSERT(c) _Static_assert((c), "source ABI")
#define KVM_EXIT_IO 2
#define KVM_EXIT_MMIO 6
#define KVM_EXIT_PAPR_HCALL 19
#define KVM_EXIT_XEN 28
#define KVM_EXIT_TDX 40
#define KVM_EXIT_HYPERCALL 3
#define KVM_EXIT_OSI 18
#define KVM_EXIT_DCR 15
#define KVM_EXIT_EPR 23
#define KVM_EXIT_X86_RDMSR 29
#define KVM_EXIT_X86_WRMSR 30
#define KVM_ENABLE_CAP 11
#define CPU_FOREACH(cpu) for ((cpu) = model_cpus; (cpu); (cpu) = (cpu)->next)
typedef int QemuMutex;
typedef struct Error { int code; } Error;
static Error error_value;
static void error_setg(Error **error, const char *format, ...)
{ (void)format; if (error) { error_value.code = 1; *error = &error_value; } }
static void error_setg_errno(Error **error, int value, const char *format, ...)
{ (void)value; error_setg(error, format); }
static void error_report(const char *format, ...) { (void)format; }
static void qemu_mutex_lock(QemuMutex *mutex) { assert(!*mutex); *mutex = 1; }
static void qemu_mutex_unlock(QemuMutex *mutex) { assert(*mutex); *mutex = 0; }
static bool bql_locked(void) { return true; }
static bool autostart;
static unsigned cpu_seals, native_queries, native_acks, clock_mutations;
static uint64_t sealed_generation;
static uint32_t model_clock_components = 159;
static bool lose_ack_copy, model_kernel_available = true, model_acknowledged;

@CPU@
@TYPES@
typedef struct CrucibleKvmResponseBytesJournal CrucibleKvmResponseBytesJournal;
typedef struct KVMState {
@FIELDS@
    struct kvm *native_vm;
} KVMState;
/* The original window fixture keeps canonical-byte mode disabled. */
static uint32_t kvm_crucible_response_bytes_exit_reason(KVMState *state, CPUState *cpu)
{
    (void)cpu;
    assert(!state->crucible_response_bytes_configured);
    assert(false && "canonical byte selector reached disabled window fixture");
    return 0;
}

static bool kvm_crucible_response_bytes_capture_return(KVMState *state, CPUState *cpu,
                                                     const struct kvm_crucible_run_return *receipt)
{
    (void)cpu;
    (void)receipt;
    assert(!state->crucible_response_bytes_configured);
    assert(false && "canonical byte capture reached disabled window fixture");
    return false;
}

static KVMState *kvm_state;
static CPUState *model_cpus;
static bool kvm_enabled(void) { return kvm_state != NULL; }
static uint64_t kvm_arch_vcpu_id(CPUState *cpu) { return cpu->kernel->vcpu_id; }
static void cpu_pause(CPUState *cpu) { cpu->stop = true; cpu->stopped = true; }
/* Work-lock/callback state is modeled here; the separate pthread fixture
 * executes the actual source predicate while real callbacks remain held. */
static bool model_work_active;
static bool qemu_cpu_native_window_stopped(CPUState *cpu)
{ return cpu->stopped && !cpu->crucible_native_window_run && !model_work_active; }
static void cpu_resume(CPUState *cpu) { cpu->stop = false; cpu->stopped = false; }
static int qemu_cpu_native_window_seal(uint64_t generation)
{ assert(generation > sealed_generation); sealed_generation = generation; cpu_seals++; return 0; }
static int kvm_vm_check_extension(KVMState *state, int capability)
{ assert(state); assert(capability == KVM_CAP_CRUCIBLE_RUN_RETURN_V1); return model_kernel_available; }
static int kvm_vcpu_ioctl(CPUState *cpu, unsigned long type, void *argument)
{
    struct kvm_crucible_run_return *request = argument;
    assert(type == KVM_CRUCIBLE_RUN_RETURN);
    if (request->operation == KVM_CRUCIBLE_RUN_RETURN_ACK) {
        native_acks++;
        fail_result_copy = lose_ack_copy;
    } else {
        native_queries++;
    }
    int result = kvm_crucible_run_return_ioctl(cpu->kernel, argument);
    fail_result_copy = false;
    return result;
}
static int kvm_vm_ioctl(KVMState *state, unsigned long type, void *argument)
{
    struct kvm_enable_cap *cap = argument;
    assert(type == KVM_ENABLE_CAP);
    if (cap->cap == KVM_CAP_CRUCIBLE_RUN_RETURN_V1) {
        return kvm_crucible_run_return_configure(state->native_vm, cap);
    }
    assert(cap->cap == KVM_CAP_CRUCIBLE_CLOCK_V3 || cap->cap == KVM_CAP_CRUCIBLE_CLOCK_V2);
    struct kvm_crucible_clock *clock = (void *)(uintptr_t)cap->args[0];
    struct kvm_crucible_clock_domain *native = &state->native_vm->arch.crucible_clock;
    if (clock->operation == KVM_CRUCIBLE_CLOCK_BEGIN) {
        clock_mutations++;
        native->window_generation = clock->window_generation;
        native->sampled_ns = clock->start_ns;
        native->active = true;
        model_acknowledged = false;
        state->native_vm->crucible_active = true;
        state->native_vm->crucible_host_ceiling_ns = 100;
    } else if (clock->operation == KVM_CRUCIBLE_CLOCK_FREEZE) {
        clock_mutations++;
        native->active = false;
        model_acknowledged = true;
        state->native_vm->crucible_active = false;
    } else {
        assert(clock->operation == KVM_CRUCIBLE_CLOCK_QUERY);
    }
    clock->coverage = model_clock_components;
    clock->window_generation = native->window_generation;
    clock->current_ns = native->sampled_ns;
    clock->active = native->active;
    clock->close_acknowledged = model_acknowledged;
    clock->run_owners = native->run_owners;
    return 0;
}
'''

CASES = r'''
static void initialize(KVMState *state, CPUState *cpu, struct kvm_vcpu *kernel,
                       struct kvm *vm)
{
    *vm = (struct kvm) { .crucible_controlled = true, .crucible_response_enabled = true };
    *kernel = (struct kvm_vcpu) { .kvm = vm, .vcpu_id = 37 };
    *cpu = (CPUState) { .cpu_index = 0, .created = true, .stopped = true, .kernel = kernel };
    *state = (KVMState) {
        .crucible_window_experiment = true,
        .crucible_clock_configured = true, .crucible_clock_kernel_edition = 3,
        .crucible_completion_configured = true,
        .crucible_response_service_configured = true,
        .crucible_userspace_configured = true,
        .crucible_userspace_capacity = 1, .native_vm = vm,
    };
    state->crucible_userspace_exits = calloc(1, sizeof(*state->crucible_userspace_exits));
    assert(state->crucible_userspace_exits);
    state->crucible_userspace_exits[0].assigned = true;
    state->crucible_userspace_exits[0].kernel_vcpu_id = 37;
    cpu->kvm_run = calloc(1, sizeof(*cpu->kvm_run));
    assert(cpu->kvm_run);
    model_cpus = cpu;
    kvm_state = state;
    sealed_generation = 0;
    host_now = 1;
    model_kernel_available = true;
    model_acknowledged = false;
    model_clock_components = 159;
    model_work_active = false;
    assert(kvm_crucible_window_configure(state) == 0);
    vm->created_vcpus = 1;
    Error *error = NULL;
    CrucibleKvmWindowInfo *info = qmp_x_crucible_kvm_original_window(
        CRUCIBLE_KVM_WINDOW_OPERATION_BEGIN, 1, 0, 20, 0, &error);
    assert(!info && error);
    error = NULL;
    info = qmp_x_crucible_kvm_original_window(
        CRUCIBLE_KVM_WINDOW_OPERATION_CLOSE, 0, 0, 0, 1000, &error);
    assert(info && !error && info->phase == CRUCIBLE_KVM_WINDOW_CLOSED);
    assert(info->clock_closed && info->original_cpus_stopped);
    assert(info->retained_returns == 0 && !info->profile_qualified);
    free(info);
}

static void dispose(KVMState *state)
{
    free(model_cpus->kvm_run);
    kvm_crucible_window_destroy(state);
    free(state->crucible_userspace_exits);
    state->crucible_userspace_exits = NULL;
    kvm_state = NULL;
    model_cpus = NULL;
}

static void open_original(KVMState *state, uint64_t generation, uint64_t start, uint64_t end)
{
    Error *error = NULL;
    CrucibleKvmWindowInfo *info = qmp_x_crucible_kvm_original_window(
        CRUCIBLE_KVM_WINDOW_OPERATION_BEGIN, generation, start, end, 0, &error);
    assert(info && !error);
    assert(info->phase == CRUCIBLE_KVM_WINDOW_RUNNING && info->clock_active);
    assert(!info->profile_qualified && !info->input_custody_known &&
           !info->device_custody_known && !info->publication_custody_known);
    free(info);
    assert(!kvm_crucible_window_allow_vcpu_create(state));
    assert(state->crucible_window_generation == generation);
}

static void actual_return(KVMState *state, CPUState *cpu, int result, bool hidden)
{
    assert(kvm_crucible_window_enter(state, cpu));
    assert(kvm_crucible_userspace_before_run(state, cpu));
    assert(kvm_crucible_run_return_admit(cpu->kernel) == 0);
    if (hidden) cpu->kernel->arch.complete_userspace_io = cpu;
    cpu->kernel->crucible_run_return.original.flags |= KVM_CRUCIBLE_RUN_RETURN_CLOCK_ENTERED;
    cpu->kernel->kvm->arch.crucible_clock.sampled_ns += 5;
    kvm_crucible_run_return_finish(cpu->kernel, result);
}

int main(void)
{
    assert(original_kernel_tests() == 0);
    KVMState state;
    CPUState cpu;
    struct kvm_vcpu kernel;
    struct kvm vm;
    Error *error = NULL;
    CrucibleKvmWindowInfo *window;
    CrucibleKvmOriginalReturnInfo *retained;

    initialize(&state, &cpu, &kernel, &vm);
    open_original(&state, 1, 0, 20);
    actual_return(&state, &cpu, -EINTR, false);
    assert(kvm_crucible_window_after_run(&state, &cpu, -EINTR));
    assert(state.crucible_userspace_exits[0].phase == CRUCIBLE_KVM_USERSPACE_READY);
    assert(!state.crucible_userspace_exits[0].uncertain_effects);
    assert(state.crucible_window_returns[0].receipt_known);
    assert(!state.crucible_window_returns[0].ack_known);
    assert(vm.crucible_uncollected_returns == 1);
    kvm_crucible_window_leave(&state, &cpu);
    assert(cpu.stop && cpu.stopped && !cpu.crucible_native_window_run);

    window = qmp_x_crucible_kvm_original_window(
        CRUCIBLE_KVM_WINDOW_OPERATION_CLOSE, 1, 0, 0, 1000, &error);
    assert(window && !error && window->clock_closed && window->original_cpus_stopped);
    assert(window->phase == CRUCIBLE_KVM_WINDOW_CLOSED);
    free(window);
    window = qmp_x_crucible_kvm_original_window(
        CRUCIBLE_KVM_WINDOW_OPERATION_BEGIN, 2, 5, 30, 0, &error);
    assert(!window && error); error = NULL;
    unsigned mutations = clock_mutations;
    retained = qmp_x_crucible_kvm_original_return(
        CRUCIBLE_KVM_ORIGINAL_RETURN_OPERATION_ACK, 0, 1, 1, &error);
    assert(retained && !error && retained->ack_known && retained->receipt_known);
    assert(vm.crucible_uncollected_returns == 0);
    free(retained);
    unsigned acknowledgements = native_acks;
    retained = qmp_x_crucible_kvm_original_return(
        CRUCIBLE_KVM_ORIGINAL_RETURN_OPERATION_ACK, 0, 1, 1, &error);
    assert(retained && !error && native_acks == acknowledgements);
    assert(clock_mutations == mutations);
    free(retained);
    open_original(&state, 2, 5, 30);
    assert(kvm_crucible_window_enter(&state, &cpu));
    assert(kvm_crucible_userspace_before_run(&state, &cpu));
    vm.crucible_active = false;
    vm.arch.crucible_clock.active = false;
    assert(kvm_crucible_run_return_admit(&kernel) == -EAGAIN);
    assert(kvm_crucible_window_after_run(&state, &cpu, -EAGAIN));
    assert(state.crucible_window_returns[1].no_birth_known);
    assert(!state.crucible_window_returns[1].receipt_known);
    assert(state.crucible_window_returns[1].receipt.invocation == 1);
    assert(state.crucible_window_returns[1].expected_invocation == 2);
    assert(state.crucible_window_returns[1].ack_known);
    assert(vm.crucible_uncollected_returns == 0);
    kvm_crucible_window_leave(&state, &cpu);
    dispose(&state);

    initialize(&state, &cpu, &kernel, &vm);
    open_original(&state, 1, 0, 20);
    actual_return(&state, &cpu, -EINTR, true);
    assert(!kvm_crucible_window_after_run(&state, &cpu, -EINTR));
    assert(state.crucible_window_phase == CRUCIBLE_KVM_WINDOW_UNKNOWN);
    assert(state.crucible_window_returns[0].receipt_known);
    assert(state.crucible_window_returns[0].receipt.pending_mask != 0);
    assert(kernel.crucible_response.flags & KVM_CRUCIBLE_COMPLETION_UNCERTAIN);
    assert(vm.crucible_uncollected_returns == 1);
    kvm_crucible_window_leave(&state, &cpu);
    dispose(&state);

    initialize(&state, &cpu, &kernel, &vm);
    open_original(&state, 1, 0, 20);
    actual_return(&state, &cpu, -EINTR, false);
    assert(kvm_crucible_window_after_run(&state, &cpu, -EINTR));
    kvm_crucible_window_leave(&state, &cpu);
    lose_ack_copy = true;
    retained = qmp_x_crucible_kvm_original_return(
        CRUCIBLE_KVM_ORIGINAL_RETURN_OPERATION_ACK, 0, 1, 1, &error);
    assert(!retained && error); error = NULL;
    assert(vm.crucible_uncollected_returns == 0);
    assert(!state.crucible_window_returns[0].ack_known);
    assert(state.crucible_window_phase == CRUCIBLE_KVM_WINDOW_UNKNOWN);
    lose_ack_copy = false;
    retained = qmp_x_crucible_kvm_original_return(
        CRUCIBLE_KVM_ORIGINAL_RETURN_OPERATION_ACK, 0, 1, 1, &error);
    assert(retained && !error && retained->ack_known);
    assert(vm.crucible_uncollected_returns == 0);
    assert(state.crucible_window_phase == CRUCIBLE_KVM_WINDOW_UNKNOWN);
    free(retained);
    dispose(&state);
    puts("Actual QEMU controller + original kernel receipt/ACK, generation/no-birth/hidden-pending/copy-fault retained custody PASS; native plumbing modeled, no hardware qualification.");
}
'''

def main():
    source, kernel, compiler, output = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4])
    output.mkdir(parents=True,exist_ok=True)
    script = Path(__file__).parent / 'kernel-return-proof.py'
    subprocess.run([sys.executable,str(script),str(kernel),compiler,str(output/'kernel')],check=True)
    generated = (output/'kernel/return-proof.c').read_text().replace('int main(void)','int original_kernel_tests(void)')
    header=(source/'include/system/crucible-kvm-clock.h').read_text()
    window=(source/'include/system/crucible-kvm-window.h').read_text()
    qapi=(source/'build/qapi/qapi-types-run-state.h').read_text()
    types=record((source/'include/exec/memattrs.h').read_text(),'MemTxAttrs')+'\n\n'+'\n\n'.join(record(header,name) for name in ['CrucibleKvmUserspacePhase','CrucibleKvmResponseGeometry','CrucibleKvmCompletionJournal','CrucibleKvmUserspaceExit','CrucibleKvmResponseService'])
    types += '\n\n' + '\n\n'.join(record(window,name) for name in ['CrucibleKvmWindowPhase','CrucibleKvmInitialResponseJournal','CrucibleKvmOriginalReturn','CrucibleKvmWindowVcpu'])
    types += '\n\n' + '\n\n'.join(record(qapi,name) for name in ['CrucibleKvmWindowOperation','CrucibleKvmOriginalReturnOperation'])
    for name in ['CrucibleKvmOriginalReturnIdentity', 'CrucibleKvmOriginalReturnIdentityList', 'CrucibleKvmOriginalReturnInventory']:
        types += '\ntypedef struct '+name+' '+name+';\n'+record(qapi,name)

    for name in ['CrucibleKvmWindowInfo','CrucibleKvmOriginalReturnInfo']:
        types += '\ntypedef struct '+name+' '+name+';\n'+record(qapi,name)
    fields=(source/'include/system/kvm_int.h').read_text()
    fields=fields[fields.index('    bool crucible_clock_experiment;'):fields.index('    int coalesced_mmio;')]
    cpu='''typedef struct CPUState {
    int cpu_index; bool stop, stopped, created, unplug, crucible_native_window_run;
    struct kvm_vcpu *kernel;
    struct { uint32_t exit_reason; } *kvm_run;
    struct CPUState *next;
} CPUState;'''
    plumbing=PLUMBING.replace('@CPU@',cpu).replace('@TYPES@',types).replace('@FIELDS@',fields)
    constants='\n'.join(re.findall(r'^#define (?:KVM_CAP_CRUCIBLE_CLOCK_|KVM_CRUCIBLE_CLOCK_|QEMU_CRUCIBLE_CLOCK_|QEMU_CRUCIBLE_WINDOW_)[A-Z0-9_]+ [^\n]+$',header+'\n'+window,re.M))
    # Actual native fallback clock definition is part of the bound source ABI.
    clock=record(header,'kvm_crucible_clock')
    legacy=(source/'accel/kvm/crucible-clock.c').read_text()
    signatures=['userspace_exit_requires_completion','userspace_run_start','userspace_run_return','userspace_entry_locked','kvm_crucible_userspace_before_run','kvm_crucible_userspace_after_run']
    functions='\n'.join(function(legacy,name) for name in signatures)
    functions=functions.replace('static CrucibleKvmUserspaceExit *userspace_entry_locked','static CrucibleKvmUserspaceExit *userspace_entry_locked')
    fresh=(source/'accel/kvm/crucible-window.c').read_text()
    fresh=re.sub(r'^#include.*$','',fresh,flags=re.M)
    kvmio=re.search(r'^#define KVMIO [^\n]+$',(kernel/'include/uapi/linux/kvm.h').read_text(),re.M).group(0)
    declared=record(window,'kvm_crucible_run_return').replace('struct kvm_crucible_run_return','struct qemu_run_return_abi')
    abi_fields=re.findall(r'    (?:uint32_t|uint64_t|int64_t) ([a-z_]+);',declared)
    assert len(abi_fields)==18
    abi=['static void actual_abi_octets(void) {',
         '    struct kvm_crucible_run_return kernel = {0};',
         '    struct qemu_run_return_abi qemu = {0};']
    for index,name in enumerate(abi_fields):
        abi.append('    kernel.'+name+' = '+str(index+1)+';')
    abi.append('    memcpy(&qemu, &kernel, sizeof(kernel));')
    for name in abi_fields:
        abi.append('    assert(qemu.'+name+' == kernel.'+name+');')
    # Kernel definitions in the generated prefix must not hide a changed
    # QEMU fallback constant. Compare the separately parsed native macros.
    cap = re.search(r'^#define KVM_CAP_CRUCIBLE_RUN_RETURN_V1 ([^\n]+)$', window, re.M).group(1)
    ioctl = re.search(r'#define KVM_CRUCIBLE_RUN_RETURN \\\n    ([^\n]+)', window).group(1)
    ioctl = ioctl.replace('struct kvm_crucible_run_return', 'struct qemu_run_return_abi')
    abi.append('    assert(KVM_CAP_CRUCIBLE_RUN_RETURN_V1 == (' + cap + '));')
    abi.append('    assert(KVM_CRUCIBLE_RUN_RETURN == (' + ioctl + '));')
    abi.append('}')
    extra=declared+'\n'+'\n'.join(abi)+'\n'+(Path(__file__).parent/'extra-cases.inc').read_text()
    cases=CASES.replace('int main(void)',extra+'\nint main(void)')
    cases=cases.replace('    assert(original_kernel_tests() == 0);','    assert(original_kernel_tests() == 0);\n    actual_abi_octets();\n    clean_interrupt_predicates();\n    admission_and_prior_lineage();\n    arm_clock_selection();\n    deferred_original_mmio();\n    composite_original_cut();\n    inventory_original_lineage();')
    body=generated+'\n'+kvmio+'\n'+constants+'\n'+clock+'\n'+plumbing+'\n'+functions+'\n'+fresh+'\n'+cases
    native,executable=output/'window-model.c',output/'window-model'
    native.write_text(body)
    subprocess.run([compiler,'-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-parameter',str(native),'-o',str(executable)],check=True)
    subprocess.run([str(executable)],check=True,timeout=20)

if __name__=='__main__':
    main()
