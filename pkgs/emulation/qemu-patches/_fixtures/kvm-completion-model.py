"""Compile actual QEMU completion commands and native kernel retry policy.

Device/kernel scheduling and user-copy plumbing are explicit single-thread model
substitutes. This proof cannot qualify KVM execution or complete native custody."""

from pathlib import Path
import re
import subprocess
import sys

if len(sys.argv) != 5:
    raise SystemExit('usage: kvm-completion-model.py QEMU_SOURCE AOS_CC OUTPUT_DIR KERNEL_PATCH')

source = Path(sys.argv[1])
compiler = sys.argv[2]
out = Path(sys.argv[3])

out.mkdir(parents=True, exist_ok=True)

kernel_patch = Path(sys.argv[4])
generated = out / 'qapi'

generated.mkdir(exist_ok=True)

# Generate the exact source-owned QAPI layout; do not copy a separate DTO.
subprocess.run([sys.executable, str(source / 'scripts/qapi-gen.py'), '-o', str(generated), '-b', str(source / 'qapi/qapi-schema.json')], check=True, timeout=30)

clock = (source / 'accel/kvm/crucible-clock.c').read_text()
header = (source / 'include/system/crucible-kvm-clock.h').read_text()
state = (source / 'include/system/kvm_int.h').read_text()
qapi = (generated / 'qapi-types-run-state.h').read_text()
patch = kernel_patch.read_text()
marker='+++ b/include/linux/kvm_crucible_completion.h\n'

assert patch.count(marker) == 1

kernel_hunk = patch.split(marker, 1)[1].split('--- ', 1)[0]
kernel = '\n'.join((line[1:] for line in kernel_hunk.splitlines() if line.startswith('+'))) + '\n'

assert kernel.startswith('/* SPDX-License-Identifier: GPL-2.0-only */')


def function(name):
    match = re.search('^(?:static )?(?:bool|int|void|CrucibleKvmCompletionInfo \\*|CrucibleKvmUserspaceExit \\*)\\s*' + name + '\\([^;{]*\\)\\n\\{', clock, re.M)
    assert match, name
    end = clock.index('\n}\n', match.start()) + 3
    return clock[match.start():end]


def record(name, text):
    match = re.search('(?:typedef )?(?:enum|struct) ' + name + ' \\{', text)
    assert match, name
    end = text.index('\n}', match.start())
    end = text.index(';', end) + 1
    return text[match.start():end]


abi = header[header.index('#ifndef KVM_CAP_CRUCIBLE_COMPLETION_V1'):header.index('#endif', header.index('#ifndef KVM_CAP_CRUCIBLE_COMPLETION_V1')) + 6]
clock_abi = header[header.index('struct kvm_crucible_clock {'):header.index('\n};', header.index('struct kvm_crucible_clock {')) + 3]
fields = state[state.index('    bool crucible_clock_experiment;'):state.index('    int coalesced_mmio;')]
policy = kernel[kernel.index('struct kvm_crucible_response_state {'):kernel.rindex('#endif')]
uapi_marker='+++ b/include/uapi/linux/kvm.h\n'

assert patch.count(uapi_marker) == 1

uapi_hunk = patch.split(uapi_marker, 1)[1].split('--- ', 1)[0]
uapi_added = '\n'.join((line[1:] for line in uapi_hunk.splitlines() if line.startswith('+')))
kernel_abi = record('kvm_crucible_completion', uapi_added).replace('struct kvm_crucible_completion', 'struct KernelCompletionABI')
abi_fields = re.findall('^\\s+__(?:u32|u64|s32)\\s+(\\w+)', kernel_abi, re.M)

assert len(abi_fields) == 12

native_cap = re.search('^#define KVM_CAP_CRUCIBLE_COMPLETION_V1\\s+(\\S+)', uapi_added, re.M).group(1)
native_ioctl = re.search('^#define KVM_CRUCIBLE_COMPLETION (.+)', uapi_added, re.M).group(1).replace('struct kvm_crucible_completion', 'struct KernelCompletionABI')
abi_asserts = '\n'.join(('_Static_assert(offsetof(struct kvm_crucible_completion, ' + name + ') == offsetof(struct KernelCompletionABI, ' + name + '), "' + name + ' ABI");' for name in abi_fields))

abi_asserts += '\n_Static_assert(sizeof(struct kvm_crucible_completion) == sizeof(struct KernelCompletionABI), "whole ABI");'

abi_asserts += '\n_Static_assert(KVM_CAP_CRUCIBLE_COMPLETION_V1 == ' + native_cap + ', "actual kernel cap");'

abi_asserts += '\n_Static_assert(KVM_CRUCIBLE_COMPLETION == ' + native_ioctl + ', "actual kernel ioctl");'

prefix=r'''// SPDX-License-Identifier: GPL-2.0-only
/* Extracted source model, not native execution qualification. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include "linux/kvm.h"
typedef uint64_t u64;
typedef uint32_t u32;
#define U64_MAX UINT64_MAX
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define KVM_CRUCIBLE_CLOCK_QUERY 4
@ABI@
@KERNEL_ABI@
@ABI_ASSERTS@
@CLOCK@
@GEOMETRY@
@JOURNAL@
@PHASE@
@ENTRY@
@KERNEL@
@OPERATION@
@INFO@
typedef struct CrucibleKvmResponseService CrucibleKvmResponseService;
typedef int QemuMutex;
typedef struct KVMState { @FIELDS@ } KVMState;
typedef struct CPUState {
    int cpu_index;
    bool created, stopped;
    struct kvm_run *kvm_run;
    uint64_t native_id;
} CPUState;
typedef struct Error { bool set; } Error;
static KVMState native;
static KVMState *kvm_state = &native;
static CPUState fixture_cpu;
static unsigned char run_bytes[16384];
static CrucibleKvmUserspaceExit original_entry;
static struct kvm_crucible_response_state kernel_state;
static bool native_enabled = true, paused = true, clock_active;
static bool clock_ack = true, autostart, allocation_fails;
static bool native_more, copy_fault, malformed_result;
static unsigned kernel_queries, kernel_steps, actual_callbacks;
static int native_callback_result = 1;
static uint32_t native_clock_owners;
#define CPU_FOREACH(cpu) for ((cpu) = &fixture_cpu; (cpu); (cpu) = NULL)
#define RUN_STATE_PAUSED 1
#define RUN_STATE_PRELAUNCH 2
#define g_free(pointer) free(pointer)
#define error_report(...) ((void)0)
#define error_setg(errp, ...) ((*(errp))->set = true)
#define g_try_new0(type, count) (allocation_fails ? NULL : calloc(count, sizeof(type)))
static bool bql_locked(void) { return true; }
static bool kvm_enabled(void) { return native_enabled; }
static bool runstate_check(int value) { return paused && value == RUN_STATE_PAUSED; }
static uint64_t kvm_arch_vcpu_id(CPUState *cpu) { return cpu->native_id; }
static void qemu_mutex_lock(QemuMutex *mutex) { assert(!*mutex); *mutex = 1; }
static void qemu_mutex_unlock(QemuMutex *mutex) { assert(*mutex); *mutex = 0; }
static int kvm_vm_check_extension(KVMState *state, int capability)
{
    (void)state; assert(capability == KVM_CAP_CRUCIBLE_COMPLETION_V1); return 1;
}
static int kvm_ioctl(KVMState *state, unsigned long operation, int argument)
{
    (void)state; assert(operation == KVM_GET_VCPU_MMAP_SIZE && !argument);
    return sizeof(run_bytes);
}
static int kvm_vm_ioctl(KVMState *state, unsigned long operation, struct kvm_enable_cap *cap)
{
    (void)state; assert(operation == KVM_ENABLE_CAP);
    assert(cap->cap == KVM_CAP_CRUCIBLE_COMPLETION_V1);
    return 0;
}
static int clock_control(KVMState *state, struct kvm_crucible_clock *clock)
{
    (void)state; assert(clock->operation == KVM_CRUCIBLE_CLOCK_QUERY);
    clock->active = clock_active; clock->run_owners = native_clock_owners;
    clock->close_acknowledged = clock_ack; return 0;
}
static int kvm_vcpu_ioctl(CPUState *cpu, unsigned long operation,
                          struct kvm_crucible_completion *request)
{
    struct kvm_crucible_completion original = *request;
    int admission;

    assert(cpu == &fixture_cpu && operation == KVM_CRUCIBLE_COMPLETION);
    admission = kvm_crucible_response_admit(&kernel_state, request);
    if (admission < 0) { return admission; }
    if (request->operation == KVM_CRUCIBLE_COMPLETION_QUERY) {
        kernel_queries++;
        kvm_crucible_response_fill(&kernel_state, request, cpu->native_id);
        request->callback_result = kernel_state.last_result.callback_result;
        return 0;
    }
    kernel_steps++;
    if (admission == 1) {
        *request = kernel_state.last_result;
        return 0;
    }
    actual_callbacks++;
    kvm_crucible_response_finish(&kernel_state, &original,
                                native_callback_result, native_more, cpu->native_id);
    if (native_more) {
        cpu->kvm_run->mmio.phys_addr += 8;
        cpu->kvm_run->mmio.len = 4;
    }
    if (copy_fault) { copy_fault = false; return -EFAULT; }
    *request = kernel_state.last_result;
    if (malformed_result) { request->reserved[3] = 1; }
    return 0;
}
'''

for tag, value in {'ABI': abi, 'CLOCK': clock_abi, 'KERNEL_ABI': kernel_abi, 'ABI_ASSERTS': abi_asserts, 'GEOMETRY': record('CrucibleKvmResponseGeometry', header), 'JOURNAL': record('CrucibleKvmCompletionJournal', header), 'PHASE': record('CrucibleKvmUserspacePhase', header), 'ENTRY': record('CrucibleKvmUserspaceExit', header), 'KERNEL': policy, 'OPERATION': record('CrucibleKvmCompletionOperation', qapi), 'INFO': 'typedef struct CrucibleKvmCompletionInfo CrucibleKvmCompletionInfo;\n' + record('CrucibleKvmCompletionInfo', qapi), 'FIELDS': fields}.items():
    prefix = prefix.replace('@' + tag + '@', value)

functions = '\n\n'.join((function(name) for name in ['userspace_entry_locked', 'kvm_crucible_userspace_allow_state_put', 'completion_geometry', 'completion_result_valid', 'completion_fill_info', 'kvm_crucible_completion_configure', 'qmp_x_crucible_kvm_completion']))

suffix=r'''
static void reset(void)
{
    memset(&native, 0, sizeof(native)); memset(&original_entry, 0, sizeof(original_entry));
    memset(&kernel_state, 0, sizeof(kernel_state)); memset(run_bytes, 0, sizeof(run_bytes));
    native.crucible_clock_configured = native.crucible_userspace_configured = true;
    native.crucible_completion_configured = true;
    native.crucible_completion_mmap_size = sizeof(run_bytes);
    native.crucible_userspace_exits = &original_entry; native.crucible_userspace_capacity = 1;
    original_entry.assigned = original_entry.seen = true; original_entry.kernel_vcpu_id = 42;
    original_entry.phase = CRUCIBLE_KVM_USERSPACE_PENDING; original_entry.exit_sequence = 1;
    original_entry.exit_reason = KVM_EXIT_MMIO;
    fixture_cpu = (CPUState){ .created = true, .stopped = true, .native_id = 42,
        .kvm_run = (struct kvm_run *)run_bytes };
    fixture_cpu.kvm_run->exit_reason = KVM_EXIT_MMIO;
    fixture_cpu.kvm_run->mmio.phys_addr = 0x1000;
    fixture_cpu.kvm_run->mmio.len = 8;
    memset(fixture_cpu.kvm_run->mmio.data, 7, 8);
    assert(completion_geometry(&native, &fixture_cpu, &original_entry, true));
    assert(kvm_crucible_response_birth(&kernel_state));
    native_enabled = paused = clock_ack = true;
    clock_active = native_more = copy_fault = malformed_result = false;
    allocation_fails = autostart = false; native_clock_owners = 0;
    kernel_queries = kernel_steps = actual_callbacks = 0; native_callback_result = 1;
}
static CrucibleKvmCompletionInfo *command(CrucibleKvmCompletionOperation operation,
                                          uint64_t id, uint64_t sequence, bool refused)
{
    Error error = { 0 }; Error *pointer = &error;
    CrucibleKvmCompletionInfo *info = qmp_x_crucible_kvm_completion(
        operation, 0, id, sequence, &pointer);
    assert(error.set == refused); assert((info == NULL) == refused);
    return info;
}
static void assert_closed(CrucibleKvmCompletionInfo *info)
{
    assert(!info->device_closure && !info->input_custody &&
           !info->output_custody && !info->profile_qualified);
}
int main(void)
{
    CrucibleKvmCompletionInfo *info, *retry;
    unsigned steps;
    _Static_assert(sizeof(struct kvm_crucible_completion) == 96, "native ABI");
    _Static_assert(offsetof(struct kvm_crucible_completion, reserved) == 64, "native reserved");

    reset();
    info = command(CRUCIBLE_KVM_COMPLETION_OPERATION_QUERY, 0, 0, false);
    assert(info->result_known && info->native_pending_sequence == 1 && !actual_callbacks);
    assert_closed(info); free(info);
    info = command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 1, 1, false);
    assert(info->result_known && info->native_consumed_sequence == 1 &&
           info->consumed_sequence == 1 && !info->handler_pending);
    assert(actual_callbacks == 1 && kernel_steps == 1); assert_closed(info);
    assert(kvm_crucible_userspace_allow_state_put(&native, &fixture_cpu));
    steps = kernel_queries + kernel_steps; native.crucible_userspace_faulted = true;
    retry = command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 1, 1, false);
    assert(!memcmp(info, retry, sizeof(*info)));
    assert(steps == kernel_queries + kernel_steps && actual_callbacks == 1);
    free(info); free(retry);

    reset(); copy_fault = true;
    info = command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 1, 1, false);
    assert(!info->result_known && info->native_errno == EFAULT && info->uncertain_effects);
    assert(actual_callbacks == 1 && original_entry.phase == CRUCIBLE_KVM_USERSPACE_UNKNOWN);
    free(info);
    info = command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 1, 1, false);
    assert(info->result_known && info->native_consumed_sequence == 1 && info->uncertain_effects);
    assert(actual_callbacks == 1 && kernel_steps == 2);
    assert(!kvm_crucible_userspace_allow_state_put(&native, &fixture_cpu));
    free(info);

    reset();
    fixture_cpu.kvm_run->exit_reason = KVM_EXIT_IO;
    fixture_cpu.kvm_run->io.port = 0x3f8;
    fixture_cpu.kvm_run->io.direction = KVM_EXIT_IO_IN;
    fixture_cpu.kvm_run->io.size = 4;
    fixture_cpu.kvm_run->io.count = 1024;
    fixture_cpu.kvm_run->io.data_offset = 8192;
    memset(run_bytes + 8192, 0x5a, 4096);
    original_entry.exit_reason = KVM_EXIT_IO;
    assert(completion_geometry(&native, &fixture_cpu, &original_entry, true));
    info = command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 1, 1, false);
    assert(info->result_known && info->consumed_sequence == 1 && actual_callbacks == 1);
    free(info);
    reset(); fixture_cpu.kvm_run->exit_reason = KVM_EXIT_IO;
    fixture_cpu.kvm_run->io.size = 4; fixture_cpu.kvm_run->io.count = 1025;
    fixture_cpu.kvm_run->io.data_offset = 8192;
    assert(!completion_geometry(&native, &fixture_cpu, &original_entry, true));
    fixture_cpu.kvm_run->io.count = 1; fixture_cpu.kvm_run->io.data_offset = UINT64_MAX;
    assert(!completion_geometry(&native, &fixture_cpu, &original_entry, true));
    assert(!actual_callbacks);

    reset(); malformed_result = true;
    info = command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 1, 1, false);
    assert(!info->result_known && info->native_errno == EPROTO && info->uncertain_effects);
    assert(actual_callbacks == 1 && original_entry.phase == CRUCIBLE_KVM_USERSPACE_UNKNOWN);
    free(info);
    malformed_result = false;
    info = command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 1, 1, false);
    assert(info->result_known && info->uncertain_effects && actual_callbacks == 1);
    free(info);

    reset(); native_more = true;
    info = command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 1, 1, false);
    assert(info->result_known && info->handler_pending && info->exit_sequence == 2 &&
           info->consumed_sequence == 1 && info->native_pending_sequence == 2);
    assert(original_entry.phase == CRUCIBLE_KVM_USERSPACE_HANDLING &&
           original_entry.reserved_revisions == 1 && native.crucible_userspace_reserved_revisions == 1);
    steps = kernel_queries + kernel_steps;
    assert(!command(CRUCIBLE_KVM_COMPLETION_OPERATION_DISPATCH, 2, 2, true));
    assert(!command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 2, 2, true));
    retry = command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 1, 1, false);
    assert(!memcmp(info, retry, sizeof(*info)) && actual_callbacks == 1);
    assert(steps == kernel_queries + kernel_steps); free(info); free(retry);

    reset(); native_callback_result = -EINTR;
    info = command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 1, 1, false);
    assert(info->result_known && info->callback_result == -EINTR &&
           info->uncertain_effects && info->consumed_sequence == 0);
    assert(original_entry.phase == CRUCIBLE_KVM_USERSPACE_UNKNOWN);
    steps = kernel_steps; free(info);
    info = command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 1, 1, false);
    assert(kernel_steps == steps && actual_callbacks == 1); free(info);

    reset(); fixture_cpu.kvm_run->mmio.data[0] ^= 1;
    assert(!command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 1, 1, true));
    assert(!actual_callbacks && !kernel_steps);
    reset(); fixture_cpu.kvm_run->mmio.phys_addr++;
    assert(!command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 1, 1, true));
    assert(!actual_callbacks);
    reset(); clock_active = true;
    assert(!command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 1, 1, true));
    assert(!actual_callbacks);
    reset(); native_clock_owners = 1;
    assert(!command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 1, 1, true));
    assert(!actual_callbacks);
    reset(); fixture_cpu.stopped = false;
    assert(!command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 1, 1, true));
    assert(!actual_callbacks);
    reset(); allocation_fails = true;
    assert(!command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 1, 1, true));
    assert(!actual_callbacks);
    reset(); native.crucible_userspace_revision = UINT64_MAX - 2;
    assert(!command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 1, 1, true));
    assert(!actual_callbacks && !kernel_steps);
    reset(); assert(!command(CRUCIBLE_KVM_COMPLETION_OPERATION_COMPLETE, 2, 1, true));
    assert(!actual_callbacks);

    reset(); native.crucible_completion_configured = false;
    native.crucible_completion_experiment = true;
    assert(kvm_crucible_completion_configure(&native) == 0);
    assert(native.crucible_completion_configured);
    assert(kvm_crucible_completion_configure(&native) == -ENOTSUP);
    reset(); native.crucible_completion_configured = false;
    native.crucible_completion_experiment = true; native.crucible_userspace_configured = false;
    assert(kvm_crucible_completion_configure(&native) == -ENOTSUP);

    puts("Actual QEMU completion/kernel retry policy model PASS: known reply loss, copy-fault retry, original More custody, unknown history, complete geometry, paused admission and finite credits; no native qualification.");
    return 0;
}
'''

body = out / 'completion.c'

body.write_text(prefix + '\n' + functions + '\n' + suffix)

includes = out / 'include'

includes.mkdir(exist_ok=True)

if not (includes / 'asm').exists():
    (includes / 'asm').symlink_to(source / 'linux-headers/asm-x86')

subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-I' + str(source / 'linux-headers'), '-I' + str(includes), str(body), '-o', str(out / 'completion')], check=True, timeout=30)

subprocess.run([str(out / 'completion')], check=True, timeout=30)
