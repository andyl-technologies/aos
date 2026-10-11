"""Compile actual private-buffer ioctl and x86/ARM consumers with native plumbing models.

Guest execution, FPU loading, clocks, buses and CPU registers are modeled. The
actual ABI, configuration/allocation hooks, native producers, original admission
policy, byte journal and consumer bodies are extracted and compiled unchanged.
No device or real KVM qualification is asserted.
"""
from pathlib import Path
import re
import subprocess
import sys


def function(body, name):
    matches = list(re.finditer(r'(?:static\s+(?:inline\s+)?)?(?:int|long|void|bool|u32|const void \*)\s*' +
        re.escape(name) + r'\s*\([^;{}]*\)\s*\{', body))
    if len(matches) != 1:
        raise ValueError(f'{name}: expected one genuine definition')
    start = matches[0].start()
    opened = body.index('{', start)
    depth = 1
    cursor = opened + 1
    while depth:
        depth += (body[cursor] == '{') - (body[cursor] == '}')
        cursor += 1
    return body[start:cursor] + '\n'


PREFIX = r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t u8;
typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint8_t __u8;
typedef int64_t __s64;
typedef int32_t __s32;
typedef uint64_t gpa_t;
#define U64_MAX UINT64_MAX
#define CONFIG_X86 1
#define CONFIG_ARM64 0
#define IS_ENABLED(option) (option)
#define __user
#define READ_ONCE(value) (value)
#define WRITE_ONCE(value, replacement) ((value) = (replacement))
#define BUILD_BUG_ON(condition) _Static_assert(!(condition), "actual ABI")
#define lockdep_assert_held(lock) ((void)(lock))
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define EXPORT_SYMBOL_FOR_KVM_INTERNAL(name)
#define GFP_KERNEL_ACCOUNT 1
#define KVM_EXIT_UNKNOWN 0
#define KVM_EXIT_IO 2
#define KVM_EXIT_MMIO 6
#define KVM_EXIT_IO_IN 0
#define KVM_EXIT_IO_OUT 1
#define KVM_PIO_BUS 1
#define KVM_PIO_PAGE_OFFSET 1
#define PAGE_SIZE 4096
#define KVM_TRACE_MMIO_READ 1
#define KVM_TRACE_MMIO_WRITE 2
static bool check_condition(bool condition) { return condition; }
#define KVM_BUG_ON(test, kvm) ((void)(kvm), check_condition(test))
#define WARN_ON_ONCE(test) check_condition(test)
#define unlikely(test) (test)
#define min(first, second) ((first) < (second) ? (first) : (second))
struct kvm_enable_cap { u32 flags; u64 args[4]; };
'''

CONTEXT = r'''
struct kvm_crucible_response_bytes_state;
struct kvm_run {
    u32 exit_reason;
    struct { u64 phys_addr; u32 len; u8 is_write; u8 data[8]; } mmio;
    struct { u64 data_offset; u32 count; u16_t_placeholder; } unused;
};
'''.replace('    struct { u64 data_offset; u32 count; u16_t_placeholder; } unused;',
'''    struct { u64 data_offset; u32 count, direction, size, port; } io;''') + r'''
struct kvm_mmio_fragment { u64 gpa; unsigned len; u8 *data; u8 val; };
struct kvm {
    int lock, crucible_configuration_lock, crucible_gate_lock;
    bool crucible_controlled, crucible_response_enabled, crucible_run_return_enabled;
    bool crucible_response_bytes_enabled, crucible_active;
    u32 created_vcpus, crucible_effect_owners;
    u64 generation;
};
struct kvm_vcpu {
    int mutex;
    u32 vcpu_id;
    struct kvm *kvm;
    struct kvm_run *run;
    struct kvm_crucible_response_state crucible_response;
    struct kvm_crucible_run_return_state crucible_run_return;
    struct kvm_crucible_response_bytes_state *crucible_response_bytes;
    bool mmio_needed, mmio_is_write, mmio_read_completed;
    unsigned mmio_cur_fragment, mmio_nr_fragments;
    struct kvm_mmio_fragment mmio_fragments[2];
    struct {
        struct { unsigned size, count, port; bool in; } pio;
        u8 pio_data[4096];
        int (*complete_userspace_io)(struct kvm_vcpu *);
    } arch;
    bool arm_write;
    unsigned arm_length, arm_rd;
    u64 regs[4], pc;
};
static bool fail_source_copy, fail_result_copy, fail_allocation, owners_stopped = true;
static unsigned callbacks, allocations, frees;
static bool hold_consumer;
static pthread_mutex_t hold_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t hold_condition = PTHREAD_COND_INITIALIZER;
static bool consumer_entered, consumer_released;
static void mutex_lock(int *lock) { assert(*lock == 0); *lock = 1; }
static void mutex_unlock(int *lock) { assert(*lock == 1); *lock = 0; }
#define raw_spin_lock_irqsave(lock, flags) do { (void)(lock); (flags) = 0; } while (0)
#define raw_spin_unlock_irqrestore(lock, flags) do { (void)(lock); (void)(flags); } while (0)
static int copy_from_user(void *target, const void *source, size_t size)
{ if (fail_source_copy) return 1; memcpy(target, source, size); return 0; }
static int copy_to_user(void *target, const void *source, size_t size)
{ if (fail_result_copy) return 1; memcpy(target, source, size); return 0; }
static void *kzalloc(size_t size, int flags)
{ assert(flags == GFP_KERNEL_ACCOUNT); allocations++; return fail_allocation ? NULL : calloc(1, size); }
static void kfree(void *value) { if (value) frees++; free(value); }
static bool kvm_arch_crucible_response_stopped(struct kvm *vm)
{ (void)vm; return owners_stopped; }
static void kvm_arch_crucible_run_clock_snapshot(struct kvm_vcpu *cpu,
    struct kvm_crucible_run_return *receipt, bool returned)
{ assert(returned); receipt->generation_end = cpu->kvm->generation; }
static void kvm_crucible_effect_leave(struct kvm *vm)
{ assert(vm->crucible_effect_owners == 1); vm->crucible_effect_owners--; }
static bool kvm_arch_crucible_response_pending(struct kvm_vcpu *cpu);
static int kvm_arch_crucible_response_complete(struct kvm_vcpu *cpu, bool *more);
#define guest_state_protected unused_protection
static int complete_emulated_io(struct kvm_vcpu *cpu) { (void)cpu; return 1; }
static int kvm_io_bus_read(struct kvm_vcpu *cpu, int bus, unsigned port, int size, void *data)
{ (void)cpu; (void)bus; (void)port; (void)size; (void)data; return -EOPNOTSUPP; }
static int kvm_io_bus_write(struct kvm_vcpu *cpu, int bus, unsigned port, int size, void *data)
{ return kvm_io_bus_read(cpu, bus, port, size, data); }
#define KVM_PIO_IN 0
#define trace_kvm_pio(...) ((void)0)
#define trace_kvm_mmio(...) ((void)0)
static bool kvm_pending_external_abort(struct kvm_vcpu *cpu) { (void)cpu; return false; }
static bool kvm_vcpu_dabt_iswrite(struct kvm_vcpu *cpu) { return cpu->arm_write; }
static unsigned kvm_vcpu_dabt_get_as(struct kvm_vcpu *cpu) { return cpu->arm_length; }
static bool kvm_vcpu_dabt_issext(struct kvm_vcpu *cpu) { (void)cpu; return false; }
static bool kvm_vcpu_dabt_issf(struct kvm_vcpu *cpu) { (void)cpu; return true; }
static unsigned kvm_vcpu_dabt_get_rd(struct kvm_vcpu *cpu) { return cpu->arm_rd; }
static unsigned long kvm_mmio_read_buf(const void *data, unsigned length)
{ unsigned long value = 0; memcpy(&value, data, length); return value; }
static unsigned long vcpu_data_host_to_guest(struct kvm_vcpu *cpu, unsigned long value, int length)
{ (void)cpu; (void)length; return value; }
static void vcpu_set_reg(struct kvm_vcpu *cpu, unsigned reg, unsigned long value)
{ assert(reg < 4); cpu->regs[reg] = value; }
static void kvm_incr_pc(struct kvm_vcpu *cpu) { cpu->pc += 4; }
static int complete_emulated_mmio(struct kvm_vcpu *cpu);
'''

# The actual native return dispatcher is exercised with real source consumers;
# CPU/FPU owners and its whitelist are modeled separately from guest execution.
DISPATCH = r'''
static bool use_arm;
static u8 pio_destination[4096];
static bool kvm_arch_crucible_response_pending(struct kvm_vcpu *cpu)
{
    u32 reason = kvm_crucible_response_bytes_reason(cpu);
    return (reason == KVM_EXIT_MMIO && cpu->mmio_needed) ||
        (reason == KVM_EXIT_IO && cpu->arch.pio.count);
}
static int kvm_arch_crucible_response_complete(struct kvm_vcpu *cpu, bool *more)
{
    int result;
    assert(kvm_arch_crucible_response_pending(cpu));
    callbacks++;
    if (hold_consumer) {
        assert(pthread_mutex_lock(&hold_lock) == 0);
        consumer_entered = true;
        assert(pthread_cond_broadcast(&hold_condition) == 0);
        while (!consumer_released)
            assert(pthread_cond_wait(&hold_condition, &hold_lock) == 0);
        assert(pthread_mutex_unlock(&hold_lock) == 0);
    }
    u32 reason = kvm_crucible_response_bytes_reason(cpu);
    kvm_crucible_response_bytes_consume_begin(cpu);
    if (reason == KVM_EXIT_IO) {
        if (cpu->arch.pio.in)
            result = complete_emulator_pio_in(cpu, pio_destination);
        else {
            cpu->arch.pio.count = 0;
            result = 1;
        }
    } else if (use_arm) {
        result = kvm_handle_mmio_return(cpu);
    } else {
        result = complete_emulated_mmio(cpu);
    }
    *more = kvm_arch_crucible_response_pending(cpu);
    return result;
}
'''

CASES = r'''
struct fixture {
    struct kvm vm;
    struct kvm_run run;
    struct kvm_vcpu cpu;
    u8 first[8], second[8];
};
static void setup(struct fixture *fixture)
{
    memset(fixture, 0, sizeof(*fixture));
    fixture->vm = (struct kvm) { .crucible_controlled = true,
        .crucible_response_enabled = true, .crucible_run_return_enabled = true,
        .generation = 9 };
    struct kvm_enable_cap cap = {0};
    assert(kvm_crucible_response_bytes_configure(&fixture->vm, &cap) == 0);
    fixture->cpu.kvm = &fixture->vm;
    fixture->cpu.run = &fixture->run;
    fixture->cpu.vcpu_id = 13;
    fixture->cpu.crucible_run_return.original.invocation = 21;
    fixture->cpu.crucible_run_return.original.generation_end = 9;
    assert(kvm_crucible_response_bytes_vcpu_init(&fixture->cpu) == 0);
}
static void mmio_birth(struct fixture *fixture, bool write, bool more)
{
    struct kvm_vcpu *cpu = &fixture->cpu;
    cpu->mmio_needed = true;
    cpu->mmio_is_write = write;
    cpu->mmio_nr_fragments = more ? 2 : 1;
    cpu->mmio_fragments[0] = (struct kvm_mmio_fragment) {
        .gpa = 0x1000, .len = 4, .data = fixture->first };
    cpu->mmio_fragments[1] = (struct kvm_mmio_fragment) {
        .gpa = 0x2000, .len = 4, .data = fixture->second };
    kvm_prepare_emulated_mmio_exit(cpu, &cpu->mmio_fragments[0]);
    assert(kvm_crucible_response_birth(&cpu->crucible_response));
}
static struct kvm_crucible_response_bytes query(struct fixture *fixture)
{
    struct kvm_crucible_response_bytes request = {
        .version = 1, .operation = KVM_CRUCIBLE_RESPONSE_BYTES_QUERY,
        .expected_invocation = fixture->cpu.crucible_run_return.original.invocation,
    };
    assert(kvm_crucible_response_bytes_ioctl(&fixture->cpu, &request) == 0);
    return request;
}
static struct kvm_crucible_response_bytes step(struct fixture *fixture, u8 byte)
{
    struct kvm_crucible_response_bytes original = query(fixture);
    struct kvm_crucible_response_bytes request = {
        .version = 1, .operation = KVM_CRUCIBLE_RESPONSE_BYTES_STEP,
        .operation_id = fixture->cpu.crucible_response.last_result.operation_id + 1,
        .expected_invocation = original.invocation,
        .expected_sequence = original.pending_sequence,
        .expected_revision = original.revision,
        .expected_generation = 9,
        .address = original.address, .data_offset = original.data_offset,
        .reason = original.reason, .length = original.length,
        .count = original.count, .size = original.size, .direction = original.direction,
    };
    if (!request.direction) {
        request.data_length = request.reason == KVM_EXIT_MMIO ? request.length : request.count * request.size;
        memset(request.data, byte, request.data_length);
    }
    return request;
}
static void geometry_and_retry(void)
{
    struct fixture fixture;
    setup(&fixture);
    mmio_birth(&fixture, false, true);
    struct kvm_crucible_response_bytes request = step(&fixture, 0x17), original = request;
    struct kvm_crucible_response_bytes bad = request;
    unsigned before = callbacks;
    bad.address++;
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &bad) == -ESTALE);
    bad = request; bad.expected_invocation++;
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &bad) == -ESTALE);
    bad = request; bad.expected_sequence++;
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &bad) == -ESTALE);
    bad = request; bad.expected_revision++;
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &bad) == -ESTALE);
    bad = request; bad.expected_generation++;
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &bad) == -ESTALE);
    bad = request; bad.data[4] = 1;
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &bad) == -EINVAL);
    bad = request; bad.reserved[0] = 1;
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &bad) == -EINVAL);
    fail_source_copy = true;
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &request) == -EFAULT);
    fail_source_copy = false;
    assert(callbacks == before);
    fixture.run.mmio.phys_addr = 0xbad;
    fixture.run.mmio.len = 8;
    fixture.run.exit_reason = KVM_EXIT_UNKNOWN;
    memset(fixture.run.mmio.data, 0xa7, sizeof(fixture.run.mmio.data));
    fail_result_copy = true;
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &request) == -EFAULT);
    fail_result_copy = false;
    assert(callbacks == before + 1 && fixture.first[0] == 0x17);
    request = original;
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &request) == 0);
    assert(callbacks == before + 1 && request.phase == KVM_CRUCIBLE_COMPLETION_MORE);
    assert(request.address == 0x2000 && request.pending_sequence == 2);
    bad = original; bad.data[0] ^= 1;
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &bad) == -ESTALE);
    assert(callbacks == before + 1);
    request = step(&fixture, 0x38);
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &request) == 0);
    assert(callbacks == before + 2 && fixture.second[0] == 0x38);
    assert(request.phase == KVM_CRUCIBLE_COMPLETION_DONE && request.consumed_sequence == 2);
    assert(request.data_length == 0);
    original = step(&fixture, 0); /* Query remains observational after Done. */
    original = fixture.cpu.crucible_response_bytes->last_request;
    fixture.cpu.crucible_run_return.original.invocation++;
    fixture.vm.generation++;
    request = original;
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &request) == 0);
    assert(callbacks == before + 2 && request.invocation == 21);
    assert(request.expected_sequence == 2);
    kvm_crucible_response_bytes_vcpu_destroy(&fixture.cpu);
}
static void writes_are_original(void)
{
    struct fixture fixture;
    setup(&fixture);
    memset(fixture.first, 0x59, sizeof(fixture.first));
    mmio_birth(&fixture, true, false);
    memset(fixture.first, 0x88, sizeof(fixture.first));
    memset(fixture.run.mmio.data, 0x99, sizeof(fixture.run.mmio.data));
    struct kvm_crucible_response_bytes view = query(&fixture);
    assert(view.data_length == 4 && view.data[0] == 0x59);
    struct kvm_crucible_response_bytes request = step(&fixture, 0);
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &request) == 0);
    kvm_crucible_response_bytes_vcpu_destroy(&fixture.cpu);

    setup(&fixture);
    u8 data[4096]; memset(data, 0x62, sizeof(data));
    assert(emulator_pio_in_out(&fixture.cpu, 4, 0x7e, data, 1024, false) == 0);
    assert(kvm_crucible_response_birth(&fixture.cpu.crucible_response));
    memset(data, 0x73, sizeof(data));
    memset(fixture.cpu.arch.pio_data, 0x81, sizeof(data));
    fixture.run.io.count = 1;
    view = query(&fixture);
    assert(view.count == 1024 && view.size == 4 && view.data_length == 4096);
    assert(view.data[0] == 0x62 && view.data[4095] == 0x62);
    request = step(&fixture, 0);
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &request) == 0);
    kvm_crucible_response_bytes_vcpu_destroy(&fixture.cpu);
}
static void pio_read_and_arm(void)
{
    struct fixture fixture;
    setup(&fixture);
    u8 unused[8] = {0};
    assert(emulator_pio_in_out(&fixture.cpu, 2, 0x20, unused, 2, true) == 0);
    assert(kvm_crucible_response_birth(&fixture.cpu.crucible_response));
    struct kvm_crucible_response_bytes request = step(&fixture, 0x47);
    memset(fixture.cpu.arch.pio_data, 0x90, 4);
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &request) == 0);
    assert(pio_destination[0] == 0x47 && pio_destination[3] == 0x47);
    kvm_crucible_response_bytes_vcpu_destroy(&fixture.cpu);

    setup(&fixture);
    use_arm = true;
    fixture.cpu.mmio_needed = true;
    fixture.cpu.arm_length = 4;
    fixture.cpu.arm_rd = 2;
    kvm_crucible_response_bytes_produce(&fixture.cpu, KVM_EXIT_MMIO, 0x3000, 0, 4, 0, 0, 0, unused);
    assert(kvm_crucible_response_birth(&fixture.cpu.crucible_response));
    request = step(&fixture, 0x51);
    memset(fixture.run.mmio.data, 0xe9, sizeof(fixture.run.mmio.data));
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &request) == 0);
    assert(fixture.cpu.regs[2] == 0x51515151 && fixture.cpu.pc == 4);
    use_arm = false;
    kvm_crucible_response_bytes_vcpu_destroy(&fixture.cpu);
}
struct thread_request { struct fixture *fixture; struct kvm_crucible_response_bytes request; int result; };
static void *execute(void *opaque)
{
    struct thread_request *thread = opaque;
    thread->result = kvm_crucible_response_bytes_ioctl(&thread->fixture->cpu, &thread->request);
    return NULL;
}
static void mutation_after_freeze(void)
{
    struct fixture fixture;
    setup(&fixture);
    mmio_birth(&fixture, false, false);
    struct thread_request thread = { .fixture = &fixture, .request = step(&fixture, 0x24) };
    hold_consumer = true; consumer_entered = false; consumer_released = false;
    pthread_t owner;
    assert(pthread_create(&owner, NULL, execute, &thread) == 0);
    assert(pthread_mutex_lock(&hold_lock) == 0);
    while (!consumer_entered)
        assert(pthread_cond_wait(&hold_condition, &hold_lock) == 0);
    memset(thread.request.data, 0xb8, 4);
    memset(fixture.run.mmio.data, 0xc6, 8);
    fixture.run.mmio.phys_addr = 0xdead;
    fixture.run.mmio.len = 8;
    fixture.run.exit_reason = KVM_EXIT_UNKNOWN;
    consumer_released = true;
    assert(pthread_cond_broadcast(&hold_condition) == 0);
    assert(pthread_mutex_unlock(&hold_lock) == 0);
    assert(pthread_join(owner, NULL) == 0);
    assert(thread.result == 0 && fixture.first[0] == 0x24);
    hold_consumer = false;
    kvm_crucible_response_bytes_vcpu_destroy(&fixture.cpu);
}
static void conservative_refusal(void)
{
    struct fixture fixture;
    setup(&fixture); mmio_birth(&fixture, false, false);
    struct kvm_crucible_response_bytes request = step(&fixture, 0x13);
    unsigned before = callbacks;
    owners_stopped = false;
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &request) == -EBUSY);
    owners_stopped = true;
    fixture.vm.crucible_active = true;
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &request) == -EBUSY);
    fixture.vm.crucible_active = false;
    fixture.vm.crucible_effect_owners = 1;
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &request) == -EBUSY);
    fixture.vm.crucible_effect_owners = 0;
    fixture.vm.generation++;
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &request) == -EBUSY);
    fixture.vm.generation--;
    fixture.cpu.crucible_response.revision = U64_MAX - 1;
    request.expected_revision = U64_MAX - 1;
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &request) == -EOVERFLOW);
    assert(callbacks == before && fixture.vm.crucible_effect_owners == 0);
    kvm_crucible_response_bytes_vcpu_destroy(&fixture.cpu);

    setup(&fixture); mmio_birth(&fixture, false, false);
    fixture.cpu.mmio_fragments[0].len = 8;
    request = step(&fixture, 0x13);
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &request) == 0);
    assert(request.phase == KVM_CRUCIBLE_COMPLETION_UNKNOWN);
    assert(request.flags & KVM_CRUCIBLE_COMPLETION_UNCERTAIN);
    unsigned completed_callbacks = callbacks;
    request = fixture.cpu.crucible_response_bytes->last_request;
    assert(kvm_crucible_response_bytes_ioctl(&fixture.cpu, &request) == 0);
    assert(request.phase == KVM_CRUCIBLE_COMPLETION_UNKNOWN && callbacks == completed_callbacks);
    assert(fixture.first[0] == 0);
    kvm_crucible_response_bytes_vcpu_destroy(&fixture.cpu);
}
int main(void)
{
    _Static_assert(sizeof(struct kvm_crucible_response_bytes) == 4264, "response ABI");
    struct kvm legacy_vm = {0};
    struct kvm_vcpu legacy = { .kvm = &legacy_vm };
    unsigned prior_allocations = allocations;
    assert(kvm_crucible_response_bytes_vcpu_init(&legacy) == 0 && !legacy.crucible_response_bytes);
    assert(allocations == prior_allocations);
    assert(kvm_crucible_response_bytes_ioctl(&legacy, NULL) == -EOPNOTSUPP);
    struct kvm_enable_cap cap = {0};
    assert(kvm_crucible_response_bytes_configure(&legacy_vm, &cap) == -EBUSY);
    legacy_vm.crucible_controlled = legacy_vm.crucible_response_enabled = true;
    assert(kvm_crucible_response_bytes_configure(&legacy_vm, &cap) == -EBUSY);
    legacy_vm.crucible_run_return_enabled = true;
    legacy_vm.created_vcpus = 1;
    assert(kvm_crucible_response_bytes_configure(&legacy_vm, &cap) == -EBUSY);
    legacy_vm.created_vcpus = 0;
    cap.args[0] = 1;
    assert(kvm_crucible_response_bytes_configure(&legacy_vm, &cap) == -EINVAL);
    cap.args[0] = 0;
    assert(kvm_crucible_response_bytes_configure(&legacy_vm, &cap) == 0);
    fail_allocation = true;
    assert(kvm_crucible_response_bytes_vcpu_init(&legacy) == -ENOMEM);
    fail_allocation = false;
    {
        struct kvm_run run = {0};
        legacy.run = &run;
        legacy_vm.crucible_response_bytes_enabled = false;
        legacy.arch.pio.size = 1; legacy.arch.pio.count = 2;
        legacy.arch.pio_data[0] = 0x29; legacy.arch.pio_data[1] = 0x31;
        u8 data[2] = {0};
        assert(complete_emulator_pio_in(&legacy, data) == 0);
        assert(data[0] == 0x29 && data[1] == 0x31);
        run.exit_reason = KVM_EXIT_IO;
        assert(kvm_crucible_response_bytes_reason(&legacy) == KVM_EXIT_IO);
    }
    geometry_and_retry(); writes_are_original(); pio_read_and_arm();
    mutation_after_freeze(); conservative_refusal();
    assert(frees + 1 == allocations);
    puts("Actual kernel byte journal/native producers/x86+ARM consumers: PASS (plumbing modeled)");
    return 0;
}
'''


def main():
    source, compiler, output = sys.argv[1:]
    source = Path(source)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    uapi = (source / 'include/uapi/linux/kvm.h').read_text()
    abi = uapi[uapi.index('#define KVM_CAP_CRUCIBLE_RESPONSE_BYTES_V1'):uapi.index('#define KVM_CAP_CRUCIBLE_CLOCK_V1')]
    abi = '\n'.join(line for line in abi.splitlines() if '_IOWR(' not in line)
    policy = (source / 'include/linux/kvm_crucible_completion.h').read_text()
    policy = re.sub(r'^#include[^\n]*\n', '', policy, flags=re.M)
    body = (source / 'virt/kvm/crucible-response-bytes.c').read_text()
    body = re.sub(r'^#include[^\n]*\n', '', body, flags=re.M)
    x86 = (source / 'arch/x86/kvm/x86.c').read_text()
    x86_header = (source / 'arch/x86/kvm/x86.h').read_text()
    arm = (source / 'arch/arm64/kvm/mmio.c').read_text()
    consumers = '\n'.join(function(x86_header, name) for name in ('__kvm_prepare_emulated_mmio_exit', 'kvm_prepare_emulated_mmio_exit'))
    consumers += '\n'.join(function(x86, name) for name in ('emulator_pio_in_out', 'complete_emulator_pio_in', 'complete_emulated_mmio'))
    consumers += function(arm, 'kvm_handle_mmio_return')
    program = PREFIX + abi + '\n' + policy + CONTEXT + body + consumers + DISPATCH + CASES
    (output / 'proof.c').write_text(program)
    subprocess.run([compiler, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-pthread', str(output / 'proof.c'), '-o', str(output / 'proof')], check=True)
    subprocess.run([str(output / 'proof')], check=True, timeout=30)


if __name__ == '__main__':
    main()
