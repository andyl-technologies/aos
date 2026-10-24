"""Exercise actual completion ioctl bodies under a bounded single-thread model.

Original native policy and ioctl code are compiled directly from the selected
source. Only user-copy faults, mutex plumbing and architecture callback effects
are modeled; this is not KVM execution, concurrency or physical qualification.
"""

from pathlib import Path
import re
import subprocess
import sys


PREFIX = r"""
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint8_t __u8;
typedef int32_t __s32;
#define U64_MAX UINT64_MAX
#define CONFIG_X86 1
#define CONFIG_ARM64 0
#define IS_ENABLED(option) (option)
#define PAGE_SIZE 4096U
#define __user
#define BUILD_BUG_ON(condition) _Static_assert(!(condition), "native ABI")
#define lockdep_assert_held(lock) ((void)(lock))
#define READ_ONCE(value) (value)
#define WRITE_ONCE(value, replacement) ((value) = (replacement))
#define raw_spin_lock_irqsave(lock, flags) do { (void)(lock); (flags) = 0; } while (0)
#define raw_spin_unlock_irqrestore(lock, flags) do { (void)(lock); (void)(flags); } while (0)

struct kvm {
    int crucible_configuration_lock, crucible_gate_lock;
    bool crucible_controlled, crucible_active, crucible_response_enabled;
    unsigned created_vcpus, crucible_effect_owners;
    struct { struct { unsigned run_owners, timer_owners; } crucible_clock; } arch;
};
struct kvm_run {
    u32 exit_reason;
    struct { u64 phys_addr; u32 len; __u8 is_write; __u8 data[8]; } mmio;
    struct { u64 data_offset; u32 count; __u8 size, direction; unsigned short port; } io;
};
struct kvm_vcpu {
    int mutex, vcpu_id;
    struct kvm *kvm;
    struct kvm_run *run;
    struct kvm_crucible_response_state crucible_response;
    struct { u64 address, data_offset; u32 reason, length, count, size, direction; } crucible_response_original;
};

static bool fail_source_copy, fail_result_copy, pending_callback, callback_more;
static int callback_result;
static unsigned callback_count;

static void mutex_lock(int *lock) { assert(*lock == 0); *lock = 1; }
static void mutex_unlock(int *lock) { assert(*lock == 1); *lock = 0; }

static int copy_from_user(void *target, const void *source, size_t length)
{
    if (fail_source_copy) return 1;
    memcpy(target, source, length);
    return 0;
}

static int copy_to_user(void *target, const void *source, size_t length)
{
    if (fail_result_copy) return 1;
    memcpy(target, source, length);
    return 0;
}

static bool kvm_arch_crucible_response_pending(struct kvm_vcpu *vcpu)
{
    (void)vcpu;
    return pending_callback;
}

static int kvm_arch_crucible_response_complete(struct kvm_vcpu *vcpu, bool *more)
{
    assert(vcpu->kvm->crucible_effect_owners == 1);
    assert(vcpu->kvm->crucible_configuration_lock == 1);
    callback_count++;
    *more = callback_more;
    pending_callback = callback_more || callback_result < 0;
    if (callback_more) vcpu->run->mmio.phys_addr += 8;
    return callback_result;
}

static void kvm_crucible_effect_leave(struct kvm *kvm)
{
    assert(kvm->crucible_effect_owners == 1);
    kvm->crucible_effect_owners--;
}
"""

CASES = r"""
static struct kvm_crucible_completion step(u64 id, u64 sequence)
{
    return (struct kvm_crucible_completion) {
        .version = 1, .operation = KVM_CRUCIBLE_COMPLETION_STEP,
        .operation_id = id, .expected_sequence = sequence,
    };
}

int main(void)
{
    struct kvm vm = { .crucible_controlled = true };
    struct kvm_enable_cap capability = { .cap = KVM_CAP_CRUCIBLE_COMPLETION_V1 };
    struct kvm_run run = { .exit_reason = KVM_EXIT_MMIO,
        .mmio = { .phys_addr = 32, .len = 4 } };
    struct kvm_vcpu cpu = { .kvm = &vm, .run = &run, .vcpu_id = 37 };
    struct kvm_crucible_completion request;
    struct kvm_crucible_response_state retained;

    vm.created_vcpus = 1;
    assert(kvm_crucible_response_configure(&vm, &capability) == -EBUSY);
    assert(!vm.crucible_response_enabled);
    vm.created_vcpus = 0;
    assert(kvm_crucible_response_configure(&vm, &capability) == 0);
    assert(kvm_crucible_response_configure(&vm, &capability) == -EBUSY);

    pending_callback = true;
    kvm_crucible_response_observe(&cpu, 0);
    assert(cpu.crucible_response.sequence == 1);
    assert(kvm_crucible_response_run_admit(&cpu) == -EBUSY);
    retained = cpu.crucible_response;
    request = step(1, 1);
    fail_source_copy = true;
    assert(kvm_crucible_response_ioctl(&cpu, &request) == -EFAULT);
    assert(callback_count == 0);
    fail_source_copy = false;

    run.mmio.phys_addr = 99;
    assert(kvm_crucible_response_ioctl(&cpu, &request) == -ESTALE);
    assert(callback_count == 0);
    run.mmio.phys_addr = 32;
    vm.crucible_active = true;
    assert(kvm_crucible_response_ioctl(&cpu, &request) == -EBUSY);
    assert(callback_count == 0);
    vm.crucible_active = false;
    vm.arch.crucible_clock.run_owners = 1;
    assert(kvm_crucible_response_ioctl(&cpu, &request) == -EBUSY);
    assert(callback_count == 0);
    vm.arch.crucible_clock.run_owners = 0;
    vm.arch.crucible_clock.timer_owners = 1;
    assert(kvm_crucible_response_ioctl(&cpu, &request) == -EBUSY);
    assert(callback_count == 0);
    vm.arch.crucible_clock.timer_owners = 0;
    vm.crucible_effect_owners = 1;
    assert(kvm_crucible_response_ioctl(&cpu, &request) == -EBUSY);
    assert(callback_count == 0);
    vm.crucible_effect_owners = 0;
    assert(memcmp(&retained, &cpu.crucible_response, sizeof(retained)) == 0);

    callback_result = 1;
    fail_result_copy = true;
    assert(kvm_crucible_response_ioctl(&cpu, &request) == -EFAULT);
    assert(callback_count == 1);
    assert(cpu.crucible_response.last_result.phase == KVM_CRUCIBLE_COMPLETION_DONE);
    assert(cpu.crucible_response.last_result.consumed_sequence == 1);
    assert(vm.crucible_effect_owners == 0 && vm.crucible_configuration_lock == 0);
    retained = cpu.crucible_response;
    fail_result_copy = false;
    assert(kvm_crucible_response_ioctl(&cpu, &request) == 0);
    assert(callback_count == 1 && request.operation_id == 1);
    assert(request.native_vcpu_id == 37 && request.consumed_sequence == 1);
    assert(memcmp(&retained, &cpu.crucible_response, sizeof(retained)) == 0);

    pending_callback = true;
    kvm_crucible_response_observe(&cpu, 0);
    request = step(2, 2);
    callback_result = 0;
    callback_more = true;
    assert(kvm_crucible_response_ioctl(&cpu, &request) == 0);
    assert(callback_count == 2 && request.phase == KVM_CRUCIBLE_COMPLETION_MORE);
    assert(request.pending_sequence == 3 && request.consumed_sequence == 2);
    assert(cpu.crucible_response_original.address == 40);
    request = step(2, 2);
    assert(kvm_crucible_response_ioctl(&cpu, &request) == 0);
    assert(callback_count == 2 && request.pending_sequence == 3);

    request = step(3, 3);
    callback_more = false;
    callback_result = -EINTR;
    assert(kvm_crucible_response_ioctl(&cpu, &request) == 0);
    assert(callback_count == 3 && request.phase == KVM_CRUCIBLE_COMPLETION_UNKNOWN);
    assert(request.consumed_sequence == 2 && request.flags == KVM_CRUCIBLE_COMPLETION_UNCERTAIN);
    request = step(3, 3);
    assert(kvm_crucible_response_ioctl(&cpu, &request) == 0);
    assert(callback_count == 3 && request.callback_result == -EINTR);
    request = step(4, 3);
    assert(kvm_crucible_response_ioctl(&cpu, &request) == -EIO);
    assert(callback_count == 3 && kvm_crucible_response_run_admit(&cpu) == -EBUSY);

    /* Failed entry with no new original callback never invents pending state. */
    pending_callback = false;
    cpu.crucible_response = (struct kvm_crucible_response_state) {0};
    run.exit_reason = KVM_EXIT_UNKNOWN;
    kvm_crucible_response_observe(&cpu, -EAGAIN);
    assert(cpu.crucible_response.sequence == 0 && cpu.crucible_response.flags == 0);
    assert(kvm_crucible_response_run_admit(&cpu) == 0);
    puts("actual ioctl model: source/result copy failures, original retry, no duplicate callback, geometry, closed clock/real owner predicates, MMIO continuation and unknown custody PASS; no native qualification");
    return 0;
}
"""


def function(source, declaration):
    start = source.index(declaration)
    return source[start:source.index("\n}\n", start) + 3]


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: completion-ioctl-test.py SOURCE AOS_CC OUTPUT_DIR")
    source, compiler, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    uapi = (source / "include/uapi/linux/kvm.h").read_text()
    packet = uapi[uapi.index("#define KVM_CAP_CRUCIBLE_COMPLETION_V1"):uapi.index("#define KVM_CAP_CRUCIBLE_CLOCK_V1")]
    enable = uapi[uapi.index("struct kvm_enable_cap {"):]
    enable = enable[:enable.index("\n};") + 4]
    numbers = "\n".join(re.findall(r"^#define KVM_EXIT_(?:IO|MMIO|OSI|PAPR_HCALL|XEN|EPR|HYPERCALL|TDX|X86_RDMSR|X86_WRMSR|UNKNOWN)\s+\d+\s*$", uapi, re.M))
    numbers += "\n" + "\n".join(re.findall(r"^#define KVM_EXIT_IO_(?:IN|OUT)\s+\d+\s*$", uapi, re.M))
    policy = re.sub(r"^#include.*$", "", (source / "include/linux/kvm_crucible_completion.h").read_text(), flags=re.M)
    module = re.sub(r"^#include.*$", "", (source / "virt/kvm/crucible-completion.c").read_text(), flags=re.M)
    stopped = function((source / "arch/x86/kvm/x86.c").read_text(), "bool kvm_arch_crucible_response_stopped(")
    # The original policy and packet precede the model's native container types.
    split = PREFIX.index("struct kvm {")
    code = PREFIX[:split] + packet + enable + numbers + policy + PREFIX[split:] + stopped + module + CASES
    output.mkdir(parents=True, exist_ok=True)
    path, binary = output / "completion-ioctl-test.c", output / "completion-ioctl-test"
    path.write_text(code)
    subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
