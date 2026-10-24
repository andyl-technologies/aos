"""Compile actual original-return source with bounded native-plumbing models.

No ioctl or guest executes. The actual ABI, common receipt/ACK functions,
architecture hidden-pending selectors and clock snapshots are extracted from
source. Native mutex, clock progression and copy-fault plumbing are modeled.
"""
from pathlib import Path
import re
import subprocess
import sys


def function(body, name):
    matches = list(re.finditer(re.escape(name) + r'[^;{}]*\{', body))
    if len(matches) != 1:
        raise ValueError(f'{name}: expected one actual function definition')
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
typedef int64_t __s64;
typedef int32_t __s32;
#define U64_MAX UINT64_MAX
#define U32_MAX UINT32_MAX
#define CONFIG_X86 1
#define CONFIG_ARM64 0
#define IS_ENABLED(option) (option)
#define __user
#define BUILD_BUG_ON(condition) _Static_assert(!(condition), "native ABI")
#define lockdep_assert_held(lock) ((void)(lock))
#define READ_ONCE(value) (value)
#define WRITE_ONCE(value, replacement) ((value) = (replacement))
#define raw_spin_lock_irqsave(lock, flags) do { (void)(lock); (flags) = 0; } while (0)
#define raw_spin_unlock_irqrestore(lock, flags) do { (void)(lock); (void)(flags); } while (0)
'''

CONTEXT = r'''
struct kvm_crucible_clock_domain {
    u64 window_generation, sampled_ns;
    unsigned run_owners, timer_owners;
    bool active;
};
struct kvm {
    int lock, crucible_configuration_lock, crucible_gate_lock;
    bool crucible_controlled, crucible_active, crucible_response_enabled;
    bool crucible_run_return_enabled;
    u32 created_vcpus, crucible_effect_owners, crucible_uncollected_returns;
    u64 crucible_host_ceiling_ns;
    struct { struct kvm_crucible_clock_domain crucible_clock; } arch;
};
struct kvm_vcpu {
    int mutex;
    u32 vcpu_id;
    struct kvm *kvm;
    bool mmio_needed, protected_guest, nested, external_abort, reset;
    struct { void *complete_userspace_io; struct { u32 count; } pio;
        bool guest_state_protected; } arch;
    struct kvm_crucible_response_state crucible_response;
    struct kvm_crucible_run_return_state crucible_run_return;
};
/* Stage6 receipt proof selects bytes mode disabled; its native mode is separate. */
static void kvm_crucible_response_bytes_run_reset(struct kvm_vcpu *cpu)
{ (void)cpu; }
static bool fail_source_copy, fail_result_copy, protected_vm;
static u64 host_now;
static bool is_guest_mode(struct kvm_vcpu *cpu) { return cpu->nested; }
static bool is_protected_kvm_enabled(void) { return protected_vm; }
static bool vcpu_has_nv(struct kvm_vcpu *cpu) { return cpu->nested; }
static bool kvm_pending_external_abort(struct kvm_vcpu *cpu) { return cpu->external_abort; }
#define KVM_REQ_VCPU_RESET 19
static bool kvm_test_request(int request, struct kvm_vcpu *cpu)
{ assert(request == KVM_REQ_VCPU_RESET); return cpu->reset; }
static u64 ktime_get_ns(void) { return host_now; }
static u64 clock_now_locked(struct kvm_crucible_clock_domain *clock) { return clock->sampled_ns; }
static void mutex_lock(int *lock) { assert(*lock == 0); *lock = 1; }
static void mutex_unlock(int *lock) { assert(*lock == 1); *lock = 0; }
static int copy_from_user(void *target, const void *source, size_t size)
{
    if (fail_source_copy) return 1;
    memcpy(target, source, size);
    return 0;
}
static int copy_to_user(void *target, const void *source, size_t size)
{
    if (fail_result_copy) return 1;
    memcpy(target, source, size);
    return 0;
}
'''

CASES = r'''
static struct kvm_crucible_run_return request(u32 operation, u64 invocation)
{
    return (struct kvm_crucible_run_return) {
        .version = 1, .operation = operation, .expected_invocation = invocation,
    };
}

static void hidden_pending(void)
{
    struct kvm_vcpu cpu = {0};

    assert(x86_pending(&cpu) == 0);
    cpu.arch.complete_userspace_io = &cpu;
    assert(x86_pending(&cpu) == KVM_CRUCIBLE_RUN_PENDING_CALLBACK);
    cpu.arch.pio.count = 4;
    cpu.mmio_needed = true;
    assert(x86_pending(&cpu) == (KVM_CRUCIBLE_RUN_PENDING_CALLBACK |
        KVM_CRUCIBLE_RUN_PENDING_MMIO | KVM_CRUCIBLE_RUN_PENDING_PIO));
    cpu.arch.guest_state_protected = true;
    assert(x86_pending(&cpu) & KVM_CRUCIBLE_RUN_PENDING_OPAQUE);
    cpu.arch.guest_state_protected = false;
    cpu.nested = true;
    assert(x86_pending(&cpu) & KVM_CRUCIBLE_RUN_PENDING_OPAQUE);

    cpu = (struct kvm_vcpu) {0};
    assert(arm_pending(&cpu) == 0);
    cpu.mmio_needed = true;
    assert(arm_pending(&cpu) == KVM_CRUCIBLE_RUN_PENDING_MMIO);
    cpu.mmio_needed = false;
    cpu.reset = true;
    assert(arm_pending(&cpu) == KVM_CRUCIBLE_RUN_PENDING_OPAQUE);
    cpu.reset = false;
    cpu.external_abort = true;
    assert(arm_pending(&cpu) == KVM_CRUCIBLE_RUN_PENDING_OPAQUE);
    cpu.external_abort = false;
    cpu.nested = true;
    assert(arm_pending(&cpu) == KVM_CRUCIBLE_RUN_PENDING_OPAQUE);
    cpu.nested = false;
    protected_vm = true;
    assert(arm_pending(&cpu) == KVM_CRUCIBLE_RUN_PENDING_OPAQUE);
    protected_vm = false;
}

static void capture_return(struct kvm_vcpu *cpu, int result, bool entered, bool birth_pending)
{
    assert(kvm_crucible_run_return_admit(cpu) == 0);
    if (birth_pending)
        cpu->arch.complete_userspace_io = cpu;
    if (entered)
        cpu->crucible_run_return.original.flags |= KVM_CRUCIBLE_RUN_RETURN_CLOCK_ENTERED;
    cpu->kvm->arch.crucible_clock.sampled_ns += 5;
    cpu->kvm->crucible_active = false;
    cpu->kvm->arch.crucible_clock.active = false;
    kvm_crucible_run_return_finish(cpu, result);
}

int main(void)
{
    struct kvm vm = { .crucible_controlled = true, .crucible_response_enabled = true };
    struct kvm_enable_cap cap = { .cap = KVM_CAP_CRUCIBLE_RUN_RETURN_V1 };
    struct kvm_vcpu cpu = { .kvm = &vm, .vcpu_id = 37 };
    struct kvm_crucible_run_return reply, original;
    struct kvm_crucible_run_return_state retained;

    _Static_assert(sizeof(struct kvm_crucible_run_return) == 128, "ABI128");
    hidden_pending();
    assert(kvm_crucible_run_return_admit(&cpu) == 0);
    assert(cpu.crucible_run_return.original.invocation == 0);
    reply = request(KVM_CRUCIBLE_RUN_RETURN_QUERY, 0);
    assert(kvm_crucible_run_return_ioctl(&cpu, &reply) == -EOPNOTSUPP);
    cap.flags = 1;
    assert(kvm_crucible_run_return_configure(&vm, &cap) == -EINVAL);
    cap.flags = 0;
    cap.args[3] = 1;
    assert(kvm_crucible_run_return_configure(&vm, &cap) == -EINVAL);
    cap.args[3] = 0;
    vm.crucible_response_enabled = false;
    assert(kvm_crucible_run_return_configure(&vm, &cap) == -EBUSY);
    vm.crucible_response_enabled = true;
    vm.created_vcpus = 1;
    assert(kvm_crucible_run_return_configure(&vm, &cap) == -EBUSY);
    vm.created_vcpus = 0;
    assert(kvm_crucible_run_return_configure(&vm, &cap) == 0);
    assert(kvm_crucible_run_return_configure(&vm, &cap) == -EBUSY);

    reply = request(KVM_CRUCIBLE_RUN_RETURN_QUERY, 0);
    assert(kvm_crucible_run_return_ioctl(&cpu, &reply) == 0);
    assert(reply.invocation == 0 && reply.flags == 0);
    reply = request(KVM_CRUCIBLE_RUN_RETURN_ACK, 0);
    assert(kvm_crucible_run_return_ioctl(&cpu, &reply) == -EINVAL);
    assert(kvm_crucible_run_return_admit(&cpu) == -EAGAIN);
    assert(vm.crucible_uncollected_returns == 0);

    vm.crucible_active = true;
    vm.crucible_host_ceiling_ns = 100;
    vm.arch.crucible_clock.active = true;
    vm.arch.crucible_clock.window_generation = 7;
    vm.arch.crucible_clock.sampled_ns = 10;
    capture_return(&cpu, -EINTR, true, false);
    original = cpu.crucible_run_return.original;
    assert(original.invocation == 1 && original.native_vcpu_id == 37);
    assert(original.generation_begin == 7 && original.generation_end == 7);
    assert(original.current_begin_ns == 10 && original.current_end_ns == 15);
    assert(original.run_result == -EINTR && original.pending_mask == 0);
    assert(original.response_flags == 0);
    assert(original.flags == (KVM_CRUCIBLE_RUN_RETURN_RETURNED |
        KVM_CRUCIBLE_RUN_RETURN_CLOCK_ENTERED | KVM_CRUCIBLE_RUN_RETURN_BEGIN_ACTIVE |
        KVM_CRUCIBLE_RUN_RETURN_CLOCK_STOPPED));
    assert(vm.crucible_uncollected_returns == 1);
    assert(kvm_crucible_run_return_admit(&cpu) == -EBUSY);

    retained = cpu.crucible_run_return;
    reply = request(KVM_CRUCIBLE_RUN_RETURN_QUERY, 1);
    fail_source_copy = true;
    assert(kvm_crucible_run_return_ioctl(&cpu, &reply) == -EFAULT);
    fail_source_copy = false;
    assert(memcmp(&retained, &cpu.crucible_run_return, sizeof(retained)) == 0);
    reply = request(KVM_CRUCIBLE_RUN_RETURN_QUERY, 1);
    fail_result_copy = true;
    assert(kvm_crucible_run_return_ioctl(&cpu, &reply) == -EFAULT);
    fail_result_copy = false;
    assert(memcmp(&retained, &cpu.crucible_run_return, sizeof(retained)) == 0);
    reply = request(KVM_CRUCIBLE_RUN_RETURN_QUERY, 2);
    assert(kvm_crucible_run_return_ioctl(&cpu, &reply) == -ESTALE);
    reply = request(KVM_CRUCIBLE_RUN_RETURN_QUERY, 1);
    reply.reserved[1] = 1;
    assert(kvm_crucible_run_return_ioctl(&cpu, &reply) == -EINVAL);
    reply = request(KVM_CRUCIBLE_RUN_RETURN_QUERY, 1);
    assert(kvm_crucible_run_return_ioctl(&cpu, &reply) == 0);
    assert(reply.invocation == 1 && reply.run_result == -EINTR);

    reply = request(KVM_CRUCIBLE_RUN_RETURN_ACK, 1);
    fail_result_copy = true;
    assert(kvm_crucible_run_return_ioctl(&cpu, &reply) == -EFAULT);
    fail_result_copy = false;
    assert(!cpu.crucible_run_return.outstanding && vm.crucible_uncollected_returns == 0);
    reply = request(KVM_CRUCIBLE_RUN_RETURN_ACK, 1);
    assert(kvm_crucible_run_return_ioctl(&cpu, &reply) == 0);
    assert(reply.run_result == -EINTR && vm.crucible_uncollected_returns == 0);
    assert(memcmp(&original, &cpu.crucible_run_return.original, sizeof(original)) == 0);

    vm.crucible_active = true;
    vm.arch.crucible_clock.active = true;
    vm.arch.crucible_clock.window_generation = 8;
    cpu.arch.complete_userspace_io = &cpu;
    assert(kvm_crucible_run_return_admit(&cpu) == -EBUSY);
    assert(cpu.crucible_run_return.original.invocation == 1);
    cpu.arch.complete_userspace_io = NULL;
    capture_return(&cpu, -EAGAIN, false, true);
    assert(cpu.crucible_run_return.original.invocation == 2);
    assert(cpu.crucible_run_return.original.generation_begin == 8);
    assert(cpu.crucible_run_return.original.pending_mask == KVM_CRUCIBLE_RUN_PENDING_CALLBACK);
    assert(cpu.crucible_run_return.original.response_flags & KVM_CRUCIBLE_COMPLETION_UNCERTAIN);
    assert(cpu.crucible_response.phase == KVM_CRUCIBLE_COMPLETION_UNKNOWN);
    assert(!(cpu.crucible_run_return.original.flags & KVM_CRUCIBLE_RUN_RETURN_CLOCK_ENTERED));
    reply = request(KVM_CRUCIBLE_RUN_RETURN_ACK, 1);
    assert(kvm_crucible_run_return_ioctl(&cpu, &reply) == -ESTALE);
    reply = request(KVM_CRUCIBLE_RUN_RETURN_ACK, 2);
    assert(kvm_crucible_run_return_ioctl(&cpu, &reply) == 0);
    assert(cpu.crucible_response.flags & KVM_CRUCIBLE_COMPLETION_UNCERTAIN);

    {
        struct kvm_vcpu second = { .kvm = &vm, .vcpu_id = 91 };
        struct kvm_vcpu third = { .kvm = &vm, .vcpu_id = 92 };

        vm.crucible_active = true;
        vm.arch.crucible_clock.active = true;
        assert(kvm_crucible_run_return_admit(&second) == 0);
        assert(kvm_crucible_run_return_admit(&third) == 0);
        assert(vm.crucible_uncollected_returns == 2);
        vm.arch.crucible_clock.run_owners = 1;
        kvm_crucible_run_return_finish(&second, -EINTR);
        assert(!(second.crucible_run_return.original.flags & KVM_CRUCIBLE_RUN_RETURN_CLOCK_STOPPED));
        vm.arch.crucible_clock.run_owners = 0;
        vm.arch.crucible_clock.active = false;
        kvm_crucible_run_return_finish(&third, -EINTR);
        reply = request(KVM_CRUCIBLE_RUN_RETURN_ACK, 1);
        assert(kvm_crucible_run_return_ioctl(&second, &reply) == 0);
        assert(reply.native_vcpu_id == 91 && vm.crucible_uncollected_returns == 1);
        reply = request(KVM_CRUCIBLE_RUN_RETURN_ACK, 1);
        assert(kvm_crucible_run_return_ioctl(&second, &reply) == 0);
        assert(vm.crucible_uncollected_returns == 1);
        assert(third.crucible_run_return.outstanding);
        reply = request(KVM_CRUCIBLE_RUN_RETURN_ACK, 1);
        assert(kvm_crucible_run_return_ioctl(&third, &reply) == 0);
        assert(reply.native_vcpu_id == 92 && vm.crucible_uncollected_returns == 0);
    }

    {
        struct kvm_vcpu opaque = { .kvm = &vm, .vcpu_id = 93 };

        vm.crucible_active = true;
        vm.arch.crucible_clock.active = true;
        capture_return(&opaque, 0, true, true);
        assert(opaque.crucible_run_return.original.pending_mask == KVM_CRUCIBLE_RUN_PENDING_CALLBACK);
        assert(opaque.crucible_run_return.original.response_phase == KVM_CRUCIBLE_COMPLETION_UNSUPPORTED);
        assert(opaque.crucible_run_return.original.response_flags & KVM_CRUCIBLE_COMPLETION_OPAQUE);
        reply = request(KVM_CRUCIBLE_RUN_RETURN_ACK, 1);
        assert(kvm_crucible_run_return_ioctl(&opaque, &reply) == 0);
        assert(kvm_crucible_run_return_admit(&opaque) == -EBUSY);
        opaque.arch.complete_userspace_io = NULL;
        assert(kvm_crucible_response_run_admit(&opaque) == -EBUSY);
    }

    cpu.arch.complete_userspace_io = NULL;
    assert(kvm_crucible_response_run_admit(&cpu) == -EBUSY);
    assert(cpu.crucible_response.flags & KVM_CRUCIBLE_COMPLETION_UNCERTAIN);
    vm.crucible_active = true;
    cpu.crucible_run_return.original.invocation = UINT64_MAX;
    assert(kvm_crucible_run_return_admit(&cpu) == -EOVERFLOW);
    cpu.crucible_run_return.original.invocation = 2;
    vm.crucible_active = true;
    vm.crucible_uncollected_returns = UINT32_MAX;
    assert(kvm_crucible_run_return_admit(&cpu) == -EOVERFLOW);
    assert(cpu.crucible_run_return.original.invocation == 2);
    assert(vm.crucible_uncollected_returns == UINT32_MAX);

    puts("Actual source ABI128, original generation/result/hidden pending, finite custody, copy-fault retry and ACK PASS; native plumbing modeled, no hardware qualification.");
    return 0;
}
'''


def main():
    source, compiler, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    output.mkdir(parents=True, exist_ok=True)
    uapi = (source / 'include/uapi/linux/kvm.h').read_text()
    packet = uapi[uapi.index('#define KVM_CAP_CRUCIBLE_RUN_RETURN_V1'):uapi.index('#define KVM_CAP_CRUCIBLE_CLOCK_V1')]
    enable = uapi[uapi.index('struct kvm_enable_cap {'):]
    enable = enable[:enable.index('\n};') + 4]
    policy = re.sub(r'^#include.*$', '', (source / 'include/linux/kvm_crucible_completion.h').read_text(), flags=re.M)
    arithmetic = (source / 'include/linux/kvm_crucible_clock_math.h').read_text()
    live = function(arithmetic, 'static inline bool kvm_crucible_clock_admission_live(')
    module = (source / 'virt/kvm/crucible-completion.c').read_text()
    common = '\n'.join(function(module, signature) for signature in (
        'int kvm_crucible_response_run_admit(', 'int kvm_crucible_run_return_configure(', 'int kvm_crucible_run_return_admit(',
        'void kvm_crucible_run_return_finish(', 'int kvm_crucible_run_return_ioctl('))
    x86 = function((source / 'arch/x86/kvm/x86.c').read_text(), 'u32 kvm_arch_crucible_run_pending(').replace('kvm_arch_crucible_run_pending', 'x86_pending')
    arm = function((source / 'arch/arm64/kvm/mmio.c').read_text(), 'u32 kvm_arch_crucible_run_pending(').replace('kvm_arch_crucible_run_pending', 'arm_pending')
    snapshots = []
    for isa in ('x86', 'arm64'):
        snapshot = function((source / f'arch/{isa}/kvm/crucible-clock.c').read_text(), 'void kvm_arch_crucible_run_clock_snapshot(')
        if isa == 'arm64':
            snapshot = snapshot.replace('kvm_arch_crucible_run_clock_snapshot', 'arm_snapshot')
        snapshots.append(snapshot)
    # Both architecture snapshots are real functions; compare their actual samples.
    cases = CASES.replace('hidden_pending();', '''hidden_pending();
    {
        struct kvm_crucible_run_return x = {0}, a = {0};
        kvm_arch_crucible_run_clock_snapshot(&cpu, &x, false);
        arm_snapshot(&cpu, &a, false);
        kvm_arch_crucible_run_clock_snapshot(&cpu, &x, true);
        arm_snapshot(&cpu, &a, true);
        assert(memcmp(&x, &a, sizeof(x)) == 0);
    }''')
    code = PREFIX + packet + enable + policy + CONTEXT + live + x86 + arm + ''.join(snapshots)
    code += '\n#define kvm_arch_crucible_run_pending x86_pending\n' + common + cases
    native, binary = output / 'return-proof.c', output / 'return-proof'
    native.write_text(code)
    subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', str(native), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
    main_body = function((source / 'virt/kvm/kvm_main.c').read_text(), 'static long kvm_vcpu_ioctl(')
    assert main_body.index('kvm_crucible_run_return_admit(vcpu)') < main_body.index('r = kvm_arch_vcpu_ioctl_run(vcpu)')
    assert main_body.index('r = kvm_arch_vcpu_ioctl_run(vcpu)') < main_body.index('kvm_crucible_run_return_finish(vcpu, r)')
    for isa in ('x86', 'arm64'):
        clock = (source / f'arch/{isa}/kvm/crucible-clock.c').read_text()
        assert clock.count('crucible_uncollected_returns') == 1
        assert 'KVM_CRUCIBLE_RUN_RETURN_CLOCK_ENTERED' in function(clock, 'int kvm_crucible_clock_run_enter(')
    print('Actual source placement before/after original RUN and both ISA clock-owner entry PASS.')


if __name__ == '__main__':
    main()
